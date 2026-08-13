#!/usr/bin/env python3
"""每日刷新 DMIT(AS906) CF 反代 IP 池 → R2 turn/dmit_ips.json

FOFA:
  server=="cloudflare" && port=="443" && header="Forbidden" && asn="906"
  + region/country 分区

测活（连发真实 WS 升级，按成功率+P50 延迟淘汰半死节点）:
  1) 对 SNI=XUDP_HOST 连发 N 次 WebSocket Upgrade（GET / Upgrade:websocket）
     - 统计 101 成功率 ws_rate、成功用例的 P50 延迟 ws_p50_ms
     - Server: cloudflare / 101 即为 CF 特征（http_cf）
     - 成功率 < WS_MIN_RATE 或 P50 > WS_MAX_P50 → 判死（这是 IP1 半死节点的拦截点）
  2) GET trace（Host 由 Secret 注入）— 仅取 colo，非硬门槛
  背景: 单发 trace 会把"偶尔通"的反代标绿，故改为多次 WS 压测。

策略:
  - 先复测 R2 旧池，活的保留
  - 每区可用 < MIN_PER_REGION → FOFA 扫该区 → 测活补齐
  - 全量 FOFA 兜底若某区仍空
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FOFA_BASE = os.environ.get("FOFA_BASE", "").strip().rstrip("/")
FOFA_TOKEN = os.environ.get("FOFA_TOKEN", "").strip()
XUDP_SNI = os.environ.get("XUDP_HOST", "").strip()
R2_KEY = os.environ.get("DMIT_IPS_KEY", "turn/dmit_ips.json")
ASN = "906"
FOFA_CORE = (
    f'server=="cloudflare" && port=="443" && header="Forbidden" && asn="{ASN}"'
)
REGIONS = ("HK", "JP", "US")
REGION_FOFA = {
    "HK": f'{FOFA_CORE} && (region=="HK" || country="HK")',
    "JP": f'{FOFA_CORE} && country="JP"',
    "US": f'{FOFA_CORE} && country="US"',
}
COLO = {"HK": "HKG", "JP": "NRT", "US": "LAX"}
CF_TRACE_HOST = os.environ.get("CF_TRACE_HOST", "").strip()
PROXY_CHECK_URL = os.environ.get("PROXY_CHECK_URL", "").strip()
if not CF_TRACE_HOST or not PROXY_CHECK_URL:
    raise RuntimeError("CF_TRACE_HOST and PROXY_CHECK_URL are required")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fofa_search(q: str, size: int = 50, retries: int = 4) -> list[dict[str, Any]]:
    size = min(max(size, 2), 50)
    url = f"{FOFA_BASE}/v1/search?q={urllib.parse.quote(q)}&size={size}&page=1"
    last_err = ""
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {FOFA_TOKEN}",
                    "Accept": "application/json",
                    "User-Agent": "dmit-cf-proxy-refresh/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=50) as resp:
                d = json.loads(resp.read().decode())
            if d.get("ok"):
                return list(((d.get("data") or {}).get("assets")) or [])
            last_err = str(d.get("error") or d)
            log(f"  fofa fail try{attempt}: {last_err}")
        except Exception as e:
            last_err = str(e)
            log(f"  fofa err try{attempt}: {e}")
        time.sleep(min(8, attempt * 1.5))
    log(f"  fofa give up: {last_err}")
    return []


def infer_region(asset: dict[str, Any], fallback: str = "") -> str:
    country = str(asset.get("country") or "").upper()
    city = str(asset.get("city") or "").upper()
    region = str(asset.get("region") or "").upper()
    if "HK" in country or "HONG KONG" in country or region == "HK" or "HONG" in city:
        return "HK"
    if "JP" in country or "JAPAN" in country or "TOKYO" in city or "OSAKA" in city:
        return "JP"
    if (
        "US" in country
        or "UNITED STATES" in country
        or "LOS ANGELES" in city
        or "SAN JOSE" in city
        or region in ("CA", "US")
    ):
        return "US"
    if fallback in REGIONS:
        return fallback
    return "US"


def _tls_once(ip: str, sni: str, timeout: float) -> tuple[bool, str]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as ss:
                return True, ss.version() or "TLS"
    except Exception as e:
        return False, type(e).__name__


def _http_trace_once(ip: str, timeout: float) -> tuple[bool, str, bool]:
    """使用注入的 Host 请求 trace，以识别 CF 特征。"""
    host = CF_TRACE_HOST
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, 443), timeout=timeout)
        ss = ctx.wrap_socket(raw, server_hostname=host)
        ss.sendall(
            f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: dmit-refresh/1.0\r\nConnection: close\r\n\r\n".encode()
        )
        ss.settimeout(timeout)
        data = b""
        while len(data) < 8000:
            try:
                chunk = ss.recv(2048)
                if not chunk:
                    break
                data += chunk
            except Exception:
                break
        ss.close()
        text = data.decode("latin1", "replace")
        head, _, body = text.partition("\r\n\r\n")
        status = head.split("\r\n", 1)[0] if head else ""
        low = head.lower()
        has_cf = (
            "cf-ray" in low
            or "cloudflare" in low
            or ("fl=" in body and "ip=" in body)
            or "colo=" in body
        )
        has_colo = "colo=" in body
        return has_cf, status[:80], has_colo
    except Exception as e:
        return False, type(e).__name__, False


def _http_xudp_once(ip: str, sni: str, timeout: float) -> tuple[bool, str]:
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, 443), timeout=timeout)
        ss = ctx.wrap_socket(raw, server_hostname=sni)
        ss.sendall(
            f"GET / HTTP/1.1\r\nHost: {sni}\r\n"
            f"User-Agent: dmit-refresh/1.0\r\nConnection: close\r\n\r\n".encode()
        )
        ss.settimeout(timeout)
        data = b""
        while len(data) < 4000:
            try:
                chunk = ss.recv(2048)
                if not chunk:
                    break
                data += chunk
            except Exception:
                break
        ss.close()
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        status = head.split("\r\n", 1)[0] if head else ""
        return True, status[:80]
    except Exception as e:
        return False, type(e).__name__


def _ws_once(ip: str, sni: str, timeout: float) -> tuple[bool, float, bool, str]:
    """一次真实 WS 升级。返回 (ok101, elapsed_s, is_cf, note)."""
    key = base64.b64encode(os.urandom(16)).decode()
    t0 = time.monotonic()
    ss = None
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, 443), timeout=timeout)
        ss = ctx.wrap_socket(raw, server_hostname=sni)
        ss.sendall(
            (
                f"GET / HTTP/1.1\r\nHost: {sni}\r\n"
                f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                f"User-Agent: dmit-refresh/2.0\r\n\r\n"
            ).encode()
        )
        ss.settimeout(timeout)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 4096:
            c = ss.recv(256)
            if not c:
                break
            buf += c
        head = buf.decode("latin1", "replace")
        status = head.split("\r\n", 1)[0]
        low = head.lower()
        ok = "101" in status and "switching protocols" in low
        is_cf = "cloudflare" in low or "cf-ray" in low
        return ok, time.monotonic() - t0, is_cf, status[:60]
    except Exception as e:
        return False, time.monotonic() - t0, False, type(e).__name__
    finally:
        try:
            if ss:
                ss.close()
        except Exception:
            pass


def _p50(xs: list[float]) -> float:
    if not xs:
        return math.inf
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def _ws_probe(
    ip: str, sni: str, *, attempts: int, timeout: float, min_rate: float
) -> dict[str, Any]:
    """连发 attempts 次 WS 升级；可提前判死。返回 rate/p50_ms/cf 等."""
    ok_lat: list[float] = []
    fails = 0
    cf = False
    last = ""
    # 允许的最大失败数：超过则不可能达标，提前 break
    max_fail = attempts - math.ceil(attempts * min_rate)
    for i in range(attempts):
        ok, dt, is_cf, note = _ws_once(ip, sni, timeout)
        last = note
        if ok:
            ok_lat.append(dt)
            cf = cf or is_cf
        else:
            fails += 1
            if fails > max_fail:
                break
        time.sleep(0.15)
    done = len(ok_lat) + fails
    rate = len(ok_lat) / done if done else 0.0
    return {
        "ws_ok": len(ok_lat),
        "ws_tried": done,
        "ws_rate": round(rate, 3),
        "ws_p50_ms": round(_p50(ok_lat) * 1000) if ok_lat else None,
        "ws_cf": cf,
        "ws_note": last,
    }


def probe(
    ip: str,
    *,
    sni: str = XUDP_SNI,
    retries: int = 3,
    timeout: float = 4.5,
    require_trace: bool = True,
    ws_attempts: int = 5,
    ws_min_rate: float = 0.8,
    ws_max_p50_ms: float = 1500.0,
) -> dict[str, Any]:
    """连发 WS 测活。usable 需 WS 成功率 & P50 达标（拦半死节点）."""
    out: dict[str, Any] = {
        "ip": ip,
        "tls": False,
        "http_cf": False,
        "trace_colo": False,
        "xudp_ok": False,
        "ws_rate": 0.0,
        "ws_p50_ms": None,
        "ws_ok": 0,
        "ws_tried": 0,
        "usable": False,
        "score": 0,
        "tls_info": "",
        "http_status": "",
        "xudp_status": "",
    }
    # 1) 连发 WS 升级——核心门槛
    wr = _ws_probe(ip, sni, attempts=ws_attempts, timeout=timeout, min_rate=ws_min_rate)
    out.update(
        {
            "ws_rate": wr["ws_rate"],
            "ws_p50_ms": wr["ws_p50_ms"],
            "ws_ok": wr["ws_ok"],
            "ws_tried": wr["ws_tried"],
            "http_status": wr["ws_note"],
        }
    )
    if wr["ws_ok"] > 0:
        out["tls"] = True  # 能完成 WS 即 TLS 通
        out["http_cf"] = bool(wr["ws_cf"])
    ws_gate = bool(
        wr["ws_rate"] >= ws_min_rate
        and wr["ws_p50_ms"] is not None
        and wr["ws_p50_ms"] <= ws_max_p50_ms
    )

    # 2) trace 仅补 colo（非硬门槛），只有 WS 有戏才值得测
    if wr["ws_ok"] > 0:
        ok, st, colo = _http_trace_once(ip, timeout)
        if ok:
            out["http_cf"] = True
            out["trace_colo"] = colo

    # 3) 打分：WS 成功率主导 + 低延迟加成
    score = 0.0
    score += wr["ws_rate"] * 5
    p50 = wr["ws_p50_ms"]
    if p50 is not None:
        if p50 <= 800:
            score += 3
        elif p50 <= 1500:
            score += 2
        elif p50 <= 3000:
            score += 1
    if out["http_cf"]:
        score += 1
    if out["trace_colo"]:
        score += 1
    out["score"] = round(score, 2)

    if require_trace:
        out["usable"] = bool(ws_gate and out["http_cf"])
    else:
        out["usable"] = bool(ws_gate)
    return out


def load_existing() -> dict[str, Any]:
    try:
        from r2_store import get_json

        d = get_json(R2_KEY, default=None)
        if isinstance(d, dict):
            return d
    except Exception as e:
        log(f"[r2] get skip: {e}")
    # public fallback
    base = os.environ.get("R2_PUBLIC_BASE", "").strip().rstrip("/")
    if not base:
        raise RuntimeError("R2_PUBLIC_BASE is required")
    try:
        req = urllib.request.Request(
            f"{base}/{R2_KEY}",
            headers={"User-Agent": "dmit-refresh/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        log(f"[public] get skip: {e}")
    return {}


def save_doc(doc: dict[str, Any], out_path: Path | None) -> None:
    text = json.dumps(doc, ensure_ascii=False, indent=2)
    if out_path:
        out_path.write_text(text + "\n", encoding="utf-8")
        log(f"[out] wrote {out_path}")
    try:
        from r2_store import put_json

        put_json(R2_KEY, doc)
        log(f"[r2] put {R2_KEY} total={doc.get('total')}")
    except Exception as e:
        log(f"[r2] put FAIL: {e}")
        raise


def collect_fofa_region(region: str, size: int, seen: set[str]) -> list[tuple[str, str]]:
    """返回 [(ip, region), ...] 新候选."""
    q = REGION_FOFA[region]
    assets = fofa_search(q, size=size)
    log(f"[fofa] {region} assets={len(assets)}")
    out: list[tuple[str, str]] = []
    for a in assets:
        ip = a.get("ip") or ""
        if not ip or ":" in ip or ip in seen:
            continue
        reg = infer_region(a, fallback=region)
        if reg != region:
            # 仍按请求区标记（查询已带 country）
            reg = region
        seen.add(ip)
        out.append((ip, reg))
    return out


def probe_many(
    ips: list[str],
    *,
    workers: int,
    retries: int,
    timeout: float,
    require_trace: bool,
    ws_attempts: int = 5,
    ws_min_rate: float = 0.8,
    ws_max_p50_ms: float = 1500.0,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    if not ips:
        return results
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {
            ex.submit(
                probe,
                ip,
                retries=retries,
                timeout=timeout,
                require_trace=require_trace,
                ws_attempts=ws_attempts,
                ws_min_rate=ws_min_rate,
                ws_max_p50_ms=ws_max_p50_ms,
            ): ip
            for ip in ips
        }
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                results[ip] = fut.result()
            except Exception as e:
                results[ip] = {
                    "ip": ip,
                    "usable": False,
                    "tls": False,
                    "score": 0,
                    "error": str(e),
                }
    return results


def build_doc(
    by_region: dict[str, list[dict[str, Any]]],
    *,
    min_per: int,
    max_per: int,
    meta: dict[str, Any],
) -> dict[str, Any]:
    regions: dict[str, list[str]] = {}
    items: list[dict[str, Any]] = []
    for reg in REGIONS:
        rows = sorted(
            by_region.get(reg) or [],
            key=lambda x: (-float(x.get("score") or 0), x["ip"]),
        )[:max_per]
        regions[reg] = [r["ip"] for r in rows]
        for r in rows:
            items.append(
                {
                    "ip": r["ip"],
                    "region": reg,
                    "colo": COLO.get(reg, reg),
                    "score": round(float(r.get("score") or 0), 2),
                    "asn": ASN,
                    "http_cf": bool(r.get("http_cf")),
                    "ws_rate": r.get("ws_rate"),
                    "ws_p50_ms": r.get("ws_p50_ms"),
                }
            )
    return {
        "updated_at": utc_now(),
        "asn": ASN,
        "source": "fofa DMIT AS906 CF reverse-proxy",
        "fofa_core": FOFA_CORE,
        "sni": XUDP_SNI,
        "note": "DMIT asn=906 CF Forbidden; live = N次WS升级成功率+P50延迟达标（拦半死反代）",
        "check": PROXY_CHECK_URL,
        "min_per_region": min_per,
        "regions": regions,
        "items": items,
        "total": len(items),
        "counts": {r: len(regions[r]) for r in REGIONS},
        "meta": meta,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Refresh DMIT AS906 CF reverse-proxy IP pool")
    ap.add_argument("--min-per-region", type=int, default=1, help="每区至少可用数")
    ap.add_argument("--target-per-region", type=int, default=8, help="每区目标保留数")
    ap.add_argument("--max-per-region", type=int, default=15, help="每区上限")
    ap.add_argument("--fofa-size", type=int, default=50, help="FOFA page1 size≤50")
    ap.add_argument("--retries", type=int, default=3, help="（保留）trace 重试次数")
    ap.add_argument("--timeout", type=float, default=4.5)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--ws-attempts", type=int, default=5, help="每 IP 连发 WS 升级次数")
    ap.add_argument("--ws-min-rate", type=float, default=0.8, help="WS 101 成功率下限")
    ap.add_argument("--ws-max-p50-ms", type=float, default=1500.0, help="WS P50 延迟上限(ms)，严打半死反代")
    ap.add_argument(
        "--require-trace",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="必须 /cdn-cgi/trace 呈 CF 特征（默认开）",
    )
    ap.add_argument("--out", default="dmit_ips.json", help="本地产物路径")
    ap.add_argument("--dry-run", action="store_true", help="不写 R2")
    ap.add_argument("--force-fofa", action="store_true", help="每区都 FOFA 扫一轮")
    args = ap.parse_args()

    min_per = max(1, args.min_per_region)
    target = max(min_per, args.target_per_region)
    max_per = max(target, args.max_per_region)

    log(
        f"[start] sni={XUDP_SNI} min/target/max={min_per}/{target}/{max_per} "
        f"ws={args.ws_attempts}x rate>={args.ws_min_rate} p50<={args.ws_max_p50_ms}ms "
        f"fofa={FOFA_BASE}"
    )

    existing = load_existing()
    old_regions: dict[str, list[str]] = {}
    if isinstance(existing.get("regions"), dict):
        for r in REGIONS:
            old_regions[r] = [
                str(ip)
                for ip in (existing["regions"].get(r) or [])
                if isinstance(ip, str) and ip.count(".") == 3
            ]
    else:
        for it in existing.get("items") or []:
            if not isinstance(it, dict):
                continue
            reg = str(it.get("region") or "")
            ip = str(it.get("ip") or "")
            if reg in REGIONS and ip.count(".") == 3:
                old_regions.setdefault(reg, []).append(ip)

    old_ips = sorted({ip for xs in old_regions.values() for ip in xs})
    log(f"[pool] existing { {r: len(old_regions.get(r) or []) for r in REGIONS} } unique={len(old_ips)}")

    # 1) 复测旧池
    reprobe = probe_many(
        old_ips,
        workers=args.workers,
        retries=args.retries,
        timeout=args.timeout,
        require_trace=args.require_trace,
        ws_attempts=args.ws_attempts,
        ws_min_rate=args.ws_min_rate,
        ws_max_p50_ms=args.ws_max_p50_ms,
    )
    by: dict[str, list[dict[str, Any]]] = {r: [] for r in REGIONS}
    alive_set: set[str] = set()
    for reg, ips in old_regions.items():
        for ip in ips:
            pr = reprobe.get(ip) or {}
            if pr.get("usable"):
                row = {"ip": ip, "region": reg, **pr}
                by[reg].append(row)
                alive_set.add(ip)
    log(
        f"[reprobe] usable={len(alive_set)} "
        f"by={ {r: len(by[r]) for r in REGIONS} }"
    )

    seen: set[str] = set(old_ips)
    fofa_added = 0
    fofa_probed = 0

    def need(reg: str) -> int:
        return max(0, target - len(by[reg]))

    # 2) 不足的区 FOFA 补
    for reg in REGIONS:
        deficit = need(reg)
        force = args.force_fofa
        if deficit <= 0 and not force:
            # 仍保证 min
            if len(by[reg]) >= min_per:
                continue
            deficit = min_per - len(by[reg])
        if deficit <= 0 and not force:
            continue
        log(f"[fill] {reg} have={len(by[reg])} need+={max(deficit, 1 if force else 0)}")
        candidates = collect_fofa_region(reg, args.fofa_size, seen)
        # 只要还没测过的
        todo = [ip for ip, _ in candidates if ip not in alive_set]
        if force:
            # 也扫 ALL 里可能漏的：已在 collect
            pass
        if not todo and len(by[reg]) < min_per:
            # 全区 core 再扫
            assets = fofa_search(FOFA_CORE, size=args.fofa_size)
            for a in assets:
                ip = a.get("ip") or ""
                if not ip or ":" in ip or ip in seen:
                    continue
                if infer_region(a, fallback="") == reg or reg == infer_region(a, reg):
                    seen.add(ip)
                    todo.append(ip)
            log(f"[fill] {reg} core-extra candidates={len(todo)}")

        if not todo:
            log(f"[fill] {reg} no new FOFA IPs")
            continue

        # 多测一些以便筛出够数
        todo = todo[: max(40, deficit * 5)]
        fofa_probed += len(todo)
        results = probe_many(
            todo,
            workers=args.workers,
            retries=args.retries,
            timeout=args.timeout,
            require_trace=args.require_trace,
            ws_attempts=args.ws_attempts,
            ws_min_rate=args.ws_min_rate,
            ws_max_p50_ms=args.ws_max_p50_ms,
        )
        for ip, pr in results.items():
            if not pr.get("usable"):
                continue
            if ip in alive_set:
                continue
            by[reg].append({"ip": ip, "region": reg, **pr})
            alive_set.add(ip)
            fofa_added += 1
            if len(by[reg]) >= max_per:
                break
        log(f"[fill] {reg} now={len(by[reg])}")

    # 3) 仍 < min 的区：放宽 require_trace 再扫一轮 FOFA（仅补 min）
    for reg in REGIONS:
        if len(by[reg]) >= min_per:
            continue
        log(f"[relax] {reg} still {len(by[reg])} < min={min_per}, retry FOFA w/ softer rule")
        # 软规则：TLS + (trace 或 xudp)
        candidates = collect_fofa_region(reg, args.fofa_size, seen)
        todo = [ip for ip, _ in candidates][:50]
        if not todo:
            assets = fofa_search(FOFA_CORE, size=args.fofa_size)
            for a in assets:
                ip = a.get("ip") or ""
                if not ip or ":" in ip or ip in seen:
                    continue
                if infer_region(a, reg) == reg:
                    seen.add(ip)
                    todo.append(ip)
            todo = todo[:50]
        results = probe_many(
            todo,
            workers=args.workers,
            retries=args.retries,
            timeout=args.timeout,
            require_trace=False,
            ws_attempts=args.ws_attempts,
            ws_min_rate=max(0.4, args.ws_min_rate - 0.3),  # 兜底放宽成功率
            ws_max_p50_ms=max(args.ws_max_p50_ms, 2500.0),  # 兜底略放宽，仍远严于旧 6000
        )
        fofa_probed += len(todo)
        for ip, pr in results.items():
            if not pr.get("usable") or ip in alive_set:
                continue
            # soft usable already set; 额外要求 tls
            if not pr.get("tls"):
                continue
            by[reg].append({"ip": ip, "region": reg, **pr})
            alive_set.add(ip)
            fofa_added += 1
            if len(by[reg]) >= min_per:
                break
        log(f"[relax] {reg} now={len(by[reg])}")

    meta = {
        "reprobed": len(old_ips),
        "fofa_probed": fofa_probed,
        "fofa_added": fofa_added,
        "require_trace": args.require_trace,
        "ws_attempts": args.ws_attempts,
        "ws_min_rate": args.ws_min_rate,
        "ws_max_p50_ms": args.ws_max_p50_ms,
    }
    doc = build_doc(by, min_per=min_per, max_per=max_per, meta=meta)

    # 校验每区至少一个
    short = [r for r in REGIONS if doc["counts"].get(r, 0) < min_per]
    if short:
        log(f"[WARN] regions below min: {short} counts={doc['counts']}")
    else:
        log(f"[ok] all regions >= {min_per}: {doc['counts']}")

    out_path = Path(args.out) if args.out else None
    if args.dry_run:
        if out_path:
            out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
        log("[dry-run] skip R2")
        print(json.dumps({"counts": doc["counts"], "total": doc["total"], "short": short}))
        return 0 if not short else 2

    # 若全部为空且旧池有数据，拒绝覆盖
    if doc["total"] == 0 and old_ips:
        log("[guard] new total=0, keep old pool on R2")
        if out_path:
            out_path.write_text(json.dumps(existing, ensure_ascii=False, indent=2) + "\n")
        return 1

    save_doc(doc, out_path)
    cfdm_info = None
    try:
        import importlib.util
        _p = Path(__file__).resolve().parent / "update_cfdm_dns.py"
        _spec = importlib.util.spec_from_file_location("update_cfdm_dns", _p)
        _cfdm = importlib.util.module_from_spec(_spec)
        assert _spec and _spec.loader
        _spec.loader.exec_module(_cfdm)
        best = _cfdm.pick_fastest_hk(doc)
        if best and best.get("ip"):
            info = _cfdm.upsert_a(_cfdm.HOST, best["ip"])
            cfdm_info = {"host": _cfdm.HOST, "ip": best["ip"], "ws_p50_ms": best.get("ws_p50_ms"), "proxied": info.get("proxied")}
            log(f"[cfdm] {_cfdm.HOST} → {best['ip']} p50={best.get('ws_p50_ms')}")
            meta["cfdm"] = cfdm_info
        else:
            log("[cfdm] skip — no HK IP")
    except Exception as e:
        log(f"[cfdm] warn: {e}")
    print(
        json.dumps(
            {
                "ok": True,
                "counts": doc["counts"],
                "total": doc["total"],
                "short": short,
                "meta": meta,
                "cfdm": cfdm_info,
                "updated_at": doc["updated_at"],
            },
            ensure_ascii=False,
        )
    )
    # 短区非 0 退出，方便 GHA 标黄但仍写入
    return 0 if not short else 2


if __name__ == "__main__":
    raise SystemExit(main())
