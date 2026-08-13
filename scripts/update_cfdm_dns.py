#!/usr/bin/env python3
"""Point cfdm.<zone> A record (DNS-only) at the fastest live HK DMIT CF reverse-proxy IP.

Reads turn/dmit_ips.json from R2 (or --from file). Ranking:
  1) region == HK
  2) lower ws_p50_ms
  3) higher score / ws_rate

IMPORTANT: proxied must be False (grey cloud). Orange-cloud would hide the
DMIT anycast/reverse-proxy IP behind CF edge and break XUDP/SNI use.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EMAIL = os.environ.get("CF_EMAIL", "").strip()
KEY = os.environ.get("CF_API_KEY", "").strip()
ZONE = os.environ.get("CF_ZONE", "").strip()
ZONE_NAME = os.environ.get("CF_ZONE_NAME", "").strip()
HOST = os.environ.get("CFDM_HOST", "").strip()
# low TTL so clients pick up HK failover faster (DNS-only honors TTL)
TTL = int(os.environ.get("CFDM_TTL", "60") or 60)
R2_KEY = os.environ.get("DMIT_IPS_KEY", "turn/dmit_ips.json")
# CN→HK 直连 RTT 上限：真 HK 直连 ≈ 30-70ms；FOFA 误标 HK 的中转节点 ≥ 150ms
DIRECT_RTT_MS = float(os.environ.get("CFDM_DIRECT_RTT_MS", "100"))
# 已验证 CN2 GIA 网段（电信视角实测）：
# 命中则最优先解析；空 = 仅按 RTT 直连排序。新网段验证后追加即可。
# 默认网段仅为公开网络路由偏好，不包含私有端点。
PREFER_CIDRS = [c.strip() for c in os.environ.get("CFDM_PREFER_CIDRS", "154.12.188.0/24,154.12.189.0/24").split(",") if c.strip()]
CF_API_BASE = os.environ.get("CF_API_BASE", "").strip().rstrip("/")
CF_TRACE_URL = os.environ.get("CF_TRACE_URL", "").strip()
if not CF_API_BASE or not CF_TRACE_URL:
    raise RuntimeError("CF_API_BASE and CF_TRACE_URL are required")
BASE = f"{CF_API_BASE}/zones/{ZONE}"
HDR = {"X-Auth-Email": EMAIL, "X-Auth-Key": KEY, "Content-Type": "application/json"}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def load_doc(path: str | None) -> dict[str, Any]:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    import r2_store

    d = r2_store.get_json(R2_KEY)
    if not d:
        raise SystemExit(f"empty R2 key {R2_KEY}")
    return d


def pick_fastest_hk(
    doc: dict[str, Any],
    *,
    probe_rtt: bool | None = None,
    direct_ms: float = DIRECT_RTT_MS,
    prefer_cidrs: list[str] | None = None,
) -> dict[str, Any] | None:
    items = [i for i in (doc.get("items") or []) if str(i.get("region") or "").upper() == "HK" and i.get("ip")]
    if not items:
        # fallback: regions.HK list order (already score-sorted in build_doc)
        ips = list((doc.get("regions") or {}).get("HK") or [])
        if not ips:
            return None
        return {"ip": ips[0], "region": "HK", "ws_p50_ms": None, "score": None, "source": "regions.HK[0]"}

    # 1) 已验证 CN2 GIA 网段（电信视角 tcptest.cn 实测 59.43 落地）最优先。
    #    同 /24 同前缀同路由，网段内再按 RTT/ws_p50 选。
    cidrs = PREFER_CIDRS if prefer_cidrs is None else prefer_cidrs
    if cidrs:
        for it in items:
            it["prefer"] = _in_cidrs(it["ip"], cidrs)
        preferred = [i for i in items if i.get("prefer")]
        log(f"[cfdm] prefer cidrs {cidrs}: {len(preferred)}/{len(items)} hit")
        if preferred:
            items = preferred

    # 2) FOFA 的 region 标注不可信：池里一半"HK"实际在 US/JP 中转（RTT 170ms+）。
    # 从 CN 视角做 TCP RTT 探测，真 HK 直连 ≈ 30-70ms，优先解析这批。
    # probe_rtt=None → auto：仅当本机在 CN 才测（GHA runner 在美国，测了会选反）。
    if probe_rtt is None:
        probe_rtt = _local_is_cn()
    if probe_rtt:
        _annotate_direct(items, direct_ms)
        directs = [i for i in items if i.get("direct")]
        log(f"[cfdm] rtt probe: {len(directs)}/{len(items)} direct (<={direct_ms}ms)")
        for it in sorted(items, key=lambda x: (x.get("direct_rtt_ms") or 9e9)):
            log(f"  {it['ip']:16} rtt={it.get('direct_rtt_ms')} direct={it.get('direct')}")
        if directs:
            items = directs

    items.sort(
        key=lambda x: (
            float(x.get("direct_rtt_ms") if x.get("direct_rtt_ms") is not None else 9e9),
            float(x.get("ws_p50_ms") if x.get("ws_p50_ms") is not None else 9e9),
            -float(x.get("score") or 0),
            -float(x.get("ws_rate") or 0),
            str(x.get("ip")),
        )
    )
    best = dict(items[0])
    best["source"] = "items"
    return best


def _in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _tcp_rtt_ms(ip: str, port: int = 443, tries: int = 3, timeout: float = 3.0) -> float | None:
    """Best of `tries` TCP connect RTTs (ms); None if all fail."""
    best = None
    for _ in range(tries):
        t0 = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                dt = (time.monotonic() - t0) * 1000
            best = dt if best is None else min(best, dt)
        except Exception:
            pass
    return best


def _annotate_direct(items: list[dict[str, Any]], threshold_ms: float, workers: int = 8) -> None:
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_tcp_rtt_ms, it["ip"]): it for it in items}
        for fut, it in futs.items():
            rtt = fut.result()
            it["direct_rtt_ms"] = round(rtt, 1) if rtt is not None else None
            it["direct"] = rtt is not None and rtt <= threshold_ms


def _local_is_cn(timeout: float = 5.0) -> bool:
    """RTT 判直连只在 CN 视角成立；GHA runner 在美国，自动跳过."""
    try:
        r = requests.get(CF_TRACE_URL, timeout=timeout)
        for line in r.text.splitlines():
            if line.startswith("loc="):
                return line[4:].strip().upper() == "CN"
    except Exception:
        pass
    return False


def list_a_records(name: str) -> list[dict[str, Any]]:
    r = requests.get(
        f"{BASE}/dns_records",
        headers=HDR,
        params={"name": name, "type": "A", "per_page": 100},
        timeout=30,
    )
    r.raise_for_status()
    j = r.json()
    if not j.get("success"):
        raise RuntimeError(j)
    return list(j.get("result") or [])


def upsert_a(name: str, ip: str, *, ttl: int = TTL) -> dict[str, Any]:
    """Ensure exactly one DNS-only A record → ip. Delete extras."""
    recs = list_a_records(name)
    body = {
        "type": "A",
        "name": name,
        "content": ip,
        "ttl": max(60, int(ttl)),  # CF min for DNS-only is often 60
        "proxied": False,  # MUST grey-cloud
        "comment": "auto: fastest HK DMIT CF reverse-proxy",
    }
    keep_id = None
    if recs:
        # update first
        keep_id = recs[0]["id"]
        r = requests.put(
            f"{BASE}/dns_records/{keep_id}", headers=HDR, json=body, timeout=30
        )
        r.raise_for_status()
        j = r.json()
        if not j.get("success"):
            raise RuntimeError(j)
        # delete other A records for same name
        for extra in recs[1:]:
            requests.delete(
                f"{BASE}/dns_records/{extra['id']}", headers=HDR, timeout=20
            ).raise_for_status()
            log(f"[dns] deleted extra A {extra.get('content')}")
        result = j.get("result") or {}
    else:
        r = requests.post(f"{BASE}/dns_records", headers=HDR, json=body, timeout=30)
        r.raise_for_status()
        j = r.json()
        if not j.get("success"):
            raise RuntimeError(j)
        result = j.get("result") or {}
        keep_id = result.get("id")
    return {
        "id": keep_id,
        "name": name,
        "ip": ip,
        "ttl": result.get("ttl"),
        "proxied": result.get("proxied"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Update cfdm.* to fastest HK DMIT IP")
    ap.add_argument("--from", dest="from_file", default="", help="local dmit_ips.json")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--ttl", type=int, default=TTL)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--ip", default="", help="force this IP (skip ranking)")
    ap.add_argument(
        "--probe-rtt",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="TCP RTT 探测真 HK 直连并优先（默认 auto：仅 CN 本机启用，GHA 跳过）",
    )
    ap.add_argument(
        "--prefer-cidrs",
        default="",
        help="已验证 CN2 GIA 网段（逗号分隔，如 154.12.188.0/24），命中最优先；默认读 CFDM_PREFER_CIDRS",
    )
    args = ap.parse_args()

    if args.ip:
        best = {"ip": args.ip, "region": "HK", "source": "cli"}
    else:
        doc = load_doc(args.from_file or None)
        prefer = [c.strip() for c in args.prefer_cidrs.split(",") if c.strip()] or None
        best = pick_fastest_hk(doc, probe_rtt=args.probe_rtt, prefer_cidrs=prefer)
        if not best:
            log("[cfdm] no HK IP in pool")
            print(json.dumps({"ok": False, "error": "no_hk_ip"}))
            return 1

    ip = best["ip"]
    log(
        f"[cfdm] pick {ip} p50={best.get('ws_p50_ms')} score={best.get('score')} "
        f"via {best.get('source')} → {args.host} (DNS-only ttl={args.ttl})"
    )
    if args.dry_run:
        print(json.dumps({"ok": True, "dry_run": True, "host": args.host, "ip": ip, "best": best}, ensure_ascii=False))
        return 0

    info = upsert_a(args.host, ip, ttl=args.ttl)
    out = {"ok": True, "host": args.host, **info, "best": best}
    print(json.dumps(out, ensure_ascii=False))
    log(f"[cfdm] {args.host} → {ip} proxied={info.get('proxied')} ttl={info.get('ttl')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
