#!/usr/bin/env python3
"""用同区 CF 优选 IP 作入口，path global=1 实连测 TURN 速度（不压 DMIT 反代）。

流程:
  1) 拉 turn_report + 661 CF 优选（按 colo→区）
  2) 生成临时 mihomo 配置：每节点 = VLESS@CF_IP + /turn://TURN?ed=2560&global=1
  3) url-test / 经 mixed-port 拉测速文件，按区排序
  4) 写 R2 turn/turn_fast.json；可选裁剪供 turn-dmit 配对的 TURN 列表

环境:
  XUDP_HOST / XUDP_UUID / TURN_API / CF_IP_API / R2_* / MIHOMO_BIN
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from curl_cffi import requests as curl_requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

XUDP_HOST = os.environ.get("XUDP_HOST", "").strip()
XUDP_UUID = os.environ.get("XUDP_UUID", "").strip()
XUDP_ECH = os.environ.get("XUDP_ECH", "").strip()
XHTTP_HOST = os.environ.get("XHTTP_HOST", "").strip()
XHTTP_UUID = os.environ.get("XHTTP_UUID", "").strip()
TURN_API = os.environ.get("TURN_API", "").strip()
CF_IP_API = os.environ.get("CF_IP_API", "").strip()
R2_KEY = os.environ.get("TURN_FAST_KEY", "turn/turn_fast.json")
SPEED_URL = os.environ.get("SPEED_URL", "").strip()
# generate_204 做延迟兜底
DELAY_URL = os.environ.get("DELAY_URL", "").strip()
IP_META_BATCH_API = os.environ.get("IP_META_BATCH_API", "").strip()
IPPURE_URL = os.environ.get("IPPURE_URL", "https://my.ippure.com/v1/info").strip()
IPPURE_CF_SUMMARY_URL = os.environ.get(
    "IPPURE_CF_SUMMARY_URL", "https://cf.999831.xyz/api/cf-summary"
).strip()
IPPURE_CF_GATEWAY_URL = os.environ.get(
    "IPPURE_CF_GATEWAY_URL", "https://api.123169.xyz/api/gateway/cf"
).strip()
if not all(
    (
        XUDP_ECH,
        XHTTP_HOST,
        XHTTP_UUID,
        CF_IP_API,
        SPEED_URL,
        DELAY_URL,
        IP_META_BATCH_API,
    )
):
    raise RuntimeError(
        "XUDP_ECH, XHTTP_HOST, XHTTP_UUID, CF_IP_API, SPEED_URL, DELAY_URL "
        "and IP_META_BATCH_API are required"
    )

# colo → 订阅区
COLO2REG = {
    "LAX": "US",
    "SJC": "US",
    "SEA": "US",
    "NRT": "JP",
    "KIX": "JP",
    "HKG": "HK",
    "SIN": "SG",
    "ICN": "KR",
}
REG_KEYS = {
    "US": ["US", "UNITED STATES", "USA"],
    "JP": ["JP", "JAPAN"],
    "HK": ["HK", "HONG KONG"],
    "SG": ["SG", "SINGAPORE"],
    "KR": ["KR", "SOUTH KOREA", "KOREA"],
}
COUNTRY_NAMES = {
    "US": "United States",
    "JP": "Japan",
    "HK": "Hong Kong",
    "SG": "Singapore",
    "KR": "South Korea",
}
DEFAULT_REGIONS = ("SG", "HK", "JP", "KR", "US")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_json(url: str, timeout: float = 45) -> Any:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "turn-speed-rank/1.0", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def fetch_turns() -> list[dict[str, Any]]:
    d = http_json(TURN_API)
    rows = d.get("sub_servers") or d.get("servers") or []
    out = []
    for s in rows:
        if not s or not s.get("IP"):
            continue
        if s.get("Mode") == "ALL" or (s.get("TCP") and s.get("UDP")):
            out.append(s)
    return out


def turn_region(s: dict[str, Any]) -> str | None:
    blob = f"{s.get('country_code') or ''} {s.get('Country') or ''}".upper()
    for reg, keys in REG_KEYS.items():
        if any(k in blob for k in keys):
            return reg
    return None


def normalize_turn_location(turn: dict[str, Any]) -> dict[str, Any]:
    """统一 Country 使用英文全名，同时保留 ISO 两位 country_code。"""
    normalized = dict(turn)
    region = turn_region(normalized)
    if region:
        normalized["Country"] = COUNTRY_NAMES[region]
        normalized["country_code"] = region
    return normalized


def enrich_unknown_locations(
    turns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """通过 IP 批量定位补全缺失地区；查询失败时保留原记录。"""
    enriched = [normalize_turn_location(turn) for turn in turns]
    unknown_indexes = [index for index, turn in enumerate(turns) if not turn_region(turn)]
    if not unknown_indexes:
        return enriched

    rows = [
        {"query": str(turns[index].get("IP") or "").strip()}
        for index in unknown_indexes
    ]
    cmd = [
        "curl",
        "-fsS",
        "--retry",
        "2",
        "--connect-timeout",
        "5",
        "--max-time",
        "30",
        "-H",
        "Content-Type: application/json",
        "--data-binary",
        "@-",
        IP_META_BATCH_API,
    ]
    try:
        result = subprocess.run(
            cmd,
            input=json.dumps(rows),
            capture_output=True,
            text=True,
            timeout=35,
            check=True,
        )
        locations = json.loads(result.stdout)
    except Exception as error:
        log(f"[geo] batch lookup failed, keep original location: {error}")
        return enriched

    for index, location in zip(unknown_indexes, locations):
        if location.get("status") != "success":
            continue
        turn = dict(turns[index])
        turn["Country"] = str(location.get("country") or "").strip()
        turn["country_code"] = str(location.get("countryCode") or "").strip().upper()
        if not turn.get("City"):
            turn["City"] = str(location.get("city") or "").strip()
        enriched[index] = normalize_turn_location(turn)

    resolved = sum(turn_region(enriched[index]) is not None for index in unknown_indexes)
    log(f"[geo] resolved={resolved}/{len(unknown_indexes)}")
    return enriched


def distribute_turns(
    turns: list[dict[str, Any]], regions: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """把全部 TURN 分配到测速区；未知地区按当前最短队列均衡分配。"""
    if not regions:
        raise ValueError("regions cannot be empty")
    by_turn: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unknown: list[dict[str, Any]] = []
    for turn in turns:
        reg = turn_region(turn)
        if reg in regions:
            by_turn[reg].append(turn)
        else:
            unknown.append(turn)

    for turn in unknown:
        reg = min(regions, key=lambda item: len(by_turn[item]))
        by_turn[reg].append(turn)
    return by_turn


def fetch_cf_by_region() -> dict[str, list[dict[str, Any]]]:
    d = http_json(CF_IP_API)
    if not d.get("success"):
        raise RuntimeError(f"CF IP API fail: {d}")
    by: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in d.get("aggregates") or []:
        ip = a.get("ip") or ""
        if not ip or ":" in str(ip):
            continue
        colo = str(a.get("colo") or "").upper()
        reg = COLO2REG.get(colo)
        if not reg:
            continue
        by[reg].append(
            {
                "ip": ip,
                "colo": colo,
                "speed": float(a.get("speed") or 0),
                "carrier": a.get("carrier") or "",
                "province": a.get("province_name") or "",
            }
        )
    for reg in by:
        by[reg].sort(key=lambda x: -x["speed"])
    return by


def vless_node(
    name: str,
    cf_ip: str,
    turn_ip: str,
    turn_port: int,
    cred: str = "",
    *,
    global_mode: str = "1",
) -> dict[str, Any]:
    """mihomo/meta VLESS 节点：入口 CF，path 强制 global=1 测 TURN。"""
    auth = f"{cred}@" if cred else ""
    path = f"/turn://{auth}{turn_ip}:{turn_port}?ed=2560&global={global_mode}"
    node: dict[str, Any] = {
        "name": name,
        "type": "vless",
        "server": cf_ip,
        "port": 443,
        "uuid": XUDP_UUID,
        "network": "ws",
        "tls": True,
        "udp": True,
        "servername": XUDP_HOST,
        "client-fingerprint": "chrome",
        "ws-opts": {
            "path": path,
            "headers": {"Host": XUDP_HOST},
        },
    }
    return node


def xhttp_node(
    source: dict[str, Any], *, global_mode: str | None = None
) -> dict[str, Any]:
    """复用同一入口与 TURN，仅把传输改成生产 XHTTP/stream-one。"""
    path = source["ws-opts"]["path"].replace("/turn://", "/turn/")
    if global_mode is not None:
        parsed = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query = [(key, value) for key, value in query if key != "global"]
        query.append(("global", global_mode))
        path = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
        )
    return {
        "name": source["name"],
        "type": "vless",
        "server": source["server"],
        "port": source["port"],
        "uuid": XHTTP_UUID,
        "network": "xhttp",
        "tls": True,
        "udp": True,
        "servername": XHTTP_HOST,
        "client-fingerprint": "chrome",
        "xhttp-opts": {
            "path": path,
            "host": XHTTP_HOST,
            "mode": "stream-one",
            "reuse-settings": {"h-keep-alive-period": 10},
        },
    }


def write_mihomo_config(
    path: Path,
    nodes: list[dict[str, Any]],
    *,
    mixed_port: int = 17890,
    controller: int = 19090,
) -> None:
    # 极简 YAML（避免依赖 pyyaml）
    lines = [
        f"mixed-port: {mixed_port}",
        "allow-lan: false",
        "mode: global",
        "log-level: warning",
        "ipv6: false",
        f"external-controller: 127.0.0.1:{controller}",
        "unified-delay: true",
        "proxies:",
    ]
    for n in nodes:
        lines.append(f"  - name: {json.dumps(n['name'], ensure_ascii=False)}")
        lines.append(f"    type: {n['type']}")
        lines.append(f"    server: {n['server']}")
        lines.append(f"    port: {n['port']}")
        lines.append(f"    uuid: {n['uuid']}")
        lines.append(f"    network: {n['network']}")
        lines.append(f"    tls: true")
        lines.append(f"    udp: true")
        lines.append(f"    servername: {n['servername']}")
        lines.append(f"    client-fingerprint: chrome")
        lines.append("    skip-cert-verify: true")
        if n["network"] == "xhttp":
            xhttp = n["xhttp-opts"]
            lines.append("    alpn:")
            lines.append('      - "h2"')
            lines.append("    xhttp-opts:")
            lines.append(f"      path: {json.dumps(xhttp['path'], ensure_ascii=False)}")
            lines.append(f"      host: {xhttp['host']}")
            lines.append(f"      mode: {xhttp['mode']}")
            lines.append("      reuse-settings:")
            lines.append(
                "        h-keep-alive-period: "
                f"{xhttp['reuse-settings']['h-keep-alive-period']}"
            )
        else:
            lines.append("    ws-opts:")
            lines.append(
                f"      path: {json.dumps(n['ws-opts']['path'], ensure_ascii=False)}"
            )
            lines.append("      headers:")
            lines.append(f"        Host: {n['ws-opts']['headers']['Host']}")
    # SELECT + url-test group
    names = [n["name"] for n in nodes]
    lines.append("proxy-groups:")
    lines.append('  - name: "AUTO"')
    lines.append("    type: url-test")
    lines.append(f"    url: {DELAY_URL}")
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append("    proxies:")
    for nm in names:
        lines.append(f"      - {json.dumps(nm, ensure_ascii=False)}")
    lines.append('  - name: "PROXY"')
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append('      - "AUTO"')
    for nm in names:
        lines.append(f"      - {json.dumps(nm, ensure_ascii=False)}")
    lines.append("rules:")
    lines.append('  - MATCH,PROXY')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def find_mihomo() -> str:
    env = os.environ.get("MIHOMO_BIN", "").strip()
    if env and Path(env).exists():
        return env
    for c in ("mihomo", "clash-meta", "clash"):
        p = shutil.which(c)
        if p:
            return p
    raise SystemExit("mihomo/clash-meta not found; set MIHOMO_BIN")


def api(controller: int, path: str, method: str = "GET", body: bytes | None = None, timeout: float = 30) -> Any:
    url = f"http://127.0.0.1:{controller}{path}"
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if not raw:
            return None
        try:
            return json.loads(raw.decode())
        except Exception:
            return raw.decode()


def measure_delay(controller: int, name: str, timeout_ms: int = 8000) -> int | None:
    q = urllib.parse.quote(name, safe="")
    url = (
        f"http://127.0.0.1:{controller}/proxies/{q}/delay"
        f"?timeout={timeout_ms}&url={urllib.parse.quote(DELAY_URL, safe='')}"
    )
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000 + 5) as resp:
            d = json.loads(resp.read().decode())
        delay = d.get("delay")
        return int(delay) if delay and int(delay) > 0 else None
    except Exception:
        return None


def measure_loss(
    controller: int,
    name: str,
    *,
    probes: int = 5,
    timeout_ms: int = 8000,
) -> tuple[float, int]:
    """多次经同一代理执行 HTTP 探测，以失败比例估算端到端丢包率。"""
    probes = max(1, probes)
    success = sum(
        measure_delay(controller, name, timeout_ms=timeout_ms) is not None
        for _ in range(probes)
    )
    return round((probes - success) * 100.0 / probes, 2), success


def measure_speed(
    mixed_port: int,
    controller: int,
    name: str,
    *,
    bytes_n: int = 2_000_000,
    timeout: float = 25,
) -> tuple[float | None, int | None]:
    """切到节点，经 mixed-port 下载，返回 (KB/s, delay_ms)."""
    # select proxy
    try:
        body = json.dumps({"name": name}).encode()
        api(controller, "/proxies/PROXY", method="PUT", body=body, timeout=10)
    except Exception as e:
        log(f"  select fail {name}: {e}")
        return None, None

    delay = measure_delay(controller, name)
    speed_url = SPEED_URL
    if "bytes=" not in speed_url:
        separator = "&" if "?" in speed_url else "?"
        speed_url = f"{speed_url}{separator}bytes={bytes_n}"
    # curl through mixed-port (HTTP proxy)
    cmd = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "-x",
        f"http://127.0.0.1:{mixed_port}",
        "-m",
        str(int(timeout)),
        "-w",
        "%{http_code} %{speed_download} %{time_total}",
        speed_url,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        out = (p.stdout or "").strip()
        parts = out.split()
        if len(parts) < 2:
            return None, delay
        code, spd = parts[0], float(parts[1])
        if code not in ("200", "206") or spd <= 0:
            return None, delay
        return spd / 1024.0, delay  # B/s → KB/s
    except Exception as e:
        log(f"  speed fail {name}: {e}")
        return None, delay


def measure_ip_quality(
    mixed_port: int,
    controller: int,
    name: str,
    *,
    timeout: float = 15,
) -> dict[str, Any]:
    """经当前节点获取出口欺诈分和住宅属性；失败不影响主测速。"""
    try:
        body = json.dumps({"name": name}).encode()
        api(controller, "/proxies/PROXY", method="PUT", body=body, timeout=10)
        response = curl_requests.get(
            IPPURE_URL,
            headers={"Accept": "application/json"},
            proxy=f"http://127.0.0.1:{mixed_port}",
            timeout=timeout,
            impersonate="chrome",
        )
        response.raise_for_status()
        response_text = response.text
        if not response_text.strip():
            raise RuntimeError(f"empty response status={response.status_code}")
        try:
            payload = json.loads(response_text)
        except json.JSONDecodeError as error:
            preview = response_text[:160].replace("\r", "\\r").replace("\n", "\\n")
            raise RuntimeError(
                f"invalid JSON bytes={len(response.content)} preview={preview!r}"
            ) from error
        score = payload.get("fraudScore")
        residential = payload.get("isResidential")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            score = None
        if not isinstance(residential, bool):
            residential = None
        return {
            "quality_ip": str(payload.get("ip") or ""),
            "fraudScore": score,
            "isResidential": residential,
        }
    except Exception as error:
        log(f"  IPPure fail {name}: {error}")
        return {"quality_ip": "", "fraudScore": None, "isResidential": None}


def validate_ip_quality(
    result: dict[str, Any], expected_ip: str, name: str
) -> dict[str, Any]:
    """仅接受确实由当前 TURN 出口返回的 IPPure 质量结果。"""
    actual_ip = str(result.get("quality_ip") or "").strip()
    expected_ip = str(expected_ip or "").strip()
    matched = bool(actual_ip and expected_ip and actual_ip == expected_ip)
    result["qualityIpMatched"] = matched
    if not matched:
        if actual_ip:
            log(
                f"  IPPure exit mismatch {name}: "
                f"expected={expected_ip or '?'} actual={actual_ip}"
            )
        result["fraudScore"] = None
        result["isResidential"] = None
    return result


def measure_cf_control_index(
    mixed_port: int,
    controller: int,
    name: str,
    *,
    timeout: float = 20,
) -> dict[str, Any]:
    """经当前节点调用 IPPure Cloudflare Bot Management，获取封控指数。"""
    try:
        api(
            controller,
            "/proxies/PROXY",
            method="PUT",
            body=json.dumps({"name": name}).encode(),
            timeout=10,
        )
        proxy = f"http://127.0.0.1:{mixed_port}"
        session = curl_requests.Session(impersonate="chrome", proxy=proxy)
        summary_response = session.get(IPPURE_CF_SUMMARY_URL, timeout=timeout)
        summary_response.raise_for_status()
        raw = summary_response.content
        key = ""
        server_time = 0
        local_time = 0
        origin = "https://ippure.com"
        for _ in range(4):
            headers = {
                "Content-Type": "application/octet-stream",
                "Origin": origin,
                "Referer": "https://ippure.com/cloudflare",
            }
            body = raw
            if key:
                timestamp = int(time.time() * 1000) - local_time + server_time
                # 浏览器 Request.text() 会以 UTF-8 replacement 方式读取二进制正文。
                # 签名必须复现该文本，再由 TextEncoder 编码，不能直接拼原始字节。
                raw_text = raw.decode("utf-8", errors="replace")
                signing = f"POST-{IPPURE_CF_GATEWAY_URL}-{raw_text}-{timestamp}".encode()
                signature = hmac.new(key.encode(), signing, hashlib.sha256).hexdigest()
                x_t = f"{timestamp}-{signature}"
                iv = secrets.token_bytes(16)
                encrypted = subprocess.run(
                    [
                        "openssl",
                        "enc",
                        "-aes-256-cbc",
                        "-K",
                        hashlib.sha256(x_t.encode()).hexdigest(),
                        "-iv",
                        iv.hex(),
                    ],
                    input=raw,
                    capture_output=True,
                    timeout=10,
                    check=True,
                ).stdout
                body = iv + encrypted
                headers.update({"x-k": key, "x-t": x_t})
            response = session.post(
                IPPURE_CF_GATEWAY_URL,
                headers=headers,
                data=body,
                timeout=timeout,
            )
            response.raise_for_status()
            response_body = response.content
            response_headers = {name.lower(): value for name, value in response.headers.items()}
            next_key = response_headers.get("x-k", "")
            if not next_key:
                if not response_body.strip():
                    raise RuntimeError(
                        "empty gateway response "
                        f"headers={sorted(response_headers)}"
                    )
                response_text = response_body.decode("utf-8", errors="replace")
                try:
                    payload = json.loads(response_text)
                except json.JSONDecodeError as error:
                    preview = response_text[:160].replace("\r", "\\r").replace("\n", "\\n")
                    raise RuntimeError(
                        f"invalid gateway JSON bytes={len(response_body)} "
                        f"preview={preview!r}"
                    ) from error
                score = payload.get("risk_score")
                if isinstance(score, bool) or not isinstance(score, (int, float)):
                    score = None
                return {
                    "cfControlIndex": score,
                    "cfQualityIp": str(payload.get("ip") or ""),
                }
            key = next_key
            server_time = int(response_headers.get("x-t") or int(time.time() * 1000))
            local_time = int(time.time() * 1000)
        raise RuntimeError("IPPure CF gateway handshake exceeded retries")
    except Exception as error:
        log(f"  IPPure CF fail {name}: {error}")
        return {"cfControlIndex": None, "cfQualityIp": ""}


def put_r2(key: str, obj: dict[str, Any]) -> None:
    from r2_store import put_json

    put_json(key, obj)
    log(f"[r2] put {key}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Rank TURN by CF-entry global=1 speed test")
    ap.add_argument("--regions", default=",".join(DEFAULT_REGIONS))
    ap.add_argument("--cf-per-region", type=int, default=2, help="每区用几个 CF 入口测（取 661 最快）")
    ap.add_argument(
        "--turn-candidates",
        type=int,
        default=0,
        help="每区最多测多少 TURN；0 表示全测",
    )
    ap.add_argument(
        "--top", type=int, default=0, help="每区保留最快 N 个 TURN；0 表示全部保留"
    )
    ap.add_argument("--bytes", type=int, default=2_000_000, help="测速下载字节")
    ap.add_argument("--workers-delay", type=int, default=6, help="delay 并发")
    ap.add_argument("--loss-probes", type=int, default=5, help="每节点丢包率探测次数")
    ap.add_argument("--skip-speed", action="store_true", help="只做 delay，不下载")
    ap.add_argument("--workdir", default="/tmp/turn-speed-rank")
    ap.add_argument("--out", default="turn_fast.json")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--global", dest="global_mode", default="1", help="path global= 测速用")
    args = ap.parse_args()

    regions = [r.strip().upper() for r in args.regions.split(",") if r.strip()]
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)

    log(f"[start] sni={XUDP_HOST} regions={regions} global={args.global_mode}")
    turns = enrich_unknown_locations(fetch_turns())
    by_turn = distribute_turns(turns, regions)
    for reg in by_turn:
        # 有上限时先按已有 latency/speed 粗排；0 表示保留全部。
        by_turn[reg].sort(
            key=lambda x: (
                x.get("latency_ms") or 9999,
                -(float(x.get("speed_kbs") or 0)),
            )
        )
        if args.turn_candidates > 0:
            by_turn[reg] = by_turn[reg][: args.turn_candidates]
        log(f"[turn] {reg} candidates={len(by_turn[reg])}")

    cf_by = fetch_cf_by_region()
    fallback_cfs = sorted(
        (cf for rows in cf_by.values() for cf in rows),
        key=lambda item: -item["speed"],
    )
    for reg in regions:
        log(f"[cf] {reg} available={len(cf_by.get(reg) or [])}")

    # 组节点：每个 TURN × 该区 top CF
    nodes: list[dict[str, Any]] = []
    meta_by_name: dict[str, dict[str, Any]] = {}
    for reg in regions:
        region_cfs = cf_by.get(reg) or []
        cfs = (region_cfs or fallback_cfs)[: args.cf_per_region]
        if not cfs:
            raise RuntimeError("CF IP API returned no usable IPv4 entry")
        if not region_cfs:
            log(f"[warn] no same-region CF IP for {reg}; use fastest global entry")
        for ti, turn in enumerate(by_turn.get(reg) or []):
            tip = turn["IP"]
            tport = int(turn.get("Port") or 3478)
            cred = ""
            if not turn.get("NoAuth") and turn.get("Cred"):
                cred = str(turn["Cred"])
            for ci, cf in enumerate(cfs):
                # 名称短且唯一
                name = f"{reg}-{ti:02d}-{ci}-{tip.replace('.', '')[-8:]}"
                nodes.append(
                    vless_node(
                        name,
                        cf["ip"],
                        tip,
                        tport,
                        cred,
                        global_mode=args.global_mode,
                    )
                )
                meta_by_name[name] = {
                    "region": reg,
                    "turn_ip": tip,
                    "turn_port": tport,
                    "exit_ip": str(turn.get("exit_ip") or tip),
                    "cred": cred,
                    "cf_ip": cf["ip"],
                    "cf_colo": cf["colo"],
                    "turn_latency_scan": turn.get("latency_ms"),
                    "country": turn.get("Country") or "",
                    "country_code": turn.get("country_code") or "",
                    "city": turn.get("City") or "",
                }

    if not nodes:
        log("[err] no nodes to test")
        return 1
    log(f"[nodes] {len(nodes)}")

    cfg_path = work / "config.yaml"
    write_mihomo_config(cfg_path, nodes, mixed_port=17890, controller=19090)
    bin_path = find_mihomo()
    log(f"[mihomo] {bin_path} cfg={cfg_path}")

    # start mihomo
    log_path = work / "mihomo.log"
    log_f = open(log_path, "w")
    proc = subprocess.Popen(
        [bin_path, "-f", str(cfg_path), "-d", str(work)],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        # wait controller
        ok = False
        for _ in range(60):
            try:
                api(19090, "/version", timeout=2)
                ok = True
                break
            except Exception:
                time.sleep(0.3)
                if proc.poll() is not None:
                    break
        if not ok:
            log_f.flush()
            tail = log_path.read_text()[-3000:] if log_path.exists() else ""
            log(f"[err] mihomo not up rc={proc.poll()}; log:\n{tail}")
            return 1
        log("[mihomo] up")

        results: list[dict[str, Any]] = []

        def job(name: str) -> dict[str, Any]:
            m = dict(meta_by_name[name])
            m["name"] = name
            loss_pct, loss_success = measure_loss(
                19090, name, probes=args.loss_probes
            )
            m["loss_pct"] = loss_pct
            m["loss_probes"] = max(1, args.loss_probes)
            m["loss_success"] = loss_success
            if args.skip_speed:
                d = delay_map.get(name)
                m["delay_ms"] = d
                m["speed_kbs"] = None
                m["ok"] = d is not None
            else:
                spd, d = measure_speed(
                    17890,
                    19090,
                    name,
                    bytes_n=args.bytes,
                    timeout=28,
                )
                m["speed_kbs"] = round(spd, 3) if spd else None
                m["delay_ms"] = d
                m["ok"] = bool(spd) or (d is not None)
            return m

        # 串行测速更稳（切换 PROXY）；delay 可并发先筛
        log("[phase] delay prefilter")
        delay_map: dict[str, int | None] = {}
        with ThreadPoolExecutor(max_workers=max(1, args.workers_delay)) as ex:
            futs = {ex.submit(measure_delay, 19090, n["name"]): n["name"] for n in nodes}
            for fut in as_completed(futs):
                name = futs[fut]
                try:
                    delay_map[name] = fut.result()
                except Exception:
                    delay_map[name] = None
        alive_names = [n for n, d in delay_map.items() if d is not None]
        log(f"[delay] alive={len(alive_names)}/{len(nodes)}")

        if args.skip_speed:
            for name in nodes:
                nm = name["name"]
                m = dict(meta_by_name[nm])
                m["name"] = nm
                m["delay_ms"] = delay_map.get(nm)
                m["speed_kbs"] = None
                loss_pct, loss_success = measure_loss(
                    19090, nm, probes=args.loss_probes
                )
                m["loss_pct"] = loss_pct
                m["loss_probes"] = max(1, args.loss_probes)
                m["loss_success"] = loss_success
                m["ok"] = delay_map.get(nm) is not None
                results.append(m)
        else:
            # 每区只对 delay 活的测速；同一 TURN 多个 CF 取最好
            log("[phase] speed via CF entry (global=1)")
            for i, name in enumerate(alive_names):
                m = job(name)
                results.append(m)
                if (i + 1) % 5 == 0 or i == 0:
                    log(
                        f"  [{i+1}/{len(alive_names)}] {m['region']} "
                        f"turn={m['turn_ip']} cf={m['cf_ip']} "
                        f"spd={m.get('speed_kbs')} delay={m.get('delay_ms')}"
                    )

        # 聚合：同一 region+turn_ip 取最佳 speed（或最低 delay）
        best: dict[tuple[str, str], dict[str, Any]] = {}
        for m in results:
            if not m.get("ok"):
                continue
            key = (m["region"], m["turn_ip"])
            cur = best.get(key)
            if cur is None:
                best[key] = m
                continue
            # 先比丢包，再比 speed 与 delay。
            loss1 = m.get("loss_pct") if m.get("loss_pct") is not None else 100.0
            loss0 = cur.get("loss_pct") if cur.get("loss_pct") is not None else 100.0
            if loss1 < loss0:
                best[key] = m
                continue
            if loss1 > loss0:
                continue
            s1, s0 = m.get("speed_kbs") or 0, cur.get("speed_kbs") or 0
            if s1 > s0:
                best[key] = m
            elif s1 == s0:
                d1, d0 = m.get("delay_ms") or 9e9, cur.get("delay_ms") or 9e9
                if d1 < d0:
                    best[key] = m

        # IPPure 两项检测以同一 TURN 的最佳实测入口为准，每个最终节点只请求一次。
        log(f"[phase] IPPure quality for best nodes={len(best)}")
        for index, item in enumerate(best.values(), 1):
            name = str(item["name"])
            ws_node = next(node for node in nodes if node["name"] == name)
            # 质量站点使用生产 XHTTP，但 global=0 让非 CF TCP 由 Worker 直接
            # 出口访问；这样 IPPure 看到的是该次 Worker 出口，不会把一个
            # 共享 TURN/中间出口分数复制到所有 TURN 节点。
            write_mihomo_config(
                cfg_path,
                [xhttp_node(ws_node, global_mode="0")],
                mixed_port=17890,
                controller=19090,
            )
            reload_body = json.dumps({"path": str(cfg_path.resolve())}).encode()
            api(
                19090,
                "/configs?force=true",
                method="PUT",
                body=reload_body,
                timeout=10,
            )
            quality = measure_ip_quality(17890, 19090, name)
            worker_exit = str(quality.get("quality_ip") or "")
            item.update(validate_ip_quality(quality, worker_exit, name))
            item["qualityRoute"] = "worker-direct" if worker_exit else ""
            item.update(measure_cf_control_index(17890, 19090, name))
            if index % 5 == 0 or index == 1:
                log(
                    f"  [{index}/{len(best)}] turn={item['turn_ip']} "
                    f"fraud={item.get('fraudScore')} residential={item.get('isResidential')} "
                    f"cf_index={item.get('cfControlIndex')}"
                )

        by_reg: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for m in best.values():
            by_reg[m["region"]].append(m)
        for reg in by_reg:
            by_reg[reg].sort(
                key=lambda x: (
                    x.get("loss_pct") if x.get("loss_pct") is not None else 100.0,
                    -(x.get("speed_kbs") or 0),
                    x.get("delay_ms") or 9e9,
                )
            )
            if args.top > 0:
                by_reg[reg] = by_reg[reg][: args.top]
            log(
                f"[top] {reg} "
                + str(
                    [
                        (
                            x["turn_ip"],
                            x.get("speed_kbs"),
                            x.get("delay_ms"),
                            x.get("cf_ip"),
                        )
                        for x in by_reg[reg]
                    ]
                )
            )

        # 供 turn-dmit：每区最快 TURN 列表 + 建议 CF（仅记录，订阅仍用反代入口）
        fast_regions = {r: [x["turn_ip"] for x in xs] for r, xs in by_reg.items()}
        doc = {
            "updated_at": utc_now(),
            "sni": XUDP_HOST,
            "global_test": args.global_mode,
            "note": "TURN ranked via same-region CF entry + global=1; DMIT reverse-proxy NOT used as test entry",
            "speed_url": SPEED_URL,
            "regions": fast_regions,
            "items": [
                {
                    "region": x["region"],
                    "turn_ip": x["turn_ip"],
                    "turn_port": x["turn_port"],
                    "exit_ip": x.get("exit_ip") or x["turn_ip"],
                    "cred": x.get("cred") or "",
                    "speed_kbs": x.get("speed_kbs"),
                    "delay_ms": x.get("delay_ms"),
                    "loss_pct": x.get("loss_pct"),
                    "loss_probes": x.get("loss_probes"),
                    "loss_success": x.get("loss_success"),
                    "test_cf_ip": x.get("cf_ip"),
                    "test_cf_colo": x.get("cf_colo"),
                    "country": x.get("country") or "",
                    "country_code": x.get("country_code") or "",
                    "city": x.get("city") or "",
                    "quality_ip": x.get("quality_ip") or "",
                    "qualityIpMatched": x.get("qualityIpMatched") is True,
                    "qualityRoute": x.get("qualityRoute") or "",
                    "fraudScore": x.get("fraudScore"),
                    "isResidential": x.get("isResidential"),
                    "cfControlIndex": x.get("cfControlIndex"),
                    "cfQualityIp": x.get("cfQualityIp") or "",
                }
                for xs in by_reg.values()
                for x in xs
            ],
            "counts": {r: len(xs) for r, xs in by_reg.items()},
            "total": sum(len(xs) for xs in by_reg.values()),
            "tested_nodes": len(nodes),
            "alive_delay": len(alive_names),
            "loss_probes_per_node": max(1, args.loss_probes),
        }

        out_path = Path(args.out)
        out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
        log(f"[out] {out_path} total={doc['total']}")

        if not args.dry_run:
            try:
                put_r2(R2_KEY, doc)
                # 同步一份给 turn-dmit 可读的 turn 优先列表（不覆盖全量 report）
                put_r2(
                    "turn/turn_fast_regions.json",
                    {
                        "updated_at": doc["updated_at"],
                        "regions": fast_regions,
                        "note": "fast TURN IPs per region for turn-dmit pairing",
                    },
                )
            except Exception as e:
                log(f"[r2] fail: {e}")
                return 1

        if doc["total"] == 0:
            log("[fallback] live test empty — rank by turn_report latency/speed_kbs (still CF-entry design note)")
            fb_reg: dict[str, list] = defaultdict(list)
            for reg in regions:
                for turn in by_turn.get(reg) or []:
                    fb_reg[reg].append({
                        "region": reg,
                        "turn_ip": turn["IP"],
                        "turn_port": int(turn.get("Port") or 3478),
                        "cred": "" if turn.get("NoAuth") else str(turn.get("Cred") or ""),
                        "speed_kbs": turn.get("speed_kbs"),
                        "delay_ms": turn.get("latency_ms"),
                        "loss_pct": None,
                        "loss_probes": 0,
                        "loss_success": 0,
                        "test_cf_ip": None,
                        "fallback": True,
                        "country": turn.get("Country") or "",
                        "country_code": turn.get("country_code") or "",
                        "city": turn.get("City") or "",
                    })
                fb_reg[reg] = sorted(
                    fb_reg[reg],
                    key=lambda x: (x.get("delay_ms") or 9e9, -(float(x.get("speed_kbs") or 0))),
                )
                if args.top > 0:
                    fb_reg[reg] = fb_reg[reg][: args.top]
            fast_regions = {r: [x["turn_ip"] for x in xs] for r, xs in fb_reg.items()}
            doc = {
                "updated_at": utc_now(),
                "sni": XUDP_HOST,
                "global_test": args.global_mode,
                "note": "FALLBACK rank from turn_report (live mihomo path failed); prefer re-run",
                "fallback": True,
                "regions": fast_regions,
                "items": [x for xs in fb_reg.values() for x in xs],
                "counts": {r: len(xs) for r, xs in fb_reg.items()},
                "total": sum(len(xs) for xs in fb_reg.values()),
            }
            out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
            if not args.dry_run:
                try:
                    put_r2(R2_KEY, doc)
                    put_r2("turn/turn_fast_regions.json", {"updated_at": doc["updated_at"], "regions": fast_regions, "fallback": True})
                except Exception as e:
                    log(f"[r2] fail: {e}")
                    return 1

        print(
            json.dumps(
                {
                    "ok": True,
                    "counts": doc["counts"],
                    "total": doc["total"],
                    "updated_at": doc["updated_at"],
                    "fallback": bool(doc.get("fallback")),
                },
                ensure_ascii=False,
            )
        )
        return 0 if doc["total"] > 0 else 2
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            log_f.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
