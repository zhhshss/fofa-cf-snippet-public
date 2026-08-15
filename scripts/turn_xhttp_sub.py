#!/usr/bin/env python3
"""根据 TURN 测速结果生成 XHTTP/stream-one Shadowrocket 订阅。"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from r2_store import client

REPORT_URL = os.environ.get("TURN_API", "").strip()
FAST_URL = os.environ.get("TURN_FAST_API", "").strip()
XHTTP_HOST = os.environ.get("XHTTP_HOST", "").strip()
XHTTP_UUID = os.environ.get("XHTTP_UUID", "").strip()
XHTTP_ALPN = os.environ.get("XHTTP_ALPN", "h2").strip()
XHTTP_GLOBAL = "0" if os.environ.get("XHTTP_GLOBAL") == "0" else "1"
R2_BUCKET = os.environ.get("R2_BUCKET", "fofa").strip()
R2_PREFIX = os.environ.get("R2_PREFIX", "turn/").strip().strip("/") + "/"


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "turn-xhttp-sub/1.0"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.loads(response.read().decode("utf-8"))


def number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def endpoint(item: dict[str, Any]) -> tuple[str, int]:
    ip = str(item.get("IP") or item.get("turn_ip") or "").strip()
    port = int(item.get("Port") or item.get("turn_port") or 3478)
    return ip, port


def entries() -> list[tuple[str, int]]:
    """支持逗号分隔的自定义 Cloudflare 优选 IP/域名，可附端口。"""
    raw = os.environ.get("XHTTP_ENTRIES") or os.environ.get("XHTTP_ENTRY") or XHTTP_HOST
    default_port = int(os.environ.get("XHTTP_ENTRY_PORT", "443"))
    result: list[tuple[str, int]] = []
    for value in raw.split(","):
        value = value.strip()
        if not value:
            continue
        host = value
        port = default_port
        if value.count(":") == 1:
            maybe_host, maybe_port = value.rsplit(":", 1)
            if maybe_port.isdigit():
                host, port = maybe_host, int(maybe_port)
        if host and 0 < port < 65536:
            result.append((host, port))
    if not result:
        result.append((XHTTP_HOST, default_port))
    return result


def credential(item: dict[str, Any]) -> str:
    if item.get("NoAuth") is True:
        return ""
    return str(item.get("Cred") or item.get("cred") or "").strip()


def text(value: Any) -> str:
    return "-".join(str(value or "").strip().split())


def compact_number(value: Any, digits: int = 0) -> str:
    if value is None or value == "":
        return ""
    try:
        result = f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return text(value)
    return result.rstrip("0").rstrip(".") if "." in result else result


def node_remark(server: dict[str, Any], index: int, entry: str, entry_port: int) -> str:
    ip, port = endpoint(server)
    tested_speed = number(server.get("tested_speed_kbs"))
    country_code = text(server.get("country_code")).upper()
    country = country_code or text(server.get("Country"))
    city = text(server.get("City"))
    region = text(server.get("tested_region"))
    geography = "/".join(value for value in (country, city) if value)
    if region and region.lower() not in {country.lower(), country_code.lower()}:
        geography = f"{geography}@{region}" if geography else region

    protocol = (
        ("T" if server.get("TCP") is True else "")
        + ("U" if server.get("UDP") is True else "")
    ) or "?"
    capability = "/".join(filter(None, (
        text(server.get("Mode")), protocol,
        "NA" if server.get("NoAuth") is True else "AU",
    )))
    parts = [f"XH{index:02d}"]
    if geography:
        parts.append(geography)
    parts.extend((f"T:{ip}:{port}", capability))

    exit_ip = text(server.get("exit_ip"))
    if exit_ip and exit_ip != ip:
        parts.append(f"E:{exit_ip}")

    quality_ip = text(server.get("quality_ip"))
    expected_quality_ip = text(server.get("exit_ip")) or ip
    quality_matches = bool(quality_ip and quality_ip == expected_quality_ip)
    fraud_score = compact_number(server.get("fraudScore"))
    if quality_matches and fraud_score != "":
        parts.append(f"Q:F{fraud_score}")
    elif quality_ip or fraud_score:
        parts.append("Q:?")
    cf_control_index = compact_number(server.get("cfControlIndex"))
    if cf_control_index:
        parts.append(f"CFI:{cf_control_index}")

    measured: list[str] = []
    if tested_speed > 0:
        measured.append(f"{compact_number(tested_speed / 1024, 1)}M")
    if compact_number(server.get("tested_delay_ms")):
        measured.append(f"{compact_number(server.get('tested_delay_ms'))}ms")
    if compact_number(server.get("tested_loss_pct"), 1):
        measured.append(f"L{compact_number(server.get('tested_loss_pct'), 1)}%")
    success = compact_number(server.get("loss_success"))
    probes = compact_number(server.get("loss_probes"))
    if success and probes:
        measured.append(f"{success}/{probes}")
    if measured:
        parts.append(f"P:{'/'.join(measured)}")

    scanned: list[str] = []
    if compact_number(server.get("latency_ms")):
        scanned.append(f"S{compact_number(server.get('latency_ms'))}ms")
    if compact_number(server.get("relay_ms")):
        scanned.append(f"R{compact_number(server.get('relay_ms'))}ms")
    if compact_number(server.get("speed_kbs"), 2):
        scanned.append(f"{compact_number(server.get('speed_kbs'), 2)}K")
    if scanned:
        parts.append("/".join(scanned))

    software = text(server.get("SW"))
    if software.lower() not in {"", "-", "--", "n/a", "unknown"}:
        parts.append(f"SW:{software}")
    cf_ip = text(server.get("test_cf_ip"))
    cf_colo = text(server.get("test_cf_colo"))
    if cf_ip or cf_colo:
        parts.append(f"CF:{cf_colo}{'@' if cf_colo and cf_ip else ''}{cf_ip}")
    parts.append(f"IN:{entry}:{entry_port}")
    return "|".join(parts)


def rank_servers(report: dict[str, Any], fast: dict[str, Any]) -> list[dict[str, Any]]:
    servers = report.get("sub_servers") or report.get("servers") or []
    usable: dict[tuple[str, int], dict[str, Any]] = {}
    for server in servers:
        if not isinstance(server, dict):
            continue
        if server.get("Mode") != "ALL" and not (server.get("TCP") and server.get("UDP")):
            continue
        ip, port = endpoint(server)
        if ip and ":" not in ip and 0 < port < 65536:
            usable[(ip, port)] = dict(server)

    # GHA 实际 XHTTP/TURN 测速为最高优先级；同一 TURN 的最佳入口结果覆盖扫描粗测。
    measured: dict[tuple[str, int], dict[str, Any]] = {}
    for item in fast.get("items") or []:
        if not isinstance(item, dict):
            continue
        ip, port = endpoint(item)
        key = (ip, port)
        if key not in usable:
            continue
        current = measured.get(key)
        if current is None or number(item.get("speed_kbs")) > number(current.get("speed_kbs")):
            measured[key] = item

    rows: list[dict[str, Any]] = []
    for key, server in usable.items():
        speed = measured.get(key)
        server["tested_speed_kbs"] = number(speed.get("speed_kbs")) if speed else 0.0
        server["tested_delay_ms"] = int(number(speed.get("delay_ms"), 0)) if speed else 0
        server["tested_loss_pct"] = number(speed.get("loss_pct"), 100.0) if speed else 100.0
        server["tested_region"] = str(speed.get("region") or "") if speed else ""
        if speed:
            server["Country"] = str(speed.get("country") or server.get("Country") or "")
            server["country_code"] = str(speed.get("country_code") or "")
            server["City"] = str(speed.get("city") or server.get("City") or "")
            server["loss_probes"] = speed.get("loss_probes")
            server["loss_success"] = speed.get("loss_success")
            server["test_cf_ip"] = str(speed.get("test_cf_ip") or "")
            server["test_cf_colo"] = str(speed.get("test_cf_colo") or "")
            server["quality_ip"] = str(speed.get("quality_ip") or "")
            server["qualityIpMatched"] = speed.get("qualityIpMatched") is True
            server["qualityRoute"] = str(speed.get("qualityRoute") or "")
            server["qualitySource"] = str(speed.get("qualitySource") or "")
            server["qualityUpdatedAt"] = str(speed.get("qualityUpdatedAt") or "")
            server["fraudScore"] = speed.get("fraudScore")
            server["qualityType"] = str(speed.get("qualityType") or "")
            server["cfControlIndex"] = speed.get("cfControlIndex")
        rows.append(server)

    rows.sort(
        key=lambda item: (
            0 if item["tested_speed_kbs"] > 0 else 1,
            item["tested_loss_pct"],
            -item["tested_speed_kbs"],
            item["tested_delay_ms"] or 10**9,
            -number(item.get("speed_kbs")),
            int(number(item.get("latency_ms"), 10**9)),
            endpoint(item),
        )
    )
    return rows


def vless_uri(server: dict[str, Any], index: int, entry: str, entry_port: int) -> str:
    ip, port = endpoint(server)
    cred = credential(server)
    auth = f"{cred}@" if cred else ""
    # 新 XHTTP Worker 的 TCP 与 UDP 都强制经此 TURN，因此不再使用旧 global 参数。
    turn_authority = base64.urlsafe_b64encode(
        f"{auth}{ip}:{port}".encode()
    ).decode().rstrip("=")
    path = f"/turn/{turn_authority}?global={XHTTP_GLOBAL}"
    remark = node_remark(server, index, entry, entry_port)

    query = {
        "path": path,
        "remarks": remark,
        "obfsParam": json.dumps({"Host": XHTTP_HOST}, separators=(",", ":")),
        "obfs": "xhttp",
        "tls": "1",
        "peer": XHTTP_HOST,
        "alpn": XHTTP_ALPN,
        "global": XHTTP_GLOBAL,
        "udp": "1",
        "mode": "stream-one",
        "fingerprint": "Chrome",
    }
    authority = base64.urlsafe_b64encode(
        f":{XHTTP_UUID}@{entry}:{entry_port}".encode()
    ).decode().rstrip("=")
    return (
        f"vless://{authority}?{urllib.parse.urlencode(query)}"
    )


def put_text(key: str, body: str, content_type: str) -> None:
    client().put_object(
        Bucket=R2_BUCKET,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType=content_type,
        CacheControl="no-cache, max-age=30",
    )


def main() -> int:
    report = fetch_json(REPORT_URL)
    try:
        fast = fetch_json(FAST_URL)
    except Exception as error:
        print(f"[warn] fast report unavailable: {error}", file=sys.stderr)
        fast = {}

    servers = rank_servers(report, fast)
    if not servers:
        raise SystemExit("no usable Mode=ALL TURN server")

    entry_list = entries()
    nodes = [
        vless_uri(server, index, entry, entry_port)
        for entry, entry_port in entry_list
        for index, server in enumerate(servers, 1)
    ]
    plain = "\n".join(nodes) + "\n"
    subscription = base64.b64encode(plain.encode()).decode()
    manifest = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "transport": "xhttp",
        "mode": "stream-one",
        "host": XHTTP_HOST,
        "entries": [f"{host}:{port}" for host, port in entry_list],
        "alpn": XHTTP_ALPN,
        "count": len(nodes),
        "sort": "measured loss asc, speed desc, delay asc, scan speed desc, scan latency asc",
        "servers": servers,
    }

    Path("turn_xhttp_nodes.txt").write_text(plain, encoding="utf-8")
    Path("turn_xhttp_sub.txt").write_text(subscription, encoding="utf-8")
    Path("turn_xhttp_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    if os.environ.get("TURN_SUB_DRY_RUN", "") != "1":
        put_text(R2_PREFIX + "turn_xhttp_nodes.txt", plain, "text/plain; charset=utf-8")
        put_text(R2_PREFIX + "turn_xhttp_sub.txt", subscription, "text/plain; charset=utf-8")
        put_text(
            R2_PREFIX + "turn_xhttp_manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            "application/json; charset=utf-8",
        )
    print(
        json.dumps(
            {
                "ok": True,
                "count": len(nodes),
                "host": XHTTP_HOST,
                "entries": [f"{host}:{port}" for host, port in entry_list],
                "top": [endpoint(server)[0] for server in servers[:5]],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
