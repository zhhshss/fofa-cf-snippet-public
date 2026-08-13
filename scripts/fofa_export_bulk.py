#!/usr/bin/env python3
"""本地/GHA 串行吃免费 web_data：多国 × 时间窗 × page1 size≤50。

不受 Snippet 单次子请求上限限制（每次只打 /v1/search page1）。
用法:
  python3 scripts/fofa_export_bulk.py -q 'protocol="stun" && port="3478"' \\
      --countries SG,JP,KR,HK,TW --days 400 --window-days 14 \\
      --limit 3000 -o turn_candidates.txt

  # TURN 预设
  python3 scripts/fofa_export_bulk.py --preset turn -o turn_candidates.txt
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path
from typing import Any

FOFA_BASE = os.environ.get("FOFA_BASE", "").strip().rstrip("/")
FOFA_TOKEN = os.environ.get("FOFA_TOKEN", "").strip()

TURN_BASE = 'protocol="stun" && port="3478" && is_domain=false'
DEFAULT_COUNTRIES = ["SG", "JP", "KR", "HK", "TW"]


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def ymd(d: date) -> str:
    return d.isoformat()


def time_windows(days: int, window_days: int) -> list[tuple[str, str]]:
    """[(after, before), ...] 旧窗在前。"""
    end = date.today()
    oldest = end - timedelta(days=max(1, days))
    step = max(1, window_days)
    out: list[tuple[str, str]] = []
    cursor = end
    while cursor > oldest and len(out) < 120:
        before = cursor
        after = cursor - timedelta(days=step)
        if after < oldest:
            after = oldest
        out.append((ymd(after), ymd(before)))
        cursor = after
    out.reverse()
    return out


def http_json(url: str, timeout: float = 45) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {FOFA_TOKEN}",
            "Accept": "application/json",
            "User-Agent": "fofa-export-bulk/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def search_page1(q: str, size: int = 50, retries: int = 4) -> dict[str, Any]:
    size = min(max(size, 2), 50)
    u = (
        f"{FOFA_BASE}/v1/search?"
        f"q={urllib.parse.quote(q)}&size={size}&page=1"
    )
    last: dict[str, Any] = {}
    for attempt in range(1, retries + 1):
        try:
            d = http_json(u)
            if d.get("ok"):
                return d
            last = d
            err = d.get("error")
            log(f"  search fail try{attempt}: {err}")
        except Exception as e:
            last = {"ok": False, "error": str(e)}
            log(f"  search err try{attempt}: {e}")
        time.sleep(min(8, attempt * 1.5))
    return last if last else {"ok": False, "error": "empty"}


def asset_key(a: dict[str, Any]) -> str:
    ip = a.get("ip") or ""
    port = a.get("port") or 0
    if not ip or not port:
        return ""
    return f"{ip}:{port}"


def export_bulk(
    base_q: str,
    *,
    countries: list[str] | None,
    days: int,
    window_days: int,
    size: int,
    limit: int,
    sleep_s: float,
    ports: set[int] | None,
) -> list[str]:
    """返回去重后的 ip:port 列表。"""
    windows = time_windows(days, window_days)
    # 无 after/before 时：base 热数据 + 各窗；有国家则展开
    jobs: list[tuple[str, str]] = []  # (label, query)

    def add_jobs(label_prefix: str, qcore: str) -> None:
        jobs.append((f"{label_prefix}/base", qcore))
        if "after=" in qcore or "before=" in qcore:
            return
        for after, before in windows:
            jobs.append(
                (
                    f"{label_prefix}/{after}_{before}",
                    f'({qcore}) && after="{after}" && before="{before}"',
                )
            )

    if countries:
        for c in countries:
            c = c.strip()
            if not c:
                continue
            # 已有 country= 则不叠
            if "country=" in base_q:
                add_jobs(c or "Q", base_q)
                break
            add_jobs(c, f'{base_q} && country="{c}"')
    else:
        add_jobs("Q", base_q)

    seen: dict[str, bool] = {}
    out: list[str] = []
    fail_streak = 0

    log(
        f"[bulk] base={FOFA_BASE} jobs={len(jobs)} "
        f"days={days} window={window_days}d size={size} limit={limit}"
    )

    for i, (label, q) in enumerate(jobs, 1):
        if len(out) >= limit:
            break
        d = search_page1(q, size=size)
        if not d.get("ok"):
            fail_streak += 1
            log(f"[{i}/{len(jobs)}] {label} FAIL streak={fail_streak}")
            if fail_streak >= 5:
                log("[bulk] 连续失败过多，停止")
                break
            time.sleep(sleep_s * 2)
            continue
        fail_streak = 0
        assets = ((d.get("data") or {}).get("assets")) or []
        added = 0
        for a in assets:
            k = asset_key(a)
            if not k or k in seen:
                continue
            port = int(a.get("port") or 0)
            if ports and port not in ports:
                continue
            seen[k] = True
            out.append(k)
            added += 1
            if len(out) >= limit:
                break
        acct = (d.get("account") or "")[:28]
        log(
            f"[{i}/{len(jobs)}] {label} +{added} "
            f"fetch={len(assets)} total={len(out)} acct={acct}"
        )
        time.sleep(sleep_s)

    log(f"[bulk] done unique={len(out)}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="FOFA free web_data bulk export (serial page1)")
    ap.add_argument("-q", "--query", default="", help="FOFA 查询（可无 country，用 --countries 展开）")
    ap.add_argument(
        "--preset",
        choices=["", "turn"],
        default="",
        help="turn = stun:3478 亚太预设",
    )
    ap.add_argument(
        "--countries",
        default="SG,JP,KR,HK,TW",
        help="逗号分隔国家代码；空=不按国展开",
    )
    ap.add_argument("--days", type=int, default=400, help="回溯天数")
    ap.add_argument("--window-days", type=int, default=14, help="每个时间窗天数（越小越不重叠）")
    ap.add_argument("--size", type=int, default=50, help="每窗条数≤50")
    ap.add_argument("--limit", type=int, default=3000, help="最多保留去重条数")
    ap.add_argument("--sleep", type=float, default=0.35, help="请求间隔秒")
    ap.add_argument(
        "-o",
        "--out",
        default="fofa_export.txt",
        help="输出 ip:port 列表",
    )
    ap.add_argument(
        "--ports",
        default="3478,3479,5349",
        help="保留端口，空=全部",
    )
    ap.add_argument("--json", dest="json_out", default="", help="可选 JSON 报告路径")
    args = ap.parse_args()

    q = (args.query or "").strip()
    if args.preset == "turn":
        q = TURN_BASE
    if not q:
        ap.error("需要 -q 或 --preset turn")

    countries_raw = (args.countries or "").strip()
    countries = [c.strip() for c in countries_raw.split(",") if c.strip()] if countries_raw else None
    ports: set[int] | None = None
    if (args.ports or "").strip():
        ports = {int(x) for x in args.ports.split(",") if x.strip().isdigit()}

    t0 = time.time()
    items = export_bulk(
        q,
        countries=countries,
        days=args.days,
        window_days=args.window_days,
        size=args.size,
        limit=args.limit,
        sleep_s=args.sleep,
        ports=ports,
    )
    out_path = Path(args.out)
    out_path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
    log(f"[bulk] wrote {out_path} ({len(items)} lines, {time.time()-t0:.1f}s)")

    if args.json_out:
        rep = {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "query": q,
            "countries": countries,
            "count": len(items),
            "days": args.days,
            "window_days": args.window_days,
            "items": items,
        }
        Path(args.json_out).write_text(
            json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(str(out_path))
    return 0 if items else 1


if __name__ == "__main__":
    raise SystemExit(main())
