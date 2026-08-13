#!/usr/bin/env python3
"""把上次可用 TURN 回灌到本次 FOFA 候选，避免可用旧节点因未被搜到而丢失。"""
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--input", default="turn_candidates.txt")
    parser.add_argument("--output", default="turn_candidates.txt")
    args = parser.parse_args()

    candidates: set[str] = set()
    source = Path(args.input)
    if source.exists():
        candidates.update(line.strip() for line in source.read_text().splitlines() if line.strip())
    before = len(candidates)

    request = urllib.request.Request(args.report, headers={"User-Agent": "turn-candidate-merge/1.0"})
    with urllib.request.urlopen(request, timeout=45) as response:
        report = json.loads(response.read().decode())
    servers = report.get("servers") or report.get("sub_servers") or []
    old = 0
    for server in servers:
        ip = str(server.get("IP") or "").strip()
        port = int(server.get("Port") or 3478)
        if ip and ":" not in ip and 0 < port < 65536:
            candidates.add(f"{ip}:{port}")
            old += 1

    def key(value: str):
        host, port = value.rsplit(":", 1)
        try:
            return tuple(map(int, host.split("."))), int(port)
        except ValueError:
            return ((999,), 65535)

    Path(args.output).write_text("\n".join(sorted(candidates, key=key)) + "\n")
    print(f"new={before} old_usable={old} merged={len(candidates)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
