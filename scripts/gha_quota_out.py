#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys

raw = subprocess.check_output([sys.executable, "redis_store.py", "quota"], text=True)
print(raw)
pathlib.Path("/tmp/quota.json").write_text(raw)
q = json.loads(raw)
live = q.get("accounts_live")
remain = (q.get("web_query") or {}).get("remain")
print(f"::notice::live={live} remain_q={remain}")
out = os.environ.get("GITHUB_OUTPUT")
if out:
    with open(out, "a", encoding="utf-8") as f:
        f.write(f"live={live}\nremain={remain}\n")
