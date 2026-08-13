#!/usr/bin/env python3
"""Probe FOFA from GHA. Prefer FOFA_PROXY; else DIRECT.

Env:
  FOFA_PROBE_SOFT=1  → on total failure exit 0 (warning only). Default 1.
  FOFA_ALLOW_DIRECT=1 → try runner direct (default 1).
"""
from __future__ import annotations

import os
import sys

import requests

AUTH_BASE = os.environ.get("FOFA_AUTH_BASE", "").strip().rstrip("/")
WEB_ORIGIN = os.environ.get("FOFA_WEB_ORIGIN", "").strip().rstrip("/")
WEB_REFERER = os.environ.get("FOFA_WEB_REFERER", "").strip()
PROBE_EMAIL = os.environ.get("FOFA_PROBE_EMAIL", "").strip()
if not all((AUTH_BASE, WEB_ORIGIN, WEB_REFERER, PROBE_EMAIL)):
    raise RuntimeError(
        "FOFA_AUTH_BASE, FOFA_WEB_ORIGIN, FOFA_WEB_REFERER and FOFA_PROBE_EMAIL are required"
    )
URL = f"{AUTH_BASE}/auth/verification_code"
BODY = {"account": PROBE_EMAIL, "type": "email", "lang": "en"}
HDR = {
    "Content-Type": "application/json",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Origin": WEB_ORIGIN,
    "Referer": WEB_REFERER,
}


def try_once(label: str, proxies) -> bool:
    try:
        r = requests.post(URL, json=BODY, headers=HDR, proxies=proxies, timeout=25)
        ok = r.status_code == 200 and r.text[:1] == "{"
        snippet = r.text[:120].replace("\n", " ")
        print(f"{label}: status={r.status_code} ok={ok} body={snippet!r}")
        return ok
    except Exception as e:
        print(f"{label}: ERR {type(e).__name__}: {e}")
        return False


def main() -> int:
    soft = (os.environ.get("FOFA_PROBE_SOFT") or "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    allow_direct = (os.environ.get("FOFA_ALLOW_DIRECT") or "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    candidates: list[tuple[str, dict | None]] = []
    for key in ("FOFA_PROXY",):
        v = (os.environ.get(key) or "").strip()
        if v and v.lower() not in ("direct", "none", "-"):
            scheme = v.split("://")[0] if "://" in v else "?"
            candidates.append((f"proxy:{scheme}", {"http": v, "https": v}))
    multi = os.environ.get("FOFA_PROXIES") or ""
    for i, ln in enumerate(multi.replace(",", "\n").splitlines()):
        ln = ln.strip()
        if not ln or ln.lower() in ("direct", "none", "-"):
            continue
        scheme = ln.split("://")[0] if "://" in ln else "?"
        candidates.append((f"proxies[{i}]:{scheme}", {"http": ln, "https": ln}))

    for label, px in candidates:
        if try_once(label, px):
            if px:
                out = os.environ.get("GITHUB_ENV")
                if out:
                    with open(out, "a", encoding="utf-8") as f:
                        f.write(f"FOFA_PROXY={px['http']}\n")
            print("EXIT=proxy")
            return 0

    if allow_direct:
        if try_once("DIRECT", None):
            out = os.environ.get("GITHUB_ENV")
            if out:
                with open(out, "a", encoding="utf-8") as f:
                    f.write("FOFA_PROXY=\n")
                    f.write("FOFA_ALLOW_DIRECT=1\n")
            print("EXIT=direct")
            return 0

    msg = "all proxies dead and DIRECT blocked (CF challenge / 403 common on GHA IPs)"
    if soft:
        print(f"WARN: {msg} — FOFA_PROBE_SOFT=1, continue (maintain may keep accounts / skip register)")
        print("EXIT=soft-fail")
        # still clear broken proxy so maintain uses direct-or-none path cleanly
        out = os.environ.get("GITHUB_ENV")
        if out:
            with open(out, "a", encoding="utf-8") as f:
                f.write("FOFA_EGRESS_OK=0\n")
        return 0

    print(f"FATAL: {msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
