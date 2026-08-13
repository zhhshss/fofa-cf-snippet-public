#!/usr/bin/env python3
"""FOFA hot pool on Upstash Redis (REST).

Keys:
  fofa:pool                 JSON compact pool (accounts + quota meta)
  fofa:acc:<name>           full account JSON
  fofa:usage:<name>         hash: used_web_query, used_web_data, disabled, fail_reason, last_used_at
  fofa:meta:state           auto_refill / sync state

Runtime (Snippet) reads fofa:pool via REST; usage increments via HINCRBY.
R2 remains durable backup via r2_store.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

def _required_env(key: str) -> str:
    """Return a required runtime setting without embedding private defaults."""
    value = os.environ.get(key, "").strip()
    if not value:
        raise RuntimeError(f"missing required environment variable: {key}")
    return value


UPSTASH_URL = _required_env("UPSTASH_REDIS_REST_URL").rstrip("/")
UPSTASH_TOKEN = _required_env("UPSTASH_REDIS_REST_TOKEN")

POOL_KEY = "fofa:pool"
ACC_PREFIX = "fofa:acc:"
USAGE_PREFIX = "fofa:usage:"
STATE_KEY = "fofa:meta:state"
DEFAULT_WEB_QUERY = 300
DEFAULT_WEB_DATA = 3000


def _upstash_timeout() -> float:
    try:
        return float(os.environ.get("UPSTASH_TIMEOUT", "30") or 30)
    except Exception:
        return 30.0


def _upstash_retries() -> int:
    try:
        return max(1, int(os.environ.get("UPSTASH_RETRIES", "4") or 4))
    except Exception:
        return 4


def _req(command: list[Any], *, timeout: float | None = None) -> Any:
    """POST one Redis command to Upstash REST; retries on timeout/5xx."""
    timeout = _upstash_timeout() if timeout is None else timeout
    body = json.dumps(command).encode("utf-8")
    last_err: Exception | None = None
    for attempt in range(1, _upstash_retries() + 1):
        req = urllib.request.Request(
            UPSTASH_URL,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {UPSTASH_TOKEN}",
                "Content-Type": "application/json",
                "User-Agent": "fofa-redis-store/1.1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8"))
            if isinstance(data, dict) and data.get("error"):
                raise RuntimeError(f"upstash error: {data['error']}")
            return data.get("result") if isinstance(data, dict) else data
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            last_err = RuntimeError(f"upstash {e.code}: {err}")
            # 4xx（非 429）不重试
            if e.code and 400 <= e.code < 500 and e.code != 429:
                raise last_err from e
        except Exception as e:
            last_err = e
        sleep_s = min(12.0, 0.8 * (2 ** (attempt - 1)))
        print(
            f"[upstash] try{attempt}/{_upstash_retries()} fail: {last_err}; sleep {sleep_s:.1f}s",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(sleep_s)
    raise RuntimeError(f"upstash exhausted retries: {last_err}") from last_err


def _pipeline(commands: list[list[Any]], *, timeout: float | None = None) -> list[Any]:
    timeout = (_upstash_timeout() + 15) if timeout is None else timeout
    body = json.dumps(commands).encode("utf-8")
    last_err: Exception | None = None
    for attempt in range(1, _upstash_retries() + 1):
        req = urllib.request.Request(
            f"{UPSTASH_URL}/pipeline",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {UPSTASH_TOKEN}",
                "Content-Type": "application/json",
                "User-Agent": "fofa-redis-store/1.1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8"))
            if not isinstance(data, list):
                raise RuntimeError(f"upstash pipeline bad resp: {data!r}")
            out = []
            for item in data:
                if isinstance(item, dict) and item.get("error"):
                    out.append(None)
                else:
                    out.append(item.get("result") if isinstance(item, dict) else item)
            return out
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            last_err = RuntimeError(f"upstash pipeline {e.code}: {err}")
            if e.code and 400 <= e.code < 500 and e.code != 429:
                raise last_err from e
        except Exception as e:
            last_err = e
        sleep_s = min(12.0, 0.8 * (2 ** (attempt - 1)))
        print(
            f"[upstash-pipeline] try{attempt} fail: {last_err}; sleep {sleep_s:.1f}s",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(sleep_s)
    raise RuntimeError(f"upstash pipeline exhausted: {last_err}") from last_err


def ping() -> str:
    return str(_req(["PING"], timeout=max(15.0, _upstash_timeout())) or "")


def get_json(key: str, default: Any = None) -> Any:
    raw = _req(["GET", key])
    if raw is None:
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default


def set_json(key: str, obj: Any, *, ex: int | None = None) -> None:
    payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if ex:
        _req(["SET", key, payload, "EX", int(ex)])
    else:
        _req(["SET", key, payload])


def delete_key(key: str) -> None:
    _req(["DEL", key])


def keys(pattern: str) -> list[str]:
    # Upstash supports KEYS; fine for small pool
    r = _req(["KEYS", pattern]) or []
    return list(r) if isinstance(r, list) else []


def hgetall(key: str) -> dict[str, str]:
    r = _req(["HGETALL", key]) or []
    if isinstance(r, dict):
        return {str(k): str(v) for k, v in r.items()}
    out: dict[str, str] = {}
    if isinstance(r, list):
        for i in range(0, len(r) - 1, 2):
            out[str(r[i])] = str(r[i + 1])
    return out


def hset_map(key: str, mapping: dict[str, Any]) -> None:
    args: list[Any] = ["HSET", key]
    for k, v in mapping.items():
        if v is None:
            continue
        args.extend([str(k), str(v)])
    if len(args) > 2:
        _req(args)


def _as_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return default
        return int(v)
    except Exception:
        return default


def normalize_quota(a: dict) -> dict:
    dl = a.get("data_limit") if isinstance(a.get("data_limit"), dict) else {}
    web_query = _as_int(dl.get("web_query"), DEFAULT_WEB_QUERY)
    web_data = _as_int(dl.get("web_data"), DEFAULT_WEB_DATA)
    if web_query <= 0 and not dl:
        web_query = DEFAULT_WEB_QUERY
    if web_data <= 0 and not dl:
        web_data = DEFAULT_WEB_DATA
    used_q = max(0, _as_int(a.get("used_web_query"), 0))
    used_d = max(0, _as_int(a.get("used_web_data"), 0))
    a["data_limit"] = {
        "web_query": web_query,
        "web_data": web_data,
        "api_query": _as_int(dl.get("api_query"), 0),
        "api_data": _as_int(dl.get("api_data"), 0),
        "data": dl.get("data", -1),
        "query": dl.get("query", -1),
    }
    a["used_web_query"] = used_q
    a["used_web_data"] = used_d
    a["remain_web_query"] = max(0, web_query - used_q) if web_query >= 0 else -1
    a["remain_web_data"] = max(0, web_data - used_d) if web_data >= 0 else -1
    return a


def compact_account(a: dict) -> dict:
    a = normalize_quota(dict(a))
    dl = a.get("data_limit") or {}
    return {
        "name": a.get("name") or (a.get("email") or "acc").split("@")[0],
        "email": a.get("email"),
        "password": a.get("password"),
        "api_key": a.get("api_key") or "",
        "access_token": a.get("access_token") or "",
        "disabled": bool(a.get("disabled")),
        "data_limit": {
            "web_query": dl.get("web_query", DEFAULT_WEB_QUERY),
            "web_data": dl.get("web_data", DEFAULT_WEB_DATA),
        },
        "used_web_query": a.get("used_web_query", 0),
        "used_web_data": a.get("used_web_data", 0),
        "remain_web_query": a.get("remain_web_query", DEFAULT_WEB_QUERY),
        "remain_web_data": a.get("remain_web_data", DEFAULT_WEB_DATA),
    }


def load_usage(name: str) -> dict:
    h = hgetall(f"{USAGE_PREFIX}{name}")
    if not h:
        return {}
    return {
        "name": name,
        "used_web_query": _as_int(h.get("used_web_query"), 0),
        "used_web_data": _as_int(h.get("used_web_data"), 0),
        "disabled": str(h.get("disabled", "")).lower() in ("1", "true", "yes"),
        "fail_reason": h.get("fail_reason") or None,
        "last_used_at": h.get("last_used_at") or None,
    }


def merge_usage(acc: dict, usage: dict | None) -> dict:
    if usage:
        acc["used_web_query"] = max(
            _as_int(acc.get("used_web_query"), 0), _as_int(usage.get("used_web_query"), 0)
        )
        acc["used_web_data"] = max(
            _as_int(acc.get("used_web_data"), 0), _as_int(usage.get("used_web_data"), 0)
        )
        if usage.get("disabled"):
            acc["disabled"] = True
            acc["fail_reason"] = usage.get("fail_reason") or acc.get("fail_reason") or "quota"
        if usage.get("last_used_at"):
            acc["last_used_at"] = usage["last_used_at"]
    return normalize_quota(acc)


def put_account(acc: dict, *, refresh_pool: bool = True) -> None:
    acc = dict(acc)
    name = acc.get("name") or (acc.get("email") or "acc").split("@")[0]
    acc["name"] = name
    usage = load_usage(name)
    acc = merge_usage(acc, usage)
    set_json(f"{ACC_PREFIX}{name}", acc)
    # mirror local
    try:
        import r2_store

        r2_store.save_local(acc)
        r2_store.put_json(f"{r2_store.ACC_PREFIX}{name}.json", acc)
    except Exception:
        acc_dir = ROOT / "account"
        acc_dir.mkdir(exist_ok=True)
        (acc_dir / f"{name}.json").write_text(
            json.dumps(acc, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    if refresh_pool:
        rebuild_pool()


def list_accounts(*, include_disabled: bool = True) -> list[dict]:
    ks = keys(f"{ACC_PREFIX}*")
    out: list[dict] = []
    if ks:
        # pipeline GET
        cmds = [["GET", k] for k in ks]
        raws = _pipeline(cmds)
        for k, raw in zip(ks, raws):
            if raw is None:
                continue
            try:
                d = raw if isinstance(raw, dict) else json.loads(raw)
            except Exception:
                continue
            if not isinstance(d, dict) or not d.get("email") or not d.get("password"):
                continue
            name = d.get("name") or k[len(ACC_PREFIX) :]
            d["name"] = name
            d = merge_usage(d, load_usage(name))
            if not include_disabled and d.get("disabled"):
                continue
            out.append(d)
        return out

    # fallback: pool only
    pool = get_json(POOL_KEY, {}) or {}
    accs = pool.get("accounts") if isinstance(pool, dict) else pool
    if not isinstance(accs, list):
        return []
    for a in accs:
        if not isinstance(a, dict):
            continue
        if not include_disabled and a.get("disabled"):
            continue
        out.append(normalize_quota(dict(a)))
    return out


def record_usage(
    name_or_email: str,
    *,
    delta_query: int = 1,
    delta_data: int = 0,
    disabled: bool | None = None,
    reason: str | None = None,
) -> dict:
    name = name_or_email.split("@")[0] if "@" in name_or_email else name_or_email
    key = f"{USAGE_PREFIX}{name}"
    cmds: list[list[Any]] = []
    if delta_query:
        cmds.append(["HINCRBY", key, "used_web_query", int(delta_query)])
    if delta_data:
        cmds.append(["HINCRBY", key, "used_web_data", int(delta_data)])
    cmds.append(["HSET", key, "last_used_at", time.strftime("%Y-%m-%d %H:%M:%S")])
    if disabled:
        cmds.append(["HSET", key, "disabled", "1", "fail_reason", reason or "quota"])
    if cmds:
        _pipeline(cmds)
    usage = load_usage(name)
    # update full acc if present
    acc = get_json(f"{ACC_PREFIX}{name}")
    if isinstance(acc, dict):
        acc = merge_usage(acc, usage)
        if acc.get("remain_web_query") == 0 or acc.get("remain_web_data") == 0:
            acc["disabled"] = True
            acc["fail_reason"] = acc.get("fail_reason") or "quota_exhausted"
            hset_map(key, {"disabled": "1", "fail_reason": acc["fail_reason"]})
        set_json(f"{ACC_PREFIX}{name}", acc)
        rebuild_pool()
        return acc
    rebuild_pool()
    return usage


def quota_summary(accs: list[dict] | None = None) -> dict:
    if accs is None:
        accs = list_accounts(include_disabled=True)
    else:
        accs = [normalize_quota(dict(a)) for a in accs]
    live = [
        a
        for a in accs
        if not a.get("disabled")
        and _as_int(a.get("remain_web_query"), 1) != 0
        and _as_int(a.get("remain_web_data"), 1) != 0
    ]
    dead = [a for a in accs if a not in live]

    def sum_f(items: list[dict], key: str) -> int:
        return sum(max(0, _as_int(a.get(key), 0)) for a in items)

    limit_q = sum(
        max(0, _as_int((a.get("data_limit") or {}).get("web_query"), DEFAULT_WEB_QUERY))
        for a in live
    )
    limit_d = sum(
        max(0, _as_int((a.get("data_limit") or {}).get("web_data"), DEFAULT_WEB_DATA))
        for a in live
    )
    used_q = sum_f(live, "used_web_query")
    used_d = sum_f(live, "used_web_data")
    return {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "backend": "upstash",
        "accounts_live": len(live),
        "accounts_disabled": len(dead),
        "accounts_total": len(accs),
        "web_query": {"limit": limit_q, "used": used_q, "remain": max(0, limit_q - used_q)},
        "web_data": {"limit": limit_d, "used": used_d, "remain": max(0, limit_d - used_d)},
        "note": "used_* from Redis HINCRBY + local; FOFA has no public remain API",
    }


def rebuild_pool(max_accounts: int = 80) -> dict:
    """Fast rebuild: list once, pipeline usage+acc writes, single pool SET."""
    accs = list_accounts(include_disabled=True)
    if not accs:
        try:
            import r2_store
            accs = r2_store.load_local_accounts() or r2_store.list_r2_accounts(
                include_disabled=True
            )
        except Exception:
            accs = []

    # batch load all usage hashes
    names = []
    for a in accs:
        name = a.get("name") or (a.get("email") or "acc").split("@")[0]
        a["name"] = name
        names.append(name)
    usage_cmds = [["HGETALL", f"{USAGE_PREFIX}{n}"] for n in names]
    usage_raw = _pipeline(usage_cmds) if usage_cmds else []

    def parse_h(r):
        if isinstance(r, dict):
            return {str(k): str(v) for k, v in r.items()}
        out = {}
        if isinstance(r, list):
            for i in range(0, len(r) - 1, 2):
                out[str(r[i])] = str(r[i + 1])
        return out

    merged = []
    set_cmds: list[list] = []
    for a, raw in zip(accs, usage_raw or [None] * len(accs)):
        h = parse_h(raw) if raw else {}
        usage = {}
        if h:
            usage = {
                "used_web_query": _as_int(h.get("used_web_query"), 0),
                "used_web_data": _as_int(h.get("used_web_data"), 0),
                "disabled": str(h.get("disabled", "")).lower() in ("1", "true", "yes"),
                "fail_reason": h.get("fail_reason") or None,
                "last_used_at": h.get("last_used_at") or None,
            }
        a = merge_usage(dict(a), usage or None)
        set_cmds.append(
            ["SET", f"{ACC_PREFIX}{a['name']}", json.dumps(a, ensure_ascii=False, separators=(",", ":"))]
        )
        merged.append(a)

    for i in range(0, len(set_cmds), 30):
        _pipeline(set_cmds[i : i + 30])

    usable = [
        a
        for a in merged
        if not a.get("disabled")
        and _as_int(a.get("remain_web_query"), 1) != 0
        and _as_int(a.get("remain_web_data"), 1) != 0
    ]
    dead_n = len(merged) - len(usable)
    usable.sort(
        key=lambda a: (
            _as_int(a.get("remain_web_query"), 0),
            _as_int(a.get("remain_web_data"), 0),
            a.get("registered_at") or "",
        ),
        reverse=True,
    )
    selected = usable[:max_accounts]
    compact = [compact_account(a) for a in selected]
    quota = quota_summary(merged)
    payload = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(compact),
        "total_live": len(usable),
        "total_disabled": dead_n,
        "quota": quota,
        "source": "upstash",
        "accounts": compact,
    }
    set_json(POOL_KEY, payload)
    set_json(STATE_KEY, {"quota": quota, "ts": payload["updated_at"]})
    try:
        import r2_store
        r2_store.put_json(r2_store.POOL_KEY, payload)
    except Exception as e:
        print(f"[redis_store] R2 backup warn: {e}", file=sys.stderr)
    return payload


def migrate_from_local_and_r2() -> dict:
    accs: list[dict] = []
    seen: set[str] = set()
    # local first
    acc_dir = ROOT / "account"
    if acc_dir.is_dir():
        for p in sorted(acc_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            email = (d.get("email") or "").lower()
            if not email or email in seen:
                continue
            seen.add(email)
            accs.append(d)
    try:
        import r2_store

        for d in r2_store.list_r2_accounts(include_disabled=True):
            email = (d.get("email") or "").lower()
            if not email or email in seen:
                continue
            seen.add(email)
            accs.append(d)
    except Exception as e:
        print(f"[migrate] r2 skip: {e}", file=sys.stderr)

    n = 0
    for a in accs:
        if not a.get("email") or not a.get("password"):
            continue
        put_account(a, refresh_pool=False)
        n += 1
    pool = rebuild_pool()
    return {
        "migrated": n,
        "pool_count": pool.get("count"),
        "quota": pool.get("quota"),
        "redis_pool_key": POOL_KEY,
    }


def public_rest_get_pool_url() -> str:
    # path-style GET for snippet convenience
    return f"{UPSTASH_URL}/get/{urllib.parse.quote(POOL_KEY, safe='')}"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage:\n"
            "  redis_store.py ping\n"
            "  redis_store.py migrate\n"
            "  redis_store.py rebuild\n"
            "  redis_store.py list\n"
            "  redis_store.py quota\n"
            "  redis_store.py usage <name> [dq] [dd]\n"
            "  redis_store.py get <name>\n"
            "  redis_store.py url\n"
        )
        return 0
    cmd = argv[0]
    if cmd == "ping":
        print(ping())
        return 0
    if cmd == "migrate":
        print(json.dumps(migrate_from_local_and_r2(), indent=2, ensure_ascii=False))
        return 0
    if cmd == "rebuild":
        print(json.dumps(rebuild_pool(), indent=2, ensure_ascii=False)[:2500])
        return 0
    if cmd == "list":
        print(json.dumps(get_json(POOL_KEY, {}), indent=2, ensure_ascii=False)[:4000])
        return 0
    if cmd == "quota":
        print(json.dumps(quota_summary(), indent=2, ensure_ascii=False))
        return 0
    if cmd == "usage" and len(argv) >= 2:
        dq = int(argv[2]) if len(argv) >= 3 else 1
        dd = int(argv[3]) if len(argv) >= 4 else 0
        print(json.dumps(record_usage(argv[1], delta_query=dq, delta_data=dd), indent=2, ensure_ascii=False)[:1500])
        return 0
    if cmd == "get" and len(argv) >= 2:
        print(json.dumps(get_json(f"{ACC_PREFIX}{argv[1]}"), indent=2, ensure_ascii=False))
        return 0
    if cmd == "url":
        print(public_rest_get_pool_url())
        return 0
    print("unknown", cmd, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
