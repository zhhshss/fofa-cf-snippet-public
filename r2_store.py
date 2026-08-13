#!/usr/bin/env python3
"""FOFA account pool on Cloudflare R2 (S3 API).

Bucket layout (bucket=fofa):
  accounts.json           compact pool for fofa2api runtime
  accounts/<name>.json    full per-account records
  meta/state.json         auto_refill / sync state

Public read is enabled so CF Snippets can fetch without SigV4.
Write always goes through S3 credentials.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent
ACC_DIR = ROOT / "account"

def _required_env(key: str) -> str:
    """Return a required runtime setting without embedding private defaults."""
    value = os.environ.get(key, "").strip()
    if not value:
        raise RuntimeError(f"missing required environment variable: {key}")
    return value


R2_ACCOUNT_ID = _required_env("R2_ACCOUNT_ID")
R2_ACCESS_KEY = _required_env("R2_ACCESS_KEY_ID")
R2_SECRET_KEY = _required_env("R2_SECRET_ACCESS_KEY")
R2_BUCKET = _required_env("R2_BUCKET")
R2_ENDPOINT = _required_env("R2_ENDPOINT")
# Public base for Snippet fetch (injected through a Secret)
R2_PUBLIC_BASE = _required_env("R2_PUBLIC_BASE")

POOL_KEY = "accounts.json"
ACC_PREFIX = "accounts/"
USAGE_PREFIX = "usage/"
STATE_KEY = "meta/state.json"
DEFAULT_WEB_QUERY = 300
DEFAULT_WEB_DATA = 3000


def client():
    return boto3.client(
        "s3",
        endpoint_url=R2_ENDPOINT,
        aws_access_key_id=R2_ACCESS_KEY,
        aws_secret_access_key=R2_SECRET_KEY,
        region_name="auto",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def put_json(key: str, obj: Any, *, public_read_hint: bool = True) -> None:
    body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    extra = {
        "Bucket": R2_BUCKET,
        "Key": key,
        "Body": body,
        "ContentType": "application/json; charset=utf-8",
        "CacheControl": "no-cache, max-age=30",
    }
    # R2 ignores ACL mostly; public comes from managed domain
    client().put_object(**extra)


def get_json(key: str, default: Any = None) -> Any:
    try:
        r = client().get_object(Bucket=R2_BUCKET, Key=key)
        return json.loads(r["Body"].read().decode("utf-8"))
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code")
        if code in ("NoSuchKey", "404", "NotFound"):
            return default
        raise


def delete_key(key: str) -> None:
    client().delete_object(Bucket=R2_BUCKET, Key=key)


def list_keys(prefix: str) -> list[str]:
    keys: list[str] = []
    token = None
    while True:
        kw: dict[str, Any] = {"Bucket": R2_BUCKET, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            kw["ContinuationToken"] = token
        r = client().list_objects_v2(**kw)
        for it in r.get("Contents") or []:
            keys.append(it["Key"])
        if not r.get("IsTruncated"):
            break
        token = r.get("NextContinuationToken")
    return keys


def _as_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except Exception:
        return default


def normalize_quota(a: dict) -> dict:
    """Attach limit/used/remain fields in-place and return a."""
    dl = a.get("data_limit") if isinstance(a.get("data_limit"), dict) else {}
    web_query = _as_int(dl.get("web_query"), DEFAULT_WEB_QUERY)
    web_data = _as_int(dl.get("web_data"), DEFAULT_WEB_DATA)
    # FOFA free tier defaults when profile missing
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


def load_usage_map() -> dict[str, dict]:
    """usage/<name>.json → {name: {used_web_query, used_web_data, ...}}"""
    out: dict[str, dict] = {}
    for k in list_keys(USAGE_PREFIX):
        if not k.endswith(".json"):
            continue
        d = get_json(k)
        if not isinstance(d, dict):
            continue
        name = d.get("name") or k[len(USAGE_PREFIX) :].removesuffix(".json")
        out[name] = d
    return out


def merge_usage_into(acc: dict, usage: dict | None) -> dict:
    if not usage:
        return normalize_quota(acc)
    # take max so local/gateway increments don't go backwards
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


def record_usage(
    name_or_email: str,
    *,
    delta_query: int = 1,
    delta_data: int = 0,
    disabled: bool | None = None,
    reason: str | None = None,
) -> dict | None:
    """Increment usage on full account + usage/ shard, rebuild pool."""
    accs = list_r2_accounts(include_disabled=True)
    hit = None
    for a in accs:
        if a.get("name") == name_or_email or a.get("email") == name_or_email:
            hit = a
            break
    if not hit:
        # still write usage shard for later merge
        name = name_or_email.split("@")[0]
        prev = get_json(f"{USAGE_PREFIX}{name}.json", {}) or {}
        used_q = _as_int(prev.get("used_web_query"), 0) + max(0, delta_query)
        used_d = _as_int(prev.get("used_web_data"), 0) + max(0, delta_data)
        shard = {
            "name": name,
            "used_web_query": used_q,
            "used_web_data": used_d,
            "last_used_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        }
        if disabled:
            shard["disabled"] = True
            shard["fail_reason"] = reason or "quota"
        put_json(f"{USAGE_PREFIX}{name}.json", shard)
        return shard

    name = hit.get("name") or hit["email"].split("@")[0]
    hit = normalize_quota(hit)
    hit["used_web_query"] = _as_int(hit.get("used_web_query"), 0) + max(0, delta_query)
    hit["used_web_data"] = _as_int(hit.get("used_web_data"), 0) + max(0, delta_data)
    hit["last_used_at"] = __import__("time").strftime("%Y-%m-%d %H:%M:%S")
    if disabled:
        hit["disabled"] = True
        hit["fail_reason"] = reason or "quota"
    hit = normalize_quota(hit)
    # exhausted?
    if hit.get("remain_web_query", 1) == 0 or hit.get("remain_web_data", 1) == 0:
        hit["disabled"] = True
        hit["fail_reason"] = hit.get("fail_reason") or "quota_exhausted"

    put_json(
        f"{USAGE_PREFIX}{name}.json",
        {
            "name": name,
            "email": hit.get("email"),
            "used_web_query": hit["used_web_query"],
            "used_web_data": hit["used_web_data"],
            "disabled": bool(hit.get("disabled")),
            "fail_reason": hit.get("fail_reason"),
            "last_used_at": hit.get("last_used_at"),
        },
    )
    put_account(hit, refresh_pool=True)
    return hit


def quota_summary(accs: list[dict] | None = None) -> dict:
    if accs is None:
        accs = [normalize_quota(a) for a in list_r2_accounts(include_disabled=True)]
    else:
        accs = [normalize_quota(dict(a)) for a in accs]
    live = [a for a in accs if not a.get("disabled")]
    dead = [a for a in accs if a.get("disabled")]

    def sum_field(items: list[dict], key: str) -> int:
        return sum(max(0, _as_int(a.get(key), 0)) for a in items)

    limit_q = sum(
        max(0, _as_int((a.get("data_limit") or {}).get("web_query"), DEFAULT_WEB_QUERY))
        for a in live
    )
    limit_d = sum(
        max(0, _as_int((a.get("data_limit") or {}).get("web_data"), DEFAULT_WEB_DATA))
        for a in live
    )
    used_q = sum_field(live, "used_web_query")
    used_d = sum_field(live, "used_web_data")
    return {
        "updated_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        "accounts_live": len(live),
        "accounts_disabled": len(dead),
        "accounts_total": len(accs),
        "web_query": {
            "limit": limit_q,
            "used": used_q,
            "remain": max(0, limit_q - used_q),
        },
        "web_data": {
            "limit": limit_d,
            "used": used_d,
            "remain": max(0, limit_d - used_d),
        },
        "note": "used_* is gateway/local estimate; FOFA has no public remain API",
    }


def load_local_accounts() -> list[dict]:
    accs = []
    if not ACC_DIR.is_dir():
        return accs
    for p in sorted(ACC_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not d.get("email") or not d.get("password"):
            continue
        accs.append(d)
    return accs


def save_local(acc: dict) -> Path:
    ACC_DIR.mkdir(exist_ok=True)
    name = acc.get("name") or (acc.get("email") or "acc").split("@")[0]
    path = ACC_DIR / f"{name}.json"
    path.write_text(json.dumps(acc, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def put_account(acc: dict, *, refresh_pool: bool = True) -> None:
    name = acc.get("name") or (acc.get("email") or "acc").split("@")[0]
    acc = dict(acc)
    acc["name"] = name
    put_json(f"{ACC_PREFIX}{name}.json", acc)
    save_local(acc)
    if refresh_pool:
        rebuild_pool()


def put_accounts_bulk(accs: list[dict], *, rebuild: bool = True) -> int:
    n = 0
    for acc in accs:
        if not acc.get("email") or not acc.get("password"):
            continue
        name = acc.get("name") or acc["email"].split("@")[0]
        acc = dict(acc)
        acc["name"] = name
        put_json(f"{ACC_PREFIX}{name}.json", acc)
        save_local(acc)
        n += 1
    if rebuild:
        rebuild_pool()
    return n


def list_r2_accounts(*, include_disabled: bool = True) -> list[dict]:
    # Prefer full per-file records
    keys = [k for k in list_keys(ACC_PREFIX) if k.endswith(".json") and k != POOL_KEY]
    out: list[dict] = []
    for k in keys:
        d = get_json(k)
        if not isinstance(d, dict):
            continue
        if not d.get("email") or not d.get("password"):
            continue
        if not include_disabled and d.get("disabled"):
            continue
        out.append(d)
    if out:
        return out
    # fallback to pool file
    pool = get_json(POOL_KEY, [])
    if isinstance(pool, dict):
        pool = pool.get("accounts") or []
    return [a for a in pool if isinstance(a, dict) and a.get("email") and a.get("password")]


def rebuild_pool(max_accounts: int = 80) -> dict:
    """Write compact accounts.json for runtime. Live (non-disabled) first."""
    accs = list_r2_accounts(include_disabled=True)
    # also merge local if r2 empty-ish
    if not accs:
        accs = load_local_accounts()
        for a in accs:
            name = a.get("name") or a["email"].split("@")[0]
            a["name"] = name
            put_json(f"{ACC_PREFIX}{name}.json", a)

    usage_map = load_usage_map()
    merged: list[dict] = []
    for a in accs:
        name = a.get("name") or (a.get("email") or "acc").split("@")[0]
        a["name"] = name
        a = merge_usage_into(a, usage_map.get(name))
        # persist merged usage back onto full object occasionally
        put_json(f"{ACC_PREFIX}{name}.json", a)
        save_local(a)
        merged.append(a)

    live = [a for a in merged if not a.get("disabled")]
    # drop exhausted even if not flagged
    usable = [
        a
        for a in live
        if _as_int(a.get("remain_web_query"), 1) != 0
        and _as_int(a.get("remain_web_data"), 1) != 0
    ]
    dead = [a for a in merged if a.get("disabled") or a not in usable]
    # prefer higher remaining query
    def sort_key(a: dict):
        return (
            _as_int(a.get("remain_web_query"), 0),
            _as_int(a.get("remain_web_data"), 0),
            a.get("registered_at") or "",
        )

    usable.sort(key=sort_key, reverse=True)
    selected = usable[:max_accounts]
    compact = [compact_account(a) for a in selected]
    quota = quota_summary(merged)
    payload = {
        "updated_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(compact),
        "total_live": len(usable),
        "total_disabled": len(dead),
        "quota": quota,
        "accounts": compact,
    }
    put_json(POOL_KEY, payload)
    put_json(STATE_KEY, {"quota": quota, "ts": payload["updated_at"]})
    return payload


def disable_account(email_or_name: str, reason: str = "disabled") -> bool:
    accs = list_r2_accounts(include_disabled=True)
    hit = None
    for a in accs:
        if a.get("email") == email_or_name or a.get("name") == email_or_name:
            hit = a
            break
    if not hit:
        return False
    hit["disabled"] = True
    hit["fail_reason"] = reason
    put_account(hit, refresh_pool=True)
    return True


def migrate_local_to_r2() -> dict:
    local = load_local_accounts()
    n = put_accounts_bulk(local, rebuild=True)
    pool = get_json(POOL_KEY, {})
    return {"migrated": n, "pool_count": (pool or {}).get("count"), "public_url": public_pool_url()}


def public_pool_url() -> str:
    return f"{R2_PUBLIC_BASE.rstrip('/')}/{POOL_KEY}"


def public_account_url(name: str) -> str:
    return f"{R2_PUBLIC_BASE.rstrip('/')}/{ACC_PREFIX}{name}.json"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage:\n"
            "  r2_store.py migrate          # local account/*.json → R2 + rebuild pool\n"
            "  r2_store.py rebuild          # rebuild accounts.json from R2 objects\n"
            "  r2_store.py list             # list pool\n"
            "  r2_store.py get <name>       # get one account\n"
            "  r2_store.py put <file.json>  # upload one account file\n"
            "  r2_store.py disable <email>  # mark disabled + rebuild\n"
            "  r2_store.py usage <name> [dq] [dd]  # +usage and rebuild\n"
            "  r2_store.py quota            # pool quota summary\n"
            "  r2_store.py url              # print public pool URL\n"
        )
        return 0
    cmd = argv[0]
    if cmd == "migrate":
        print(json.dumps(migrate_local_to_r2(), indent=2, ensure_ascii=False))
        return 0
    if cmd == "rebuild":
        print(json.dumps(rebuild_pool(), indent=2, ensure_ascii=False)[:2000])
        return 0
    if cmd == "list":
        pool = get_json(POOL_KEY, {"accounts": []})
        print(json.dumps(pool, indent=2, ensure_ascii=False)[:4000])
        return 0
    if cmd == "get" and len(argv) >= 2:
        name = argv[1]
        print(json.dumps(get_json(f"{ACC_PREFIX}{name}.json"), indent=2, ensure_ascii=False))
        return 0
    if cmd == "put" and len(argv) >= 2:
        d = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        put_account(normalize_quota(d), refresh_pool=True)
        print("ok", d.get("name") or d.get("email"))
        return 0
    if cmd == "disable" and len(argv) >= 2:
        ok = disable_account(argv[1], reason=argv[2] if len(argv) > 2 else "manual")
        print("ok" if ok else "not found")
        return 0 if ok else 1
    if cmd == "usage" and len(argv) >= 2:
        dq = int(argv[2]) if len(argv) >= 3 else 1
        dd = int(argv[3]) if len(argv) >= 4 else 0
        hit = record_usage(argv[1], delta_query=dq, delta_data=dd)
        print(json.dumps(hit, indent=2, ensure_ascii=False)[:1500])
        return 0 if hit else 1
    if cmd == "quota":
        print(json.dumps(quota_summary(), indent=2, ensure_ascii=False))
        return 0
    if cmd == "url":
        print(public_pool_url())
        return 0
    print("unknown command", cmd, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
