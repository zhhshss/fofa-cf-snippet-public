#!/usr/bin/env python3
"""
FOFA 号池自动维持

目标：Redis 热池可用号 ≥ TARGET（默认 50）。
流程：
  1. 统计 live（Redis → 本地 → R2）
  2. login 探测，死号 disabled 并写回 Redis/R2
  3. live < target 时调用 register_cfip 分批补号
  4. rebuild Redis + R2 pool
  5. 可选 sync 部署 snippet

用法:
  # 立刻补到 50（当前 25 → 再注册约 25）
  python3 maintain_pool.py --target 50 --once

  # 只补 N 个（不管当前多少）
  python3 maintain_pool.py --register 25 --once

  # 常驻：每 30 分钟检查，维持 ≥50
  nohup python3 maintain_pool.py --target 50 --interval 1800 --workers 4 --batch 5 \
      >> /tmp/fofa_maintain_pool.log 2>&1 &
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

ACC_DIR = ROOT / "account"
REGISTER = ROOT / "register_cfip.py"
SYNC = ROOT / "sync_accounts_and_deploy.py"
STATE = ROOT / "maintain_pool.state.json"
PID_FILE = Path("/tmp/fofa_maintain_pool.pid")
LOG_FILE = Path("/tmp/fofa_maintain_pool.log")
AUTH_BASE = os.environ.get("FOFA_AUTH_BASE", "").strip().rstrip("/")
FOFA_PROBE_EMAIL = os.environ.get("FOFA_PROBE_EMAIL", "").strip()
if not AUTH_BASE or not FOFA_PROBE_EMAIL:
    raise RuntimeError("FOFA_AUTH_BASE and FOFA_PROBE_EMAIL are required")
PROXY = None  # filled by resolve_proxy_dict() at runtime

def resolve_proxy_dict():
    """Build requests proxies dict. Empty FOFA_PROXY or dead proxy → try DIRECT.

    On GHA, an overseas runner's direct connection usually works.
    Local China hosts often get CF 403 on direct — set FOFA_PROXY.
    FOFA_ALLOW_DIRECT=0 disables direct fallback.
    """
    import os
    allow = (os.environ.get("FOFA_ALLOW_DIRECT") or "1").strip().lower() not in ("0", "false", "no", "off")
    candidates = []
    for key in ("FOFA_PROXY", "HTTPS_PROXY", "HTTP_PROXY"):
        v = (os.environ.get(key) or "").strip()
        if v and v not in candidates and v.lower() not in ("direct", "none", "-"):
            candidates.append(v)
    multi = os.environ.get("FOFA_PROXIES") or ""
    for ln in multi.replace(",", "\n").splitlines():
        ln = ln.strip()
        if ln and ln not in candidates and ln.lower() not in ("direct", "none", "-"):
            candidates.append(ln)
    # local defaults only if no remote configured
    if not candidates:
        for u in ("http://127.0.0.1:7890", "socks5h://127.0.0.1:40000", "http://127.0.0.1:40080"):
            candidates.append(u)

    def ok(proxy):
        try:
            r = requests.post(
                f"{AUTH_BASE}/auth/verification_code",
                json={"account": FOFA_PROBE_EMAIL, "type": "email", "lang": "en"},
                headers={"Content-Type": "application/json", "User-Agent": "fofa-proxy-resolve/1"},
                proxies=({"http": proxy, "https": proxy} if proxy else None),
                timeout=12,
            )
            return r.status_code == 200 and r.text[:1] == "{"
        except Exception:
            return False

    for pxy in candidates:
        if ok(pxy):
            print(f"[proxy] using {pxy}", flush=True)
            return {"http": pxy, "https": pxy}
    if allow and ok(None):
        print("[proxy] all dead → DIRECT", flush=True)
        return None
    # last resort: return first candidate (or None) so caller still attempts
    if candidates:
        print(f"[proxy] probe failed, force first {candidates[0]}", flush=True)
        return {"http": candidates[0], "https": candidates[0]}
    print("[proxy] no candidates, DIRECT", flush=True)
    return None


_stop = False


def log(msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _on_sig(*_a) -> None:
    global _stop
    _stop = True
    log("收到退出信号，结束当前轮…")


def probe_account(acc: dict) -> tuple[str, dict]:
    """Return (ok|empty|error|skip, acc)."""
    if acc.get("disabled") or not acc.get("email") or not acc.get("password"):
        return "skip", acc
    try:
        r = requests.post(
            f"{AUTH_BASE}/auth/login",
            json={"account": acc["email"], "password": acc["password"], "lang": "en"},
            headers={"Content-Type": "application/json", "User-Agent": "fofa-maintain/1.0"},
            proxies=PROXY,
            timeout=25,
        )
        j = r.json()
        if j.get("code") == 0:
            acc["access_token"] = j["data"]["access_token"]
            acc["disabled"] = False
            # soft refresh profile limits
            try:
                rr = requests.get(
                    f"{AUTH_BASE}/m/profile",
                    headers={"Authorization": acc["access_token"], "User-Agent": "fofa-maintain/1.0"},
                    proxies=PROXY,
                    timeout=20,
                )
                info = ((rr.json().get("data") or {}).get("info") or {})
                if info.get("key"):
                    acc["api_key"] = info["key"]
                if info.get("data_limit"):
                    acc["data_limit"] = info["data_limit"]
            except Exception:
                pass
            return "ok", acc
        acc["disabled"] = True
        acc["fail_reason"] = j.get("message") or "login_fail"
        return "empty", acc
    except Exception as e:
        return "error", acc | {"_probe_error": str(e)}


def load_all_accounts() -> list[dict]:
    by_email: dict[str, dict] = {}

    def add(a: dict) -> None:
        email = (a.get("email") or "").lower()
        if not email or not a.get("password"):
            return
        name = a.get("name") or email.split("@")[0]
        a = dict(a)
        a["name"] = name
        prev = by_email.get(email)
        if not prev:
            by_email[email] = a
            return
        if prev.get("disabled") and not a.get("disabled"):
            by_email[email] = a
        elif (not prev.get("access_token")) and a.get("access_token"):
            by_email[email] = a

    # redis
    try:
        import redis_store

        for a in redis_store.list_accounts(include_disabled=True):
            add(a)
    except Exception as e:
        log(f"redis list warn: {e}")

    # local
    if ACC_DIR.is_dir():
        for p in ACC_DIR.glob("*.json"):
            try:
                add(json.loads(p.read_text(encoding="utf-8")))
            except Exception:
                continue

    # r2
    try:
        import r2_store

        for a in r2_store.list_r2_accounts(include_disabled=True):
            add(a)
    except Exception as e:
        log(f"r2 list warn: {e}")

    return list(by_email.values())


def persist_account(acc: dict) -> None:
    name = acc.get("name") or (acc.get("email") or "acc").split("@")[0]
    acc["name"] = name
    ACC_DIR.mkdir(exist_ok=True)
    (ACC_DIR / f"{name}.json").write_text(
        json.dumps(acc, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    try:
        import redis_store

        redis_store.put_account(acc, refresh_pool=False)
    except Exception as e:
        log(f"redis put warn {name}: {e}")
    try:
        import r2_store

        r2_store.put_account(acc, refresh_pool=False)
    except Exception as e:
        log(f"r2 put warn {name}: {e}")


def count_and_prune(workers: int = 6) -> tuple[int, int, int]:
    """Probe all, return (live, dead, total)."""
    accs = load_all_accounts()
    live = 0
    dead = 0
    total = len(accs)
    if not accs:
        return 0, 0, 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(probe_account, dict(a)) for a in accs]
        for fut in as_completed(futs):
            st, acc = fut.result()
            if st == "ok":
                live += 1
                persist_account(acc)
            elif st == "empty":
                dead += 1
                persist_account(acc)
                log(f"disable {acc.get('name')} ({acc.get('fail_reason')})")
            elif st == "error":
                # keep as live-ish — network blip
                live += 1
                log(f"probe error keep {acc.get('name')}: {acc.get('_probe_error')}")
            else:
                if acc and acc.get("disabled"):
                    dead += 1
                elif acc and acc.get("email"):
                    live += 1
    return live, dead, total


def rebuild_pools() -> dict:
    out: dict = {}
    try:
        import redis_store

        out["redis"] = redis_store.rebuild_pool()
        log(
            f"Redis pool count={out['redis'].get('count')} "
            f"q_remain={(out['redis'].get('quota') or {}).get('web_query', {}).get('remain')}"
        )
    except Exception as e:
        log(f"Redis rebuild warn: {e}")
    try:
        import r2_store

        out["r2"] = r2_store.rebuild_pool()
        log(f"R2 pool count={out['r2'].get('count')} url={r2_store.public_pool_url()}")
    except Exception as e:
        log(f"R2 rebuild warn: {e}")
    return out


def register_batch(n: int, workers: int, delay: float) -> int:
    if n <= 0:
        return 0
    log(f"registering {n} (workers={workers}, delay={delay})")
    r = subprocess.run(
        [
            sys.executable,
            str(REGISTER),
            "-n",
            str(n),
            "--workers",
            str(workers),
            "--delay",
            str(delay),
        ],
        cwd=str(ROOT),
        check=False,
        capture_output=True,
        text=True,
    )
    if r.stdout:
        # last json summary lines
        tail = r.stdout.strip().splitlines()[-20:]
        for line in tail:
            log(f"reg: {line}")
    if r.returncode != 0 and r.stderr:
        log(f"reg stderr: {r.stderr[-500:]}")
    # count ok from output if possible
    ok = 0
    try:
        # find last {...} with "ok"
        for line in reversed(r.stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and '"ok"' in line:
                j = json.loads(line)
                ok = int(j.get("ok") or 0)
                break
        else:
            # multi-line json at end
            text = r.stdout.strip()
            if text.endswith("}"):
                # try parse from last {
                idx = text.rfind("\n{")
                if idx >= 0:
                    j = json.loads(text[idx + 1 :])
                    ok = int(j.get("ok") or 0)
    except Exception:
        ok = 0
    # also check out/last_register.json
    try:
        last = json.loads((ROOT / "out" / "last_register.json").read_text())
        if isinstance(last, list):
            ok = sum(1 for x in last if x.get("ok"))
    except Exception:
        pass
    log(f"register batch done ok≈{ok} rc={r.returncode}")
    return ok


def refill_to_target(
    target: int,
    *,
    workers: int,
    batch: int,
    delay: float,
    max_rounds: int = 12,
) -> int:
    live, dead, total = count_and_prune(workers=min(workers, 8))
    log(f"pool live={live} dead={dead} total_files={total} target={target}")
    if live >= target:
        rebuild_pools()
        return live

    need = target - live
    rounds = 0
    while need > 0 and not _stop and rounds < max_rounds:
        rounds += 1
        n = min(batch, need)
        # slight over-register to absorb failures
        n_req = min(n + max(1, n // 3), need + 5)
        register_batch(n_req, workers=workers, delay=delay)
        live, dead, total = count_and_prune(workers=min(workers, 8))
        log(f"after round{rounds} live={live} dead={dead} need={max(0, target - live)}")
        need = max(0, target - live)
        if need > 0:
            time.sleep(3)
    rebuild_pools()
    return live


def save_state(**kw) -> None:
    data = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), **kw}
    STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        import redis_store

        redis_store.set_json(redis_store.STATE_KEY, data)
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="FOFA 号池自动维持")
    ap.add_argument("--target", type=int, default=50, help="维持可用号数量（默认 50）")
    ap.add_argument("--register", type=int, default=0, help="强制再注册 N 个（忽略 target 差值下限）")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--batch", type=int, default=5, help="每批注册数")
    ap.add_argument("--delay", type=float, default=1.5, help="注册任务提交间隔秒")
    ap.add_argument("--interval", type=int, default=1800, help="常驻循环间隔秒（默认 30min）")
    ap.add_argument("--once", action="store_true", help="只跑一轮")
    ap.add_argument("--no-sync", action="store_true", help="不部署 snippet")
    ap.add_argument("--no-probe", action="store_true", help="跳过 login 探测，只按文件数补")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, _on_sig)
    signal.signal(signal.SIGTERM, _on_sig)
    ACC_DIR.mkdir(exist_ok=True)
    global PROXY
    PROXY = resolve_proxy_dict()
    PID_FILE.write_text(str(os.getpid()))
    log(f"maintain_pool start target={args.target} register={args.register} once={args.once}")
    if (os.environ.get("FOFA_EGRESS_OK") or "1").strip() in ("0", "false", "no") and args.register <= 0:
        log("FOFA_EGRESS_OK=0 → skip register, rebuild only")
        args.no_probe = True
        # freeze target to current so refill loop does not register
        try:
            import redis_store
            cur = len(redis_store.list_accounts(include_disabled=False))
            if cur > 0:
                args.target = cur
                log(f"freeze target to current live≈{cur}")
        except Exception as e:
            log(f"freeze target warn: {e}")


    while not _stop:
        t0 = time.time()
        if args.register > 0:
            log(f"force register {args.register}")
            register_batch(args.register, workers=args.workers, delay=args.delay)
            if not args.no_probe:
                live, dead, total = count_and_prune(workers=min(args.workers, 8))
            else:
                live = len(list(ACC_DIR.glob("*.json")))
                dead, total = 0, live
            rebuild_pools()
            # clear one-shot force after first loop
            args.register = 0
        else:
            if args.no_probe:
                # crude count: redis usable or local non-disabled
                try:
                    import redis_store

                    live = len(redis_store.list_accounts(include_disabled=False))
                except Exception:
                    live = sum(
                        1
                        for p in ACC_DIR.glob("*.json")
                        if not json.loads(p.read_text()).get("disabled", False)
                    )
                log(f"no-probe live≈{live} target={args.target}")
                if live < args.target:
                    register_batch(
                        args.target - live + 2,
                        workers=args.workers,
                        delay=args.delay,
                    )
                rebuild_pools()
            else:
                live = refill_to_target(
                    args.target,
                    workers=args.workers,
                    batch=args.batch,
                    delay=args.delay,
                )

        save_state(live=live if "live" in dir() else None, target=args.target, elapsed=round(time.time() - t0, 1))

        if not args.no_sync:
            log("sync deploy…")
            subprocess.run([sys.executable, str(SYNC)], cwd=str(ROOT), check=False)

        if args.once:
            break
        log(f"sleep {args.interval}s …")
        for _ in range(args.interval):
            if _stop:
                break
            time.sleep(1)

    log("maintain_pool exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
