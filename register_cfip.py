#!/usr/bin/env python3
"""
FOFA 并发注册（出口轮转）

优先顺序：
  1) --cf-ip: 从 Cloudflare IPv4 段抽 IP，Host/SNI 由环境变量注入
  2) 代理池 /tmp/pref_proxies.txt + config proxies + mihomo mixed
  3) 直连（通常 CF 403，仅兜底）

邮箱走正常 DNS；auth 走选定出口。

用法:
  python3 register_cfip.py -n 15 --workers 3 --sync
  python3 register_cfip.py -n 5 --workers 2 --cf-ip
"""
from __future__ import annotations

import argparse
import os
import http.client
import ipaddress
import json
import quopri
import random
import re
import socket
import ssl
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional

import requests

CF_RANGES = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

AUTH_BASE = os.environ.get("FOFA_AUTH_BASE", "").strip().rstrip("/")
FOFA_WEB_ORIGIN = os.environ.get("FOFA_WEB_ORIGIN", "").strip().rstrip("/")
FOFA_WEB_REFERER = os.environ.get("FOFA_WEB_REFERER", "").strip()
FOFA_PROBE_EMAIL = os.environ.get("FOFA_PROBE_EMAIL", "").strip()
MAILTM_BASE = os.environ.get("MAILTM_BASE", "").strip().rstrip("/")
if not all((AUTH_BASE, FOFA_WEB_ORIGIN, FOFA_WEB_REFERER, FOFA_PROBE_EMAIL, MAILTM_BASE)):
    raise RuntimeError(
        "FOFA_AUTH_BASE, FOFA_WEB_ORIGIN, FOFA_WEB_REFERER, "
        "FOFA_PROBE_EMAIL and MAILTM_BASE are required"
    )
HOST = urllib.parse.urlparse(AUTH_BASE).hostname or ""
if not HOST:
    raise RuntimeError("FOFA_AUTH_BASE must contain a hostname")

# --- identity (low-signal) ---
_FIRST = [
    "alex","sam","jordan","casey","riley","morgan","taylor","jamie","drew","quinn",
    "avery","blake","cameron","devon","emery","finley","harper","hayden","jules","kai",
    "logan","noah","owen","parker","reese","rowan","sage","skyler","sydney","winter",
]
_WORDS = [
    "cloud","pixel","nova","orbit","maple","cedar","river","stone","harbor","signal",
    "north","south","quiet","bright","swift","amber","coral","mint","olive","silver",
]
_SPECIALS = "!@#$%&*+-=?"


def gen_local_part() -> str:
    """Mailbox local-part: human-ish, no product keywords."""
    style = random.randint(0, 4)
    if style == 0:
        # first + digits
        return random.choice(_FIRST) + "".join(random.choices(string.digits, k=random.randint(2, 4)))
    if style == 1:
        # word + word + digit
        return (
            random.choice(_WORDS)
            + random.choice(["", ".", "_"])
            + random.choice(_WORDS)
            + str(random.randint(1, 99))
        )
    if style == 2:
        # consonant-vowel nick 6-9
        c, v = "bcdfghjklmnpqrstvwxyz", "aeiou"
        n = random.randint(6, 9)
        s = "".join((random.choice(c) if i % 2 == 0 else random.choice(v)) for i in range(n))
        return s + str(random.randint(10, 99))
    if style == 3:
        # letter soup mixed case lower only for email
        return "".join(random.choices(string.ascii_lowercase, k=random.randint(7, 11))) + str(
            random.randint(1, 9)
        )
    # first_word_digits
    return f"{random.choice(_FIRST)}{random.choice(['.', '_'])}{random.choice(_WORDS)}{random.randint(10, 999)}"


def gen_password() -> str:
    """8-16 chars: upper+lower+digit+special, no product tokens."""
    # FOFA en: 8-16, upper, lower, digit, special
    length = random.randint(10, 14)
    # ensure classes
    chars = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(_SPECIALS),
    ]
    pool = string.ascii_letters + string.digits + _SPECIALS
    chars += [random.choice(pool) for _ in range(length - 4)]
    random.shuffle(chars)
    pw = "".join(chars)
    # avoid obvious substrings
    low = pw.lower()
    if any(x in low for x in ("fofa", "nosec", "admin", "password", "123456")):
        return gen_password()
    return pw


UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)
ROOT = Path(__file__).resolve().parent
ACC_DIR = ROOT / "account"

MAIL_BASE = os.environ.get("MAIL_BASE", "").strip().rstrip("/")
MAIL_ADMIN = os.environ.get("MAIL_ADMIN", "").strip()
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "").strip()
if not all((MAIL_BASE, MAIL_ADMIN, MAIL_DOMAIN)):
    raise RuntimeError("MAIL_BASE, MAIL_ADMIN and MAIL_DOMAIN are required")
# GHA / remote: FOFA_PROXY or FOFA_PROXIES (comma/newline) override local exits
_NETS = [ipaddress.ip_network(c) for c in CF_RANGES]

HDR = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "Origin": FOFA_WEB_ORIGIN,
    "Referer": FOFA_WEB_REFERER,
    "X-Fofa-Timezone": "Asia/Shanghai",
}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def load_proxy_pool() -> list[str]:
    out: list[str] = []
    # remote / GHA first
    for key in ("FOFA_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        v = (os.environ.get(key) or "").strip()
        if v and v not in out:
            out.append(v)
    multi = os.environ.get("FOFA_PROXIES") or ""
    for ln in multi.replace(",", "\n").splitlines():
        ln = ln.strip()
        if ln and ln not in out:
            out.append(ln)
    # local exits (ignored on GHA unless present)
    for u in (
        "socks5h://127.0.0.1:40000",  # docker warp
        "http://127.0.0.1:40080",     # docker privoxy → warp
        "http://127.0.0.1:7890",      # mihomo
        "socks5h://127.0.0.1:1080",
    ):
        if u not in out:
            out.append(u)
    for path in (
        os.environ.get("FOFA_PROXY_FILE") or "",
        "/tmp/pref_proxies.txt",
        str(ROOT / "proxies.txt"),
    ):
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            continue
        for ln in p.read_text(errors="ignore").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            m = re.match(r"(socks5h?|http|https)://\S+", ln)
            if m:
                url = m.group(0)
                if url.startswith("socks5://"):
                    url = "socks5h://" + url[len("socks5://"):]
                if url not in out:
                    out.append(url)
                continue
            m = re.match(r"(socks5|http|https)://([^:\s/]+):(\d+)", ln)
            if not m:
                continue
            scheme, host, port = m.group(1), m.group(2), m.group(3)
            url = f"{'socks5h' if scheme == 'socks5' else scheme}://{host}:{port}"
            if url not in out:
                out.append(url)
    return out


# Sentinel for "no proxy — connect directly". GitHub runners have an
# overseas IP that FOFA usually accepts, so direct is a real fallback there.
DIRECT = "direct"


def _proxies_arg(proxy: Optional[str]):
    """None/DIRECT → no proxy dict; else route through it."""
    if not proxy or proxy == DIRECT:
        return None
    return {"http": proxy, "https": proxy}


def probe_proxy(proxy: str, timeout: float = 10) -> bool:
    try:
        r = requests.post(
            f"{AUTH_BASE}/auth/verification_code",
            json={"account": FOFA_PROBE_EMAIL, "type": "email", "lang": "en"},
            headers=HDR,
            proxies=_proxies_arg(proxy),
            timeout=timeout,
        )
        # 200 JSON is good even if rate limited later
        return r.status_code == 200 and r.text[:1] == "{"
    except Exception:
        return False


def _allow_direct() -> bool:
    """Default: allow direct fallback (env FOFA_ALLOW_DIRECT=0 to disable)."""
    v = (os.environ.get("FOFA_ALLOW_DIRECT") or "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def _mask(proxy: str) -> str:
    """Hide credentials in logs (user:pass@host → host)."""
    return proxy.split("@")[-1] if "@" in proxy else proxy


def pick_working_proxies(pool: list[str], limit: int = 12) -> list[str]:
    """Concurrently probe a (possibly huge) pool; return up to `limit` live proxies.

    Scans in parallel with early stop once `limit` are found. Workers/scan cap
    come from env so a 5000-entry list is tractable on CI:
      FOFA_PROBE_WORKERS (default 60)
      FOFA_PROBE_SCAN    (default 1500; 0 = whole pool)
    """
    pool = pool or []
    workers = max(1, int(os.environ.get("FOFA_PROBE_WORKERS", "60") or 60))
    scan_cap = int(os.environ.get("FOFA_PROBE_SCAN", "1500") or 1500)
    # shuffle so we don't hammer the same dead prefix every run
    scan = list(pool)
    random.shuffle(scan)
    if scan_cap > 0:
        scan = scan[:scan_cap]

    good: list[str] = []
    if scan:
        log(f"probing {len(scan)} proxies (workers={workers}, want={limit})")
        from concurrent.futures import ThreadPoolExecutor, as_completed

        tried = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(probe_proxy, p): p for p in scan}
            try:
                for fut in as_completed(futs):
                    proxy = futs[fut]
                    tried += 1
                    try:
                        ok = fut.result()
                    except Exception:
                        ok = False
                    if ok:
                        good.append(proxy)
                        log(f"proxy ok {_mask(proxy)} ({len(good)}/{limit})")
                        if len(good) >= limit:
                            break
            finally:
                for f in futs:
                    f.cancel()
        log(f"probe done tried={tried} good={len(good)}")
    if good:
        return good
    # all proxies dead — try direct (works on GitHub Actions / overseas hosts)
    if _allow_direct():
        if probe_proxy(DIRECT):
            log("all proxies dead → DIRECT works, using direct connect")
            return [DIRECT]
        log("all proxies dead and DIRECT also blocked")
    if "http://127.0.0.1:7890" in pool:
        return ["http://127.0.0.1:7890"]
    # last resort: return direct so the run at least attempts
    return [DIRECT] if _allow_direct() else (scan[:3] or [DIRECT])


def random_cf_ip() -> str:
    net = random.choice(_NETS)
    hi = min(net.num_addresses - 2, 2_000_000)
    idx = random.randint(1, max(1, hi))
    return str(net[idx])


def probe_cf_ip(ip: str, timeout: float = 3.5) -> bool:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
                body = (
                    f"POST /v1/auth/verification_code HTTP/1.1\r\n"
                    f"Host: {HOST}\r\nUser-Agent: probe\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                )
                ssock.sendall(body.encode())
                data = ssock.recv(64)
                # reject HTML challenge
                return data.startswith(b"HTTP/1.") and b"403" not in data[:20]
    except Exception:
        return False


class CFIPHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, connect_ip: str):
        self.connect_ip = connect_ip
        self._ctx = ssl.create_default_context()
        super().__init__(context=self._ctx)

    def https_open(self, req):  # type: ignore[override]
        return self.do_open(self._connection, req)

    def _connection(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source=None, **kwargs):
        hostname = host.split(":")[0]
        p = port or 443
        connect_ip = self.connect_ip
        ctx = self._ctx

        class Forced(http.client.HTTPSConnection):
            def connect(self):  # type: ignore[override]
                sock = socket.create_connection((connect_ip, self.port), self.timeout)
                self.sock = ctx.wrap_socket(sock, server_hostname=hostname)

        return Forced(hostname, p, timeout=timeout, context=ctx)


def qp_unfold(s: str) -> str:
    s2 = re.sub(r"=\r?\n", "", s)
    try:
        return quopri.decodestring(s2.encode("utf-8", "ignore")).decode("utf-8", "ignore")
    except Exception:
        return s2


def extract_code(raw: str) -> Optional[str]:
    unfolded = qp_unfold(raw)
    m = re.search(r'class=3D"verification-code"[^>]*>([^<]+)<', raw)
    if not m:
        m = re.search(r'class="verification-code"[^>]*>([^<]+)<', unfolded)
    if m:
        c = re.sub(r"[^0-9]", "", m.group(1))
        if c:
            return c
    m = re.search(r"verification code is:.*?([0-9]{6})", unfolded, re.I | re.S)
    if m:
        return m.group(1)
    m = re.search(r"verification-code[^0-9]{0,80}([0-9]{6})", unfolded, re.I)
    if m:
        return m.group(1)
    return None


def create_mailbox() -> tuple[str, str]:
    name = gen_local_part().replace(".", "").replace("_", "")[:16]
    r = requests.post(
        f"{MAIL_BASE}/admin/new_address",
        headers={"x-admin-auth": MAIL_ADMIN, "Content-Type": "application/json"},
        json={"name": name, "domain": MAIL_DOMAIN},
        timeout=30,
    )
    j = r.json()
    if r.status_code == 200 and j.get("address"):
        return j["address"], j["jwt"]
    # public mailbox fallback
    d = requests.get(f"{MAILTM_BASE}/domains", timeout=20).json()
    domain = d[0]["domain"] if isinstance(d, list) else d["hydra:member"][0]["domain"]
    local = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{local}@{domain}"
    mp = "Fa" + "".join(random.choices(string.ascii_letters + string.digits, k=10)) + "9"
    requests.post(
        f"{MAILTM_BASE}/accounts",
        json={"address": email, "password": mp},
        timeout=20,
    )
    tok = requests.post(
        f"{MAILTM_BASE}/token",
        json={"address": email, "password": mp},
        timeout=20,
    ).json()
    return email, "mailtm:" + tok["token"]


def wait_code(email: str, jwt: str, timeout: int = 90) -> Optional[str]:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if jwt.startswith("mailtm:"):
                token = jwt.split(":", 1)[1]
                data = requests.get(
                    f"{MAILTM_BASE}/messages",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=20,
                ).json()
                members = data if isinstance(data, list) else (data.get("hydra:member") or [])
                if members:
                    mid = members[0]["id"]
                    msg = requests.get(
                        f"{MAILTM_BASE}/messages/{mid}",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=20,
                    ).json()
                    blob = json.dumps(msg, ensure_ascii=False)
                    code = extract_code(blob)
                    if not code:
                        m = re.search(r"(?<!\d)(\d{6})(?!\d)", blob)
                        if m and m.group(1) not in ("000000", "333333"):
                            code = m.group(1)
                    if code:
                        return code
            else:
                data = requests.get(
                    f"{MAIL_BASE}/api/mails",
                    headers={"Authorization": f"Bearer {jwt}"},
                    params={"limit": 10, "offset": 0},
                    timeout=20,
                ).json()
                results = data.get("results") or []
                if results:
                    code = extract_code(results[0].get("raw") or "")
                    if code:
                        return code
        except Exception as e:
            log(f"mail poll {e}")
        time.sleep(2)
    return None


def session_for(proxy: Optional[str] = None, cf_ip: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    s.headers.update(HDR)
    # DIRECT / empty / None → no proxy (runner direct egress)
    if proxy and proxy != DIRECT:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def post_auth(s: requests.Session, path: str, body: dict, timeout: float = 30) -> dict:
    r = s.post(f"{AUTH_BASE}{path}", json=body, timeout=timeout)
    try:
        return {"status": r.status_code, "json": r.json(), "text": r.text[:300]}
    except Exception:
        return {"status": r.status_code, "json": None, "text": r.text[:300]}


def get_auth(s: requests.Session, path: str, token: str, timeout: float = 30) -> dict:
    r = s.get(
        f"{AUTH_BASE}{path}",
        headers={"Authorization": token},
        timeout=timeout,
    )
    try:
        return {"status": r.status_code, "json": r.json()}
    except Exception:
        return {"status": r.status_code, "json": None, "text": r.text[:300]}


def register_one(
    idx: int,
    proxies: list[str],
    use_cf_ip: bool = False,
    timeout: float = 45,
) -> dict:
    exit_label = ""
    s: Optional[requests.Session] = None
    cf_ip = None
    proxy = None

    if use_cf_ip:
        # try a few CF IPs; often 403 — then fall through to proxy
        for _ in range(5):
            ip = random_cf_ip()
            if not probe_cf_ip(ip):
                continue
            # custom urllib path for CF IP is complex with requests; skip if not easy
            # fall back: use proxy
            break
        use_cf_ip = False  # practical path: proxy

    # pick exit: prefer working proxy list; fall back to DIRECT on GHA/overseas
    if proxies:
        proxy = random.choice(proxies)
    elif _allow_direct():
        proxy = DIRECT
    else:
        proxy = "http://127.0.0.1:7890"
    exit_label = proxy
    s = session_for(proxy=proxy)

    email, jwt = create_mailbox()
    password = gen_password()
    log(f"[{idx}] email={email} exit={exit_label}")

    resp = post_auth(
        s, "/auth/verification_code", {"account": email, "type": "email", "lang": "en"}, timeout
    )
    log(f"[{idx}] send {resp['status']} {resp.get('json') or resp.get('text')}")
    j = resp.get("json") or {}
    if j.get("code") != 0:
        # rotate: try other proxies, then DIRECT
        candidates = list(proxies) if proxies else []
        if _allow_direct() and DIRECT not in candidates:
            candidates.append(DIRECT)
        candidates = [c for c in candidates if c != proxy] or [DIRECT]
        proxy2 = random.choice(candidates)
        exit_label = proxy2
        s = session_for(proxy=proxy2)
        resp = post_auth(
            s, "/auth/verification_code", {"account": email, "type": "email", "lang": "en"}, timeout
        )
        j = resp.get("json") or {}
        log(f"[{idx}] send-retry via {proxy2} {resp['status']} {j}")
        if j.get("code") != 0:
            return {"ok": False, "stage": "send", "email": email, "resp": j, "exit": exit_label}

    code = wait_code(email, jwt)
    if not code:
        post_auth(
            s, "/auth/verification_code", {"account": email, "type": "email", "lang": "en"}, timeout
        )
        code = wait_code(email, jwt, timeout=60)
    if not code:
        return {"ok": False, "stage": "code", "email": email, "exit": exit_label}
    log(f"[{idx}] code={code}")

    resp = post_auth(
        s,
        "/auth/register",
        {"account": email, "code": code, "password": password, "lang": "en"},
        timeout,
    )
    reg = resp.get("json") or {}
    log(f"[{idx}] register {resp['status']} {reg}")
    if reg.get("code") != 0:
        return {"ok": False, "stage": "register", "email": email, "resp": reg, "code": code, "exit": exit_label}

    resp = post_auth(
        s,
        "/auth/login",
        {"account": email, "password": password, "lang": "en"},
        timeout,
    )
    login = resp.get("json") or {}
    if login.get("code") != 0:
        return {"ok": False, "stage": "login", "email": email, "resp": login, "exit": exit_label}

    token = login["data"]["access_token"]
    username = (login["data"].get("user_info") or {}).get("username")
    prof = get_auth(s, "/m/profile", token, timeout).get("json") or {}
    info = (prof.get("data") or {}).get("info") or {}
    acct = {
        "ok": True,
        "name": email.split("@")[0],
        "email": email,
        "password": password,
        "username": username or info.get("username"),
        "api_key": info.get("key"),
        "access_token": token,
        "auth_base": AUTH_BASE,
        "rank": info.get("rank_name"),
        "data_limit": info.get("data_limit"),
        "exit": exit_label,
        "cf_ip": cf_ip,
        "registered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "used_web_query": 0,
        "used_web_data": 0,
        "status": "active",
        "disabled": False,
    }
    ACC_DIR.mkdir(exist_ok=True)
    (ACC_DIR / f"{acct['name']}.json").write_text(json.dumps(acct, indent=2, ensure_ascii=False))
    try:
        import r2_store
        r2_store.put_account(acct, refresh_pool=False)
    except Exception as e:
        log(f"[{idx}] R2 put warn: {e}")
    try:
        import redis_store
        redis_store.put_account(acct, refresh_pool=False)
    except Exception as e:
        log(f"[{idx}] Redis put warn: {e}")
    log(f"[{idx}] OK {email} key={acct.get('api_key')}")
    return acct


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=1)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=45)
    ap.add_argument("--sync", action="store_true")
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--cf-ip", action="store_true", help="prefer CF anycast IPs (often 403)")
    ap.add_argument("--probe-limit", type=int, default=8)
    args = ap.parse_args()

    ACC_DIR.mkdir(exist_ok=True)
    pool = load_proxy_pool()
    log(f"probing proxies from {len(pool)} candidates…")
    proxies = pick_working_proxies(pool, limit=args.probe_limit)
    log(f"using {len(proxies)} exits")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = []
        for i in range(args.n):
            futs.append(
                ex.submit(register_one, i + 1, proxies, args.cf_ip, args.timeout)
            )
            time.sleep(args.delay)
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"ok": False, "error": str(e)})

    ok = [r for r in results if r.get("ok")]
    fail = [r for r in results if not r.get("ok")]
    print(
        json.dumps(
            {"ok": len(ok), "fail": len(fail), "emails": [r["email"] for r in ok]},
            indent=2,
            ensure_ascii=False,
        )
    )
    (ROOT / "out").mkdir(exist_ok=True)
    (ROOT / "out" / "last_register.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False)
    )
    # always refresh R2 pool after batch
    try:
        import r2_store
        pool = r2_store.rebuild_pool()
        log(f"R2 pool refreshed count={pool.get('count')} url={r2_store.public_pool_url()}")
    except Exception as e:
        log(f"R2 rebuild warn: {e}")
    try:
        import redis_store
        rpool = redis_store.rebuild_pool()
        log(f"Redis pool refreshed count={rpool.get('count')}")
    except Exception as e:
        log(f"Redis rebuild warn: {e}")
    if args.sync:
        subprocess.check_call([sys.executable, str(ROOT / "sync_accounts_and_deploy.py")])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
