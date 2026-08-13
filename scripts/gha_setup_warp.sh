#!/usr/bin/env bash
# Start containerized WARP (caomingjun/warp) + privoxy on GHA / local.
# Mirrors grok-clearance stack: socks :40000, http :40080
set -euo pipefail

log() { echo "[warp-docker] $*"; }

ROOT="${GITHUB_WORKSPACE:-$(cd "$(dirname "$0")/.." && pwd)}"
COMPOSE_DIR="$ROOT/docker/warp"
cd "$COMPOSE_DIR"

if ! command -v docker >/dev/null 2>&1; then
  log "docker missing — install docker"
  : "${DOCKER_INSTALL_URL:?DOCKER_INSTALL_URL is required}"
  curl -fsSL "$DOCKER_INSTALL_URL" | sudo sh
  sudo systemctl enable --now docker || true
fi

# compose plugin
if ! docker compose version >/dev/null 2>&1; then
  log "install docker compose plugin…"
  sudo apt-get update -qq
  sudo apt-get install -y -qq docker-compose-plugin || true
fi

log "pull images…"
docker compose pull || true

log "down old stack (if any)…"
docker compose down --remove-orphans 2>/dev/null || true

log "up warp + privoxy…"
# SYS_MODULE may fail on GHA — try full first, then without SYS_MODULE
if ! docker compose up -d; then
  log "compose up failed — retry warp without SYS_MODULE"
  # temporary override
  cat > docker-compose.override.yml <<'OVR'
services:
  warp:
    cap_add:
      - NET_ADMIN
OVR
  docker compose down --remove-orphans 2>/dev/null || true
  docker compose up -d
  rm -f docker-compose.override.yml
fi

# wait for socks
ok_socks=0
for i in $(seq 1 36); do
  if python3 -c "import socket; s=socket.create_connection(('127.0.0.1',40000),3); s.close()" 2>/dev/null; then
    ok_socks=1
    log "socks :40000 up (try $i)"
    break
  fi
  # show container status every few tries
  if [ $((i % 6)) -eq 0 ]; then
    docker compose ps || true
    docker logs fofa-gha-warp 2>&1 | tail -15 || true
  fi
  sleep 5
done

if [ "$ok_socks" != "1" ]; then
  log "socks never became ready"
  docker compose ps || true
  docker logs fofa-gha-warp 2>&1 | tail -40 || true
  exit 0  # soft — probe step will soft-fail
fi

# wait privoxy briefly
for i in $(seq 1 12); do
  if python3 -c "import socket; s=socket.create_connection(('127.0.0.1',40080),3); s.close()" 2>/dev/null; then
    log "privoxy :40080 up"
    break
  fi
  sleep 2
done

probe() {
  local label="$1" proxy="$2"
  python3 - "$label" "$proxy" <<'PY'
import os, sys, requests
label, proxy = sys.argv[1], sys.argv[2]
px = {"http": proxy, "https": proxy}
auth_base = os.environ["FOFA_AUTH_BASE"].rstrip("/")
probe_email = os.environ["FOFA_PROBE_EMAIL"]
web_origin = os.environ["FOFA_WEB_ORIGIN"].rstrip("/")
web_referer = os.environ["FOFA_WEB_REFERER"]
try:
    r = requests.post(
        f"{auth_base}/auth/verification_code",
        json={"account": probe_email, "type": "email", "lang": "en"},
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150.0.0.0 Safari/537.36",
            "Origin": web_origin,
            "Referer": web_referer,
            "Accept": "application/json, text/plain, */*",
        },
        proxies=px,
        timeout=25,
    )
    ok = r.status_code == 200 and r.text[:1] == "{"
    print(f"{label}: status={r.status_code} ok={ok} body={r.text[:120]!r}")
    # also show egress ip
    try:
        ip = requests.get(os.environ["PUBLIC_IP_API"], proxies=px, timeout=12).text.strip()
        print(f"{label}: egress_ip={ip}")
    except Exception as e:
        print(f"{label}: egress_ip_err={e}")
    sys.exit(0 if ok else 1)
except Exception as e:
    print(f"{label}: ERR {type(e).__name__}: {e}")
    sys.exit(1)
PY
}

# Prefer socks (local WARP works on socks); then HTTP privoxy
if probe "warp-socks:40000" "socks5h://127.0.0.1:40000"; then
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "FOFA_PROXY=socks5h://127.0.0.1:40000" >> "$GITHUB_ENV"
  fi
  log "FOFA_PROXY=socks5h://127.0.0.1:40000"
  exit 0
fi

if probe "privoxy:40080" "http://127.0.0.1:40080"; then
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "FOFA_PROXY=http://127.0.0.1:40080" >> "$GITHUB_ENV"
  fi
  log "FOFA_PROXY=http://127.0.0.1:40080"
  exit 0
fi

log "containers up but FOFA still blocked — soft continue (probe may soft-fail)"
docker logs fofa-gha-warp 2>&1 | tail -30 || true
exit 0
