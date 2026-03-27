#!/usr/bin/env bash
# =============================================================================
#  manager/scripts/setup.sh — Set up the mac_intel Manager
#
#  Run from the manager/ package directory:
#    cd macbook_data/manager
#    bash scripts/setup.sh
# =============================================================================
set -euo pipefail

MANAGER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "${MANAGER_DIR}/.." && pwd)"
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; CYN='\033[0;36m'; BLD='\033[1m'; N='\033[0m'
info() { printf "${CYN}[info]${N}  %s\n" "$*"; }
ok()   { printf "${GRN}[ok]${N}    %s\n" "$*"; }
warn() { printf "${YEL}[warn]${N}  %s\n" "$*"; }
err()  { printf "${RED}[err]${N}   %s\n" "$*"; exit 1; }

# ── 1. Python check ───────────────────────────────────────────────────────────
command -v python3 &>/dev/null || err "python3 not found"
VER=$(python3 -c "import sys; print(sys.version_info[:2] >= (3,9))")
[[ "$VER" == "True" ]] || err "Python 3.9+ required"
ok "Python $(python3 --version)"

# ── 2. Install deps ───────────────────────────────────────────────────────────
info "Installing manager dependencies..."
python3 -m pip install -q --upgrade pip
python3 -m pip install -q -r "${MANAGER_DIR}/requirements.txt"
ok "Dependencies installed"

# ── 3. TLS certificate ───────────────────────────────────────────────────────
CERTS_DIR="${ROOT_DIR}/certs"
mkdir -p "${CERTS_DIR}"
if [[ -f "${CERTS_DIR}/server.crt" ]]; then
    warn "certs/server.crt already exists — skipping cert generation"
else
    info "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout "${CERTS_DIR}/server.key" \
        -out    "${CERTS_DIR}/server.crt" \
        -subj "/CN=mac-intel-manager" \
        -addext "subjectAltName=IP:0.0.0.0,IP:127.0.0.1" 2>/dev/null
    chmod 600 "${CERTS_DIR}/server.key"
    ok "TLS cert → certs/server.crt"
    warn "Self-signed cert. Set tls_verify=false in agent config for local dev."
fi

# ── 4. Data directory ────────────────────────────────────────────────────────
mkdir -p "${MANAGER_DIR}/data" "${MANAGER_DIR}/logs"

# ── 5. API key check ─────────────────────────────────────────────────────────
[[ -n "${API_KEY:-}" ]] || {
    warn "API_KEY env var not set."
    info "Generate one: cd ${MANAGER_DIR} && python3 scripts/keygen.py"
    info "Then:         export API_KEY=<key>"
    exit 1
}

ok "Manager ready."
printf "\n${BLD}Start the manager:${N}\n"
echo "  cd ${MANAGER_DIR}"
echo "  export API_KEY=\"${API_KEY}\""
echo "  python3 -m manager.server"
echo ""
echo "  Or with uvicorn directly:"
echo "  uvicorn manager.server:app \\"
echo "    --host 0.0.0.0 --port 8443 \\"
echo "    --ssl-certfile ${CERTS_DIR}/server.crt \\"
echo "    --ssl-keyfile  ${CERTS_DIR}/server.key"
echo ""
echo "  Dashboard: https://$(curl -s ifconfig.me 2>/dev/null || echo YOUR_IP):8443"
