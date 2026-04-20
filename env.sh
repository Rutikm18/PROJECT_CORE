#!/usr/bin/env bash
# =============================================================================
#  env.sh — Jarvis Manager one-shot setup
#
#  Run this once on your server before `docker compose up`.
#  It generates all secrets, detects your public IP, and writes:
#    • .env          — environment config loaded by Docker Compose
#    • Caddyfile     — TLS reverse proxy config (IP-only or domain)
#
#  Usage:
#    chmod +x env.sh && bash env.sh
#
#  Re-run to update config (existing secrets are preserved from .env).
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'; BOLD='\033[1m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; DIM='\033[2m'; NC='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║         Jarvis Manager — First-Run Setup         ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

step()  { echo -e "\n${CYAN}${BOLD}▶  $*${NC}"; }
ok()    { echo -e "   ${GREEN}✔  $*${NC}"; }
info()  { echo -e "   ${DIM}ℹ  $*${NC}"; }
warn()  { echo -e "   ${YELLOW}⚠  $*${NC}"; }

# ── Secret generator ──────────────────────────────────────────────────────────
gen_secret() {
  # Use openssl if available (most reliable), fall back to /dev/urandom
  if command -v openssl &>/dev/null; then
    openssl rand -hex "$1"
  else
    head -c "$1" /dev/urandom | xxd -p | tr -d '\n' | head -c $(( $1 * 2 ))
  fi
}

gen_token() {
  local prefix="$1"
  local bytes="${2:-18}"
  echo "${prefix}$(openssl rand -base64 $bytes 2>/dev/null \
    | tr '+/' '-_' | tr -d '=' | head -c 24 || head -c $bytes /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
}

# ── Detect public IP ──────────────────────────────────────────────────────────
detect_ip() {
  local ip=""
  # Try multiple endpoints
  for url in \
    "https://api.ipify.org" \
    "https://checkip.amazonaws.com" \
    "https://ifconfig.me" \
    "https://icanhazip.com"; do
    ip=$(curl -fsSL --max-time 4 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    [[ -n "$ip" ]] && echo "$ip" && return
  done
  # AWS IMDSv2 fallback
  local tok
  tok=$(curl -fsSL --max-time 2 \
    -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 10" 2>/dev/null || true)
  if [[ -n "$tok" ]]; then
    ip=$(curl -fsSL --max-time 2 \
      -H "X-aws-ec2-metadata-token: $tok" \
      "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)
    [[ -n "$ip" ]] && echo "$ip" && return
  fi
  echo ""
}

# ── Load existing secrets if .env exists (preserve across re-runs) ────────────
load_existing() {
  if [[ -f .env ]]; then
    # shellcheck disable=SC1091
    set -a; source .env 2>/dev/null || true; set +a
    info "Existing .env loaded — secrets preserved"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
banner
load_existing

# ── Step 1: Public IP ─────────────────────────────────────────────────────────
step "Detecting public IP"
AUTO_IP=$(detect_ip)
if [[ -n "$AUTO_IP" ]]; then
  ok "Detected: ${AUTO_IP}"
else
  warn "Could not auto-detect public IP"
fi

echo ""
read -rp "  Public IP [${AUTO_IP:-<enter manually>}]: " INPUT_IP
PUBLIC_IP="${INPUT_IP:-$AUTO_IP}"
if [[ -z "$PUBLIC_IP" ]]; then
  echo "  ERROR: Public IP is required." >&2; exit 1
fi
ok "Public IP: ${PUBLIC_IP}"

# ── Step 2: Domain (optional) ─────────────────────────────────────────────────
step "TLS configuration"
echo ""
echo "  Option A — IP only (self-signed cert, agents set tls_verify = false)"
echo "  Option B — Domain  (real Let's Encrypt cert, agents set tls_verify = true)"
echo ""
read -rp "  Do you have a domain name pointing to this server? [y/N]: " HAS_DOMAIN
HAS_DOMAIN=$(echo "${HAS_DOMAIN:-n}" | tr '[:upper:]' '[:lower:]')

DOMAIN=""
ADMIN_EMAIL=""
BIND_PORT="8443"
TLS_MODE="self-signed"

if [[ "$HAS_DOMAIN" == "y" || "$HAS_DOMAIN" == "yes" ]]; then
  read -rp "  Domain (e.g. jarvis.company.com): " DOMAIN
  if [[ -z "$DOMAIN" ]]; then
    echo "  ERROR: Domain cannot be empty." >&2; exit 1
  fi
  read -rp "  Admin email for Let's Encrypt [admin@${DOMAIN##*.}]: " ADMIN_EMAIL
  ADMIN_EMAIL="${ADMIN_EMAIL:-admin@${DOMAIN}}"
  BIND_PORT="443"
  TLS_MODE="letsencrypt"
  ok "Domain: ${DOMAIN} (Let's Encrypt TLS)"
else
  ok "IP-only mode (Caddy internal self-signed cert on port ${BIND_PORT})"
fi

# ── Step 3: Enrollment mode ───────────────────────────────────────────────────
step "Enrollment mode"
echo ""
echo "  OPEN  — any agent with manager URL can connect (recommended for single operator)"
echo "  TOKEN — agents need a pre-shared token to enroll (use for multi-team deploys)"
echo ""
read -rp "  Require enrollment token? [y/N]: " NEED_TOKEN
NEED_TOKEN=$(echo "${NEED_TOKEN:-n}" | tr '[:upper:]' '[:lower:]')

OPEN_ENROLLMENT="true"
if [[ "$NEED_TOKEN" == "y" || "$NEED_TOKEN" == "yes" ]]; then
  OPEN_ENROLLMENT="false"
  ok "Token-mode enrollment (token will be generated)"
else
  ok "Open enrollment (no token needed)"
fi

# ── Step 4: Generate secrets (only if not already set) ───────────────────────
step "Generating secrets"
: "${ADMIN_TOKEN:=$(gen_token 'sk-admin-' 24)}"
: "${ENROLLMENT_TOKENS:=$(gen_token 'sk-enroll-' 18)}"
ok "Admin token   : ${ADMIN_TOKEN:0:16}... (full value in .env)"
if [[ "$OPEN_ENROLLMENT" == "false" ]]; then
ok "Enroll token  : ${ENROLLMENT_TOKENS:0:16}... (full value in .env)"
fi

# ── Step 5: Write .env ────────────────────────────────────────────────────────
step "Writing .env"

cat > .env <<EOF
# =============================================================================
#  Jarvis Manager — Environment Configuration
#  Generated by env.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
#  DO NOT commit this file to version control.
# =============================================================================

# ── Network ───────────────────────────────────────────────────────────────────
PUBLIC_IP=${PUBLIC_IP}
DOMAIN=${DOMAIN}
BIND_PORT=${BIND_PORT}
ADMIN_EMAIL=${ADMIN_EMAIL}

# ── TLS mode ──────────────────────────────────────────────────────────────────
# self-signed = Caddy internal CA (IP-only, tls_verify=false on agents)
# letsencrypt = Let's Encrypt (domain required, tls_verify=true on agents)
TLS_MODE=${TLS_MODE}

# ── Auth ──────────────────────────────────────────────────────────────────────
# Admin token — protects the key management API (/api/v1/keys/*)
ADMIN_TOKEN=${ADMIN_TOKEN}

# Enrollment mode: true = any agent connects; false = token required
OPEN_ENROLLMENT=${OPEN_ENROLLMENT}

# Enrollment token (only used when OPEN_ENROLLMENT=false)
ENROLLMENT_TOKENS=${ENROLLMENT_TOKENS}

# ── Key policy ────────────────────────────────────────────────────────────────
# Days until agent API keys expire. 0 = never expire.
DEFAULT_KEY_EXPIRY_DAYS=0

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL=info

# ── CORS ─────────────────────────────────────────────────────────────────────
CORS_ORIGINS=*
EOF

ok ".env written"

# ── Step 6: Write Caddyfile ───────────────────────────────────────────────────
step "Writing Caddyfile"

if [[ "$TLS_MODE" == "letsencrypt" ]]; then
  # Domain mode — Let's Encrypt
  cat > Caddyfile <<EOF
# =============================================================================
#  Caddyfile — Jarvis Manager (Let's Encrypt TLS)
#  Generated by env.sh — do not edit manually (re-run env.sh to regenerate)
# =============================================================================

{
    # Global options
    email ${ADMIN_EMAIL}
}

${DOMAIN} {
    # Caddy automatically obtains and renews TLS cert from Let's Encrypt
    # DNS A record must point to this server's IP before first boot.

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options    "nosniff"
        X-Frame-Options           "DENY"
        -Server
    }

    # Agent ingest + enrollment + API
    reverse_proxy manager:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }

    # Access logs
    log {
        output stdout
        format json
    }
}
EOF

else
  # IP-only mode — Caddy internal CA (self-signed)
  cat > Caddyfile <<EOF
# =============================================================================
#  Caddyfile — Jarvis Manager (internal self-signed TLS on port ${BIND_PORT})
#  Generated by env.sh — do not edit manually (re-run env.sh to regenerate)
#
#  Agents must set tls_verify = false in agent.toml (self-signed cert).
# =============================================================================

{
    # Use Caddy's internal CA — generates a local self-signed cert.
    # No internet access required.
    local_certs
}

:${BIND_PORT} {
    # Internal self-signed TLS certificate
    tls internal

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options    "nosniff"
        X-Frame-Options           "DENY"
        -Server
    }

    # Agent ingest + enrollment + API
    reverse_proxy manager:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }

    # Access logs
    log {
        output stdout
        format json
    }
}
EOF

fi

ok "Caddyfile written (mode: ${TLS_MODE})"

# ── Step 7: Create runtime directories ───────────────────────────────────────
step "Creating runtime directories"
mkdir -p data logs
ok "data/ logs/ ready"

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║           ✔  Setup Complete — Ready to Launch           ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [[ "$TLS_MODE" == "letsencrypt" ]]; then
MANAGER_URL="https://${DOMAIN}"
AGENT_TLS="true"
else
MANAGER_URL="https://${PUBLIC_IP}:${BIND_PORT}"
AGENT_TLS="false"
fi

echo -e "${BOLD}  Next step — start the manager:${NC}"
echo "    docker compose up -d"
echo ""
echo -e "${BOLD}  Manager URL:${NC}   ${MANAGER_URL}"
echo -e "${BOLD}  Dashboard:${NC}     ${MANAGER_URL}"
echo -e "${BOLD}  Health check:${NC}  ${MANAGER_URL}/health"
echo ""
echo -e "${BOLD}  Credentials:${NC}"
echo "    Admin token : ${ADMIN_TOKEN}"
if [[ "$OPEN_ENROLLMENT" == "false" ]]; then
echo "    Enroll token: ${ENROLLMENT_TOKENS}"
else
echo "    Enrollment  : OPEN (no token needed)"
fi
echo ""
echo -e "${BOLD}  Install agent on macOS:${NC}"
echo "    sudo installer -pkg macintel-agent-2.0.0-arm64.pkg -target /"
echo "    sudo nano /Library/Jarvis/agent.toml"
echo "    # Set:"
echo "    #   url        = \"${MANAGER_URL}\""
echo "    #   tls_verify = ${AGENT_TLS}"
echo ""
echo -e "${BOLD}  Install agent on Windows (Admin PowerShell):${NC}"
echo "    .\\install.ps1 \`"
echo "      -ManagerUrl \"${MANAGER_URL}\" \`"
echo "      -TlsVerify \$${AGENT_TLS}"
echo ""
echo -e "${DIM}  Secrets saved to: .env"
echo -e "  Caddy config  : Caddyfile${NC}"
echo ""
