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

# Base64 secret — used for JWT_SECRET, which auth_ui.py base64-decodes into raw
# HMAC key material and key_store.py uses as the HKDF master for the encrypted
# AI provider key.
#
# Standard base64 (padding kept) on purpose: auth_ui.py calls base64.b64decode()
# and only falls back to raw-string bytes on failure, so a URL-safe alphabet
# would be silently discarded as non-alphabet chars and stripped padding would
# force the fallback. The standard alphabet contains no '$', so the value is
# still safe from docker compose interpolation when it reads .env.
gen_b64_secret() {
  local bytes="${1:-32}"
  if command -v openssl &>/dev/null; then
    openssl rand -base64 "$bytes" | tr -d '\n'
  else
    head -c "$bytes" /dev/urandom | base64 | tr -d '\n'
  fi
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

# ── Parse one KEY=VALUE line ──────────────────────────────────────────────────
# Sets ENV_KEY / ENV_VAL and returns 0, or returns 1 for comments and blanks.
# One layer of matching surrounding quotes is stripped from the value.
parse_env_line() {
  local line="$1"
  ENV_KEY=""; ENV_VAL=""
  [[ "$line" =~ ^[[:space:]]*# ]] && return 1
  [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || return 1
  ENV_KEY="${BASH_REMATCH[2]}"
  ENV_VAL="${BASH_REMATCH[3]}"
  if [[ ${#ENV_VAL} -ge 2 ]]; then
    if [[ "$ENV_VAL" == \"*\" || "$ENV_VAL" == \'*\' ]]; then
      ENV_VAL="${ENV_VAL:1:${#ENV_VAL}-2}"
    fi
  fi
  return 0
}

# ── Load existing secrets if .env exists (preserve across re-runs) ────────────
# Parsed line by line, never sourced. `source` *parses* the file, so a value
# holding shell metacharacters aborts env.sh with a syntax error that `|| true`
# cannot trap — the unquoted 'SMTP_FROM=Alerts <alerts@example.com>' that
# .env.example used to ship was enough to kill the whole run before it wrote
# anything. Sourcing would also execute any command substitution left in .env.
load_existing() {
  [[ -f .env ]] || return 0
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    parse_env_line "$line" || continue
    export "${ENV_KEY}=${ENV_VAL}"
  done < .env
  info "Existing .env loaded — secrets preserved"
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

# JWT_SECRET does double duty: auth_ui.py signs dashboard session tokens with
# it, and ai/key_store.py uses it as the HKDF master that derives the AES-256
# key encrypting your stored AI provider API key. When it is unset the manager
# degrades in two ways — every dashboard session is lost on restart, and the AI
# key falls back to a random file written next to the ciphertext it protects.
JWT_SECRET_IS_NEW=0
if [[ -z "${JWT_SECRET:-}" ]]; then
  JWT_SECRET_IS_NEW=1
  JWT_SECRET="$(gen_b64_secret 32)"
fi

ok "Admin token   : ${ADMIN_TOKEN:0:16}... (full value in .env)"
if [[ "$OPEN_ENROLLMENT" == "false" ]]; then
ok "Enroll token  : ${ENROLLMENT_TOKENS:0:16}... (full value in .env)"
fi
if [[ "$JWT_SECRET_IS_NEW" == "1" ]]; then
  ok "JWT secret    : generated (32 bytes, base64)"
else
  info "JWT secret    : preserved from existing .env"
fi

# Introducing JWT_SECRET where one was never set changes the HKDF master, so a
# previously stored AI key can no longer be decrypted. Say so now rather than
# letting it surface later as a silent "AI provider not configured".
if [[ "$JWT_SECRET_IS_NEW" == "1" && -f data/ai_provider.enc ]]; then
  warn "data/ai_provider.enc exists but JWT_SECRET was not previously set."
  warn "The new secret changes the encryption master, so the stored AI key"
  warn "cannot be decrypted. Re-enter it in Settings → AI Provider after restart."
fi

# ── Step 5: Write .env ────────────────────────────────────────────────────────
step "Writing .env"

# Defaults for every variable env.sh manages. ':=' means an existing value —
# already loaded from .env by load_existing() — always wins, so a re-run never
# resets configuration you have filled in by hand.
: "${DEFAULT_KEY_EXPIRY_DAYS:=0}"
: "${LOG_LEVEL:=info}"

# Same-origin by default. The dashboard is served by this manager through Caddy,
# so it needs no cross-origin grant. A wildcard here would be actively unsafe:
# with credentials allowed, Starlette echoes the caller's origin back when a
# cookie is present, so any site could call the API using a logged-in admin's
# session. Only widen this if you serve the dashboard from another host.
if [[ "$TLS_MODE" == "letsencrypt" && -n "$DOMAIN" ]]; then
  : "${CORS_ORIGINS:=https://${DOMAIN}}"
else
  : "${CORS_ORIGINS:=https://${PUBLIC_IP}:${BIND_PORT}}"
fi
: "${APP_UID:=1000}"
: "${APP_GID:=1000}"

# AI provider bootstrap. These seed the encrypted store at data/ai_provider.enc
# on first boot only — once a provider is configured, the stored config wins and
# these are ignored. Runtime changes go through Settings -> AI Provider.
: "${AI_PROVIDER:=openrouter}"
: "${AI_MODEL:=openai/gpt-oss-20b:free}"
: "${AI_API_KEY:=}"
: "${AI_BASE_URL:=}"

# OpenRouter transport tuning and its spend guard.
: "${OPENROUTER_APP_URL:=https://attacklens.ai}"
: "${OPENROUTER_APP_TITLE:=AttackLens}"
: "${ATTACKLENS_OPENROUTER_ENABLED:=true}"
: "${ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE:=60}"
: "${ATTACKLENS_OPENROUTER_DAILY_BUDGET_USD:=25}"
: "${ATTACKLENS_AI_ALLOW_TRAINING_MODELS:=false}"

# Legacy env-var AI path (manager/manager/ai_analyst.py) — Anthropic only.
: "${ANTHROPIC_API_KEY:=}"
: "${AI_ANALYST_MODEL:=claude-sonnet-4-6}"
: "${AI_ANALYST_ENABLED:=true}"

: "${LANGGRAPH_INVESTIGATIONS_ENABLED:=true}"
: "${LANGGRAPH_AUTO_INVESTIGATE:=true}"
: "${LANGGRAPH_AUTO_SEVERITIES:=critical,high}"
: "${LANGGRAPH_MAX_REVIEW_ROUNDS:=2}"

: "${ATTACKLENS_VALIDATION:=false}"
: "${ATTACKLENS_AI_VALIDATION:=false}"
: "${ATTACKLENS_AI_PRECISION_THRESHOLD:=0.90}"

: "${ABUSEIPDB_KEY:=}"
: "${OTX_KEY:=}"
: "${GREYNOISE_KEY:=}"
: "${NVD_API_KEY:=}"

: "${SMTP_HOST:=}"
: "${SMTP_PORT:=587}"
: "${SMTP_USER:=}"
: "${SMTP_PASS:=}"
: "${SMTP_FROM:=}"
: "${SMTP_TLS:=starttls}"
: "${OUTLOOK_CLIENT_ID:=}"
: "${OUTLOOK_CLIENT_SECRET:=}"
: "${OUTLOOK_TENANT_ID:=}"
: "${OUTLOOK_SENDER:=}"
: "${ALERT_RECIPIENTS:=}"
: "${DIGEST_RECIPIENTS:=}"
: "${EMAIL_ENABLED:=true}"

: "${THREAT_FEED_INTERVAL_SECONDS:=3600}"
: "${NVD_SYNC_INTERVAL_SECONDS:=7200}"
: "${NVD_SYNC_HOURS:=48}"
: "${NVD_SYNC_MAX_PAGES:=3}"
: "${NVD_MIRROR_ENABLED:=true}"

# Every key env.sh writes below. Anything in .env that is NOT in this list is
# treated as user-added and copied through verbatim.
MANAGED_KEYS=(
  PUBLIC_IP DOMAIN BIND_PORT ADMIN_EMAIL TLS_MODE
  ADMIN_TOKEN OPEN_ENROLLMENT ENROLLMENT_TOKENS JWT_SECRET
  DEFAULT_KEY_EXPIRY_DAYS LOG_LEVEL CORS_ORIGINS APP_UID APP_GID
  AI_PROVIDER AI_MODEL AI_API_KEY AI_BASE_URL
  OPENROUTER_APP_URL OPENROUTER_APP_TITLE
  ATTACKLENS_OPENROUTER_ENABLED ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE
  ATTACKLENS_OPENROUTER_DAILY_BUDGET_USD ATTACKLENS_AI_ALLOW_TRAINING_MODELS
  ANTHROPIC_API_KEY AI_ANALYST_MODEL AI_ANALYST_ENABLED
  LANGGRAPH_INVESTIGATIONS_ENABLED LANGGRAPH_AUTO_INVESTIGATE
  LANGGRAPH_AUTO_SEVERITIES LANGGRAPH_MAX_REVIEW_ROUNDS
  ATTACKLENS_VALIDATION ATTACKLENS_AI_VALIDATION ATTACKLENS_AI_PRECISION_THRESHOLD
  ABUSEIPDB_KEY OTX_KEY GREYNOISE_KEY NVD_API_KEY
  SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_FROM SMTP_TLS
  OUTLOOK_CLIENT_ID OUTLOOK_CLIENT_SECRET OUTLOOK_TENANT_ID OUTLOOK_SENDER
  ALERT_RECIPIENTS DIGEST_RECIPIENTS EMAIL_ENABLED
  THREAT_FEED_INTERVAL_SECONDS NVD_SYNC_INTERVAL_SECONDS
  NVD_SYNC_HOURS NVD_SYNC_MAX_PAGES NVD_MIRROR_ENABLED
)

is_managed() {
  local needle="$1" k
  for k in "${MANAGED_KEYS[@]}"; do
    [[ "$k" == "$needle" ]] && return 0
  done
  return 1
}

# Carry through any variable present in .env that env.sh does not manage. The
# old 'cat > .env' truncated the file, so hand-added keys were silently lost on
# every re-run — load_existing() sourced them but nothing wrote them back.
EXTRA_LINES=""
EXTRA_COUNT=0
if [[ -f .env ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    parse_env_line "$line" || continue
    if ! is_managed "$ENV_KEY"; then
      # Re-emit quoted rather than verbatim, so a value carrying spaces or shell
      # metacharacters stays safe to re-read on the next run.
      escaped="${ENV_VAL//\\/\\\\}"
      escaped="${escaped//\"/\\\"}"
      EXTRA_LINES+="${ENV_KEY}=\"${escaped}\""$'\n'
      EXTRA_COUNT=$(( EXTRA_COUNT + 1 ))
    fi
  done < .env
fi

# Timestamped backup before any rewrite, so a bad run is always recoverable.
if [[ -f .env ]]; then
  ENV_BACKUP=".env.bak.$(date -u +%Y%m%d%H%M%S)"
  cp .env "$ENV_BACKUP"
  chmod 600 "$ENV_BACKUP" 2>/dev/null || true
  info "Previous .env backed up to ${ENV_BACKUP}"
fi

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

# Signs dashboard session tokens AND derives the AES-256 key that encrypts your
# stored AI provider key. Changing it logs everyone out and makes the existing
# data/ai_provider.enc undecryptable — you would re-enter the AI key in
# Settings. Keep it stable, and treat it like any other production secret.
JWT_SECRET="${JWT_SECRET}"

# ── Key policy ────────────────────────────────────────────────────────────────
# Days until agent API keys expire. 0 = never expire.
DEFAULT_KEY_EXPIRY_DAYS=${DEFAULT_KEY_EXPIRY_DAYS}

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL=${LOG_LEVEL}

# ── CORS ─────────────────────────────────────────────────────────────────────
CORS_ORIGINS="${CORS_ORIGINS}"

# ── Container runtime user ────────────────────────────────────────────────────
# The manager/threat-intel images run as this uid/gid (manager/Dockerfile:
# useradd -u 1000 jarvis). install.sh chowns the ./data and ./logs bind mounts
# to it so the container can write its logs and store on first boot. Change only
# if you rebuild the image with a different user.
APP_UID=${APP_UID}
APP_GID=${APP_GID}

# ── AI provider ───────────────────────────────────────────────────────────────
# Set AI_API_KEY to seed the encrypted provider store on first boot. The key is
# health-checked against the provider, then written AES-256-GCM encrypted to
# data/ai_provider.enc — never in plaintext, never returned by the API. This is
# a ONE-TIME seed: once a provider is configured, the stored config wins and
# these values are ignored. You may blank AI_API_KEY afterwards.
#
# To change the key later, use the dashboard (Settings -> AI Provider) or:
#
#   curl -X POST https://<manager>/api/v1/ai/provider \\
#        -H 'X-Admin-Token: <ADMIN_TOKEN above>' \\
#        -H 'Content-Type: application/json' \\
#        -d '{"provider":"openrouter","api_key":"sk-or-...","model":"..."}'
#
# openrouter is recommended — one key reaches every model including Claude, and
# it is the only provider with spend guards and cost tracking wired up.
AI_PROVIDER=${AI_PROVIDER}
AI_MODEL="${AI_MODEL}"
AI_API_KEY="${AI_API_KEY}"
AI_BASE_URL="${AI_BASE_URL}"

# Attribution headers sent to OpenRouter (shown in your OpenRouter dashboard).
OPENROUTER_APP_URL="${OPENROUTER_APP_URL}"
OPENROUTER_APP_TITLE="${OPENROUTER_APP_TITLE}"

# Spend guard. The kill switch stops all OpenRouter calls immediately; the other
# two cap per-minute call rate and daily spend (USD, process-local).
ATTACKLENS_OPENROUTER_ENABLED=${ATTACKLENS_OPENROUTER_ENABLED}
ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE=${ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE}
ATTACKLENS_OPENROUTER_DAILY_BUDGET_USD=${ATTACKLENS_OPENROUTER_DAILY_BUDGET_USD}

# Free OpenRouter models (':free') generally TRAIN ON SUBMITTED PROMPTS, and
# these prompts carry endpoint telemetry: process names, package lists, finding
# evidence. Calls to a free model are refused until you accept that here.
# Set to true to use free models; keep false and pick a paid model otherwise.
ATTACKLENS_AI_ALLOW_TRAINING_MODELS=${ATTACKLENS_AI_ALLOW_TRAINING_MODELS}

# Legacy Anthropic-only path used by the remediation API. Leave empty once the
# encrypted provider config above is in use.
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}"
AI_ANALYST_MODEL=${AI_ANALYST_MODEL}
AI_ANALYST_ENABLED=${AI_ANALYST_ENABLED}

# ── Post-finding LangGraph investigation ──────────────────────────────────────
# Runs only after deterministic detection has persisted a finding, and stays
# read-only until an analyst approves its verdict.
LANGGRAPH_INVESTIGATIONS_ENABLED=${LANGGRAPH_INVESTIGATIONS_ENABLED}
LANGGRAPH_AUTO_INVESTIGATE=${LANGGRAPH_AUTO_INVESTIGATE}
LANGGRAPH_AUTO_SEVERITIES=${LANGGRAPH_AUTO_SEVERITIES}
LANGGRAPH_MAX_REVIEW_ROUNDS=${LANGGRAPH_MAX_REVIEW_ROUNDS}

# ── AttackLens precision validation ───────────────────────────────────────────
ATTACKLENS_VALIDATION=${ATTACKLENS_VALIDATION}
ATTACKLENS_AI_VALIDATION=${ATTACKLENS_AI_VALIDATION}
ATTACKLENS_AI_PRECISION_THRESHOLD=${ATTACKLENS_AI_PRECISION_THRESHOLD}

# ── Threat Intel API keys (all optional — feeds degrade gracefully) ───────────
ABUSEIPDB_KEY="${ABUSEIPDB_KEY}"
OTX_KEY="${OTX_KEY}"
GREYNOISE_KEY="${GREYNOISE_KEY}"
NVD_API_KEY="${NVD_API_KEY}"

# ── Email notifications ───────────────────────────────────────────────────────
SMTP_HOST="${SMTP_HOST}"
SMTP_PORT=${SMTP_PORT}
SMTP_USER="${SMTP_USER}"
SMTP_PASS="${SMTP_PASS}"
SMTP_FROM="${SMTP_FROM}"
SMTP_TLS=${SMTP_TLS}
OUTLOOK_CLIENT_ID="${OUTLOOK_CLIENT_ID}"
OUTLOOK_CLIENT_SECRET="${OUTLOOK_CLIENT_SECRET}"
OUTLOOK_TENANT_ID="${OUTLOOK_TENANT_ID}"
OUTLOOK_SENDER="${OUTLOOK_SENDER}"
ALERT_RECIPIENTS="${ALERT_RECIPIENTS}"
DIGEST_RECIPIENTS="${DIGEST_RECIPIENTS}"
EMAIL_ENABLED=${EMAIL_ENABLED}

# ── Threat feed intervals ─────────────────────────────────────────────────────
THREAT_FEED_INTERVAL_SECONDS=${THREAT_FEED_INTERVAL_SECONDS}
NVD_SYNC_INTERVAL_SECONDS=${NVD_SYNC_INTERVAL_SECONDS}
NVD_SYNC_HOURS=${NVD_SYNC_HOURS}
NVD_SYNC_MAX_PAGES=${NVD_SYNC_MAX_PAGES}
NVD_MIRROR_ENABLED=${NVD_MIRROR_ENABLED}
EOF

# Append anything env.sh does not manage, so nothing is ever lost on a re-run.
if [[ -n "$EXTRA_LINES" ]]; then
  {
    echo ""
    echo "# ── Preserved from your previous .env ──────────────────────────────────────"
    echo "# env.sh does not manage these. They are copied through untouched."
    printf '%s' "$EXTRA_LINES"
  } >> .env
  info "Preserved ${EXTRA_COUNT} unmanaged variable(s)"
fi

# .env holds ADMIN_TOKEN, JWT_SECRET and any API keys — keep it owner-only.
chmod 600 .env 2>/dev/null || warn "Could not chmod 600 .env — check permissions"

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
        header_up X-Forwarded-Proto {scheme}
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
        header_up X-Forwarded-Proto {scheme}
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
