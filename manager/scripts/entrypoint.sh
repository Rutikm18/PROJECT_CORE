#!/bin/bash
# =============================================================================
#  manager/scripts/entrypoint.sh — Docker container entrypoint
#
#  On first boot:
#    1. Auto-generates a self-signed TLS cert (if none present)
#    2. Auto-generates ENROLLMENT_TOKENS and ADMIN_TOKEN (if not set)
#    3. Persists generated secrets to /app/data/.secrets (survives restarts)
#    4. Prints all credentials to stdout (visible in docker logs)
#    5. Starts uvicorn
# =============================================================================

set -e

SECRETS_FILE="/app/data/.secrets"
CERT_FILE="/app/certs/server.crt"
KEY_FILE="/app/certs/server.key"

mkdir -p /app/data /app/logs /app/certs

# ── Load persisted secrets ────────────────────────────────────────────────────
if [ -f "$SECRETS_FILE" ]; then
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"
fi

# ── Enrollment mode ───────────────────────────────────────────────────────────
# Default: OPEN_ENROLLMENT=true — agents only need the manager IP to connect.
# Set OPEN_ENROLLMENT=false to require a token (more restrictive).
OPEN_ENROLLMENT="${OPEN_ENROLLMENT:-true}"

# If token-mode is requested, auto-generate a token on first boot.
if [ "$OPEN_ENROLLMENT" = "false" ] && [ -z "$ENROLLMENT_TOKENS" ]; then
    ENROLLMENT_TOKENS=$(python3 -c "import secrets; print('sk-enroll-' + secrets.token_urlsafe(18))")
    echo "ENROLLMENT_TOKENS=$ENROLLMENT_TOKENS" >> "$SECRETS_FILE"
fi

# ── Auto-generate ADMIN_TOKEN ─────────────────────────────────────────────────
if [ -z "$ADMIN_TOKEN" ]; then
    ADMIN_TOKEN=$(python3 -c "import secrets; print('sk-admin-' + secrets.token_urlsafe(24))")
    echo "ADMIN_TOKEN=$ADMIN_TOKEN" >> "$SECRETS_FILE"
fi

export OPEN_ENROLLMENT
export ENROLLMENT_TOKENS
export ADMIN_TOKEN

# ── Generate self-signed TLS cert ─────────────────────────────────────────────
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating self-signed TLS certificate..."

    # Build SAN list: always include 0.0.0.0 + 127.0.0.1
    # Add PUBLIC_IP if set, add DOMAIN if set
    SAN="IP:0.0.0.0,IP:127.0.0.1"
    if [ -n "$PUBLIC_IP" ]; then
        SAN="$SAN,IP:$PUBLIC_IP"
    fi
    if [ -n "$DOMAIN" ]; then
        SAN="$SAN,DNS:$DOMAIN"
    fi

    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=${DOMAIN:-jarvis-manager}/O=Jarvis/OU=Agent" \
        -addext "subjectAltName=$SAN" \
        2>/dev/null

    chmod 600 "$KEY_FILE"
    echo "TLS cert generated. SAN: $SAN"
fi

# ── Print credentials banner ──────────────────────────────────────────────────
PUBLIC_IP_DISPLAY="${PUBLIC_IP:-<your-server-ip>}"
DOMAIN_DISPLAY="${DOMAIN:-}"
BIND_PORT="${BIND_PORT:-8443}"

if [ -n "$DOMAIN_DISPLAY" ]; then
    MANAGER_URL="https://$DOMAIN_DISPLAY"
else
    MANAGER_URL="https://$PUBLIC_IP_DISPLAY:$BIND_PORT"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              mac_intel Manager — Starting Up                ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
if [ "$OPEN_ENROLLMENT" = "true" ]; then
echo "║  ENROLLMENT: OPEN (no token required)                       ║"
echo "║  Agents connect with just the manager IP — no token needed. ║"
else
echo "║  ENROLLMENT: TOKEN REQUIRED                                 ║"
printf "║  %-60s║\n" "  Token: $ENROLLMENT_TOKENS"
fi
echo "║                                                              ║"
echo "║  ADMIN TOKEN (for key management API):                      ║"
printf "║  %-60s║\n" "  $ADMIN_TOKEN"
echo "║                                                              ║"
echo "║  Manager URL:                                               ║"
printf "║  %-60s║\n" "  $MANAGER_URL"
echo "║                                                              ║"
echo "║  Install agent on macOS (one command):                      ║"
printf "║  %-60s║\n" "  sudo bash install.sh --manager-url $MANAGER_URL"
echo "║                                                              ║"
echo "║  Dashboard: $MANAGER_URL"
printf "║  %-60s║\n" "  Admin API: $MANAGER_URL/api/v1/keys"
echo "║                                                              ║"
echo "║  Secrets: /app/data/.secrets                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Start uvicorn ─────────────────────────────────────────────────────────────
if [ "${TLS_DISABLED:-0}" = "1" ]; then
    # Plain HTTP — used when running behind a TLS-terminating proxy (Caddy, nginx)
    echo "TLS_DISABLED=1: running on plain HTTP (behind reverse proxy)"
    exec python3 -m uvicorn manager.manager.server:app \
        --host      "0.0.0.0" \
        --port      "${BIND_PORT:-8080}" \
        --log-level "${LOG_LEVEL:-info}"
else
    exec python3 -m uvicorn manager.manager.server:app \
        --host       "0.0.0.0" \
        --port       "${BIND_PORT:-8443}" \
        --ssl-certfile "$CERT_FILE" \
        --ssl-keyfile  "$KEY_FILE" \
        --log-level    "${LOG_LEVEL:-info}"
fi
