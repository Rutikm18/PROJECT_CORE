#!/bin/bash
# =============================================================================
#  manager/scripts/entrypoint.sh — Docker container entrypoint
#
#  TLS is handled entirely by Caddy — manager always runs plain HTTP on 8080.
#
#  On first boot:
#    1. Auto-generates ENROLLMENT_TOKENS and ADMIN_TOKEN (if not set via .env)
#    2. Persists generated secrets to /app/data/.secrets (survives restarts)
#    3. Prints all credentials to stdout (visible in docker logs)
#    4. Starts uvicorn on plain HTTP port 8080
# =============================================================================

set -e

SECRETS_FILE="/app/data/.secrets"

mkdir -p /app/data /app/logs

# ── Load persisted secrets ────────────────────────────────────────────────────
if [ -f "$SECRETS_FILE" ]; then
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"
fi

# ── Enrollment mode ───────────────────────────────────────────────────────────
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

# ── Print credentials banner ──────────────────────────────────────────────────
PUBLIC_IP_DISPLAY="${PUBLIC_IP:-<your-server-ip>}"
BIND_PORT="${BIND_PORT:-8443}"

if [ -n "${DOMAIN:-}" ]; then
    MANAGER_URL="https://$DOMAIN"
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
else
echo "║  ENROLLMENT: TOKEN REQUIRED                                 ║"
printf "║  %-60s║\n" "  Token: $ENROLLMENT_TOKENS"
fi
echo "║                                                              ║"
echo "║  ADMIN TOKEN (for key management API):                      ║"
printf "║  %-60s║\n" "  $ADMIN_TOKEN"
echo "║                                                              ║"
printf "║  Manager URL:  %-47s║\n" "$MANAGER_URL"
printf "║  Dashboard:    %-47s║\n" "$MANAGER_URL"
printf "║  Health:       %-47s║\n" "$MANAGER_URL/health"
echo "║                                                              ║"
echo "║  Secrets file: /app/data/.secrets                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Start uvicorn (plain HTTP — Caddy handles TLS) ───────────────────────────
exec python3 -m uvicorn manager.manager.server:app \
    --host      "0.0.0.0" \
    --port      "8080" \
    --log-level "${LOG_LEVEL:-info}"
