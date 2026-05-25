#!/usr/bin/env bash
# =============================================================================
#  dev.sh — Run AttackLens manager natively (no Docker)
#
#  Skips: RabbitMQ, Caddy, Threat-Intel container, nginx
#  Uses:  embedded threat intel, direct HTTP, local SQLite
#
#  Usage:
#    bash dev.sh              # start on http://localhost:8080
#    bash dev.sh --port 9000  # custom port
#    bash dev.sh --stop       # kill running dev server
#    bash dev.sh --logs       # tail the dev log
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="$REPO_ROOT/data/.secrets"
LOG_FILE="$REPO_ROOT/logs/manager-dev.log"
PID_FILE="$REPO_ROOT/logs/manager-dev.pid"
DEV_PORT="${DEV_PORT:-8080}"

# ── Parse args ────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --port)  shift; DEV_PORT="$1"; shift ;;
    --stop)  _stop=1 ;;
    --logs)  _logs=1 ;;
  esac
done

if [[ "${_stop:-}" == "1" ]]; then
  if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    kill "$PID" 2>/dev/null && echo "Stopped manager (pid $PID)" || echo "Process $PID already stopped"
    rm -f "$PID_FILE"
  else
    pkill -f "uvicorn manager.manager.server" 2>/dev/null && echo "Stopped manager" || echo "No running manager found"
  fi
  exit 0
fi

if [[ "${_logs:-}" == "1" ]]; then
  tail -f "$LOG_FILE"
  exit 0
fi

# ── Check Python ──────────────────────────────────────────────────────────────
PYTHON=$(command -v python3.12 2>/dev/null || command -v python3 2>/dev/null || "")
if [[ -z "$PYTHON" ]]; then
  echo "ERROR: python3 not found. Install Python 3.12+." >&2
  exit 1
fi

PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if [[ $(echo "$PY_VER < 3.11" | bc -l 2>/dev/null || echo 0) == "1" ]]; then
  echo "WARNING: Python $PY_VER detected. Python 3.12+ recommended."
fi

# ── Install / verify deps ─────────────────────────────────────────────────────
echo "Checking dependencies..."
if ! "$PYTHON" -c "import fastapi, uvicorn, aiosqlite, cryptography" 2>/dev/null; then
  echo "Installing manager requirements..."
  "$PYTHON" -m pip install -q -r "$REPO_ROOT/manager/requirements.txt"
fi

# ── Create runtime dirs ───────────────────────────────────────────────────────
mkdir -p "$REPO_ROOT/data" "$REPO_ROOT/logs"

# ── Load or generate secrets ──────────────────────────────────────────────────
if [[ -f "$SECRETS_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$SECRETS_FILE"
fi

if [[ -z "${ADMIN_TOKEN:-}" ]]; then
  ADMIN_TOKEN=$("$PYTHON" -c "import secrets; print('sk-admin-' + secrets.token_urlsafe(24))")
  echo "ADMIN_TOKEN=$ADMIN_TOKEN" >> "$SECRETS_FILE"
fi

if [[ -z "${API_KEY:-}" ]]; then
  API_KEY=$("$PYTHON" -c "import secrets; print(secrets.token_urlsafe(32))")
  echo "API_KEY=$API_KEY" >> "$SECRETS_FILE"
fi

export ADMIN_TOKEN API_KEY

# ── Load .env if present (skip Docker-specific vars) ─────────────────────────
if [[ -f "$REPO_ROOT/.env" ]]; then
  while IFS='=' read -r key val; do
    [[ "$key" =~ ^# ]] && continue
    [[ -z "$key" ]] && continue
    # Skip vars that only make sense in Docker
    [[ "$key" =~ ^(PUBLIC_IP|DOMAIN|TLS_MODE|BIND_PORT)$ ]] && continue
    [[ -z "${!key:-}" ]] && export "$key=$val"
  done < "$REPO_ROOT/.env"
fi

# ── Dev environment (overrides .env) ─────────────────────────────────────────
export PYTHONPATH="$REPO_ROOT/manager:$REPO_ROOT"

export BIND_HOST="${BIND_HOST:-127.0.0.1}"
export BIND_PORT="$DEV_PORT"
export TLS_MODE="none"
export TLS_CERT=""
export TLS_KEY=""

export DATA_DIR="${DATA_DIR:-$REPO_ROOT/data}"
export LOG_FILE="$LOG_FILE"
export LOG_LEVEL="${LOG_LEVEL:-info}"

export OPEN_ENROLLMENT="${OPEN_ENROLLMENT:-true}"
export CORS_ORIGINS="${CORS_ORIGINS:-*}"

# Disable heavy services — embedded threat intel handles everything locally
export RABBITMQ_URL=""
export THREAT_INTEL_URL=""
export MANAGER_EMBEDDED_THREAT_INTEL="true"

# AI analyst — read from shell env if available
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
export AI_ANALYST_ENABLED="${AI_ANALYST_ENABLED:-true}"

# Email — disabled by default in dev
export EMAIL_ENABLED="${EMAIL_ENABLED:-false}"

# ── Print startup banner ──────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          AttackLens Manager — Dev Mode (no Docker)          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
printf "║  Dashboard:    http://localhost:%-31s║\n" "$DEV_PORT"
printf "║  Health:       http://localhost:$DEV_PORT/%-22s║\n" "health"
echo "║                                                              ║"
printf "║  Admin token:  %-47s║\n" "$ADMIN_TOKEN"
echo "║                                                              ║"
echo "║  RabbitMQ:       disabled (sync ingest)                     ║"
echo "║  Threat-Intel:   embedded                                   ║"
echo "║  TLS:            off (plain HTTP)                           ║"
echo "║                                                              ║"
printf "║  Logs:  %-54s║\n" "$LOG_FILE"
printf "║  Data:  %-54s║\n" "$DATA_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop."
echo ""

# ── Start uvicorn ─────────────────────────────────────────────────────────────
exec "$PYTHON" -m uvicorn manager.manager.server:app \
  --host     "$BIND_HOST" \
  --port     "$DEV_PORT"  \
  --log-level "$LOG_LEVEL" \
  --reload   \
  --reload-dir "$REPO_ROOT/manager"
