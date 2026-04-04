#!/bin/bash
# =============================================================================
#  start.sh — Start manager + agent (reads enrollment token from agent.toml)
#
#  Usage:
#    bash start.sh            → start manager
#    bash start.sh agent      → start agent
#    bash start.sh both       → start both (manager in background)
# =============================================================================

set -e
cd "$(dirname "$0")"

# ── Read enrollment token from agent.toml ─────────────────────────────────────
if [ ! -f agent.toml ]; then
  echo ""
  echo "  ERROR: agent.toml not found."
  echo "  Run:   cp agent/config/agent.toml.example agent.toml"
  echo "         make enroll-token"
  echo ""
  exit 1
fi

ENROLL_TOKEN=$(python3 -c "
import tomllib
with open('agent.toml', 'rb') as f:
    cfg = tomllib.load(f)
print(cfg.get('enrollment', {}).get('token', '').strip(), end='')
" 2>/dev/null || true)

if [ -n "$ENROLL_TOKEN" ]; then
  export ENROLLMENT_TOKENS="$ENROLL_TOKEN"
  echo ""
  echo "  ENROLLMENT_TOKENS loaded from agent.toml (...${ENROLLMENT_TOKENS: -8})"
  echo ""
else
  echo ""
  echo "  WARNING: No enrollment token in agent.toml [enrollment] token."
  echo "  Run:  make enroll-token  to generate one."
  echo ""
fi

# ── Kill any process already on port 8443 ─────────────────────────────────────
PORT=${BIND_PORT:-8443}
EXISTING=$(lsof -ti tcp:$PORT 2>/dev/null || true)
if [ -n "$EXISTING" ]; then
  echo "  Killing existing process on port $PORT (PID $EXISTING)..."
  kill -9 $EXISTING 2>/dev/null || true
  sleep 1
fi

# ── Decide what to start ───────────────────────────────────────────────────────
MODE=${1:-manager}

start_manager() {
  echo "  Starting manager on https://0.0.0.0:$PORT ..."
  echo ""
  PYTHONPATH=. python3 -m uvicorn manager.manager.server:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    --ssl-certfile certs/server.crt \
    --ssl-keyfile  certs/server.key \
    --log-level info
}

start_agent() {
  echo "  Starting agent (config: agent.toml) ..."
  echo ""
  PYTHONPATH=. python3 -m agent.agent.core --config agent.toml
}

case "$MODE" in
  manager)
    start_manager
    ;;
  agent)
    start_agent
    ;;
  both)
    echo "  Starting manager in background..."
    start_manager &
    MGR_PID=$!
    sleep 3
    echo "  Manager PID: $MGR_PID"
    echo "  Starting agent in foreground..."
    start_agent
    ;;
  *)
    echo "  Usage: bash start.sh [manager|agent|both]"
    exit 1
    ;;
esac
