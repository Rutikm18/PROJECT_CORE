#!/usr/bin/env bash
# scripts/run_manager.sh — Start manager, always reading API_KEY from agent.toml
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# Read API_KEY from agent.toml when set (same 64-hex as agent after enroll or dev paste)
if [ -f agent.toml ]; then
    TOML_KEY=$(python3 -c "
import tomllib
with open('agent.toml','rb') as f:
    d = tomllib.load(f)
print((d.get('manager') or {}).get('api_key') or '')
")
    if [ -n "$TOML_KEY" ]; then
        export API_KEY="$TOML_KEY"
        echo "  API_KEY loaded from agent.toml (...${API_KEY: -8})"
    fi
    # Pass enrollment token to manager so POST /api/v1/enroll works
    export ENROLLMENT_TOKENS="$(python3 -c "
import tomllib
with open('agent.toml','rb') as f:
    t = (tomllib.load(f).get('enrollment') or {}).get('token') or ''
print(t.strip())
")"
    if [ -n "${ENROLLMENT_TOKENS:-}" ]; then
        echo "  ENROLLMENT_TOKENS set from agent.toml [enrollment] token"
    fi
fi

# Seed agent_keys from api_key so ingest HMAC matches without a separate enroll (dev convenience).
if [ -n "${API_KEY:-}" ]; then
    export MACOS_INTEL_DEV_BOOTSTRAP=1
    if [ -f agent.toml ]; then
        export BOOTSTRAP_AGENT_ID="$(python3 -c "import tomllib; f=open('agent.toml','rb'); print(tomllib.load(f)['agent']['id'])" 2>/dev/null || echo "agent-001")"
        export BOOTSTRAP_AGENT_NAME="$(python3 -c "import tomllib; f=open('agent.toml','rb'); print(tomllib.load(f).get('agent',{}).get('name','dev'))" 2>/dev/null || echo "dev")"
    fi
else
    echo "  NOTE: No API_KEY — use enrollment only, or add [manager] api_key (make keygen) for dev bootstrap"
fi

PYTHONPATH="$ROOT" exec python3 -m uvicorn manager.manager.server:app \
    --host 0.0.0.0 \
    --port "${BIND_PORT:-8443}" \
    --ssl-certfile certs/server.crt \
    --ssl-keyfile  certs/server.key \
    --log-level info \
    --reload
