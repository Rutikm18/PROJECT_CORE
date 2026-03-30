#!/usr/bin/env bash
# scripts/run_manager.sh — Start manager, always reading API_KEY from agent.toml
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# Read API_KEY from agent.toml (overrides env var — ensures agent and manager always match)
if [ -f agent.toml ]; then
    TOML_KEY=$(python3 -c "import tomllib; f=open('agent.toml','rb'); print(tomllib.load(f)['manager']['api_key'])")
    if [ -n "$TOML_KEY" ]; then
        export API_KEY="$TOML_KEY"
        echo "  API_KEY loaded from agent.toml (...${API_KEY: -8})"
    fi
fi

if [ -z "${API_KEY:-}" ]; then
    echo ""
    echo "  ERROR: api_key not found in agent.toml and API_KEY env var is empty."
    echo "  Run:   make keygen  then paste the key into agent.toml [manager] api_key"
    echo ""
    exit 1
fi

PYTHONPATH="$ROOT" exec python3 -m uvicorn manager.manager.server:app \
    --host 0.0.0.0 \
    --port "${BIND_PORT:-8443}" \
    --ssl-certfile certs/server.crt \
    --ssl-keyfile  certs/server.key \
    --log-level info \
    --reload
