#!/bin/bash
# Entrypoint for the standalone central threat-intel service.

set -e

mkdir -p /app/data /app/logs

echo ""
echo "AttackLens Central Threat Intel — starting"
echo "  API:      http://0.0.0.0:8090"
echo "  Health:   http://0.0.0.0:8090/health"
echo "  Intel DB: ${THREAT_INTEL_DB:-${DATA_DIR:-/app/data}/intel.db}"
echo ""

exec python3 -m uvicorn manager.manager.threat_intel_service:app \
    --host "0.0.0.0" \
    --port "8090" \
    --log-level "${LOG_LEVEL:-info}"
