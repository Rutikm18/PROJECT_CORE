#!/usr/bin/env bash
# List SOC findings flagged with CISA KEV (Known Exploited Vulnerabilities).
#
# Usage:
#   ./scripts/check_kev_findings.sh
#   MANAGER_API_URL=http://127.0.0.1:8443 CURL_INSECURE=1 ./scripts/check_kev_findings.sh
#   LIMIT=500 ./scripts/check_kev_findings.sh
#
set -euo pipefail

BASE="${MANAGER_API_URL:-http://localhost:8000}"
LIMIT="${LIMIT:-100}"

curl_args=(-sf)
if [[ "${CURL_INSECURE:-}" == "1" ]] || [[ "$BASE" == https://* ]]; then
  curl_args+=(-k)
fi

curl "${curl_args[@]}" "${BASE}/api/v1/soc/findings?limit=${LIMIT}" | python3 -c "
import json, sys

d = json.load(sys.stdin)
findings = d.get('findings', [])
kevs = [f for f in findings if f.get('kev')]

print(f'{len(kevs)} KEV-flagged findings (of {len(findings)} returned, limit=${LIMIT})')
for f in kevs[:3]:
    print(f\"  {f.get('title', '?')}  {f.get('cve_ids', [])}\")
"
