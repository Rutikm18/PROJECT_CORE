#!/usr/bin/env bash
# =============================================================================
#  agent/os/macos/installer/generate_config.sh
#
#  Write a complete agent.toml to DATA_DIR/agent.toml.
#  Called by install.sh and the .pkg postinstall script.
#  Can also be run standalone to regenerate config after edits.
#
#  All parameters come from environment variables so that the
#  .pkg postinstall script can set them before calling this.
#
#  Required:
#    MANAGER_URL      — https://manager-host:8443
#    AGENT_ID         — unique UUID-style identifier
#    AGENT_NAME       — human-readable label (default: ComputerName)
#
#  Optional:
#    ENROLL_TOKEN     — sk-enroll-<hex>  (first-run enrollment)
#    MANAGER_API_KEY  — 64-hex key (skip enrollment)
#    TLS_VERIFY       — true/false (default: true)
#    INSTALL_DIR      — default: /Library/Jarvis
#    DATA_DIR         — default: /Library/Jarvis
#    LOG_DIR          — default: /Library/Jarvis/logs
#    SECURITY_DIR     — default: $DATA_DIR/security
# =============================================================================
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/Library/Jarvis}"
DATA_DIR="${DATA_DIR:-/Library/Jarvis}"
LOG_DIR="${LOG_DIR:-/Library/Jarvis/logs}"
SECURITY_DIR="${SECURITY_DIR:-${DATA_DIR}/security}"
MANAGER_URL="${MANAGER_URL:-https://localhost:8443}"
ENROLL_TOKEN="${ENROLL_TOKEN:-}"
MANAGER_API_KEY="${MANAGER_API_KEY:-}"
AGENT_ID="${AGENT_ID:-}"
AGENT_NAME="${AGENT_NAME:-$(scutil --get ComputerName 2>/dev/null || hostname)}"
TLS_VERIFY="${TLS_VERIFY:-true}"

CONFIG_PATH="${DATA_DIR}/agent.toml"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Resolve agent ID — prefer hardware UUID for stability across reinstalls
if [[ -z "$AGENT_ID" ]]; then
  HW_UUID=$(system_profiler SPHardwareDataType 2>/dev/null \
    | awk '/Hardware UUID/{print tolower($NF)}')
  if [[ -n "$HW_UUID" ]]; then
    AGENT_ID="mac-${HW_UUID}"
  else
    AGENT_ID="mac-$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')"
  fi
fi

# Ensure data dir exists
mkdir -p "${DATA_DIR}" "${SECURITY_DIR}" "${LOG_DIR}" "${DATA_DIR}/data"

# ── Write agent.toml ──────────────────────────────────────────────────────────
{
cat <<EOF
# agent.toml — mac_intel Agent Configuration
# Generated: ${TIMESTAMP}
# Edit this file to change agent behaviour; send SIGHUP or restart to apply.

[agent]
id   = "${AGENT_ID}"
name = "${AGENT_NAME}"

[manager]
url            = "${MANAGER_URL}"
tls_verify     = ${TLS_VERIFY}
timeout_sec    = 30
max_queue_size = 500
EOF

# Only write api_key if a 64-hex key was provided
if [[ ${#MANAGER_API_KEY} -eq 64 && "$MANAGER_API_KEY" =~ ^[0-9a-fA-F]+$ ]]; then
  echo "api_key = \"${MANAGER_API_KEY}\""
fi

cat <<EOF

[enrollment]
token    = "${ENROLL_TOKEN}"
keystore = "keychain"

[watchdog]
enabled            = true
check_interval_sec = 30
max_restarts       = 5
restart_window_sec = 300

[paths]
install_dir  = "${INSTALL_DIR}"
config_dir   = "${DATA_DIR}"
log_dir      = "${LOG_DIR}"
data_dir     = "${DATA_DIR}/data"
security_dir = "${SECURITY_DIR}"
pid_file     = "/Library/Jarvis/jarvis-agent.pid"

[binaries]
agent    = "${INSTALL_DIR}/bin/macintel-agent"
watchdog = "${INSTALL_DIR}/bin/macintel-watchdog"

[logging]
level   = "INFO"
file    = "${LOG_DIR}/agent.log"
max_mb  = 10
backups = 3

[collection]
tick_sec = 5

[collection.sections.metrics]
enabled = true; interval_sec = 60;    send = true

[collection.sections.connections]
enabled = true; interval_sec = 60;    send = true

[collection.sections.processes]
enabled = true; interval_sec = 60;    send = true

[collection.sections.ports]
enabled = true; interval_sec = 60;    send = true

[collection.sections.network]
enabled = true; interval_sec = 300;   send = true

[collection.sections.arp]
enabled = true; interval_sec = 300;   send = true

[collection.sections.mounts]
enabled = true; interval_sec = 300;   send = true

[collection.sections.battery]
enabled = true; interval_sec = 300;   send = true

[collection.sections.openfiles]
enabled = true; interval_sec = 120;   send = true

[collection.sections.services]
enabled = true; interval_sec = 300;   send = true

[collection.sections.users]
enabled = true; interval_sec = 600;   send = true

[collection.sections.hardware]
enabled = true; interval_sec = 3600;  send = true

[collection.sections.containers]
enabled = true; interval_sec = 120;   send = true

[collection.sections.security]
enabled = true; interval_sec = 600;   send = true

[collection.sections.sysctl]
enabled = true; interval_sec = 3600;  send = true

[collection.sections.configs]
enabled = true; interval_sec = 3600;  send = true

[collection.sections.storage]
enabled = true; interval_sec = 300;   send = true

[collection.sections.tasks]
enabled = true; interval_sec = 3600;  send = true

[collection.sections.apps]
enabled = true; interval_sec = 3600;  send = true

[collection.sections.packages]
enabled = true; interval_sec = 3600;  send = true

[collection.sections.binaries]
enabled = true; interval_sec = 86400; send = true

[collection.sections.sbom]
enabled = true; interval_sec = 86400; send = true
EOF
} > "${CONFIG_PATH}"

chown root:wheel "${CONFIG_PATH}" 2>/dev/null || true
chmod 640 "${CONFIG_PATH}"

echo "  agent.toml written to: ${CONFIG_PATH}"
echo "  Agent ID  : ${AGENT_ID}"
echo "  Agent Name: ${AGENT_NAME}"
echo "  Manager   : ${MANAGER_URL}"
