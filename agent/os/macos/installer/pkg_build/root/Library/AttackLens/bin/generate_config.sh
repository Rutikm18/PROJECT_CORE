#!/usr/bin/env bash
# =============================================================================
#  generate_config.sh — Write a complete agent.toml
#
#  Bundled inside the .pkg at /Library/AttackLens/bin/generate_config.sh
#  Called by: postinstall (fresh install), attacklens-service update-config
#
#  Environment variables:
#    MANAGER_URL      — http://HOST:8080 or https://HOST
#    AGENT_ID         — stable machine ID (auto-derived from HW UUID if empty)
#    AGENT_NAME       — human label (default: ComputerName)
#    AGENT_TAGS       — comma-separated tags e.g. "prod,finance"
#    ENROLL_TOKEN     — sk-enroll-<hex> if manager requires enrollment tokens
#    TLS_VERIFY       — true/false (auto-set from URL scheme)
#    INSTALL_DIR      — default: /Library/AttackLens
#    LOG_DIR          — default: $INSTALL_DIR/logs
#    SECURITY_DIR     — default: $INSTALL_DIR/security
#    RUN_AS_USER      — optional: run service as this user
#    RUN_AS_GROUP     — optional: run service as this group
#    RUN_AS_UID       — optional: numeric UID
# =============================================================================
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/Library/AttackLens}"
LOG_DIR="${LOG_DIR:-${INSTALL_DIR}/logs}"
SECURITY_DIR="${SECURITY_DIR:-${INSTALL_DIR}/security}"
MANAGER_URL="${MANAGER_URL:-http://YOUR_MANAGER_IP:8080}"
ENROLL_TOKEN="${ENROLL_TOKEN:-}"
AGENT_ID="${AGENT_ID:-}"
AGENT_NAME="${AGENT_NAME:-}"
AGENT_TAGS="${AGENT_TAGS:-}"
TLS_VERIFY="${TLS_VERIFY:-}"
RUN_AS_USER="${RUN_AS_USER:-}"
RUN_AS_GROUP="${RUN_AS_GROUP:-}"
RUN_AS_UID="${RUN_AS_UID:-}"

# http:// URLs don't need TLS
if [[ -z "$TLS_VERIFY" ]]; then
  [[ "$MANAGER_URL" == http://* ]] && TLS_VERIFY="false" || TLS_VERIFY="true"
fi

CONFIG_PATH="${INSTALL_DIR}/agent.toml"

# Stable agent ID from hardware UUID
if [[ -z "$AGENT_ID" ]]; then
  HW_UUID=$(system_profiler SPHardwareDataType 2>/dev/null \
    | awk '/Hardware UUID/{print tolower($NF)}')
  if [[ -n "$HW_UUID" ]]; then
    AGENT_ID="mac-${HW_UUID}"
  else
    AGENT_ID="mac-$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')"
  fi
fi

# Human-readable name
if [[ -z "$AGENT_NAME" ]]; then
  AGENT_NAME=$(scutil --get ComputerName 2>/dev/null \
    || scutil --get HostName 2>/dev/null \
    || hostname)
  AGENT_NAME="${AGENT_NAME%%$'\n'*}"
fi

# Create directories
mkdir -p "${INSTALL_DIR}" \
         "${INSTALL_DIR}/data" \
         "${INSTALL_DIR}/spool" \
         "${SECURITY_DIR}" \
         "${LOG_DIR}"

# Write agent.toml using Python — avoids bash heredoc Unicode corruption
/usr/local/bin/python3 - \
  "$CONFIG_PATH" \
  "$INSTALL_DIR" \
  "$LOG_DIR" \
  "$SECURITY_DIR" \
  "$MANAGER_URL" \
  "$TLS_VERIFY" \
  "$AGENT_ID" \
  "$AGENT_NAME" \
  "$AGENT_TAGS" \
  "$ENROLL_TOKEN" \
  "$RUN_AS_USER" \
  "$RUN_AS_GROUP" \
  "$RUN_AS_UID" \
<<'PYEOF'
import sys, os, datetime

(config_path, install_dir, log_dir, security_dir,
 manager_url, tls_verify, agent_id, agent_name,
 agent_tags, enroll_token, run_as_user, run_as_group, run_as_uid) = sys.argv[1:14]

ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

# Build optional identity extras
extras = []
tags_list = [t.strip() for t in agent_tags.split(',') if t.strip()] if agent_tags else []
tags_toml = '[' + ', '.join(f'"{t}"' for t in tags_list) + ']'
extras.append(f'tags        = {tags_toml}')
if run_as_user:  extras.append(f'run_as_user  = "{run_as_user}"')
if run_as_group: extras.append(f'run_as_group = "{run_as_group}"')
if run_as_uid:   extras.append(f'run_as_uid   = {run_as_uid}')
identity_extras = ('\n' + '\n'.join(extras)) if extras else ''

# Build enrollment block
if enroll_token:
    enroll_block = f'\n[enrollment]\ntoken    = "{enroll_token}"\nkeystore = "keychain"\n'
else:
    enroll_block = '\n[enrollment]\n# token = ""\nkeystore = "keychain"\n'

content = f"""# AttackLens Agent Configuration
# Generated: {ts}
#
# Service management:
#   sudo attacklens-service set-manager <IP>
#   sudo attacklens-service restart
#   attacklens-service status
#   attacklens-service diagnose

[agent]
id          = "{agent_id}"
name        = "{agent_name}"{identity_extras}

[manager]
url             = "{manager_url}"
tls_verify      = {tls_verify}
timeout_sec     = 30
retry_attempts  = 3
retry_delay_sec = 5
max_queue_size  = 1000
{enroll_block}
[watchdog]
enabled            = true
check_interval_sec = 30
max_restarts       = 5
restart_window_sec = 300

[paths]
install_dir  = "{install_dir}"
config_dir   = "{install_dir}"
log_dir      = "{log_dir}"
data_dir     = "{install_dir}/data"
security_dir = "{security_dir}"
spool_dir    = "{install_dir}/spool"
pid_file     = "{install_dir}/attacklens-agent.pid"

[binaries]
agent    = "{install_dir}/bin/run_agent.py"
watchdog = "{install_dir}/bin/run_watchdog.py"

[logging]
level   = "INFO"
file    = "{log_dir}/agent.log"
max_mb  = 10
backups = 5

[collection]
enabled        = true
tick_sec       = 5
worker_threads = 0

[collection.sections.metrics]
enabled      = true
interval_sec = 10
send         = true

[collection.sections.connections]
enabled      = true
interval_sec = 10
send         = true

[collection.sections.processes]
enabled      = true
interval_sec = 10
send         = true
max_processes = 80

[collection.sections.ports]
enabled      = true
interval_sec = 30
send         = true

[collection.sections.network]
enabled      = true
interval_sec = 120
send         = true

[collection.sections.arp]
enabled      = true
interval_sec = 120
send         = true

[collection.sections.mounts]
enabled      = true
interval_sec = 120
send         = true

[collection.sections.battery]
enabled      = true
interval_sec = 120
send         = true

[collection.sections.openfiles]
enabled      = true
interval_sec = 120
send         = true
max_processes = 60

[collection.sections.services]
enabled      = true
interval_sec = 120
send         = true

[collection.sections.users]
enabled      = true
interval_sec = 120
send         = true

[collection.sections.hardware]
enabled      = true
interval_sec = 120
send         = true

[collection.sections.containers]
enabled      = true
interval_sec = 120
send         = true

[collection.sections.storage]
enabled      = true
interval_sec = 600
send         = true

[collection.sections.tasks]
enabled      = true
interval_sec = 600
send         = true

[collection.sections.security]
enabled      = true
interval_sec = 3600
send         = true

[collection.sections.sysctl]
enabled      = true
interval_sec = 3600
send         = true

[collection.sections.configs]
enabled      = true
interval_sec = 3600
send         = true

[collection.sections.apps]
enabled      = true
interval_sec = 3600
send         = true

[collection.sections.packages]
enabled      = true
interval_sec = 3600
send         = true

[collection.sections.binaries]
enabled      = false
interval_sec = 3600
send         = false

[collection.sections.sbom]
enabled      = true
interval_sec = 3600
send         = true
"""

with open(config_path, 'w') as f:
    f.write(content)
os.chmod(config_path, 0o644)
print(f"  agent.toml written -> {config_path}")
PYEOF

# Verify it parses as valid TOML
/usr/local/bin/python3 -c "
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
with open('${CONFIG_PATH}', 'rb') as f:
    tomllib.load(f)
print('  TOML validation: OK')
" || { echo "  ERROR: generated agent.toml failed TOML validation"; exit 1; }

echo "  Agent ID  : ${AGENT_ID}"
echo "  Agent name: ${AGENT_NAME}"
echo "  Manager   : ${MANAGER_URL}"
