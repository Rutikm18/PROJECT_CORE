#!/usr/bin/env bash
# =============================================================================
#  generate_config.sh — Write a complete agent.toml
#
#  Bundled inside the .pkg at /Library/AttackLens/bin/generate_config.sh
#  Called by: postinstall (fresh install), attacklens-service update-config
#
#  Environment variables (all optional except MANAGER_URL for new installs):
#    MANAGER_URL      — http://HOST:8080 or https://HOST
#    AGENT_ID         — stable machine ID (auto-derived from HW UUID if empty)
#    AGENT_NAME       — human label (default: ComputerName)
#    AGENT_DESC       — optional description
#    AGENT_TAGS       — comma-separated tags  e.g. "prod,finance"
#    ENROLL_TOKEN     — sk-enroll-<hex> for manager with enrollment tokens enabled
#    TLS_VERIFY       — true/false (auto-set from URL scheme)
#    INSTALL_DIR      — default: /Library/AttackLens
#    LOG_DIR          — default: $INSTALL_DIR/logs
#    SECURITY_DIR     — default: $INSTALL_DIR/security
#    RUN_AS_USER      — optional: run service as this user (default: root)
#    RUN_AS_GROUP     — optional: run service as this group (default: wheel)
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
AGENT_DESC="${AGENT_DESC:-}"
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
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Stable agent ID from hardware UUID ───────────────────────────────────────
if [[ -z "$AGENT_ID" ]]; then
  HW_UUID=$(system_profiler SPHardwareDataType 2>/dev/null \
    | awk '/Hardware UUID/{print tolower($NF)}')
  if [[ -n "$HW_UUID" ]]; then
    AGENT_ID="mac-${HW_UUID}"
  else
    AGENT_ID="mac-$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')"
  fi
fi

# ── Human-readable name from ComputerName ────────────────────────────────────
if [[ -z "$AGENT_NAME" ]]; then
  AGENT_NAME=$(scutil --get ComputerName 2>/dev/null \
    || scutil --get HostName 2>/dev/null \
    || hostname)
  AGENT_NAME="${AGENT_NAME%%$'\n'*}"   # strip newlines
fi

# ── Convert comma-separated tags to TOML array ───────────────────────────────
TAGS_TOML="[]"
if [[ -n "$AGENT_TAGS" ]]; then
  # "prod,finance" → ["prod", "finance"]
  TAGS_TOML=$(python3 -c "
import sys
tags = [t.strip() for t in '$AGENT_TAGS'.split(',') if t.strip()]
print('[' + ', '.join(f'\"\"\"' + t + '\"\"\"' for t in tags) + ']')
" 2>/dev/null || echo "[]")
fi

# ── Optional identity extras ─────────────────────────────────────────────────
IDENTITY_EXTRAS=""
[[ -n "$AGENT_DESC" ]]  && IDENTITY_EXTRAS+=$'\n'"description = \"${AGENT_DESC}\""
IDENTITY_EXTRAS+=$'\n'"tags        = ${TAGS_TOML}"
[[ -n "$RUN_AS_USER" ]] && IDENTITY_EXTRAS+=$'\n'"run_as_user  = \"${RUN_AS_USER}\""
[[ -n "$RUN_AS_GROUP" ]] && IDENTITY_EXTRAS+=$'\n'"run_as_group = \"${RUN_AS_GROUP}\""
[[ -n "$RUN_AS_UID" ]]  && IDENTITY_EXTRAS+=$'\n'"run_as_uid   = ${RUN_AS_UID}"

# ── Enrollment block ─────────────────────────────────────────────────────────
ENROLL_BLOCK=""
if [[ -n "$ENROLL_TOKEN" ]]; then
  ENROLL_BLOCK=$(cat <<EOF

[enrollment]
token    = "${ENROLL_TOKEN}"
keystore = "keychain"
EOF
)
else
  ENROLL_BLOCK=$(cat <<'EOF'

[enrollment]
# token = ""       # set to sk-enroll-xxx if manager requires enrollment tokens
keystore = "keychain"   # "keychain" (macOS Keychain) or "file" (fallback)
EOF
)
fi

# ── Create directories ────────────────────────────────────────────────────────
mkdir -p "${INSTALL_DIR}" \
         "${INSTALL_DIR}/data" \
         "${INSTALL_DIR}/spool" \
         "${SECURITY_DIR}" \
         "${LOG_DIR}"

# ── Write agent.toml ──────────────────────────────────────────────────────────
cat > "${CONFIG_PATH}" <<TOML
# =============================================================================
#  AttackLens Agent Configuration
#  Generated: ${TIMESTAMP}
#
#  Quick start:
#    sudo attacklens-service set-manager <IP>   — update manager IP
#    sudo attacklens-service restart            — apply changes
#    attacklens-service status                  — check service + enrollment
#    attacklens-service diagnose                — connectivity + health check
#
#  Hot reload (no restart):
#    sudo attacklens-service reload             — SIGHUP
#
#  SECURITY MODEL
#  API key is auto-generated at first manager contact and stored in
#  macOS System Keychain (service: com.attacklens.agent).
#  It is NOT written to this file.  To re-enroll: attacklens-service enroll
# =============================================================================


# ── Agent identity ────────────────────────────────────────────────────────────
[agent]
id          = "${AGENT_ID}"
name        = "${AGENT_NAME}"${IDENTITY_EXTRAS}


# ── Manager connection ────────────────────────────────────────────────────────
[manager]
url             = "${MANAGER_URL}"
tls_verify      = ${TLS_VERIFY}
timeout_sec     = 30        # per-request HTTP timeout
retry_attempts  = 3         # retries before spooling to disk
retry_delay_sec = 5         # base retry delay (exponential backoff)
max_queue_size  = 1000      # in-memory queue depth before dropping oldest
# api_key = ""              # DO NOT SET — managed by enrollment + Keychain
${ENROLL_BLOCK}


# ── Watchdog ──────────────────────────────────────────────────────────────────
[watchdog]
enabled            = true
check_interval_sec = 30    # how often watchdog polls the agent process
max_restarts       = 5     # max crashes within restart_window_sec before giving up
restart_window_sec = 300   # sliding 5-min window for restart counting


# ── Filesystem paths ──────────────────────────────────────────────────────────
[paths]
install_dir  = "${INSTALL_DIR}"
config_dir   = "${INSTALL_DIR}"
log_dir      = "${LOG_DIR}"
data_dir     = "${INSTALL_DIR}/data"
security_dir = "${SECURITY_DIR}"
spool_dir    = "${INSTALL_DIR}/spool"
pid_file     = "${INSTALL_DIR}/attacklens-agent.pid"

[binaries]
agent    = "${INSTALL_DIR}/bin/run_agent.py"
watchdog = "${INSTALL_DIR}/bin/run_watchdog.py"


# ── Logging ───────────────────────────────────────────────────────────────────
[logging]
level   = "INFO"    # DEBUG | INFO | WARNING | ERROR
file    = "${LOG_DIR}/agent.log"
max_mb  = 10        # rotate at this file size (MB)
backups = 5         # keep N rotated log files


# ── Collection orchestrator ───────────────────────────────────────────────────
[collection]
enabled        = true
tick_sec       = 5     # how often the orchestrator checks section timers
worker_threads = 0     # 0 = auto (max(4, num_sections)) — tune on low-power devices


# ══════════════════════════════════════════════════════════════════════════════
#  VOLATILE  — 10 s  (high-frequency runtime state)
# ══════════════════════════════════════════════════════════════════════════════

# CPU %, memory %, load averages, disk/network I/O rates
# Fields: cpu_percent, mem_percent, cpu_per_core[], cpu_cores, cpu_cores_physical,
#         cpu_freq_mhz, mem_used_mb, mem_total_mb, mem_available_mb,
#         swap_percent, swap_used_mb, swap_total_mb,
#         disk_read_mb_s, disk_write_mb_s, net_sent_mb_s, net_recv_mb_s,
#         load_1m, load_5m, load_15m, uptime_sec
[collection.sections.metrics]
enabled      = true
interval_sec = 10
send         = true

# Active TCP/UDP connections (all states: ESTABLISHED, LISTEN, CLOSE_WAIT, TIME_WAIT)
# Fields: proto, local_addr, local_port, remote_addr, remote_port,
#         remote_service, state, pid, process, user, is_private, direction
[collection.sections.connections]
enabled      = true
interval_sec = 10
send         = true

# Running process list (top N by CPU) with codesign status
# Fields: pid, ppid, name, user, cpu_percent, mem_percent, mem_rss_mb,
#         mem_vms_mb, status, started_at, cmdline (512 chars), exe, signed
[collection.sections.processes]
enabled      = true
interval_sec = 10
send         = true
max_processes = 80


# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK  — 30 s – 2 min
# ══════════════════════════════════════════════════════════════════════════════

# All LISTEN sockets (attack surface / open port map)
# Fields: proto, port, bind_addr, state, pid, process
[collection.sections.ports]
enabled      = true
interval_sec = 30
send         = true

# Network interfaces, DNS, default gateway, WiFi
# Fields: interfaces[], dns_servers[], default_gw, hostname, domain,
#         wifi_ssid, wifi_bssid, wifi_rssi, wifi_channel
[collection.sections.network]
enabled      = true
interval_sec = 120
send         = true

# ARP table — LAN neighbours (lateral movement baseline)
# Fields: ip, mac, interface, state
[collection.sections.arp]
enabled      = true
interval_sec = 120
send         = true

# Mounted filesystems
# Fields: device, mountpoint, fstype, options
[collection.sections.mounts]
enabled      = true
interval_sec = 120
send         = true


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM STATE  — 2 min
# ══════════════════════════════════════════════════════════════════════════════

# Battery: charge %, cycle count, condition, power source
# (returns present=false on desktop Macs — safe to leave enabled)
[collection.sections.battery]
enabled      = true
interval_sec = 120
send         = true

# Top 60 processes by open file-descriptor count (leak / exhaustion detection)
[collection.sections.openfiles]
enabled      = true
interval_sec = 120
send         = true
max_processes = 60

# LaunchDaemons and LaunchAgents (persistence mechanism visibility)
# Fields: name, status (running/stopped), enabled, pid, exit_code, type
[collection.sections.services]
enabled      = true
interval_sec = 120
send         = true

# Local accounts, admin group, last login timestamps
# Fields: name, uid, gid, admin, locked, home, last_login
[collection.sections.users]
enabled      = true
interval_sec = 120
send         = true

# Hardware peripherals: USB, Thunderbolt, Bluetooth, GPU, SoC
# Fields per device: bus, name, vendor, product_id, vendor_id, serial, revision
[collection.sections.hardware]
enabled      = true
interval_sec = 120
send         = true

# Running containers (Docker, Podman)
# Fields: id, name, image, status, runtime, ports, created_at
[collection.sections.containers]
enabled      = true
interval_sec = 120
send         = true


# ══════════════════════════════════════════════════════════════════════════════
#  STORAGE INVENTORY  — 10 min
# ══════════════════════════════════════════════════════════════════════════════

# Disk volumes — device, mountpoint, fstype, total/used/free GB, usage %
[collection.sections.storage]
enabled      = true
interval_sec = 600
send         = true

# Scheduled tasks — crontab entries + launchd periodic timers
# Fields: name, type (cron|launchd), schedule, command, user, enabled,
#         last_run, next_run
[collection.sections.tasks]
enabled      = true
interval_sec = 600
send         = true


# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY POSTURE  — 1 hr
# ══════════════════════════════════════════════════════════════════════════════

# macOS security controls: SIP, Gatekeeper, FileVault, Firewall, XProtect,
# Secure Boot, auto-update, Developer Tools, Lockdown Mode,
# SSH/ARD/VNC status, password auth, screensaver lock
[collection.sections.security]
enabled      = true
interval_sec = 3600
send         = true

# Security-relevant sysctl parameters
# Fields: key, value, security_relevant
[collection.sections.sysctl]
enabled      = true
interval_sec = 3600
send         = true

# Critical config files: shell rc, SSH config, authorized_keys, /etc/hosts,
#   sshd_config, sudoers — content capped at 4 KiB each
# Includes suspicious pattern detection (curl|bash, eval base64, osascript)
[collection.sections.configs]
enabled      = true
interval_sec = 3600
send         = true


# ══════════════════════════════════════════════════════════════════════════════
#  SOFTWARE INVENTORY  — 24 hr
# ══════════════════════════════════════════════════════════════════════════════

# Installed .app bundles from /Applications, /System/Applications, ~/Applications
# Fields: name, version, bundle_id, path, vendor, signed, notarized, installed_at
[collection.sections.apps]
enabled      = true
interval_sec = 86400
send         = true

# Package managers: brew, pip3, npm -g, gem, cargo
# Fields: manager, name, version, latest, outdated, installed_at
[collection.sections.packages]
enabled      = true
interval_sec = 86400
send         = true

# Filesystem binary scan — SHA-256 of executables in key PATH directories
# Directories: /usr/bin, /usr/local/bin, /opt/homebrew/bin, /usr/sbin, /bin, /sbin
# Fields: path, name, hash_sha256, size_bytes, permissions, suid, sgid, world_writable
# Disabled by default: can be slow on large systems
[collection.sections.binaries]
enabled      = false
interval_sec = 86400
send         = false

# Software Bill of Materials (PURL format: pip3, brew, npm, gem)
# Fields: type, name, version, purl, license, source, cpe
[collection.sections.sbom]
enabled      = true
interval_sec = 86400
send         = true


# ── Agent health heartbeat (internal, always-on) ──────────────────────────────
# Emitted every 60 s by the orchestrator automatically.
# Contains circuit-breaker state, queue depth, uptime, section timing.
# Do NOT add a [collection.sections.agent_health] block — it is read-only.
TOML

chown root:wheel "${CONFIG_PATH}" 2>/dev/null || true
chmod 640 "${CONFIG_PATH}"

echo ""
echo "  agent.toml written → ${CONFIG_PATH}"
echo "  Agent ID  : ${AGENT_ID}"
echo "  Agent name: ${AGENT_NAME}"
echo "  Manager   : ${MANAGER_URL}"
echo ""
