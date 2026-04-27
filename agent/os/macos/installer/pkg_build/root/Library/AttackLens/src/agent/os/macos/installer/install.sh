#!/usr/bin/env bash
# =============================================================================
#  AttackLens Agent — macOS Installer
#
#  USAGE:
#    sudo bash install.sh <MANAGER_IP>
#    sudo bash install.sh <MANAGER_IP> "My MacBook"
#
#  EXAMPLES:
#    sudo bash install.sh 34.224.174.38
#    sudo bash install.sh 34.224.174.38 "Rutik's MacBook Air"
#    sudo bash install.sh localhost           # local dev
#    sudo bash install.sh http://1.2.3.4:9090 # custom port/protocol
# =============================================================================
set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────
MANAGER_ARG="${1:-}"
# Strip newlines/extra whitespace from agent name (safety for multi-line shell input)
AGENT_NAME="${2:-$(scutil --get ComputerName 2>/dev/null || hostname)}"
AGENT_NAME="$(echo "$AGENT_NAME" | tr -d '\n\r' | tr -s ' ' | sed 's/^ //;s/ $//')"
ENROLL_TOKEN="${3:-}"

if [[ -z "$MANAGER_ARG" ]]; then
  echo "  Usage: sudo bash install.sh <MANAGER_IP> [agent_name]"
  echo "  Example: sudo bash install.sh 34.224.174.38"
  exit 1
fi

# Accept plain IP/hostname → http://IP:8080
if [[ "$MANAGER_ARG" == http://* || "$MANAGER_ARG" == https://* ]]; then
  MANAGER_URL="$MANAGER_ARG"
else
  MANAGER_URL="http://${MANAGER_ARG}:8080"
fi
TLS_VERIFY="false"
[[ "$MANAGER_URL" == https://* ]] && TLS_VERIFY="true"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "  ERROR: run as root:  sudo bash install.sh $*" >&2; exit 1
fi

# ── Paths ─────────────────────────────────────────────────────────────────────
INSTALL_DIR="/Library/AttackLens"
LOG_DIR="${INSTALL_DIR}/logs"
SECURITY_DIR="${INSTALL_DIR}/security"
CONFIG_PATH="${INSTALL_DIR}/agent.toml"
LAUNCHDAEMON_DIR="/Library/LaunchDaemons"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

# ── Detect Python (real binary — NOT a script, required for macOS 15+) ────────
PYTHON3=""
for p in /usr/local/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3; do
  if [[ -x "$p" ]]; then
    # Confirm it's a real Mach-O binary, not a symlink to a script
    if file "$p" 2>/dev/null | grep -q "Mach-O\|executable"; then
      PYTHON3="$p"; break
    elif [[ -x "$p" ]]; then
      PYTHON3="$p"; break
    fi
  fi
done
[[ -z "$PYTHON3" ]] && { echo "  ERROR: python3 not found." >&2; exit 1; }
PYTHON_VER=$("$PYTHON3" --version 2>&1)

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║    AttackLens Agent Installer (macOS)    ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Manager  : ${MANAGER_URL}"
echo "  Agent    : ${AGENT_NAME}"
echo "  Install  : ${INSTALL_DIR}"
echo "  Source   : ${REPO_DIR}"
echo "  Python   : ${PYTHON3} (${PYTHON_VER})"
echo ""

# ── Stop existing services ────────────────────────────────────────────────────
for LABEL in com.macintel.watchdog com.macintel.agent com.attacklens.watchdog com.attacklens.agent; do
  PLIST="${LAUNCHDAEMON_DIR}/${LABEL}.plist"
  launchctl bootout "system/${LABEL}" 2>/dev/null || \
  launchctl unload -w "$PLIST"         2>/dev/null || true
done
sleep 1

# ── Directories ───────────────────────────────────────────────────────────────
echo "  Creating directories..."
mkdir -p "${INSTALL_DIR}/bin" "${LOG_DIR}" "${SECURITY_DIR}" \
         "${INSTALL_DIR}/data" "${INSTALL_DIR}/spool"
chown -R root:wheel "${INSTALL_DIR}"
chmod 755 "${INSTALL_DIR}" "${INSTALL_DIR}/bin"
chmod 750 "${LOG_DIR}" "${INSTALL_DIR}/data" "${INSTALL_DIR}/spool"
chmod 700 "${SECURITY_DIR}"

# ── Bootstrap scripts (hard sys.path isolation) ───────────────────────────────
# Sets sys.path = [REPO_DIR] as a hard reset AFTER Python startup completes.
# This neutralises sitecustomize.py / .pth injections that insert conflicting
# same-named packages (e.g. another repo's agent/ package) into sys.path[0].
echo "  Writing bootstrap scripts..."
cat > "${INSTALL_DIR}/bin/run_agent.py" <<PYBOOT
import sys
sys.path = ['${REPO_DIR}']
from agent.agent_entry import main
main()
PYBOOT

cat > "${INSTALL_DIR}/bin/run_watchdog.py" <<PYBOOT
import sys
sys.path = ['${REPO_DIR}']
from agent.agent.watchdog import main
main()
PYBOOT

chmod 644 "${INSTALL_DIR}/bin/run_agent.py" "${INSTALL_DIR}/bin/run_watchdog.py"

# ── Agent ID ──────────────────────────────────────────────────────────────────
HW_UUID=$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Hardware UUID/{print tolower($NF)}')
AGENT_ID="mac-${HW_UUID:-$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')}"
echo "  Agent ID : ${AGENT_ID}"

# ── Write agent.toml ──────────────────────────────────────────────────────────
echo "  Writing config : ${CONFIG_PATH}"
cat > "${CONFIG_PATH}" <<TOML
# AttackLens Agent Configuration — $(date -u +"%Y-%m-%dT%H:%M:%SZ")
#
# Change manager IP:  sudo attacklens set-manager <NEW_IP>
# Edit manually:      sudo nano ${CONFIG_PATH}  →  sudo attacklens reload
# Manage services:    attacklens status | start | stop | restart | logs

[agent]
id   = "${AGENT_ID}"
name = "${AGENT_NAME}"

[manager]
url        = "${MANAGER_URL}"
tls_verify = ${TLS_VERIFY}

[paths]
install_dir  = "${INSTALL_DIR}"
config_dir   = "${INSTALL_DIR}"
log_dir      = "${LOG_DIR}"
data_dir     = "${INSTALL_DIR}/data"
security_dir = "${SECURITY_DIR}"
spool_dir    = "${INSTALL_DIR}/spool"
pid_file     = "${INSTALL_DIR}/attacklens-agent.pid"

[binaries]
agent    = "${PYTHON3}"
watchdog = "${PYTHON3}"

[logging]
level   = "INFO"
file    = "${LOG_DIR}/agent.log"
max_mb  = 10
backups = 5
TOML

[[ -n "$ENROLL_TOKEN" ]] && printf '\n[enrollment]\ntoken = "%s"\n' "$ENROLL_TOKEN" >> "${CONFIG_PATH}"

chown root:wheel "${CONFIG_PATH}"
chmod 640 "${CONFIG_PATH}"

# ── Install attacklens CLI ────────────────────────────────────────────────────
if [[ -f "${SCRIPT_DIR}/attacklens" ]]; then
  cp "${SCRIPT_DIR}/attacklens" /usr/local/bin/attacklens
  chown root:wheel /usr/local/bin/attacklens
  chmod 755 /usr/local/bin/attacklens
  echo "  CLI          : /usr/local/bin/attacklens"
fi

# ── LaunchDaemon plists ───────────────────────────────────────────────────────
# ProgramArguments[0] = python3 binary (Mach-O) — required by macOS 15+/26.
# No EnvironmentVariables block needed: bootstrap scripts handle sys.path.
echo "  Writing LaunchDaemons..."

cat > "${LAUNCHDAEMON_DIR}/com.attacklens.agent.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.attacklens.agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON3}</string>
        <string>${INSTALL_DIR}/bin/run_agent.py</string>
        <string>--config</string>
        <string>${CONFIG_PATH}</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONUNBUFFERED</key><string>1</string>
    </dict>

    <key>WorkingDirectory</key><string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>

    <key>StandardOutPath</key><string>${LOG_DIR}/agent-stdout.log</string>
    <key>StandardErrorPath</key><string>${LOG_DIR}/agent-stderr.log</string>

    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Background</string>
    <key>LowPriorityIO</key><true/>
</dict>
</plist>
PLIST

cat > "${LAUNCHDAEMON_DIR}/com.attacklens.watchdog.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.attacklens.watchdog</string>

    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON3}</string>
        <string>${INSTALL_DIR}/bin/run_watchdog.py</string>
        <string>--config</string>
        <string>${CONFIG_PATH}</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONUNBUFFERED</key><string>1</string>
    </dict>

    <key>WorkingDirectory</key><string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>

    <key>StandardOutPath</key><string>${LOG_DIR}/watchdog-stdout.log</string>
    <key>StandardErrorPath</key><string>${LOG_DIR}/watchdog-stderr.log</string>

    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Background</string>
    <key>LowPriorityIO</key><true/>
</dict>
</plist>
PLIST

for f in com.attacklens.agent.plist com.attacklens.watchdog.plist; do
  chown root:wheel "${LAUNCHDAEMON_DIR}/${f}"
  chmod 644 "${LAUNCHDAEMON_DIR}/${f}"
done

# ── Enable + Load (macOS 13+ compatible) ─────────────────────────────────────
echo "  Loading services..."
for LABEL in com.attacklens.agent com.attacklens.watchdog; do
  launchctl enable "system/${LABEL}" 2>/dev/null || true
done

launchctl bootstrap system "${LAUNCHDAEMON_DIR}/com.attacklens.agent.plist"    2>/dev/null || \
  launchctl load -w "${LAUNCHDAEMON_DIR}/com.attacklens.agent.plist"            2>/dev/null || true
launchctl bootstrap system "${LAUNCHDAEMON_DIR}/com.attacklens.watchdog.plist" 2>/dev/null || \
  launchctl load -w "${LAUNCHDAEMON_DIR}/com.attacklens.watchdog.plist"         2>/dev/null || true

sleep 3

# ── Result ────────────────────────────────────────────────────────────────────
AGENT_PID=$(launchctl list com.attacklens.agent 2>/dev/null | grep '"PID"' | grep -o '[0-9]*' || true)
WD_PID=$(launchctl list com.attacklens.watchdog 2>/dev/null | grep '"PID"' | grep -o '[0-9]*' || true)

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║           Installation Complete          ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
if [[ -n "$AGENT_PID" ]]; then
  echo "  Agent PID    : ${AGENT_PID}  ✓ running"
  echo "  Watchdog PID : ${WD_PID:-starting...}"
else
  echo "  Services starting... (check below if macOS blocked them)"
  echo ""
  echo "  ⚠  macOS 15+ APPROVAL REQUIRED:"
  echo "     System Settings → General → Login Items & Extensions"
  echo "     → Allow in Background → enable AttackLens"
  echo "     Then run: sudo attacklens restart"
fi
echo ""
echo "  Manager  : ${MANAGER_URL}"
echo "  Config   : ${CONFIG_PATH}"
echo ""
echo "  ── Commands ─────────────────────────────────"
echo "    attacklens status"
echo "    attacklens logs"
echo "    sudo attacklens restart"
echo "    sudo attacklens set-manager <NEW_IP>   ← if server IP changes"
echo ""
