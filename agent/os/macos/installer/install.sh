#!/usr/bin/env bash
# =============================================================================
#  agent/os/macos/installer/install.sh — mac_intel Agent macOS Installer
#
#  Installs the agent binaries, config, LaunchDaemons, and ACLs.
#  Must be run as root (or via sudo).
#
#  Usage:
#    sudo bash install.sh \
#      --manager-url  https://manager.corp.example:8443 \
#      --enroll-token sk-enroll-abc123 \
#      [--agent-id    my-unique-id] \
#      [--agent-name  "My MacBook"] \
#      [--tls-verify  true|false] \
#      [--version     1.0.0]
#
#  Environment variable equivalents (override CLI flags):
#    MANAGER_URL, ENROLL_TOKEN, MANAGER_API_KEY, AGENT_ID, AGENT_NAME,
#    TLS_VERIFY, INSTALL_DIR, DATA_DIR, LOG_DIR
#
#  Upgrade: re-run with the same flags — services are stopped/restarted.
# =============================================================================
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/opt/macintel}"
DATA_DIR="${DATA_DIR:-/Library/Application Support/MacIntel}"
LOG_DIR="${LOG_DIR:-/Library/Logs/MacIntel}"
SECURITY_DIR="${DATA_DIR}/security"
LAUNCHDAEMON_DIR="/Library/LaunchDaemons"
MANAGER_URL="${MANAGER_URL:-}"
ENROLL_TOKEN="${ENROLL_TOKEN:-}"
MANAGER_API_KEY="${MANAGER_API_KEY:-}"
AGENT_ID="${AGENT_ID:-}"
AGENT_NAME="${AGENT_NAME:-$(scutil --get ComputerName 2>/dev/null || hostname)}"
TLS_VERIFY="${TLS_VERIFY:-true}"

# ── Parse CLI flags ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --manager-url)   MANAGER_URL="$2";    shift 2 ;;
    --enroll-token)  ENROLL_TOKEN="$2";   shift 2 ;;
    --api-key)       MANAGER_API_KEY="$2"; shift 2 ;;
    --agent-id)      AGENT_ID="$2";       shift 2 ;;
    --agent-name)    AGENT_NAME="$2";     shift 2 ;;
    --tls-verify)    TLS_VERIFY="$2";     shift 2 ;;
    --install-dir)   INSTALL_DIR="$2";    shift 2 ;;
    --data-dir)      DATA_DIR="$2";       shift 2 ;;
    --log-dir)       LOG_DIR="$2";        shift 2 ;;
    *)               echo "Unknown flag: $1"; exit 1 ;;
  esac
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
  echo "  ERROR: must run as root. Use: sudo bash install.sh ..." >&2
  exit 1
fi

# ── Arch detection ────────────────────────────────────────────────────────────
ARCH=$(uname -m)
if [[ "$ARCH" != "arm64" && "$ARCH" != "x86_64" ]]; then
  echo "  WARNING: Unknown arch: $ARCH — proceeding anyway"
fi

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║    mac_intel Agent Installer (macOS)     ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Install dir : ${INSTALL_DIR}"
echo "  Data dir    : ${DATA_DIR}"
echo "  Log dir     : ${LOG_DIR}"
echo "  Manager     : ${MANAGER_URL:-[not set]}"
echo "  Agent name  : ${AGENT_NAME}"
echo "  Arch        : ${ARCH}"
echo ""

# ── Validation ────────────────────────────────────────────────────────────────
if [[ -z "$MANAGER_URL" ]]; then
  echo "  ERROR: --manager-url is required." >&2
  exit 1
fi
if [[ -z "$ENROLL_TOKEN" && -z "$MANAGER_API_KEY" ]]; then
  echo "  WARNING: Neither --enroll-token nor --api-key set." >&2
  echo "           Agent will fail to connect on first run."
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${SCRIPT_DIR}/dist"

for BIN in macintel-agent macintel-watchdog; do
  if [[ ! -f "${BIN_SRC}/${BIN}" ]]; then
    echo "  ERROR: Binary not found: ${BIN_SRC}/${BIN}" >&2
    echo "         Run build_pkg.sh first, or place binaries in ${BIN_SRC}/" >&2
    exit 1
  fi
done

# ── Stop existing services ─────────────────────────────────────────────────────
for LABEL in com.macintel.watchdog com.macintel.agent; do
  PLIST="${LAUNCHDAEMON_DIR}/${LABEL}.plist"
  if [[ -f "$PLIST" ]]; then
    echo "  Stopping ${LABEL}..."
    launchctl unload -w "$PLIST" 2>/dev/null || true
  fi
done
sleep 1

# ── Create directories ────────────────────────────────────────────────────────
echo "  Creating directories..."
mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${DATA_DIR}"
mkdir -p "${SECURITY_DIR}"
mkdir -p "${LOG_DIR}"

# ── Set ownership and permissions ─────────────────────────────────────────────
chown -R root:wheel "${INSTALL_DIR}"
chown -R root:wheel "${DATA_DIR}"
chown -R root:wheel "${LOG_DIR}"

chmod 755 "${INSTALL_DIR}"
chmod 755 "${INSTALL_DIR}/bin"
chmod 750 "${DATA_DIR}"
chmod 700 "${SECURITY_DIR}"    # root only
chmod 750 "${LOG_DIR}"

# ── Install binaries ──────────────────────────────────────────────────────────
echo "  Installing binaries..."
for BIN in macintel-agent macintel-watchdog; do
  cp "${BIN_SRC}/${BIN}" "${INSTALL_DIR}/bin/${BIN}"
  chown root:wheel "${INSTALL_DIR}/bin/${BIN}"
  chmod 755 "${INSTALL_DIR}/bin/${BIN}"
done

# Quarantine removal (Gatekeeper) — binaries shipped in .pkg are already cleared
# but direct copy from disk needs this:
xattr -dr com.apple.quarantine "${INSTALL_DIR}/bin/" 2>/dev/null || true

echo "  Binaries installed: $(ls "${INSTALL_DIR}/bin/")"

# ── Generate agent ID if not provided ────────────────────────────────────────
if [[ -z "$AGENT_ID" ]]; then
  AGENT_ID=$(python3 -c "import uuid; print(str(uuid.uuid4()))" 2>/dev/null \
    || uuidgen | tr '[:upper:]' '[:lower:]')
  echo "  Generated agent ID: ${AGENT_ID}"
fi

# ── Write agent.toml ──────────────────────────────────────────────────────────
CONFIG_PATH="${DATA_DIR}/agent.toml"
echo "  Writing config: ${CONFIG_PATH}"

GEN_SCRIPT="${SCRIPT_DIR}/generate_config.sh"
if [[ -f "$GEN_SCRIPT" ]]; then
  MANAGER_URL="$MANAGER_URL"     \
  ENROLL_TOKEN="$ENROLL_TOKEN"   \
  MANAGER_API_KEY="$MANAGER_API_KEY" \
  AGENT_ID="$AGENT_ID"           \
  AGENT_NAME="$AGENT_NAME"       \
  TLS_VERIFY="$TLS_VERIFY"       \
  INSTALL_DIR="$INSTALL_DIR"     \
  DATA_DIR="$DATA_DIR"           \
  LOG_DIR="$LOG_DIR"             \
  SECURITY_DIR="$SECURITY_DIR"   \
  bash "$GEN_SCRIPT"
else
  # Inline minimal config generation
  cat > "${CONFIG_PATH}" <<TOML
# agent.toml — mac_intel Agent Configuration (generated by install.sh)
[agent]
id   = "${AGENT_ID}"
name = "${AGENT_NAME}"

[manager]
url        = "${MANAGER_URL}"
tls_verify = ${TLS_VERIFY}
timeout_sec    = 30
max_queue_size = 500

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
pid_file     = "/var/run/macintel-agent.pid"

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
TOML
fi

chown root:wheel "${CONFIG_PATH}"
chmod 640 "${CONFIG_PATH}"    # root:wheel rw-r-----

# ── Install LaunchDaemon plists ────────────────────────────────────────────────
echo "  Installing LaunchDaemons..."

cat > "${LAUNCHDAEMON_DIR}/com.macintel.agent.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macintel.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/bin/macintel-agent</string>
        <string>--config</string>
        <string>${CONFIG_PATH}</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>
    <key>StandardOutPath</key><string>${LOG_DIR}/agent-stdout.log</string>
    <key>StandardErrorPath</key><string>${LOG_DIR}/agent-stderr.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Background</string>
    <key>WorkingDirectory</key><string>${INSTALL_DIR}</string>
    <key>LowPriorityIO</key><true/>
</dict>
</plist>
PLIST

cat > "${LAUNCHDAEMON_DIR}/com.macintel.watchdog.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macintel.watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/bin/macintel-watchdog</string>
        <string>--config</string>
        <string>${CONFIG_PATH}</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>
    <key>StandardOutPath</key><string>${LOG_DIR}/watchdog-stdout.log</string>
    <key>StandardErrorPath</key><string>${LOG_DIR}/watchdog-stderr.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Background</string>
    <key>WorkingDirectory</key><string>${INSTALL_DIR}</string>
    <key>LowPriorityIO</key><true/>
</dict>
</plist>
PLIST

for PLIST in com.macintel.agent.plist com.macintel.watchdog.plist; do
  chown root:wheel "${LAUNCHDAEMON_DIR}/${PLIST}"
  chmod 644 "${LAUNCHDAEMON_DIR}/${PLIST}"
done

# ── Load and start services ────────────────────────────────────────────────────
echo "  Loading LaunchDaemons..."
launchctl load -w "${LAUNCHDAEMON_DIR}/com.macintel.agent.plist"
launchctl load -w "${LAUNCHDAEMON_DIR}/com.macintel.watchdog.plist"

sleep 2

# ── Verify ────────────────────────────────────────────────────────────────────
AGENT_PID=$(launchctl list com.macintel.agent 2>/dev/null | grep '"PID"' | grep -o '[0-9]*' || echo "")
WD_PID=$(launchctl list com.macintel.watchdog 2>/dev/null | grep '"PID"' | grep -o '[0-9]*' || echo "")

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║           Installation Complete          ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Agent PID    : ${AGENT_PID:-not running}"
echo "  Watchdog PID : ${WD_PID:-not running}"
echo ""
echo "  Binaries  : ${INSTALL_DIR}/bin/"
echo "  Config    : ${CONFIG_PATH}"
echo "  Logs      : ${LOG_DIR}/"
echo "  Keys      : macOS Keychain (com.macintel.agent)"
echo ""
echo "  Management commands:"
echo "    Check status : sudo launchctl list com.macintel.agent"
echo "    Reload config: sudo launchctl kill HUP system/com.macintel.agent"
echo "    Stop agent   : sudo launchctl unload ${LAUNCHDAEMON_DIR}/com.macintel.agent.plist"
echo "    Uninstall    : sudo bash ${SCRIPT_DIR}/uninstall.sh"
echo ""
