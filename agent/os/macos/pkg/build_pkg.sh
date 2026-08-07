#!/usr/bin/env bash
# =============================================================================
#  agent/os/macos/pkg/build_pkg.sh — mac_intel Agent ARM64 .pkg Builder
#
#  Full pipeline:
#    1. Build attacklens-agent binary    (PyInstaller, ARM64)
#    2. Build attacklens-watchdog binary (PyInstaller, ARM64)
#    3. Assemble package root (binaries, plists, scripts, config template)
#    4. pkgbuild → unsigned .pkg
#    5. productbuild → distribution .pkg (with welcome/license pages)
#    6. Optional: productsign + notarytool submission
#
#  Usage:
#    cd /path/to/macbook_data
#    VERSION=1.2.0 bash agent/os/macos/pkg/build_pkg.sh
#
#  Environment variables:
#    MANAGER_IP      Manager IP or domain (optional — baked into pkg, can be set later)
#    MANAGER_PORT    Manager port (default: 8443)
#    VERSION         Semantic version. If unset, the patch auto-increments on
#                    every build from the last-built version recorded in
#                    .pkg_version (2.1.0 → 2.1.1 → 2.1.2 …). Setting it explicitly
#                    overrides the bump and becomes the new baseline.
#    AUTO_BUMP       true | false (default: true) — false reuses the last version
#    ARCH            arm64 | x86_64 | universal2 (default: arm64)
#    ENROLL_TOKEN    Enrollment token — leave empty for open-enrollment managers
#    TLS_VERIFY      true | false (default: false for IP-based, true for domain)
#    SIGN_IDENTITY   "Developer ID Installer: Your Name (TEAMID)"
#    NOTARIZE        true | false (default: false) — requires SIGN_IDENTITY
#    APPLE_ID        Apple ID for notarisation (xcrun notarytool)
#    TEAM_ID         Apple Team ID
#    APP_PASSWORD    App-specific password for notarisation
#
#  Output:
#    agent/os/macos/pkg/dist/attacklens-agent-<VERSION>-<ARCH>.pkg
#
#  Prerequisites (on macOS):
#    pip install pyinstaller
#    Xcode Command Line Tools  (pkgbuild, productbuild, codesign)
#    Apple Developer ID        (for signing + notarisation — optional)
# =============================================================================
set -euo pipefail

# ── Version: auto-increment the patch on every build ──────────────────────────
# The last successfully-built version is persisted in .pkg_version next to this
# script. Each run bumps the patch by 1 (2.1.0 → 2.1.1 → 2.1.2 …). An explicit
# `VERSION=x.y.z bash build_pkg.sh` overrides the auto-bump and becomes the new
# baseline for subsequent runs. Set `AUTO_BUMP=false` to reuse the last version
# verbatim (e.g. rebuilding the same release after a transient failure).
_SCRIPT_DIR_EARLY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_STATE_FILE="${_SCRIPT_DIR_EARLY}/.pkg_version"
DEFAULT_VERSION="2.1.0"       # treated as the last-built baseline on first run
AUTO_BUMP="${AUTO_BUMP:-true}"

if [[ -n "${VERSION:-}" ]]; then
  # Explicit override — honour it verbatim; recorded as the new baseline on success.
  :
else
  if [[ -f "${VERSION_STATE_FILE}" ]]; then
    _LAST_BUILT="$(tr -d '[:space:]' < "${VERSION_STATE_FILE}")"
  else
    _LAST_BUILT="${DEFAULT_VERSION}"
  fi
  if [[ "${AUTO_BUMP}" == "true" && "${_LAST_BUILT}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    VERSION="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$(( BASH_REMATCH[3] + 1 ))"
  elif [[ "${_LAST_BUILT}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    VERSION="${_LAST_BUILT}"       # AUTO_BUMP=false — reuse last version
  else
    echo "  WARNING: unparseable version '${_LAST_BUILT}' in ${VERSION_STATE_FILE} — resetting to ${DEFAULT_VERSION}" >&2
    VERSION="${DEFAULT_VERSION}"
  fi
fi

ARCH="${ARCH:-arm64}"
NOTARIZE="${NOTARIZE:-false}"
SIGN_IDENTITY="${SIGN_IDENTITY:-}"
APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
APP_PASSWORD="${APP_PASSWORD:-}"
TLS_VERIFY="${TLS_VERIFY:-false}"   # default false — most installs use self-signed certs

# ── Manager URL ───────────────────────────────────────────────────────────────
# MANAGER_IP is optional: the pkg works without it (open enrollment).
# Agent can be pointed at a manager after install by editing agent.toml.
MANAGER_PORT="${MANAGER_PORT:-8443}"
if [[ -n "${MANAGER_IP:-}" ]]; then
  MANAGER_URL="https://${MANAGER_IP}:${MANAGER_PORT}"
else
  MANAGER_URL="${MANAGER_URL:-}"   # allow full URL override
fi

# ── Enrollment token (optional for open-enrollment managers) ──────────────────
ENROLL_TOKEN="${ENROLL_TOKEN:-}"   # leave empty — manager uses OPEN_ENROLLMENT=true

PKG_ID="com.attacklens.agent"

INSTALL_DIR="/Library/AttackLens"
CONFIG_DIR="/Library/AttackLens"
LOG_DIR="/Library/AttackLens/logs"
LAUNCHDAEMON_DIR="/Library/LaunchDaemons"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS_MACOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"
PKG_ROOT="${BUILD_DIR}/pkgroot"
SCRIPTS_DIR="${BUILD_DIR}/scripts"

PKG_COMPONENT="${BUILD_DIR}/attacklens-agent-component-${VERSION}.pkg"
PKG_FINAL="${DIST_DIR}/attacklens-agent-${VERSION}-${ARCH}.pkg"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   mac_intel Agent PKG Builder (macOS)   ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Version      : ${VERSION}"
echo "  Arch         : ${ARCH}"
echo "  Manager URL  : ${MANAGER_URL:-[not baked in — set after install]}"
echo "  Enroll Token : ${ENROLL_TOKEN:-[none — open enrollment]}"
echo "  TLS Verify   : ${TLS_VERIFY}"
echo "  Output       : ${PKG_FINAL}"
[[ -n "$SIGN_IDENTITY" ]] && echo "  Signing      : ${SIGN_IDENTITY}" || echo "  Signing      : disabled (dev build)"
echo ""

# ── Clean build directories ───────────────────────────────────────────────────
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}" "${DIST_DIR}"

cd "${REPO_ROOT}"

# ── Step 1: Build attacklens-agent binary ───────────────────────────────────────
echo "  [1/6] Building attacklens-agent binary (PyInstaller, ${ARCH})..."
PYTHONPATH="${REPO_ROOT}" python3 -m PyInstaller \
    --onefile \
    --clean \
    --name "attacklens-agent" \
    --target-architecture "${ARCH}" \
    --hidden-import "agent.agent.circuit_breaker" \
    --hidden-import "agent.agent.collectors" \
    --hidden-import "agent.agent.normalizer" \
    --hidden-import "agent.agent.enrollment" \
    --hidden-import "agent.agent.keystore" \
    --hidden-import "agent.agent.crypto" \
    --hidden-import "agent.agent.sender" \
    --hidden-import "agent.agent.policy" \
    --hidden-import "agent.agent.config_engine" \
    --hidden-import "agent.os.macos.collectors" \
    --hidden-import "agent.os.macos.collectors.volatile" \
    --hidden-import "agent.os.macos.collectors.network" \
    --hidden-import "agent.os.macos.collectors.system" \
    --hidden-import "agent.os.macos.collectors.posture" \
    --hidden-import "agent.os.macos.collectors.inventory" \
    --hidden-import "agent.os.macos.collectors.developer_security" \
    --hidden-import "agent.os.macos.collectors.sca" \
    --hidden-import "agent.agent.sca" \
    --hidden-import "agent.agent.sca.engine" \
    --hidden-import "yaml" \
    --add-data "${REPO_ROOT}/agent/agent/sca/policies/sca_apple_macos.yml:agent/agent/sca/policies" \
    --hidden-import "agent.os.macos.normalizer" \
    --hidden-import "agent.os.macos.keystore" \
    --hidden-import "psutil" \
    --hidden-import "cryptography" \
    --hidden-import "cryptography.hazmat.primitives.ciphers.aead" \
    --hidden-import "cryptography.hazmat.primitives.asymmetric.ed25519" \
    --hidden-import "cryptography.hazmat.primitives.asymmetric.rsa" \
    --hidden-import "cryptography.hazmat.primitives.asymmetric.padding" \
    --hidden-import "cryptography.hazmat.primitives.serialization" \
    --hidden-import "keyring" \
    --hidden-import "keyring.backends.macOS" \
    --hidden-import "tomllib" \
    --distpath "${BUILD_DIR}/bin" \
    --workpath "${BUILD_DIR}/pyinstaller/agent" \
    --specpath "${BUILD_DIR}" \
    agent/agent_entry.py

echo "  [1/6] DONE — $(du -sh "${BUILD_DIR}/bin/attacklens-agent" | cut -f1)"

# ── Step 2: Build attacklens-watchdog binary ────────────────────────────────────
echo "  [2/6] Building attacklens-watchdog binary (PyInstaller, ${ARCH})..."
PYTHONPATH="${REPO_ROOT}" python3 -m PyInstaller \
    --onefile \
    --clean \
    --name "attacklens-watchdog" \
    --target-architecture "${ARCH}" \
    --hidden-import "tomllib" \
    --distpath "${BUILD_DIR}/bin" \
    --workpath "${BUILD_DIR}/pyinstaller/watchdog" \
    --specpath "${BUILD_DIR}" \
    agent/agent/watchdog.py

echo "  [2/6] DONE — $(du -sh "${BUILD_DIR}/bin/attacklens-watchdog" | cut -f1)"

# ── Codesign binaries (before packaging) ──────────────────────────────────────
if [[ -n "$SIGN_IDENTITY" ]]; then
  echo "  [2b] Codesigning binaries..."
  for BIN in attacklens-agent attacklens-watchdog; do
    codesign --force --options runtime \
      --sign "$SIGN_IDENTITY" \
      --entitlements "${OS_MACOS_DIR}/pkg/entitlements.plist" \
      "${BUILD_DIR}/bin/${BIN}" \
      || codesign --force --options runtime \
          --sign "$SIGN_IDENTITY" \
          "${BUILD_DIR}/bin/${BIN}"
    echo "    Signed: ${BIN}"
  done
fi

# ── Step 3: Assemble package root ─────────────────────────────────────────────
echo "  [3/6] Assembling package root..."

# Directory tree
mkdir -p "${PKG_ROOT}${INSTALL_DIR}/bin"
mkdir -p "${PKG_ROOT}${CONFIG_DIR}/security"
mkdir -p "${PKG_ROOT}${LOG_DIR}"
mkdir -p "${PKG_ROOT}${LAUNCHDAEMON_DIR}"

# Binaries
cp "${BUILD_DIR}/bin/attacklens-agent"    "${PKG_ROOT}${INSTALL_DIR}/bin/"
cp "${BUILD_DIR}/bin/attacklens-watchdog" "${PKG_ROOT}${INSTALL_DIR}/bin/"
chmod 755 "${PKG_ROOT}${INSTALL_DIR}/bin/attacklens-agent"
chmod 755 "${PKG_ROOT}${INSTALL_DIR}/bin/attacklens-watchdog"

# LaunchDaemon plists (config path is set by postinstall script)
cat > "${PKG_ROOT}${LAUNCHDAEMON_DIR}/com.attacklens.agent.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.attacklens.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/AttackLens/bin/attacklens-agent</string>
        <string>run</string>
        <string>--config</string>
        <string>/Library/AttackLens/agent.toml</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>
    <key>StandardOutPath</key>
    <string>/Library/AttackLens/logs/agent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/AttackLens/logs/agent-stderr.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Background</string>
    <key>WorkingDirectory</key><string>/Library/AttackLens</string>
    <key>LowPriorityIO</key><true/>
</dict>
</plist>
PLIST

cat > "${PKG_ROOT}${LAUNCHDAEMON_DIR}/com.attacklens.watchdog.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.attacklens.watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/AttackLens/bin/attacklens-watchdog</string>
        <string>--config</string>
        <string>/Library/AttackLens/agent.toml</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>
    <key>StandardOutPath</key>
    <string>/Library/AttackLens/logs/watchdog-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/AttackLens/logs/watchdog-stderr.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Background</string>
    <key>WorkingDirectory</key><string>/Library/AttackLens</string>
    <key>LowPriorityIO</key><true/>
</dict>
</plist>
PLIST

chmod 644 "${PKG_ROOT}${LAUNCHDAEMON_DIR}/"*.plist

# Config template (postinstall fills in agent_id / manager_url)
cp "${OS_MACOS_DIR}/installer/generate_config.sh" \
   "${PKG_ROOT}${CONFIG_DIR}/generate_config.sh"
chmod 750 "${PKG_ROOT}${CONFIG_DIR}/generate_config.sh"

# Management CLI → /usr/local/bin/attacklens-service
mkdir -p "${PKG_ROOT}/usr/local/bin"
cp "${SCRIPT_DIR}/attacklens-service" "${PKG_ROOT}/usr/local/bin/attacklens-service"
chmod 755 "${PKG_ROOT}/usr/local/bin/attacklens-service"

# Ownership — only root can chown; pkgbuild --ownership recommended handles
# this at install time so failures here are non-fatal for dev builds.
chown -R root:wheel "${PKG_ROOT}${INSTALL_DIR}"       2>/dev/null || true
chown -R root:wheel "${PKG_ROOT}${CONFIG_DIR}"        2>/dev/null || true
chown -R root:wheel "${PKG_ROOT}${LOG_DIR}"           2>/dev/null || true
chown -R root:wheel "${PKG_ROOT}${LAUNCHDAEMON_DIR}"  2>/dev/null || true
chmod 700  "${PKG_ROOT}${CONFIG_DIR}/security"

echo "  [3/6] DONE"

# ── Step 4: Build postinstall / preinstall scripts ────────────────────────────
echo "  [4/6] Building installer scripts..."
mkdir -p "${SCRIPTS_DIR}"

cat > "${SCRIPTS_DIR}/preinstall" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
for LABEL in com.attacklens.watchdog com.attacklens.agent; do
  launchctl bootout "system/${LABEL}" 2>/dev/null || true
  PLIST="/Library/LaunchDaemons/${LABEL}.plist"
  if [[ -f "$PLIST" ]]; then
    launchctl unload -w "$PLIST" 2>/dev/null || true
  fi
done
exit 0
SCRIPT

# Part 1: bake build-time values into the script (variable-expanding heredoc)
cat > "${SCRIPTS_DIR}/postinstall" <<SCRIPT_HEADER
#!/usr/bin/env bash
set -euo pipefail

# ── Values baked in at build time ─────────────────────────────────────────────
BAKED_MANAGER_URL="${MANAGER_URL}"
BAKED_ENROLL_TOKEN="${ENROLL_TOKEN}"
BAKED_TLS_VERIFY="${TLS_VERIFY}"
SCRIPT_HEADER

# Part 2: runtime logic (single-quoted — no expansion)
cat >> "${SCRIPTS_DIR}/postinstall" <<'SCRIPT_BODY'

INSTALL_DIR="/Library/AttackLens"
DATA_DIR="/Library/AttackLens"
LOG_DIR="/Library/AttackLens/logs"
SECURITY_DIR="${DATA_DIR}/security"
LAUNCHDAEMON_DIR="/Library/LaunchDaemons"
CONFIG_PATH="${DATA_DIR}/agent.toml"

# ── Create directories with correct permissions ────────────────────────────────
mkdir -p "${DATA_DIR}" "${SECURITY_DIR}" "${LOG_DIR}" "${DATA_DIR}/data"
chown -R root:wheel "${DATA_DIR}" "${LOG_DIR}"
chmod 750 "${DATA_DIR}"
chmod 700 "${SECURITY_DIR}"
chmod 750 "${LOG_DIR}"

# ── Generate config (only on fresh install; preserved on upgrade) ──────────────
if [[ ! -f "${CONFIG_PATH}" ]]; then
  # Stable agent ID from hardware UUID — same machine always gets same ID
  HW_UUID=$(system_profiler SPHardwareDataType 2>/dev/null \
    | awk '/Hardware UUID/{print tolower($NF)}')
  if [[ -n "$HW_UUID" ]]; then
    AGENT_ID="mac-${HW_UUID}"
  else
    AGENT_ID="mac-$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')"
  fi
  AGENT_NAME=$(scutil --get ComputerName 2>/dev/null || hostname -s)

  export AGENT_ID AGENT_NAME
  export INSTALL_DIR DATA_DIR LOG_DIR SECURITY_DIR
  export MANAGER_URL="${BAKED_MANAGER_URL}"
  export ENROLL_TOKEN="${BAKED_ENROLL_TOKEN}"
  export TLS_VERIFY="${BAKED_TLS_VERIFY}"

  bash "${DATA_DIR}/generate_config.sh"
  echo "  Config generated: ${CONFIG_PATH}"
  echo "  Agent ID  : ${AGENT_ID}"
  echo "  Agent Name: ${AGENT_NAME}"
else
  echo "  Existing config preserved (upgrade): ${CONFIG_PATH}"
fi

# ── Migrate/repair preserved configs (idempotent) ──────────────────────────────
# Older configs point [binaries] at removed .py entry scripts — the watchdog
# would FATAL-loop on them. Retarget to the shipped native binaries.
if grep -qE 'run_agent\.py|run_watchdog\.py' "${CONFIG_PATH}" 2>/dev/null; then
  sed -i '' \
    -e 's|/Library/AttackLens/bin/run_agent\.py|/Library/AttackLens/bin/attacklens-agent|g' \
    -e 's|/Library/AttackLens/bin/run_watchdog\.py|/Library/AttackLens/bin/attacklens-watchdog|g' \
    "${CONFIG_PATH}"
  echo "  Migrated [binaries] paths in preserved config to native binaries"
fi

# Add the new hourly developer/AI security inventory on upgrade without
# rewriting any operator-owned settings.  Existing explicit blocks win.
if ! grep -q '^\[collection\.sections\.developer_security\]$' "${CONFIG_PATH}" 2>/dev/null; then
  cat >> "${CONFIG_PATH}" <<'DEVELOPER_SECURITY_CONFIG'

[collection.sections.developer_security]
enabled      = true
interval_sec = 3600
send         = true
timeout_sec  = 120
DEVELOPER_SECURITY_CONFIG
  echo "  Enabled hourly developer_security collection in preserved config"
fi

# Compatibility wrapper: anything still launching run_agent.sh gets the
# correct 'run' subcommand inserted transparently.
cat > "${INSTALL_DIR}/bin/run_agent.sh" <<'WRAP'
#!/bin/bash
exec /Library/AttackLens/bin/attacklens-agent run "$@"
WRAP
chmod 755 "${INSTALL_DIR}/bin/run_agent.sh"

# ── Fix plist ownership ────────────────────────────────────────────────────────
chown root:wheel "${LAUNCHDAEMON_DIR}/com.attacklens.agent.plist"
chown root:wheel "${LAUNCHDAEMON_DIR}/com.attacklens.watchdog.plist"
chmod 644 "${LAUNCHDAEMON_DIR}/com.attacklens.agent.plist"
chmod 644 "${LAUNCHDAEMON_DIR}/com.attacklens.watchdog.plist"

# ── Remove quarantine ──────────────────────────────────────────────────────────
xattr -dr com.apple.quarantine "${INSTALL_DIR}/bin/" 2>/dev/null || true

# ── Management CLI symlink + legacy cleanup ───────────────────────────────────
ln -sf /usr/local/bin/attacklens-service /usr/local/bin/attacklens-ctl
# dangling symlink from old installs
if [[ -L /usr/local/bin/attacklens-control && ! -e /usr/local/bin/attacklens-control ]]; then
  rm -f /usr/local/bin/attacklens-control
fi

# ── Pre-flight: the agent binary must actually be runnable ────────────────────
# A quarantined or arch-mismatched binary would exit-loop under launchd and only
# be discovered AFTER a reboot. Catch it now, at install time, with a clear fix.
if ! "${INSTALL_DIR}/bin/attacklens-agent" --help >/dev/null 2>&1; then
  echo "  ⚠️  WARNING: ${INSTALL_DIR}/bin/attacklens-agent failed to run (--help)." >&2
  echo "     Likely Gatekeeper quarantine or an arch mismatch. Try:" >&2
  echo "       sudo xattr -dr com.apple.quarantine ${INSTALL_DIR}/bin/" >&2
  echo "     then: sudo attacklens-service restart" >&2
fi

# ── Ensure the boot-safe key directory is root-only (file keystore lives here) ─
mkdir -p "${SECURITY_DIR}"
chown root:wheel "${SECURITY_DIR}" 2>/dev/null || true
chmod 700 "${SECURITY_DIR}" 2>/dev/null || true

# ── SINGLE-SUPERVISOR topology ────────────────────────────────────────────────
# CRITICAL: only ONE launchd job may start the agent. The agent LaunchDaemon runs
# the agent directly; the watchdog LaunchDaemon *also* spawns an agent as a child
# (watchdog.py subprocess.Popen). Bootstrapping BOTH — as older builds did — runs
# TWO agent processes that race on the shared disk spool (unsent.ndjson),
# duplicating telemetry and burning CPU. launchd's own KeepAlive already provides
# crash recovery, so the agent daemon alone is the supported topology.
#
# We therefore START the agent and explicitly DISABLE + bootout the watchdog. To
# opt into the watchdog supervision model instead, disable the agent daemon and
# bootstrap ONLY the watchdog (they must never both be loaded).

# Stop + disable the watchdog so it can't spawn a second agent (idempotent).
launchctl bootout "system/com.attacklens.watchdog" 2>/dev/null || true
launchctl disable "system/com.attacklens.watchdog" 2>/dev/null || true
# Kill any orphaned watchdog-spawned agent from a previous (dual-daemon) install.
pkill -f "attacklens-agent run" 2>/dev/null || true

# Start the single agent daemon (bootout stale copy first, then bootstrap).
launchctl bootout  "system/com.attacklens.agent" 2>/dev/null || true
launchctl enable   "system/com.attacklens.agent" 2>/dev/null || true
if ! launchctl bootstrap system "${LAUNCHDAEMON_DIR}/com.attacklens.agent.plist" 2>/dev/null; then
  # already loaded (error 5) or transient — kick it, fall back to legacy load
  launchctl kickstart -k "system/com.attacklens.agent" 2>/dev/null \
    || launchctl load -w "${LAUNCHDAEMON_DIR}/com.attacklens.agent.plist" 2>/dev/null || true
fi

# ── Verify the agent daemon actually reached 'running' ────────────────────────
# Poll for a PID for a few seconds instead of assuming success — surfaces a
# crash-loop (exit 2/78, missing key, bad config) here rather than silently
# after the next reboot. Non-fatal: the watchdog + self-heal still recover, but
# the operator gets an immediate, actionable signal.
AGENT_UP=0
for _ in 1 2 3 4 5; do
  if launchctl print "system/com.attacklens.agent" 2>/dev/null | grep -q "pid = "; then
    AGENT_UP=1; break
  fi
  sleep 1
done
if [[ "${AGENT_UP}" == "1" ]]; then
  echo "  ✓ AttackLens agent installed and running."
else
  echo "  ⚠️  Agent installed but did NOT reach 'running' within 5s." >&2
  echo "     Last agent stderr:" >&2
  tail -n 15 "${LOG_DIR}/agent-stderr.log" 2>/dev/null | sed 's/^/       /' >&2 || true
  echo "     Diagnose with: sudo attacklens-service diagnose" >&2
fi
echo "  Manage it with: sudo attacklens-service status|start|stop|diagnose"
exit 0
SCRIPT_BODY

chmod +x "${SCRIPTS_DIR}/preinstall" "${SCRIPTS_DIR}/postinstall"
echo "  [4/6] DONE"

# ── Step 5: pkgbuild → component pkg ─────────────────────────────────────────
echo "  [5/6] Running pkgbuild..."
pkgbuild \
    --root "${PKG_ROOT}" \
    --scripts "${SCRIPTS_DIR}" \
    --identifier "${PKG_ID}" \
    --version "${VERSION}" \
    --install-location "/" \
    --ownership recommended \
    "${PKG_COMPONENT}"

echo "  [5/6] DONE (component pkg: $(du -sh "${PKG_COMPONENT}" | cut -f1))"

# ── Step 6: productbuild → distribution pkg ───────────────────────────────────
echo "  [6/6] Running productbuild..."

DIST_XML="${BUILD_DIR}/distribution.xml"
cat > "${DIST_XML}" <<DISTXML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>mac_intel Agent ${VERSION}</title>
    <organization>com.attacklens</organization>
    <domains enable_localSystem="true" />
    <options customize="never" require-scripts="true" hostArchitectures="${ARCH}" />
    <welcome file="welcome.html" mime-type="text/html" />
    <pkg-ref id="${PKG_ID}" />
    <choices-outline>
        <line choice="${PKG_ID}" />
    </choices-outline>
    <choice id="${PKG_ID}" visible="false">
        <pkg-ref id="${PKG_ID}" />
    </choice>
    <pkg-ref id="${PKG_ID}" version="${VERSION}" onConclusion="none">${PKG_COMPONENT}</pkg-ref>
</installer-gui-script>
DISTXML

# Welcome HTML (shown in Installer.app) — variable-expanding heredoc
MANAGER_DISPLAY="${MANAGER_URL:-[configure in agent.toml after install]}"
cat > "${BUILD_DIR}/welcome.html" <<HTML
<!DOCTYPE html><html>
<head><style>
  body { font-family: -apple-system, sans-serif; font-size: 13px; margin: 20px; line-height: 1.5; }
  h2   { color: #1d3461; margin-bottom: 4px; }
  code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-size: 12px; }
  .ok  { color: #2a7a2a; font-weight: bold; }
  .note { color: #666; font-size: 11px; }
  ul   { padding-left: 18px; }
  li   { margin-bottom: 4px; }
</style></head>
<body>
  <h2>mac_intel Agent ${VERSION} (${ARCH})</h2>
  <p>Installs the mac_intel endpoint telemetry agent as a background LaunchDaemon.
     Telemetry is encrypted end-to-end (AES-256-GCM + TLS 1.3).</p>

  <p class="ok">&#x2705; Zero-touch — no token or manual config needed.</p>

  <ul>
    <li><b>Manager:</b> <code>${MANAGER_DISPLAY}</code></li>
    <li><b>Agent ID</b> derived from this Mac's hardware UUID — stable across reinstalls.</li>
    <li><b>API key</b> auto-generated and stored in macOS Keychain on first run.</li>
    <li>Services start automatically after installation.</li>
    <li>22 collectors: metrics, processes, network, security posture, full inventory.</li>
  </ul>

  <p class="note">
    Requires macOS 12 (Monterey) or later &bull; ARM64 &bull;
    Installs to <code>/Library/AttackLens/</code>
  </p>
</body>
</html>
HTML

if [[ -n "$SIGN_IDENTITY" ]]; then
  productbuild \
    --distribution "${DIST_XML}" \
    --package-path "${BUILD_DIR}" \
    --resources "${BUILD_DIR}" \
    --sign "${SIGN_IDENTITY}" \
    "${PKG_FINAL}"
else
  productbuild \
    --distribution "${DIST_XML}" \
    --package-path "${BUILD_DIR}" \
    --resources "${BUILD_DIR}" \
    "${PKG_FINAL}"
fi

echo "  [6/6] DONE"

# ── Record the built version so the next run auto-increments the patch ─────────
# Only written after productbuild succeeded and the pkg exists (set -e would have
# aborted earlier on failure, leaving the previous baseline intact for a retry).
if [[ -f "${PKG_FINAL}" ]]; then
  printf '%s\n' "${VERSION}" > "${VERSION_STATE_FILE}"
  echo "  Recorded version ${VERSION} → ${VERSION_STATE_FILE} (next build: patch +1)"
fi

# ── Notarisation ──────────────────────────────────────────────────────────────
if [[ "$NOTARIZE" == "true" && -n "$SIGN_IDENTITY" ]]; then
  echo ""
  echo "  Submitting for notarisation..."
  if [[ -z "$APPLE_ID" || -z "$TEAM_ID" || -z "$APP_PASSWORD" ]]; then
    echo "  WARNING: Set APPLE_ID, TEAM_ID, APP_PASSWORD to notarise" >&2
  else
    xcrun notarytool submit "${PKG_FINAL}" \
      --apple-id  "${APPLE_ID}" \
      --team-id   "${TEAM_ID}" \
      --password  "${APP_PASSWORD}" \
      --wait

    xcrun stapler staple "${PKG_FINAL}"
    echo "  Notarisation complete — staple attached."
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
PKG_SIZE=$(du -sh "${PKG_FINAL}" | cut -f1)
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║            Build Complete!               ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Package  : ${PKG_FINAL}"
echo "  Size     : ${PKG_SIZE}"
echo ""
echo "  ── Install ──────────────────────────────────────────────────────────────"
echo "    sudo installer -pkg '${PKG_FINAL}' -target /"
echo ""
echo "  ── What happens on install ──────────────────────────────────────────────"
echo "    • Binaries installed to /Library/AttackLens/bin/"
echo "    • Management CLI installed: /usr/local/bin/attacklens-service"
echo "    • SCA policy (CIS macOS, 57 checks) bundled in agent binary"
echo "    • Agent ID auto-derived from hardware UUID (stable across reinstalls)"
echo "    • Config written to '/Library/AttackLens/agent.toml'"
echo "    • LaunchDaemons loaded: com.attacklens.agent + com.attacklens.watchdog"
echo "    • Agent enrolls with manager on first run (open enrollment — no token needed)"
echo "    • API key stored in macOS Keychain (com.attacklens.agent)"
echo ""
if [[ -n "${MANAGER_URL:-}" ]]; then
echo "  Manager URL baked in: ${MANAGER_URL}"
else
echo "  No manager URL baked in — edit agent.toml after install:"
echo "    sudo nano '/Library/AttackLens/agent.toml'"
echo "    Set [manager] url = \"https://YOUR_MANAGER_IP:8443\""
echo "    Then: sudo launchctl kickstart -k system/com.attacklens.agent"
fi
echo ""
echo "  ── MDM silent deploy (Jamf / Mosyle / Intune) ───────────────────────────"
echo "    Upload '${PKG_FINAL}' — no extra scripts needed."
echo ""
