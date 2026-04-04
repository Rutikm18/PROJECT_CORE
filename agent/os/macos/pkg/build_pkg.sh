#!/usr/bin/env bash
# =============================================================================
#  agent/os/macos/pkg/build_pkg.sh — mac_intel Agent ARM64 .pkg Builder
#
#  Full pipeline:
#    1. Build macintel-agent binary    (PyInstaller, ARM64)
#    2. Build macintel-watchdog binary (PyInstaller, ARM64)
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
#    MANAGER_IP      Manager server IP address (REQUIRED — e.g. 192.168.1.100)
#    MANAGER_PORT    Manager port (default: 8443)
#    VERSION         Semantic version (default: 1.0.0)
#    ARCH            arm64 | x86_64 | universal2 (default: arm64)
#    ENROLL_TOKEN    Pre-set enrollment token (auto-generated if omitted)
#    TLS_VERIFY      true | false (default: true)
#    SIGN_IDENTITY   "Developer ID Installer: Your Name (TEAMID)"
#    NOTARIZE        true | false (default: false) — requires SIGN_IDENTITY
#    APPLE_ID        Apple ID for notarisation (xcrun notarytool)
#    TEAM_ID         Apple Team ID
#    APP_PASSWORD    App-specific password for notarisation
#
#  Output:
#    agent/os/macos/pkg/dist/macintel-agent-<VERSION>-<ARCH>.pkg
#
#  Prerequisites (on macOS):
#    pip install pyinstaller
#    Xcode Command Line Tools  (pkgbuild, productbuild, codesign)
#    Apple Developer ID        (for signing + notarisation — optional)
# =============================================================================
set -euo pipefail

VERSION="${VERSION:-1.0.0}"
ARCH="${ARCH:-arm64}"
NOTARIZE="${NOTARIZE:-false}"
SIGN_IDENTITY="${SIGN_IDENTITY:-}"
APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
APP_PASSWORD="${APP_PASSWORD:-}"
TLS_VERIFY="${TLS_VERIFY:-true}"

# ── Manager IP (required) + auto-generated enrollment token ───────────────────
if [[ -z "${MANAGER_IP:-}" ]]; then
  echo ""
  echo "  ERROR: MANAGER_IP is required."
  echo "  Usage: MANAGER_IP=192.168.1.100 bash agent/os/macos/pkg/build_pkg.sh"
  echo ""
  exit 1
fi
MANAGER_PORT="${MANAGER_PORT:-8443}"
MANAGER_URL="https://${MANAGER_IP}:${MANAGER_PORT}"

# Auto-generate enrollment token if not provided
if [[ -z "${ENROLL_TOKEN:-}" ]]; then
  ENROLL_TOKEN="sk-enroll-$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
fi

PKG_ID="com.macintel.agent"

INSTALL_DIR="/opt/macintel"
CONFIG_DIR="/Library/Application Support/MacIntel"
LOG_DIR="/Library/Logs/MacIntel"
LAUNCHDAEMON_DIR="/Library/LaunchDaemons"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS_MACOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"
PKG_ROOT="${BUILD_DIR}/pkgroot"
SCRIPTS_DIR="${BUILD_DIR}/scripts"

PKG_COMPONENT="${BUILD_DIR}/macintel-agent-component-${VERSION}.pkg"
PKG_FINAL="${DIST_DIR}/macintel-agent-${VERSION}-${ARCH}.pkg"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   mac_intel Agent PKG Builder (macOS)   ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Version      : ${VERSION}"
echo "  Arch         : ${ARCH}"
echo "  Manager IP   : ${MANAGER_IP}:${MANAGER_PORT}"
echo "  Manager URL  : ${MANAGER_URL}"
echo "  Enroll Token : ${ENROLL_TOKEN}  ← add this to manager ENROLLMENT_TOKENS"
echo "  TLS Verify   : ${TLS_VERIFY}"
echo "  Output       : ${PKG_FINAL}"
[[ -n "$SIGN_IDENTITY" ]] && echo "  Signing      : ${SIGN_IDENTITY}" || echo "  Signing      : disabled (dev build)"
echo ""

# ── Clean build directories ───────────────────────────────────────────────────
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}" "${DIST_DIR}"

cd "${REPO_ROOT}"

# ── Step 1: Build macintel-agent binary ───────────────────────────────────────
echo "  [1/6] Building macintel-agent binary (PyInstaller)..."
python3 -m PyInstaller \
    --onefile \
    --clean \
    --name "macintel-agent" \
    --target-architecture "${ARCH}" \
    --hidden-import "agent.agent.collectors" \
    --hidden-import "agent.agent.normalizer" \
    --hidden-import "agent.agent.enrollment" \
    --hidden-import "agent.agent.keystore" \
    --hidden-import "agent.agent.crypto" \
    --hidden-import "agent.agent.sender" \
    --hidden-import "agent.os.macos.collectors" \
    --hidden-import "agent.os.macos.normalizer" \
    --hidden-import "agent.os.macos.keystore" \
    --hidden-import "psutil" \
    --hidden-import "cryptography" \
    --hidden-import "keyring" \
    --hidden-import "keyring.backends.macOS" \
    --hidden-import "tomllib" \
    --distpath "${BUILD_DIR}/bin" \
    --workpath "${BUILD_DIR}/pyinstaller/agent" \
    --specpath "${BUILD_DIR}" \
    agent/os/macos/launchd.py

echo "  [1/6] DONE"

# ── Step 2: Build macintel-watchdog binary ────────────────────────────────────
echo "  [2/6] Building macintel-watchdog binary (PyInstaller)..."
python3 -m PyInstaller \
    --onefile \
    --clean \
    --name "macintel-watchdog" \
    --target-architecture "${ARCH}" \
    --hidden-import "tomllib" \
    --distpath "${BUILD_DIR}/bin" \
    --workpath "${BUILD_DIR}/pyinstaller/watchdog" \
    --specpath "${BUILD_DIR}" \
    agent/agent/watchdog.py

echo "  [2/6] DONE"

# ── Codesign binaries (before packaging) ──────────────────────────────────────
if [[ -n "$SIGN_IDENTITY" ]]; then
  echo "  [2b] Codesigning binaries..."
  for BIN in macintel-agent macintel-watchdog; do
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
cp "${BUILD_DIR}/bin/macintel-agent"    "${PKG_ROOT}${INSTALL_DIR}/bin/"
cp "${BUILD_DIR}/bin/macintel-watchdog" "${PKG_ROOT}${INSTALL_DIR}/bin/"
chmod 755 "${PKG_ROOT}${INSTALL_DIR}/bin/macintel-agent"
chmod 755 "${PKG_ROOT}${INSTALL_DIR}/bin/macintel-watchdog"

# LaunchDaemon plists (config path is set by postinstall script)
cat > "${PKG_ROOT}${LAUNCHDAEMON_DIR}/com.macintel.agent.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.macintel.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/macintel/bin/macintel-agent</string>
        <string>--config</string>
        <string>/Library/Application Support/MacIntel/agent.toml</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>
    <key>StandardOutPath</key>
    <string>/Library/Logs/MacIntel/agent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/MacIntel/agent-stderr.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Background</string>
    <key>WorkingDirectory</key><string>/opt/macintel</string>
    <key>LowPriorityIO</key><true/>
</dict>
</plist>
PLIST

cat > "${PKG_ROOT}${LAUNCHDAEMON_DIR}/com.macintel.watchdog.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.macintel.watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/macintel/bin/macintel-watchdog</string>
        <string>--config</string>
        <string>/Library/Application Support/MacIntel/agent.toml</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>
    <key>StandardOutPath</key>
    <string>/Library/Logs/MacIntel/watchdog-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/MacIntel/watchdog-stderr.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Background</string>
    <key>WorkingDirectory</key><string>/opt/macintel</string>
    <key>LowPriorityIO</key><true/>
</dict>
</plist>
PLIST

chmod 644 "${PKG_ROOT}${LAUNCHDAEMON_DIR}/"*.plist

# Config template (postinstall fills in agent_id / manager_url)
cp "${OS_MACOS_DIR}/installer/generate_config.sh" \
   "${PKG_ROOT}${CONFIG_DIR}/generate_config.sh"
chmod 750 "${PKG_ROOT}${CONFIG_DIR}/generate_config.sh"

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
for LABEL in com.macintel.watchdog com.macintel.agent; do
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

INSTALL_DIR="/opt/macintel"
DATA_DIR="/Library/Application Support/MacIntel"
LOG_DIR="/Library/Logs/MacIntel"
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
  AGENT_ID=$(python3 -c "import uuid; print(str(uuid.uuid4()))" 2>/dev/null \
    || uuidgen | tr '[:upper:]' '[:lower:]')
  AGENT_NAME=$(scutil --get ComputerName 2>/dev/null || hostname -s)

  export AGENT_ID AGENT_NAME
  export INSTALL_DIR DATA_DIR LOG_DIR SECURITY_DIR
  export MANAGER_URL="${BAKED_MANAGER_URL}"
  export ENROLL_TOKEN="${BAKED_ENROLL_TOKEN}"
  export TLS_VERIFY="${BAKED_TLS_VERIFY}"

  bash "${DATA_DIR}/generate_config.sh"
  echo "  Config generated: ${CONFIG_PATH}"
else
  echo "  Existing config preserved: ${CONFIG_PATH}"
fi

# ── Fix plist ownership ────────────────────────────────────────────────────────
chown root:wheel "${LAUNCHDAEMON_DIR}/com.macintel.agent.plist"
chown root:wheel "${LAUNCHDAEMON_DIR}/com.macintel.watchdog.plist"
chmod 644 "${LAUNCHDAEMON_DIR}/com.macintel.agent.plist"
chmod 644 "${LAUNCHDAEMON_DIR}/com.macintel.watchdog.plist"

# ── Remove quarantine ──────────────────────────────────────────────────────────
xattr -dr com.apple.quarantine "${INSTALL_DIR}/bin/" 2>/dev/null || true

# ── Load LaunchDaemons ────────────────────────────────────────────────────────
launchctl load -w "${LAUNCHDAEMON_DIR}/com.macintel.watchdog.plist" 2>/dev/null || true
launchctl load -w "${LAUNCHDAEMON_DIR}/com.macintel.agent.plist"    2>/dev/null || true

echo "  MacIntel agent installed and started."
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
    <organization>com.macintel</organization>
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
cat > "${BUILD_DIR}/welcome.html" <<HTML
<!DOCTYPE html><html>
<head><style>
  body { font-family: -apple-system, sans-serif; font-size: 13px; margin: 20px; }
  h2   { color: #1d3461; }
  code { background: #f0f0f0; padding: 2px 4px; border-radius: 3px; }
  .ok  { color: #2a7a2a; font-weight: bold; }
</style></head>
<body>
  <h2>mac_intel Agent ${VERSION} (${ARCH})</h2>
  <p>This package installs the mac_intel endpoint telemetry agent.</p>
  <p>The agent runs as a <b>background LaunchDaemon</b> and sends
     encrypted telemetry to your mac_intel Manager.</p>
  <p class="ok">&#x2705; Zero-touch install — no manual configuration required.</p>
  <ul>
    <li><b>Manager:</b> <code>${MANAGER_URL}</code></li>
    <li><b>Agent ID</b> and <b>API key</b> are generated automatically on first run.</li>
    <li>The agent starts immediately after installation.</li>
  </ul>
  <p style="font-size:11px;color:#888">
    Enrollment token is pre-configured. Ensure it is registered in the manager's
    <code>ENROLLMENT_TOKENS</code> before installing.
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
echo "  Package      : ${PKG_FINAL}"
echo "  Size         : ${PKG_SIZE}"
echo ""
echo "  ── Install ─────────────────────────────────────────────────────────────"
echo "    sudo installer -pkg '${PKG_FINAL}' -target /"
echo ""
echo "  ── Manager setup (do this BEFORE installing on endpoints) ───────────────"
echo "    Add the enrollment token to your manager's allowed tokens:"
echo ""
echo "      ENROLLMENT_TOKENS=${ENROLL_TOKEN}"
echo ""
echo "    The agent will auto-enroll on first start and obtain its API key."
echo "    No manual key generation or config editing needed on the endpoint."
echo ""
echo "  ── Silent MDM deploy (Jamf / Mosyle / Intune) ───────────────────────────"
echo "    Upload '${PKG_FINAL}' — manager URL and token are baked in."
echo "    No pre/post scripts or policy variables required."
echo ""
