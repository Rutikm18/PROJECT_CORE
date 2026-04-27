#!/usr/bin/env bash
# =============================================================================
#  build_pkg.sh — Build attacklens-agent-2.0.0-arm64.pkg
#
#  Self-contained macOS installer. Bundles Python source + all support scripts.
#  Works on any arm64 Mac with Python 3.11+.  No dev environment needed.
#
#  Usage:
#    bash build_pkg.sh [MANAGER_IP_OR_URL]
#    bash build_pkg.sh 34.224.174.38                   # auto-wrapped to http://...:8080
#    bash build_pkg.sh https://manager.example.com     # full URL accepted
#    bash build_pkg.sh                                  # placeholder IP (set after install)
#
#  Output:
#    dist/attacklens-agent-2.0.0-arm64.pkg
#
#  Install on target Mac:
#    sudo installer -pkg dist/attacklens-agent-2.0.0-arm64.pkg -target /
#
#  After install:
#    attacklens-service status
#    attacklens-service diagnose
#    sudo attacklens-service set-manager <NEW_IP>    (if placeholder was used)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

MANAGER_ARG="${1:-YOUR_MANAGER_IP}"
readonly VERSION="2.0.0"
readonly ARCH="arm64"
readonly PKG_ID="com.attacklens.agent"
readonly PKG_NAME="attacklens-agent-${VERSION}-${ARCH}.pkg"

# Normalise manager arg → URL
if   [[ "$MANAGER_ARG" == http://*  ]]; then DEFAULT_MANAGER_URL="$MANAGER_ARG"
elif [[ "$MANAGER_ARG" == https://* ]]; then DEFAULT_MANAGER_URL="$MANAGER_ARG"
else DEFAULT_MANAGER_URL="http://${MANAGER_ARG}:8080"
fi

# ── Build directory layout ────────────────────────────────────────────────────
BUILD_DIR="${SCRIPT_DIR}/pkg_build"
DIST_DIR="${SCRIPT_DIR}/dist"
PKG_ROOT="${BUILD_DIR}/root"
PKG_SCRIPTS="${BUILD_DIR}/scripts"

# ── Installed paths (inside the pkg payload) ──────────────────────────────────
readonly INSTALL_DIR="/Library/AttackLens"
readonly SRC_DIR="${INSTALL_DIR}/src"
readonly BIN_DIR="${INSTALL_DIR}/bin"
readonly LOG_DIR="${INSTALL_DIR}/logs"
readonly SECURITY_DIR="${INSTALL_DIR}/security"
readonly CONFIG_PATH="${INSTALL_DIR}/agent.toml"
readonly LDIR="/Library/LaunchDaemons"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║     AttackLens Agent  PKG Builder  v${VERSION}              ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Manager  : ${DEFAULT_MANAGER_URL}"
echo "  Source   : ${REPO_DIR}"
echo "  Output   : dist/${PKG_NAME}"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────
echo "  [0/6] Pre-flight checks..."

command -v pkgbuild     >/dev/null || { echo "  ERROR: pkgbuild not found (install Xcode CLT)"; exit 1; }
command -v productbuild >/dev/null || { echo "  ERROR: productbuild not found (install Xcode CLT)"; exit 1; }
command -v rsync        >/dev/null || { echo "  ERROR: rsync not found"; exit 1; }

[[ -d "${REPO_DIR}/agent"  ]] || { echo "  ERROR: ${REPO_DIR}/agent not found"; exit 1; }
[[ -f "${SCRIPT_DIR}/attacklens-service" ]] || { echo "  ERROR: attacklens-service not found in ${SCRIPT_DIR}"; exit 1; }
[[ -f "${SCRIPT_DIR}/generate_config.sh" ]] || { echo "  ERROR: generate_config.sh not found in ${SCRIPT_DIR}"; exit 1; }

echo "     OK."

# ── [1/6] Clean & scaffold ────────────────────────────────────────────────────
echo "  [1/6] Scaffolding build directory..."
rm -rf "${BUILD_DIR}"
mkdir -p \
    "${PKG_ROOT}${SRC_DIR}" \
    "${PKG_ROOT}${BIN_DIR}" \
    "${PKG_ROOT}${LOG_DIR}" \
    "${PKG_ROOT}${SECURITY_DIR}" \
    "${PKG_ROOT}${INSTALL_DIR}/data" \
    "${PKG_ROOT}${INSTALL_DIR}/spool" \
    "${PKG_ROOT}${LDIR}" \
    "${PKG_ROOT}/usr/local/bin" \
    "${PKG_SCRIPTS}" \
    "${DIST_DIR}"
echo "     Done."

# ── [2/6] Copy Python source ──────────────────────────────────────────────────
echo "  [2/6] Copying Python source → ${SRC_DIR} ..."
rsync -a \
    --exclude '__pycache__' --exclude '*.pyc' --exclude '.git' \
    --exclude 'dist' --exclude 'build' --exclude 'pkg_build' \
    --exclude '*.pkg' --exclude 'venv' --exclude '.venv' \
    --exclude '*.egg-info' --exclude '.env' --exclude '*.key' \
    --exclude 'spool' --exclude 'tests' \
    "${REPO_DIR}/agent/"  "${PKG_ROOT}${SRC_DIR}/agent/"
rsync -a \
    --exclude '__pycache__' --exclude '*.pyc' \
    "${REPO_DIR}/shared/" "${PKG_ROOT}${SRC_DIR}/shared/" 2>/dev/null || true
echo "     Done."

# ── [3/6] Bootstrap launchers ────────────────────────────────────────────────
# Launchers set sys.path to ONLY our installed source directory before importing.
# PYTHON3_PLACEHOLDER is replaced at postinstall time with the real python3 path.
echo "  [3/6] Writing bootstrap launchers..."

cat > "${PKG_ROOT}${BIN_DIR}/run_agent.py" <<PYBOOT
import sys
# Hard-reset sys.path to our installed source only.
# Must run before any other import — prevents host-env package conflicts.
sys.path = ['${SRC_DIR}']
from agent.agent_entry import main
main()
PYBOOT

cat > "${PKG_ROOT}${BIN_DIR}/run_watchdog.py" <<PYBOOT
import sys
sys.path = ['${SRC_DIR}']
from agent.agent.watchdog import main
main()
PYBOOT

chmod 644 \
    "${PKG_ROOT}${BIN_DIR}/run_agent.py" \
    "${PKG_ROOT}${BIN_DIR}/run_watchdog.py"

# Bundle generate_config.sh so attacklens-service update-config works post-install
cp  "${SCRIPT_DIR}/generate_config.sh" "${PKG_ROOT}${BIN_DIR}/generate_config.sh"
chmod 755 "${PKG_ROOT}${BIN_DIR}/generate_config.sh"

echo "     Done."

# ── [4/6] CLI binaries ────────────────────────────────────────────────────────
echo "  [4/6] Installing attacklens-service CLI..."
cp "${SCRIPT_DIR}/attacklens-service" "${PKG_ROOT}/usr/local/bin/attacklens-service"
chmod 755 "${PKG_ROOT}/usr/local/bin/attacklens-service"
# attacklens → attacklens-service  (backward-compatible alias, same binary)
ln -sf "attacklens-service" "${PKG_ROOT}/usr/local/bin/attacklens"
echo "     Installed: /usr/local/bin/attacklens-service"
echo "     Alias:     /usr/local/bin/attacklens → attacklens-service"

# ── [5/6] LaunchDaemon plists ─────────────────────────────────────────────────
# PYTHON3_PLACEHOLDER is replaced in postinstall after detecting the real binary.
# ProgramArguments[0] MUST be a Mach-O binary — macOS 15+ (Sequoia/Tahoe)
# blocks LaunchDaemons that launch shell scripts as their primary executable.
echo "  [5/6] Writing LaunchDaemon plists..."

cat > "${PKG_ROOT}${LDIR}/com.attacklens.agent.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.attacklens.agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>PYTHON3_PLACEHOLDER</string>
        <string>${BIN_DIR}/run_agent.py</string>
        <string>--config</string>
        <string>${CONFIG_PATH}</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONUNBUFFERED</key>
        <string>1</string>
    </dict>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>UserName</key>
    <string>root</string>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent-stderr.log</string>
</dict>
</plist>
PLIST

cat > "${PKG_ROOT}${LDIR}/com.attacklens.watchdog.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.attacklens.watchdog</string>

    <key>ProgramArguments</key>
    <array>
        <string>PYTHON3_PLACEHOLDER</string>
        <string>${BIN_DIR}/run_watchdog.py</string>
        <string>--config</string>
        <string>${CONFIG_PATH}</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONUNBUFFERED</key>
        <string>1</string>
    </dict>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>UserName</key>
    <string>root</string>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/watchdog-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/watchdog-stderr.log</string>
</dict>
</plist>
PLIST

echo "     Done."

# ── [6/6] Installer scripts ───────────────────────────────────────────────────
echo "  [6/6] Writing installer scripts (preinstall / postinstall)..."

# ---------- preinstall --------------------------------------------------------
cat > "${PKG_SCRIPTS}/preinstall" <<'PREINST'
#!/usr/bin/env bash
# Stop any existing AttackLens (or legacy mac_intel) services before upgrade.
set -uo pipefail
LDIR="/Library/LaunchDaemons"
for LABEL in \
    com.attacklens.watchdog com.attacklens.agent \
    com.macintel.watchdog   com.macintel.agent; do
    launchctl bootout "system/${LABEL}" 2>/dev/null || \
    launchctl unload -w "${LDIR}/${LABEL}.plist" 2>/dev/null || true
done
exit 0
PREINST
chmod 755 "${PKG_SCRIPTS}/preinstall"

# ---------- postinstall -------------------------------------------------------
# Variables embedded at build time; shell vars inside single-quotes are
# intentionally deferred to postinstall runtime (via \$ escaping).
cat > "${PKG_SCRIPTS}/postinstall" <<POSTINST
#!/usr/bin/env bash
# =============================================================================
#  postinstall — AttackLens Agent v${VERSION}
#  Runs as root on the target Mac after the pkg payload is laid down.
# =============================================================================
set -uo pipefail

readonly INSTALL_DIR="${INSTALL_DIR}"
readonly BIN_DIR="${BIN_DIR}"
readonly LOG_DIR="${LOG_DIR}"
readonly SECURITY_DIR="${SECURITY_DIR}"
readonly CONFIG_PATH="${CONFIG_PATH}"
readonly LDIR="${LDIR}"
readonly DEFAULT_MANAGER_URL="${DEFAULT_MANAGER_URL}"

log() { echo "  \$1"; }
die() { echo "  ERROR: \$1" >&2; exit 1; }

# ── 1. Set file ownership & permissions ───────────────────────────────────────
log "Setting permissions..."
chown -R root:wheel "\${INSTALL_DIR}"
chmod 755 "\${INSTALL_DIR}" "\${BIN_DIR}"
chmod 644 "\${BIN_DIR}/run_agent.py" "\${BIN_DIR}/run_watchdog.py"
chmod 755 "\${BIN_DIR}/generate_config.sh"
chmod 750 "\${LOG_DIR}" "\${INSTALL_DIR}/data" "\${INSTALL_DIR}/spool"
chmod 700 "\${SECURITY_DIR}"

for cli in /usr/local/bin/attacklens-service /usr/local/bin/attacklens; do
    [[ -e "\$cli" ]] && { chown root:wheel "\$cli"; chmod 755 "\$cli"; } || true
done

for f in com.attacklens.agent.plist com.attacklens.watchdog.plist; do
    chown root:wheel "\${LDIR}/\${f}" 2>/dev/null || true
    chmod 644        "\${LDIR}/\${f}" 2>/dev/null || true
done

# ── 2. Detect python3 (MUST be a Mach-O binary, not a shell script) ───────────
log "Detecting python3..."
PYTHON3=""
for p in /usr/local/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3; do
    if [[ -x "\$p" ]]; then
        # Reject shell-script wrappers — macOS 15+ LaunchDaemon requirement
        if file "\$p" 2>/dev/null | grep -q "Mach-O"; then
            PYTHON3="\$p"; break
        else
            log "  Skipping shell-script python3 at \$p"
        fi
    fi
done

if [[ -z "\$PYTHON3" ]]; then
    # Last resort: accept any executable python3 (handles wrapper chains)
    for p in /usr/local/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3; do
        [[ -x "\$p" ]] && { PYTHON3="\$p"; break; }
    done
fi

[[ -z "\$PYTHON3" ]] && die "python3 not found. Install from https://python.org and reinstall."
log "  python3: \${PYTHON3}  (\$("\${PYTHON3}" --version 2>&1))"

# ── 3. Verify Python version ≥ 3.11 ──────────────────────────────────────────
PY_OK=\$("\${PYTHON3}" -c "
import sys
ok = (sys.version_info >= (3,11))
print('yes' if ok else 'no')
" 2>/dev/null || echo "no")
if [[ "\$PY_OK" != "yes" ]]; then
    log "WARNING: Python < 3.11 detected. Agent requires 3.11+."
    log "         Download: https://python.org/downloads/"
    log "         Continuing install — agent may fail to start until upgraded."
fi

# ── 4. Patch PYTHON3_PLACEHOLDER in LaunchDaemon plists ─────────────────────
log "Patching plists..."
for plist in "\${LDIR}/com.attacklens.agent.plist" "\${LDIR}/com.attacklens.watchdog.plist"; do
    if [[ -f "\$plist" ]]; then
        sed -i '' "s|PYTHON3_PLACEHOLDER|\${PYTHON3}|g" "\$plist"
        log "  Patched: \$(basename "\$plist")"
    fi
done

# ── 5. Install Python dependencies ────────────────────────────────────────────
log "Checking Python dependencies..."

# tomllib (stdlib in 3.11+) or tomli (backport for 3.10 and earlier)
"\${PYTHON3}" -c "import tomllib" 2>/dev/null || \
"\${PYTHON3}" -c "import tomli"   2>/dev/null || {
    log "  Installing tomli (TOML parser backport)..."
    "\${PYTHON3}" -m pip install --quiet --break-system-packages tomli 2>/dev/null || \
    "\${PYTHON3}" -m pip install --quiet tomli 2>/dev/null || \
    log "  WARNING: Could not install tomli — agent may fail to read config on Python < 3.11"
}

# psutil (optional but strongly recommended — falls back to CLI tools without it)
"\${PYTHON3}" -c "import psutil" 2>/dev/null || {
    log "  Installing psutil (system metrics collector)..."
    "\${PYTHON3}" -m pip install --quiet --break-system-packages psutil 2>/dev/null || \
    "\${PYTHON3}" -m pip install --quiet psutil 2>/dev/null || \
    log "  NOTE: psutil not installed — using CLI fallbacks (lsof, sysctl, etc.)"
}

# cryptography (required for AES-256-GCM payload encryption)
"\${PYTHON3}" -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" 2>/dev/null || {
    log "  Installing cryptography..."
    "\${PYTHON3}" -m pip install --quiet --break-system-packages cryptography 2>/dev/null || \
    "\${PYTHON3}" -m pip install --quiet cryptography 2>/dev/null || \
    log "  WARNING: cryptography not installed — payload encryption disabled"
}

# requests (HTTP transport)
"\${PYTHON3}" -c "import requests" 2>/dev/null || {
    log "  Installing requests..."
    "\${PYTHON3}" -m pip install --quiet --break-system-packages requests 2>/dev/null || \
    "\${PYTHON3}" -m pip install --quiet requests 2>/dev/null || \
    log "  WARNING: requests not installed — agent cannot send telemetry"
}

# ── 6. Write complete agent.toml (skip if already configured) ─────────────────
if [[ ! -f "\${CONFIG_PATH}" ]]; then
    log "Generating agent.toml..."
    MANAGER_URL="\${DEFAULT_MANAGER_URL}" \
    INSTALL_DIR="\${INSTALL_DIR}"         \
    LOG_DIR="\${LOG_DIR}"                 \
    SECURITY_DIR="\${SECURITY_DIR}"       \
    bash "\${BIN_DIR}/generate_config.sh"
else
    log "Existing agent.toml found — skipping config generation."
    log "  Run 'sudo attacklens-service update-config' to regenerate."
fi

# ── 7. Validate plist syntax ──────────────────────────────────────────────────
log "Validating plists..."
for plist in "\${LDIR}/com.attacklens.agent.plist" "\${LDIR}/com.attacklens.watchdog.plist"; do
    if ! plutil -lint "\$plist" >/dev/null 2>&1; then
        log "  WARNING: plist syntax error in \$(basename \$plist) — service may not load"
        plutil -lint "\$plist" 2>&1 | sed 's/^/    /' || true
    else
        log "  Valid: \$(basename "\$plist")"
    fi
done

# ── 8. Load services ──────────────────────────────────────────────────────────
log "Loading LaunchDaemons..."
for LABEL in com.attacklens.agent com.attacklens.watchdog; do
    launchctl enable "system/\${LABEL}" 2>/dev/null || true
done

AGENT_STARTED=false
if launchctl bootstrap system "\${LDIR}/com.attacklens.agent.plist" 2>/dev/null; then
    AGENT_STARTED=true
    log "  Started: com.attacklens.agent"
elif launchctl load -w "\${LDIR}/com.attacklens.agent.plist" 2>/dev/null; then
    AGENT_STARTED=true
    log "  Started: com.attacklens.agent (legacy load)"
else
    log "  NOTE: com.attacklens.agent could not start automatically."
    log "        On first install macOS may require background service approval."
    log "        → System Settings › Privacy & Security › Background Items"
    log "        → Allow items from AttackLens"
    log "        Then run: sudo attacklens-service start"
fi

if launchctl bootstrap system "\${LDIR}/com.attacklens.watchdog.plist" 2>/dev/null || \
   launchctl load -w "\${LDIR}/com.attacklens.watchdog.plist" 2>/dev/null; then
    log "  Started: com.attacklens.watchdog"
else
    log "  NOTE: com.attacklens.watchdog did not start (non-critical — agent runs independently)."
fi

# ── 9. Summary ────────────────────────────────────────────────────────────────
sleep 2
echo ""
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║  AttackLens Agent v${VERSION} — Installation Complete          ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  Manager:  \${DEFAULT_MANAGER_URL}"
echo "  Config:   \${CONFIG_PATH}"
echo "  Python:   \${PYTHON3}"
echo ""
echo "  Quick commands:"
echo "    attacklens-service status          — check service status"
echo "    attacklens-service diagnose        — connectivity check"
echo "    attacklens-service logs            — tail live log"
echo ""
if [[ "\$DEFAULT_MANAGER_URL" == *"YOUR_MANAGER"* ]]; then
    echo "  ⚠  Manager IP is a placeholder."
    echo "     Set it now:  sudo attacklens-service set-manager <IP>"
    echo ""
fi
echo "  Change manager:"
echo "    sudo attacklens-service set-manager <NEW_IP>"
echo ""
POSTINST
chmod 755 "${PKG_SCRIPTS}/postinstall"

# ── Build component pkg + distribution pkg ───────────────────────────────────
echo ""
echo "  Building pkg..."

pkgbuild \
    --root            "${PKG_ROOT}" \
    --scripts         "${PKG_SCRIPTS}" \
    --identifier      "${PKG_ID}" \
    --version         "${VERSION}" \
    --install-location "/" \
    "${BUILD_DIR}/attacklens-component.pkg"

cat > "${BUILD_DIR}/distribution.xml" <<DIST
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>AttackLens Agent ${VERSION}</title>
    <organization>com.attacklens</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    <allowed-os-versions>
        <os-version min="13.0"/>
    </allowed-os-versions>
    <pkg-ref id="${PKG_ID}"/>
    <choices-outline>
        <line choice="default">
            <line choice="${PKG_ID}"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="${PKG_ID}" visible="false">
        <pkg-ref id="${PKG_ID}"/>
    </choice>
    <pkg-ref id="${PKG_ID}" version="${VERSION}" onConclusion="none">attacklens-component.pkg</pkg-ref>
</installer-gui-script>
DIST

productbuild \
    --distribution "${BUILD_DIR}/distribution.xml" \
    --package-path "${BUILD_DIR}" \
    "${DIST_DIR}/${PKG_NAME}"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "  ╔═══════════════════════════════════════════════════════════════╗"
echo "  ║  Built:  dist/${PKG_NAME}  ║"
echo "  ╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Install on arm64 Mac (macOS 13+):"
echo "    sudo installer -pkg dist/${PKG_NAME} -target /"
echo ""
echo "  After install:"
echo "    attacklens-service status"
echo "    attacklens-service diagnose"
echo "    sudo attacklens-service set-manager <IP>   (if placeholder was used)"
echo ""
ls -lh "${DIST_DIR}/${PKG_NAME}"
echo ""
