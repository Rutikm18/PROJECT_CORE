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
# Prepend our source directory so our code takes priority over any
# host-installed packages with the same name.  DO NOT replace sys.path
# entirely — that kills stdlib (argparse, os, etc.) and site-packages.
sys.path.insert(0, '${SRC_DIR}')
from agent.agent_entry import main
main()
PYBOOT

cat > "${PKG_ROOT}${BIN_DIR}/run_watchdog.py" <<PYBOOT
import sys
sys.path.insert(0, '${SRC_DIR}')
from agent.agent.watchdog import main
main()
PYBOOT

chmod 644 \
    "${PKG_ROOT}${BIN_DIR}/run_agent.py" \
    "${PKG_ROOT}${BIN_DIR}/run_watchdog.py"

# Bundle generate_config.sh + QUICKSTART.md
cp  "${SCRIPT_DIR}/generate_config.sh" "${PKG_ROOT}${BIN_DIR}/generate_config.sh"
chmod 755 "${PKG_ROOT}${BIN_DIR}/generate_config.sh"
[[ -f "${SCRIPT_DIR}/QUICKSTART.md" ]] && \
    cp "${SCRIPT_DIR}/QUICKSTART.md" "${PKG_ROOT}${INSTALL_DIR}/QUICKSTART.md" && \
    chmod 644 "${PKG_ROOT}${INSTALL_DIR}/QUICKSTART.md"

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
# Stop any existing AttackLens services (system + gui domains) before upgrade.
set -uo pipefail
LDIR="/Library/LaunchDaemons"
for LABEL in \
    com.attacklens.watchdog com.attacklens.agent \
    com.macintel.watchdog   com.macintel.agent; do
    # Remove from system domain
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
    # Also remove from any user gui/ domain (wrong-domain installs)
    for uid in $(dscl . -list /Users UniqueID 2>/dev/null | awk '$2>499{print $2}'); do
        launchctl bootout "gui/${uid}/${LABEL}" 2>/dev/null || true
    done
    launchctl unload -w "${LDIR}/${LABEL}.plist" 2>/dev/null || true
done
exit 0
PREINST
chmod 755 "${PKG_SCRIPTS}/preinstall"

# ---------- postinstall -------------------------------------------------------
cat > "${PKG_SCRIPTS}/postinstall" <<POSTINST
#!/usr/bin/env bash
# =============================================================================
#  postinstall — AttackLens Agent v${VERSION}
#
#  Reads optional env file before installing:
#    echo "ATTACKLENS_MANAGER='<IP_or_URL>'" > /tmp/attacklens_envs
#    echo "ATTACKLENS_AGENT_NAME='<name>'"   >> /tmp/attacklens_envs
#
#  Supported env vars:
#    ATTACKLENS_MANAGER    — manager IP, IP:port, or full http/https URL
#    ATTACKLENS_AGENT_NAME — human-readable agent label (default: ComputerName)
#    ATTACKLENS_TAGS       — comma-separated tags, e.g. "prod,finance"
#    ATTACKLENS_TOKEN      — enrollment token (if manager requires one)
# =============================================================================
set -uo pipefail

readonly INSTALL_DIR="${INSTALL_DIR}"
readonly BIN_DIR="${BIN_DIR}"
readonly LOG_DIR="${LOG_DIR}"
readonly SECURITY_DIR="${SECURITY_DIR}"
readonly CONFIG_PATH="${CONFIG_PATH}"
readonly LDIR="${LDIR}"
readonly PKG_DEFAULT_MANAGER="${DEFAULT_MANAGER_URL}"
readonly VERSION="${VERSION}"

log()  { echo "  \$1"; }
die()  { echo "  ERROR: \$1" >&2; exit 1; }
ok()   { echo "  [OK] \$1"; }
warn() { echo "  [WARN] \$1"; }

echo ""
echo "  AttackLens Agent v\${VERSION} — Installing..."
echo "  =================================================="

# ── Step 1: Read /tmp/attacklens_envs ─────────────────────────────────────────
log "Reading environment..."
ATTACKLENS_MANAGER=""
ATTACKLENS_AGENT_NAME=""
ATTACKLENS_TAGS=""
ATTACKLENS_TOKEN=""

ENV_FILE="/tmp/attacklens_envs"
if [[ -f "\$ENV_FILE" ]]; then
    log "  Found: \${ENV_FILE}"
    while IFS= read -r line || [[ -n "\$line" ]]; do
        # Skip comments and blank lines
        [[ "\$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "\${line//[[:space:]]/}" ]] && continue
        key="\${line%%=*}"
        val="\${line#*=}"
        # Strip surrounding single or double quotes
        val="\${val#\\'}" ; val="\${val%\\'}"
        val="\${val#\"}"  ; val="\${val%\"}"
        val="\${val#\\'}" ; val="\${val%\\'}"   # handle echo "KEY='val'" format
        case "\$key" in
            ATTACKLENS_MANAGER)    ATTACKLENS_MANAGER="\$val" ;;
            ATTACKLENS_AGENT_NAME) ATTACKLENS_AGENT_NAME="\$val" ;;
            ATTACKLENS_TAGS)       ATTACKLENS_TAGS="\$val" ;;
            ATTACKLENS_TOKEN)      ATTACKLENS_TOKEN="\$val" ;;
        esac
    done < "\$ENV_FILE"
    [[ -n "\$ATTACKLENS_MANAGER"    ]] && log "  Manager   : \$ATTACKLENS_MANAGER"
    [[ -n "\$ATTACKLENS_AGENT_NAME" ]] && log "  Agent name: \$ATTACKLENS_AGENT_NAME"
    [[ -n "\$ATTACKLENS_TAGS"       ]] && log "  Tags      : \$ATTACKLENS_TAGS"
else
    log "  No /tmp/attacklens_envs — using package defaults"
fi

# ── Step 2: Normalise manager URL ─────────────────────────────────────────────
# Priority: env file > pkg baked-in default
MANAGER="\${ATTACKLENS_MANAGER:-\$PKG_DEFAULT_MANAGER}"

# If bare IP or IP:PORT (no scheme), prepend http://
if [[ -n "\$MANAGER" ]] && [[ "\$MANAGER" != http://* ]] && [[ "\$MANAGER" != https://* ]]; then
    MANAGER="http://\${MANAGER}"
fi
log "  Effective manager URL: \${MANAGER}"

# ── Step 3: Permissions ───────────────────────────────────────────────────────
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
    [[ -f "\${LDIR}/\${f}" ]] && chown root:wheel "\${LDIR}/\${f}" && chmod 644 "\${LDIR}/\${f}" || true
done
ok "Permissions"

# ── Step 4: Find real Mach-O python3 ──────────────────────────────────────────
# macOS 15+ Sequoia/Tahoe: ProgramArguments[0] MUST be a Mach-O binary.
# Ask Python to resolve its own real path (handles all symlink/wrapper chains).
log "Detecting python3..."
PYTHON3=""
for p in /usr/local/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3; do
    [[ -x "\$p" ]] || continue
    real="\$("\$p" -c "import os,sys; print(os.path.realpath(sys.executable))" 2>/dev/null)" || continue
    [[ -x "\$real" ]] || continue
    if file "\$real" 2>/dev/null | grep -q "Mach-O"; then
        PYTHON3="\$real"; break
    fi
done
# Fallback: accept any python3 (may be a wrapper; will work but may hit exit-78 on macOS 15+)
if [[ -z "\$PYTHON3" ]]; then
    for p in /usr/local/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3; do
        [[ -x "\$p" ]] && { PYTHON3="\$p"; break; }
    done
fi
[[ -z "\$PYTHON3" ]] && die "python3 not found. Install from https://python.org then reinstall."
ok "python3: \${PYTHON3}  (\$("\${PYTHON3}" --version 2>&1))"

# Warn if Python < 3.11
"\${PYTHON3}" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" 2>/dev/null || \
    warn "Python < 3.11 — upgrade recommended: https://python.org/downloads/"

# ── Step 5: Install Python prerequisites (always, not conditional) ────────────
log "Installing Python prerequisites..."
_pip() {
    local pkg="\$1"
    "\${PYTHON3}" -m pip install --quiet --upgrade --break-system-packages "\${pkg}" 2>/dev/null || \
    "\${PYTHON3}" -m pip install --quiet --upgrade "\${pkg}" 2>/dev/null || \
    warn "Could not install \${pkg} — agent may have reduced functionality"
}
# tomllib is stdlib in 3.11+; install tomli as backport for older Python
"\${PYTHON3}" -c "import tomllib" 2>/dev/null || _pip tomli
_pip psutil
_pip cryptography
_pip requests
ok "Prerequisites installed"

# ── Step 6: Patch plists with real Mach-O python3 ────────────────────────────
log "Patching LaunchDaemon plists..."
for plist in "\${LDIR}/com.attacklens.agent.plist" "\${LDIR}/com.attacklens.watchdog.plist"; do
    [[ -f "\$plist" ]] || continue
    sed -i '' "s|PYTHON3_PLACEHOLDER|\${PYTHON3}|g" "\$plist"
    # Also replace any previously-set path that differs from detected Mach-O
    "\${PYTHON3}" - "\$plist" "\${PYTHON3}" <<'PYEOF'
import sys, re
plist, py3 = sys.argv[1], sys.argv[2]
with open(plist) as f: content = f.read()
new = re.sub(
    r'(<key>ProgramArguments</key>\s*<array>\s*<string>)[^<]*(</string>)',
    rf'\g<1>{py3}\g<2>', content, flags=re.DOTALL)
if new != content:
    with open(plist, 'w') as f: f.write(new)
PYEOF
    ok "Patched: \$(basename "\$plist") → \${PYTHON3}"
done

# ── Step 7: Generate agent.toml ───────────────────────────────────────────────
# Always regenerate when env file provides values; otherwise skip if exists.
SHOULD_GEN=false
[[ ! -f "\${CONFIG_PATH}" ]] && SHOULD_GEN=true
[[ -f "\${ENV_FILE}" ]]       && SHOULD_GEN=true   # env file present → always apply

if [[ "\$SHOULD_GEN" == "true" ]]; then
    log "Generating agent.toml..."
    MANAGER_URL="\${MANAGER}"                           \
    AGENT_NAME="\${ATTACKLENS_AGENT_NAME:-}"            \
    AGENT_TAGS="\${ATTACKLENS_TAGS:-}"                  \
    ENROLL_TOKEN="\${ATTACKLENS_TOKEN:-}"               \
    INSTALL_DIR="\${INSTALL_DIR}"                       \
    LOG_DIR="\${LOG_DIR}"                               \
    SECURITY_DIR="\${SECURITY_DIR}"                     \
    bash "\${BIN_DIR}/generate_config.sh"
    ok "agent.toml written"
else
    log "  Existing agent.toml kept (no env file provided)"
    log "  To reconfigure: sudo attacklens-service set-manager <IP>"
fi

# ── Step 8: Validate plists ───────────────────────────────────────────────────
for plist in "\${LDIR}/com.attacklens.agent.plist" "\${LDIR}/com.attacklens.watchdog.plist"; do
    plutil -lint "\$plist" >/dev/null 2>&1 \
        && ok "Valid plist: \$(basename "\$plist")" \
        || warn "Plist syntax error: \$(basename "\$plist")"
done

# ── Step 9: Start services in SYSTEM domain (never gui/) ─────────────────────
log "Starting LaunchDaemons..."
for LABEL in com.attacklens.agent com.attacklens.watchdog; do
    # Make sure not stuck in wrong domain from previous installs
    for uid in \$(dscl . -list /Users UniqueID 2>/dev/null | awk '\$2>499{print \$2}'); do
        launchctl bootout "gui/\${uid}/\${LABEL}" 2>/dev/null || true
    done
    launchctl enable "system/\${LABEL}" 2>/dev/null || true
done

launchctl bootstrap system "\${LDIR}/com.attacklens.agent.plist" 2>/dev/null \
    && ok "Started: com.attacklens.agent" \
    || log "  com.attacklens.agent queued — run: sudo attacklens-service start"

launchctl bootstrap system "\${LDIR}/com.attacklens.watchdog.plist" 2>/dev/null \
    && ok "Started: com.attacklens.watchdog" \
    || log "  com.attacklens.watchdog queued (non-critical)"

# ── Step 10: Verify & summary ─────────────────────────────────────────────────
sleep 3
AGENT_STATE=\$(launchctl print "system/com.attacklens.agent" 2>/dev/null | awk '/state =/{print \$3}')

echo ""
echo "  =================================================="
echo "  AttackLens Agent v\${VERSION} — Installation Complete"
echo "  =================================================="
echo "  Manager : \${MANAGER}"
echo "  Config  : \${CONFIG_PATH}"
echo "  Python  : \${PYTHON3}"
echo "  Agent   : \${AGENT_STATE:-checking...}"
echo ""
echo "  Service commands:"
echo "    attacklens-service status     # check agent state"
echo "    sudo attacklens-service start  # start"
echo "    sudo attacklens-service stop   # stop"
echo "    sudo attacklens-service restart # restart"
echo "    attacklens-service logs        # live log"
echo "    attacklens-service diagnose    # connectivity check"
echo ""
if [[ "\$MANAGER" == *"YOUR_MANAGER"* ]]; then
    echo "  NOTE: Set manager IP:"
    echo "    sudo attacklens-service set-manager <IP>"
    echo ""
fi
# Clean up env file (contains potentially sensitive token)
rm -f "\${ENV_FILE}" 2>/dev/null && log "  Cleaned up \${ENV_FILE}"
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
