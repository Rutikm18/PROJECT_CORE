#!/usr/bin/env bash
# =============================================================================
#  AttackLens Agent — macOS Uninstaller
#
#  Usage:
#    sudo bash uninstall.sh [--keep-config] [--keep-logs] [--keep-keys]
#
#  Handles both old (/Library/Jarvis) and new (/Library/AttackLens) installs.
# =============================================================================
set -euo pipefail

KEEP_CONFIG=false
KEEP_LOGS=false
KEEP_KEYS=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --keep-config) KEEP_CONFIG=true; shift ;;
    --keep-logs)   KEEP_LOGS=true;   shift ;;
    --keep-keys)   KEEP_KEYS=true;   shift ;;
    *)             echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "  ERROR: must run as root. Use: sudo bash uninstall.sh" >&2
  exit 1
fi

echo ""
echo "  AttackLens Agent — Uninstalling..."
echo ""

LAUNCHDAEMON_DIR="/Library/LaunchDaemons"

# ── Stop all known service labels (old + new) ─────────────────────────────────
for LABEL in com.macintel.watchdog com.macintel.agent com.attacklens.watchdog com.attacklens.agent; do
  PLIST="${LAUNCHDAEMON_DIR}/${LABEL}.plist"
  if [[ -f "$PLIST" ]]; then
    echo "  Stopping ${LABEL}..."
    launchctl unload -w "$PLIST" 2>/dev/null || true
    sleep 1
    rm -f "$PLIST"
    echo "    Removed: $PLIST"
  fi
done

# ── Remove binaries from all known locations ──────────────────────────────────
echo "  Removing binaries..."
for DIR in "/Library/AttackLens/bin" "/Library/Jarvis/bin"; do
  for BIN in attacklens-agent attacklens-watchdog macintel-agent macintel-watchdog; do
    if [[ -f "${DIR}/${BIN}" ]]; then
      rm -f "${DIR}/${BIN}"
      echo "    Removed: ${DIR}/${BIN}"
    fi
  done
  rmdir "${DIR}" 2>/dev/null || true
done

# ── Remove attacklens CLI ─────────────────────────────────────────────────────
for CLI in /usr/local/bin/attacklens /usr/local/bin/attacklens-ctl; do
  if [[ -f "$CLI" ]]; then
    rm -f "$CLI"
    echo "  Removed: $CLI"
  fi
done

# ── Remove Keychain entries ───────────────────────────────────────────────────
if [[ "$KEEP_KEYS" == "false" ]]; then
  echo "  Removing Keychain entries..."
  for SVC in com.attacklens.agent com.macintel.agent com.jarvis.agent; do
    security delete-generic-password -s "$SVC" \
      /Library/Keychains/System.keychain 2>/dev/null || true
  done
  for DIR in "/Library/AttackLens/security" "/Library/Jarvis/security"; do
    if [[ -d "$DIR" ]]; then
      rm -rf "$DIR"
      echo "    Removed: $DIR"
    fi
  done
fi

# ── Remove config ─────────────────────────────────────────────────────────────
if [[ "$KEEP_CONFIG" == "false" ]]; then
  for DIR in "/Library/AttackLens" "/Library/Jarvis"; do
    if [[ -f "${DIR}/agent.toml" ]]; then
      rm -f "${DIR}/agent.toml"
      echo "  Removed: ${DIR}/agent.toml"
    fi
  done
fi

# ── Remove logs ───────────────────────────────────────────────────────────────
if [[ "$KEEP_LOGS" == "false" ]]; then
  for DIR in "/Library/AttackLens/logs" "/Library/Jarvis/logs"; do
    if [[ -d "$DIR" ]]; then
      rm -rf "$DIR"
      echo "  Removed: $DIR"
    fi
  done
fi

# ── Clean up data dirs ────────────────────────────────────────────────────────
for DIR in "/Library/AttackLens" "/Library/Jarvis"; do
  rm -f "${DIR}/"*.pid 2>/dev/null || true
  for SUB in data spool; do
    rmdir "${DIR}/${SUB}" 2>/dev/null || true
  done
  rmdir "${DIR}" 2>/dev/null || true
done

echo ""
echo "  Uninstall complete."
echo ""
