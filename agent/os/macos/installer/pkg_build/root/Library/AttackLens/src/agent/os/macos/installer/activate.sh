#!/bin/bash
#
# activate.sh — Activate the AttackLens macOS agent as a boot-persistent
#               LaunchDaemon (capability #1: auto-launch on restart).
#
# What it does (transparent, no stealth):
#   • validates the python interpreter, entry script, plist, and config exist
#   • loads com.attacklens.agent into the system domain via the modern
#     `launchctl bootstrap` API  (RunAtLoad=true → starts now and at every boot;
#      KeepAlive=true → launchd auto-restarts it if it ever exits)
#   • verifies the daemon is actually running (prints PID)
#
# Idempotent: safe to re-run; it boots out any stale instance first.
# Requires root:  sudo bash activate.sh
#
set -euo pipefail

LABEL="com.attacklens.agent"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
PY="/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13"
ENTRY="/Library/AttackLens/bin/run_agent.py"
CONFIG="/Library/AttackLens/agent.toml"
LOGDIR="/Library/AttackLens/logs"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '  • %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { red "Must run as root:  sudo bash $0"; exit 1; }

echo "── Preflight ───────────────────────────────────────────"
fail=0
for f in "$PY" "$ENTRY" "$CONFIG" "$PLIST"; do
  if [ -e "$f" ]; then info "found  $f"; else red "  ✗ missing $f"; fail=1; fi
done
[ "$fail" -eq 0 ] || { red "Preflight failed — fix the missing paths above."; exit 1; }

# Confirm the plist points at an interpreter that exists (not a stale binary path)
prog="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$PLIST" 2>/dev/null || true)"
if [ "$prog" != "$PY" ]; then
  red "  ! plist ProgramArguments[0] is '$prog', expected '$PY'"
  red "    The daemon would fail to launch. Re-run the installer/generate_config step."
  exit 1
fi
green "Preflight OK"

echo "── Loading daemon ──────────────────────────────────────"
# Drop any stale registration first (ignore errors — may not be loaded yet)
launchctl bootout "system/${LABEL}" 2>/dev/null || true
# Clear any prior `disable` override, then load + start
launchctl enable "system/${LABEL}" 2>/dev/null || true
if launchctl bootstrap system "$PLIST" 2>/dev/null; then
  info "bootstrapped via modern API"
else
  info "bootstrap unavailable — falling back to legacy load -w"
  launchctl load -w "$PLIST"
fi
# Nudge it to start immediately (RunAtLoad should already have)
launchctl kickstart -k "system/${LABEL}" 2>/dev/null || true

echo "── Verify ──────────────────────────────────────────────"
sleep 2
if launchctl print "system/${LABEL}" >/tmp/al_print.$$ 2>/dev/null; then
  pid="$(awk -F'= ' '/^[[:space:]]*pid =/{print $2; exit}' /tmp/al_print.$$)"
  state="$(awk -F'= ' '/^[[:space:]]*state =/{print $2; exit}' /tmp/al_print.$$)"
  rm -f /tmp/al_print.$$
  if [ -n "${pid:-}" ]; then
    green "Agent RUNNING — pid=${pid} state=${state:-running}"
    green "It will now auto-start on every reboot and auto-restart if it exits."
  else
    red "Daemon loaded but not running (state=${state:-unknown})."
    red "Check logs: tail -n 50 ${LOGDIR}/agent-stderr.log"
    exit 1
  fi
else
  red "Daemon did not register. Check: sudo launchctl print system/${LABEL}"
  exit 1
fi

echo "── Recent agent log ────────────────────────────────────"
tail -n 15 "${LOGDIR}/agent.log" 2>/dev/null || info "(no agent.log yet — give it a few seconds)"

cat <<EOF

Done. Useful follow-ups:
  status:   sudo launchctl print system/${LABEL} | grep -E 'state|pid'
  logs:     tail -f ${LOGDIR}/agent.log
  stop:     sudo launchctl bootout system/${LABEL}
  re-run:   sudo bash $0
EOF
