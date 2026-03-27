#!/usr/bin/env bash
# =============================================================================
# mac_intel daemon — v4.1 (Apple Silicon / ARM)
#
# ARM changes vs v4.0:
#   • PATH: /opt/homebrew first (ARM Homebrew location)
#   • python3 resolved from /opt/homebrew/bin/python3 with fallback
#   • status: shows chip name, boot security mode, developer mode
#   • ARM-specific SQLite timeline shortcuts in help
#   • Page size note for memory calculations
# =============================================================================

set -uo pipefail

# ── ARM: Homebrew at /opt/homebrew on Apple Silicon ───────────────────────────
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Python3 — prefer Homebrew ARM build
PYTHON3="/opt/homebrew/bin/python3"
[[ -x "${PYTHON3}" ]] || PYTHON3="$(command -v python3 2>/dev/null || echo 'python3')"

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly COLLECTOR="${SCRIPT_DIR}/collector.sh"
readonly STORAGE="${SCRIPT_DIR}/storage.py"
readonly DB="${SCRIPT_DIR}/data/intel.db"
readonly LOG_DIR="${SCRIPT_DIR}/logs"
readonly FIFO="${SCRIPT_DIR}/intel.fifo"
readonly LAST_FULL_FILE="${SCRIPT_DIR}/.last_full_epoch"

readonly WRAP_LABEL="com.intel.mac-collector"
readonly WRAP_PLIST="/Library/LaunchDaemons/com.intel.mac-collector.plist"

FULL_HOURS=6
VOLATILE_MINS=5

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
info() { echo -e "${C}[info]${N} $*"; }
ok()   { echo -e "${G}[ok]${N}   $*"; }
warn() { echo -e "${Y}[warn]${N} $*"; }
err()  { echo -e "${R}[err]${N}  $*"; }
hdr()  { echo -e "\n${BOLD}${B}$*${N}"; }

CMD="${1:-help}"; shift || true
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full-hours)    FULL_HOURS="$2";    shift 2 ;;
    --volatile-mins) VOLATILE_MINS="$2"; shift 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

# ── Guards ────────────────────────────────────────────────────────────────────
need_root() { [[ "${EUID}" -eq 0 ]] || { err "Needs sudo."; exit 1; }; }
need_files() {
  local miss=()
  [[ -f "${COLLECTOR}" ]] || miss+=("collector.sh")
  [[ -f "${STORAGE}"   ]] || miss+=("storage.py")
  [[ -x "${PYTHON3}"   ]] || miss+=("python3 (expected at /opt/homebrew/bin/python3)")
  command -v sqlite3 &>/dev/null || miss+=("sqlite3")
  [[ ${#miss[@]} -gt 0 ]] && { err "Missing: ${miss[*]}"; exit 1; }
}

# ── FIFO pipe-run ──────────────────────────────────────────────────────────────
pipe_run() {
  local mode="${1:-full}"
  mkdir -p "${LOG_DIR}"
  local col_log="${LOG_DIR}/collector-${mode}.log"
  local sto_log="${LOG_DIR}/storage.log"

  info "pipe_run mode=${mode}"
  [[ -p "${FIFO}" ]] || mkfifo "${FIFO}"

  "${PYTHON3}" "${STORAGE}" --ingest "${FIFO}" --db "${DB}" >> "${sto_log}" 2>&1 &
  local sto_pid=$!

  bash "${COLLECTOR}" --mode "${mode}" --pipe "${FIFO}" >> "${col_log}" 2>&1
  local col_exit=$?

  wait "${sto_pid}" 2>/dev/null || true
  [[ ${col_exit} -eq 0 ]] && ok "pipe_run complete (mode=${mode})" || warn "Collector exit: ${col_exit}"
}

# ── Wrapper script ────────────────────────────────────────────────────────────
write_wrapper() {
  local wrapper="${SCRIPT_DIR}/run_wrapper.sh"
  cat > "${wrapper}" <<WRAPPER
#!/usr/bin/env bash
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
SCRIPT_DIR="${SCRIPT_DIR}"
FULL_SECS=$((FULL_HOURS * 3600))
LAST_FULL="${LAST_FULL_FILE}"
NOW="\$(date +%s)"
LAST="\$(cat "\${LAST_FULL}" 2>/dev/null || echo 0)"
if (( NOW - LAST >= FULL_SECS )); then
  echo "\${NOW}" > "\${LAST_FULL}"
  exec bash "${SCRIPT_DIR}/daemon.sh" pipe-run full
else
  exec bash "${SCRIPT_DIR}/daemon.sh" pipe-run volatile
fi
WRAPPER
  chmod +x "${wrapper}"
  echo "${wrapper}"
}

# ── Install ───────────────────────────────────────────────────────────────────
cmd_install() {
  need_root; need_files
  mkdir -p "${LOG_DIR}"
  chmod +x "${COLLECTOR}"

  hdr "Installing mac_intel v5.0 (core inventory, Apple Silicon)"
  info "Full:     every ${FULL_HOURS}h"
  info "Volatile: every ${VOLATILE_MINS}min"
  info "Python3:  ${PYTHON3}"
  info "Homebrew: /opt/homebrew"

  local wrapper; wrapper="$(write_wrapper)"
  ok "Wrapper: ${wrapper}"

  local vol_secs=$(( VOLATILE_MINS * 60 ))
  launchctl bootout system "${WRAP_PLIST}" 2>/dev/null || true

  cat > "${WRAP_PLIST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${WRAP_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${wrapper}</string>
  </array>
  <key>StartInterval</key>
  <integer>${vol_secs}</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/daemon.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/daemon-err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>HOME</key>
    <string>/var/root</string>
  </dict>
  <key>Nice</key>
  <integer>10</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>ThrottleInterval</key>
  <integer>30</integer>
</dict>
</plist>
PLIST

  chown root:wheel "${WRAP_PLIST}"
  chmod 644 "${WRAP_PLIST}"
  launchctl bootstrap system "${WRAP_PLIST}"
  ok "Loaded: ${WRAP_LABEL}"
  echo
  ok "Done. First collection starting now."
  echo "  sudo bash daemon.sh status"
  echo "  sudo bash daemon.sh report"
}

cmd_uninstall() {
  need_root; hdr "Uninstalling"
  launchctl bootout system "${WRAP_PLIST}" 2>/dev/null && ok "Unloaded" || warn "Was not loaded"
  [[ -f "${WRAP_PLIST}" ]] && rm -f "${WRAP_PLIST}" && ok "Removed plist"
  [[ -p "${FIFO}" ]] && rm -f "${FIFO}" && ok "Removed FIFO"
  warn "Data preserved: ${SCRIPT_DIR}"
}

# ── Status (ARM-enhanced) ─────────────────────────────────────────────────────
cmd_status() {
  hdr "Status — Apple Silicon"

  local info_out pid lx
  info_out="$(launchctl list "${WRAP_LABEL}" 2>/dev/null || echo '')"
  if [[ -n "${info_out}" ]]; then
    pid="$("${PYTHON3}" -c "import sys,json; d=json.load(sys.stdin); print(d.get('PID','idle'))" <<< "${info_out}" 2>/dev/null || echo 'idle')"
    lx="$("${PYTHON3}" -c "import sys,json; d=json.load(sys.stdin); print(d.get('LastExitStatus',0))" <<< "${info_out}" 2>/dev/null || echo '0')"
    ok "${WRAP_LABEL}  PID=${pid}  LastExit=${lx}"
  else
    warn "${WRAP_LABEL} — NOT LOADED"
  fi

  # Last full timing
  local last now
  last="$(cat "${LAST_FULL_FILE}" 2>/dev/null || echo 0)"
  now="$(date +%s)"
  if [[ "${last}" -gt 0 ]]; then
    local next=$(( last + FULL_HOURS * 3600 - now ))
    info "Last full: $(date -r "${last}" 2>/dev/null || echo '?')"
    [[ ${next} -gt 0 ]] && info "Next full: in $((next/60))min" || info "Next full: OVERDUE"
  fi

  echo
  # Latest snapshot: host / OS / chip (core inventory)
  if [[ -f "${DB}" ]]; then
    local db_sz chip_name host osv
    db_sz="$(du -h "${DB}" 2>/dev/null | awk '{print $1}')"
    chip_name="$("${PYTHON3}" -c "
import sqlite3,sys
try:
  db=sqlite3.connect('${DB}')
  r=db.execute(\"SELECT chip_name FROM snapshots ORDER BY epoch DESC LIMIT 1\").fetchone()
  print(r[0] if r else '')
except: print('')
" 2>/dev/null)"
    host="$("${PYTHON3}" -c "
import sqlite3
try:
  db=sqlite3.connect('${DB}')
  snap=db.execute('SELECT id FROM snapshots ORDER BY epoch DESC LIMIT 1').fetchone()
  if snap:
    r=db.execute(\"SELECT value FROM fields WHERE snapshot_id=? AND path='identity.hostname' LIMIT 1\",(snap[0],)).fetchone()
    print(r[0] if r else '')
except: print('')
" 2>/dev/null)"
    osv="$("${PYTHON3}" -c "
import sqlite3
try:
  db=sqlite3.connect('${DB}')
  snap=db.execute('SELECT id FROM snapshots ORDER BY epoch DESC LIMIT 1').fetchone()
  if snap:
    r=db.execute(\"SELECT value FROM fields WHERE snapshot_id=? AND path='identity.os_version' LIMIT 1\",(snap[0],)).fetchone()
    print(r[0] if r else '')
except: print('')
" 2>/dev/null)"

    info "Database: ${DB} (${db_sz})"
    info "Host:     ${host:-unknown}"
    info "macOS:    ${osv:-unknown}"
    info "Chip:     ${chip_name:-unknown}"
    echo
    "${PYTHON3}" "${STORAGE}" --stats --db "${DB}" 2>/dev/null || true
  else
    warn "No database yet. Run: sudo bash daemon.sh run-once full"
  fi

  echo
  info "Logs:"
  for f in "${LOG_DIR}"/*.log; do
    [[ -f "${f}" ]] || continue
    sz="$(du -h "${f}" 2>/dev/null | awk '{print $1}')"
    mt="$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "${f}" 2>/dev/null || echo '?')"
    echo "  ${f} (${sz}, ${mt})"
  done
}

# ── Run-once ──────────────────────────────────────────────────────────────────
cmd_run_once() {
  need_root
  local mode="${ARGS[0]:-full}"
  info "run-once: mode=${mode}"
  pipe_run "${mode}"
}

# ── Analysis shims ────────────────────────────────────────────────────────────
need_db() { [[ -f "${DB}" ]] || { warn "No database. Run: run-once full"; exit 1; }; }

cmd_report()   { need_db; "${PYTHON3}" "${STORAGE}" --report              --db "${DB}"; }
cmd_risks()    { need_db; "${PYTHON3}" "${STORAGE}" --risks "${ARGS[0]:-}" --db "${DB}"; }
cmd_timeline() { need_db
  [[ -n "${ARGS[0]:-}" ]] || { err "Usage: timeline <field.path>"; exit 1; }
  "${PYTHON3}" "${STORAGE}" --timeline "${ARGS[0]}" --db "${DB}"; }
cmd_search()   { need_db
  [[ -n "${ARGS[0]:-}" ]] || { err "Usage: search <keyword>"; exit 1; }
  "${PYTHON3}" "${STORAGE}" --search   "${ARGS[0]}" --db "${DB}"; }
cmd_stats()    { need_db; "${PYTHON3}" "${STORAGE}" --stats               --db "${DB}"; }

cmd_rotatelog() {
  need_root
  for f in "${LOG_DIR}"/*.log; do
    [[ -f "${f}" ]] || continue
    sz=$(stat -f '%z' "${f}" 2>/dev/null || echo 0)
    (( sz > 52428800 )) && mv "${f}" "${f}.$(date +%Y%m%d).bak" && : > "${f}" && ok "Rotated: ${f}"
  done
}

# ── Help ──────────────────────────────────────────────────────────────────────
cmd_help() {
  cat <<HELP

${BOLD}mac_intel daemon v5.0 — core inventory (Apple Silicon)${N}

${BOLD}INSTALL${N}
  sudo bash daemon.sh install [--full-hours N] [--volatile-mins N]
  sudo bash daemon.sh uninstall
  sudo bash daemon.sh status

${BOLD}COLLECTION${N}
  sudo bash daemon.sh run-once [full|volatile|quick]
      full     = identity + packages + network + processes + services (~30–90s)
      volatile = live network sockets + process list (~5–15s)
      quick    = identity + packages only (no lsof/ps load)

${BOLD}ANALYSIS${N}
  sudo bash daemon.sh report
  sudo bash daemon.sh risks [CRITICAL|HIGH|MEDIUM]
  sudo bash daemon.sh timeline <field.path>
  sudo bash daemon.sh search <keyword>
  sudo bash daemon.sh stats

${BOLD}EXAMPLE TIMELINES${N}
  sudo bash daemon.sh timeline identity.os_version
  sudo bash daemon.sh timeline identity.chip_name
  sudo bash daemon.sh timeline packages.python
  sudo bash daemon.sh timeline network.listening

${BOLD}USEFUL SQLITE QUERIES${N}
  # Latest pip-style package list (JSON)
  sqlite3 "${DB}" "SELECT f.value FROM fields f JOIN snapshots s ON f.snapshot_id=s.id WHERE f.path='packages.python' ORDER BY s.epoch DESC LIMIT 1"

  # Listening ports snapshot (JSON)
  sqlite3 "${DB}" "SELECT f.value FROM fields f JOIN snapshots s ON f.snapshot_id=s.id WHERE f.path='network.listening' ORDER BY s.epoch DESC LIMIT 1"

  # launchd jobs (JSON)
  sqlite3 "${DB}" "SELECT f.value FROM fields f JOIN snapshots s ON f.snapshot_id=s.id WHERE f.path='services.launchctl_list' ORDER BY s.epoch DESC LIMIT 1"

${BOLD}PIPE MODE (no disk JSON)${N}
  mkfifo /tmp/intel.fifo
  bash collector.sh --mode full --pipe /tmp/intel.fifo &
  python3 storage.py --ingest /tmp/intel.fifo

${BOLD}PATHS${N}
  Scripts:  ${SCRIPT_DIR}
  Database: ${DB}
  Python3:  ${PYTHON3}
  Homebrew: /opt/homebrew
  FIFO:     ${FIFO}
  Logs:     ${LOG_DIR}
HELP
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "${CMD}" in
  install)    cmd_install ;;
  uninstall)  cmd_uninstall ;;
  status)     cmd_status ;;
  run-once)   cmd_run_once ;;
  pipe-run)   pipe_run "${ARGS[0]:-volatile}" ;;
  report)     cmd_report ;;
  risks)      cmd_risks ;;
  timeline)   cmd_timeline ;;
  search)     cmd_search ;;
  stats)      cmd_stats ;;
  rotatelog)  cmd_rotatelog ;;
  help|--help|-h) cmd_help ;;
  *) err "Unknown: ${CMD}"; cmd_help; exit 1 ;;
esac
