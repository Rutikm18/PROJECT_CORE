#!/usr/bin/env bash
# =============================================================================
# mac_intel collector — v5.0 CORE INVENTORY (Apple Silicon)
#
# Collects ground-truth operational data only:
#   • Host / OS / hardware summary
#   • Installed packages (Mac apps, Homebrew, pip, npm, Ruby gems)
#   • Listening and established network sockets
#   • Running processes
#   • Services (launchd jobs + LaunchDaemon/LaunchAgent plists)
#
# Portable on macOS: uses python3 + to_json_array (no GNU paste / gawk).
# =============================================================================

set -uo pipefail

readonly VERSION="5.0.0-core"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly EPOCH="$(date +%s)"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly LOCK_FILE="/tmp/mac_intel_collector.lock"

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

MODE="full"
PIPE_OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --pipe) PIPE_OUT="$2"; shift 2 ;;
    --help) echo "Usage: sudo bash collector.sh [--mode full|volatile|quick] [--pipe /path/fifo]"; exit 0 ;;
    *) shift ;;
  esac
done

if [[ -f "${LOCK_FILE}" ]]; then
  existing_pid="$(cat "${LOCK_FILE}" 2>/dev/null)"
  if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" 2>/dev/null; then
    echo "Another collection is already running (pid=${existing_pid}). Exiting." >&2
    exit 0
  fi
  rm -f "${LOCK_FILE}"
fi
printf '%s' "$$" > "${LOCK_FILE}"
trap 'rm -f "${LOCK_FILE}"' EXIT

WORK="$(mktemp -d /tmp/mac_intel_XXXXXX)"
trap 'rm -rf "${WORK}"; rm -f "${LOCK_FILE}"' EXIT

CONSOLE_USER="$(stat -f '%Su' /dev/console 2>/dev/null || echo "${SUDO_USER:-$USER}")"
CONSOLE_HOME="$(eval echo "~${CONSOLE_USER}" 2>/dev/null || echo "/Users/${CONSOLE_USER}")"
readonly CONSOLE_USER CONSOLE_HOME

LOG="${WORK}/collector.log"
log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" >> "${LOG}" 2>&1; }
log "v${VERSION} | mode=${MODE} | pid=$$ | user=${CONSOLE_USER}"

q()  { "$@" 2>/dev/null || true; }
cmd_exists() { command -v "$1" &>/dev/null; }

jstr() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  printf '"%s"' "${s}"
}

write_domain() { printf '%s' "$2" > "${WORK}/$1.dom"; }

to_json_array() { python3 -c "import sys; d=[l.rstrip() for l in sys.stdin if l.strip()]; print('['+','.join(d)+']')"; }
jcat() { local f="$1" def="${2:-[]}"; [[ -s "$f" ]] && cat "$f" 2>/dev/null || printf '%s' "$def"; }

# ═══════════════════════════════════════════════════════════════════════════════
#  IDENTITY — hostname, OS, chip (no system_profiler cache required)
# ═══════════════════════════════════════════════════════════════════════════════
dom_identity() {
  local h os_name os_ver os_build kern arch chip ram
  h="$(q hostname)"
  os_name="$(q sw_vers -productName)"
  os_ver="$(q sw_vers -productVersion)"
  os_build="$(q sw_vers -buildVersion)"
  kern="$(q uname -r)"
  arch="$(q uname -m)"
  chip="$(q sysctl -n machdep.cpu.brand_string)"
  ram="$(q sysctl -n hw.memsize | awk '{printf "%.1f", $1/1073741824}')"

  write_domain "identity" "{
\"hostname\":$(jstr "${h}"),
\"os_name\":$(jstr "${os_name}"),
\"os_version\":$(jstr "${os_ver}"),
\"os_build\":$(jstr "${os_build}"),
\"kernel\":$(jstr "${kern}"),
\"arch\":$(jstr "${arch}"),
\"chip_name\":$(jstr "${chip}"),
\"ram_gb\":$(jstr "${ram}")
}"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PACKAGES — Mac apps + Homebrew + pip + npm + gems
# ═══════════════════════════════════════════════════════════════════════════════
dom_packages() {
  local apps mac_json brew_pkgs brew_casks py_json npm_json gems_json
  mac_json="[]"
  if apps="$(q system_profiler SPApplicationsDataType -json 2>/dev/null)"; then
    mac_json="$(printf '%s' "${apps}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    rows = []
    for a in d.get('SPApplicationsDataType', [])[:500]:
        rows.append({
            'n': a.get('_name', ''),
            'v': a.get('version', ''),
            'path': a.get('path', ''),
            'src': a.get('obtained_from', ''),
        })
    print(json.dumps(rows, separators=(',', ':')))
except Exception:
    print('[]')
")"
  fi

  local BREW="/opt/homebrew/bin/brew"
  [[ -x "${BREW}" ]] || BREW="brew"
  brew_pkgs="[]"
  brew_casks="[]"
  if cmd_exists "${BREW}"; then
    { q "${BREW}" list --versions 2>/dev/null | \
        awk '{n=$1;$1="";gsub(/^ /,""); printf "{\"n\":\"%s\",\"v\":\"%s\"}\n",n,$0}' | \
        head -300 | to_json_array > "${WORK}/brew_f.json"; } &
    { q "${BREW}" list --cask --versions 2>/dev/null | \
        awk '{n=$1;$1="";gsub(/^ /,""); printf "{\"n\":\"%s\",\"v\":\"%s\"}\n",n,$0}' | \
        head -200 | to_json_array > "${WORK}/brew_c.json"; } &
    wait
    brew_pkgs="$(jcat "${WORK}/brew_f.json")"
    brew_casks="$(jcat "${WORK}/brew_c.json")"
  fi

  { q /opt/homebrew/bin/pip3 list --format=json 2>/dev/null || q pip3 list --format=json 2>/dev/null || echo "[]"; } | head -c 80000 > "${WORK}/py.json" &
  { q npm list -g --depth=0 --json 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    deps = d.get('dependencies') or {}
    out = [{'n': k, 'v': (v or {}).get('version', '')} for k, v in list(deps.items())[:200]]
    print(json.dumps(out, separators=(',', ':')))
except Exception:
    print('[]')
" 2>/dev/null || echo "[]"; } > "${WORK}/npm.json" &
  { q gem list 2>/dev/null | python3 -c "
import sys, json, re
rows = []
for line in sys.stdin:
    line = line.strip()
    m = re.match(r'^(\S+)\s+\(([^)]+)\)', line)
    if m:
        rows.append({'n': m.group(1), 'v': m.group(2)})
    if len(rows) >= 150:
        break
print(json.dumps(rows, separators=(',', ':')))
" 2>/dev/null || echo "[]"; } > "${WORK}/gems.json" &
  wait

  py_json="$(jcat "${WORK}/py.json" "[]")"
  npm_json="$(jcat "${WORK}/npm.json")"
  gems_json="$(jcat "${WORK}/gems.json")"

  write_domain "packages" "{
\"mac_apps\":${mac_json},
\"brew\":${brew_pkgs},
\"brew_casks\":${brew_casks},
\"python\":${py_json},
\"npm\":${npm_json},
\"gems\":${gems_json}
}"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK — listening + established TCP/UDP sockets (lsof)
# ═══════════════════════════════════════════════════════════════════════════════
dom_network() {
  local listening established
  listening="$(python3 <<'PY'
import subprocess, json
try:
    p = subprocess.run(
        ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
        capture_output=True, text=True, timeout=120, errors="replace",
    )
    rows = []
    for line in (p.stdout or "").splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 3:
            continue
        proc, pid = parts[0], parts[1]
        tail = parts[-1] if len(parts) > 8 else line
        rows.append({"proc": proc, "pid": pid, "name": tail.strip()})
    print(json.dumps(rows[:400], separators=(",", ":")))
except Exception:
    print("[]")
PY
)"
  established="$(python3 - <<'PY'
import subprocess, json
try:
    p = subprocess.run(
        ["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"],
        capture_output=True, text=True, timeout=120, errors="replace",
    )
    rows = []
    for line in (p.stdout or "").splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 3:
            continue
        proc, pid = parts[0], parts[1]
        tail = parts[-1] if len(parts) > 8 else line
        rows.append({"proc": proc, "pid": pid, "name": tail.strip()})
    print(json.dumps(rows[:500], separators=(",", ":")))
except Exception:
    print("[]")
PY
)"

  write_domain "network" "{
\"listening\":${listening},
\"established\":${established}
}"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PROCESSES — full ps snapshot (JSON-safe)
# ═══════════════════════════════════════════════════════════════════════════════
dom_processes() {
  local running
  running="$(python3 - <<PY
import subprocess, json
try:
    out = subprocess.check_output(
        ["ps", "-axo", "pid=,user=,pcpu=,pmem=,rss=,comm=,args="],
        text=True, errors="replace", timeout=60,
    )
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        pid, user, pcpu, pmem, rss, comm, args = parts
        rows.append({
            "pid": pid.strip(),
            "user": user.strip(),
            "pcpu": pcpu.strip(),
            "pmem": pmem.strip(),
            "rss": rss.strip(),
            "comm": comm.strip(),
            "args": args[:2000],
        })
        if len(rows) >= 400:
            break
    print(json.dumps(rows, separators=(",", ":")))
except Exception as e:
    print(json.dumps([{"error": str(e)}], separators=(",", ":")))
PY
)"

  write_domain "processes" "{
\"running\":${running}
}"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SERVICES — launchd + plist inventory
# ═══════════════════════════════════════════════════════════════════════════════
dom_services() {
  local launchd_json plist_json
  launchd_json="$(python3 - <<PY
import subprocess, json
try:
    p = subprocess.run(
        ["launchctl", "list"],
        capture_output=True, text=True, timeout=90, errors="replace",
    )
    rows = []
    for line in (p.stdout or "").splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, status, label = parts[0], parts[1], parts[2]
        rows.append({"pid": pid, "status": status, "label": label})
    print(json.dumps(rows[:500], separators=(",", ":")))
except Exception:
    print("[]")
PY
)"

  plist_json="$(python3 - "${CONSOLE_HOME}" <<'PY'
import glob, json, os, sys
home = sys.argv[1]
paths = []
for pat in (
    "/Library/LaunchDaemons/*.plist",
    "/Library/LaunchAgents/*.plist",
    os.path.join(home, "Library/LaunchAgents/*.plist"),
):
    paths.extend(glob.glob(pat))
rows = [{"path": p} for p in sorted(set(paths))[:600]]
print(json.dumps(rows, separators=(",", ":")))
PY
)"

  write_domain "services" "{
\"launchctl_list\":${launchd_json},
\"launch_plists\":${plist_json}
}"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  DISPATCH
# ═══════════════════════════════════════════════════════════════════════════════
dispatch() {
  log "Dispatching mode=${MODE}"
  case "${MODE}" in
    full)
      DOMAINS=(identity packages network processes services) ;;
    volatile)
      DOMAINS=(network processes) ;;
    quick)
      DOMAINS=(identity packages) ;;
    *)
      log "Unknown mode: ${MODE}"; exit 1 ;;
  esac

  local pids=()
  for dom in "${DOMAINS[@]}"; do
    log "  Starting: ${dom}"
    ( "dom_${dom}" ) &
    pids+=($!)
  done

  local failed=0
  for pid in "${pids[@]}"; do
    wait "${pid}" || { log "  [WARN] Domain job failed (pid=${pid})"; ((failed++)) || true; }
  done
  log "All domains complete. Failures: ${failed}"
}

assemble() {
  python3 - "${WORK}" "${VERSION}" "${MODE}" "${EPOCH}" "${TIMESTAMP}" "${CONSOLE_USER}" <<'PY'
import os, sys, json

work, version, mode, epoch, ts, user = sys.argv[1:]

doc = {
    "meta": {
        "collector_version": version,
        "mode": mode,
        "arch": "apple_silicon",
        "epoch": int(epoch),
        "timestamp_utc": ts,
        "console_user": user,
    }
}

for fname in sorted(os.listdir(work)):
    if not fname.endswith('.dom'):
        continue
    try:
        with open(os.path.join(work, fname)) as f:
            doc[fname[:-4]] = json.load(f)
    except Exception as e:
        doc[fname[:-4]] = {"error": str(e)}

json.dump(doc, sys.stdout, separators=(',', ':'), default=str)
sys.stdout.flush()
PY
}

log "Starting collection"
dispatch
log "Assembling JSON"

if [[ -n "${PIPE_OUT}" ]]; then
  assemble > "${PIPE_OUT}"
  log "Written to: ${PIPE_OUT}"
  cp "${LOG}" "$(dirname "${PIPE_OUT}")/collector.log" 2>/dev/null || true
else
  assemble
fi

log "Done. Elapsed: $(($(date +%s) - EPOCH))s"
