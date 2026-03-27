#!/usr/bin/env bash
# =============================================================================
#  watch.sh — macOS Live Section Monitor
#
#  Each section runs on its own cadence. The main loop ticks every few seconds
#  and fires a section only when its interval has elapsed.
#
#  GLOBAL ENV VARS:
#    WATCH_TICK        main poll interval in seconds        (default: 5)
#    WATCH_SECTIONS    comma-separated section names        (default: all)
#    WATCH_DIFF_ONLY   1 = show only changed lines          (default: 0)
#    WATCH_LOG         1 = append each run to log files     (default: 1)
#    WATCH_TOP_N       max rows in process/port tables      (default: 40)
#
#  PER-SECTION INTERVAL OVERRIDE:
#    WATCH_INTERVAL_<SECTION>=<seconds>
#    e.g.  WATCH_INTERVAL_PORTS=15  WATCH_INTERVAL_METRICS=5
#
#  SECTIONS + DEFAULT INTERVALS (based on criticality):
#    CRITICAL  (5–10 s)    : metrics, connections, processes
#    CRITICAL  (30–60 s)   : ports
#    HIGH      (1–5 min)   : network, openfiles, services, users,
#                            hardware, containers, power, arp, mounts, battery
#    HIGH      (10–30 min) : storage, tasks
#    HIGH      (hourly)    : security, sysctl, configs
#    LOW       (daily)     : apps, packages, binaries
#
#  USAGE:
#    sudo bash watch.sh
#    WATCH_TICK=3 sudo bash watch.sh
#    WATCH_SECTIONS=metrics,ports,connections sudo bash watch.sh
#    WATCH_INTERVAL_METRICS=5 WATCH_INTERVAL_PORTS=20 sudo bash watch.sh
#    WATCH_DIFF_ONLY=1 WATCH_SECTIONS=security,configs,tasks sudo bash watch.sh
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs/watch"
STATE_DIR="${SCRIPT_DIR}/.watch_state"
mkdir -p "${LOG_DIR}" "${STATE_DIR}"

# ── Global config ─────────────────────────────────────────────────────────────
TICK="${WATCH_TICK:-5}"
SECTIONS="${WATCH_SECTIONS:-metrics,connections,processes,ports,network,openfiles,services,users,hardware,containers,power,arp,mounts,battery,storage,tasks,security,sysctl,configs,apps,packages,binaries}"
DIFF_ONLY="${WATCH_DIFF_ONLY:-0}"
DO_LOG="${WATCH_LOG:-1}"
TOP_N="${WATCH_TOP_N:-40}"

IS_ROOT=false; [[ "$(id -u)" == "0" ]] && IS_ROOT=true
CONSOLE_USER="$(stat -f '%Su' /dev/console 2>/dev/null || echo "${SUDO_USER:-$USER}")"
CONSOLE_HOME="$(eval echo "~${CONSOLE_USER}" 2>/dev/null || echo "/Users/${CONSOLE_USER}")"
TOTAL_RUNS=0

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m';    DIM='\033[2m'; N='\033[0m'
MAG='\033[0;35m'

# ── Helpers ───────────────────────────────────────────────────────────────────
q()      { "$@" 2>/dev/null || true; }
cmd_ok() { command -v "$1" &>/dev/null; }
now()    { date +%s; }

# ── Per-section default intervals (seconds) ───────────────────────────────────
declare -A DEFAULT_INTERVAL=(
    # Critical — seconds
    [metrics]=10        [connections]=10    [processes]=10
    [ports]=30
    # High — 1-5 min
    [network]=120       [openfiles]=120     [services]=120
    [users]=120         [hardware]=120      [containers]=120
    [power]=120         [arp]=120           [mounts]=120
    [battery]=120
    # High — 10-30 min
    [storage]=600       [tasks]=600
    # High — hourly / on-change
    [security]=3600     [sysctl]=3600       [configs]=3600
    # Low — daily
    [apps]=86400        [packages]=86400    [binaries]=86400
)

# ── Section metadata ──────────────────────────────────────────────────────────
declare -A TITLES=(
    [metrics]="DYNAMIC METRICS  (CPU / MEM / NET / DISK deltas)"
    [connections]="ACTIVE CONNECTIONS  (ESTABLISHED)"
    [processes]="RUNNING PROCESSES"
    [ports]="OPEN PORTS  (LISTENING)"
    [network]="NETWORK INTERFACES"
    [openfiles]="OPEN FILES  (by process)"
    [services]="LAUNCHD SERVICES  (daemons + agents)"
    [users]="USERS  (accounts / sudoers / login history)"
    [hardware]="CONNECTED HARDWARE  (USB / BT)"
    [containers]="CONTAINERS  (Docker / Podman)"
    [power]="POWER MANAGEMENT"
    [arp]="ARP TABLE"
    [mounts]="ACTIVE MOUNTS"
    [battery]="BATTERY"
    [storage]="STORAGE  (filesystems + disk usage)"
    [tasks]="SCHEDULED TASKS  (cron + launchd timers)"
    [security]="SECURITY CONFIG  (SIP / Firewall / FileVault)"
    [sysctl]="SYSCTL  (kernel / network params)"
    [configs]="CONFIG FILES  (SSH / shell / hosts)"
    [apps]="INSTALLED APPS"
    [packages]="PACKAGE MANAGERS  (brew / pip / npm / gems)"
    [binaries]="BINARIES  (PATH inventory)"
)

declare -A CRITICALITY=(
    [metrics]="CRITICAL" [connections]="CRITICAL" [processes]="CRITICAL"
    [ports]="CRITICAL"
    [network]="HIGH"     [openfiles]="HIGH"        [services]="HIGH"
    [users]="HIGH"       [hardware]="HIGH"          [containers]="HIGH"
    [power]="HIGH"       [arp]="HIGH"               [mounts]="HIGH"
    [battery]="HIGH"     [storage]="HIGH"            [tasks]="HIGH"
    [security]="HIGH"    [sysctl]="HIGH"             [configs]="HIGH"
    [apps]="LOW"         [packages]="LOW"            [binaries]="LOW"
)

# ── Resolve per-section interval (env override or default) ────────────────────
declare -A INTERVAL
for sec in "${!DEFAULT_INTERVAL[@]}"; do
    env_key="WATCH_INTERVAL_${sec^^}"
    INTERVAL[${sec}]="${!env_key:-${DEFAULT_INTERVAL[${sec}]}}"
done

# ── Last-run timestamps (0 = never run → run immediately) ────────────────────
declare -A LAST_RUN
for sec in "${!DEFAULT_INTERVAL[@]}"; do LAST_RUN[${sec}]=0; done

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION COLLECTORS
# ─────────────────────────────────────────────────────────────────────────────

collect_metrics() {
    # CPU
    local cpu_line
    cpu_line="$(top -l 2 -n 0 2>/dev/null | grep 'CPU usage' | tail -1)"
    printf 'CPU        %s\n' "${cpu_line}"

    # Load
    printf 'Load       %s\n' "$(sysctl -n vm.loadavg 2>/dev/null)"

    # Memory
    vm_stat 2>/dev/null | awk '
      /Pages free/       {free=$3}
      /Pages active/     {act=$3}
      /Pages wired/      {wired=$4}
      /Pages compressed/ {comp=$3}
      END {
        p=4096/1073741824
        printf "Mem Free   %.2f GB\n", free*p
        printf "Mem Active %.2f GB\n", act*p
        printf "Mem Wired  %.2f GB\n", wired*p
        printf "Mem Compr  %.2f GB\n", comp*p
      }'

    # Swap
    sysctl -n vm.swapusage 2>/dev/null | \
        awk '{printf "Swap       total=%-10s used=%-10s free=%s\n",$3,$6,$9}'

    # Network bytes (delta requires two samples — show current counters)
    printf '\nNetstat interface stats:\n'
    netstat -ib 2>/dev/null | awk '
      NR==1 {print "  " $0; next}
      /^en|^utun|^lo/ {printf "  %-12s in=%-14s out=%s\n", $1, $7, $10}
    ' | head -12

    # Disk I/O
    printf '\nDisk I/O (iostat):\n'
    iostat -d 2>/dev/null | awk 'NR>2{printf "  %-12s KB/t=%-8s tps=%-8s MB/s=%s\n",$1,$2,$3,$4}' | head -6
}

collect_connections() {
    if ${IS_ROOT}; then
        lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | tail -n +2 | \
            awk '{printf "%-22s %-7s %s\n", $1, $2, $NF}' | sort | head -"${TOP_N}"
    else
        netstat -an 2>/dev/null | grep ESTABLISHED | \
            awk '{printf "%-45s -> %s\n", $4, $5}' | sort | head -"${TOP_N}"
    fi
}

collect_processes() {
    ps -axo pid=,user=,pcpu=,pmem=,rss=,comm= 2>/dev/null | \
        sort -k3 -rn | head -"${TOP_N}" | \
        awk '{printf "%-7s %-18s cpu=%-6s mem=%-6s rss=%-9s %s\n",$1,$2,$3,$4,$5,$6}'
}

collect_ports() {
    if ${IS_ROOT}; then
        lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2 | \
            awk '{printf "%-22s pid=%-7s TCP  %s\n", $1, $2, $NF}' | sort | head -"${TOP_N}"
        lsof -nP -iUDP 2>/dev/null | tail -n +2 | \
            awk '{printf "%-22s pid=%-7s UDP  %s\n", $1, $2, $NF}' | sort | head -20
    else
        netstat -an 2>/dev/null | grep LISTEN | \
            awk '{printf "%-50s %s\n", $4, $1}' | sort | head -"${TOP_N}"
    fi
}

collect_network() {
    ifconfig 2>/dev/null | awk '
        /^[a-z]/ {
            if(iface && (ip4||mac))
                printf "%-12s ip4=%-20s ip6=%-38s mac=%-20s %s\n",iface,ip4,ip6,mac,status
            iface=substr($1,1,length($1)-1); mac=""; ip4=""; ip6=""; status=($0~/UP/)?"UP":"DOWN"
        }
        /ether /           { mac=$2 }
        /inet / && !/inet6/{ ip4=$2 }
        /inet6 /           { ip6=$2 }
        END {
            if(iface && (ip4||mac))
                printf "%-12s ip4=%-20s ip6=%-38s mac=%-20s %s\n",iface,ip4,ip6,mac,status
        }'
    printf '\nDNS: '
    scutil --dns 2>/dev/null | awk '/nameserver/{print $3}' | sort -u | tr '\n' ' '
    printf '\nRoutes:\n'
    netstat -rn 2>/dev/null | grep -E '^(default|0\.0\.0\.0)' | awk '{printf "  %-20s gw=%-20s iface=%s\n",$1,$2,$6}'
}

collect_openfiles() {
    if ${IS_ROOT}; then
        lsof 2>/dev/null | \
            awk 'NR>1{c[$2" "$1]++} END{for(k in c) print c[k], k}' | \
            sort -rn | head -"${TOP_N}" | \
            awk '{printf "pid=%-7s %-22s %s fds\n", $2, $3, $1}'
    else
        echo "(sudo required)"
    fi
}

collect_services() {
    printf 'RUNNING DAEMONS:\n'
    launchctl list 2>/dev/null | awk '$1 != "-" {printf "  pid=%-7s exit=%-5s %s\n",$1,$2,$3}' | head -60
    printf '\nALL LOADED (inc. stopped):\n'
    launchctl list 2>/dev/null | awk '{printf "  %-7s %-5s %s\n",$1,$2,$3}' | head -100
    printf '\nLaunchDaemons:\n'
    ls /Library/LaunchDaemons/ 2>/dev/null | awk '{print "  " $0}' | head -40
    printf 'LaunchAgents:\n'
    ls /Library/LaunchAgents/ 2>/dev/null | awk '{print "  " $0}' | head -40
    printf 'User LaunchAgents:\n'
    ls "${CONSOLE_HOME}/Library/LaunchAgents/" 2>/dev/null | awk '{print "  " $0}' || echo "  (none)"
}

collect_users() {
    printf 'LOCAL USERS:\n'
    dscl . list /Users 2>/dev/null | grep -v '^_' | while IFS= read -r u; do
        uid=$(q dscl . read /Users/"${u}" UniqueID 2>/dev/null | awk '{print $2}')
        shell=$(q dscl . read /Users/"${u}" UserShell 2>/dev/null | awk '{print $2}')
        printf '  %-20s uid=%-6s shell=%s\n' "${u}" "${uid}" "${shell}"
    done
    printf '\nADMINS:\n'
    q dscl . read /Groups/admin GroupMembership 2>/dev/null | \
        awk '{for(i=2;i<=NF;i++) print "  " $i}'
    printf '\nLOGGED IN NOW:\n'
    who | awk '{print "  " $0}'
    printf '\nLAST LOGINS (10):\n'
    last 2>/dev/null | head -10 | awk '{print "  " $0}'
    printf '\nSUDOERS:\n'
    if ${IS_ROOT}; then
        grep -v '^#\|^$' /etc/sudoers 2>/dev/null | sed 's/^/  /'
        ls /etc/sudoers.d/ 2>/dev/null | awk '{print "  sudoers.d/" $0}'
    else
        echo "  (sudo required)"
    fi
}

collect_hardware() {
    printf 'USB:\n'
    system_profiler SPUSBDataType 2>/dev/null | \
        grep -E '^\s{4}[A-Z]|Product ID|Vendor ID|Speed|Manufacturer' | \
        sed 's/^[[:space:]]*/  /' | head -40
    printf '\nBLUETOOTH:\n'
    system_profiler SPBluetoothDataType 2>/dev/null | \
        grep -E 'Device Name|Address|Connected|RSSI' | \
        sed 's/^[[:space:]]*/  /' | head -30
    printf '\nTHUNDERBOLT:\n'
    system_profiler SPThunderboltDataType 2>/dev/null | \
        grep -E 'Device Name|Vendor|Status|Speed' | \
        sed 's/^[[:space:]]*/  /' | head -20
}

collect_containers() {
    if cmd_ok docker && docker info &>/dev/null 2>&1; then
        printf 'RUNNING:\n'
        docker ps --format '  {{.ID}}  {{.Image}}  {{.Status}}  {{.Ports}}  {{.Names}}' 2>/dev/null
        printf '\nALL:\n'
        docker ps -a --format '  {{.ID}}  {{.Image}}  {{.Status}}  {{.Names}}' 2>/dev/null | head -30
        printf '\nIMAGES:\n'
        docker images --format '  {{.Repository}}:{{.Tag}}  {{.Size}}  {{.ID}}' 2>/dev/null | head -20
    else
        echo "  docker not running / not installed"
    fi
    if cmd_ok podman; then
        printf '\nPODMAN:\n'
        podman ps -a --format '  {{.ID}} {{.Image}} {{.Status}} {{.Names}}' 2>/dev/null | head -10
    fi
    printf '\nVMs:\n'
    printf '  VMware:  %s running\n' "$(pgrep -x vmware-vmx  2>/dev/null | wc -l | xargs)"
    printf '  Parallels: %s running\n' "$(pgrep -x prl_vm_app 2>/dev/null | wc -l | xargs)"
    printf '  UTM:     %s running\n' "$(pgrep -x QEMULauncher 2>/dev/null | wc -l | xargs)"
}

collect_power() {
    printf 'pmset -g:\n'
    pmset -g 2>/dev/null | sed 's/^/  /'
    printf '\nAssertions (blocking sleep):\n'
    pmset -g assertions 2>/dev/null | grep -vE '^Listed|^$|^No|pid 0' | sed 's/^/  /' | head -20
    printf '\nPower source:\n'
    pmset -g ps 2>/dev/null | sed 's/^/  /'
}

collect_arp() {
    arp -a 2>/dev/null | awk '{printf "  %-25s %-20s iface=%s\n", $2, $4, $6}'
}

collect_mounts() {
    mount 2>/dev/null | grep -vE '^(devfs|map )' | \
        awk '{printf "  %-30s on  %-35s (%s)\n", $1, $3, $5}'
}

collect_battery() {
    pmset -g batt 2>/dev/null | grep -E 'InternalBattery|Now drawing'
    system_profiler SPPowerDataType 2>/dev/null | \
        grep -E 'Cycle Count|Condition|Maximum Capacity|Charge Remaining|Charging:|Connected' | \
        sed 's/^[[:space:]]*/  /'
}

collect_storage() {
    printf 'FILESYSTEM USAGE:\n'
    df -h 2>/dev/null | awk '
        NR==1 {printf "  %-40s %-8s %-8s %-8s %-6s %s\n",$1,$2,$3,$4,$5,$6; next}
        {printf "  %-40s %-8s %-8s %-8s %-6s %s\n",$1,$2,$3,$4,$5,$6}'
    printf '\nDISK LIST:\n'
    diskutil list 2>/dev/null | sed 's/^/  /'
    printf '\nIOSTAT:\n'
    iostat -d 2>/dev/null | sed 's/^/  /'
}

collect_tasks() {
    printf 'USER CRONTAB:\n'
    crontab -l 2>/dev/null | grep -v '^#\|^$' | sed 's/^/  /' || echo "  (empty)"
    printf '\nSYSTEM CRONTAB:\n'
    [[ -f /etc/crontab ]] && grep -v '^#\|^$' /etc/crontab | sed 's/^/  /' || echo "  (none)"
    printf '\nPERIODIC SCRIPTS:\n'
    for d in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
        [[ -d "${d}" ]] && { printf '  %s:\n' "${d}"; ls "${d}" | awk '{print "    " $0}'; }
    done
    printf '\nLAUNCHD TIMERS:\n'
    grep -rl 'StartInterval\|StartCalendarInterval' \
        /Library/LaunchDaemons/ /Library/LaunchAgents/ \
        "${CONSOLE_HOME}/Library/LaunchAgents/" 2>/dev/null | \
    while IFS= read -r f; do
        interval=$(q defaults read "${f}" StartInterval 2>/dev/null)
        printf '  %-60s interval=%s\n' "$(basename "${f}")" "${interval:-calendar}"
    done
}

collect_security() {
    printf 'CORE STATUS:\n'
    printf '  %-35s %s\n' "SIP"            "$(q csrutil status | sed 's/System Integrity Protection status: //')"
    printf '  %-35s %s\n' "Gatekeeper"     "$(q spctl --status 2>/dev/null)"
    printf '  %-35s %s\n' "FileVault"      "$(q fdesetup status)"
    printf '  %-35s %s\n' "Secure Boot"    "$(q nvram security-mode 2>/dev/null | awk '{print $2}' || echo '—')"
    printf '  %-35s %s\n' "Dev Tools Sec"  "$(q DevToolsSecurity -status 2>/dev/null | head -1)"
    printf '  %-35s %s\n' "Remote Login"   "$(q systemsetup -getremotelogin 2>/dev/null | sed 's/Remote Login: //')"
    printf '  %-35s %s\n' "XProtect"       "$(q defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)"
    printf '  %-35s %s\n' "Screen Sharing" "$(launchctl list com.apple.screensharing 2>/dev/null | head -1 || echo stopped)"
    printf '\nFIREWALL:\n'
    printf '  %-35s %s\n' "App Firewall" \
        "$(q /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)"
    printf '  %-35s %s\n' "Stealth Mode" \
        "$(q /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode)"
    if ${IS_ROOT}; then
        printf '\npf rules:\n'
        pfctl -sr 2>/dev/null | sed 's/^/  /' || echo "  (none)"
    fi
    printf '\nTCC (Privacy DB) — last 20 changes:\n'
    if ${IS_ROOT}; then
        TCC_DB="/Library/Application Support/com.apple.TCC/TCC.db"
        [[ -f "${TCC_DB}" ]] && sqlite3 -separator $'\t' "${TCC_DB}" \
            "SELECT service,client,auth_value,datetime(last_modified,'unixepoch') FROM access ORDER BY last_modified DESC LIMIT 20" 2>/dev/null | \
            awk -F'\t' '{printf "  %-35s %-30s %-5s %s\n",$1,$2,$3,$4}' || echo "  TCC.db not found"
    else
        echo "  (sudo required)"
    fi
}

collect_sysctl() {
    sysctl -a 2>/dev/null | grep -E \
        'kern\.(bootargs|hostname|osversion|securelevel|maxfiles|maxproc)|
         hw\.(model|memsize|ncpu|physicalcpu|logicalcpu)|
         net\.inet\.(ip\.(forwarding|ttl)|tcp\.(mssdflt|keepidle)|icmp)|
         vm\.(loadavg|swapusage|compressor_mode)|
         security\.' | \
    awk -F': ' '{printf "  %-55s %s\n", $1, $2}'
}

collect_configs() {
    for f in \
        "${CONSOLE_HOME}/.zshrc"     \
        "${CONSOLE_HOME}/.bashrc"    \
        "${CONSOLE_HOME}/.zprofile"  \
        "${CONSOLE_HOME}/.bash_profile" \
        /etc/zshrc /etc/bashrc /etc/profile \
        "${CONSOLE_HOME}/.ssh/config" \
        /etc/hosts
    do
        [[ -f "${f}" ]] || continue
        printf '\n── %s ──\n' "${f}"
        grep -v '^#\|^$' "${f}" 2>/dev/null | sed 's/^/  /' | head -30
    done
    printf '\nSSH authorized_keys:\n'
    [[ -f "${CONSOLE_HOME}/.ssh/authorized_keys" ]] && \
        cat "${CONSOLE_HOME}/.ssh/authorized_keys" | sed 's/^/  /' || echo "  (none)"
}

collect_apps() {
    printf '/Applications:\n'
    ls -1 /Applications/ 2>/dev/null | awk '{print "  " $0}'
    printf '\n/System/Applications:\n'
    ls -1 /System/Applications/ 2>/dev/null | awk '{print "  " $0}'
}

collect_packages() {
    if cmd_ok brew; then
        printf 'HOMEBREW FORMULAE:\n'
        brew list --versions 2>/dev/null | awk '{printf "  %-35s %s\n", $1, $2}' | head -200
        printf '\nHOMEBREW CASKS:\n'
        brew list --cask --versions 2>/dev/null | awk '{printf "  %-35s %s\n", $1, $2}' | head -100
    fi
    if cmd_ok pip3; then
        printf '\nPIP3:\n'
        pip3 list --format=columns 2>/dev/null | tail -n +3 | \
            awk '{printf "  %-40s %s\n", $1, $2}' | head -100
    fi
    if cmd_ok npm; then
        printf '\nNPM GLOBAL:\n'
        npm list -g --depth=0 2>/dev/null | tail -n +2 | sed 's/[├└─│ ]*//' | \
            awk '{printf "  %s\n", $0}' | head -40
    fi
    if cmd_ok gem; then
        printf '\nRUBY GEMS:\n'
        gem list 2>/dev/null | awk '{printf "  %-35s %s\n", $1, $2}' | head -60
    fi
}

collect_binaries() {
    for dir in \
        /opt/homebrew/bin /opt/homebrew/sbin \
        /usr/local/bin /usr/local/sbin \
        "${CONSOLE_HOME}/.local/bin" \
        "${CONSOLE_HOME}/go/bin" \
        "${CONSOLE_HOME}/.cargo/bin"
    do
        [[ -d "${dir}" ]] || continue
        count=$(ls -1 "${dir}" 2>/dev/null | wc -l | xargs)
        printf '\n%s  (%s files):\n' "${dir}" "${count}"
        ls -1 "${dir}" 2>/dev/null | awk '{print "  " $0}' | head -100
    done
}

# ── Collector dispatch ────────────────────────────────────────────────────────
declare -A COLLECTORS=(
    [metrics]="collect_metrics"         [connections]="collect_connections"
    [processes]="collect_processes"     [ports]="collect_ports"
    [network]="collect_network"         [openfiles]="collect_openfiles"
    [services]="collect_services"       [users]="collect_users"
    [hardware]="collect_hardware"       [containers]="collect_containers"
    [power]="collect_power"             [arp]="collect_arp"
    [mounts]="collect_mounts"           [battery]="collect_battery"
    [storage]="collect_storage"         [tasks]="collect_tasks"
    [security]="collect_security"       [sysctl]="collect_sysctl"
    [configs]="collect_configs"         [apps]="collect_apps"
    [packages]="collect_packages"       [binaries]="collect_binaries"
)

# ── Parse & validate WATCH_SECTIONS ──────────────────────────────────────────
IFS=',' read -ra ACTIVE_SECTIONS <<< "${SECTIONS}"
for s in "${ACTIVE_SECTIONS[@]}"; do
    if [[ -z "${COLLECTORS[${s}]+x}" ]]; then
        printf '%bUnknown section: "%s". Valid: %s%b\n' \
            "${RED}" "${s}" "${!COLLECTORS[*]}" "${N}" >&2
        exit 1
    fi
done

# ── diff helper ───────────────────────────────────────────────────────────────
show_diff() {
    local prev="$1" curr="$2"
    if [[ ! -f "${prev}" ]]; then cat "${curr}" | sed 's/^/  /'; return; fi
    local changed=0
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        printf '%b  - %s%b\n' "${RED}" "${line}" "${N}"; changed=1
    done < <(comm -23 <(sort "${prev}") <(sort "${curr}"))
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        printf '%b  + %s%b\n' "${GRN}" "${line}" "${N}"; changed=1
    done < <(comm -13 <(sort "${prev}") <(sort "${curr}"))
    [[ "${changed}" == "0" ]] && printf '  %b(no change)%b\n' "${DIM}" "${N}"
}

# ── run one section ───────────────────────────────────────────────────────────
run_section() {
    local key="$1"
    local ts; ts="$(date '+%H:%M:%S')"
    local curr="${STATE_DIR}/${key}.curr"
    local prev="${STATE_DIR}/${key}.prev"
    local crit="${CRITICALITY[${key}]}"
    local ivl="${INTERVAL[${key}]}"

    # colour by criticality
    local col="${DIM}"
    [[ "${crit}" == "CRITICAL" ]] && col="${RED}${BLD}"
    [[ "${crit}" == "HIGH"     ]] && col="${YEL}"

    { eval "${COLLECTORS[${key}]}"; } > "${curr}" 2>/dev/null || true

    printf '\n%b┌─ %-52s %-10s  every %ss  %s%b\n' \
        "${col}" "${TITLES[${key}]}" "[${crit}]" "${ivl}" "${ts}" "${N}"

    if [[ "${DIFF_ONLY}" == "1" ]]; then
        show_diff "${prev}" "${curr}"
    else
        sed 's/^/  /' "${curr}"
        if [[ -f "${prev}" ]]; then
            printf '%b  ── delta ──%b\n' "${DIM}" "${N}"
            show_diff "${prev}" "${curr}"
        fi
    fi

    [[ "${DO_LOG}" == "1" ]] && {
        printf '\n[%s] run=%d\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${TOTAL_RUNS}" \
            >> "${LOG_DIR}/${key}.log"
        cat "${curr}" >> "${LOG_DIR}/${key}.log"
    }

    cp "${curr}" "${prev}" 2>/dev/null || true
    LAST_RUN[${key}]="$(now)"
    (( TOTAL_RUNS++ )) || true
}

# ── Trap ──────────────────────────────────────────────────────────────────────
trap 'printf "\n%b[watch] stopped — %d total section runs%b\n" \
    "${YEL}" "${TOTAL_RUNS}" "${N}"; exit 0' INT TERM

# ── Banner ────────────────────────────────────────────────────────────────────
clear
printf '%b╔══════════════════════════════════════════════════════════════════════╗%b\n' "${CYN}${BLD}" "${N}"
printf '%b║  mac_intel — Live Watch Mode                                         ║%b\n' "${CYN}${BLD}" "${N}"
printf '%b╚══════════════════════════════════════════════════════════════════════╝%b\n' "${CYN}${BLD}" "${N}"
printf '\n  %bTick%b           = every %s s\n'      "${BLD}" "${N}" "${TICK}"
printf '  %bDiff only%b      = %s\n'              "${BLD}" "${N}" "${DIFF_ONLY}"
printf '  %bLogging%b        = %s  → %s\n'        "${BLD}" "${N}" "${DO_LOG}" "${LOG_DIR}"
printf '  %bTop N rows%b     = %s\n'              "${BLD}" "${N}" "${TOP_N}"
printf '  %bRunning as%b     : %s  (root=%s)\n'   "${BLD}" "${N}" "${CONSOLE_USER}" "${IS_ROOT}"
printf '\n  %bActive sections + intervals:%b\n'    "${BLD}" "${N}"
printf '  %-22s %-10s %-12s %s\n' "Section" "Interval" "Criticality" "Override env var"
printf '  %s\n' "$(printf '─%.0s' {1..70})"
for sec in "${ACTIVE_SECTIONS[@]}"; do
    crit="${CRITICALITY[${sec}]}"
    col="${DIM}"
    [[ "${crit}" == "CRITICAL" ]] && col="${RED}"
    [[ "${crit}" == "HIGH"     ]] && col="${YEL}"
    printf '  %b%-22s %-10s %-12s %s%b\n' \
        "${col}" "${sec}" "${INTERVAL[${sec}]}s" "${crit}" \
        "WATCH_INTERVAL_${sec^^}=<s>" "${N}"
done
printf '\n  Press %bCtrl+C%b to stop.\n\n' "${BLD}" "${N}"
sleep 3

# ── Main tick loop ────────────────────────────────────────────────────────────
TICK_COUNT=0
while true; do
    (( TICK_COUNT++ )) || true
    T="$(now)"

    DUE=()
    for sec in "${ACTIVE_SECTIONS[@]}"; do
        elapsed=$(( T - LAST_RUN[${sec}] ))
        [[ "${elapsed}" -ge "${INTERVAL[${sec}]}" ]] && DUE+=("${sec}")
    done

    if [[ "${#DUE[@]}" -gt 0 ]]; then
        printf '\n%b══ tick #%d · %s · firing: %s%b\n' \
            "${MAG}${BLD}" "${TICK_COUNT}" "$(date '+%H:%M:%S')" "${DUE[*]}" "${N}"
        for sec in "${DUE[@]}"; do
            run_section "${sec}"
        done
    fi

    # show countdown for next due section
    NEXT=9999999; NEXT_SEC=""
    for sec in "${ACTIVE_SECTIONS[@]}"; do
        remaining=$(( INTERVAL[${sec}] - ( $(now) - LAST_RUN[${sec}] ) ))
        [[ "${remaining}" -lt "${NEXT}" ]] && { NEXT="${remaining}"; NEXT_SEC="${sec}"; }
    done
    printf '\r%b  next: %-20s in %3ds  (tick #%d)  Ctrl+C to stop%b' \
        "${DIM}" "${NEXT_SEC}" "${NEXT}" "$(( TICK_COUNT + 1 ))" "${N}"

    sleep "${TICK}"
done
