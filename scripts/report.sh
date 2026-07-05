#!/usr/bin/env bash
# =============================================================================
#  report.sh — macOS Full Core System Snapshot
#  Requires: sudo bash report.sh
#  Output  : output/report_YYYYMMDD_HHMMSS.txt   (also printed to terminal)
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/output"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT="${OUT_DIR}/report_${TIMESTAMP}.txt"

mkdir -p "${OUT_DIR}"

# ── Formatting helpers ────────────────────────────────────────────────────────
SEP="$(printf '─%.0s' {1..90})"
THICK="$(printf '═%.0s' {1..90})"

section() {
    printf '\n%s\n' "${THICK}"
    printf '  %-86s\n' "  $1"
    printf '%s\n' "${THICK}"
}

subsection() {
    printf '\n  ── %s ──\n' "$1"
}

kv() {
    printf '  %-35s %s\n' "$1" "${2:-—}"
}

table_header() {
    printf '\n  %s\n' "$SEP"
    printf "  $1\n"
    printf '  %s\n' "$SEP"
}

q() { "$@" 2>/dev/null || true; }
q_str() { "$@" 2>/dev/null || echo "—"; }
cmd_ok() { command -v "$1" &>/dev/null; }

# ── Tee everything to file ────────────────────────────────────────────────────
exec > >(tee "${REPORT}") 2>&1

CONSOLE_USER="$(stat -f '%Su' /dev/console 2>/dev/null || echo "${SUDO_USER:-$USER}")"
CONSOLE_HOME="$(eval echo "~${CONSOLE_USER}" 2>/dev/null || echo "/Users/${CONSOLE_USER}")"
IS_ROOT=false; [[ "$(id -u)" == "0" ]] && IS_ROOT=true

printf '\n%s\n' "${THICK}"
printf '  macOS Core System Snapshot\n'
printf '  Generated : %s\n' "$(date)"
printf '  User      : %s   (sudo: %s)\n' "${CONSOLE_USER}" "${IS_ROOT}"
printf '  Report    : %s\n' "${REPORT}"
printf '%s\n' "${THICK}"


# ══════════════════════════════════════════════════════════════════════════════
section "1. SYSTEM IDENTITY"
# ══════════════════════════════════════════════════════════════════════════════

kv "Hostname"          "$(q_str hostname)"
kv "Local Hostname"    "$(q_str scutil --get LocalHostName)"
kv "Computer Name"     "$(q_str scutil --get ComputerName)"
kv "OS"                "$(q_str sw_vers -productName) $(q_str sw_vers -productVersion) ($(q_str sw_vers -buildVersion))"
kv "Kernel"            "$(q_str uname -r)"
kv "Architecture"      "$(q_str uname -m)"
kv "Chip"              "$(q_str sysctl -n machdep.cpu.brand_string)"
kv "Serial Number"     "$(q system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/{print $NF}' || echo '—')"
kv "Model"             "$(q system_profiler SPHardwareDataType 2>/dev/null | awk '/Model Name/{$1=$2=""; print $0}' | xargs || echo '—')"
kv "Model Identifier"  "$(q sysctl -n hw.model)"
kv "Boot Time"         "$(q_str sysctl -n kern.boottime | awk -F'[=,}]' '{print $2}' | xargs -I{} date -r {} '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '—')"
kv "Uptime"            "$(q_str uptime | sed 's/.*up //' | sed 's/,.*//')"
kv "Current Date/Time" "$(date '+%Y-%m-%d %H:%M:%S %Z')"


# ══════════════════════════════════════════════════════════════════════════════
section "2. HARDWARE"
# ══════════════════════════════════════════════════════════════════════════════

RAM_BYTES="$(q sysctl -n hw.memsize)"
RAM_GB="$(echo "${RAM_BYTES}" | awk '{printf "%.0f GB", $1/1073741824}')"
PCPU="$(q sysctl -n hw.physicalcpu)"
LCPU="$(q sysctl -n hw.logicalcpu)"

kv "Total RAM"          "${RAM_GB}"
kv "Physical CPUs"      "${PCPU}"
kv "Logical CPUs"       "${LCPU}"
kv "CPU Freq (max)"     "$(q sysctl -n hw.cpufrequency_max 2>/dev/null | awk '{printf "%.0f MHz", $1/1000000}' || echo '—')"
kv "Cache Line"         "$(q sysctl -n hw.cachelinesize) bytes"
kv "L2 Cache"           "$(q sysctl -n hw.l2cachesize 2>/dev/null | awk '{printf "%.0f KB", $1/1024}' || echo '—')"
kv "Page Size"          "$(q sysctl -n hw.pagesize) bytes"
kv "Byte Order"         "$(q sysctl -n hw.byteorder)"

subsection "Memory Pressure"
q vm_stat | awk '
  /Pages free/         {free=$3}
  /Pages active/       {act=$3}
  /Pages inactive/     {inact=$3}
  /Pages wired/        {wired=$4}
  /Pages compressed/   {comp=$3}
  END {
    ps=4096
    printf "  %-20s %s\n", "Free",       int(free)*ps/1073741824 " GB"
    printf "  %-20s %s\n", "Active",     int(act)*ps/1073741824  " GB"
    printf "  %-20s %s\n", "Inactive",   int(inact)*ps/1073741824" GB"
    printf "  %-20s %s\n", "Wired",      int(wired)*ps/1073741824" GB"
    printf "  %-20s %s\n", "Compressed", int(comp)*ps/1073741824 " GB"
  }'

subsection "CPU Load"
q top -l 1 -n 0 | awk '/CPU usage/'


# ══════════════════════════════════════════════════════════════════════════════
section "3. STORAGE"
# ══════════════════════════════════════════════════════════════════════════════

table_header "$(printf '%-18s %-8s %-8s %-8s %-6s  %s' 'Filesystem' 'Size' 'Used' 'Avail' 'Use%%' 'Mounted On')"
df -h | tail -n +2 | while IFS= read -r line; do
    printf '  %s\n' "${line}"
done

subsection "Disk List"
q diskutil list


# ══════════════════════════════════════════════════════════════════════════════
section "4. BATTERY"
# ══════════════════════════════════════════════════════════════════════════════

BATT_RAW="$(q system_profiler SPPowerDataType 2>/dev/null)"
if [[ -n "${BATT_RAW}" ]]; then
    echo "${BATT_RAW}" | awk '
        /Cycle Count/          {kv("Cycle Count", $NF)}
        /Condition/            {kv("Condition", $NF)}
        /Maximum Capacity/     {kv("Maximum Capacity", $NF)}
        /Charge Remaining/     {kv("Charge Remaining", $NF)}
        /Charging/             {kv("Charging", $NF)}
        /Connected/            {kv("Power Connected", $NF)}
        function kv(k,v) { printf "  %-35s %s\n", k, v }
    '
fi
q pmset -g batt | sed 's/^/  /'


# ══════════════════════════════════════════════════════════════════════════════
section "5. NETWORK INTERFACES"
# ══════════════════════════════════════════════════════════════════════════════

table_header "$(printf '%-12s %-20s %-20s %-15s %s' 'Interface' 'IPv4' 'IPv6' 'MAC' 'Status')"
ifconfig 2>/dev/null | awk '
/^[a-z]/ {
    iface = substr($1, 1, length($1)-1)
    mac=""; ipv4=""; ipv6=""; flags=""
    if ($0 ~ /UP/) flags="UP"
    else flags="DOWN"
}
/ether / { mac=$2 }
/inet / && !/inet6/ { ipv4=$2 }
/inet6 / && $2 !~ /^fe80/ { ipv6=$2 }
/^[[:space:]]*$/ || /^[a-z]/ {
    if (iface && (ipv4 != "" || mac != "")) {
        printf "  %-12s %-20s %-20s %-15s %s\n", iface, ipv4, ipv6, mac, flags
        iface=""; ipv4=""; ipv6=""; mac=""
    }
}
'

subsection "DNS Servers"
q scutil --dns | awk '/nameserver/{print "  " $3}' | sort -u

subsection "WiFi"
AIRPORT="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
if [[ -x "${AIRPORT}" ]]; then
    q "${AIRPORT}" -I | awk '
        / SSID/    {kv("SSID", $2)}
        /BSSID/    {kv("BSSID", $2)}
        /channel/  {kv("Channel", $2)}
        /agrCtlRSSI/ {kv("RSSI", $2)}
        /lastTxRate/ {kv("TX Rate", $2 " Mbps")}
        /link auth/ {kv("Auth", $3)}
        function kv(k,v) { printf "  %-25s %s\n", k, v }
    '
else
    q networksetup -getairportnetwork en0 | sed 's/^/  /'
fi

subsection "Routing Table"
q netstat -rn | grep -E '^(default|0\.0\.0\.0|::/0)' | sed 's/^/  /'


# ══════════════════════════════════════════════════════════════════════════════
section "6. OPEN PORTS  (LISTENING)"
# ══════════════════════════════════════════════════════════════════════════════

table_header "$(printf '%-25s %-8s %-8s %-45s' 'Process' 'PID' 'Proto' 'Address:Port')"
if $IS_ROOT; then
    lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2 | sort -k1 | \
    while IFS= read -r line; do
        proc=$(echo "${line}" | awk '{print $1}')
        pid=$(echo  "${line}" | awk '{print $2}')
        addr=$(echo "${line}" | awk '{print $NF}')
        printf '  %-25s %-8s %-8s %-45s\n' "${proc}" "${pid}" "TCP" "${addr}"
    done
    lsof -nP -iUDP 2>/dev/null | tail -n +2 | sort -k1 | \
    while IFS= read -r line; do
        proc=$(echo "${line}" | awk '{print $1}')
        pid=$(echo  "${line}" | awk '{print $2}')
        addr=$(echo "${line}" | awk '{print $NF}')
        printf '  %-25s %-8s %-8s %-45s\n' "${proc}" "${pid}" "UDP" "${addr}"
    done
else
    echo "  ⚠  Run with sudo for complete port list"
    netstat -an | grep LISTEN | awk '{printf "  %-50s %s\n", $4, $6}'
fi


# ══════════════════════════════════════════════════════════════════════════════
section "7. ACTIVE CONNECTIONS  (ESTABLISHED)"
# ══════════════════════════════════════════════════════════════════════════════

table_header "$(printf '%-22s %-8s %-42s %-42s' 'Process' 'PID' 'Local' 'Remote')"
if $IS_ROOT; then
    lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | tail -n +2 | \
    while IFS= read -r line; do
        proc=$(echo "${line}" | awk '{print $1}')
        pid=$(echo  "${line}" | awk '{print $2}')
        name=$(echo "${line}" | awk '{print $9}')
        local_addr=$(echo "${name}" | cut -d'-' -f1)
        remote_addr=$(echo "${name}" | cut -d'>' -f2)
        printf '  %-22s %-8s %-42s %-42s\n' "${proc}" "${pid}" "${local_addr}" "${remote_addr}"
    done
else
    echo "  ⚠  Run with sudo for process names"
    netstat -an | grep ESTABLISHED | awk '{printf "  %-45s %s\n", $4, $5}'
fi


# ══════════════════════════════════════════════════════════════════════════════
section "8. RUNNING PROCESSES  (top 60 by CPU)"
# ══════════════════════════════════════════════════════════════════════════════

table_header "$(printf '%-8s %-20s %-7s %-7s %-10s %s' 'PID' 'USER' '%CPU' '%MEM' 'RSS(KB)' 'COMMAND')"
ps -axo pid=,user=,pcpu=,pmem=,rss=,comm= 2>/dev/null | \
    sort -k3 -rn | head -60 | \
    while IFS= read -r line; do
        pid=$(echo  "${line}" | awk '{print $1}')
        usr=$(echo  "${line}" | awk '{print $2}')
        cpu=$(echo  "${line}" | awk '{print $3}')
        mem=$(echo  "${line}" | awk '{print $4}')
        rss=$(echo  "${line}" | awk '{print $5}')
        cmd=$(echo  "${line}" | awk '{print $6}')
        printf '  %-8s %-20s %-7s %-7s %-10s %s\n' "${pid}" "${usr}" "${cpu}" "${mem}" "${rss}" "${cmd}"
    done


# ══════════════════════════════════════════════════════════════════════════════
section "9. LAUNCHD SERVICES"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Running LaunchDaemons (system)"
table_header "$(printf '%-10s %-10s %s' 'PID' 'Status' 'Label')"
launchctl list 2>/dev/null | tail -n +2 | awk '
$1 != "-" {
    printf "  %-10s %-10s %s\n", $1, $2, $3
}' | head -80

subsection "All Loaded Services (including stopped)"
table_header "$(printf '%-10s %-10s %s' 'PID' 'Status' 'Label')"
launchctl list 2>/dev/null | tail -n +2 | awk '{printf "  %-10s %-10s %s\n", $1, $2, $3}' | head -200

subsection "LaunchDaemon Plists  /Library/LaunchDaemons"
ls /Library/LaunchDaemons/ 2>/dev/null | awk '{print "  " $0}'

subsection "LaunchAgent Plists  /Library/LaunchAgents"
ls /Library/LaunchAgents/ 2>/dev/null | awk '{print "  " $0}'

subsection "User LaunchAgent Plists  ~/Library/LaunchAgents"
ls "${CONSOLE_HOME}/Library/LaunchAgents/" 2>/dev/null | awk '{print "  " $0}' || echo "  (none)"

subsection "Login Items"
q osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | \
    tr ',' '\n' | sed 's/^ */  /' || echo "  (none or no access)"


# ══════════════════════════════════════════════════════════════════════════════
section "10. INSTALLED APPLICATIONS"
# ══════════════════════════════════════════════════════════════════════════════

table_header "$(printf '%-55s %s' 'Application' 'Path')"
ls -1 /Applications/ 2>/dev/null | while IFS= read -r app; do
    printf '  %-55s %s\n' "${app}" "/Applications/${app}"
done

subsection "System Applications  (/System/Applications)"
ls -1 /System/Applications/ 2>/dev/null | awk '{print "  " $0}'


# ══════════════════════════════════════════════════════════════════════════════
section "11. PACKAGE MANAGERS"
# ══════════════════════════════════════════════════════════════════════════════

# ── Homebrew Formulae ─────────────────────────────────────────────────────────
subsection "Homebrew Formulae"
if cmd_ok brew; then
    table_header "$(printf '%-35s %s' 'Package' 'Version')"
    brew list --versions 2>/dev/null | awk '{printf "  %-35s %s\n", $1, $2}' | head -200
else
    echo "  Homebrew not installed"
fi

# ── Homebrew Casks ────────────────────────────────────────────────────────────
subsection "Homebrew Casks"
if cmd_ok brew; then
    table_header "$(printf '%-35s %s' 'Cask' 'Version')"
    brew list --cask --versions 2>/dev/null | awk '{printf "  %-35s %s\n", $1, $2}' | head -100
fi

# ── Python Packages ───────────────────────────────────────────────────────────
subsection "Python Packages (pip3)"
if cmd_ok pip3; then
    table_header "$(printf '%-40s %s' 'Package' 'Version')"
    pip3 list --format=columns 2>/dev/null | tail -n +3 | \
        awk '{printf "  %-40s %s\n", $1, $2}' | head -200
elif cmd_ok /opt/homebrew/bin/pip3; then
    table_header "$(printf '%-40s %s' 'Package' 'Version')"
    /opt/homebrew/bin/pip3 list --format=columns 2>/dev/null | tail -n +3 | \
        awk '{printf "  %-40s %s\n", $1, $2}' | head -200
else
    echo "  pip3 not found"
fi

# ── Python versions ───────────────────────────────────────────────────────────
subsection "Python Interpreters"
for py in python python3 /opt/homebrew/bin/python3 /usr/bin/python3; do
    [[ -x "$(command -v ${py} 2>/dev/null)" ]] && \
        printf '  %-35s %s\n' "${py}" "$(${py} --version 2>&1)" || true
done

# ── npm Global Packages ───────────────────────────────────────────────────────
subsection "npm Global Packages"
if cmd_ok npm; then
    table_header "$(printf '%-40s %s' 'Package' 'Version')"
    npm list -g --depth=0 2>/dev/null | tail -n +2 | \
        sed 's/[├└─│ ]*//' | sed 's/@/ /' | \
        awk '{printf "  %-40s %s\n", $1, $2}' | head -100
else
    echo "  npm not installed"
fi

# ── Ruby Gems ─────────────────────────────────────────────────────────────────
subsection "Ruby Gems"
if cmd_ok gem; then
    table_header "$(printf '%-40s %s' 'Gem' 'Version')"
    gem list 2>/dev/null | awk '{printf "  %-40s %s\n", $1, $2}' | head -100
else
    echo "  gem not found"
fi

# ── Go Binaries ───────────────────────────────────────────────────────────────
subsection "Go Binaries  (~/go/bin)"
GOBIN="${CONSOLE_HOME}/go/bin"
if [[ -d "${GOBIN}" ]]; then
    ls -1 "${GOBIN}" | awk '{print "  " $0}'
else
    echo "  No ~/go/bin directory"
fi

# ── Cargo Binaries ────────────────────────────────────────────────────────────
subsection "Cargo Binaries  (Rust)"
CARGOBIN="${CONSOLE_HOME}/.cargo/bin"
if [[ -d "${CARGOBIN}" ]]; then
    ls -1 "${CARGOBIN}" | awk '{print "  " $0}'
else
    echo "  No ~/.cargo/bin directory"
fi


# ══════════════════════════════════════════════════════════════════════════════
section "12. BINARIES  (PATH inventory)"
# ══════════════════════════════════════════════════════════════════════════════

for bin_dir in \
    /opt/homebrew/bin \
    /opt/homebrew/sbin \
    /usr/local/bin \
    /usr/local/sbin \
    "${CONSOLE_HOME}/.local/bin" \
    "${CONSOLE_HOME}/bin"
do
    if [[ -d "${bin_dir}" ]]; then
        subsection "${bin_dir}"
        ls -1 "${bin_dir}" 2>/dev/null | awk '{print "  " $0}' | head -200
    fi
done

subsection "System Binaries  /usr/bin  (first 80)"
ls -1 /usr/bin/ 2>/dev/null | head -80 | awk '{print "  " $0}'


# ══════════════════════════════════════════════════════════════════════════════
section "13. USERS & GROUPS"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Local Users"
table_header "$(printf '%-25s %-6s %-6s %-30s %s' 'Username' 'UID' 'GID' 'Home' 'Shell')"
dscl . list /Users 2>/dev/null | grep -v '^_' | while IFS= read -r u; do
    uid=$(q dscl . read /Users/"${u}" UniqueID | awk '{print $2}')
    gid=$(q dscl . read /Users/"${u}" PrimaryGroupID | awk '{print $2}')
    home=$(q dscl . read /Users/"${u}" NFSHomeDirectory | awk '{print $2}')
    shell=$(q dscl . read /Users/"${u}" UserShell | awk '{print $2}')
    printf '  %-25s %-6s %-6s %-30s %s\n' "${u}" "${uid}" "${gid}" "${home}" "${shell}"
done

subsection "Admin Users"
q dscl . read /Groups/admin GroupMembership 2>/dev/null | \
    awk '{for(i=2;i<=NF;i++) print "  " $i}'

subsection "Groups"
dscl . list /Groups 2>/dev/null | grep -v '^_' | awk '{print "  " $0}'

subsection "Currently Logged-In Users"
who | awk '{print "  " $0}'

subsection "Last Logins (last 20)"
last 2>/dev/null | head -20 | awk '{print "  " $0}'

subsection "Sudo Configuration"
if $IS_ROOT; then
    cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | sed 's/^/  /'
    ls /etc/sudoers.d/ 2>/dev/null | awk '{print "  sudoers.d/" $0}'
else
    echo "  ⚠  Run with sudo to see sudoers"
fi


# ══════════════════════════════════════════════════════════════════════════════
section "14. SECURITY CONFIGURATION"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Core Security Status"
# SIP
SIP="$(q csrutil status | sed 's/System Integrity Protection status: //')"
kv "SIP (csrutil)"           "${SIP}"

# Gatekeeper
GK="$(q spctl --status 2>/dev/null)"
kv "Gatekeeper"              "${GK}"

# FileVault
FV="$(q fdesetup status)"
kv "FileVault"               "${FV}"

# Secure Boot (NVRAM)
SBOOT="$(q nvram security-mode 2>/dev/null | awk '{print $2}' || echo '—')"
kv "Secure Boot Mode"        "${SBOOT}"

# Developer Mode
DEVMODE="$(q DevToolsSecurity -status 2>/dev/null | head -1)"
kv "Developer Tools Security" "${DEVMODE}"

# Rosetta2
ROSETTA="$(q pkgutil --pkg-info com.apple.pkg.RosettaUpdateAuto 2>/dev/null | head -1)"
kv "Rosetta2"                "${ROSETTA:-not installed}"

# XProtect version
XPROT="$(q defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)"
kv "XProtect Version"        "${XPROT:-—}"

# MRT version
MRT="$(q defaults read /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)"
kv "MRT Version"             "${MRT:-—}"

# SSH server
SSH_STATUS="$(q launchctl list com.openssh.sshd 2>/dev/null | head -1)"
kv "SSH Server"              "${SSH_STATUS:-not running}"

# Remote Login
kv "Remote Login"            "$(q systemsetup -getremotelogin 2>/dev/null | sed 's/Remote Login: //')"

# Screen sharing
kv "Screen Sharing"          "$(q launchctl list com.apple.screensharing 2>/dev/null | head -1 || echo 'not running')"

subsection "Firewall"
if $IS_ROOT; then
    FW_STATE="$(q /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)"
    kv "Application Firewall"  "${FW_STATE}"
    FW_STEALTH="$(q /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode)"
    kv "Stealth Mode"          "${FW_STEALTH}"
    FW_BLOCK="$(q /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall)"
    kv "Block All"             "${FW_BLOCK}"
    echo ""
    echo "  -- pf rules --"
    pfctl -sr 2>/dev/null | sed 's/^/  /' || echo "  (no active pf rules)"
else
    kv "Application Firewall" "$(q /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)"
    echo "  ⚠  Run with sudo for pf rules"
fi

subsection "TCC (Privacy Database)"
if $IS_ROOT; then
    TCC_DB="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ -f "${TCC_DB}" ]]; then
        table_header "$(printf '%-40s %-30s %-15s %s' 'Service' 'Client' 'Auth' 'LastModified')"
        sqlite3 -separator $'\t' "${TCC_DB}" \
            "SELECT service, client, auth_value, datetime(last_modified,'unixepoch') FROM access ORDER BY service, client" 2>/dev/null | \
        while IFS=$'\t' read -r svc client auth ts; do
            printf '  %-40s %-30s %-15s %s\n' "${svc}" "${client}" "${auth}" "${ts}"
        done
    else
        echo "  TCC.db not found"
    fi
else
    echo "  ⚠  Run with sudo to read TCC database"
fi

subsection "Keychain Info"
q security list-keychains | sed 's/^/  /'

subsection "Code Signing — Running Processes (sample 20)"
if $IS_ROOT; then
    ps -axo pid=,comm= 2>/dev/null | head -20 | while IFS= read -r line; do
        pid=$(echo "${line}" | awk '{print $1}')
        cmd=$(echo "${line}" | awk '{print $2}')
        sig="$(codesign -v "${cmd}" 2>&1 | head -1 || echo 'unsigned/error')"
        printf '  %-8s %-40s %s\n' "${pid}" "$(basename "${cmd}")" "${sig}"
    done
else
    echo "  ⚠  Run with sudo for full codesign info"
fi


# ══════════════════════════════════════════════════════════════════════════════
section "15. KERNEL EXTENSIONS"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Loaded Kernel Extensions"
table_header "$(printf '%-60s %s' 'Extension' 'Version')"
if cmd_ok kmutil; then
    kmutil showloaded 2>/dev/null | grep -v '^No\|^$' | sed 's/^/  /'
else
    kextstat 2>/dev/null | tail -n +2 | \
        awk '{printf "  %-60s %s\n", $6, $5}' | head -80
fi

subsection "System Extensions"
if $IS_ROOT; then
    q systemextensionsctl list 2>/dev/null | sed 's/^/  /'
else
    echo "  ⚠  Run with sudo for system extensions"
fi


# ══════════════════════════════════════════════════════════════════════════════
section "16. SCHEDULED TASKS  (cron + launchd timers)"
# ══════════════════════════════════════════════════════════════════════════════

subsection "User Crontab"
crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | sed 's/^/  /' || echo "  (empty)"

subsection "System Crontab  /etc/crontab"
[[ -f /etc/crontab ]] && grep -v '^#' /etc/crontab | grep -v '^$' | sed 's/^/  /' || echo "  (none)"

subsection "Periodic Scripts"
for d in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
    [[ -d "${d}" ]] && { echo "  ${d}:"; ls "${d}" | awk '{print "    " $0}'; }
done

subsection "LaunchDaemons with StartInterval (timers)"
grep -rl 'StartInterval\|StartCalendarInterval' /Library/LaunchDaemons/ 2>/dev/null | \
    while IFS= read -r f; do
        interval=$(q defaults read "${f}" StartInterval 2>/dev/null)
        printf '  %-65s interval=%s\n' "$(basename "${f}")" "${interval:-calendar}"
    done


# ══════════════════════════════════════════════════════════════════════════════
section "17. CONFIGURATION FILES"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Shell Config Files"
for f in \
    "${CONSOLE_HOME}/.zshrc" \
    "${CONSOLE_HOME}/.bashrc" \
    "${CONSOLE_HOME}/.bash_profile" \
    "${CONSOLE_HOME}/.profile" \
    "${CONSOLE_HOME}/.zprofile" \
    /etc/zshrc \
    /etc/bashrc \
    /etc/profile
do
    if [[ -f "${f}" ]]; then
        echo ""
        printf '  ── %s ──\n' "${f}"
        grep -v '^#' "${f}" | grep -v '^$' | sed 's/^/    /' | head -40
    fi
done

subsection "SSH Config"
[[ -f "${CONSOLE_HOME}/.ssh/config" ]] && \
    cat "${CONSOLE_HOME}/.ssh/config" | sed 's/^/  /' || echo "  (no ~/.ssh/config)"

subsection "SSH Authorized Keys"
[[ -f "${CONSOLE_HOME}/.ssh/authorized_keys" ]] && \
    cat "${CONSOLE_HOME}/.ssh/authorized_keys" | sed 's/^/  /' || echo "  (none)"

subsection "Hosts File"
grep -v '^#' /etc/hosts | grep -v '^$' | sed 's/^/  /'

subsection "Resolv.conf"
[[ -f /etc/resolv.conf ]] && cat /etc/resolv.conf | grep -v '^#' | sed 's/^/  /' || echo "  (none)"


# ══════════════════════════════════════════════════════════════════════════════
section "18. ENVIRONMENT VARIABLES"
# ══════════════════════════════════════════════════════════════════════════════

table_header "$(printf '%-35s %s' 'Variable' 'Value')"
env | sort | while IFS='=' read -r k v; do
    printf '  %-35s %s\n' "${k}" "${v}"
done


# ══════════════════════════════════════════════════════════════════════════════
section "19. SYSCTL  (security & network relevant)"
# ══════════════════════════════════════════════════════════════════════════════

table_header "$(printf '%-55s %s' 'Key' 'Value')"
sysctl -a 2>/dev/null | grep -E \
    'kern\.(bootargs|hostname|osversion|version|securelevel|maxfiles|maxproc|ipc|sysv)|
     hw\.(model|memsize|ncpu|physicalcpu|logicalcpu|byteorder|cputype|cpusubtype)|
     net\.inet\.(ip\.(forwarding|ttl|redirect)|tcp\.(mssdflt|keepidle)|icmp)|
     machdep\.cpu|
     vm\.(loadavg|swapusage|compressor_mode)|
     security\.' | \
    sed 's/: /=/' | \
    while IFS='=' read -r k v; do
        printf '  %-55s %s\n' "${k}" "${v}"
    done


# ══════════════════════════════════════════════════════════════════════════════
section "20. OPEN FILES SUMMARY  (top processes)"
# ══════════════════════════════════════════════════════════════════════════════

if $IS_ROOT; then
    table_header "$(printf '%-8s %-20s %s' 'PID' 'Process' 'Open File Count')"
    lsof 2>/dev/null | awk 'NR>1{count[$2" "$1]++} END{for(k in count) print count[k], k}' | \
        sort -rn | head -30 | \
        while IFS= read -r line; do
            cnt=$(echo "${line}" | awk '{print $1}')
            pid=$(echo "${line}" | awk '{print $2}')
            prc=$(echo "${line}" | awk '{print $3}')
            printf '  %-8s %-20s %s\n' "${pid}" "${prc}" "${cnt}"
        done
else
    echo "  ⚠  Run with sudo for full open-file data"
fi




# ══════════════════════════════════════════════════════════════════════════════
section "21. CONNECTED HARDWARE DEVICES"
# ══════════════════════════════════════════════════════════════════════════════

subsection "USB Devices"
system_profiler SPUSBDataType 2>/dev/null | awk '
  /^    [^ ]/ { dev=$0 }
  /Product ID/ { pid=$NF }
  /Vendor ID/  { vid=$NF }
  /Version/    { ver=$NF; printf "  %-45s pid=%-8s vid=%-10s ver=%s\n", dev, pid, vid, ver; pid=""; vid=""; ver="" }
' | sed 's/://g' | head -60
q system_profiler SPUSBDataType 2>/dev/null | grep -E '(USB 3|USB-C|Product ID|Vendor ID|Manufacturer|Speed|Location)' | \
    sed 's/^[[:space:]]*/  /' | head -60

subsection "Thunderbolt / DisplayPort"
q system_profiler SPThunderboltDataType 2>/dev/null | \
    grep -E '(Thunderbolt|Vendor|Status|Speed|Rx Lanes|Tx Lanes|Device Name|UID)' | \
    sed 's/^[[:space:]]*/  /' | head -40

subsection "Bluetooth Devices (paired)"
q system_profiler SPBluetoothDataType 2>/dev/null | \
    grep -E '(Device Name|Address|Firmware|Vendor ID|Product|Connected|Services|RSSI)' | \
    sed 's/^[[:space:]]*/  /' | head -60

subsection "Audio Devices"
q system_profiler SPAudioDataType 2>/dev/null | \
    grep -E '(Audio ID|Manufacturer|Transport|Input|Output|Current|Default)' | \
    sed 's/^[[:space:]]*/  /' | head -40

subsection "Displays"
q system_profiler SPDisplaysDataType 2>/dev/null | \
    grep -E '(Display Type|Resolution|Framebuffer|Pixel|VRAM|EFI Driver|Vendor|Device ID|Revision ID|Color)' | \
    sed 's/^[[:space:]]*/  /' | head -30

subsection "Printers"
q system_profiler SPPrintersDataType 2>/dev/null | \
    grep -E '(Printer|Status|Driver|URI|PPD)' | \
    sed 's/^[[:space:]]*/  /' | head -20


# ══════════════════════════════════════════════════════════════════════════════
section "22. MDM / CONFIG PROFILES"
# ══════════════════════════════════════════════════════════════════════════════

if $IS_ROOT; then
    subsection "Installed Profiles"
    q profiles list -all 2>/dev/null | sed 's/^/  /' || echo "  (none)"

    subsection "Profile Details"
    q profiles show -all 2>/dev/null | \
        grep -E '(PayloadDisplayName|PayloadOrganization|PayloadIdentifier|PayloadType|PayloadDescription)' | \
        sed 's/^[[:space:]]*/  /' | head -80
else
    echo "  ⚠  Run with sudo to read MDM profiles"
fi


# ══════════════════════════════════════════════════════════════════════════════
section "23. NETWORK SHARES, MOUNTS & VPN"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Active Mounts"
mount 2>/dev/null | grep -vE '^(devfs|map |/dev/disk)' | sed 's/^/  /'

subsection "ARP Table"
table_header "$(printf '%-25s %-20s %s' 'Host' 'MAC' 'Interface')"
arp -a 2>/dev/null | awk '{printf "  %-25s %-20s %s\n", $2, $4, $6}'

subsection "VPN Connections"
q scutil --nc list 2>/dev/null | sed 's/^/  /' || echo "  (none configured)"

subsection "Proxy Settings"
q scutil --proxy 2>/dev/null | grep -v '^{' | grep -v '^}' | sed 's/^/  /'

subsection "Network Shares (Bonjour services)"
q dns-sd -B _smb._tcp local 2>/dev/null &
sleep 1; kill $! 2>/dev/null || true

subsection "Shared Folders (sharing)"
if $IS_ROOT; then
    q sharing -l 2>/dev/null | sed 's/^/  /' || echo "  (none)"
else
    echo "  ⚠  Run with sudo to list shared folders"
fi

subsection "SMB/AFP/NFS Sharing Status"
kv "Remote Login (SSH)"   "$(q systemsetup -getremotelogin 2>/dev/null | sed 's/Remote Login: //')"
kv "Remote Management"    "$(q systemsetup -getremoteappleevents 2>/dev/null)"
kv "SMB Service"          "$(launchctl list com.apple.smbd 2>/dev/null | grep -c '"PID"' | xargs -I{} sh -c 'if [ {} -gt 0 ]; then echo running; else echo stopped; fi')"
kv "Screen Sharing (VNC)" "$(launchctl list com.apple.screensharing 2>/dev/null | head -1 || echo stopped)"
kv "FTP Service"          "$(launchctl list com.apple.ftpd 2>/dev/null | head -1 || echo stopped)"


# ══════════════════════════════════════════════════════════════════════════════
section "24. POWER MANAGEMENT"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Power Settings  (pmset -g)"
q pmset -g 2>/dev/null | sed 's/^/  /'

subsection "Sleep Settings"
q pmset -g custom 2>/dev/null | sed 's/^/  /'

subsection "Power Assertions  (what's preventing sleep)"
q pmset -g assertions 2>/dev/null | grep -v '^Listed\|^$\|^No\|pid 0' | sed 's/^/  /' | head -30

subsection "Power Source Info"
q pmset -g ps 2>/dev/null | sed 's/^/  /'

subsection "Thermal State"
q pmset -g thermlog 2>/dev/null | head -10 | sed 's/^/  /' || echo "  (no thermal events)"


# ══════════════════════════════════════════════════════════════════════════════
section "25. SOFTWARE UPDATES"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Pending macOS Updates"
q softwareupdate -l 2>/dev/null | sed 's/^/  /'

subsection "Last Update Check"
q defaults read /Library/Preferences/com.apple.SoftwareUpdate LastFullSuccessfulDate 2>/dev/null | \
    sed 's/^/  /' || echo "  —"

subsection "Homebrew Outdated Formulae"
if cmd_ok brew; then
    table_header "$(printf '%-35s %-20s %s' 'Package' 'Current' 'Latest')"
    brew outdated --verbose 2>/dev/null | awk '{printf "  %-35s %-20s %s\n", $1, $2, $4}' | head -80
else
    echo "  Homebrew not installed"
fi

subsection "Outdated pip Packages"
if cmd_ok pip3; then
    table_header "$(printf '%-40s %-15s %s' 'Package' 'Installed' 'Latest')"
    pip3 list --outdated --format=columns 2>/dev/null | tail -n +3 | \
        awk '{printf "  %-40s %-15s %s\n", $1, $2, $3}' | head -50
fi


# ══════════════════════════════════════════════════════════════════════════════
section "26. CRASH & DIAGNOSTIC REPORTS"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Recent Crash Reports  (last 30 days)"
table_header "$(printf '%-55s %-25s %s' 'Report' 'Date' 'Size')"
find /Library/Logs/DiagnosticReports "${CONSOLE_HOME}/Library/Logs/DiagnosticReports" \
    -type f -mtime -30 2>/dev/null | sort -r | head -40 | \
    while IFS= read -r f; do
        fname=$(basename "${f}")
        fdate=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "${f}" 2>/dev/null)
        fsize=$(stat -f '%z' "${f}" 2>/dev/null | awk '{printf "%.1f KB", $1/1024}')
        printf '  %-55s %-25s %s\n' "${fname}" "${fdate}" "${fsize}"
    done

subsection "Kernel Panics  (last 10)"
find /Library/Logs/DiagnosticReports /var/log \
    -name 'panic-*' -o -name 'kernel_*.ips' 2>/dev/null | \
    sort -r | head -10 | awk '{print "  " $0}'

subsection "Recent System Log Errors  (last 1 hour)"
if $IS_ROOT; then
    log show --last 1h --predicate 'messageType == 16 OR messageType == 17' \
        --style compact 2>/dev/null | tail -30 | sed 's/^/  /'
else
    echo "  ⚠  Run with sudo for system log errors"
fi


# ══════════════════════════════════════════════════════════════════════════════
section "27. KEYCHAIN CERTIFICATES"
# ══════════════════════════════════════════════════════════════════════════════

subsection "System Keychain — Certificates"
table_header "$(printf '%-55s %s' 'Certificate Name' 'Keychain')"
security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | \
    grep '"labl"' | sed 's/.*"labl"<blob>="//' | sed 's/"//' | \
    awk '{printf "  %-55s %s\n", $0, "System"}' | head -50

subsection "Login Keychain — Certificates"
security find-certificate -a "${CONSOLE_HOME}/Library/Keychains/login.keychain-db" 2>/dev/null | \
    grep '"labl"' | sed 's/.*"labl"<blob>="//' | sed 's/"//' | \
    awk '{printf "  %-55s %s\n", $0, "Login"}' | head -50

subsection "Root CAs — System Roots"
security find-certificate -a /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | \
    grep '"labl"' | sed 's/.*"labl"<blob>="//' | sed 's/"//' | \
    awk '{print "  " $0}' | head -40


# ══════════════════════════════════════════════════════════════════════════════
section "28. NVRAM / BOOT ARGS"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Full NVRAM Variables"
if $IS_ROOT; then
    table_header "$(printf '%-50s %s' 'Variable' 'Value')"
    nvram -p 2>/dev/null | while IFS=$'\t' read -r k v; do
        printf '  %-50s %s\n' "${k}" "${v:0:120}"
    done
else
    echo "  ⚠  Run with sudo for full NVRAM"
    kv "boot-args" "$(q nvram boot-args 2>/dev/null | awk '{$1=""; print}' || echo '—')"
    kv "security-mode" "$(q nvram security-mode 2>/dev/null | awk '{print $2}' || echo '—')"
fi

subsection "Boot Policy  (bputil)"
if $IS_ROOT; then
    q bputil --display-all-policies 2>/dev/null | sed 's/^/  /' || echo "  bputil not available"
else
    echo "  ⚠  Run with sudo for boot policy"
fi


# ══════════════════════════════════════════════════════════════════════════════
section "29. CONTAINERS & VIRTUALISATION"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Docker"
if cmd_ok docker; then
    subsection "Running Containers"
    table_header "$(printf '%-16s %-30s %-20s %-20s %s' 'ID' 'Image' 'Status' 'Ports' 'Name')"
    docker ps --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}' 2>/dev/null | \
        awk -F'\t' '{printf "  %-16s %-30s %-20s %-20s %s\n", $1, $2, $3, $4, $5}' | head -30

    subsection "All Containers (including stopped)"
    docker ps -a --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}' 2>/dev/null | \
        awk -F'\t' '{printf "  %-16s %-30s %-25s %s\n", $1, $2, $3, $4}' | head -40

    subsection "Docker Images"
    table_header "$(printf '%-40s %-15s %-15s %s' 'Repository' 'Tag' 'Size' 'ID')"
    docker images --format '{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.ID}}' 2>/dev/null | \
        awk -F'\t' '{printf "  %-40s %-15s %-15s %s\n", $1, $2, $3, $4}' | head -40

    subsection "Docker Volumes"
    docker volume ls 2>/dev/null | sed 's/^/  /'

    subsection "Docker Networks"
    docker network ls 2>/dev/null | sed 's/^/  /'
else
    echo "  Docker not installed"
fi

subsection "Podman"
if cmd_ok podman; then
    podman ps -a 2>/dev/null | sed 's/^/  /' | head -20
else
    echo "  Podman not installed"
fi

subsection "Running VMs"
kv "VMware Fusion"  "$(pgrep -x vmware-vmx  2>/dev/null | wc -l | xargs) VM(s) running"
kv "Parallels"      "$(pgrep -x prl_vm_app  2>/dev/null | wc -l | xargs) VM(s) running"
kv "UTM"            "$(pgrep -x QEMULauncher 2>/dev/null | wc -l | xargs) VM(s) running"
kv "VirtualBox"     "$(pgrep -x VBoxHeadless 2>/dev/null | wc -l | xargs) VM(s) running"


# ══════════════════════════════════════════════════════════════════════════════
section "30. TIME MACHINE"
# ══════════════════════════════════════════════════════════════════════════════

subsection "Status"
q tmutil status 2>/dev/null | sed 's/^/  /' || echo "  Time Machine not configured"

subsection "Destinations"
q tmutil destinationinfo 2>/dev/null | sed 's/^/  /' || echo "  No destinations"

subsection "Latest Snapshots"
q tmutil listbackups 2>/dev/null | tail -5 | sed 's/^/  /' || echo "  No backups found"

subsection "Local Snapshots"
q tmutil listlocalsnapshots / 2>/dev/null | sed 's/^/  /' || echo "  None"


# ══════════════════════════════════════════════════════════════════════════════
section "31. SSH KNOWN HOSTS"
# ══════════════════════════════════════════════════════════════════════════════

subsection "User Known Hosts  (~/.ssh/known_hosts)"
if [[ -f "${CONSOLE_HOME}/.ssh/known_hosts" ]]; then
    table_header "$(printf '%-55s %s' 'Host/IP' 'Key Type')"
    awk '{printf "  %-55s %s\n", $1, $2}' "${CONSOLE_HOME}/.ssh/known_hosts" | head -60
else
    echo "  (none)"
fi

subsection "SSH Keys Present"
table_header "$(printf '%-45s %s' 'Key File' 'Type / Fingerprint')"
ls "${CONSOLE_HOME}/.ssh/"*.pub 2>/dev/null | while IFS= read -r k; do
    fp=$(ssh-keygen -lf "${k}" 2>/dev/null)
    printf '  %-45s %s\n' "$(basename "${k}")" "${fp}"
done || echo "  (no public keys found)"


# ══════════════════════════════════════════════════════════════════════════════
section "32. SBOM — SOFTWARE BILL OF MATERIALS"
# ══════════════════════════════════════════════════════════════════════════════
# Aggregated inventory of every software component on this machine.
# Format: Name | Version | Type | Source/Vendor | Install Path
# ══════════════════════════════════════════════════════════════════════════════

printf '\n'
table_header "$(printf '%-45s %-20s %-18s %-20s %s' 'Component' 'Version' 'Type' 'Source' 'Path')"

# ── macOS Apps ────────────────────────────────────────────────────────────────
system_profiler SPApplicationsDataType -json 2>/dev/null | \
python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for a in d.get('SPApplicationsDataType', [])[:300]:
        name = a.get('_name','')[:44]
        ver  = a.get('version','')[:19]
        src  = a.get('obtained_from','')[:19]
        path = a.get('path','')
        print(f'  {name:<45} {ver:<20} {\"mac-app\":<18} {src:<20} {path}')
except: pass
" 2>/dev/null

# ── Homebrew Formulae ─────────────────────────────────────────────────────────
if cmd_ok brew; then
    brew list --versions 2>/dev/null | head -300 | awk '{
        printf "  %-45s %-20s %-18s %-20s %s\n",
        $1, $2, "brew-formula", "Homebrew", "/opt/homebrew/Cellar/" $1
    }'

    # ── Homebrew Casks ────────────────────────────────────────────────────────
    brew list --cask --versions 2>/dev/null | head -150 | awk '{
        printf "  %-45s %-20s %-18s %-20s %s\n",
        $1, $2, "brew-cask", "Homebrew", "/opt/homebrew/Caskroom/" $1
    }'
fi

# ── Python Packages ───────────────────────────────────────────────────────────
{ pip3 list --format=json 2>/dev/null || /opt/homebrew/bin/pip3 list --format=json 2>/dev/null; } | \
python3 -c "
import sys, json
try:
    pkgs = json.load(sys.stdin)
    for p in pkgs[:300]:
        name = p.get('name','')[:44]
        ver  = p.get('version','')[:19]
        print(f'  {name:<45} {ver:<20} {\"pip-package\":<18} {\"PyPI\":<20} site-packages')
except: pass
" 2>/dev/null

# ── npm Global ────────────────────────────────────────────────────────────────
npm list -g --depth=0 --json 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for k,v in (d.get('dependencies') or {}).items():
        ver = (v or {}).get('version','')[:19]
        print(f'  {k:<45} {ver:<20} {\"npm-global\":<18} {\"npm\":<20} node_modules/{k}')
except: pass
" 2>/dev/null

# ── Ruby Gems ─────────────────────────────────────────────────────────────────
gem list 2>/dev/null | awk '{
    gsub(/[()]/,""); printf "  %-45s %-20s %-18s %-20s %s\n",
    $1, $2, "ruby-gem", "RubyGems", "gems/" $1
}' | head -100

# ── Go Binaries ───────────────────────────────────────────────────────────────
GOBIN="${CONSOLE_HOME}/go/bin"
if [[ -d "${GOBIN}" ]]; then
    ls -1 "${GOBIN}" | while IFS= read -r b; do
        printf '  %-45s %-20s %-18s %-20s %s\n' \
            "${b}" "—" "go-binary" "Go" "${GOBIN}/${b}"
    done
fi

# ── Cargo / Rust ──────────────────────────────────────────────────────────────
CARGOBIN="${CONSOLE_HOME}/.cargo/bin"
if [[ -d "${CARGOBIN}" ]]; then
    ls -1 "${CARGOBIN}" | while IFS= read -r b; do
        printf '  %-45s %-20s %-18s %-20s %s\n' \
            "${b}" "—" "cargo-binary" "crates.io" "${CARGOBIN}/${b}"
    done
fi

# ── System Packages (pkgutil) ─────────────────────────────────────────────────
pkgutil --pkgs 2>/dev/null | head -100 | while IFS= read -r pkg; do
    ver=$(pkgutil --pkg-info "${pkg}" 2>/dev/null | awk '/version:/{print $2}')
    printf '  %-45s %-20s %-18s %-20s %s\n' \
        "${pkg}" "${ver}" "macos-pkg" "Apple/Vendor" "pkgutil"
done

# ── Syft (if installed) ───────────────────────────────────────────────────────
if cmd_ok syft; then
    subsection "Syft SBOM (CycloneDX)"
    q syft / --output cyclonedx-json 2>/dev/null | \
        python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for c in d.get('components',[])[:200]:
        print(f\"  {c.get('name','')[:44]:<45} {c.get('version','')[:19]:<20} {c.get('type','')[:17]:<18}\")
except: pass
" || true
fi


# ══════════════════════════════════════════════════════════════════════════════
printf '\n%s\n' "${THICK}"
printf '  Snapshot complete: %s\n' "$(date)"
printf '  Total sections   : 32\n'
printf '  Saved to         : %s\n' "${REPORT}"
printf '%s\n\n' "${THICK}"
