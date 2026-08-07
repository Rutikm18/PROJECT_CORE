#!/usr/bin/env bash
# =============================================================================
#  install.sh — AttackLens one-command installer
#
#  Usage:
#    bash install.sh                    # interactive
#    bash install.sh --repair           # auto-fix deps and retry
#    SKIP_CONFIRM=1 bash install.sh     # non-interactive (CI/CD)
#    REPO_URL=https://... bash install.sh
#    REPO_DIR=/opt/attacklens bash install.sh
#
#  Exit codes:
#    0  success
#    1  unsupported OS / arch
#    2  dependency install failed
#    3  repo clone failed
#    4  docker compose failed
#    5  user cancelled
#    6  pre-flight check failed (disk, port, etc.)
#    7  health check failed
#    8  dependency version too old and cannot be upgraded
# =============================================================================

set -Eeuo pipefail

# ── Configurable ──────────────────────────────────────────────────────────────
REPO_URL="${REPO_URL:-https://github.com/your-org/attacklens.git}"
REPO_DIR="${REPO_DIR:-$HOME/attacklens}"
SKIP_CONFIRM="${SKIP_CONFIRM:-0}"
LOG_FILE="/tmp/attacklens-install-$(date +%s).log"
REPAIR_MODE="${REPAIR_MODE:-0}"

# Container app user — manager/threat-intel run as this uid/gid (see manager/Dockerfile:
# `useradd -m -u 1000 jarvis`). The compose bind-mounts host ./data and ./logs over
# /app/data and /app/logs, and a bind mount keeps the HOST dir's ownership — so these
# host dirs must be writable by this uid or the manager crashes writing manager.log.
CONTAINER_UID="${CONTAINER_UID:-1000}"
CONTAINER_GID="${CONTAINER_GID:-1000}"

# ── Minimum required versions ────────────────────────────────────────────────
DOCKER_MIN="25.0.0"
COMPOSE_MIN="2.27.0"
BUILDX_MIN="0.17.0"
BUILDKIT_MIN="0.16.0"

# ── Step progress ─────────────────────────────────────────────────────────────
TOTAL_STEPS=10
STEP_CURRENT=0

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Logging ───────────────────────────────────────────────────────────────────
banner() {
  clear 2>/dev/null || true
  echo ""
  echo -e "${CYN}${BLD}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║        AttackLens — One-Command Installer       ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

info()  { echo -e "   ${CYN}${DIM}ℹ${NC}  $*"; }
ok()    { echo -e "   ${GRN}✔${NC}  $*"; }
warn()  { echo -e "   ${YEL}⚠${NC}  $*"; }
fail()  { echo -e "\n   ${RED}✘${NC}  ${BLD}$*${NC}"; }
die()   { fail "$1"; exit "${2:-1}"; }

header() {
  STEP_CURRENT=$((STEP_CURRENT + 1))
  echo ""
  echo -e "${BLD}━━━ Step ${STEP_CURRENT}/${TOTAL_STEPS}: $* ━━━${NC}"
}

# ── Error trap ────────────────────────────────────────────────────────────────
err_trap() {
  local ec=$?
  local line=${BASH_LINENO[0]:-?}
  local func=${FUNCNAME[1]:-main}
  echo ""
  fail "Unexpected error at line ${line} in ${func} (exit ${ec})"
  echo ""
  warn "Full log saved to: ${LOG_FILE}"
  echo "   Last 10 lines:"
  tail -10 "${LOG_FILE}" 2>/dev/null | sed 's/^/   /' || true
  echo ""
  echo "   To retry with auto-repair:"
  echo "     bash install.sh --repair"
  echo ""
  echo "   To run diagnostics:"
  echo "     bash install.sh --doctor"
  echo ""
}
trap err_trap ERR

ctrl_c() {
  echo ""
  warn "Installation interrupted by user."
  exit 5
}
trap ctrl_c INT

exec > >(tee -a "${LOG_FILE}") 2>&1

# ── Argument parsing ──────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --repair)  REPAIR_MODE=1; SKIP_CONFIRM=1 ;;
    --doctor)
      # Delegate to the attacklens CLI if available
      if [ -f "$(dirname "$0")/attacklens" ]; then
        bash "$(dirname "$0")/attacklens" doctor
      else
        echo "Run: bash install.sh --repair  to diagnose and fix issues"
      fi
      exit 0
      ;;
    --upgrade-buildx)
      REPAIR_MODE=1; SKIP_CONFIRM=1
      ;;
  esac
done

# ── Semver comparison: semver_gte A B → true if A >= B ──────────────────────
semver_gte() {
  local a="${1#v}" b="${2#v}"
  local a1 a2 a3 b1 b2 b3
  IFS='.' read -r a1 a2 a3 <<< "${a%-*}"  # strip pre-release
  IFS='.' read -r b1 b2 b3 <<< "${b%-*}"
  a1=${a1:-0}; a2=${a2:-0}; a3=${a3:-0}
  b1=${b1:-0}; b2=${b2:-0}; b3=${b3:-0}
  if   [ "$a1" -gt "$b1" ]; then return 0
  elif [ "$a1" -lt "$b1" ]; then return 1
  elif [ "$a2" -gt "$b2" ]; then return 0
  elif [ "$a2" -lt "$b2" ]; then return 1
  elif [ "$a3" -ge "$b3" ]; then return 0
  else return 1
  fi
}

# ── Extract a version string (first X.Y.Z pattern in a string) ───────────────
extract_version() {
  echo "$1" | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "0.0.0"
}

# ── Sudo detection ────────────────────────────────────────────────────────────
detect_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    info "Running as root"
  else
    if ! command -v sudo &>/dev/null; then
      die "Not running as root and sudo not available." 6
    fi
    SUDO="sudo"
    info "Running as $(whoami), sudo available"
  fi
}

# ── OS / arch detection ──────────────────────────────────────────────────────
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-linux}"
    OS_LIKE="${ID_LIKE:-}"
    OS_NAME="${NAME:-Linux}"
    OS_VERSION="${VERSION_ID:-}"
  elif command -v sw_vers &>/dev/null; then
    OS_ID="macos"
    OS_LIKE=""
    OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '?')"
    OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo '')"
  else
    OS_ID="unknown"
    OS_LIKE=""
    OS_NAME="$(uname -s)"
    OS_VERSION=""
  fi

  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64)  ARCH_DOCKER="amd64" ;;
    aarch64|arm64) ARCH_DOCKER="arm64" ;;
    *) die "Unsupported architecture: ${ARCH}. Only amd64 and arm64 are supported." 1 ;;
  esac

  info "OS:   ${OS_NAME}${OS_VERSION:+ ${OS_VERSION}}"
  info "Arch: ${ARCH}"
  ok "System compatible"
}

# ── Package manager detection ─────────────────────────────────────────────────
detect_pkg_manager() {
  if   command -v apt-get &>/dev/null; then PKG_MGR="apt-get"
  elif command -v dnf     &>/dev/null; then PKG_MGR="dnf"
  elif command -v yum     &>/dev/null; then PKG_MGR="yum"
  elif command -v apk     &>/dev/null; then PKG_MGR="apk"
  elif command -v pacman  &>/dev/null; then PKG_MGR="pacman"
  elif command -v brew    &>/dev/null; then PKG_MGR="brew"
  else die "No supported package manager (apt/dnf/yum/apk/pacman/brew)" 1; fi
  info "Package manager: ${PKG_MGR}"

  # Amazon Linux 2023 flag — affects how Compose plugin is installed
  IS_AMAZON_LINUX=0
  if [ "$OS_ID" = "amzn" ] || echo "${OS_LIKE:-}" | grep -q "fedora"; then
    case "$OS_VERSION" in
      2023*) IS_AMAZON_LINUX=2023 ;;
      2*)    IS_AMAZON_LINUX=2 ;;
    esac
  fi
  if [ "${IS_AMAZON_LINUX}" != "0" ]; then
    info "Detected Amazon Linux ${IS_AMAZON_LINUX}"
  fi
}

# ── Install packages ──────────────────────────────────────────────────────────
install_pkgs() {
  local pkgs=("$@")
  local missing=()
  for pkg in "${pkgs[@]}"; do
    command -v "$pkg" &>/dev/null || missing+=("$pkg")
  done
  [ ${#missing[@]} -eq 0 ] && { ok "Packages already installed: ${pkgs[*]}"; return 0; }

  info "Installing: ${missing[*]}"
  case "$PKG_MGR" in
    apt-get)
      $SUDO apt-get update -qq 2>/dev/null
      $SUDO apt-get install -y -qq "${missing[@]}" 2>&1 | tail -2 || {
        for pkg in "${missing[@]}"; do
          $SUDO apt-get install -y -qq "$pkg" 2>/dev/null || warn "  Skipped: $pkg"
        done
      }
      ;;
    yum|dnf)
      $SUDO "$PKG_MGR" install -y -q "${missing[@]}" 2>&1 | tail -2 || {
        for pkg in "${missing[@]}"; do
          $SUDO "$PKG_MGR" install -y -q "$pkg" 2>/dev/null || warn "  Skipped: $pkg"
        done
      }
      ;;
    apk)   $SUDO apk add --quiet "${missing[@]}" 2>&1 | tail -2 || die "apk install failed" 2 ;;
    pacman) $SUDO pacman -S --noconfirm "${missing[@]}" 2>&1 | tail -2 || die "pacman failed" 2 ;;
    brew)   brew install "${missing[@]}" 2>&1 | tail -2 || die "brew install failed" 2 ;;
  esac

  local still_missing=()
  for pkg in "${missing[@]}"; do
    command -v "$pkg" &>/dev/null || still_missing+=("$pkg")
  done
  [ ${#still_missing[@]} -gt 0 ] && warn "Could not install: ${still_missing[*]} — continuing" || \
    ok "Installed: ${missing[*]}"
}

# ── Pre-flight: disk, RAM, ports, internet ────────────────────────────────────
preflight_checks() {
  local warnings=0

  # Disk — auto-clean before checking so apt/docker cache doesn't block installs
  local disk_avail
  disk_avail=$(df -m . 2>/dev/null | awk 'NR==2{print $4}' || echo "0")
  if [ "$disk_avail" -lt 5120 ]; then
    info "Disk low (${disk_avail}MB) — auto-cleaning package cache..."
    $SUDO apt-get clean -qq 2>/dev/null || true
    $SUDO apt-get autoremove -y -qq 2>/dev/null || true
    $SUDO journalctl --vacuum-size=50M 2>/dev/null || true
    if command -v docker &>/dev/null; then
      docker system prune -f --filter "until=24h" 2>/dev/null || true
    fi
    disk_avail=$(df -m . 2>/dev/null | awk 'NR==2{print $4}' || echo "0")
    info "Disk after cleanup: ${disk_avail}MB free"
  fi
  if [ "$disk_avail" -lt 3072 ]; then
    fail "Insufficient disk: ${disk_avail}MB available, need ≥ 3 GB"
    echo ""
    echo "   Fix options:"
    echo "   1. Expand your EBS volume (recommended):"
    echo "      AWS Console → EC2 → Volumes → Modify → increase to 20 GB"
    echo "      Then: sudo growpart /dev/xvda1 1 && sudo resize2fs /dev/xvda1"
    echo "   2. Free space manually:"
    echo "      sudo apt-get clean && sudo apt-get autoremove -y"
    echo "      docker system prune -af  (if Docker is installed)"
    die "Expand disk and re-run." 6
  elif [ "$disk_avail" -lt 5120 ]; then
    warn "Disk tight (${disk_avail}MB) — recommend ≥ 5 GB for production"
    warn "If the build fails, expand EBS volume: AWS Console → EC2 → Volumes → Modify"
    warnings=$((warnings + 1))
  else
    ok "Disk: ${disk_avail}MB free"
  fi

  # RAM
  local mem_mb
  mem_mb=$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo 2>/dev/null || echo "4096")
  if [ "$mem_mb" -lt 1024 ]; then
    warn "Low RAM: ${mem_mb}MB — will create swap"
    warnings=$((warnings + 1))
  else
    ok "RAM: ${mem_mb}MB"
  fi

  # Port conflicts
  for port in 80 443 8080 8443; do
    if command -v ss &>/dev/null && ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      local proc
      proc=$(ss -tlnp 2>/dev/null | grep ":${port} " | head -1 | \
        sed 's/.*users:(("//' | cut -d'"' -f1 || echo "unknown")
      warn "Port ${port} already in use${proc:+ by ${proc}}"
      warnings=$((warnings + 1))
    fi
  done

  # Internet connectivity
  if ! curl -fsSL --max-time 5 https://api.github.com &>/dev/null; then
    warn "Cannot reach github.com — buildx/compose downloads may fail"
    warnings=$((warnings + 1))
  else
    ok "Internet connectivity: OK"
  fi

  [ $warnings -gt 0 ] && warn "${warnings} warning(s) — Docker will handle port conflicts" || \
    ok "No port conflicts"
}

# ── Docker Engine installation ────────────────────────────────────────────────
install_docker_engine() {
  if command -v docker &>/dev/null; then
    local ver
    ver=$(extract_version "$(docker --version 2>/dev/null)")
    ok "Docker ${ver} already installed"
    if ! semver_gte "$ver" "$DOCKER_MIN"; then
      warn "Docker ${ver} < minimum ${DOCKER_MIN} — consider upgrading"
    fi
    return 0
  fi

  info "Installing Docker Engine..."
  case "$PKG_MGR" in
    apt-get)
      $SUDO apt-get update -qq 2>/dev/null
      $SUDO apt-get install -y -qq docker.io 2>&1 | tail -1 || {
        warn "docker.io package failed — trying official install script..."
        curl -fsSL https://get.docker.com 2>/dev/null | $SUDO bash 2>&1 | tail -5 || \
          die "Docker install failed. See: https://docs.docker.com/engine/install/" 2
      }
      ;;
    *)
      curl -fsSL https://get.docker.com 2>/dev/null | $SUDO bash 2>&1 | tail -5 || \
        die "Docker install failed. See: https://docs.docker.com/engine/install/" 2
      ;;
  esac
  command -v docker &>/dev/null || die "Docker binary not found after install." 2
  ok "Docker installed"
}

# ── Docker Compose v2 plugin installation ─────────────────────────────────────
install_docker_compose() {
  if docker compose version &>/dev/null 2>&1; then
    local ver
    ver=$(extract_version "$(docker compose version 2>/dev/null)")
    ok "Docker Compose ${ver} already installed"
    if ! semver_gte "$ver" "$COMPOSE_MIN"; then
      warn "Compose ${ver} < minimum ${COMPOSE_MIN} — upgrading via binary download"
      _install_compose_binary
    fi
    return 0
  fi

  info "Installing Docker Compose plugin..."

  # Amazon Linux 2023: docker-compose-plugin is NOT in dnf — skip straight to binary
  if [ "${IS_AMAZON_LINUX}" = "2023" ]; then
    warn "Amazon Linux 2023 — installing Compose via binary (not dnf)"
    _install_compose_binary
  else
    case "$PKG_MGR" in
      apt-get) $SUDO apt-get install -y -qq docker-compose-plugin 2>/dev/null || true ;;
      yum|dnf) $SUDO "$PKG_MGR" install -y -q docker-compose-plugin 2>/dev/null || true ;;
      *) : ;;
    esac
  fi

  # Verify; fallback to binary if plugin not available
  if ! docker compose version &>/dev/null 2>&1; then
    warn "Package install failed — falling back to binary download"
    _install_compose_binary
  fi

  docker compose version &>/dev/null 2>&1 || \
    die "Docker Compose v2 unavailable. Install: https://docs.docker.com/compose/install/" 2

  local ver
  ver=$(extract_version "$(docker compose version 2>/dev/null)")
  ok "Docker Compose ${ver} installed"
}

_install_compose_binary() {
  local os arch ver
  os=$(uname -s)
  arch=$(uname -m)
  # Resolve latest compose version from GitHub API
  ver=$(curl -fsSL --max-time 10 \
    https://api.github.com/repos/docker/compose/releases/latest 2>/dev/null | \
    grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/' || echo "2.29.0")
  local url="https://github.com/docker/compose/releases/download/v${ver}/docker-compose-${os}-${arch}"
  info "Downloading Docker Compose v${ver}..."
  $SUDO mkdir -p /usr/local/lib/docker/cli-plugins
  if curl -fsSL --max-time 120 "$url" -o /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null; then
    $SUDO chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    ok "Docker Compose v${ver} installed via binary"
  else
    warn "Could not download Compose binary from GitHub"
  fi
}

# ── Buildx install / upgrade ─────────────────────────────────────────────────
check_and_upgrade_buildx() {
  local current_ver="0.0.0"

  if docker buildx version &>/dev/null 2>&1; then
    current_ver=$(extract_version "$(docker buildx version 2>/dev/null)")
    if semver_gte "$current_ver" "$BUILDX_MIN"; then
      ok "Buildx ${current_ver} ✔ (≥ ${BUILDX_MIN} required)"
      return 0
    else
      warn "Buildx ${current_ver} is below minimum ${BUILDX_MIN} — upgrading"
    fi
  else
    warn "Buildx not found — installing"
  fi

  _install_buildx_binary

  # Re-check
  local new_ver
  new_ver=$(extract_version "$(docker buildx version 2>/dev/null || echo '0.0.0')")
  if semver_gte "$new_ver" "$BUILDX_MIN"; then
    ok "Buildx ${new_ver} installed ✔"
  else
    fail "Buildx ${new_ver} after upgrade — still below ${BUILDX_MIN}"
    echo ""
    echo "   Manual install:"
    echo "     https://github.com/docker/buildx/releases"
    echo "     Place binary in /usr/local/lib/docker/cli-plugins/docker-buildx"
    echo "     chmod +x ..."
    die "Buildx upgrade failed." 8
  fi
}

_install_buildx_binary() {
  local os arch ver
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch="$ARCH_DOCKER"
  # Fetch latest from GitHub; fall back to a known-good version
  ver=$(curl -fsSL --max-time 10 \
    https://api.github.com/repos/docker/buildx/releases/latest 2>/dev/null | \
    grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/' || echo "0.21.1")
  local url="https://github.com/docker/buildx/releases/download/v${ver}/buildx-v${ver}.${os}-${arch}"
  info "Downloading Buildx v${ver} from GitHub..."
  $SUDO mkdir -p /usr/local/lib/docker/cli-plugins
  if curl -fsSL --max-time 120 "$url" -o /usr/local/lib/docker/cli-plugins/docker-buildx 2>/dev/null; then
    $SUDO chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
  else
    warn "Download failed — trying fallback version 0.21.1..."
    local fb_url="https://github.com/docker/buildx/releases/download/v0.21.1/buildx-v0.21.1.${os}-${arch}"
    curl -fsSL --max-time 120 "$fb_url" -o /usr/local/lib/docker/cli-plugins/docker-buildx && \
      $SUDO chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx || \
      warn "Fallback download also failed"
  fi
}

# ── BuildKit builder creation ────────────────────────────────────────────────
BUILDER_NAME="attacklens-builder"

create_buildkit_builder() {
  # Check if our named builder already exists and is usable
  if docker buildx inspect "$BUILDER_NAME" &>/dev/null 2>&1; then
    local bk_ver
    bk_ver=$(docker buildx inspect "$BUILDER_NAME" 2>/dev/null | \
      grep -i "buildkit" | grep -oP 'v?\d+\.\d+\.\d+' | head -1 || echo "?")
    ok "BuildKit builder '${BUILDER_NAME}' exists (BuildKit ${bk_ver})"
    docker buildx use "$BUILDER_NAME" 2>/dev/null || true
    return 0
  fi

  # Check if default builder has a modern BuildKit
  local default_bk_ver
  default_bk_ver=$(docker buildx inspect default 2>/dev/null | \
    grep -i "buildkit" | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "0.0.0")
  if semver_gte "$default_bk_ver" "$BUILDKIT_MIN"; then
    ok "Default BuildKit builder v${default_bk_ver} is sufficient"
    return 0
  fi

  # Create a modern builder
  info "Creating BuildKit builder '${BUILDER_NAME}' (default BuildKit ${default_bk_ver} < ${BUILDKIT_MIN})..."
  if docker buildx create \
      --name "$BUILDER_NAME" \
      --driver docker-container \
      --driver-opt network=host \
      --use \
      --bootstrap 2>&1 | tail -3; then
    local new_ver
    new_ver=$(docker buildx inspect "$BUILDER_NAME" 2>/dev/null | \
      grep -i "buildkit" | grep -oP 'v?\d+\.\d+\.\d+' | head -1 || echo "?")
    ok "BuildKit builder '${BUILDER_NAME}' ready (BuildKit ${new_ver})"
  else
    warn "Could not create named builder — using default"
    docker buildx use default 2>/dev/null || true
  fi
}

# ── Start Docker daemon ───────────────────────────────────────────────────────
start_docker_daemon() {
  if command -v systemctl &>/dev/null; then
    $SUDO systemctl enable docker 2>/dev/null || true
    if ! $SUDO systemctl is-active --quiet docker 2>/dev/null; then
      info "Starting Docker daemon..."
      $SUDO systemctl start docker 2>/dev/null || \
        $SUDO service docker start 2>/dev/null || \
        warn "Could not start Docker — try: sudo systemctl start docker"
    fi
  fi

  local retries=5
  while [ $retries -gt 0 ]; do
    docker info &>/dev/null 2>&1 && { ok "Docker daemon running"; return 0; }
    retries=$((retries - 1))
    info "Waiting for Docker daemon... ($((5 - retries))/5)"
    sleep 2
  done
  fail "Docker daemon not responding"
  warn "Run: sudo systemctl start docker"
  die "Cannot continue without Docker daemon." 2
}

# ── Combined Docker step ─────────────────────────────────────────────────────
install_docker() {
  install_docker_engine
  install_docker_compose
  start_docker_daemon

  # Add user to docker group
  if [ "$(id -u)" -ne 0 ] && ! groups "${USER:-root}" 2>/dev/null | grep -qw docker; then
    $SUDO usermod -aG docker "${USER:-root}" 2>/dev/null || true
    DOCKER_GROUP_CHANGED=true
    warn "Added to 'docker' group — run 'newgrp docker' or re-login if commands fail"
  fi
}

# ── Swap ──────────────────────────────────────────────────────────────────────
setup_swap() {
  [ -f /swapfile ] && return 0
  [ "$OS_ID" = "macos" ] && return 0
  local mem_mb
  mem_mb=$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo 2>/dev/null || echo "4096")
  if [ "$mem_mb" -le 2048 ]; then
    warn "RAM ${mem_mb}MB — creating 2 GB swap"
    $SUDO fallocate -l 2G /swapfile 2>/dev/null || \
      $SUDO dd if=/dev/zero of=/swapfile bs=1M count=2048 2>/dev/null
    $SUDO chmod 600 /swapfile
    $SUDO mkswap /swapfile 2>/dev/null
    $SUDO swapon /swapfile 2>/dev/null
    grep -q swapfile /etc/fstab 2>/dev/null || \
      echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab > /dev/null
    ok "Swap enabled (2 GB)"
  fi
}

# ── Clone or update repo ─────────────────────────────────────────────────────
setup_repo() {
  if [ -d "$REPO_DIR/.git" ]; then
    info "Repo exists at ${REPO_DIR}"
    cd "$REPO_DIR"
    if [ "$SKIP_CONFIRM" = "1" ]; then
      git pull --ff-only 2>&1 | tail -2 || warn "git pull failed — using current files"
    else
      read -rp "  Pull latest? [Y/n]: " PULL
      [[ "${PULL:-y}" =~ ^[Yy] ]] && \
        { git pull --ff-only 2>&1 | tail -2 || warn "git pull failed"; } || \
        info "Using existing files"
    fi
    ok "Repository ready"
  elif [ -d "$REPO_DIR" ]; then
    warn "${REPO_DIR} exists but is not a git repo — using as-is"
    cd "$REPO_DIR"
  else
    info "Cloning ${REPO_URL}..."
    if git clone "$REPO_URL" "$REPO_DIR" 2>&1 | tail -3; then
      ok "Repository cloned"
      cd "$REPO_DIR"
    else
      fail "Clone from ${REPO_URL} failed"
      if [ "$SKIP_CONFIRM" = "1" ]; then
        die "Clone failed. Set REPO_URL env var to your fork." 3
      fi
      read -rp "  Enter git URL (or Enter to use current dir): " CUSTOM_URL
      if [ -n "${CUSTOM_URL:-}" ]; then
        git clone "$CUSTOM_URL" "$REPO_DIR" 2>&1 | tail -3 || die "Clone failed." 3
        cd "$REPO_DIR"
        ok "Repository cloned"
      else
        mkdir -p "$REPO_DIR"; cd "$REPO_DIR"
        warn "No repo cloned — place files in ${REPO_DIR} manually"
      fi
    fi
  fi

  [ -f docker-compose.yml ] || die "docker-compose.yml not found in ${REPO_DIR}." 3
  ok "docker-compose.yml found"
}

# ── Config ────────────────────────────────────────────────────────────────────
setup_config() {
  if [ -f .env ]; then
    info ".env exists — reusing"
    if [ ! -f Caddyfile ] && [ -f env.sh ]; then
      bash env.sh || _write_minimal_caddyfile
    fi
    if [ ! -f Caddyfile ]; then _write_minimal_caddyfile; fi
    ok "Config ready"
    return 0
  fi

  if [ -f env.sh ]; then
    if [ "$SKIP_CONFIRM" = "1" ]; then
      info "Non-interactive — generating minimal .env"
      local public_ip="" admin_token
      for url in "https://api.ipify.org" "https://ifconfig.me"; do
        public_ip=$(curl -fsSL --max-time 3 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        [ -n "$public_ip" ] && break
      done
      admin_token="sk-admin-$(openssl rand -hex 12 2>/dev/null || head -c 12 /dev/urandom | xxd -p)"
      _write_minimal_env "$public_ip" "$admin_token"
      _write_minimal_caddyfile
      ok "Minimal config generated"
      info "Admin token: ${admin_token}"
    else
      info "Running interactive setup..."
      bash env.sh || { warn "env.sh failed — creating minimal config"; _write_minimal_env "" ""; _write_minimal_caddyfile; }
    fi
  else
    warn "env.sh not found — creating minimal .env"
    _write_minimal_env "" ""
    _write_minimal_caddyfile
    ok "Minimal .env created"
  fi

  grep -q "BIND_PORT" .env 2>/dev/null || echo "BIND_PORT=8443" >> .env
}

_write_minimal_env() {
  cat > .env <<-EOF
PUBLIC_IP=${1:-}
DOMAIN=
BIND_PORT=8443
TLS_MODE=self-signed
ADMIN_TOKEN=${2:-}
OPEN_ENROLLMENT=true
LOG_LEVEL=info
CORS_ORIGINS=*
EOF
}

_write_minimal_caddyfile() {
  cat > Caddyfile <<-CADDY
{
    local_certs
    admin off
}

:80 {
    redir https://{host}:8443{uri} permanent
}

:8443 {
    tls internal

    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options    "nosniff"
        X-Frame-Options           "DENY"
        Referrer-Policy           "strict-origin-when-cross-origin"
        -Server
    }

    reverse_proxy manager:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
CADDY
}

# ── Pull images / build ───────────────────────────────────────────────────────
pull_images() {
  info "Pulling images (~1.5 GB, may take a few minutes)..."
  if docker compose pull 2>&1 | tail -8; then
    ok "Images pulled"
    return 0
  fi

  warn "Pull failed — building from source..."
  info "Using builder: $(docker buildx inspect --bootstrap 2>/dev/null | grep 'Name:' | head -1 | awk '{print $2}' || echo 'default')"

  local build_log
  build_log=$(mktemp)
  if docker compose build 2>&1 | tee "$build_log" | tail -15; then
    rm -f "$build_log"
    ok "Images built from source"
    return 0
  fi

  # Interpret the most common build failure: old Buildx
  if grep -q "requires buildx" "$build_log" 2>/dev/null || \
     grep -q "buildx.*0\." "$build_log" 2>/dev/null; then
    rm -f "$build_log"
    echo ""
    fail "Build failed because Buildx is too old."
    echo ""
    echo -e "   ${BLD}Required:${NC}  Buildx ≥ ${BUILDX_MIN}"
    echo -e "   ${BLD}Detected:${NC}  $(extract_version "$(docker buildx version 2>/dev/null || echo '?')")"
    echo ""
    echo "   Auto-fix:"
    echo "     bash install.sh --repair"
    echo ""
    echo "   Manual fix:"
    echo "     https://github.com/docker/buildx/releases"
    die "Build failed: Buildx too old." 8
  fi

  rm -f "$build_log"
  fail "Image pull and build both failed — see log: ${LOG_FILE}"
  diagnose_failure
  die "Cannot continue without images." 4
}

# ── Bind-mount ownership (prevents the #1 first-boot manager crash) ───────────
# The manager container runs as uid $CONTAINER_UID but ./data and ./logs are
# bind-mounted over /app/data and /app/logs. If the repo was cloned/run as root,
# those host dirs are root-owned and the container user cannot create
# /app/logs/manager.log → the manager aborts in startup() with:
#     PermissionError: [Errno 13] Permission denied: '/app/logs/manager.log'
# → container is "unhealthy" → Caddy's depends_on fails → whole deploy fails.
# Pre-creating the dirs and handing them to the container uid makes first boot work.
prepare_bind_mounts() {
  # Let .env (APP_UID/APP_GID, written by env.sh) drive the target ownership so
  # the host chown and the container user can never drift apart.
  if [ -f .env ]; then
    local env_uid env_gid
    env_uid=$(grep -oP '^APP_UID=\K.*' .env 2>/dev/null | head -1 || true)
    env_gid=$(grep -oP '^APP_GID=\K.*' .env 2>/dev/null | head -1 || true)
    [ -n "${env_uid:-}" ] && CONTAINER_UID="$env_uid"
    [ -n "${env_gid:-}" ] && CONTAINER_GID="$env_gid"
  fi
  info "Preparing ./data and ./logs for container uid ${CONTAINER_UID}..."
  # Pre-create the exact dirs the manager writes on first boot (tiered store +
  # threat-intel's own data subdir) so ownership is correct before any mount.
  $SUDO mkdir -p data/hot data/warm data/cold data/threat-intel logs
  if $SUDO chown -R "${CONTAINER_UID}:${CONTAINER_GID}" data logs 2>/dev/null; then
    # Owner + group rwX (X = dir-traverse only, no spurious +x on files). No 777.
    $SUDO chmod -R u+rwX,g+rwX data logs 2>/dev/null || true
    ok "data/ and logs/ owned by uid ${CONTAINER_UID} (u+rwX,g+rwX)"
  else
    warn "Could not chown data/ logs/ to uid ${CONTAINER_UID} — the manager may fail to write its log"
    warn "Fix manually: chown -R ${CONTAINER_UID}:${CONTAINER_GID} data logs"
  fi
}

# Detect + repair the root-owned bind-mount case after a failed start. Returns 0
# only when it actually recognized the permission error and applied a fix, so the
# caller knows a retry is worthwhile.
fix_bind_mount_permissions() {
  docker compose logs manager 2>/dev/null \
    | grep -qiE "Permission denied: '/app/(logs|data)" || return 1
  warn "Manager crashed writing /app/logs (host bind mount not writable by uid ${CONTAINER_UID})."
  $SUDO mkdir -p data logs data/threat-intel
  if $SUDO chown -R "${CONTAINER_UID}:${CONTAINER_GID}" data logs 2>/dev/null \
     || $SUDO chmod -R 777 data logs 2>/dev/null; then
    ok "Reset ownership of data/ and logs/ — safe to retry"
    return 0
  fi
  return 1
}

# Prove the container user can actually write the bind mounts BEFORE we bring up
# the whole stack — using the real image/user, so it catches ownership problems
# that a host-side `test -w` would miss (e.g. root-owned mount, SELinux label,
# rootless-Docker uid remapping). Fail fast with a clear message instead of a
# cryptic mid-startup PermissionError.
preflight_write_test() {
  info "Verifying container can write /app/data and /app/logs..."
  if docker compose run --rm --no-deps --entrypoint sh manager -c '
        set -e
        mkdir -p /app/data/hot
        touch /app/data/hot/.write-test && rm -f /app/data/hot/.write-test
        touch /app/logs/.write-test    && rm -f /app/logs/.write-test
      ' >/dev/null 2>&1; then
    ok "Container write test passed"
    return 0
  fi
  warn "Container cannot write the bind mounts — attempting ownership fix..."
  prepare_bind_mounts
  if docker compose run --rm --no-deps --entrypoint sh manager -c '
        set -e; touch /app/data/hot/.write-test && rm -f /app/data/hot/.write-test
        touch /app/logs/.write-test && rm -f /app/logs/.write-test' >/dev/null 2>&1; then
    ok "Container write test passed after ownership fix"
    return 0
  fi
  fail "Container user (uid ${CONTAINER_UID}) still cannot write ./data or ./logs."
  echo "   Fix:  $SUDO chown -R ${CONTAINER_UID}:${CONTAINER_GID} data logs"
  echo "   Then: docker compose up -d"
  die "Bind-mount write test failed — refusing to start with unwritable volumes." 4
}

# ── Start containers ─────────────────────────────────────────────────────────
start_services() {
  prepare_bind_mounts
  preflight_write_test

  if docker compose ps -q 2>/dev/null | grep -q .; then
    info "Stopping existing containers..."
    docker compose down --remove-orphans 2>&1 | tail -2 || true
  fi

  info "Starting all services..."
  if docker compose up -d --remove-orphans 2>&1 | tail -10; then
    ok "Services started"
  else
    warn "First attempt failed — retrying with --build..."
    if docker compose up -d --remove-orphans --build 2>&1 | tail -15; then
      ok "Services started (with rebuild)"
    elif fix_bind_mount_permissions && \
         docker compose up -d --remove-orphans 2>&1 | tail -15; then
      ok "Services started (after bind-mount permission fix)"
    else
      fail "Could not start containers"
      diagnose_failure
      die "Container startup failed." 4
    fi
  fi

  sleep 3
  local total started
  total=$(docker compose ps -q 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  started=$(docker compose ps --filter "status=running" -q 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  if [ "$started" -lt "$total" ]; then
    warn "${started}/${total} containers running — some may still be initializing"
  else
    ok "All ${total} containers running"
  fi
}

# ── Diagnostics ───────────────────────────────────────────────────────────────
diagnose_failure() {
  echo ""
  warn "Diagnosing..."

  docker info &>/dev/null 2>&1 || { fail "Docker daemon not running"; echo "   Fix: sudo systemctl start docker"; return; }

  for port in 80 443 8080 8443 5432 5672; do
    if command -v ss &>/dev/null && ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      local proc
      proc=$(ss -tlnp 2>/dev/null | grep ":${port} " | head -1 | sed 's/.*users:(("//' | cut -d'"' -f1 || echo "?")
      warn "Port ${port} in use: ${proc}"
    fi
  done

  # Targeted: the manager's most common first-boot failure — it can't write its
  # log/data dir because the host bind mount is owned by root, not uid $CONTAINER_UID.
  if docker compose logs manager 2>/dev/null | grep -qiE "Permission denied: '/app/(logs|data)"; then
    fail "Manager cannot write to /app/logs or /app/data (host bind mount owned by root)."
    echo "   Container runs as uid ${CONTAINER_UID}; host ./data and ./logs must be writable by it."
    echo "   Fix:"
    echo "     $SUDO chown -R ${CONTAINER_UID}:${CONTAINER_GID} data logs && docker compose up -d"
  fi

  echo ""
  info "Container status:"
  docker compose ps -a 2>/dev/null || true

  # Bind-mount ownership is the usual manager-crash culprit — surface it plainly.
  echo ""
  info "Manager bind mounts (source -> destination):"
  docker inspect attacklens-manager \
    --format '{{range .Mounts}}   {{println .Source "->" .Destination}}{{end}}' 2>/dev/null || true
  info "Host directory ownership (want uid ${CONTAINER_UID}):"
  ls -ld data logs data/hot 2>/dev/null | sed 's/^/   /' || true

  echo ""
  info "Recent logs per service (manager gets a deeper tail — its traceback lives here):"
  for svc in manager postgres rabbitmq caddy threat-intel; do
    local n tail_n=15
    [ "$svc" = "manager" ] && tail_n=100
    n=$(docker compose logs --tail="$tail_n" "$svc" 2>/dev/null | wc -l || echo "0")
    if [ "$n" -gt 0 ]; then
      echo -e "\n  ${BLD}── ${svc} ──${NC}"
      docker compose logs --tail="$tail_n" "$svc" 2>/dev/null | sed 's/^/  /' || true
    fi
  done

  local disk_avail
  disk_avail=$(df -m . 2>/dev/null | awk 'NR==2{print $4}' || echo "?")
  if [ "$disk_avail" -lt 1024 ] 2>/dev/null; then
    fail "Disk full — Docker cannot create containers"
    echo "   Fix: docker system prune -af"
  fi
  if [ ! -f .env ]; then
    fail ".env missing — run: bash env.sh"
  fi
}

# ── Health check ──────────────────────────────────────────────────────────────
wait_healthy() {
  info "Waiting for manager to become healthy (up to 120s)..."
  local max=40 attempt=0

  while [ $attempt -lt $max ]; do
    attempt=$((attempt + 1))
    if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
      echo ""
      ok "Manager healthy (attempt ${attempt}/${max})"
      return 0
    fi

    if [ $attempt -eq 10 ]; then
      local st
      st=$(docker compose ps manager --format '{{.Status}}' 2>/dev/null | head -1 || echo "?")
      if echo "$st" | grep -qi "exited\|restarting"; then
        warn "Manager not running (${st}) — restarting..."
        docker compose restart manager 2>/dev/null || true
        sleep 5
      fi
    fi

    printf "."
    sleep 3
  done

  echo ""
  fail "Health check timed out after 120s"
  diagnose_failure
  return 1
}

# ── Post-install verification ────────────────────────────────────────────────
verify_deployment() {
  local all_ok=true

  for svc in postgres rabbitmq caddy manager threat-intel; do
    local st
    st=$(docker compose ps "$svc" --format '{{.Status}}' 2>/dev/null | head -1 || echo "not found")
    if echo "$st" | grep -qi "up\|healthy"; then
      ok "${svc}: ${st}"
    else
      warn "${svc}: ${st:-not found}"
      all_ok=false
    fi
  done

  curl -sf http://localhost:8080/health 2>/dev/null | grep -q "." && \
    ok "Manager API responding" || { warn "Manager API not responding on :8080"; all_ok=false; }

  docker compose exec -T postgres pg_isready -U attacklens &>/dev/null 2>&1 && \
    ok "Postgres ready" || warn "Postgres not ready yet"

  docker compose exec -T rabbitmq rabbitmq-diagnostics check_port_listener 5672 &>/dev/null 2>&1 && \
    ok "RabbitMQ ready" || warn "RabbitMQ not ready yet"

  # ── Databases exist (all three, or the manager can't start) ─────────────────
  local pg_user dbs
  pg_user=$(grep -oP '^POSTGRES_USER=\K.*' .env 2>/dev/null | head -1 || echo "attacklens")
  pg_user="${pg_user:-attacklens}"
  dbs=$(docker compose exec -T postgres psql -U "$pg_user" -d postgres -tAc \
        "SELECT datname FROM pg_database WHERE datname IN ('manager','intel','threat_intel');" \
        2>/dev/null | tr -d ' ' | sort | tr '\n' ' ' || echo "")
  for db in manager intel threat_intel; do
    if echo " $dbs " | grep -q " $db "; then
      ok "Database '${db}' exists"
    else
      warn "Database '${db}' MISSING — if this is a re-deploy on an old volume, run: docker compose down -v && bash install.sh"
      all_ok=false
    fi
  done

  # ── Internal services must NOT be internet-exposed ──────────────────────────
  if command -v ss &>/dev/null; then
    for port in 5432 5672 15672; do
      if ss -tlnp 2>/dev/null | grep -E ":${port} " | grep -qE '0\.0\.0\.0|\[::\]|\*:'; then
        fail "SECURITY: port ${port} is listening on a public interface (0.0.0.0)."
        echo "   It must be loopback-only. Pull latest compose (binds 127.0.0.1) and re-up,"
        echo "   or block it: $SUDO iptables -I DOCKER-USER -p tcp --dport ${port} -j DROP"
        all_ok=false
      else
        ok "Port ${port} not publicly exposed"
      fi
    done
  fi

  [ "$all_ok" = false ] && warn "Some checks need attention — review the messages above and: docker compose ps"
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
  local public_ip=""
  for url in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://ifconfig.me"; do
    public_ip=$(curl -fsSL --max-time 3 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    [ -n "$public_ip" ] && break
  done
  public_ip="${public_ip:-<your-server-ip>}"

  local bind_port domain admin_token
  bind_port=$(grep -oP '^BIND_PORT=\K.*' .env 2>/dev/null | head -1 || echo "8443")
  domain=$(grep -oP '^DOMAIN=\K.*' .env 2>/dev/null | head -1 || echo "")
  admin_token=$(grep -oP '^ADMIN_TOKEN=\K.*' .env 2>/dev/null | head -1 || echo "")

  local mgr_url
  if [ -n "$domain" ]; then mgr_url="https://${domain}"; else mgr_url="https://${public_ip}:${bind_port}"; fi

  echo ""
  echo -e "${GRN}${BLD}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║          AttackLens is running!                 ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo ""
  echo -e "  ${BLD}Dashboard:${NC}    ${mgr_url}"
  echo -e "  ${BLD}Health:${NC}       ${mgr_url}/health"
  if [ -n "$admin_token" ]; then echo -e "  ${BLD}Admin token:${NC}  ${admin_token}"; fi
  echo ""
  echo -e "  ${BLD}Useful commands:${NC}"
  echo "    docker compose logs -f            # live logs"
  echo "    docker compose ps                 # status"
  echo "    docker compose restart manager    # restart a service"
  echo "    bash install.sh --doctor          # run diagnostics"
  echo "    bash install.sh --repair          # fix deps and retry"
  echo ""
  echo -e "  ${BLD}Agent config (agent.toml):${NC}"
  echo "    url        = \"${mgr_url}\""
  echo "    tls_verify = ${domain:+true}${domain:-false}"
  echo ""
  if [ "${DOCKER_GROUP_CHANGED:-false}" = true ]; then
    warn "Run 'newgrp docker' or log out/in for docker group changes"
  fi
  echo -e "  ${DIM}Install log: ${LOG_FILE}${NC}"
  echo ""
}

# ── Repair mode: just upgrade deps and retry ──────────────────────────────────
run_repair() {
  banner
  echo ""
  info "Repair mode — upgrading Docker dependencies and retrying..."
  echo ""

  STEP_CURRENT=0
  TOTAL_STEPS=4

  header "System detection"
  detect_sudo
  detect_os
  detect_pkg_manager
  ok "System detected"

  header "Upgrade Buildx"
  _install_buildx_binary
  local ver
  ver=$(extract_version "$(docker buildx version 2>/dev/null || echo '0.0.0')")
  if semver_gte "$ver" "$BUILDX_MIN"; then
    ok "Buildx ${ver} ✔"
  else
    fail "Buildx ${ver} still below ${BUILDX_MIN} after upgrade"
    echo "   Manual: https://github.com/docker/buildx/releases"
    exit 8
  fi

  header "Upgrade/install Docker Compose"
  _install_compose_binary
  docker compose version &>/dev/null 2>&1 && ok "Compose ready" || warn "Compose still unavailable"

  header "Create BuildKit builder"
  create_buildkit_builder

  echo ""
  ok "Repair complete. Re-run installer:"
  echo "    bash install.sh"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  if [ "$REPAIR_MODE" = "1" ]; then
    run_repair
    exit 0
  fi

  banner

  echo ""
  info "This installer will:"
  echo ""
  printf "   %2s. System detection\n"            1
  printf "   %2s. Pre-flight checks\n"           2
  printf "   %2s. System packages\n"             3
  printf "   %2s. Docker Engine + Compose\n"     4
  printf "   %2s. Buildx + BuildKit builder\n"   5
  printf "   %2s. Clone repository\n"            6
  printf "   %2s. Generate configuration\n"      7
  printf "   %2s. Pull / build images\n"         8
  printf "   %2s. Start services\n"              9
  printf "   %2s. Health check + summary\n"      10
  echo ""

  if [ "$SKIP_CONFIRM" != "1" ]; then
    read -rp "  Continue? [Y/n]: " CONFIRM
    CONFIRM="${CONFIRM:-y}"
    [[ ! "$CONFIRM" =~ ^[Yy] ]] && { info "Cancelled."; exit 5; }
  fi

  header "System detection"
  detect_sudo
  detect_os
  detect_pkg_manager

  header "Pre-flight checks"
  preflight_checks

  header "System packages"
  install_pkgs curl git jq
  command -v python3 &>/dev/null || install_pkgs python3

  header "Docker Engine + Compose"
  install_docker

  header "Buildx + BuildKit builder"
  check_and_upgrade_buildx
  create_buildkit_builder

  header "Clone repository"
  setup_swap
  setup_repo

  header "Generate configuration"
  setup_config

  header "Pull / build images"
  pull_images

  header "Start services"
  start_services

  header "Health check + verification"
  wait_healthy || true
  verify_deployment
  print_summary
}

main "$@"
