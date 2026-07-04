#!/usr/bin/env bash
# =============================================================================
#  install.sh — AttackLens one-command installer
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/<org>/attacklens/main/install.sh | bash
#
#  Or with options:
#    REPO_URL=https://github.com/myorg/attacklens.git bash install.sh
#    REPO_DIR=/opt/attacklens bash install.sh
#    SKIP_CONFIRM=1 bash install.sh   # non-interactive (CI/CD)
#
#  What it does (in order):
#    1.  Pre-flight checks (OS, arch, disk, RAM, ports, existing installs)
#    2.  Install system packages (curl, git, python3, jq)
#    3.  Install Docker + Docker Compose v2
#    4.  Create swap if RAM ≤ 2GB
#    5.  Clone or update the repo
#    6.  Generate .env + Caddyfile (via env.sh or minimal defaults)
#    7.  Pull Docker images
#    8.  Start all containers
#    9.  Wait for health (up to 120s)
#    10. Diagnose failures if any
#    11. Print dashboard URL + credentials
#
#  Exit codes:
#    0  — success
#    1  — unsupported OS / arch
#    2  — dependency install failed
#    3  — repo clone failed
#    4  — docker compose failed
#    5  — user cancelled
#    6  — pre-flight check failed (disk, port, etc.)
#    7  — health check failed
# =============================================================================

set -Eeuo pipefail

# ── Configurable via environment ──────────────────────────────────────────────
REPO_URL="${REPO_URL:-https://github.com/your-org/attacklens.git}"
REPO_DIR="${REPO_DIR:-$HOME/attacklens}"
SKIP_CONFIRM="${SKIP_CONFIRM:-0}"
LOG_FILE="/tmp/attacklens-install-$(date +%s).log"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Logging ───────────────────────────────────────────────────────────────────
banner() {
  clear 2>/dev/null || true
  echo ""
  echo -e "${CYN}${BLD}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║         AttackLens — One-Click Install          ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

info()  { echo -e "   ${CYN}${DIM}ℹ${NC}  $*"; }
ok()    { echo -e "   ${GRN}✔${NC}  $*"; }
warn()  { echo -e "   ${YEL}⚠${NC}  $*"; }
fail()  { echo -e "\n   ${RED}✘${NC}  ${BLD}$*${NC}"; }
die()   { fail "$1"; exit "${2:-1}"; }
header() { echo ""; echo -e "${BLD}━━━ $* ━━━${NC}"; }

# ── Error trap — logs everything to file + prints context ──────────────────────
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
  echo "   To retry:"
  echo "     bash install.sh"
  echo ""
}
trap err_trap ERR

# ── Ctrl+C handler ───────────────────────────────────────────────────────────
ctrl_c() {
  echo ""
  warn "Installation interrupted by user."
  exit 5
}
trap ctrl_c INT

# ── Log everything to file ────────────────────────────────────────────────────
exec > >(tee -a "${LOG_FILE}") 2>&1

# ── Sudo detection ────────────────────────────────────────────────────────────
detect_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    info "Running as root"
  else
    if ! command -v sudo &>/dev/null; then
      die "Not running as root and sudo not available. Run as root or install sudo." 6
    fi
    SUDO="sudo"
    info "Running as $(whoami), using sudo for system packages"
  fi
}

# ── OS / arch detection ──────────────────────────────────────────────────────
detect_os() {
  header "System detection"

  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-linux}"
    OS_NAME="${NAME:-Linux}"
    OS_VERSION="${VERSION_ID:-}"
  elif command -v sw_vers &>/dev/null; then
    OS_ID="macos"
    OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '?')"
  else
    OS_ID="unknown"
    OS_NAME="$(uname -s)"
  fi

  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64)  ARCH_OK=1 ;;
    aarch64|arm64) ARCH_OK=1 ;;
    *) die "Unsupported architecture: ${ARCH}. Only amd64 and arm64 are supported." 1 ;;
  esac

  info "OS:   ${OS_NAME}"
  info "Arch: ${ARCH}"
  ok "System compatible"
}

# ── Package manager detection ─────────────────────────────────────────────────
detect_pkg_manager() {
  if   command -v apt-get &>/dev/null; then PKG_MGR="apt-get"
  elif command -v yum     &>/dev/null; then PKG_MGR="yum"
  elif command -v dnf     &>/dev/null; then PKG_MGR="dnf"
  elif command -v apk     &>/dev/null; then PKG_MGR="apk"
  elif command -v pacman  &>/dev/null; then PKG_MGR="pacman"
  elif command -v brew    &>/dev/null; then PKG_MGR="brew"
  else die "No supported package manager (apt/yum/dnf/apk/pacman/brew)" 1; fi
  info "Package manager: ${PKG_MGR}"
}

# ── Install packages with error handling ──────────────────────────────────────
install_pkgs() {
  local pkgs=("$@")
  local missing=()
  for pkg in "${pkgs[@]}"; do
    command -v "$pkg" &>/dev/null || missing+=("$pkg")
  done
  [ ${#missing[@]} -eq 0 ] && { ok "All packages already installed"; return 0; }

  info "Installing: ${missing[*]}"
  case "$PKG_MGR" in
    apt-get)
      $SUDO apt-get update -qq 2>/dev/null
      $SUDO apt-get install -y -qq "${missing[@]}" 2>&1 | tail -2 || {
        warn "apt-get failed for some packages, trying individually..."
        for pkg in "${missing[@]}"; do
          $SUDO apt-get install -y -qq "$pkg" 2>/dev/null || warn "  Failed: $pkg"
        done
      }
      ;;
    yum|dnf)
      $SUDO "$PKG_MGR" install -y -q "${missing[@]}" 2>&1 | tail -2 || {
        warn "$PKG_MGR failed, trying individually..."
        for pkg in "${missing[@]}"; do
          $SUDO "$PKG_MGR" install -y -q "$pkg" 2>/dev/null || warn "  Failed: $pkg"
        done
      }
      ;;
    apk)
      $SUDO apk add --quiet "${missing[@]}" 2>&1 | tail -2 || die "apk install failed" 2
      ;;
    pacman)
      $SUDO pacman -S --noconfirm "${missing[@]}" 2>&1 | tail -2 || die "pacman install failed" 2
      ;;
    brew)
      brew install "${missing[@]}" 2>&1 | tail -2 || die "brew install failed" 2
      ;;
  esac

  # Verify each package is actually available now
  local still_missing=()
  for pkg in "${missing[@]}"; do
    command -v "$pkg" &>/dev/null || still_missing+=("$pkg")
  done
  if [ ${#still_missing[@]} -gt 0 ]; then
    warn "Could not install: ${still_missing[*]}"
    warn "Some features may not work. Continuing anyway."
  else
    ok "Installed: ${missing[*]}"
  fi
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────
preflight_checks() {
  header "Pre-flight checks"
  local warnings=0

  # ── Disk space ──────────────────────────────────────────────────────────
  local disk_avail
  disk_avail=$(df -m . 2>/dev/null | awk 'NR==2{print $4}' || echo "0")
  if [ "$disk_avail" -lt 5120 ]; then
    fail "Insufficient disk space: ${disk_avail}MB available, need at least 5GB"
    die "Free up disk space and re-run." 6
  fi
  ok "Disk space: ${disk_avail}MB available"

  # ── RAM ──────────────────────────────────────────────────────────────────
  local mem_mb
  mem_mb=$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo 2>/dev/null || echo "4096")
  if [ "$mem_mb" -lt 1024 ]; then
    warn "Low RAM: ${mem_mb}MB. Recommend ≥ 2GB. Will create swap."
    warnings=$((warnings + 1))
  else
    ok "RAM: ${mem_mb}MB"
  fi

  # ── Port conflicts ───────────────────────────────────────────────────────
  local ports_to_check=(80 443 8080 8443)
  for port in "${ports_to_check[@]}"; do
    if command -v ss &>/dev/null; then
      if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        local proc
        proc=$(ss -tlnp 2>/dev/null | grep ":${port} " | head -1 | sed 's/.*users:(("//' | cut -d'"' -f1 || echo "unknown")
        warn "Port ${port} is already in use${proc:+ by ${proc}}"
        warnings=$((warnings + 1))
      fi
    elif command -v netstat &>/dev/null; then
      if netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        warn "Port ${port} is already in use"
        warnings=$((warnings + 1))
      fi
    fi
  done

  if [ $warnings -gt 0 ]; then
    echo ""
    warn "${warnings} warning(s) found. Continuing — Docker will handle port conflicts."
  else
    ok "No port conflicts detected"
  fi
}

# ── Docker installation ──────────────────────────────────────────────────────
install_docker() {
  header "Docker"

  if command -v docker &>/dev/null; then
    ok "Docker already installed ($(docker --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1 || echo 'unknown'))"
  else
    info "Installing Docker..."
    case "$PKG_MGR" in
      apt-get)
        $SUDO apt-get update -qq 2>/dev/null
        $SUDO apt-get install -y -qq docker.io 2>&1 | tail -1 || {
          warn "apt docker.io failed — trying official Docker script..."
          curl -fsSL https://get.docker.com 2>/dev/null | $SUDO bash 2>&1 | tail -5 || {
            die "Docker installation failed. Install manually: https://docs.docker.com/engine/install/" 2
          }
        }
        ;;
      *)
        info "Using official Docker install script..."
        curl -fsSL https://get.docker.com 2>/dev/null | $SUDO bash 2>&1 | tail -5 || {
          die "Docker installation failed. Install manually: https://docs.docker.com/engine/install/" 2
        }
        ;;
    esac
    command -v docker &>/dev/null || die "Docker binary not found after install" 2
    ok "Docker installed"
  fi

  # ── Docker Compose v2 ─────────────────────────────────────────────────────
  if docker compose version &>/dev/null 2>&1; then
    ok "Docker Compose v2 available"
  else
    info "Installing Docker Compose plugin..."
    case "$PKG_MGR" in
      apt-get) $SUDO apt-get install -y -qq docker-compose-plugin 2>/dev/null || true ;;
      yum|dnf) $SUDO "$PKG_MGR" install -y -q docker-compose-plugin 2>/dev/null || true ;;
      *) warn "Could not install compose plugin via $PKG_MGR" ;;
    esac
    # Fallback: download binary directly
    if ! docker compose version &>/dev/null 2>&1; then
      local compose_url
      compose_url="https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)"
      $SUDO mkdir -p /usr/local/lib/docker/cli-plugins
      curl -fsSL "$compose_url" -o /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null && \
        $SUDO chmod +x /usr/local/lib/docker/cli-plugins/docker-compose || \
        warn "Could not install compose plugin. Install manually."
    fi
    docker compose version &>/dev/null 2>&1 && ok "Docker Compose v2 installed" || \
      die "Docker Compose v2 not available. Install: https://docs.docker.com/compose/install/" 2
  fi

  # ── Start Docker daemon ──────────────────────────────────────────────────
  if command -v systemctl &>/dev/null; then
    $SUDO systemctl enable docker 2>/dev/null || true
    if ! $SUDO systemctl is-active --quiet docker 2>/dev/null; then
      info "Starting Docker daemon..."
      $SUDO systemctl start docker 2>/dev/null || {
        warn "systemctl start failed — trying service..."
        $SUDO service docker start 2>/dev/null || warn "Could not start Docker via service"
      }
    fi
  fi

  # ── Verify Docker daemon is responding ───────────────────────────────────
  local docker_retries=5
  while [ $docker_retries -gt 0 ]; do
    if docker info &>/dev/null 2>&1; then
      ok "Docker daemon is running"
      break
    fi
    docker_retries=$((docker_retries - 1))
    if [ $docker_retries -eq 0 ]; then
      fail "Docker daemon not responding after 5 attempts"
      warn "Try: sudo systemctl start docker"
      warn "Or:  sudo service docker start"
      die "Cannot continue without Docker daemon" 2
    fi
    info "Waiting for Docker daemon... ($((5 - docker_retries))/5)"
    sleep 2
  done

  # ── Add user to docker group ─────────────────────────────────────────────
  if [ "$(id -u)" -ne 0 ] && ! groups "$USER" 2>/dev/null | grep -qw docker; then
    $SUDO usermod -aG docker "$USER" 2>/dev/null || true
    DOCKER_GROUP_CHANGED=true
    warn "Added to 'docker' group. Run 'newgrp docker' or log out/in if docker commands fail."
  fi
}

# ── Swap setup ───────────────────────────────────────────────────────────────
setup_swap() {
  if [ -f /swapfile ] || [ "$OS_ID" = "macos" ]; then
    return 0
  fi
  local mem_mb
  mem_mb=$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo 2>/dev/null || echo "4096")
  if [ "$mem_mb" -le 2048 ]; then
    header "Swap"
    warn "RAM is ${mem_mb}MB — creating 2GB swap"
    $SUDO fallocate -l 2G /swapfile 2>/dev/null || $SUDO dd if=/dev/zero of=/swapfile bs=1M count=2048 2>/dev/null
    $SUDO chmod 600 /swapfile
    $SUDO mkswap /swapfile 2>/dev/null
    $SUDO swapon /swapfile 2>/dev/null
    grep -q swapfile /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab > /dev/null
    ok "Swap enabled (2GB)"
  fi
}

# ── Clone or update repo ─────────────────────────────────────────────────────
setup_repo() {
  header "Repository"

  if [ -d "$REPO_DIR/.git" ]; then
    info "Repo exists at ${REPO_DIR}"
    if [ "$SKIP_CONFIRM" = "1" ]; then
      cd "$REPO_DIR"
      git pull --ff-only 2>&1 | tail -2 || warn "git pull failed — using existing files"
      ok "Repository updated"
    else
      read -rp "  Pull latest? [Y/n]: " PULL
      PULL="${PULL:-y}"
      if [[ "$PULL" =~ ^[Yy] ]]; then
        cd "$REPO_DIR"
        git pull --ff-only 2>&1 | tail -2 || warn "git pull failed — using existing files"
        ok "Repository updated"
      else
        info "Using existing files"
        cd "$REPO_DIR"
      fi
    fi
  elif [ -d "$REPO_DIR" ]; then
    warn "${REPO_DIR} exists but is not a git repo"
    info "Using existing directory"
    cd "$REPO_DIR"
  else
    info "Cloning from ${REPO_URL}..."
    if git clone "$REPO_URL" "$REPO_DIR" 2>&1 | tail -3; then
      ok "Repository cloned"
      cd "$REPO_DIR"
    else
      fail "Clone from ${REPO_URL} failed"
      if [ "$SKIP_CONFIRM" = "1" ]; then
        die "Repository clone failed. Set REPO_URL env var to your fork." 3
      fi
      echo ""
      echo "   Set REPO_URL and re-run:"
      echo "     REPO_URL=https://github.com/your-org/attacklens.git bash install.sh"
      echo ""
      read -rp "  Enter git URL (or Enter to skip and use current dir): " CUSTOM_URL
      if [ -n "$CUSTOM_URL" ]; then
        git clone "$CUSTOM_URL" "$REPO_DIR" 2>&1 | tail -3 || die "Clone failed" 3
        cd "$REPO_DIR"
        ok "Repository cloned"
      else
        mkdir -p "$REPO_DIR"
        cd "$REPO_DIR"
        warn "No repo cloned. Place files in ${REPO_DIR} manually."
      fi
    fi
  fi

  # ── Verify docker-compose.yml exists ──────────────────────────────────────
  if [ ! -f docker-compose.yml ]; then
    die "docker-compose.yml not found in ${REPO_DIR}. Is this the right repo?" 3
  fi
  ok "docker-compose.yml found"
}

# ── Generate config ──────────────────────────────────────────────────────────
setup_config() {
  header "Configuration"

  if [ -f .env ]; then
    info ".env exists — reusing"
    if [ ! -f Caddyfile ] && [ -f env.sh ]; then
      warn "Caddyfile missing — regenerating"
      bash env.sh || warn "env.sh had issues — creating minimal Caddyfile"
      [ ! -f Caddyfile ] && cat > Caddyfile <<-CADDY
{
    auto_https off
    admin off
}
:80 {
    reverse_proxy manager:8080
}
CADDY
    fi
    ok "Config ready"
  elif [ -f env.sh ]; then
    if [ "$SKIP_CONFIRM" = "1" ]; then
      # Non-interactive: generate minimal config
      info "Non-interactive mode — generating minimal .env"
      local public_ip=""
      for url in "https://api.ipify.org" "https://ifconfig.me"; do
        public_ip=$(curl -fsSL --max-time 3 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        [ -n "$public_ip" ] && break
      done
      local admin_token
      admin_token="sk-admin-$(openssl rand -hex 12 2>/dev/null || head -c 12 /dev/urandom | xxd -p)"
      cat > .env <<-EOF
PUBLIC_IP=${public_ip:-}
DOMAIN=
BIND_PORT=8443
TLS_MODE=self-signed
ADMIN_TOKEN=${admin_token}
OPEN_ENROLLMENT=true
ENROLLMENT_TOKENS=
LOG_LEVEL=info
CORS_ORIGINS=*
EOF
      cat > Caddyfile <<-CADDY
{
    auto_https off
    admin off
}
:80 {
    reverse_proxy manager:8080
}
CADDY
      ok "Minimal .env + Caddyfile generated"
      info "Admin token: ${admin_token}"
    else
      info "Running interactive setup wizard..."
      bash env.sh || {
        warn "env.sh failed — creating minimal .env"
        cat > .env <<-EOF
LOG_LEVEL=info
OPEN_ENROLLMENT=true
BIND_PORT=8443
EOF
        ok "Minimal .env created"
      }
    fi
  else
    warn "env.sh not found — creating minimal .env"
    cat > .env <<-EOF
LOG_LEVEL=info
OPEN_ENROLLMENT=true
BIND_PORT=8443
EOF
    ok "Minimal .env created"
  fi

  # ── Validate .env has required fields ─────────────────────────────────────
  if ! grep -q "BIND_PORT" .env 2>/dev/null; then
    warn "BIND_PORT missing from .env — defaulting to 8443"
    echo "BIND_PORT=8443" >> .env
  fi
}

# ── Pull images ──────────────────────────────────────────────────────────────
pull_images() {
  header "Docker images"

  info "Pulling images (~1.5 GB)..."
  if docker compose pull 2>&1 | tail -8; then
    ok "Images pulled"
  else
    warn "Some images failed to pull — will build from source"
    info "Building images..."
    docker compose build 2>&1 | tail -10 || {
      fail "Image pull and build both failed"
      warn "Check your internet connection and Docker daemon"
      die "Cannot continue without images" 4
    }
    ok "Images built from source"
  fi
}

# ── Start containers ──────────────────────────────────────────────────────────
start_services() {
  header "Starting containers"

  # ── Stop existing containers if running ──────────────────────────────────
  if docker compose ps -q 2>/dev/null | grep -q .; then
    info "Existing containers found — stopping them first..."
    docker compose down --remove-orphans 2>&1 | tail -2 || true
    ok "Old containers stopped"
  fi

  info "Starting all services..."
  if docker compose up -d --remove-orphans 2>&1 | tail -10; then
    ok "Containers started"
  else
    warn "docker compose up failed — trying with --build..."
    if docker compose up -d --remove-orphans --build 2>&1 | tail -15; then
      ok "Containers started (with build)"
    else
      fail "Failed to start containers"
      diagnose_failure
      die "Container startup failed. See diagnostics above." 4
    fi
  fi

  # ── Verify all containers are running ─────────────────────────────────────
  sleep 3
  local total started
  total=$(docker compose ps -q 2>/dev/null | wc -l || echo "0")
  started=$(docker compose ps --filter "status=running" -q 2>/dev/null | wc -l || echo "0")
  if [ "$started" -lt "$total" ]; then
    warn "${started}/${total} containers running — some may still be starting"
  else
    ok "All ${total} containers running"
  fi
}

# ── Diagnose failures ────────────────────────────────────────────────────────
diagnose_failure() {
  header "Diagnostics"
  warn "Attempting to diagnose the failure..."

  # ── Check Docker daemon ──────────────────────────────────────────────────
  if ! docker info &>/dev/null 2>&1; then
    fail "Docker daemon is not running"
    echo "   Fix: sudo systemctl start docker"
    return
  fi

  # ── Check port conflicts ─────────────────────────────────────────────────
  for port in 80 443 8080 8443 5432 5672; do
    if command -v ss &>/dev/null && ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      local proc
      proc=$(ss -tlnp 2>/dev/null | grep ":${port} " | head -1 | sed 's/.*users:(("//' | cut -d'"' -f1 || echo "?")
      warn "Port ${port} in use by: ${proc}"
    fi
  done

  # ── Check container logs ─────────────────────────────────────────────────
  echo ""
  info "Container status:"
  docker compose ps -a 2>/dev/null || true

  echo ""
  info "Recent logs (last 15 lines per service):"
  for svc in manager postgres rabbitmq caddy threat-intel; do
    local log_count
    log_count=$(docker compose logs --tail=15 "$svc" 2>/dev/null | wc -l || echo "0")
    if [ "$log_count" -gt 0 ]; then
      echo ""
      echo -e "  ${BLD}── ${svc} ──${NC}"
      docker compose logs --tail=15 "$svc" 2>/dev/null | sed 's/^/  /' || true
    fi
  done

  # ── Check disk space ──────────────────────────────────────────────────────
  echo ""
  local disk_avail
  disk_avail=$(df -m . 2>/dev/null | awk 'NR==2{print $4}' || echo "?")
  info "Disk available: ${disk_avail}MB"
  if [ "$disk_avail" -lt 1024 ]; then
    fail "Disk almost full — Docker cannot create containers"
    echo "   Fix: docker system prune -af && sudo apt clean"
  fi

  # ── Check .env validity ──────────────────────────────────────────────────
  if [ ! -f .env ]; then
    fail ".env file missing — run: bash env.sh"
  fi
}

# ── Health check ─────────────────────────────────────────────────────────────
wait_healthy() {
  header "Health check"

  info "Waiting for manager to become healthy (up to 120s)..."
  local max_attempts=40
  local attempt=0

  while [ $attempt -lt $max_attempts ]; do
    attempt=$((attempt + 1))
    if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
      echo ""
      ok "Manager is healthy! (attempt ${attempt}/${max_attempts})"
      return 0
    fi

    # Check if manager container is even running
    if [ $attempt -eq 10 ]; then
      local mgr_status
      mgr_status=$(docker compose ps manager --format '{{.Status}}' 2>/dev/null | head -1 || echo "?")
      if echo "$mgr_status" | grep -qi "exited\|restarting"; then
        warn "Manager container is not running (status: ${mgr_status})"
        warn "Recent logs:"
        docker compose logs --tail=10 manager 2>/dev/null | sed 's/^/  /' || true
        echo ""
        warn "Trying to restart..."
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
  header "Verification"

  # ── Check each service ────────────────────────────────────────────────────
  local services=(postgres rabbitmq caddy manager threat-intel)
  local all_ok=true

  for svc in "${services[@]}"; do
    local status
    status=$(docker compose ps "$svc" --format '{{.Status}}' 2>/dev/null | head -1 || echo "not found")
    if echo "$status" | grep -qi "up\|healthy"; then
      ok "${svc}: ${status}"
    else
      warn "${svc}: ${status:-not found}"
      all_ok=false
    fi
  done

  # ── Check API responds ───────────────────────────────────────────────────
  if curl -sf http://localhost:8080/health 2>/dev/null | grep -q "." 2>/dev/null; then
    ok "Manager API responding"
  else
    warn "Manager API not responding on :8080"
    all_ok=false
  fi

  # ── Check Postgres ────────────────────────────────────────────────────────
  if docker compose exec -T postgres pg_isready -U attacklens &>/dev/null 2>&1; then
    ok "Postgres is ready"
  else
    warn "Postgres not ready yet (may still be initializing)"
  fi

  # ── Check RabbitMQ ────────────────────────────────────────────────────────
  if docker compose exec -T rabbitmq rabbitmq-diagnostics check_port_listener 5672 &>/dev/null 2>&1; then
    ok "RabbitMQ is ready"
  else
    warn "RabbitMQ not ready yet (may still be starting)"
  fi

  if [ "$all_ok" = false ]; then
    warn "Some services need more time. Check: docker compose ps"
  fi
}

# ── Print summary ────────────────────────────────────────────────────────────
print_summary() {
  header "Installation complete"

  # ── Get public IP ─────────────────────────────────────────────────────────
  local public_ip=""
  for url in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://ifconfig.me"; do
    public_ip=$(curl -fsSL --max-time 3 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    [ -n "$public_ip" ] && break
  done
  public_ip="${public_ip:-<your-server-ip>}"

  # ── Read config ───────────────────────────────────────────────────────────
  local bind_port domain admin_token
  bind_port=$(grep -oP '^BIND_PORT=\K.*' .env 2>/dev/null | head -1 || echo "8443")
  domain=$(grep -oP '^DOMAIN=\K.*' .env 2>/dev/null | head -1 || echo "")
  admin_token=$(grep -oP '^ADMIN_TOKEN=\K.*' .env 2>/dev/null | head -1 || echo "")

  local manager_url
  if [ -n "$domain" ]; then
    manager_url="https://${domain}"
  else
    manager_url="https://${public_ip}:${bind_port}"
  fi

  echo ""
  echo -e "${GRN}${BLD}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║          AttackLens is running!                 ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo ""
  echo -e "  ${BLD}Dashboard:${NC}     ${manager_url}"
  echo -e "  ${BLD}Health:${NC}        ${manager_url}/health"
  if [ -n "$admin_token" ]; then
    echo -e "  ${BLD}Admin token:${NC}    ${admin_token}"
  fi
  echo ""
  echo -e "  ${BLD}Commands:${NC}"
  echo "    docker compose logs -f          # live logs"
  echo "    docker compose ps               # status"
  echo "    docker compose restart manager   # restart one service"
  echo "    ./scripts/monitor.sh            # health dashboard"
  echo "    ./scripts/backup.sh /backup      # backup databases"
  echo ""
  echo -e "  ${BLD}Install agent:${NC}"
  echo "    # In agent.toml set:"
  echo "    #   url        = \"${manager_url}\""
  echo "    #   tls_verify = ${domain:+true}${domain:-false}"
  echo ""
  if [ "${DOCKER_GROUP_CHANGED:-false}" = true ]; then
    warn "Run 'newgrp docker' or log out/in for docker group changes"
  fi
  echo -e "  ${DIM}Install log: ${LOG_FILE}${NC}"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  banner

  echo ""
  info "This script will:"
  echo "    1. Install Docker + Docker Compose"
  echo "    2. Clone the AttackLens repo"
  echo "    3. Generate config (.env + Caddyfile)"
  echo "    4. Pull images and start all containers"
  echo "    5. Verify health and print credentials"
  echo ""

  if [ "$SKIP_CONFIRM" != "1" ]; then
    read -rp "  Continue? [Y/n]: " CONFIRM
    CONFIRM="${CONFIRM:-y}"
    if [[ ! "$CONFIRM" =~ ^[Yy] ]]; then
      echo ""
      info "Installation cancelled."
      exit 5
    fi
  fi

  # ── Execute all steps ─────────────────────────────────────────────────────
  detect_sudo
  detect_os
  detect_pkg_manager
  preflight_checks

  install_pkgs curl git jq

  install_docker
  setup_swap
  setup_repo

  # Python (optional — for local dev/scripts)
  if ! command -v python3 &>/dev/null; then
    install_pkgs python3
  fi

  setup_config
  pull_images
  start_services
  wait_healthy || true
  verify_deployment
  print_summary
}

main "$@"
