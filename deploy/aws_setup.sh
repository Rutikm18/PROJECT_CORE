#!/usr/bin/env bash
# =============================================================================
#  tools/aws_setup.sh — Jarvis Manager — One-Shot AWS Installer
#
#  Run this script on a fresh Ubuntu 22.04/24.04 EC2 instance.
#  It installs every dependency, clones the repo, configures Docker,
#  generates TLS certs + tokens, and starts the manager automatically.
#
#  Usage:
#    curl -fsSL <raw-url>/tools/aws_setup.sh | bash
#
#  OR copy to EC2 and run:
#    chmod +x aws_setup.sh && bash aws_setup.sh
#
#  Optional env vars (all have safe defaults):
#    JARVIS_DIR     — where to clone/place the project  (default: ~/jarvis)
#    BIND_PORT      — manager HTTPS port                (default: 8443)
#    LOG_LEVEL      — uvicorn log level                 (default: info)
#    REPO_URL       — git repo to clone                 (default: skip clone if dir exists)
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Colour

# ── Config ────────────────────────────────────────────────────────────────────
JARVIS_DIR="${JARVIS_DIR:-$HOME/jarvis}"
BIND_PORT="${BIND_PORT:-8443}"
LOG_LEVEL="${LOG_LEVEL:-info}"
REPO_URL="${REPO_URL:-}"

# ── Helpers ───────────────────────────────────────────────────────────────────
step()  { echo -e "\n${CYAN}${BOLD}▶  $*${NC}"; }
ok()    { echo -e "   ${GREEN}✔  $*${NC}"; }
info()  { echo -e "   ${DIM}ℹ  $*${NC}"; }
warn()  { echo -e "   ${YELLOW}⚠  $*${NC}"; }
die()   { echo -e "\n${RED}${BOLD}✖  ERROR: $*${NC}\n" >&2; exit 1; }

hr() {
  echo -e "${DIM}────────────────────────────────────────────────────────────${NC}"
}

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════╗"
  echo "  ║                                                          ║"
  echo "  ║         Jarvis Manager — AWS One-Shot Installer          ║"
  echo "  ║                                                          ║"
  echo "  ╚══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

spinner() {
  local pid=$1 msg=$2
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r   ${CYAN}%s${NC}  %s " "${frames[i % ${#frames[@]}]}" "$msg"
    i=$((i+1))
    sleep 0.1
  done
  printf "\r   ${GREEN}✔${NC}  %-50s\n" "$msg"
}

check_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    warn "Running as root. Jarvis will be installed to /root/jarvis."
    warn "For a non-root install, run as a regular user (ubuntu, ec2-user, etc.)"
    sleep 2
  fi
}

# ── OS detection ──────────────────────────────────────────────────────────────
detect_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-}"
  else
    die "Cannot detect OS. Supported: Ubuntu 20.04/22.04/24.04, Amazon Linux 2/2023, Debian 11/12"
  fi
  info "Detected OS: ${OS_ID} ${OS_VERSION}"
}

# ── Step 1 — System packages ──────────────────────────────────────────────────
install_base_packages() {
  step "Installing system packages"

  case "$OS_ID" in
    ubuntu|debian)
      (sudo apt-get update -qq && \
       sudo apt-get install -y -qq \
         curl wget git unzip ca-certificates gnupg lsb-release \
         openssl jq htop net-tools 2>&1) &
      spinner $! "apt-get update + install base packages"
      ;;
    amzn|fedora|rhel|centos)
      (sudo yum update -y -q && \
       sudo yum install -y -q \
         curl wget git unzip ca-certificates gnupg openssl jq \
         net-tools 2>&1) &
      spinner $! "yum update + install base packages"
      ;;
    *)
      die "Unsupported OS: ${OS_ID}. Use Ubuntu, Debian, Amazon Linux, RHEL, or CentOS."
      ;;
  esac

  ok "Base packages installed"
}

# ── Step 2 — Docker ───────────────────────────────────────────────────────────
install_docker() {
  step "Installing Docker Engine"

  if command -v docker &>/dev/null; then
    local ver
    ver=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
    ok "Docker already installed (${ver}) — skipping"
    return
  fi

  case "$OS_ID" in
    ubuntu|debian)
      (
        sudo install -m 0755 -d /etc/apt/keyrings
        sudo curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
          -o /etc/apt/keyrings/docker.asc 2>/dev/null
        sudo chmod a+r /etc/apt/keyrings/docker.asc

        CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/${OS_ID} ${CODENAME} stable" | \
          sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

        sudo apt-get update -qq
        sudo apt-get install -y -qq \
          docker-ce docker-ce-cli containerd.io \
          docker-buildx-plugin docker-compose-plugin
      ) &
      spinner $! "Installing Docker via apt"
      ;;
    amzn)
      (sudo amazon-linux-extras install docker -y 2>&1 || \
       sudo yum install -y docker 2>&1) &
      spinner $! "Installing Docker via yum/amazon-linux-extras"
      ;;
    fedora|rhel|centos)
      (sudo yum install -y yum-utils 2>&1
       sudo yum-config-manager --add-repo \
         https://download.docker.com/linux/centos/docker-ce.repo 2>&1
       sudo yum install -y docker-ce docker-ce-cli containerd.io \
         docker-compose-plugin 2>&1) &
      spinner $! "Installing Docker via yum"
      ;;
  esac

  ok "Docker installed ($(docker --version 2>/dev/null | awk '{print $3}' | tr -d ','))"
}

# ── Step 3 — Docker Compose (standalone fallback) ────────────────────────────
install_docker_compose() {
  step "Checking Docker Compose"

  # docker compose plugin (v2)
  if docker compose version &>/dev/null 2>&1; then
    ok "Docker Compose plugin available ($(docker compose version --short 2>/dev/null))"
    return
  fi

  # fallback: install standalone compose v2
  info "Installing Docker Compose standalone..."
  local COMPOSE_VER
  COMPOSE_VER=$(curl -fsSL \
    https://api.github.com/repos/docker/compose/releases/latest \
    2>/dev/null | grep '"tag_name"' | cut -d'"' -f4 || echo "v2.27.0")

  sudo curl -fsSL \
    "https://github.com/docker/compose/releases/download/${COMPOSE_VER}/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose 2>/dev/null
  sudo chmod +x /usr/local/bin/docker-compose

  ok "Docker Compose ${COMPOSE_VER} installed"
}

# ── Step 4 — Docker group + service ──────────────────────────────────────────
configure_docker_service() {
  step "Configuring Docker service"

  # Enable and start Docker
  if ! systemctl is-active --quiet docker 2>/dev/null; then
    sudo systemctl enable docker --now &>/dev/null || true
    sleep 2
  fi
  ok "Docker service running"

  # Add current user to docker group (takes effect on next login)
  local CURRENT_USER
  CURRENT_USER=$(id -un)
  if ! groups "$CURRENT_USER" | grep -q docker; then
    sudo usermod -aG docker "$CURRENT_USER" 2>/dev/null || true
    info "Added ${CURRENT_USER} to docker group (re-login to take effect)"
    info "In this script we will use 'sudo docker' where needed"
  else
    ok "User already in docker group"
  fi
}

# ── Step 5 — Project setup ────────────────────────────────────────────────────
setup_project() {
  step "Setting up Jarvis project directory"

  if [[ -d "$JARVIS_DIR" ]]; then
    ok "Project directory already exists: ${JARVIS_DIR}"
    info "Skipping clone. Using existing files."
  elif [[ -n "$REPO_URL" ]]; then
    info "Cloning from: ${REPO_URL}"
    (git clone "$REPO_URL" "$JARVIS_DIR" 2>&1) &
    spinner $! "Cloning repository"
    ok "Repository cloned to ${JARVIS_DIR}"
  else
    # Check if we're already inside the project (script run locally)
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local REPO_ROOT
    REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    if [[ -f "${REPO_ROOT}/docker-compose.yml" ]]; then
      info "Detected project at: ${REPO_ROOT}"
      if [[ "$REPO_ROOT" != "$JARVIS_DIR" ]]; then
        info "Copying project to: ${JARVIS_DIR}"
        cp -r "$REPO_ROOT" "$JARVIS_DIR"
        ok "Project copied to ${JARVIS_DIR}"
      else
        ok "Already in project dir: ${JARVIS_DIR}"
      fi
    else
      die "No project found. Either:\n  • Set REPO_URL=https://github.com/your/repo\n  • Or run this script from inside the project directory"
    fi
  fi

  cd "$JARVIS_DIR"
  ok "Working directory: ${JARVIS_DIR}"
}

# ── Step 6 — Configure .env ───────────────────────────────────────────────────
configure_env() {
  step "Configuring environment"

  cd "$JARVIS_DIR"

  # Get public IP
  local PUBLIC_IP=""
  info "Detecting public IP..."
  for endpoint in \
    "https://api.ipify.org" \
    "https://checkip.amazonaws.com" \
    "https://ifconfig.me" \
    "https://icanhazip.com"; do
    PUBLIC_IP=$(curl -fsSL --max-time 5 "$endpoint" 2>/dev/null | tr -d '[:space:]')
    [[ -n "$PUBLIC_IP" ]] && break
  done

  if [[ -z "$PUBLIC_IP" ]]; then
    # Try EC2 metadata service (IMDSv2)
    TOKEN=$(curl -fsSL --max-time 2 \
      -X PUT "http://169.254.169.254/latest/api/token" \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 10" 2>/dev/null || true)
    if [[ -n "$TOKEN" ]]; then
      PUBLIC_IP=$(curl -fsSL --max-time 2 \
        -H "X-aws-ec2-metadata-token: $TOKEN" \
        "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)
    fi
  fi

  if [[ -z "$PUBLIC_IP" ]]; then
    warn "Could not auto-detect public IP. Set it manually in ${JARVIS_DIR}/.env"
    PUBLIC_IP="<your-server-ip>"
  else
    ok "Public IP detected: ${PUBLIC_IP}"
  fi

  # Write .env
  cat > "${JARVIS_DIR}/.env" <<EOF
# =============================================================
#  Jarvis Manager — auto-generated by aws_setup.sh
#  $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================

PUBLIC_IP=${PUBLIC_IP}
DOMAIN=
BIND_PORT=${BIND_PORT}

# Leave blank — auto-generated on first boot (shown in docker logs)
ENROLLMENT_TOKENS=
ADMIN_TOKEN=

DEFAULT_KEY_EXPIRY_DAYS=0
LOG_LEVEL=${LOG_LEVEL}
CORS_ORIGINS=*

# Let's Encrypt (docker-compose.prod.yml only)
ADMIN_EMAIL=admin@example.com
EOF

  ok ".env written with PUBLIC_IP=${PUBLIC_IP}"
}

# ── Step 7 — Create runtime directories ──────────────────────────────────────
create_directories() {
  step "Creating runtime directories"

  cd "$JARVIS_DIR"
  mkdir -p data certs logs
  ok "data/ certs/ logs/ created"
}

# ── Step 8 — Build Docker image ───────────────────────────────────────────────
build_docker_image() {
  step "Building Docker image (this takes 1-3 minutes on first run)"

  cd "$JARVIS_DIR"
  (sudo docker compose build --no-cache 2>&1 | tail -5) &
  spinner $! "Building jarvis-manager Docker image"
  ok "Docker image built"
}

# ── Step 9 — Start the manager ────────────────────────────────────────────────
start_manager() {
  step "Starting Jarvis Manager"

  cd "$JARVIS_DIR"

  # Stop any existing containers
  sudo docker compose down --remove-orphans 2>/dev/null || true

  # Start
  sudo docker compose up -d 2>&1 | grep -v "^#" || true
  ok "Container started"

  # Wait for health
  local MAX_WAIT=60
  local waited=0
  info "Waiting for manager to become healthy..."
  while [[ $waited -lt $MAX_WAIT ]]; do
    local status
    status=$(sudo docker inspect --format='{{.State.Health.Status}}' \
      jarvis-manager 2>/dev/null || echo "starting")
    if [[ "$status" == "healthy" ]]; then
      ok "Manager is healthy"
      return
    fi
    sleep 3
    waited=$((waited + 3))
    printf "\r   ${DIM}ℹ  Waiting... ${waited}s${NC}"
  done
  printf "\n"
  warn "Health check timed out — manager may still be initialising."
  warn "Run: sudo docker compose logs manager"
}

# ── Step 10 — Extract tokens from logs ───────────────────────────────────────
extract_tokens() {
  step "Extracting generated credentials"

  cd "$JARVIS_DIR"

  # Give entrypoint a moment to write secrets
  sleep 3

  local SECRETS_FILE="data/.secrets"
  local ADMIN_TOKEN="" ENROLLMENT_TOKENS="" PUBLIC_IP=""

  PUBLIC_IP=$(grep "^PUBLIC_IP=" .env | cut -d= -f2 | tr -d '"')

  if [[ -f "$SECRETS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$SECRETS_FILE" 2>/dev/null || true
  fi

  # Also try reading from container logs if secrets file not yet written
  if [[ -z "$ADMIN_TOKEN" ]]; then
    ADMIN_TOKEN=$(sudo docker compose logs manager 2>/dev/null \
      | grep -o 'sk-admin-[A-Za-z0-9_-]*' | tail -1 || true)
  fi

  # Write a summary file the user can always cat
  local SUMMARY="${JARVIS_DIR}/CREDENTIALS.txt"
  {
    echo "================================================"
    echo "  Jarvis Manager — Credentials"
    echo "  Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "================================================"
    echo ""
    echo "  Manager URL  : https://${PUBLIC_IP}:${BIND_PORT}"
    echo "  Dashboard    : https://${PUBLIC_IP}:${BIND_PORT}"
    echo ""
    if [[ -n "$ADMIN_TOKEN" ]]; then
      echo "  Admin Token  : ${ADMIN_TOKEN}"
    else
      echo "  Admin Token  : (see: sudo docker compose logs manager)"
    fi
    if [[ -n "$ENROLLMENT_TOKENS" ]]; then
      echo "  Enroll Token : ${ENROLLMENT_TOKENS}"
    else
      echo "  Enrollment   : OPEN (no token required)"
    fi
    echo ""
    echo "  Mac Install  :"
    echo "    1. Copy macintel-agent-2.0.0-arm64.pkg to the target Mac"
    echo "    2. sudo installer -pkg macintel-agent-2.0.0-arm64.pkg -target /"
    echo "    3. sudo sed -i '' 's|url.*=.*|url = \"https://${PUBLIC_IP}:${BIND_PORT}\"|' /Library/Jarvis/agent.toml"
    echo "    4. sudo sed -i '' 's|tls_verify.*=.*|tls_verify = false|' /Library/Jarvis/agent.toml"
    echo "    5. sudo launchctl kickstart -k system/com.macintel.agent"
    echo ""
    echo "  Secrets file : ${JARVIS_DIR}/data/.secrets"
    echo "================================================"
  } > "$SUMMARY"

  ok "Credentials saved to: ${SUMMARY}"

  # Store for the final summary banner
  _FINAL_URL="https://${PUBLIC_IP}:${BIND_PORT}"
  _FINAL_ADMIN="${ADMIN_TOKEN:-see: sudo docker compose logs manager}"
  _FINAL_OPEN_ENROLL="${ENROLLMENT_TOKENS:-}"
}

# ── Step 11 — Firewall (ufw) ──────────────────────────────────────────────────
configure_firewall() {
  step "Checking firewall (ufw)"

  if ! command -v ufw &>/dev/null; then
    info "ufw not installed — skipping (AWS Security Groups handle firewall)"
    return
  fi

  local ufw_status
  ufw_status=$(sudo ufw status 2>/dev/null | head -1 || echo "inactive")

  if echo "$ufw_status" | grep -qi "inactive"; then
    info "ufw is inactive — AWS Security Groups are your firewall"
    info "Ensure port ${BIND_PORT}/tcp is open in your Security Group"
    return
  fi

  # ufw is active — open our port
  sudo ufw allow "${BIND_PORT}/tcp" comment "Jarvis Manager" &>/dev/null || true
  ok "ufw: port ${BIND_PORT}/tcp opened"
}

# ── Step 12 — Auto-start on reboot ───────────────────────────────────────────
configure_autostart() {
  step "Configuring auto-start on system reboot"

  local SERVICE_FILE="/etc/systemd/system/jarvis-manager.service"
  local COMPOSE_BIN
  COMPOSE_BIN=$(which docker 2>/dev/null || echo "/usr/bin/docker")

  sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Jarvis Manager
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${JARVIS_DIR}
ExecStart=${COMPOSE_BIN} compose up -d
ExecStop=${COMPOSE_BIN} compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable jarvis-manager.service &>/dev/null
  ok "systemd service installed: jarvis-manager.service"
  ok "Manager will auto-start after every reboot"
}

# ── Step 13 — Quick smoke test ────────────────────────────────────────────────
smoke_test() {
  step "Running smoke test"

  cd "$JARVIS_DIR"

  local URL="https://localhost:${BIND_PORT}/health"
  local RESPONSE
  local RETRIES=5

  for i in $(seq 1 $RETRIES); do
    RESPONSE=$(sudo docker exec jarvis-manager \
      curl -fsk "$URL" 2>/dev/null || true)
    if [[ -n "$RESPONSE" ]]; then
      ok "Health endpoint responded: ${RESPONSE}"
      return
    fi
    sleep 3
  done
  warn "Health endpoint did not respond within ${RETRIES} retries."
  warn "Manager may still be starting. Check: sudo docker compose logs manager"
}

# ── Step 14 — Print final summary ────────────────────────────────────────────
print_summary() {
  local PUBLIC_IP
  PUBLIC_IP=$(grep "^PUBLIC_IP=" "${JARVIS_DIR}/.env" | cut -d= -f2 | tr -d '"')

  echo ""
  hr
  echo -e "${GREEN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════╗"
  echo "  ║                                                          ║"
  echo "  ║           ✔  Jarvis Manager — Install Complete          ║"
  echo "  ║                                                          ║"
  echo "  ╚══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  echo -e "${BOLD}  Manager${NC}"
  echo "    URL       : https://${PUBLIC_IP}:${BIND_PORT}"
  echo "    Dashboard  : https://${PUBLIC_IP}:${BIND_PORT}  (accept self-signed cert)"
  echo "    Health     : https://${PUBLIC_IP}:${BIND_PORT}/health"
  echo ""

  echo -e "${BOLD}  Credentials${NC}"
  echo "    Admin Token : ${_FINAL_ADMIN}"
  if [[ -z "$_FINAL_OPEN_ENROLL" ]]; then
  echo "    Enrollment  : OPEN — agents need only the manager URL (no token)"
  else
  echo "    Enroll Token: ${_FINAL_OPEN_ENROLL}"
  fi
  echo "    Saved to    : ${JARVIS_DIR}/CREDENTIALS.txt"
  echo ""

  echo -e "${BOLD}  Install agent on macOS (.pkg)${NC}"
  echo "    Step 1 — Copy the package to your Mac (from your Mac terminal):"
  echo "      scp agent/os/macos/pkg/dist/macintel-agent-2.0.0-arm64.pkg ~/"
  echo ""
  echo "    Step 2 — Install the package:"
  echo "      sudo installer -pkg ~/macintel-agent-2.0.0-arm64.pkg -target /"
  echo ""
  echo "    Step 3 — Set the manager URL in the config:"
  echo "      sudo nano /Library/Jarvis/agent.toml"
  echo "      # Set these two lines:"
  echo "      #   url        = \"https://${PUBLIC_IP}:${BIND_PORT}\""
  echo "      #   tls_verify = false"
  echo ""
  echo "    Step 4 — Start the agent:"
  echo "      sudo launchctl kickstart -k system/com.macintel.agent"
  echo "      sudo launchctl kickstart -k system/com.macintel.watchdog"
  echo ""
  echo "    Step 5 — Verify (agent log):"
  echo "      tail -f /Library/Jarvis/logs/agent-stdout.log"
  echo ""

  echo -e "${BOLD}  Manager management (on EC2)${NC}"
  echo "    cd ${JARVIS_DIR}"
  echo "    sudo docker compose logs -f manager     # live logs"
  echo "    sudo docker compose restart manager     # restart"
  echo "    sudo docker compose down                # stop"
  echo "    sudo docker compose up -d               # start"
  echo "    cat data/.secrets                       # view saved tokens"
  echo ""

  echo -e "${BOLD}  Key management API${NC}"
  echo "    TOKEN='${_FINAL_ADMIN}'"
  echo "    # List all enrolled agents:"
  echo "    curl -sk -H \"X-Admin-Token: \$TOKEN\" \\"
  echo "      https://${PUBLIC_IP}:${BIND_PORT}/api/v1/keys | python3 -m json.tool"
  echo "    # Rotate a key:"
  echo "    curl -sk -X POST -H \"X-Admin-Token: \$TOKEN\" \\"
  echo "      https://${PUBLIC_IP}:${BIND_PORT}/api/v1/keys/<agent_id>/rotate"
  echo ""

  echo -e "${BOLD}  Files${NC}"
  echo "    Project    : ${JARVIS_DIR}/"
  echo "    Config     : ${JARVIS_DIR}/.env"
  echo "    Secrets    : ${JARVIS_DIR}/data/.secrets"
  echo "    TLS cert   : ${JARVIS_DIR}/certs/server.crt"
  echo "    Logs       : ${JARVIS_DIR}/logs/"
  echo ""

  echo -e "${BOLD}  AWS Security Group reminder${NC}"
  echo -e "    ${YELLOW}Ensure TCP port ${BIND_PORT} is open inbound (0.0.0.0/0) in your EC2 Security Group.${NC}"
  echo -e "    ${YELLOW}SSH (22) should be restricted to your IP only.${NC}"
  echo ""
  hr
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  banner
  check_root
  detect_os

  hr
  echo -e "  ${DIM}Install dir : ${JARVIS_DIR}${NC}"
  echo -e "  ${DIM}Manager port: ${BIND_PORT}${NC}"
  echo -e "  ${DIM}OS          : ${OS_ID} ${OS_VERSION}${NC}"
  hr

  install_base_packages
  install_docker
  install_docker_compose
  configure_docker_service
  setup_project
  configure_env
  create_directories
  build_docker_image
  start_manager
  extract_tokens
  configure_firewall
  configure_autostart
  smoke_test
  print_summary
}

main "$@"
