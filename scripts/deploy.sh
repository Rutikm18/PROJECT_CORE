#!/usr/bin/env bash
# =============================================================================
#  scripts/deploy.sh — Manual/SSH deploy to a single EC2 instance
#
#  Usage:
#    chmod +x scripts/deploy.sh
#
#    # Deploy latest (build on server):
#    ./scripts/deploy.sh ec2-user@1.2.3.4
#
#    # Deploy a specific git ref:
#    ./scripts/deploy.sh ec2-user@1.2.3.4 --branch feature/new-detection
#
#    # Deploy without rebuild (just restart containers):
#    ./scripts/deploy.sh ec2-user@1.2.3.4 --restart
# =============================================================================
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <user@host> [--branch <ref>] [--restart]"
  exit 1
fi

HOST="$1"
shift

BRANCH=""
RESTART_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch) BRANCH="$2"; shift 2 ;;
    --restart) RESTART_ONLY=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'
info() { echo -e "${CYN}[info]${NC}  $*"; }
ok()   { echo -e "${GRN}[ok]${NC}    $*"; }
err()  { echo -e "${RED}[err]${NC}   $*"; }

info "Deploying to ${HOST}..."

if [ "$RESTART_ONLY" = true ]; then
  info "Restarting containers only..."
  ssh "$HOST" -- "
    cd ~/attacklens
    docker compose pull
    docker compose up -d --remove-orphans
    docker image prune -f 2>/dev/null || true
  "
  ok "Containers restarted"
  exit 0
fi

# Build and deploy
REMOTE_DIR="/home/$(echo "$HOST" | cut -d@ -f2)/attacklens"

# Rsync the project (excluding heavy/unnecessary dirs)
info "Syncing project files..."
rsync -az --delete --progress \
  --exclude '.git' \
  --exclude 'node_modules' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.venv' \
  --exclude '.env' \
  --exclude 'data/' \
  --exclude 'logs/' \
  --exclude 'certs/' \
  --exclude 'output/' \
  --exclude 'manager/dashboard/templates/Build Smart AttackLens Platform/node_modules' \
  ./ "${HOST}:${REMOTE_DIR}/"

ok "Files synced"

# Deploy via SSH
info "Building and starting containers..."
ssh "$HOST" -- "
  set -e
  cd ${REMOTE_DIR}

  # Pull latest base images
  docker compose pull

  # Build and start
  docker compose up -d --build --remove-orphans

  # Wait for health check
  echo 'Waiting for manager to become healthy...'
  for i in \$(seq 1 20); do
    if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
      echo 'Manager is healthy!'
      break
    fi
    echo \"Attempt \$i/20...\"
    sleep 5
  done

  # Clean up old images
  docker image prune -f 2>/dev/null || true

  # Show running containers
  docker compose ps
"

ok "Deploy complete"
