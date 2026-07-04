#!/usr/bin/env bash
# =============================================================================
#  scripts/monitor.sh — Health diagnostics for the AttackLens stack
#
#  Usage:
#    ./scripts/monitor.sh              # full health report
#    ./scripts/monitor.sh --quick      # just status + metrics
#    ./scripts/monitor.sh --watch      # continuous refresh (Ctrl+C to stop)
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; CYN='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'
PASS="${GRN}●${NC}"; FAIL="${RED}●${NC}"; WARN="${YEL}●${NC}"

MODE="${1:-full}"  # full, quick, watch
COMPOSE_FILE="docker-compose.yml"

# ── Detect compose ────────────────────────────────────────────────────────────
if [ ! -f "$COMPOSE_FILE" ]; then
  echo "ERROR: $COMPOSE_FILE not found. Run from project root."
  exit 1
fi

health_check() {
  local label="$1" cmd="$2"
  if eval "$cmd" > /dev/null 2>&1; then
    echo -e "  ${PASS} ${label}"
  else
    echo -e "  ${FAIL} ${label}"
  fi
}

metric() { echo -e "  ${CYN}→${NC} $1: ${BLD}$2${NC}"; }

report() {
  echo ""
  echo -e "${BLD}╔══════════════════════════════════════════╗${NC}"
  echo -e "${BLD}║   AttackLens — Health Report             ║${NC}"
  echo -e "${BLD}╚══════════════════════════════════════════╝${NC}"
  echo "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo ""

  # ── Container status ─────────────────────────────────────────────────────
  echo -e "${BLD}Containers:${NC}"
  docker compose -f "$COMPOSE_FILE" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
    echo "  ${FAIL} docker compose not running"

  echo ""

  # ── Health checks ────────────────────────────────────────────────────────
  echo -e "${BLD}Health Checks:${NC}"
  health_check "Manager API"    "curl -sf http://localhost:8080/health"
  health_check "Postgres"       "docker compose exec -T postgres pg_isready -U attacklens 2>/dev/null || docker compose exec -T postgres pg_isready 2>/dev/null"
  health_check "RabbitMQ"       "docker compose exec -T rabbitmq rabbitmq-diagnostics check_port_listener 5672 2>/dev/null"
  health_check "Caddy/Proxy"    "curl -sf -o /dev/null http://localhost:80/health 2>/dev/null || curl -sfk -o /dev/null https://localhost:8443/health 2>/dev/null"

  echo ""

  # ── Metrics ──────────────────────────────────────────────────────────────
  echo -e "${BLD}Metrics:${NC}"
  # Total findings
  local total
  total=$(curl -sf http://localhost:8080/api/v1/soc/findings?limit=1 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('count','?'))" 2>/dev/null || echo "?")
  metric "Total findings" "$total"

  # Agents
  local agents
  agents=$(curl -sf http://localhost:8080/api/v1/agents 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "?")
  metric "Enrolled agents" "$agents"

  # Uptime
  local uptime
  uptime=$(docker ps --filter name=attacklens-manager --format '{{.RunningFor}}' 2>/dev/null | head -1 || echo "?")
  metric "Manager uptime" "$uptime"

  # Disk usage
  local disk_pg disk_data
  disk_pg=$(docker system df --format '{{.Size}}' 2>/dev/null | head -3 | tail -1 || echo "?")
  disk_data=$(du -sh ./data 2>/dev/null | cut -f1 || echo "?")
  metric "Postgres volume size" "$disk_pg"
  metric "Data directory" "${disk_data:-?}"

  # Memory
  local mem
  mem=$(docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}' 2>/dev/null | grep attacklens | head -4 || echo "?")
  echo -e "  ${CYN}→${NC} Container memory:"
  echo "$mem" | while IFS=$'\t' read -r name usage; do
    echo -e "    ${BLD}$name${NC}: $usage"
  done

  echo ""
}

case "$MODE" in
  quick)  report ;;
  watch)
    while true; do
      clear 2>/dev/null || true
      report
      sleep 5
    done
    ;;
  *)
    report
    # ── Recent logs (last 20 lines) ──────────────────────────────────────
    echo -e "${BLD}Recent Errors (last 20 lines):${NC}"
    docker compose -f "$COMPOSE_FILE" logs --tail=20 manager 2>/dev/null | grep -i "error\|exception\|traceback" | head -10 || echo "  No recent errors"
    echo ""
    # ── Resource usage ─────────────────────────────────────────────────────
    echo -e "${BLD}Disk (top-level directories):${NC}"
    du -sh ./data ./certs ./logs ./manager/data 2>/dev/null || true
    echo ""
    echo -e "${BLD}System:${NC}"
    echo "  Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "  Mem:  $(free -h 2>/dev/null | awk '/^Mem:/{print $3"/"$2}' || echo "N/A")"
    echo "  Disk: $(df -h . | awk 'NR==2{print $3"/"$2" ("$5")"}')"
    ;;
esac
