#!/usr/bin/env bash
# =============================================================================
#  troubleshoot.sh — AttackLens manager / Caddy TLS auto-diagnostics
#
#  Read-only. Walks the whole "why isn't HTTPS working" chain and reports
#  PASS / WARN / FAIL per scenario with the exact fix, then prints the single
#  most important next action. Safe to run repeatedly.
#
#    bash troubleshoot.sh              # full run
#    NO_EGRESS_TEST=1 bash troubleshoot.sh   # skip the container->internet test
#                                            # (that one pulls the alpine image)
#
#  The scenarios covered are the real failure modes seen bringing up
#  console.attacklens.ai: config drift, missing dashboard password, port
#  conflicts on 80/443, host IP-forwarding off, the app network having no
#  internet egress, DNS not pointing here, inbound firewall, and cert status.
# =============================================================================

# Deliberately NOT `set -e`: a diagnostic must run every check even when some
# fail. Unset vars are guarded with ${VAR:-} throughout.
set -o pipefail

CYAN='\033[0;36m'; BOLD='\033[1m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'

PASS=0; WARN=0; FAIL=0
# Priority-ordered remediation queue: the first entry pushed is the top pick.
declare -a NEXT_ACTIONS=()

section(){ echo -e "\n${CYAN}${BOLD}▶ $*${NC}"; }
pass(){ echo -e "  ${GREEN}✔ PASS${NC}  $*"; PASS=$((PASS+1)); }
warn(){ echo -e "  ${YELLOW}⚠ WARN${NC}  $*"; WARN=$((WARN+1)); }
fail(){ echo -e "  ${RED}✗ FAIL${NC}  $*"; FAIL=$((FAIL+1)); }
info(){ echo -e "  ${DIM}·      $*${NC}"; }
hint(){ echo -e "     ${DIM}↳ $*${NC}"; }
add_action(){ NEXT_ACTIONS+=("$1"); }

# Run from the repo root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "cannot cd to $SCRIPT_DIR"; exit 1; }

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║      AttackLens TLS / Caddy Auto-Troubleshoot     ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}${DIM}  repo: ${SCRIPT_DIR}${NC}"

# ── Detect environment ────────────────────────────────────────────────────────
DC="docker compose"
if ! docker compose version >/dev/null 2>&1; then
  command -v docker-compose >/dev/null 2>&1 && DC="docker-compose"
fi
TIMEOUT=""; command -v timeout >/dev/null 2>&1 && TIMEOUT="timeout 45"

getenv(){ [ -f .env ] && grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'; }

DOMAIN="$(getenv DOMAIN)"
PUBLIC_IP="$(getenv PUBLIC_IP)"
BIND_PORT="$(getenv BIND_PORT)"; BIND_PORT="${BIND_PORT:-8443}"
TLS_MODE="$(getenv TLS_MODE)"
DASH_HASH="$(getenv DASHBOARD_PASSWORD_HASH)"
CADDY="attacklens-caddy"
NET="$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -m1 'attacklens_internal')"

# Ports Caddy publishes: always 80, plus BIND_PORT.
PORTS=(80 "$BIND_PORT")

# ── Scenario 1: prerequisites ─────────────────────────────────────────────────
section "1. Prerequisites"
if command -v docker >/dev/null 2>&1; then pass "docker present ($(docker --version 2>/dev/null | cut -d, -f1))"
else fail "docker not found"; add_action "Install Docker Engine before anything else."; fi
if docker info >/dev/null 2>&1; then pass "docker daemon reachable"
else fail "docker daemon not reachable (is it running? are you root?)"; add_action "Start Docker: sudo systemctl start docker"; fi
[ -f docker-compose.yml ] && pass "docker-compose.yml found" || fail "docker-compose.yml missing — run from the repo root"
[ -f .env ] && pass ".env found" || warn ".env missing — run: bash env.sh"
[ -f Caddyfile ] && pass "Caddyfile found" || fail "Caddyfile missing — run: bash env.sh"

# ── Scenario 2: TLS config sanity ─────────────────────────────────────────────
section "2. TLS configuration"
info "TLS_MODE=${TLS_MODE:-<unset>}  DOMAIN=${DOMAIN:-<none>}  BIND_PORT=${BIND_PORT}  PUBLIC_IP=${PUBLIC_IP:-<unset>}"
if [ "$TLS_MODE" = "letsencrypt" ]; then
  [ -n "$DOMAIN" ] && pass "Let's Encrypt mode with domain ${DOMAIN}" || { fail "letsencrypt mode but DOMAIN empty"; add_action "Re-run env.sh and provide the domain."; }
  [ "$BIND_PORT" = "443" ] && pass "BIND_PORT=443 (standard HTTPS)" || warn "letsencrypt usually uses BIND_PORT=443 (found ${BIND_PORT})"
  if [ -f Caddyfile ] && grep -q "$DOMAIN" Caddyfile 2>/dev/null; then pass "Caddyfile references ${DOMAIN}"
  else warn "Caddyfile does not mention ${DOMAIN} — regenerate with env.sh"; fi
elif [ "$TLS_MODE" = "self-signed" ] || grep -q "tls internal" Caddyfile 2>/dev/null; then
  warn "self-signed mode — browsers will warn; no trusted cert. Set a domain via env.sh for real HTTPS."
  if [ -f Caddyfile ] && [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "localhost" ] && ! grep -q "$PUBLIC_IP" Caddyfile 2>/dev/null; then
    fail "self-signed Caddyfile does not include ${PUBLIC_IP} — remote agents can't reach it by IP"
    add_action "Regenerate Caddyfile so the site is '${PUBLIC_IP}:${BIND_PORT}, localhost:${BIND_PORT}'."
  fi
else
  info "TLS_MODE unrecognised; inferring from Caddyfile only."
fi

# ── Scenario 3: dashboard credential ──────────────────────────────────────────
section "3. Dashboard login credential"
if [ -n "$DASH_HASH" ]; then pass "DASHBOARD_PASSWORD_HASH is set"
else
  fail "DASHBOARD_PASSWORD_HASH is empty — login returns 503 'password not configured'"
  add_action "Set a dashboard password: make set-password EMAIL=you@co   (or re-run env.sh)."
fi

# ── Scenario 4: containers up & healthy ───────────────────────────────────────
section "4. Containers"
if docker info >/dev/null 2>&1; then
  $DC ps 2>/dev/null | sed '1d' | while read -r line; do info "$line"; done
  for c in attacklens-postgres attacklens-rabbitmq attacklens-threat-intel attacklens-manager attacklens-caddy; do
    st="$(docker inspect -f '{{.State.Status}}{{if .State.Health}}/{{.State.Health.Status}}{{end}}' "$c" 2>/dev/null)"
    if [ -z "$st" ]; then warn "$c not created"
    elif echo "$st" | grep -q "running"; then
      case "$st" in *unhealthy*) fail "$c is $st";; *) pass "$c is $st";; esac
    else fail "$c is $st"; fi
  done
  docker inspect -f '{{.State.Status}}' "$CADDY" 2>/dev/null | grep -q running \
    || add_action "Caddy is not running — check: $DC logs caddy   then: $DC up -d"
fi

# ── Scenario 5: host networking (IP forwarding, firewall) ─────────────────────
section "5. Host networking"
IPF="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
if [ "$IPF" = "1" ]; then pass "net.ipv4.ip_forward = 1"
else
  fail "net.ipv4.ip_forward = ${IPF:-unknown} — containers can't be routed to the internet"
  add_action "Enable IP forwarding:  sudo sysctl -w net.ipv4.ip_forward=1  &&  sudo systemctl restart docker"
fi
if command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | grep -qi "Status: active"; then
    warn "ufw is active — its FORWARD policy can silently drop container traffic"
    hint "check: sudo ufw status verbose  (DEFAULT_FORWARD_POLICY should allow forwarding)"
  else info "ufw present but inactive"; fi
fi
if command -v iptables >/dev/null 2>&1; then
  if iptables -t nat -S POSTROUTING 2>/dev/null | grep -qi masquerade; then pass "iptables NAT MASQUERADE rule present"
  else warn "no MASQUERADE rule in nat/POSTROUTING — Docker's NAT may be missing (restart docker)"; fi
fi

# ── Scenario 6: host port conflicts (the 'address already in use' case) ───────
section "6. Host port availability (80, ${BIND_PORT})"
port_holder(){
  local p="$1"
  if command -v ss >/dev/null 2>&1; then ss -ltn "sport = :${p}" 2>/dev/null | awk 'NR>1{print $4; exit}'
  elif command -v lsof >/dev/null 2>&1; then lsof -iTCP:"${p}" -sTCP:LISTEN -Pn 2>/dev/null | awk 'NR>1{print $1" pid="$2; exit}'; fi
}
for p in "${PORTS[@]}"; do
  h="$(port_holder "$p")"
  if [ -z "$h" ]; then
    # Free is only a problem if Caddy is supposed to be bound here.
    info "Port ${p} is free"
  elif docker ps --filter "name=${CADDY}" --format '{{.Ports}}' 2>/dev/null | grep -q ":${p}->"; then
    pass "Port ${p} held by ${CADDY} (expected)"
  else
    fail "Port ${p} in use by something else (${h}) — Caddy can't bind it"
    add_action "Free port ${p}:  sudo ss -ltnp 'sport = :${p}' ; sudo systemctl stop nginx apache2 2>/dev/null ; docker rm -f <name>  (or: $DC down && $DC up -d)"
  fi
done

# ── Scenario 7: container egress on the APP network (the critical one) ────────
section "7. Container internet egress on '${NET:-attacklens_internal}'"
if [ -z "$NET" ]; then
  warn "app network not found (is the stack up? try: $DC up -d)"
elif [ -n "${NO_EGRESS_TEST:-}" ]; then
  info "skipped (NO_EGRESS_TEST set)"
else
  internal="$(docker network inspect "$NET" -f '{{.Internal}}' 2>/dev/null)"
  [ "$internal" = "true" ] && { fail "network is 'internal:true' — no egress by design"; add_action "Set 'internal: false' for attacklens_internal in docker-compose.yml, then: $DC down && $DC up -d"; } \
                           || info "network internal=${internal:-?} (false = egress allowed)"
  masq="$(docker network inspect "$NET" -f '{{index .Options "com.docker.network.bridge.enable_ip_masquerade"}}' 2>/dev/null)"
  [ "$masq" = "false" ] && warn "enable_ip_masquerade=false on this network — NAT disabled" || true

  info "running a probe container on ${NET} (pulls alpine once)..."
  OUT="$($TIMEOUT docker run --rm --network "$NET" alpine sh -c '
    (ip route 2>/dev/null || route -n 2>/dev/null) | grep -qiE "default|^0\.0\.0\.0" && echo ROUTE-OK || echo ROUTE-NONE
    nslookup acme-v02.api.letsencrypt.org >/dev/null 2>&1 && echo DNS-OK || echo DNS-FAIL
    wget -qO- -T6 https://acme-v02.api.letsencrypt.org/directory >/dev/null 2>&1 && echo NET-OK || echo NET-FAIL
  ' 2>/dev/null)"
  echo "$OUT" | grep -q ROUTE-OK   && pass "container has a default route" || { fail "container has NO default route on ${NET}"; add_action "Rebuild the network:  $DC down && $DC up -d   (ensure ip_forward=1 first)"; }
  echo "$OUT" | grep -q DNS-OK     && pass "container DNS resolves"        || fail "container DNS fails (check dns: entries in docker-compose.yml)"
  if echo "$OUT" | grep -q NET-OK; then
    pass "container can REACH Let's Encrypt — egress OK ✅"
  else
    fail "container CANNOT reach the internet — this blocks the ACME cert"
    add_action "Fix container egress: (1) sudo sysctl -w net.ipv4.ip_forward=1 && sudo systemctl restart docker  (2) $DC down && $DC up -d  (3) re-run this script"
  fi
fi

# ── Scenario 8: DNS — does the domain point HERE? ─────────────────────────────
section "8. DNS record for ${DOMAIN:-<no domain>}"
if [ -z "$DOMAIN" ]; then info "no domain configured (self-signed / IP mode) — skipping"
else
  resolve_a(){
    if command -v dig >/dev/null 2>&1; then dig +short A "$1" 2>/dev/null | grep -E '^[0-9]' | head -1
    elif command -v host >/dev/null 2>&1; then host -t A "$1" 2>/dev/null | awk '/has address/{print $NF; exit}'
    elif command -v getent >/dev/null 2>&1; then getent ahostsv4 "$1" 2>/dev/null | awk '{print $1; exit}'; fi
  }
  A="$(resolve_a "$DOMAIN")"
  if [ -z "$A" ]; then warn "could not resolve ${DOMAIN} (no dig/host/getent, or record missing)"
  elif [ -n "$PUBLIC_IP" ] && [ "$A" = "$PUBLIC_IP" ]; then pass "${DOMAIN} → ${A} (matches PUBLIC_IP)"
  else
    warn "${DOMAIN} → ${A}, but PUBLIC_IP=${PUBLIC_IP:-?} — if these differ, Let's Encrypt's challenge will hit the wrong host"
    hint "Point the A record at this server, or fix PUBLIC_IP in .env."
  fi
fi

# ── Scenario 9: inbound reachability (firewall for the ACME challenge) ─────────
section "9. Inbound ports (Let's Encrypt challenge needs 80 + 443)"
for p in 80 443; do
  if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :${p}" 2>/dev/null | awk 'NR>1' | grep -q .; then
    pass "something is LISTENing on :${p} (host side)"
  else
    warn "nothing listening on :${p} on the host"
  fi
done
info "Listening ≠ reachable. Confirm 80 AND 443 are OPEN inbound in the cloud security group / firewall."
hint "External check (from your laptop): curl -sS -m 8 -o /dev/null -w '%{http_code}\\n' http://${DOMAIN:-$PUBLIC_IP}/"

# ── Scenario 10: certificate status ───────────────────────────────────────────
section "10. Certificate status"
if [ -n "$DOMAIN" ] && docker inspect -f '{{.State.Status}}' "$CADDY" 2>/dev/null | grep -q running; then
  CRT="$(docker exec "$CADDY" sh -c "find /data/caddy/certificates -name '${DOMAIN}.crt' 2>/dev/null | head -1" 2>/dev/null)"
  if [ -n "$CRT" ]; then
    pass "Caddy holds a certificate for ${DOMAIN}"
    info "path (in container): ${CRT}"
  else
    fail "no issued certificate for ${DOMAIN} yet"
    if $DC logs --tail 40 caddy 2>/dev/null | grep -qi "obtained successfully"; then
      info "…but a recent log says it was obtained — re-check after a restart"
    fi
    LASTERR="$($DC logs --tail 60 caddy 2>/dev/null | grep -iE 'could not get certificate|network is unreachable|connection refused|timeout|no such host|urn:ietf' | tail -1)"
    [ -n "$LASTERR" ] && hint "last ACME error: ${LASTERR}"
    add_action "Resolve the failing scenario above (egress / DNS / firewall), then Caddy auto-retries within ~1–2 min."
  fi
else
  info "self-signed mode or Caddy down — no ACME cert expected."
fi

# ── Scenario 11: live endpoint probe ──────────────────────────────────────────
section "11. Endpoint probe"
if command -v curl >/dev/null 2>&1; then
  if [ "$TLS_MODE" = "letsencrypt" ] && [ -n "$DOMAIN" ]; then
    CODE="$(curl -sS -m 8 -o /dev/null -w '%{http_code}' "https://${DOMAIN}/health" 2>/dev/null)"
    [ "$CODE" = "200" ] && pass "https://${DOMAIN}/health → 200 (trusted TLS working)" \
                        || warn "https://${DOMAIN}/health → ${CODE:-no response} (not serving a trusted cert yet)"
  else
    CODE="$(curl -ksS -m 8 -o /dev/null -w '%{http_code}' "https://${PUBLIC_IP:-localhost}:${BIND_PORT}/health" 2>/dev/null)"
    [ "$CODE" = "200" ] && pass "https://${PUBLIC_IP:-localhost}:${BIND_PORT}/health → 200 (self-signed, -k)" \
                        || warn "self-signed endpoint → ${CODE:-no response}"
  fi
else info "curl not available — skipping endpoint probe"; fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASS ${PASS}${NC}   ${YELLOW}WARN ${WARN}${NC}   ${RED}FAIL ${FAIL}${NC}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
if [ "${#NEXT_ACTIONS[@]}" -gt 0 ]; then
  echo -e "${BOLD}  Most important next step:${NC}"
  echo -e "    ${YELLOW}➤ ${NEXT_ACTIONS[0]}${NC}"
  if [ "${#NEXT_ACTIONS[@]}" -gt 1 ]; then
    echo -e "${DIM}  Then, in order:${NC}"
    for i in $(seq 1 $(( ${#NEXT_ACTIONS[@]} - 1 ))); do echo -e "${DIM}    - ${NEXT_ACTIONS[$i]}${NC}"; done
  fi
else
  echo -e "  ${GREEN}No blocking issues detected. If HTTPS still fails, re-run after a minute (ACME retries).${NC}"
fi
echo ""
# Exit non-zero when something is broken, so CI / scripts can gate on it.
[ "$FAIL" -eq 0 ]
