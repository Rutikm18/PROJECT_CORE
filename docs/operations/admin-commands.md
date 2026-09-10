# AttackLens — Admin Operations Runbook

Day-to-day operator commands for a deployed AttackLens manager: managing agents,
dashboard login, org name, licensing, and the stack lifecycle.

**Where to run these:** on the manager host, from the repo root
(e.g. `cd /home/ubuntu/attacklens_AEM/attacklens`). The `make` targets wrap the
right `docker compose` call for you, so the stack must be up (`docker compose ps`).

**Secrets:** `ADMIN_TOKEN`, `DASHBOARD_*`, and `JWT_SECRET` live in `.env` (owner-only).
API examples below use `$MANAGER_URL` (e.g. `https://console.attacklens.ai:8443`)
and the `ADMIN_TOKEN` from `.env`.

---

## 1. Agents

### List agents (always do this before deleting)
```bash
make list-agents
```

### Delete an agent and ALL its data
Removes the agent plus every row it produced across both databases. The command
now **de-enrolls the agent first** (revokes its key so ingest is rejected even
while it's online), waits for in-flight writes to drain, then deletes — so it no
longer deadlocks against a live agent.
```bash
# Preview first (no changes):
make delete-agents AGENTS="mac-xxxx" DRY_RUN=1

# Delete specific agents (space-separated), skipping the confirm prompt:
make delete-agents AGENTS="mac-xxxx mac-yyyy" YES=1

# Delete everything older than 30 days:
make delete-agents OLDER_THAN=30d YES=1

# Delete ALL agents (dangerous):
make delete-agents ALL=1 YES=1
```
- Tune the drain wait with `DELETE_AGENT_DRAIN_SECONDS` (default `2`; `0` to skip):
  `DELETE_AGENT_DRAIN_SECONDS=5 make delete-agents AGENTS="mac-xxxx" YES=1`
- **If you ever see `deadlock detected`:** just re-run the command (it's transient
  and the delete is one transaction — nothing is partially removed). Guaranteed
  fallback: `docker compose stop manager` → run the delete → `docker compose start manager`.

---

## 2. Dashboard login (password & username/email)

Only the PBKDF2 hash is stored in `.env`; the plaintext is shown once and is not recoverable.

### Set / reset the password (prompts securely)
```bash
make set-password
# or also change the login email at the same time:
make set-password EMAIL=admin@yourco.com
# non-interactive (visible to `ps` — use with care):
make set-password EMAIL=admin@yourco.com PASSWORD='Str0ng#Passw0rd!2026'
```
Password policy: 16–128 chars with upper, lower, digit, and symbol. Add `ALLOW_WEAK=1`
to bypass (not recommended). `make reset-password` is an alias for the same thing.

### Change the login email / username only (no password change)
```bash
make set-email EMAIL=admin@yourco.com
```
Both targets recreate the manager container so the new credential takes effect.

---

## 3. Organization name
The org name shown in the dashboard is backend-locked; set it from the host:
```bash
make set-org-name NAME="Acme Corp"
```

---

## 4. Licensing (raise the agent cap / extend expiry)

A license is a **signed key** carrying entitlements — `max_agents` (agent cap),
expiry, tier, and features. The active key is stored as `license_key` in settings
(masked on read). Check current status:
```bash
curl -s "$MANAGER_URL/api/v1/settings/license" -H "X-Admin-Token: $ADMIN_TOKEN"
```

**To increase the cap / extend validity, issue a new key with a higher `max_agents`,
then install it.** Two paths depending on how this manager is run:

### A. Operator/customer portal enabled (`CUSTOMER_PORTAL_LIVE`)
Rotate the org's license to a higher cap — returns a fresh `license_key`:
```bash
# Find the org id:
curl -s "$MANAGER_URL/api/v1/customers" -H "X-Admin-Token: $ADMIN_TOKEN"

# Rotate to a new cap / validity (issues + applies a new signed key):
curl -s -X POST "$MANAGER_URL/api/v1/customers/<ORG_ID>/license/rotate" \
     -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
     -d '{"max_agents": 250, "valid_days": 365, "tier": "standard"}'
```
Creating a brand-new org + its first license uses `POST /api/v1/customers`
(`{"name","slug","max_agents","valid_days","tier"}`).

### B. Single self-hosted manager (install a provided key)
Paste the new key in the dashboard under **Settings → License**, or via the API:
```bash
curl -s -X PUT "$MANAGER_URL/api/v1/settings" \
     -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
     -d '{"license_key": "XXXX-XXXX-XXXX-..."}'
```
> Minting a key requires the server's signing key (done by the customers endpoint
> in path A). If the portal isn't enabled, obtain a new key for your higher
> `max_agents` from whoever issues your licenses, then install it as above.

---

## 5. Stack lifecycle

### First-time setup / reconfigure (generates `.env` + `Caddyfile`)
```bash
bash env.sh            # safe to re-run: existing secrets are preserved, never wiped
```

### Start / stop / status / logs
```bash
make up          # docker compose up -d (start the full stack)
make ps          # container status
make logs        # tail all services
make logs-manager
make restart     # restart the manager container only
make down        # stop + remove containers (data volumes are preserved)
```

### Deploy new code after a pull
```bash
git pull origin main
docker compose build manager   # rebuild if backend deps/code changed
docker compose up -d
```

### Rebuild the dashboard UI (after front-end changes)
```bash
make dashboard   # build React app into manager/dashboard/static/
```

---

## 6. TLS / HTTPS

Diagnose any "why isn't HTTPS working" issue (config, DNS, container egress,
port conflicts, cert status) in one read-only run:
```bash
bash troubleshoot_tls.sh
```
TLS is configured by `bash env.sh` (domain → Let's Encrypt on 443; IP-only →
self-signed on 8443). If another service (e.g. a Wazuh dashboard) already holds
port 443, set `BIND_PORT=8443` in `.env` and recreate Caddy — see the script's
guidance.

---

## 7. Reports export

From the dashboard **Reports** page (`/reports`): export Deep Analysis + DeepMesh
telemetry and full incident detail (evidence, scores, remediation, actions,
timeline history) as Excel/CSV. For very large exports the UI streams from the
backend endpoint `GET /api/v1/reports/export?type=all|incident|telemetry&format=xlsx|csv`.

---

## Quick reference

| Task | Command |
|---|---|
| List agents | `make list-agents` |
| Delete agent(s) | `make delete-agents AGENTS="id" YES=1` |
| Preview delete | `make delete-agents AGENTS="id" DRY_RUN=1` |
| Set/reset password | `make set-password [EMAIL=…] [PASSWORD=…]` |
| Change login email | `make set-email EMAIL=you@co` |
| Set org name | `make set-org-name NAME="Acme Corp"` |
| License status | `curl $MANAGER_URL/api/v1/settings/license -H "X-Admin-Token: $ADMIN_TOKEN"` |
| Raise agent cap | `POST /api/v1/customers/<org>/license/rotate` or Settings → License |
| Start / stop | `make up` / `make down` |
| Logs / status | `make logs` / `make ps` |
| Restart manager | `make restart` |
| Rebuild UI | `make dashboard` |
| Diagnose TLS | `bash troubleshoot_tls.sh` |
