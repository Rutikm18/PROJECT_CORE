# Manager Installation Guide

The manager is a Docker Compose application (Caddy + FastAPI).
Total setup time: ~5 minutes on a fresh Linux server.

---

## Requirements

| | Minimum | Recommended |
|-|---------|-------------|
| OS | Ubuntu 22.04 / Debian 12 / Amazon Linux 2023 | Ubuntu 22.04 LTS |
| CPU | 1 vCPU | 2 vCPU |
| RAM | 512 MB | 2 GB |
| Disk | 5 GB | 20 GB |
| Docker | 24.x | latest |
| Docker Compose | v2.x | latest |
| Ports | 8443 (or 443) open | 443 + 80 for Let's Encrypt |

---

## Step 1 — Install Docker (skip if already installed)

```bash
# Ubuntu / Debian
curl -fsSL https://get.docker.com | sudo bash
sudo usermod -aG docker $USER
newgrp docker        # apply group without logout

# Amazon Linux 2023
sudo dnf install -y docker
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

Verify:
```bash
docker compose version    # must show v2.x
```

---

## Step 2 — Clone the Repository

```bash
cd ~
git clone <REPO_URL> macbook_data
cd macbook_data
```

---

## Step 3 — Run Interactive Setup

```bash
bash env.sh
```

This script will:

1. **Detect your public IP** automatically via multiple services
2. **Ask about TLS mode:**
   - Option A: IP-only (self-signed cert, `tls_verify = false` on agents) — no domain needed
   - Option B: Domain (real Let's Encrypt cert, `tls_verify = true` on agents)
3. **Ask about enrollment mode:**
   - OPEN: any agent with the manager URL connects freely (recommended for single operator)
   - TOKEN: agents must supply a pre-shared token (for multi-team deployments)
4. **Generate secrets** (`ADMIN_TOKEN`, `ENROLLMENT_TOKENS`)
5. **Write** `.env` and `Caddyfile`

**Example output:**
```
▶  Detecting public IP
   ✔  Detected: 54.213.44.12

▶  TLS configuration
   ✔  IP-only mode (Caddy internal self-signed cert on port 8443)

▶  Enrollment mode
   ✔  Open enrollment (no token needed)

▶  Generating secrets
   ✔  Admin token   : sk-admin-Kjd8mNpQ... (full value in .env)

▶  Writing .env
▶  Writing Caddyfile
▶  Creating runtime directories
   ✔  data/ logs/ ready

  ╔══════════════════════════════════════════════════════════╗
  ║           ✔  Setup Complete — Ready to Launch           ║
  ╚══════════════════════════════════════════════════════════╝

  Manager URL:   https://54.213.44.12:8443
  Admin token :  sk-admin-Kjd8mNpQXyz...
  Enrollment  :  OPEN (no token needed)

  Install agent on macOS:
    sudo installer -pkg macintel-agent-2.0.0-arm64.pkg -target /
    sudo nano /Library/Jarvis/agent.toml
    # Set:
    #   url        = "https://54.213.44.12:8443"
    #   tls_verify = false
```

---

## Step 4 — Fix Directory Ownership

The manager container runs as uid 1000. Create the runtime directories
with the correct ownership before starting:

```bash
mkdir -p data logs
sudo chown -R 1000:1000 data logs
```

---

## Step 5 — Start the Manager

```bash
docker compose up -d
```

Wait 20–30 seconds for startup, then check:

```bash
# Check container status
docker compose ps

# Expected output:
# NAME              STATUS          PORTS
# jarvis-caddy      running         0.0.0.0:8443->8443/tcp
# jarvis-manager    running (healthy)

# View startup logs (tokens printed here)
docker compose logs manager

# Health check
curl -sk https://localhost:8443/health
# {"status":"ok","db":"ok","store":{...}}
```

---

## Step 6 — Save Your Credentials

```bash
cat .env | grep -E 'ADMIN_TOKEN|ENROLLMENT_TOKENS|PUBLIC_IP|BIND_PORT'
```

Save these securely:
- `ADMIN_TOKEN` — protects the key management API
- `ENROLLMENT_TOKENS` — enrollment token (if token-mode enabled)
- Manager URL — `https://<PUBLIC_IP>:<BIND_PORT>`

---

## Operations

### View Logs

```bash
docker compose logs -f manager     # application logs
docker compose logs -f caddy       # TLS / access logs
```

### Restart

```bash
docker compose restart manager
docker compose restart             # restart all
```

### Upgrade

```bash
git pull
docker compose build --no-cache manager
docker compose up -d
```

### Backup

```bash
# Database files
cp -r data/ backup-$(date +%Y%m%d)/

# Config
cp .env Caddyfile backup-$(date +%Y%m%d)/
```

### Rotate an Agent Key (via Admin API)

```bash
ADMIN_TOKEN=$(grep ADMIN_TOKEN .env | cut -d= -f2)
MANAGER_URL="https://$(grep PUBLIC_IP .env | cut -d= -f2):$(grep BIND_PORT .env | cut -d= -f2)"

# List all agent keys
curl -sk -H "X-Admin-Token: $ADMIN_TOKEN" $MANAGER_URL/api/v1/keys | python3 -m json.tool

# Rotate a specific agent's key
curl -sk -X POST -H "X-Admin-Token: $ADMIN_TOKEN" $MANAGER_URL/api/v1/keys/mac-abc123/rotate

# Revoke (agent must re-enroll)
curl -sk -X POST -H "X-Admin-Token: $ADMIN_TOKEN" $MANAGER_URL/api/v1/keys/mac-abc123/revoke
```

---

## Configuration Reference (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `PUBLIC_IP` | (auto) | Server's public IP address |
| `DOMAIN` | `` | Domain name (Let's Encrypt mode) |
| `BIND_PORT` | `8443` | Caddy listening port |
| `TLS_MODE` | `self-signed` | `self-signed` or `letsencrypt` |
| `ADMIN_TOKEN` | (generated) | Admin API token (sk-admin-...) |
| `OPEN_ENROLLMENT` | `true` | `true`=any agent; `false`=token required |
| `ENROLLMENT_TOKENS` | (generated) | Enrollment token(s) (sk-enroll-...) |
| `DEFAULT_KEY_EXPIRY_DAYS` | `0` | Agent key lifetime in days (0=never) |
| `LOG_LEVEL` | `info` | Logging level (debug/info/warning/error) |
| `CORS_ORIGINS` | `*` | Allowed CORS origins |

---

## Firewall Rules

```bash
# Ubuntu UFW
sudo ufw allow 8443/tcp comment "mac_intel Manager (self-signed)"
# OR for domain mode:
sudo ufw allow 443/tcp  comment "mac_intel Manager (HTTPS)"
sudo ufw allow 80/tcp   comment "Let's Encrypt ACME challenge"

# AWS Security Group
# Inbound: TCP 8443 (or 443) from 0.0.0.0/0
# Outbound: all (for threat feed downloads and ACME challenges)
```

---

## Troubleshooting

**Permission denied on data/**
```bash
sudo chown -R 1000:1000 data logs
docker compose restart manager
```

**Manager container not healthy**
```bash
docker compose logs manager | tail -50
# Usually missing pip dependency or DB permission issue
```

**Caddy TLS error / cert not trusted**
For self-signed mode: agents set `tls_verify = false` — this is expected.
For Let's Encrypt: DNS must point to your server BEFORE first boot.

**No findings appearing**
```bash
# Check agent enrolled
curl -sk $MANAGER_URL/api/v1/agents | python3 -m json.tool

# Check ingest is receiving data
docker compose logs manager | grep ingest
```

**aiohttp / module import error**
```bash
docker compose build --no-cache manager
docker compose up -d
```
