# AttackLens — Complete Step-by-Step Setup Guide

> **Goal**: Manager running on a server + macOS agent enrolled and sending telemetry.
> **Time**: 20–30 minutes on a fresh server.
> **Prerequisites**: A Linux server (Ubuntu 22.04+ recommended) with Docker installed, and a macOS endpoint.

---

## Part 1 — Deploy the Manager

### Step 1: Clone the Repository

```bash
git clone <repo-url> attacklens
cd attacklens
```

### Step 2: Install Docker (if not already installed)

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

### Step 3: Run the Interactive Setup Wizard

`env.sh` auto-detects your IP, asks a few questions, and generates your `.env` + `Caddyfile`.

```bash
bash env.sh
```

The wizard will ask:
1. **IP or domain?** — Enter your server's public IP (or domain name for Let's Encrypt TLS)
2. **Open enrollment?** — `y` = any agent can connect; `n` = agents need a token
3. **SMTP email?** — Optional, for alerts

It generates:
- `.env` with `ADMIN_TOKEN`, `ENROLLMENT_TOKENS`, all secrets
- `Caddyfile` configured for self-signed or Let's Encrypt TLS

**Save the tokens printed at the end** — you'll need `ADMIN_TOKEN` for the dashboard and `ENROLLMENT_TOKEN` for agents.

### Step 4: (Optional) Add API Keys to `.env`

Open `.env` and fill in optional keys for enhanced intelligence:

```bash
# AI analysis — highly recommended
ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE

# Threat intelligence enrichment (all optional)
ABUSEIPDB_KEY=your_key
OTX_KEY=your_key
GREYNOISE_KEY=your_key

# Email alerts
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@yourorg.com
SMTP_PASS=your_app_password
SMTP_FROM=AttackLens <alerts@yourorg.com>
ALERT_RECIPIENTS=soc@yourorg.com,security@yourorg.com
```

### Step 5: Start the Full Stack

```bash
docker compose up -d
```

This starts 4 containers:
- `jarvis-rabbitmq` — Message queue
- `attacklens-threat-intel` — Threat feed sync service
- `jarvis-manager` — Main application
- `jarvis-caddy` — TLS reverse proxy

Watch the startup:

```bash
docker compose logs -f
```

Wait until you see:
```
jarvis-manager  | INFO: Jarvis engine started
jarvis-manager  | INFO: ThreatIntelWorker started
jarvis-manager  | INFO: Application startup complete.
```

### Step 6: Verify the Manager is Running

```bash
# Health check
curl http://localhost:8080/health

# Expected response:
# {"status":"ok","version":"...","agents":0,"db":"connected"}

# Check all services are healthy
docker compose ps
```

All services should show `(healthy)` status.

### Step 7: Access the Dashboard

Open a browser and navigate to:
- **Self-signed**: `https://YOUR_SERVER_IP:8443` (accept the cert warning)
- **Domain (Let's Encrypt)**: `https://YOUR_DOMAIN`

Log in with your `ADMIN_TOKEN` from Step 3.

---

## Part 2 — Install the macOS Agent

### Step 8: Build the Agent Package (on the manager server)

```bash
# On the server, build the PKG installer
cd agent/os/macos/installer
sudo bash build_pkg.sh
```

This produces `attacklens-agent-1.0.pkg` in the `dist/` directory.

### Step 9: Transfer the Package to the macOS Endpoint

```bash
# From your Mac, download from the server
scp user@YOUR_SERVER:~/attacklens/agent/os/macos/installer/dist/attacklens-agent-1.0.pkg ~/Downloads/
```

Or serve it directly from the manager:
```bash
# On the server
python3 -m http.server 9999 --directory agent/os/macos/installer/dist/
```
Then download from: `http://YOUR_SERVER:9999/attacklens-agent-1.0.pkg`

### Step 10: Install the Agent on macOS

```bash
# On the macOS endpoint
sudo installer -pkg ~/Downloads/attacklens-agent-1.0.pkg -target /
```

This installs to `/Library/AttackLens/` and registers two LaunchDaemons.

### Step 11: Configure the Agent

```bash
# Generate agent.toml with your manager URL
sudo /Library/AttackLens/bin/generate_config.sh \
  --manager-url https://YOUR_SERVER_IP:8443 \
  --tls-verify false   # only if using self-signed cert
```

If you set `OPEN_ENROLLMENT=false`, also add the token:
```bash
sudo /Library/AttackLens/bin/generate_config.sh \
  --manager-url https://YOUR_SERVER_IP:8443 \
  --enrollment-token sk-enroll-YOUR_TOKEN_HERE \
  --tls-verify false
```

You can also edit the config manually:
```bash
sudo nano /Library/AttackLens/agent.toml
```

Key fields:
```toml
[agent]
name = "Rutik-MacBook"          # friendly name on dashboard

[manager]
url = "https://YOUR_SERVER_IP:8443"
tls_verify = false              # false for self-signed certs

[enrollment]
token = "sk-enroll-..."         # leave empty if OPEN_ENROLLMENT=true
```

### Step 12: Start the Agent

```bash
# Load and start the agent LaunchDaemon
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/com.attacklens.agent.plist

# Load and start the watchdog
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/com.attacklens.watchdog.plist
```

### Step 13: Verify the Agent is Running

```bash
# Check status
sudo /Library/AttackLens/bin/attacklens-ctl status

# Watch the agent log
sudo /Library/AttackLens/bin/attacklens-ctl logs

# Expected log output:
# INFO  Enrollment complete. Agent ID: mac-XXXXXXXX
# INFO  Sending section: metrics
# INFO  Sending section: connections
# INFO  Sending section: processes
```

### Step 14: Confirm on the Dashboard

Refresh the dashboard at `https://YOUR_SERVER_IP:8443`.

Your Mac should appear as an enrolled agent within 30 seconds. You'll start seeing:
- **Volatile telemetry** (metrics, connections, processes) within 10 seconds
- **First findings** within 1–2 minutes (as the detection engine processes data)
- **Threat intel correlations** within 5–10 minutes (as feeds sync)

---

## Part 3 — Verify Everything is Working

### Step 15: Check Threat Intelligence Feeds

```bash
# On the server
curl http://localhost:8090/api/v1/intel/summary
```

Expected: feed counts showing IOCs ingested. Feeds take 5–10 minutes to fully populate on first run.

```bash
# Check feed health
curl http://localhost:8090/api/v1/intel/feeds
```

### Step 16: Verify AI Analysis (if ANTHROPIC_API_KEY is set)

Navigate to the dashboard → Findings → click any finding → "Generate AI Analysis".

Or via API:
```bash
curl -X POST http://localhost:8080/api/v1/remediation/1/analysis/generate \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Step 17: Test Email Notifications

```bash
# On the server
curl -X POST http://localhost:8080/api/v1/test/email \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"recipient": "your@email.com", "type": "test"}'
```

---

## Part 4 — Day 2 Operations

### Managing the Manager

```bash
# View logs
docker compose logs -f manager
docker compose logs -f threat-intel

# Restart a service
docker compose restart manager

# Update (pull latest image and restart)
docker compose pull
docker compose up -d

# Stop everything
docker compose down

# Stop and remove all data (DESTRUCTIVE)
docker compose down -v
```

### Managing the Agent

```bash
# Check status
sudo attacklens-ctl status

# Start / stop / restart
sudo attacklens-ctl start
sudo attacklens-ctl stop
sudo attacklens-ctl restart

# Reload config without restart (hot reload)
sudo attacklens-ctl reload

# View live logs
sudo attacklens-ctl logs

# Force re-enrollment (clears stored key)
sudo attacklens-ctl enroll

# Uninstall completely
sudo /Library/AttackLens/uninstall.sh
```

### Rotating Admin Token

```bash
# Edit .env
nano .env
# Change ADMIN_TOKEN to a new value

# Restart manager
docker compose restart manager
```

### Rotating an Agent Key

```bash
# Via admin API
curl -X POST http://localhost:8080/api/v1/keys/mac-AGENT_ID/rotate \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

# Agent will re-enroll automatically on next heartbeat
# Or force it immediately:
sudo attacklens-ctl enroll
```

### Adding More Agents

Repeat Steps 9–14 for each additional macOS endpoint. Each agent auto-generates a unique hardware UUID and gets its own API key.

---

## Troubleshooting

### Agent won't connect

```bash
# Check the agent log
sudo attacklens-ctl logs

# Test connectivity
curl -k https://YOUR_SERVER_IP:8443/health

# Common issues:
# - tls_verify = true but using self-signed cert → set to false
# - Firewall blocking port 8443 → open it
# - Wrong manager URL in agent.toml
```

### Manager won't start

```bash
# Check what's wrong
docker compose logs manager

# Common issues:
# - Port 8080 already in use → change BIND_PORT in .env
# - SQLite locked → stop other processes using data/
# - RabbitMQ not ready → wait 30s and retry
```

### No findings appearing

```bash
# Check Jarvis engine is running
docker compose logs manager | grep -i jarvis

# Check RabbitMQ queue depth
curl http://localhost:15672/api/queues/%2F/agent.telemetry \
  -u jarvis:changeme

# Check the intel DB
docker compose exec manager sqlite3 /app/data/intel.db \
  "SELECT count(*) FROM findings;"
```

### Feeds not populating

```bash
# Check threat intel service
docker compose logs threat-intel

# Check feed health
curl http://localhost:8090/api/v1/intel/feeds

# Feeds need internet access — verify the container can reach external URLs
docker compose exec threat-intel curl -s https://feodotracker.abuse.ch/downloads/ipblocklist.json | head -5
```

### AI analysis returns 503

```bash
# Verify API key is set
docker compose exec manager env | grep ANTHROPIC

# Check for billing/quota issues in Anthropic console
# Restart after adding key
docker compose restart manager
```

---

## Ports Reference

| Port | Service | Purpose |
|---|---|---|
| `8443` | Caddy | HTTPS — agents and dashboard (self-signed mode) |
| `443` | Caddy | HTTPS — agents and dashboard (Let's Encrypt mode) |
| `80` | Caddy | HTTP (Let's Encrypt ACME challenge only) |
| `8080` | Manager | Direct HTTP access (internal/trusted network only) |
| `8090` | Threat Intel | Central intel API (internal only) |
| `5672` | RabbitMQ | AMQP (internal only) |
| `15672` | RabbitMQ | Management UI (internal only, for debugging) |

---

## Security Checklist Before Going to Production

- [ ] Change default `RABBITMQ_PASS` in `.env`
- [ ] Set a strong `ADMIN_TOKEN` (32+ random characters)
- [ ] Set `OPEN_ENROLLMENT=false` if deploying to untrusted networks
- [ ] Configure TLS with a real domain (Let's Encrypt) instead of self-signed
- [ ] Restrict port `8090` and `15672` to localhost-only in production
- [ ] Set up email alerts: `ALERT_RECIPIENTS` for critical findings
- [ ] Back up `./data/` directory regularly (contains all findings + telemetry)
- [ ] Set `DEFAULT_KEY_EXPIRY_DAYS=90` for key rotation policy
