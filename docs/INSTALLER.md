# AttackLens — Installation Guide

Complete guide for deploying the Manager and installing the macOS agent.

---

## Table of Contents
1. [Manager Installation](#1-manager-installation)
   - [Docker Compose (recommended)](#option-a-docker-compose-recommended)
   - [Manual / bare metal](#option-b-manual-bare-metal)
   - [AWS EC2 quick deploy](#option-c-aws-ec2-quick-deploy)
2. [macOS Agent Installation](#2-macos-agent-installation)
   - [PKG installer (recommended)](#option-a-pkg-installer-recommended)
   - [Manual script install](#option-b-manual-script-install)
   - [Mass deployment (MDM / Jamf)](#option-c-mass-deployment-mdm--jamf)
3. [TLS Configuration](#3-tls-configuration)
4. [Agent Configuration Reference](#4-agent-configuration-reference)
5. [Post-Installation Verification](#5-post-installation-verification)
6. [Uninstallation](#6-uninstallation)
7. [Upgrade Guide](#7-upgrade-guide)

---

## 1. Manager Installation

### Option A: Docker Compose (recommended)

**Requirements:**
- Linux server (Ubuntu 22.04+ / Debian 12 / RHEL 9)
- Docker 20.10+ and Compose v2
- 2 vCPU / 4 GB RAM minimum
- Ports 443 (or 8443) and 80 open in firewall

**Step 1 — Install Docker**

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```

```bash
# RHEL / Rocky Linux / Amazon Linux 2023
sudo dnf install -y docker docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```

**Step 2 — Clone and configure**

```bash
git clone <repo-url> attacklens
cd attacklens

# Run the interactive setup wizard
bash env.sh
```

The wizard generates:
- `.env` — all environment variables with auto-generated secrets
- `Caddyfile` — TLS configuration (self-signed for IP, or Let's Encrypt for domain)

**Step 3 — Start services**

```bash
docker compose up -d

# Monitor startup
docker compose logs -f

# Verify all services are healthy
docker compose ps
```

**Step 4 — Open firewall ports**

```bash
# Ubuntu (ufw)
sudo ufw allow 8443/tcp   # self-signed mode
sudo ufw allow 443/tcp    # Let's Encrypt mode
sudo ufw allow 80/tcp     # ACME challenge (Let's Encrypt only)

# AWS (add to Security Group inbound rules)
# Port 8443 TCP from 0.0.0.0/0 (or restrict to your network)
```

---

### Option B: Manual / Bare Metal

**Requirements:**
- Python 3.11+
- RabbitMQ 3.12+ (must be running separately)

```bash
git clone <repo-url> attacklens
cd attacklens

# Install Python dependencies
pip install -r manager/requirements.txt

# Create data directories
mkdir -p data/threat-intel data/hot data/warm data/cold logs

# Set required environment variables (or create a .env file)
export ENROLLMENT_TOKENS="sk-enroll-$(openssl rand -hex 32)"
export ADMIN_TOKEN="sk-admin-$(openssl rand -hex 32)"
export RABBITMQ_URL="amqp://user:pass@localhost:5672/"
export DATA_DIR="./data"
export LOG_FILE="./logs/manager.log"

# Start the manager
cd manager
uvicorn manager.server:app --host 0.0.0.0 --port 8080

# Start the threat intel service (separate process)
uvicorn manager.manager.threat_intel_service:app --host 0.0.0.0 --port 8090
```

For TLS, put Caddy or Nginx in front of port 8080.

---

### Option C: AWS EC2 Quick Deploy

**Launch a t3.medium (or larger) with Ubuntu 22.04:**

```bash
# SSH into your EC2 instance
ssh -i your-key.pem ubuntu@YOUR_EC2_IP

# One-shot setup
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu && newgrp docker

git clone <repo-url> attacklens && cd attacklens

# Run wizard with your EC2 public IP auto-detected
bash env.sh

docker compose up -d
```

**Security Group rules required:**

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 8443 | TCP | 0.0.0.0/0 | HTTPS (agent + dashboard) — self-signed mode |
| 443 | TCP | 0.0.0.0/0 | HTTPS (agent + dashboard) — Let's Encrypt mode |
| 80 | TCP | 0.0.0.0/0 | Let's Encrypt ACME challenge |
| 22 | TCP | Your IP | SSH management |

---

## 2. macOS Agent Installation

### Option A: PKG Installer (recommended)

**Step 1 — Build the PKG on the server**

```bash
# On the manager server
cd attacklens/agent/os/macos/installer
sudo bash build_pkg.sh

# Output: dist/attacklens-agent-1.0.pkg
```

**Step 2 — Transfer to endpoint**

```bash
# SCP from server
scp user@SERVER:~/attacklens/agent/os/macos/installer/dist/attacklens-agent-1.0.pkg ~/Downloads/

# Or serve via HTTP from the manager
python3 -m http.server 9000 --directory dist/
# → Download from http://SERVER_IP:9000/attacklens-agent-1.0.pkg
```

**Step 3 — Install on macOS**

```bash
# Install the package (requires admin / sudo)
sudo installer -pkg ~/Downloads/attacklens-agent-1.0.pkg -target /
```

Or double-click the PKG in Finder and follow the installer wizard.

**What the PKG installs:**

```
/Library/AttackLens/
├── bin/
│   ├── attacklens-agent      # Main agent binary
│   ├── attacklens-watchdog   # Crash recovery watchdog
│   ├── attacklens-ctl        # Management CLI
│   └── generate_config.sh    # Config generator
├── agent.toml                # Configuration (auto-generated by generate_config.sh)
├── security/                 # API key storage (mode 700, root only)
├── data/                     # In-flight telemetry queue
├── spool/                    # Offline send queue (NDJSON+gzip)
├── logs/                     # Rotating log files
└── QUICKSTART.md

/Library/LaunchDaemons/
├── com.attacklens.agent.plist    # Agent service definition
└── com.attacklens.watchdog.plist # Watchdog service definition
```

**Step 4 — Configure the agent**

```bash
# Minimum configuration — just the manager URL
sudo /Library/AttackLens/bin/generate_config.sh \
  --manager-url https://YOUR_SERVER_IP:8443 \
  --tls-verify false          # only if self-signed cert
```

```bash
# With enrollment token (if OPEN_ENROLLMENT=false on manager)
sudo /Library/AttackLens/bin/generate_config.sh \
  --manager-url https://YOUR_SERVER_IP:8443 \
  --enrollment-token sk-enroll-YOUR_TOKEN \
  --tls-verify false
```

```bash
# With all options
sudo /Library/AttackLens/bin/generate_config.sh \
  --manager-url https://your-domain.com \
  --agent-name "Finance-MacBook-Pro" \
  --tls-verify true \
  --log-level INFO
```

**Step 5 — Start the agent**

```bash
# Load and start both services
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.watchdog.plist

# Verify
sudo attacklens-ctl status
```

Expected output:
```
AttackLens Agent:   Running (PID 1234)
AttackLens Watchdog: Running (PID 1235)
Agent ID:  mac-XXXXXXXXXXXXXXXX
Manager:   https://YOUR_SERVER_IP:8443
Last send: 5 seconds ago
```

---

### Option B: Manual Script Install

For environments where you can't use the PKG installer:

```bash
# Clone the repo on the Mac (or copy just the agent/ directory)
git clone <repo-url> attacklens

cd attacklens

# Install Python dependencies
pip3 install -r agent/requirements.txt

# Create directories
sudo mkdir -p /Library/AttackLens/{bin,security,data,spool,logs}
sudo chmod 700 /Library/AttackLens/security

# Copy agent files
sudo cp agent/agent_entry.py /Library/AttackLens/bin/attacklens-agent
sudo chmod +x /Library/AttackLens/bin/attacklens-agent

# Create basic config
sudo tee /Library/AttackLens/agent.toml > /dev/null <<EOF
[agent]
name = "$(scutil --get ComputerName)"

[manager]
url = "https://YOUR_SERVER_IP:8443"
tls_verify = false

[enrollment]
token = ""
keystore = "file"

[collection]
enabled = true
tick_sec = 5
EOF

# Create LaunchDaemon
sudo tee /Library/LaunchDaemons/com.attacklens.agent.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.attacklens.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
        <string>/Library/AttackLens/bin/attacklens-agent</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/Library/AttackLens/logs/agent.log</string>
    <key>StandardErrorPath</key><string>/Library/AttackLens/logs/agent.log</string>
</dict>
</plist>
EOF

sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist
```

---

### Option C: Mass Deployment (MDM / Jamf)

**For Jamf Pro deployment:**

1. Upload `attacklens-agent-1.0.pkg` to Jamf as a package
2. Create a policy with the package
3. Create a script with the post-install configuration:

```bash
#!/bin/bash
# Jamf post-install configuration script

MANAGER_URL="https://your-attacklens.company.com"
ENROLLMENT_TOKEN="sk-enroll-YOUR_TOKEN"
AGENT_NAME="$(scutil --get ComputerName)"

/Library/AttackLens/bin/generate_config.sh \
  --manager-url "$MANAGER_URL" \
  --enrollment-token "$ENROLLMENT_TOKEN" \
  --agent-name "$AGENT_NAME" \
  --tls-verify true

# Start services
launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist
launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.watchdog.plist
```

**For Apple Business Manager / MDM via configuration profile:**

The PKG can be signed and notarized for silent MDM deployment:

```bash
# Sign the PKG (requires Apple Developer ID)
productsign \
  --sign "Developer ID Installer: Your Company (TEAMID)" \
  attacklens-agent-1.0.pkg \
  attacklens-agent-1.0-signed.pkg

# Notarize
xcrun notarytool submit attacklens-agent-1.0-signed.pkg \
  --apple-id your@email.com \
  --team-id YOURTEAMID \
  --password your-app-specific-password \
  --wait
```

---

## 3. TLS Configuration

### Self-Signed (IP-only, development / internal)

Set in `.env`:
```
BIND_PORT=8443
TLS_MODE=self-signed
```

Agents must set `tls_verify = false` in `agent.toml`.

Generated Caddyfile:
```
https://YOUR_IP:8443 {
    tls internal
    reverse_proxy manager:8080
}
```

### Let's Encrypt (domain, production)

Set in `.env`:
```
DOMAIN=attacklens.yourcompany.com
BIND_PORT=443
TLS_MODE=letsencrypt
ADMIN_EMAIL=admin@yourcompany.com
```

Port 80 must be publicly reachable for the ACME HTTP-01 challenge.

Agents use `tls_verify = true` (default).

### Custom Certificate (corporate CA)

```
# Caddyfile (edit manually after env.sh)
https://attacklens.yourcompany.com:8443 {
    tls /etc/caddy/certs/attacklens.crt /etc/caddy/certs/attacklens.key
    reverse_proxy manager:8080
}
```

Mount your certificate in `docker-compose.yml`:
```yaml
caddy:
  volumes:
    - ./Caddyfile:/etc/caddy/Caddyfile:ro
    - ./certs:/etc/caddy/certs:ro    # add this line
    - caddy_data:/data
```

On agents, install your corporate CA certificate in the macOS System Keychain and set `tls_verify = true`.

---

## 4. Agent Configuration Reference

Full configuration file: `/Library/AttackLens/agent.toml`

### Critical Settings

```toml
[agent]
name = "hostname-or-label"         # shown on dashboard
id   = ""                          # auto-set from hardware UUID on enrollment

[manager]
url          = "https://IP:8443"   # REQUIRED
tls_verify   = true                # false only for self-signed certs
timeout_sec  = 30

[enrollment]
token    = ""                      # empty if OPEN_ENROLLMENT=true on manager
keystore = "keychain"              # "keychain" (recommended) or "file"
```

### Collection Tuning

```toml
[collection]
enabled  = true
tick_sec = 5                       # orchestrator pulse (seconds)

# Reduce volatile interval on battery / constrained devices
[collection.sections.metrics]
interval_sec = 30                  # default: 10

# Disable expensive sections if not needed
[collection.sections.binaries]
enabled = false                    # binary scan is slow on large systems

[collection.sections.sbom]
enabled = false                    # SBOM collection adds 5-10 seconds/day
```

### All Configurable Sections

| Section | Default Interval | Data |
|---|---|---|
| `metrics` | 10 s | CPU, RAM, swap, disk I/O, network I/O |
| `connections` | 10 s | Active TCP/UDP connections with process + IP |
| `processes` | 10 s | Top 80 processes (CPU/mem, cmdline, signing) |
| `ports` | 30 s | All LISTEN sockets |
| `network` | 120 s | Interfaces, DNS, gateway, WiFi info |
| `arp` | 120 s | Local LAN ARP table |
| `mounts` | 120 s | Mounted filesystems |
| `battery` | 120 s | Battery state, cycle count |
| `openfiles` | 120 s | Top 60 FD-heavy processes |
| `services` | 120 s | LaunchDaemons + LaunchAgents |
| `users` | 120 s | Local accounts, admin group, last login |
| `hardware` | 120 s | USB, Thunderbolt, Bluetooth, GPU |
| `containers` | 120 s | Running Docker/Podman containers |
| `storage` | 600 s | Disk volumes (size, used, free) |
| `tasks` | 600 s | Cron + launchd periodic tasks |
| `security` | 3600 s | SIP, Gatekeeper, FileVault, Firewall, XProtect |
| `sysctl` | 3600 s | Security-relevant kernel parameters |
| `configs` | 3600 s | Critical config file content + hash |
| `apps` | 86400 s | Installed .app bundles |
| `packages` | 86400 s | brew, pip3, npm, gem, cargo packages |
| `binaries` | 3600 s | SUID/SGID/world-writable binaries in PATH |
| `sbom` | 86400 s | Software Bill of Materials (PURL format) |

---

## 5. Post-Installation Verification

### Manager Verification

```bash
# Basic health
curl http://localhost:8080/health

# Check all containers
docker compose ps

# Verify threat feeds started (wait 5 minutes)
curl http://localhost:8090/api/v1/intel/feeds | python3 -m json.tool

# Test the admin API
curl -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  http://localhost:8080/api/v1/agents
```

### Agent Verification

```bash
# Status overview
sudo attacklens-ctl status

# Live log (watch for enrollment and first sends)
sudo attacklens-ctl logs
# Look for:
# INFO  Enrollment complete. Agent ID: mac-XXXXXXXX
# INFO  Section 'metrics' sent successfully

# Verify Keychain entry (after enrollment)
security find-generic-password -s "com.attacklens.agent" -a mac-XXXXXXXX
```

### End-to-End Test

```bash
# On the manager server — watch for the agent appearing
watch -n 2 'curl -s -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  http://localhost:8080/api/v1/agents | python3 -m json.tool'

# Check findings are being generated
curl -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  "http://localhost:8080/api/v1/findings?limit=5" | python3 -m json.tool
```

---

## 6. Uninstallation

### Remove the macOS Agent

```bash
# Stop services
sudo launchctl bootout system /Library/LaunchDaemons/com.attacklens.agent.plist 2>/dev/null
sudo launchctl bootout system /Library/LaunchDaemons/com.attacklens.watchdog.plist 2>/dev/null

# Remove files
sudo rm -rf /Library/AttackLens
sudo rm -f /Library/LaunchDaemons/com.attacklens.agent.plist
sudo rm -f /Library/LaunchDaemons/com.attacklens.watchdog.plist

# Remove Keychain entry
security delete-generic-password -s "com.attacklens.agent" 2>/dev/null

echo "AttackLens agent removed."
```

Or use the bundled uninstaller:
```bash
sudo /Library/AttackLens/uninstall.sh
```

### Remove the Manager

```bash
# Stop and remove all containers
docker compose down

# Remove all data (DESTRUCTIVE — deletes all findings and telemetry)
docker compose down -v
rm -rf data/ logs/

# Remove Docker images
docker rmi jarvis-manager:latest attacklens-threat-intel:latest
```

---

## 7. Upgrade Guide

### Manager Upgrade

```bash
cd attacklens

# Pull latest code
git pull

# Rebuild and restart
docker compose build
docker compose up -d

# Check logs for migration messages
docker compose logs manager | grep -i "migrat\|schema\|init"
```

The manager runs schema migrations automatically on startup (`ALTER TABLE ... ADD COLUMN` pattern — safe on existing data).

### Agent Upgrade

```bash
# Build new PKG on server
cd agent/os/macos/installer
sudo bash build_pkg.sh

# Transfer to endpoint and reinstall (over existing installation)
sudo installer -pkg ~/Downloads/attacklens-agent-1.0.pkg -target /

# The PKG upgrade preserves:
# - /Library/AttackLens/agent.toml (your config)
# - /Library/AttackLens/security/ (your API key)
# - /Library/AttackLens/spool/ (any unsent payloads)

# Restart to pick up new binary
sudo attacklens-ctl restart
```

### Zero-Downtime Agent Upgrade (MDM)

For MDM deployments:
1. Upload the new PKG to Jamf
2. Target a test scope first
3. Deploy the policy (installs over existing — no downtime)
4. Verify on test scope
5. Expand to full scope

---

## Troubleshooting Quick Reference

| Symptom | Likely Cause | Fix |
|---|---|---|
| Agent doesn't appear on dashboard | Manager URL wrong or unreachable | Check `agent.toml` URL; test `curl -k https://MANAGER_URL/health` |
| `TLS certificate verify failed` | Self-signed cert with `tls_verify=true` | Set `tls_verify = false` in agent.toml |
| `Enrollment failed: 401` | Wrong or missing enrollment token | Set correct `token` in `[enrollment]` |
| Agent keeps restarting | Config error or crash | Check `sudo attacklens-ctl logs` for error |
| No findings after 5 minutes | Threat intel feeds still loading | Wait 10 min; check `docker compose logs threat-intel` |
| `503 AI analyst not available` | No Anthropic API key | Add `ANTHROPIC_API_KEY` to `.env`, restart manager |
| Manager container exits | Port conflict or SQLite error | Check `docker compose logs manager`; ensure `./data/` is writable |
| RabbitMQ unhealthy | Not enough memory | Increase server RAM; RabbitMQ needs at least 256 MB |
