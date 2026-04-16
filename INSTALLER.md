# mac_intel Platform — Installation Guide

Step-by-step instructions to deploy the Manager and install agents on macOS and Windows.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Deploy the Manager (Docker)](#2-deploy-the-manager-docker)
   - [Option A — Dev / VM (self-signed TLS, port 8443)](#option-a--dev--vm-self-signed-tls-port-8443)
   - [Option B — Production (Caddy + Let's Encrypt, port 443)](#option-b--production-caddy--lets-encrypt-port-443)
3. [Get Credentials from Manager](#3-get-credentials-from-manager)
4. [Install macOS Agent](#4-install-macos-agent)
5. [Install Windows Agent](#5-install-windows-agent)
6. [Verify Connectivity](#6-verify-connectivity)
7. [Key Management](#7-key-management)
8. [Uninstall](#8-uninstall)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Prerequisites

### Manager host (any Linux/macOS server or VM)
- Docker 24+ and Docker Compose v2
- Outbound port 80/443 (prod) or 8443 (dev) open in firewall/security group
- For production: a domain name with an A record pointing to the server

### macOS endpoint
- macOS 12 (Monterey) or later
- Python 3.10+ (for dev/direct run) **or** pre-built `jarvis-agent` + `jarvis-watchdog` PyInstaller binaries
- `sudo` access for service installation

### Windows endpoint
- Windows 10 / Server 2016 or later
- PowerShell 5.1+ (run as Administrator)
- Pre-built `jarvis-agent.exe` + `jarvis-watchdog.exe` PyInstaller binaries
- Python 3.10+ only needed if running from source

---

## 2. Deploy the Manager (Docker)

Clone the repository on the manager host:

```bash
git clone <repo-url> macbook_data
cd macbook_data
```

### Option A — Dev / VM (self-signed TLS, port 8443)

Use this when you have a public IP but no domain name (or for local dev).

```bash
# 1. Set your server's public IP (agents will trust the cert at this IP)
export PUBLIC_IP=$(curl -s https://api.ipify.org)

# 2. (Optional) override port
export BIND_PORT=8443

# 3. Start
docker compose up -d

# 4. Watch startup and copy the printed tokens
docker compose logs -f manager
```

On first boot the manager auto-generates:
- A **self-signed RSA-4096 TLS certificate** with the public IP in the SAN
- An **enrollment token** (`sk-enroll-…`) — put this in agent.toml
- An **admin token** (`sk-admin-…`) — used for key management API

Both are saved to `./data/.secrets` and survive container restarts.

**Agent config for Option A:**
```toml
[manager]
url        = "https://<PUBLIC_IP>:8443"
tls_verify = false     # self-signed cert
```

---

### Option B — Production (Caddy + Let's Encrypt, port 443)

Use this when you have a domain name.  
DNS A record must already point to the server before starting.

```bash
# 1. Set domain and admin email
export DOMAIN=jarvis.example.com
export ADMIN_EMAIL=you@example.com

# 2. (Optional) pre-set tokens to avoid auto-generation
# export ENROLLMENT_TOKENS=sk-enroll-yourtoken
# export ADMIN_TOKEN=sk-admin-yourtoken

# 3. Start
docker compose -f docker-compose.prod.yml up -d

# 4. Watch startup and copy tokens
docker compose -f docker-compose.prod.yml logs -f manager
```

Caddy automatically provisions and renews a Let's Encrypt certificate.

**Agent config for Option B:**
```toml
[manager]
url        = "https://jarvis.example.com"
tls_verify = true      # real CA cert
```

---

## 3. Get Credentials from Manager

```bash
docker compose logs manager 2>&1 | grep -A 20 "Jarvis Manager"
```

Expected output:
```
╔══════════════════════════════════════════════════════════════╗
║              Jarvis Manager — Starting Up                   ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  ENROLLMENT TOKEN (put in agent.toml):                      ║
║    sk-enroll-xxxxxxxxxxxxxxxxxxxxxxxx                        ║
║                                                              ║
║  ADMIN TOKEN (for key management API):                       ║
║    sk-admin-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx                 ║
║                                                              ║
║  Manager URL:                                                ║
║    https://<YOUR_IP>:8443                                    ║
╚══════════════════════════════════════════════════════════════╝
```

Tokens are also stored at `./data/.secrets` on the manager host.

---

## 4. Install macOS Agent

### 4.1 Prepare directories

```bash
sudo mkdir -p /Library/Jarvis/{bin,config,data,security,spool,logs}
sudo chown -R root:wheel /Library/Jarvis
sudo chmod 750 /Library/Jarvis/config
sudo chmod 700 /Library/Jarvis/security
sudo chmod 755 /Library/Jarvis/{bin,data,spool,logs}
```

### 4.2 Install binaries

**From pre-built PyInstaller binaries (recommended for production):**
```bash
sudo cp jarvis-agent    /Library/Jarvis/bin/
sudo cp jarvis-watchdog /Library/Jarvis/bin/
sudo chmod 755 /Library/Jarvis/bin/jarvis-agent
sudo chmod 755 /Library/Jarvis/bin/jarvis-watchdog
```

**From source (dev only):**
```bash
# Install dependencies
pip3 install -r agent/requirements.txt

# Binaries are replaced by the Python entry points:
# python3 agent/os/macos/launchd.py   (or python3 -m agent.agent.core)
# The plist will point to python3 instead of a binary
```

### 4.3 Write agent configuration

```bash
sudo cp agent/config/agent.toml.example /Library/Jarvis/config/agent.toml
sudo nano /Library/Jarvis/config/agent.toml
```

Minimum required changes:

```toml
[agent]
id   = "macbook-001"          # unique ID — alphanumeric, max 128 chars
name = "Alice's MacBook Pro"  # display name on dashboard

[manager]
url        = "https://<MANAGER_IP_OR_DOMAIN>:8443"
tls_verify = false            # false for self-signed, true for Let's Encrypt

[enrollment]
token    = "sk-enroll-xxxxxxxxxxxxxxxxxxxxxxxx"  # from step 3
keystore = "keychain"         # "keychain" (recommended) or "file"
```

Lock down the config:
```bash
sudo chmod 640 /Library/Jarvis/config/agent.toml
sudo chown root:wheel /Library/Jarvis/config/agent.toml
```

### 4.4 Register LaunchDaemons

The plists are generated by `agent/os/macos/launchd.py`.  
Run as root to write and load them:

```bash
sudo python3 -c "
from agent.os.macos.launchd import install_plist
install_plist('both')
print('LaunchDaemons loaded.')
"
```

Or manually write the plists (see `agent/os/macos/launchd.py` for full XML templates):

**`/Library/LaunchDaemons/com.jarvis.watchdog.plist`** — launchd keeps watchdog alive; watchdog manages the agent.  
**`/Library/LaunchDaemons/com.jarvis.agent.plist`** — loaded but managed by watchdog.

Plist permissions:
```bash
sudo chown root:wheel /Library/LaunchDaemons/com.jarvis.{agent,watchdog}.plist
sudo chmod 644 /Library/LaunchDaemons/com.jarvis.{agent,watchdog}.plist
```

Load services:
```bash
sudo launchctl load -w /Library/LaunchDaemons/com.jarvis.watchdog.plist
sudo launchctl load -w /Library/LaunchDaemons/com.jarvis.agent.plist
```

### 4.5 Verify macOS agent is running

```bash
# Check launchd status (look for "PID" in output)
sudo launchctl list com.jarvis.agent
sudo launchctl list com.jarvis.watchdog

# Tail logs
tail -f /Library/Jarvis/logs/agent-stdout.log
tail -f /Library/Jarvis/logs/agent-stderr.log
```

On first run the agent enrolls automatically — look for:
```
Enrollment successful. API key stored in keychain.
```

### 4.6 Day-to-day macOS service management

```bash
# Status
sudo launchctl list com.jarvis.agent

# Stop
sudo launchctl kill TERM system/com.jarvis.agent

# Start / restart
sudo launchctl kickstart -k system/com.jarvis.agent

# Reload config (SIGHUP, no full restart)
sudo launchctl kill HUP system/com.jarvis.agent

# View logs
tail -f /Library/Jarvis/logs/agent-stdout.log
```

---

## 5. Install Windows Agent

Run **PowerShell as Administrator** for all steps.

### 5.1 Prepare the installer package

Copy these files to a working directory (e.g. `C:\Temp\jarvis-install\`):
- `jarvis-agent.exe`
- `jarvis-watchdog.exe`
- `agent/os/windows/installer/install.ps1`

```powershell
cd C:\Temp\jarvis-install
```

### 5.2 Run the installer

```powershell
.\install.ps1 `
    -ManagerUrl  "https://<MANAGER_IP>:8443" `
    -EnrollToken "sk-enroll-xxxxxxxxxxxxxxxxxxxxxxxx" `
    -AgentId     "desktop-001" `
    -AgentName   "Bob's Workstation" `
    -TlsVerify   $false        # $false for self-signed, $true for Let's Encrypt
```

The installer will:
1. Create `C:\Program Files (x86)\Jarvis\{bin,config,data,security,spool,logs}`
2. Apply restrictive ACLs (SYSTEM + Admins only; no user read on security/)
3. Copy and lock binaries (SYSTEM + Admins read/execute only)
4. Write `agent.toml` with the provided parameters
5. Register `MacIntelAgent` and `MacIntelWatchdog` Windows services
6. Start both services

### 5.3 Verify Windows agent is running

```powershell
# Check service status
Get-Service MacIntelAgent, MacIntelWatchdog

# View agent logs
Get-Content "C:\Program Files (x86)\Jarvis\logs\agent.log" -Tail 50 -Wait

# Or use Event Viewer: Windows Logs → Application, source MacIntelAgent
```

On first run look for:
```
Enrollment successful. API key stored in Windows Credential Manager.
```

### 5.4 Day-to-day Windows service management

```powershell
# Stop
Stop-Service MacIntelAgent -Force

# Start
Start-Service MacIntelAgent

# Restart
Restart-Service MacIntelAgent

# View status
Get-Service MacIntelAgent | Select-Object Status, DisplayName
```

### 5.5 Build Windows binaries from source (optional)

If you don't have pre-built binaries, build them on a Windows machine:

```powershell
# Install build dependencies
pip install pyinstaller -r agent\requirements.txt

# Build agent binary
pyinstaller --onefile --name jarvis-agent `
    --add-data "agent\config;config" `
    agent\agent\core.py

# Build watchdog binary
pyinstaller --onefile --name jarvis-watchdog `
    agent\agent\watchdog.py

# Outputs: dist\jarvis-agent.exe, dist\jarvis-watchdog.exe
```

---

## 6. Verify Connectivity

### Manager health check

```bash
# Dev (self-signed)
curl -sk https://<MANAGER_IP>:8443/health | python3 -m json.tool

# Prod (real cert)
curl -s https://jarvis.example.com/health | python3 -m json.tool
```

Expected:
```json
{"status": "ok", "agents": 1, "payloads": 240}
```

### Confirm agent appears

```bash
curl -sk https://<MANAGER_IP>:8443/api/v1/agents | python3 -m json.tool
```

Expected:
```json
[{"agent_id": "macbook-001", "name": "Alice's MacBook Pro", "last_seen": 1712700120, ...}]
```

### Check section data is arriving

```bash
# Replace macbook-001 with your agent_id
curl -sk https://<MANAGER_IP>:8443/api/v1/agents/macbook-001/metrics | python3 -m json.tool
```

### Open the dashboard

Navigate to `https://<MANAGER_IP>:8443` in a browser.  
Accept the self-signed certificate warning in dev, or trust Let's Encrypt in prod.

---

## 7. Key Management

All key management calls require the admin token from step 3.

```bash
MANAGER="https://<MANAGER_IP>:8443"
ADMIN_TOKEN="sk-admin-xxxxxxxx"
AGENT_ID="macbook-001"
```

### List all agent keys (no secrets returned)
```bash
curl -sk -H "X-Admin-Token: $ADMIN_TOKEN" $MANAGER/api/v1/keys | python3 -m json.tool
```

### Rotate a key (new key shown once)
```bash
curl -sk -X POST -H "X-Admin-Token: $ADMIN_TOKEN" \
     $MANAGER/api/v1/keys/$AGENT_ID/rotate | python3 -m json.tool
```

After rotation the agent will fail to ingest until it re-enrolls  
(or until you push the new key into the keystore manually).  
Simplest: delete the keystore entry on the agent and restart — it will re-enroll.

### Set key expiry (30 days from now)
```bash
curl -sk -X PATCH \
     -H "X-Admin-Token: $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"expires_in_days": 30}' \
     $MANAGER/api/v1/keys/$AGENT_ID/expiry
```

### Revoke a key immediately
```bash
curl -sk -X POST -H "X-Admin-Token: $ADMIN_TOKEN" \
     $MANAGER/api/v1/keys/$AGENT_ID/revoke
```

### Hard-delete a key (agent must re-enroll)
```bash
curl -sk -X DELETE -H "X-Admin-Token: $ADMIN_TOKEN" \
     $MANAGER/api/v1/keys/$AGENT_ID
```

---

## 8. Uninstall

### Uninstall macOS agent

```bash
# Unload and remove LaunchDaemons
sudo launchctl unload -w /Library/LaunchDaemons/com.jarvis.agent.plist    2>/dev/null
sudo launchctl unload -w /Library/LaunchDaemons/com.jarvis.watchdog.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.jarvis.{agent,watchdog}.plist

# Remove all agent files
sudo rm -rf /Library/Jarvis

# Remove Keychain entry (replace agent-001 with your agent_id)
security delete-generic-password -s com.jarvis.agent -a agent-001 2>/dev/null || true
```

### Uninstall Windows agent

Run PowerShell as Administrator:

```powershell
# Run the uninstaller
.\agent\os\windows\installer\uninstall.ps1

# Or manually:
Stop-Service MacIntelAgent, MacIntelWatchdog -Force -ErrorAction SilentlyContinue
& sc.exe delete MacIntelAgent
& sc.exe delete MacIntelWatchdog
Remove-Item -Recurse -Force "C:\Program Files (x86)\Jarvis"

# Remove Credential Manager entry
& cmdkey /delete:jarvis:agent-001
```

### Remove manager

```bash
# Stop containers
docker compose down

# Remove data (tokens, certs, database, telemetry store)
# WARNING: this is irreversible
sudo rm -rf ./data ./certs ./logs
```

---

## 9. Troubleshooting

### Agent won't enroll

| Symptom | Fix |
|---------|-----|
| `401 Unauthorized` on enroll | Enrollment token wrong or expired — check `./data/.secrets` on manager |
| `Connection refused` | Manager not running, or wrong IP/port in `agent.toml` |
| TLS certificate error | Use `tls_verify = false` for self-signed (dev only); or copy the cert to the agent |
| `Clock skew too large` | NTP sync the agent and manager clocks; skew window is ±300 s |

### Agent enrolled but no data visible

| Symptom | Fix |
|---------|-----|
| `401` on ingest | Key mismatch — rotate key via admin API and re-enroll |
| `409 Replay` | System clock drifted; check NTP |
| Sections missing | Collector returned empty data; check agent logs for errors |
| Circuit breaker OPEN | Section is failing; check stderr log for root cause |

### Disk spool growing

```bash
# macOS
ls -lh /Library/Jarvis/spool/

# Windows PowerShell
Get-ChildItem "C:\Program Files (x86)\Jarvis\spool"
```

The spool grows when the manager is unreachable. It drains automatically on reconnect.  
Max size is 50 MB; oldest entries are trimmed when full.

### Check manager logs

```bash
# Live logs
docker compose logs -f manager

# Persistent log file
tail -f ./logs/manager.log
```

### Useful curl one-liners

```bash
# Manager health
curl -sk https://<IP>:8443/health

# List agents
curl -sk https://<IP>:8443/api/v1/agents

# Last 10 metrics payloads for an agent
curl -sk "https://<IP>:8443/api/v1/agents/macbook-001/metrics?limit=10"

# Jarvis findings
curl -sk https://<IP>:8443/api/v1/jarvis/macbook-001/findings

# Jarvis summary
curl -sk https://<IP>:8443/api/v1/jarvis/macbook-001/summary
```
