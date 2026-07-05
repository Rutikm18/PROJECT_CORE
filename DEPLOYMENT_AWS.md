# AttackLens — AWS Deployment Guide

**Stack:** EC2 → Docker Compose → Caddy (TLS) + Manager + Threat-Intel + RabbitMQ  
**Time:** ~20 minutes (IP-only) · ~30 minutes (custom domain + Let's Encrypt)

> **Important — OS choice:** Use **Ubuntu 22.04 LTS**. Amazon Linux 2023 lacks
> `docker-compose-plugin` in dnf and ships BuildKit 0.12 (need ≥ 0.16) — the
> installer handles it automatically, but Ubuntu avoids those hurdles entirely.

**Minimum dependency versions enforced by the installer:**

| Tool | Minimum | Why |
|---|---|---|
| Docker | 25.0 | BuildKit feature flags |
| Docker Compose | 2.27 | `--build` parallelism |
| Docker Buildx | 0.17 | multi-platform support |
| BuildKit | 0.16 | cache mounts |

---

## Contents

1. [Choose a Deployment Mode](#1-choose-a-deployment-mode)
2. [Launch EC2 Instance](#2-launch-ec2-instance)
3. [Configure Security Group](#3-configure-security-group)
4. [SSH into the Instance](#4-ssh-into-the-instance)
5. [Install Dependencies](#5-install-dependencies)
6. [Clone the Repository](#6-clone-the-repository)
7. [Configure the Stack](#7-configure-the-stack)
8. [Start the Stack](#8-start-the-stack)
9. [Verify Everything is Running](#9-verify-everything-is-running)
10. [Connect Agents](#10-connect-agents)
11. [Domain + Let's Encrypt (optional)](#11-domain--lets-encrypt-optional)
12. [Auto-restart on Reboot](#12-auto-restart-on-reboot)
13. [Backup & Persistence](#13-backup--persistence)
14. [Security Hardening](#14-security-hardening)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Choose a Deployment Mode

| Mode | URL agents use | TLS cert | Requirement |
|---|---|---|---|
| **IP-only** (quick start) | `https://YOUR_EC2_IP:8443` | Self-signed (Caddy) | Just an EC2 instance |
| **Domain** (production) | `https://attacklens.your-domain.com` | Let's Encrypt (auto) | A domain pointed at the EC2 IP |

Start with **IP-only** if you just want it running. Upgrade to a domain later.

---

## 2. Launch EC2 Instance

### Recommended specs

| Setting | Value |
|---|---|
| **AMI** | Ubuntu 22.04 LTS (`ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64`) |
| **Instance type** | `t3.large` (2 vCPU, 8 GB RAM) — threat-intel needs RAM for CVE data |
| **Minimum type** | `t3.medium` (2 vCPU, 4 GB) — works but tight for a demo |
| **Storage** | 30 GB gp3 root volume (50 GB if you plan long-term telemetry retention) |
| **Region** | Pick closest to your endpoints — us-east-1 (N. Virginia) or us-west-2 (Oregon) |

> Do **not** use Amazon Linux 2023 — see the note at the top.

### Via AWS Console

1. Go to **EC2 → Launch Instance**
2. Name: `attacklens-manager`
3. AMI: Ubuntu 22.04 LTS
4. Instance type: `t3.large`
5. Key pair: create new or use existing — **save the .pem file**
6. Storage: 30 GB gp3
7. Security group: create new (configure in step 3)
8. Click **Launch Instance**

### Via AWS CLI

```bash
# Create key pair (skip if you have one)
aws ec2 create-key-pair \
  --key-name attacklens-key \
  --query 'KeyMaterial' \
  --output text > ~/.ssh/attacklens-key.pem
chmod 400 ~/.ssh/attacklens-key.pem

# Launch instance
aws ec2 run-instances \
  --image-id ami-0c7217cdde317cfec \
  --instance-type t3.large \
  --key-name attacklens-key \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":30,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=attacklens-manager}]' \
  --query 'Instances[0].InstanceId' \
  --output text
```

---

## 3. Configure Security Group

Open these ports in the instance's security group:

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 22 | TCP | Your IP only | SSH access |
| 80 | TCP | 0.0.0.0/0 | Let's Encrypt ACME challenge (required even for IP-only) |
| 8443 | TCP | 0.0.0.0/0 | **Agents connect here (IP-only / self-signed mode)** |
| 443 | TCP | 0.0.0.0/0 | HTTPS (domain + Let's Encrypt mode) |
| 8080 | TCP | 0.0.0.0/0 | Direct manager HTTP (agent fallback, no TLS) |

**Do NOT open** 5672 (RabbitMQ) or 15672 (RabbitMQ UI) to the internet — internal only.

### Via AWS Console

1. EC2 → Security Groups → select the group → Inbound rules → Edit
2. Add each row from the table above

### Via AWS CLI

```bash
# Get your SG ID from the instance
SG_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=attacklens-manager" \
  --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
  --output text)

MY_IP=$(curl -s https://api.ipify.org)/32

# Add rules
aws ec2 authorize-security-group-ingress --group-id $SG_ID \
  --ip-permissions \
  "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=${MY_IP}}]" \
  "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0}]" \
  "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}]" \
  "IpProtocol=tcp,FromPort=8443,ToPort=8443,IpRanges=[{CidrIp=0.0.0.0/0}]" \
  "IpProtocol=tcp,FromPort=8080,ToPort=8080,IpRanges=[{CidrIp=0.0.0.0/0}]"
```

---

## 4. SSH into the Instance

```bash
# Get the public IP
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=attacklens-manager" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text

# SSH in
ssh -i ~/.ssh/attacklens-key.pem ubuntu@YOUR_EC2_IP
```

> All remaining commands run **on the EC2 instance**.

---

## 5. Install Dependencies

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker (official get.docker.com — ships 25+, not the Ubuntu snap)
curl -fsSL https://get.docker.com | sudo bash
sudo usermod -aG docker ubuntu
newgrp docker   # apply group without logout

# Verify versions against minimums
docker --version                      # must be 25.0+
docker compose version                # must be 2.27+
docker buildx version                 # must be 0.17+

# Install Git
sudo apt-get install -y git curl
```

> If Buildx is below 0.17 (common on older Ubuntu images), the installer's
> `--repair` flag or `attacklens repair` command will auto-upgrade it.

### Pre-flight check

The installer validates all versions before building. Run this once to confirm your environment is clean:

```bash
bash install.sh --doctor
# or after cloning (step 6):
./attacklens doctor
```

Sample passing output:
```
[ok] Docker 25.0.6
[ok] Compose v2.29.1
[ok] Buildx v0.17.1
[ok] BuildKit 0.16.0 (attacklens-builder)
[ok] Disk ≥ 5 GB (28 GB free)
[ok] RAM ≥ 2 GB (7.5 GB)
[ok] Port 80 free
[ok] Port 8080 free
[ok] Internet reachable

Overall: PASSED
```

---

## 6. Clone the Repository

```bash
# Clone into home directory
cd ~
git clone https://github.com/Rutikm18/PROJECT_CORE.git attacklens
cd attacklens
```

> Replace `YOUR_ORG/macbook_data` with your actual repo URL.  
> If the repo is private, either use SSH keys or a GitHub personal access token:
> ```bash
> git clone https://YOUR_TOKEN@github.com/YOUR_ORG/macbook_data.git attacklens
> ```

---

## 7. Configure the Stack

### Run the setup script

`env.sh` auto-detects your public IP, generates all secrets, and writes `.env` + `Caddyfile`:

```bash
bash env.sh
```

The script will ask two questions:

**Question 1 — Do you have a domain?**
- **No domain (IP-only):** Press Enter. Caddy uses a self-signed cert on port 8443.
- **Domain:** Enter `attacklens.your-domain.com`. Caddy uses Let's Encrypt on port 443.

**Question 2 — Require enrollment token?**
- **Open (recommended for single operator):** Press Enter.
- **Token-gated:** type `y`. Agents must supply the generated token.

After it runs, verify `.env` looks correct:

```bash
cat .env
```

You should see values for `PUBLIC_IP`, `ADMIN_TOKEN`, and `BIND_PORT`.

---

### Retrieve your ADMIN_TOKEN

The ADMIN_TOKEN (for key management API) is displayed once at startup:

```bash
# Extract from logs and copy to clipboard
docker compose logs manager | grep "ADMIN TOKEN" | awk -F': ' '{print $NF}' | pbcopy
# (or xclip on Linux: | xclip -selection clipboard)

# Or just view it
docker compose logs manager | grep -A1 "ADMIN TOKEN"
```

Save it for safe keeping — you'll need it for:
- `curl -H "X-Admin-Token: $ADMIN_TOKEN" http://localhost:8080/api/v1/keys`
- Rotating agent API keys
- Access control management

### Optional: add API keys to .env

Edit `.env` to add optional integrations:

```bash
nano .env
```

```dotenv
# AI-powered analysis (recommended — get key at console.anthropic.com)
ANTHROPIC_API_KEY=sk-ant-...

# Threat intel feeds (all optional — platform works without them)
ABUSEIPDB_KEY=...
OTX_KEY=...
GREYNOISE_KEY=...

# Email alerts (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=app-password
ALERT_RECIPIENTS=you@gmail.com
```

---

## 8. Start the Stack

```bash
# Build images and start all containers
bash install.sh
```

The installer runs pre-flight checks, builds images, and starts all containers in one step. It prints progress for each of 10 steps:

```
━━━ Step 1/10: Checking OS + user ━━━
━━━ Step 2/10: Validating dependencies ━━━
...
━━━ Step 8/10: Building images ━━━
━━━ Step 9/10: Starting containers ━━━
━━━ Step 10/10: Verifying health ━━━
```

First build takes **3–5 minutes** — Docker compiles the manager and threat-intel images, then RabbitMQ must pass its health check before the manager starts.

**If the build fails** (e.g. Buildx or Compose version too old):

```bash
# Auto-repair: upgrades Buildx + Compose + creates BuildKit builder
bash install.sh --repair
# or
./attacklens repair
```

Watch live logs after start:

```bash
docker compose logs -f
```

Press `Ctrl+C` to stop following logs (containers keep running).

---

## 9. Verify Everything is Running

```bash
# All 4 containers should show "healthy" or "running"
docker compose ps
```

Expected output:
```
NAME                    STATUS         PORTS
attacklens-caddy        running        0.0.0.0:80->80/tcp, 0.0.0.0:8443->8443/tcp
attacklens-manager      healthy        0.0.0.0:8080->8080/tcp
attacklens-rabbitmq     healthy        0.0.0.0:5672->5672/tcp
attacklens-threat-intel healthy        0.0.0.0:8090->8090/tcp
```

### Health checks

```bash
# Manager direct (no TLS)
curl http://localhost:8080/health

# Through Caddy (self-signed — ignore cert warning)
curl -k https://YOUR_EC2_IP:8443/health

# Should return: {"status":"ok","db":"ok","store":...}
```

### Open the dashboard

```
IP-only mode:   https://YOUR_EC2_IP:8443
Domain mode:    https://attacklens.your-domain.com
```

> **Browser TLS warning (IP-only):** This is expected. Caddy uses a self-signed cert.
> Click "Advanced → Proceed" in Chrome, or "Accept Risk" in Firefox.

### Default login credentials

**Email:** `admin@attacklens.ai`  
**Password:** `!HLwS=f73fHo$?p!#M77XA*M`

These are shown on the login page. After login, navigate to **Settings → API Keys** to retrieve your `ADMIN_TOKEN` (also shown in `docker compose logs manager` at startup).

---

## 10. Connect Agents

### macOS agent (binary PKG — v2.1.0+)

Build the PKG on your dev Mac, then distribute it to endpoints:

```bash
# On your dev Mac — build the PKG
cd /path/to/macbook_data
MANAGER_IP=YOUR_EC2_IP MANAGER_PORT=8080 VERSION=2.1.0 ARCH=arm64 \
  bash agent/os/macos/pkg/build_pkg.sh
# Output: agent/os/macos/pkg/dist/attacklens-agent-2.1.0-arm64.pkg
```

Install on the endpoint Mac:

```bash
sudo installer -pkg attacklens-agent-2.1.0-arm64.pkg -target /
```

The postinstall automatically:
- derives a stable Agent ID from the hardware UUID (`mac-<uuid>`)
- writes `/Library/AttackLens/agent.toml` with your EC2 IP baked in
- loads both LaunchDaemons (the agent + watchdog)

**Verify on the endpoint:**

```bash
sudo attacklens-service status      # both services ● running
sudo attacklens-service diagnose    # tests manager /health endpoint
```

**Agent didn't appear in the dashboard?** Check connectivity first:

```bash
# On the Mac
sudo attacklens-service diagnose
# Section 4 will report: manager reachable / NOT reachable + HTTP code

# If reachable, check manager received it
curl http://YOUR_EC2_IP:8080/api/v1/agents
```

> Use `tls_verify = false` when the manager has a self-signed cert (IP-only mode).  
> Use `tls_verify = true` with a Let's Encrypt domain cert (domain mode).

### macOS agent management CLI

```bash
sudo attacklens-service status      # agent + watchdog state
sudo attacklens-service restart     # stop watchdog first, then agent, then restart both
sudo attacklens-service logs 100    # last 100 lines of agent/watchdog logs
sudo attacklens-service diagnose    # full health: files, services, manager connectivity
```

### Check agent appeared in the manager

```bash
curl http://localhost:8080/api/v1/agents
```

---

## 11. Domain + Let's Encrypt (optional)

Skip this section if IP-only mode is sufficient.

### Step 1 — Point DNS to your EC2 IP

In your DNS provider (Route 53, Cloudflare, etc.):
```
Type: A
Name: attacklens
Value: YOUR_EC2_IP
TTL: 300
```

Wait for DNS propagation (~1–5 min):
```bash
dig +short attacklens.your-domain.com
# Should return your EC2 IP
```

### Step 2 — Re-run env.sh with your domain

```bash
bash env.sh
# When asked "Do you have a domain?" → enter: attacklens.your-domain.com
```

This rewrites `.env` (`BIND_PORT=443`, `DOMAIN=...`) and `Caddyfile` with Let's Encrypt config.

### Step 3 — Restart the stack

```bash
docker compose down
docker compose up -d
```

Caddy will automatically obtain and renew a certificate from Let's Encrypt.  
The dashboard is now at `https://attacklens.your-domain.com` with a valid cert.

### Step 4 — Reconfigure agents to use domain

Update agent.toml on each monitored machine:
```toml
[manager]
url        = "https://attacklens.your-domain.com"
tls_verify = true   # valid cert now, verify it
```

---

## 12. Auto-restart on Reboot

All containers already have `restart: unless-stopped` in docker-compose.yml.  
Docker's own daemon needs to start on boot:

```bash
# Enable Docker to start on boot
sudo systemctl enable docker

# Verify
sudo systemctl is-enabled docker   # should print "enabled"
```

To confirm containers restart after a reboot:
```bash
sudo reboot
# Wait ~2 minutes, then SSH back in
ssh -i ~/.ssh/attacklens-key.pem ubuntu@YOUR_EC2_IP
docker compose -f ~/attacklens/docker-compose.yml ps
```

---

## 13. Backup & Persistence

All persistent data lives in two directories:

| Directory | Contents |
|---|---|
| `~/attacklens/data/` | SQLite DBs (`manager.db`, `intel.db`), hot/warm/cold telemetry store |
| `~/attacklens/logs/` | Rotating log files |

### Snapshot to S3 (recommended)

```bash
# Install AWS CLI
sudo apt-get install -y awscli

# Configure IAM credentials (or use an IAM role attached to the instance)
aws configure

# Create a backup bucket
aws s3 mb s3://attacklens-backups-$(date +%Y%m%d)

# Manual backup
tar czf /tmp/attacklens-data-$(date +%Y%m%d).tar.gz ~/attacklens/data ~/attacklens/logs
aws s3 cp /tmp/attacklens-data-$(date +%Y%m%d).tar.gz s3://attacklens-backups/
```

### Scheduled daily backup (cron)

```bash
crontab -e
```
Add:
```
0 2 * * * tar czf /tmp/al-backup-$(date +\%Y\%m\%d).tar.gz ~/attacklens/data && aws s3 cp /tmp/al-backup-$(date +\%Y\%m\%d).tar.gz s3://YOUR_BUCKET/ && rm /tmp/al-backup-*.tar.gz
```

---

## 14. Security Hardening

### Lock down SSH

```bash
# Disable password auth (key-only login)
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### UFW firewall (in addition to security group)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 8080/tcp
sudo ufw enable
```

### Rotate ADMIN_TOKEN after first login

```bash
nano ~/attacklens/.env
# Generate new token:
#   openssl rand -hex 24 → use as new ADMIN_TOKEN
# Then restart:
docker compose restart manager
```

### Restrict 8080 to known agent IPs

Once agents are enrolled, you can restrict port 8080 to specific CIDR ranges in the security group. This prevents unauthenticated access to the direct HTTP port.

### Enable enrollment tokens (after initial setup)

```bash
nano ~/attacklens/.env
# Change:
OPEN_ENROLLMENT=false
ENROLLMENT_TOKENS=sk-enroll-YOUR_GENERATED_TOKEN
```
```bash
docker compose restart manager
```
New agents must now supply the enrollment token during install:
```bash
sudo attacklens-agent install --manager https://YOUR_IP:8443 --token sk-enroll-...
```

---

## 15. Troubleshooting

### Run the doctor first

```bash
./attacklens doctor
```

This checks all dependencies, services, ports, disk, RAM, and internet in one pass. Fix anything reported as `[fail]` before proceeding.

### "compose build requires buildx 0.17.0 or later"

Your Buildx is too old. Auto-repair:

```bash
bash install.sh --repair
# or
./attacklens repair
```

This downloads the latest Buildx + Compose binaries from GitHub and creates an `attacklens-builder` BuildKit builder. Takes ~2 minutes.

### "docker-compose: command not found" / compose plugin missing

On Amazon Linux 2023 (or older Ubuntu), the compose plugin may not be installed. The `--repair` flag installs it automatically. Or manually:

```bash
COMPOSE_VER=$(curl -s https://api.github.com/repos/docker/compose/releases/latest \
  | grep '"tag_name"' | cut -d'"' -f4)
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VER}/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version   # verify
```

### Containers not starting

```bash
# View all logs including startup errors
docker compose logs --tail=50

# Check a specific container
docker compose logs manager
docker compose logs caddy
docker compose logs rabbitmq
```

### Manager not healthy after 2+ minutes

```bash
# Check if RabbitMQ health is blocking manager startup
docker compose ps rabbitmq
# If rabbitmq shows "unhealthy", wait longer or restart it:
docker compose restart rabbitmq
```

### Agent can't reach manager

```bash
# From the Mac, run the built-in diagnostic:
sudo attacklens-service diagnose
# Section 4 tests /health and prints HTTP status + error message

# Or test manually:
curl -k https://YOUR_EC2_IP:8443/health
curl    http://YOUR_EC2_IP:8080/health

# Common causes:
# 1. Port 8443/8080 not open in security group → re-check step 3
# 2. tls_verify = true but cert is self-signed → set tls_verify = false in agent.toml
# 3. EC2 public IP changed (Elastic IP prevents this — see below)
# 4. Manager URL in agent.toml uses https:// but manager only listens on http://
#    → grep url /Library/AttackLens/agent.toml — should be http://IP:8080 for direct
```

### macOS agent: "Bootstrap failed: 5" or service not starting

```bash
# Not a real failure — means the service was already loaded.
# Use bootout → bootstrap instead:
sudo launchctl bootout system/com.attacklens.agent
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist
# or simply:
sudo attacklens-service restart
```

### macOS agent: "attacklens-service: command not found"

You installed a pre-2.1.0 PKG. Rebuild the PKG from the repo (v2.1.0+) and reinstall — the new PKG ships the management CLI to `/usr/local/bin/attacklens-service`.

### macOS agent: SCA section missing from dashboard payloads

Pre-2.1.0 frozen binaries shipped without policy files (PyInstaller `--onefile` doesn't bundle data files automatically). Rebuild + reinstall the PKG — the 57-check CIS macOS policy is now bundled with `--add-data`. To add custom policies without rebuilding, drop `.yml` files into `/Library/AttackLens/sca/` and restart the agent.

### Assign an Elastic IP (prevents IP changes on reboot)

```bash
# Allocate
EIP=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)

# Get instance ID
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=attacklens-manager" \
  --query 'Reservations[0].Instances[0].InstanceId' \
  --output text)

# Associate
aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id $EIP
aws ec2 describe-addresses --allocation-ids $EIP --query 'Addresses[0].PublicIp' --output text
```

### Dashboard shows no data

```bash
# Verify data is being received by the manager
curl http://localhost:8080/api/v1/raw/sections?agent_id=YOUR_AGENT_ID
curl http://localhost:8080/api/v1/raw/count?agent_id=YOUR_AGENT_ID

# Check manager received the agent
curl http://localhost:8080/api/v1/agents

# Check agent spool (large number = manager not reachable)
wc -l ~/attacklens/agent/spool/unsent.ndjson 2>/dev/null
```

### Disk full

```bash
df -h
# If /dev/sda1 is full, extend via AWS Console:
# EC2 → Volumes → Modify → increase size → then:
sudo growpart /dev/sda1 1
sudo resize2fs /dev/sda1
```

---

## Quick Reference

```bash
# Full install (with pre-flight checks + progress output)
bash install.sh

# Health check — all dependencies, services, ports
./attacklens doctor

# Auto-repair Buildx/Compose versions + create BuildKit builder
bash install.sh --repair   # or: ./attacklens repair

# Status of all containers
./attacklens status

# Start / Stop / Restart
cd ~/attacklens && docker compose up -d
docker compose down
docker compose restart manager

# Rebuild after code changes
docker compose up -d --build manager

# View live logs
docker compose logs -f
./attacklens logs             # shorthand
./attacklens logs manager     # specific service

# Check health endpoint
curl http://localhost:8080/health

# List agents
curl http://localhost:8080/api/v1/agents | python3 -m json.tool

# Update to latest code
git pull
docker compose up -d --build

# macOS agent management (on endpoint)
sudo attacklens-service status
sudo attacklens-service diagnose
sudo attacklens-service restart
sudo attacklens-service logs 100
```

---

## Architecture Overview

```
Internet
    │
    ├── :443/:8443  ──→  Caddy (TLS termination)
    │                         │
    │                         └──→  manager:8080  (internal Docker network)
    │                                    │
    └── :8080       ──→  manager (direct, no TLS — for agents on trusted nets)
                               │
                         ┌─────┴──────────────────────────┐
                         │                                │
                    RabbitMQ:5672              threat-intel:8090
                    (async queue)              (CVE + IOC feeds)
                         │
                    data/            ← SQLite + hot/warm/cold store
                    logs/            ← rotating log files
```

**Agents** → `https://YOUR_EC2_IP:8443` (TLS via Caddy) or `http://YOUR_EC2_IP:8080` (direct)  
**Dashboard** → `https://YOUR_EC2_IP:8443` (same Caddy endpoint)  
**Admin API** → `http://localhost:8080/api/v1/keys/*` (requires `ADMIN_TOKEN` header)
