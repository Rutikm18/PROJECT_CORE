# mac_intel — Complete Step-by-Step Setup Guide
## AWS Manager + macOS Agent

> This guide takes you from zero to a fully running manager on AWS and agent
> on your Mac. Every command is copy-pasteable. Expected total time: 30–45 min.

---

## What you will have at the end

```
Your Mac (agent)
  └── macintel-agent  (LaunchDaemon, runs as root)
        │  AES-256-GCM encrypted payload
        │  HTTPS :443 / TLS 1.3
        ▼
  AWS EC2 (manager)
        │  Caddy (auto TLS via Let's Encrypt)  ─── :443
        └── jarvis-manager (Docker)            ─── :8080 internal
              │
              ├── SQLite (manager.db, intel.db)
              └── Dashboard (https://jarvis.yourdomain.com)
```

---

## Prerequisites Checklist

Before you start, make sure you have:

- [ ] An **AWS account** with permission to create EC2, VPC, Security Groups
- [ ] **AWS CLI** installed and configured (`aws configure`)
- [ ] A **domain name** (e.g. `jarvis.yourdomain.com`) — you will point its A record to the EC2 Elastic IP
- [ ] **macOS 12+** on the endpoint machine
- [ ] **Python 3.11+** on the Mac (`python3 --version`)
- [ ] This repo cloned on your Mac: `git clone <repo-url> macbook_data && cd macbook_data`

---

---

# PART A — Deploy the Manager on AWS

---

## A-1. Create Security Group

Open your terminal on your local machine (not the EC2 yet).

```bash
# Set your default AWS region
export AWS_DEFAULT_REGION=us-east-1   # change to your preferred region

# Find your default VPC ID
VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=isDefault,Values=true" \
  --query "Vpcs[0].VpcId" --output text)
echo "VPC: $VPC_ID"

# Create the Security Group
SG_ID=$(aws ec2 create-security-group \
  --group-name "jarvis-manager-sg" \
  --description "Jarvis Manager: agent ingest + dashboard" \
  --vpc-id "$VPC_ID" \
  --query "GroupId" --output text)
echo "Security Group: $SG_ID"

# Allow HTTPS (443) from anywhere — agents + browser dashboard
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Allow HTTP (80) from anywhere — Let's Encrypt HTTP challenge only
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp --port 80 --cidr 0.0.0.0/0

# Allow SSH (22) from YOUR IP only — emergency access
MY_IP=$(curl -s https://api.ipify.org)
echo "Your IP: $MY_IP"
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "${MY_IP}/32"

echo "Security Group $SG_ID created."
```

**Why port 80?** Caddy uses Let's Encrypt's HTTP-01 challenge to prove domain ownership before issuing the certificate. After the cert is issued, all HTTP traffic is redirected to HTTPS.

---

## A-2. Create SSH Key Pair

```bash
# Create a key pair and save it locally
aws ec2 create-key-pair \
  --key-name jarvis-key \
  --query "KeyMaterial" --output text > ~/.ssh/jarvis-key.pem

# Lock down the key file (SSH refuses keys that are world-readable)
chmod 400 ~/.ssh/jarvis-key.pem

echo "Key saved to ~/.ssh/jarvis-key.pem"
```

---

## A-3. Launch EC2 Instance

```bash
# Get the latest Amazon Linux 2023 AMI for your region
AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters \
    "Name=name,Values=al2023-ami-*-x86_64" \
    "Name=state,Values=available" \
  --query "sort_by(Images, &CreationDate)[-1].ImageId" \
  --output text)
echo "AMI: $AMI_ID"

# Launch instance
#   t3.medium  = 2 vCPU + 4 GB RAM, handles ~200 agents
#   Root disk: 20 GB gp3 (encrypted)
#   Data disk:  50 GB gp3 (encrypted, separate for database + telemetry)
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type t3.medium \
  --key-name jarvis-key \
  --security-group-ids "$SG_ID" \
  --block-device-mappings '[
    {
      "DeviceName":"/dev/xvda",
      "Ebs":{"VolumeSize":20,"VolumeType":"gp3","Encrypted":true}
    },
    {
      "DeviceName":"/dev/xvdb",
      "Ebs":{"VolumeSize":50,"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":false}
    }
  ]' \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=jarvis-manager}]" \
  --query "Instances[0].InstanceId" --output text)

echo "Instance launched: $INSTANCE_ID"
echo "Waiting for it to be running..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"
echo "Instance is running."
```

> **`HttpTokens=required`** enforces IMDSv2 — protects against SSRF attacks that could steal
> AWS credentials by calling the instance metadata API (169.254.169.254).

---

## A-4. Allocate and Attach Elastic IP

An Elastic IP gives you a stable public IP address. If you ever replace the EC2 instance, you just re-attach the same EIP — your domain A record stays valid.

```bash
# Allocate an Elastic IP
ALLOC_ID=$(aws ec2 allocate-address \
  --domain vpc \
  --query "AllocationId" --output text)
echo "Elastic IP Allocation: $ALLOC_ID"

# Associate it to the instance
aws ec2 associate-address \
  --instance-id "$INSTANCE_ID" \
  --allocation-id "$ALLOC_ID"

# Get the actual public IP address
PUBLIC_IP=$(aws ec2 describe-addresses \
  --allocation-ids "$ALLOC_ID" \
  --query "Addresses[0].PublicIp" --output text)
echo ""
echo "========================================"
echo "  Your server's public IP: $PUBLIC_IP"
echo "========================================"
echo ""
```

**Save this IP address** — you need it in the next step.

---

## A-5. Point Your Domain to the Elastic IP

Go to your DNS provider (Route 53, Cloudflare, Namecheap, etc.) and create:

```
Type:  A
Name:  jarvis          (full hostname will be jarvis.yourdomain.com)
Value: <PUBLIC_IP>     (the IP from step A-4)
TTL:   300
```

Wait 2–5 minutes, then verify:

```bash
dig +short jarvis.yourdomain.com
# Must return your PUBLIC_IP before continuing
```

> **Do not skip the DNS check.** If DNS isn't resolved, Let's Encrypt will fail to issue the cert in step A-8.

---

## A-6. Connect to the Instance via SSH

```bash
# Get the public DNS of your instance
EC2_HOST=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].PublicDnsName" --output text)
echo "Host: $EC2_HOST"

# Connect
ssh -i ~/.ssh/jarvis-key.pem ec2-user@"$EC2_HOST"
```

You should see the Amazon Linux 2023 welcome banner. All remaining steps in Part A run **inside this SSH session**.

---

## A-7. Harden and Prepare the EC2 Instance

Run all of the following as `ec2-user` (the commands that need root use `sudo`).

### Update packages

```bash
sudo dnf update -y
```

### Install Docker + Docker Compose

```bash
# Install Docker
sudo dnf install -y docker git

# Start Docker and enable on boot
sudo systemctl enable --now docker

# Add ec2-user to docker group (so you don't need sudo for docker commands)
sudo usermod -aG docker ec2-user

# Install Docker Compose v2 as a plugin
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL \
  "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Apply group change WITHOUT logging out (just for this session)
newgrp docker << 'EOF'
docker compose version
EOF
# Expected: Docker Compose version v2.x.x
```

### Enable automatic security updates

```bash
sudo dnf install -y dnf-automatic
sudo sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic.timer
echo "Auto security updates enabled."
```

### Mount the data volume

The 50 GB EBS volume (`/dev/xvdb`) will hold all SQLite databases, telemetry files, and TLS certs. It is separate from the OS — you can snapshot it independently or move it to a new instance.

```bash
# Check the device name (should be /dev/xvdb or /dev/nvme1n1 on newer instances)
lsblk
# Look for the 50G disk — it will NOT have a filesystem yet

# Format it (do this ONCE only — never again after data is on it)
sudo mkfs.ext4 /dev/xvdb

# Create the mount point
sudo mkdir -p /opt/jarvis

# Add to /etc/fstab for automatic mount on reboot
echo '/dev/xvdb /opt/jarvis ext4 defaults,nofail 0 2' | sudo tee -a /etc/fstab

# Mount now (without rebooting)
sudo mount -a

# Verify
df -h /opt/jarvis
# Should show ~50G available

# Create directory structure and set permissions
sudo mkdir -p /opt/jarvis/{data,logs,certs}
sudo chmod 700 /opt/jarvis/data    # only root reads secrets
sudo chmod 755 /opt/jarvis/logs
sudo chmod 700 /opt/jarvis/certs   # TLS private key lives here
echo "Data volume mounted at /opt/jarvis"
```

---

## A-8. Deploy the Manager

### Get the code

```bash
cd /opt/jarvis
sudo git clone <YOUR_REPO_URL> app
sudo chown -R ec2-user:ec2-user /opt/jarvis/app
cd /opt/jarvis/app
```

### Configure environment variables

```bash
cp .env.example .env
nano .env
```

Fill in the `.env` file. Every line that needs your attention is marked `# <-- CHANGE THIS`:

```bash
# ── Required for production ────────────────────────────────────────────────
DOMAIN=jarvis.yourdomain.com          # <-- CHANGE THIS to your actual domain
ADMIN_EMAIL=you@yourdomain.com        # <-- CHANGE THIS (Let's Encrypt notifications)

# ── Leave blank — auto-generated and printed on first boot ─────────────────
ENROLLMENT_TOKENS=
ADMIN_TOKEN=

# ── Security hardening ─────────────────────────────────────────────────────
DEFAULT_KEY_EXPIRY_DAYS=90            # agent keys auto-expire after 90 days
CORS_ORIGINS=https://jarvis.yourdomain.com   # <-- CHANGE THIS (lock down CORS)

# ── Logging ────────────────────────────────────────────────────────────────
LOG_LEVEL=info
```

Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X` in nano).

### Update volume paths in docker-compose.prod.yml

The compose file uses relative `./data`, `./logs`, `./certs` — we want these on the separate data volume:

```bash
# Update the volume mounts to use the data volume
sed -i 's|./data:|/opt/jarvis/data:|g'  docker-compose.prod.yml
sed -i 's|./logs:|/opt/jarvis/logs:|g'  docker-compose.prod.yml
sed -i 's|./certs:|/opt/jarvis/certs:|g' docker-compose.prod.yml

# Verify the change
grep '/opt/jarvis' docker-compose.prod.yml
```

### Start the manager

```bash
# Build and start (Caddy + Manager)
docker compose -f docker-compose.prod.yml up -d --build

# Watch the logs — wait for the credentials banner
# This takes 60–90 seconds on first run (Let's Encrypt cert issuance)
docker compose -f docker-compose.prod.yml logs -f manager
```

You will see this banner — **copy these tokens right now**:

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
║    https://jarvis.yourdomain.com                             ║
╚══════════════════════════════════════════════════════════════╝
```

Press `Ctrl+C` to stop following logs (the container keeps running).

### Verify the manager is healthy

```bash
# From the EC2 instance
curl -s https://jarvis.yourdomain.com/health
```

Expected response:
```json
{"status": "ok", "agents": 0, "payloads": 0}
```

If you get a connection error, check:
```bash
docker compose -f docker-compose.prod.yml ps       # are both containers running?
docker compose -f docker-compose.prod.yml logs caddy  # any TLS errors?
```

### Make the manager start automatically on instance reboot

```bash
sudo tee /etc/systemd/system/jarvis-manager.service > /dev/null << 'EOF'
[Unit]
Description=Jarvis Manager
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/jarvis/app
ExecStart=/usr/local/lib/docker/cli-plugins/docker-compose \
  -f docker-compose.prod.yml up -d
ExecStop=/usr/local/lib/docker/cli-plugins/docker-compose \
  -f docker-compose.prod.yml down
TimeoutStartSec=300
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable jarvis-manager
echo "Manager will now auto-start on reboot."
```

### Save credentials somewhere safe

Before leaving the EC2 session, write the tokens to a secure file:

```bash
cat /opt/jarvis/app/.env | grep -E 'ENROLLMENT_TOKENS|ADMIN_TOKEN'
# If they are blank (auto-generated), check the secrets file:
cat /opt/jarvis/data/.secrets
```

**You now have a fully running Manager on AWS.** Exit SSH:

```bash
exit
```

---

---

# PART B — Install the macOS Agent

---

Everything below runs **on your Mac**. Open a new Terminal window.

---

## B-1. Check Prerequisites

```bash
# Python version — must be 3.11 or later
python3 --version
# Good:    Python 3.11.x or Python 3.12.x
# Problem: Python 3.9 or 3.10 → install tomli (or upgrade Python)

# If you need to upgrade Python on macOS:
# brew install python@3.12
# Then use python3.12 instead of python3 throughout

# Check pip
pip3 --version

# Check you are in the repo root
ls agent/agent/core.py
# Should print: agent/agent/core.py
# If not, cd to the repo: cd /path/to/macbook_data
```

---

## B-2. Install Python Dependencies

```bash
# Base agent dependencies
pip3 install -r agent/requirements.txt

# macOS-specific (Keychain + psutil)
pip3 install -r agent/os/macos/requirements.txt

# Verify
python3 -c "import cryptography, psutil, keyring, requests; print('All OK')"
# Expected: All OK
```

---

## B-3. Test Connectivity to Manager First

Before installing anything, verify the Mac can reach the manager:

```bash
# Replace with your actual domain
curl -s https://jarvis.yourdomain.com/health
# Expected: {"status": "ok", "agents": 0, "payloads": 0}
```

If this fails:
- Check that DNS resolves: `dig +short jarvis.yourdomain.com`
- Check that port 443 is reachable: `nc -zv jarvis.yourdomain.com 443`
- Check AWS Security Group has port 443 open to 0.0.0.0/0

---

## B-4. Choose Your Installation Method

There are two paths:

| Method | When to use | Time |
|--------|-------------|------|
| **Option 1 — Python source** | Development, testing, no binary build needed | 5 min |
| **Option 2 — Binary install** | Production, persistent launchd service | 15 min |

---

## Option 1 — Run from Python Source (Quickest)

This runs the agent directly with Python. Good for testing. No binary build needed.

### B1-1. Create a local config file

```bash
# From the repo root
cp agent/config/agent.toml.example agent.toml
```

### B1-2. Edit the config

```bash
nano agent.toml
```

Find and update these fields:

```toml
[agent]
id   = "macbook-yourname-001"         # UNIQUE — use your machine name, no spaces
name = "Your Name MacBook Pro"        # display name shown in dashboard

[manager]
url        = "https://jarvis.yourdomain.com"   # your AWS manager URL
tls_verify = true                              # true = real Let's Encrypt cert

[enrollment]
token    = "sk-enroll-xxxxxxxxxxxxxxxxxxxxxxxx"  # from Part A step A-8
keystore = "keychain"                            # macOS Keychain storage
```

Everything else can stay at defaults. Save and exit.

### B1-3. Run the agent

```bash
# Option 1a: Standard agent
PYTHONPATH=. python3 -m agent.agent.core --config agent.toml

# Option 1b: Hardened v2 (circuit breakers, disk spool — recommended)
PYTHONPATH=. python3 agent_v2.py --config agent.toml
```

You should see output like:
```
INFO  agent       Starting mac_intel agent agent-001
INFO  enrollment  No key found in keystore — enrolling...
INFO  enrollment  Enrollment successful. API key stored in Keychain.
INFO  sender      Connected to https://jarvis.yourdomain.com
INFO  collector   [metrics] collected 1 record
INFO  sender      POST /api/v1/ingest section=metrics → 200 OK
```

Leave this running and jump to **Step B-5 (Verify)** to confirm data is arriving.

To stop: `Ctrl+C`

---

## Option 2 — Full Binary Install as a LaunchDaemon (Production)

This compiles the agent to a standalone binary, installs it as a system service that:
- Starts automatically at boot
- Runs as root (needed to collect system-level data)
- Restarts automatically if it crashes
- Survives log-outs

### B2-1. Install PyInstaller

```bash
pip3 install pyinstaller
pyinstaller --version
# Expected: 6.x.x
```

### B2-2. Build the agent binary

```bash
# From the repo root
make build-agent
# This runs:
# pyinstaller --onefile --clean --name macintel-agent \
#   --target-architecture arm64 \
#   --hidden-import agent.agent.collectors \
#   ...
#   agent/agent/core.py
```

Expected output ends with:
```
Building EXE from EXE-00.toc completed successfully.
```

Binary is at: `dist/macintel-agent`

### B2-3. Build the watchdog binary

```bash
make build-watchdog
# Produces: dist/macintel-watchdog
```

### B2-4. Verify the binaries

```bash
ls -lh dist/macintel-agent dist/macintel-watchdog
# Should show two files, each 20-40 MB

file dist/macintel-agent
# Expected: Mach-O 64-bit executable arm64  (or x86_64 on Intel Mac)
```

### B2-5. Copy binaries to the installer's expected location

The installer script looks for binaries in `agent/os/macos/installer/dist/`:

```bash
mkdir -p agent/os/macos/installer/dist
cp dist/macintel-agent     agent/os/macos/installer/dist/
cp dist/macintel-watchdog  agent/os/macos/installer/dist/

# Verify
ls -lh agent/os/macos/installer/dist/
```

### B2-6. Run the installer

```bash
# Replace the values in quotes with your actual tokens and domain
sudo bash agent/os/macos/installer/install.sh \
  --manager-url  "https://jarvis.yourdomain.com" \
  --enroll-token "sk-enroll-xxxxxxxxxxxxxxxxxxxxxxxx" \
  --agent-name   "Your Name MacBook Pro" \
  --tls-verify   true
```

The installer will:
1. Create `/opt/macintel/bin/` — installs the binaries
2. Create `/Library/Application Support/MacIntel/` — config, data, security (key)
3. Create `/Library/Logs/MacIntel/` — log files
4. Write `agent.toml` with your settings
5. Write `/Library/LaunchDaemons/com.macintel.agent.plist`
6. Write `/Library/LaunchDaemons/com.macintel.watchdog.plist`
7. Load both services immediately

Expected output:
```
  ╔══════════════════════════════════════════╗
  ║    mac_intel Agent Installer (macOS)     ║
  ╚══════════════════════════════════════════╝

  Install dir : /opt/macintel
  Data dir    : /Library/Application Support/MacIntel
  Log dir     : /Library/Logs/MacIntel
  Manager     : https://jarvis.yourdomain.com
  Agent name  : Your Name MacBook Pro
  ...

  ╔══════════════════════════════════════════╗
  ║           Installation Complete          ║
  ╚══════════════════════════════════════════╝

  Agent PID    : 12345
  Watchdog PID : 12346
```

### B2-7. Check the logs

```bash
# Follow agent stdout (most useful)
tail -f "/Library/Logs/MacIntel/agent-stdout.log"

# Follow agent stderr (errors only)
tail -f "/Library/Logs/MacIntel/agent-stderr.log"
```

Look for:
```
INFO  enrollment  Enrollment successful. API key stored in Keychain.
INFO  sender      POST /api/v1/ingest section=metrics → 200 OK
```

### B2-8. Day-to-day service management

```bash
# Check if agent is running (look for "PID" in output)
sudo launchctl list com.macintel.agent

# Check if watchdog is running
sudo launchctl list com.macintel.watchdog

# Stop agent
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist

# Start agent
sudo launchctl load -w /Library/LaunchDaemons/com.macintel.agent.plist

# Restart agent
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist
sudo launchctl load  -w /Library/LaunchDaemons/com.macintel.agent.plist

# Reload config without full restart (sends SIGHUP)
sudo launchctl kill HUP system/com.macintel.agent

# View logs
tail -100 "/Library/Logs/MacIntel/agent-stdout.log"
tail -100 "/Library/Logs/MacIntel/agent-stderr.log"
```

---

## B-5. Verify the Agent is Connected

### Check from the Mac

```bash
# If using Option 1 (Python source) — check in the running terminal output
# Look for: POST /api/v1/ingest section=metrics → 200 OK

# If using Option 2 (installed service):
tail -20 "/Library/Logs/MacIntel/agent-stdout.log"
```

### Check from the Manager (any terminal)

```bash
# List all agents that have enrolled
curl -s https://jarvis.yourdomain.com/api/v1/agents | python3 -m json.tool
```

Expected:
```json
[
  {
    "agent_id": "macbook-yourname-001",
    "name": "Your Name MacBook Pro",
    "last_seen": 1713200400,
    "last_ip": "203.0.113.50"
  }
]
```

### Check section data is arriving

```bash
# Replace macbook-yourname-001 with your agent_id
curl -s "https://jarvis.yourdomain.com/api/v1/agents/macbook-yourname-001/metrics" \
  | python3 -m json.tool
```

Expected: JSON with `cpu_pct`, `mem_pct`, `load_1m`, etc.

### Open the dashboard

Open in browser: `https://jarvis.yourdomain.com`

You should see the dark sidebar dashboard with your agent listed. The Let's Encrypt certificate means no browser warning.

---

---

# PART C — Key Management (Post-Install)

---

All commands use the admin token from Part A step A-8.

```bash
# Set these once in your terminal
MANAGER="https://jarvis.yourdomain.com"
ADMIN_TOKEN="sk-admin-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AGENT_ID="macbook-yourname-001"
```

### List all agent keys (no secrets shown)

```bash
curl -s -H "X-Admin-Token: $ADMIN_TOKEN" \
     "$MANAGER/api/v1/keys" | python3 -m json.tool
```

### Rotate a key (if the Mac is compromised)

```bash
curl -s -X POST \
     -H "X-Admin-Token: $ADMIN_TOKEN" \
     "$MANAGER/api/v1/keys/$AGENT_ID/rotate" | python3 -m json.tool
# New key is shown ONCE. The agent must re-enroll.
```

After rotation, clear the old key from Keychain and restart the agent:

```bash
# On the Mac:
security delete-generic-password -s com.macintel.agent -a "$AGENT_ID" 2>/dev/null
# Then restart agent — it will auto-enroll with the enrollment token
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist
sudo launchctl load  -w /Library/LaunchDaemons/com.macintel.agent.plist
```

### Set 90-day expiry

```bash
curl -s -X PATCH \
     -H "X-Admin-Token: $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"expires_in_days": 90}' \
     "$MANAGER/api/v1/keys/$AGENT_ID/expiry"
```

### Revoke a key immediately (block agent from sending)

```bash
curl -s -X POST \
     -H "X-Admin-Token: $ADMIN_TOKEN" \
     "$MANAGER/api/v1/keys/$AGENT_ID/revoke"
```

---

---

# PART D — Uninstall

---

### Remove macOS agent (Option 2 binary install)

```bash
sudo bash agent/os/macos/installer/uninstall.sh
# Stops services, removes plists, removes /opt/macintel and /Library/Application Support/MacIntel
# Also removes Keychain entry
```

### Remove macOS agent (Option 1 Python source)

```bash
# Just stop the running python3 process (Ctrl+C)
# And optionally remove the Keychain entry:
security delete-generic-password -s com.macintel.agent -a "macbook-yourname-001"
```

### Remove manager from AWS

```bash
# On EC2: stop manager
docker compose -f /opt/jarvis/app/docker-compose.prod.yml down

# From your local machine: terminate EC2 instance
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"

# Release Elastic IP (stops billing for it)
aws ec2 release-address --allocation-id "$ALLOC_ID"

# Delete Security Group (must wait until instance is fully terminated)
aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
aws ec2 delete-security-group --group-id "$SG_ID"
```

---

---

# PART E — Troubleshooting

---

## Problem: Enrollment fails with "401 Unauthorized"

```
ERROR enrollment  POST /api/v1/enroll → 401
```

**Cause:** Wrong enrollment token.

**Fix:**
```bash
# Check what token the manager expects:
ssh -i ~/.ssh/jarvis-key.pem ec2-user@"$EC2_HOST" \
  "cat /opt/jarvis/data/.secrets"

# Update the token in your config:
# Option 1 (source): edit agent.toml [enrollment] token = "..."
# Option 2 (binary): edit /Library/Application\ Support/MacIntel/agent.toml
#                    then: sudo launchctl kill HUP system/com.macintel.agent
```

## Problem: "Clock skew too large" or "Timestamp rejected"

```
ERROR ingest  timestamp skew 412s > 300s
```

**Cause:** The Mac's clock and EC2 instance clock differ by more than 5 minutes.

**Fix:**
```bash
# On the Mac — sync clock
sudo sntp -sS time.apple.com

# On EC2 — should be auto-synced via chrony (Amazon Linux 2023)
# Verify: chronyc tracking | grep "System time"
```

## Problem: TLS error on the Mac

```
ERROR sender  SSL: CERTIFICATE_VERIFY_FAILED
```

**Cause:** `tls_verify = true` but the cert isn't trusted.

**Diagnosis:**
```bash
# Check the cert
curl -v https://jarvis.yourdomain.com/health 2>&1 | grep -A5 "SSL"

# If you see "self-signed" it means Caddy hasn't gotten the Let's Encrypt cert yet
# Check Caddy logs:
ssh -i ~/.ssh/jarvis-key.pem ec2-user@"$EC2_HOST" \
  "docker compose -f /opt/jarvis/app/docker-compose.prod.yml logs caddy"
```

**Fix:** Wait for DNS to propagate, then restart Caddy:
```bash
# On EC2:
docker compose -f /opt/jarvis/app/docker-compose.prod.yml restart caddy
```

**Temporary workaround** while debugging:
```toml
# in agent.toml — ONLY for debugging, revert after cert is valid
tls_verify = false
```

## Problem: Agent is running but no data in dashboard

```
# agent log shows: POST /api/v1/ingest → 200 OK
# But dashboard shows 0 payloads
```

**Cause:** Usually a minor delay — the Jarvis engine processes async. Wait 10–30 seconds and refresh.

If still empty after 2 minutes:
```bash
# Check manager is writing to SQLite
ssh -i ~/.ssh/jarvis-key.pem ec2-user@"$EC2_HOST" \
  "docker compose -f /opt/jarvis/app/docker-compose.prod.yml logs manager | tail -50"
```

## Problem: "Binary not found" during install.sh

```
ERROR: Binary not found: agent/os/macos/installer/dist/macintel-agent
```

**Fix:** You need to build the binaries first (B2-2 through B2-5 above):
```bash
make build-agent
make build-watchdog
mkdir -p agent/os/macos/installer/dist
cp dist/macintel-agent    agent/os/macos/installer/dist/
cp dist/macintel-watchdog agent/os/macos/installer/dist/
```

## Problem: Port 443 not reachable from Mac

```bash
nc -zv jarvis.yourdomain.com 443
# Connection refused
```

**Fix:** Check Security Group allows port 443 from 0.0.0.0/0:
```bash
aws ec2 describe-security-groups --group-ids "$SG_ID" \
  --query "SecurityGroups[0].IpPermissions"
```

Look for `"FromPort": 443` with `"CidrIp": "0.0.0.0/0"`.

If missing:
```bash
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp --port 443 --cidr 0.0.0.0/0
```

---

## Quick Reference Card

```
MANAGER
  Health check:    curl -s https://jarvis.yourdomain.com/health
  List agents:     curl -s https://jarvis.yourdomain.com/api/v1/agents
  Dashboard:       https://jarvis.yourdomain.com
  Logs (EC2):      docker compose -f docker-compose.prod.yml logs -f manager
  Restart:         docker compose -f docker-compose.prod.yml restart manager

macOS AGENT (Option 1 — Python source)
  Run:             PYTHONPATH=. python3 agent_v2.py --config agent.toml
  Config:          agent.toml  (in repo root)

macOS AGENT (Option 2 — Binary install)
  Status:          sudo launchctl list com.macintel.agent
  Logs:            tail -f "/Library/Logs/MacIntel/agent-stdout.log"
  Restart:         sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist
                   sudo launchctl load  -w /Library/LaunchDaemons/com.macintel.agent.plist
  Config:          /Library/Application\ Support/MacIntel/agent.toml
  Uninstall:       sudo bash agent/os/macos/installer/uninstall.sh

KEY MANAGEMENT
  List keys:       curl -s -H "X-Admin-Token: $ADMIN_TOKEN" $MANAGER/api/v1/keys
  Rotate key:      curl -s -X POST -H "X-Admin-Token: $ADMIN_TOKEN" $MANAGER/api/v1/keys/$ID/rotate
  Revoke key:      curl -s -X POST -H "X-Admin-Token: $ADMIN_TOKEN" $MANAGER/api/v1/keys/$ID/revoke
```
