# mac_intel on AWS — Secure Deployment Guide

## Architecture Decision: What We're Building and Why

```
Internet (Agents + Admin Browser)
          │
          │  HTTPS :443
          ▼
┌─────────────────────────────────────────────────────┐
│  AWS Security Group (stateful firewall)             │
│   IN  :443  TCP  0.0.0.0/0   ← agents + dashboard  │
│   IN  :80   TCP  0.0.0.0/0   ← Let's Encrypt only  │
│   OUT all                    ← threat feed updates  │
│   NO port 22 from internet   ← use SSM instead      │
└──────────────┬──────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│  EC2 t3.medium  (Amazon Linux 2023)                 │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │  Docker Compose                             │    │
│  │   caddy:2-alpine → :443/:80                 │    │
│  │     └─ reverse proxy → manager:8080        │    │
│  │   jarvis-manager → :8080 (plain HTTP)       │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
│  EBS gp3 50 GB  (encrypted, separate data volume)  │
│   /opt/jarvis/data/   ← SQLite, telemetry store    │
│   /opt/jarvis/logs/   ← rotating log files         │
│   /opt/jarvis/certs/  ← Caddy-managed TLS certs    │
└─────────────────────────────────────────────────────┘
               │
         Elastic IP  (static, maps to your domain)
               │
         Route 53  A record → jarvis.yourdomain.com
```

### Why each choice?

| Choice | Reason |
|--------|--------|
| Caddy + Let's Encrypt | Zero-config auto-renewing TLS. No cert rotation script needed. Real CA cert means `tls_verify=true` on agents — no MITM risk. |
| Elastic IP | Agents are configured once with a stable IP or domain. If instance is replaced, just re-associate the EIP. |
| SSM Session Manager (no SSH port) | Eliminates brute-force surface on port 22. Access is IAM-gated, CloudTrail-audited, no key management. |
| Separate EBS data volume | Lets you snapshot/replace the root volume without touching your SQLite database or telemetry. Encrypted at rest with KMS. |
| t3.medium | 2 vCPU, 4 GB RAM handles ~200 agents comfortably. Scale up to t3.large for 500+. |
| Amazon Linux 2023 | Kernel livepatch, automatic security updates, Docker supported natively. |

---

## What You Need Before Starting

| Item | Where to get it |
|------|----------------|
| AWS account | aws.amazon.com |
| Domain name | Route 53 or any registrar (e.g., `jarvis.yourdomain.com`) |
| AWS CLI configured locally | `aws configure` with an IAM user/role |
| 15–20 minutes | — |

If you don't have a domain, use **Option B** (self-signed TLS on port 8443) — covered in a separate section at the end.

---

## Phase 1 — AWS Infrastructure Setup

### 1.1 Create a VPC (or use default)

For most setups the default VPC is fine. If you want isolation:

```bash
# Create a dedicated VPC
aws ec2 create-vpc --cidr-block 10.10.0.0/16 --tag-specifications \
  'ResourceType=vpc,Tags=[{Key=Name,Value=jarvis-vpc}]'

# Create a public subnet
aws ec2 create-subnet --vpc-id <VPC_ID> \
  --cidr-block 10.10.1.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=jarvis-public}]'

# Internet gateway + attach
aws ec2 create-internet-gateway --tag-specifications \
  'ResourceType=internet-gateway,Tags=[{Key=Name,Value=jarvis-igw}]'
aws ec2 attach-internet-gateway --vpc-id <VPC_ID> --internet-gateway-id <IGW_ID>

# Route table
aws ec2 create-route-table --vpc-id <VPC_ID>
aws ec2 create-route --route-table-id <RTB_ID> \
  --destination-cidr-block 0.0.0.0/0 --gateway-id <IGW_ID>
aws ec2 associate-route-table --subnet-id <SUBNET_ID> --route-table-id <RTB_ID>
```

### 1.2 Create the Security Group

```bash
# Create security group
SG=$(aws ec2 create-security-group \
  --group-name jarvis-manager-sg \
  --description "Jarvis Manager - agents and dashboard" \
  --vpc-id <VPC_ID> \
  --query 'GroupId' --output text)

echo "Security Group: $SG"

# HTTPS (443) — agents + dashboard browser
aws ec2 authorize-security-group-ingress --group-id $SG \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# HTTP (80) — Let's Encrypt ACME HTTP-01 challenge ONLY
# Caddy auto-redirects all other HTTP to HTTPS
aws ec2 authorize-security-group-ingress --group-id $SG \
  --protocol tcp --port 80 --cidr 0.0.0.0/0

# SSM Session Manager — NO port 22 needed
# (If you absolutely need SSH for troubleshooting, add your IP only):
# aws ec2 authorize-security-group-ingress --group-id $SG \
#   --protocol tcp --port 22 --cidr <YOUR_HOME_IP>/32
```

**Port summary:**

| Port | Protocol | Source | Purpose | Keep? |
|------|----------|--------|---------|-------|
| 443 | TCP | 0.0.0.0/0 | Agent telemetry + dashboard HTTPS | Required |
| 80 | TCP | 0.0.0.0/0 | Let's Encrypt HTTP-01 challenge | Required for LE |
| 8443 | TCP | 0.0.0.0/0 | Direct TLS (Option B only) | Only if no domain |
| 22 | TCP | **Your IP /32** | SSH emergency access | Optional, restrict tightly |

> **Security rule:** never open port 22 to 0.0.0.0/0. If you open it at all, whitelist only your static IP.

### 1.3 Launch the EC2 Instance

```bash
# Find latest Amazon Linux 2023 AMI
AMI=$(aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=al2023-ami-*-x86_64" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text)

echo "Latest AL2023 AMI: $AMI"

# Launch instance
INSTANCE=$(aws ec2 run-instances \
  --image-id $AMI \
  --instance-type t3.medium \
  --key-name <YOUR_KEY_PAIR_NAME> \       # omit if using SSM only
  --security-group-ids $SG \
  --subnet-id <SUBNET_ID> \
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
  --iam-instance-profile Name=jarvis-ssm-profile \
  --metadata-options HttpTokens=required \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=jarvis-manager}]' \
  --query 'Instances[0].InstanceId' --output text)

echo "Instance: $INSTANCE"
```

> **Security note: `HttpTokens=required`** enforces IMDSv2 — prevents SSRF attacks from leaking instance credentials via the metadata API.

### 1.4 Attach Elastic IP

```bash
# Allocate Elastic IP
EIP=$(aws ec2 allocate-address --domain vpc \
  --query 'AllocationId' --output text)

# Associate with instance (wait ~30s for instance to start)
aws ec2 associate-address \
  --instance-id $INSTANCE \
  --allocation-id $EIP

# Get the public IP
PUBLIC_IP=$(aws ec2 describe-addresses \
  --allocation-ids $EIP \
  --query 'Addresses[0].PublicIp' --output text)
echo "Elastic IP: $PUBLIC_IP"
```

### 1.5 Create IAM Role for SSM (no SSH needed)

```bash
# Trust policy
cat > trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

# Create role
aws iam create-role --role-name jarvis-ssm-role \
  --assume-role-policy-document file://trust.json

# Attach SSM managed policy
aws iam attach-role-policy --role-name jarvis-ssm-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

# Create instance profile
aws iam create-instance-profile \
  --instance-profile-name jarvis-ssm-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name jarvis-ssm-profile \
  --role-name jarvis-ssm-role
```

### 1.6 Point Your Domain to the Elastic IP

In Route 53 (or your registrar's DNS):

```
Type:  A
Name:  jarvis.yourdomain.com
Value: <ELASTIC_IP>
TTL:   300
```

Wait for DNS propagation (2–5 minutes). Verify:
```bash
dig +short jarvis.yourdomain.com
# Should return your Elastic IP
```

---

## Phase 2 — Harden and Prepare the EC2 Instance

### 2.1 Connect via SSM Session Manager (no SSH)

```bash
# Install SSM plugin locally if not already installed
# https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html

aws ssm start-session --target $INSTANCE
```

Or use the AWS Console: EC2 → select instance → Connect → Session Manager.

### 2.2 Instance baseline setup

All commands below run on the EC2 instance:

```bash
# Switch to root for setup
sudo -i

# Update all packages
dnf update -y

# Install Docker
dnf install -y docker git
systemctl enable --now docker
usermod -aG docker ec2-user

# Install Docker Compose v2
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version   # verify: Docker Compose version v2.x

# Enable automatic security updates
dnf install -y dnf-automatic
sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer

# Install and configure fail2ban (protects against brute-force)
dnf install -y epel-release 2>/dev/null || true
dnf install -y fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOF
systemctl enable --now fail2ban
```

### 2.3 Mount and format the data volume

```bash
# Check if /dev/xvdb exists
lsblk

# Format (only on first setup — NEVER if data already exists)
mkfs.ext4 /dev/xvdb

# Create mount point
mkdir -p /opt/jarvis

# Persistent mount
echo '/dev/xvdb /opt/jarvis ext4 defaults,nofail 0 2' >> /etc/fstab
mount -a

# Verify
df -h /opt/jarvis
# Should show 50GB

# Set permissions
mkdir -p /opt/jarvis/{data,logs,certs}
chmod 700 /opt/jarvis/data    # only root can read secrets
chmod 755 /opt/jarvis/logs
chmod 700 /opt/jarvis/certs
```

---

## Phase 3 — Deploy the Manager

### 3.1 Get the code onto the instance

```bash
cd /opt/jarvis

# Clone the repo
git clone <YOUR_REPO_URL> app
cd app
```

### 3.2 Configure environment

```bash
cp .env.example .env
nano .env
```

Minimum required `.env` for production:

```bash
# ── Network ───────────────────────────────────────────────────────────
DOMAIN=jarvis.yourdomain.com          # your actual domain
ADMIN_EMAIL=you@yourdomain.com        # Let's Encrypt notifications

# ── Auth (leave blank to auto-generate on first boot) ─────────────────
# Or pre-generate strong tokens:
ENROLLMENT_TOKENS=sk-enroll-$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")
ADMIN_TOKEN=sk-admin-$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

# ── Security ──────────────────────────────────────────────────────────
DEFAULT_KEY_EXPIRY_DAYS=90            # agent keys expire in 90 days
CORS_ORIGINS=https://jarvis.yourdomain.com   # lock down CORS

# ── Logging ───────────────────────────────────────────────────────────
LOG_LEVEL=info
```

> **Never commit `.env`** — it contains secrets. It is already in `.gitignore`.

### 3.3 Map volumes to the data disk

Edit `docker-compose.prod.yml` volumes section to use `/opt/jarvis`:

```bash
sed -i 's|./data|/opt/jarvis/data|g'  docker-compose.prod.yml
sed -i 's|./logs|/opt/jarvis/logs|g'  docker-compose.prod.yml
sed -i 's|./certs|/opt/jarvis/certs|g' docker-compose.prod.yml
```

Or edit the file directly so volumes are:
```yaml
volumes:
  - /opt/jarvis/data:/app/data
  - /opt/jarvis/logs:/app/logs
  - /opt/jarvis/certs:/app/certs   # not used in prod (Caddy manages certs)
```

### 3.4 Start the manager

```bash
cd /opt/jarvis/app

# Load environment
export $(grep -v '^#' .env | xargs)

# Start Caddy + Manager
docker compose -f docker-compose.prod.yml up -d

# Watch startup (30-60s for Let's Encrypt cert)
docker compose -f docker-compose.prod.yml logs -f manager
```

You should see:
```
╔══════════════════════════════════════════════════════════════╗
║              Jarvis Manager — Starting Up                   ║
╠══════════════════════════════════════════════════════════════╣
║  ENROLLMENT TOKEN:  sk-enroll-xxxxxxxxxxxxxxxxxxxxxxxx      ║
║  ADMIN TOKEN:       sk-admin-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ║
║  Manager URL:       https://jarvis.yourdomain.com           ║
╚══════════════════════════════════════════════════════════════╝
```

**Save these tokens** — you need them for agent installation.

### 3.5 Verify manager is healthy

```bash
# From the EC2 instance (or any machine with internet access)
curl -s https://jarvis.yourdomain.com/health | python3 -m json.tool
# Expected: {"status": "ok", "agents": 0, "payloads": 0}
```

### 3.6 Make the manager start on boot

```bash
cat > /etc/systemd/system/jarvis-manager.service << 'EOF'
[Unit]
Description=Jarvis Manager (Docker Compose)
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/jarvis/app
EnvironmentFile=/opt/jarvis/app/.env
ExecStart=/usr/local/lib/docker/cli-plugins/docker-compose \
  -f docker-compose.prod.yml up -d
ExecStop=/usr/local/lib/docker/cli-plugins/docker-compose \
  -f docker-compose.prod.yml down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable jarvis-manager
```

---

## Phase 4 — Install macOS Agent

Run these commands on each macOS endpoint. You need the following from Phase 3:
- Manager URL: `https://jarvis.yourdomain.com`
- Enrollment token: `sk-enroll-xxxxxxxx`

### 4.1 Create directories

```bash
sudo mkdir -p /Library/Jarvis/{bin,config,data,security,spool,logs}
sudo chown -R root:wheel /Library/Jarvis
sudo chmod 750 /Library/Jarvis/config
sudo chmod 700 /Library/Jarvis/security
sudo chmod 755 /Library/Jarvis/{bin,data,spool,logs}
```

### 4.2 Install dependencies (dev/source mode)

If running from Python source (no pre-built binary):

```bash
# Install Homebrew if needed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Python 3.11+
brew install python@3.11

# Agent dependencies
pip3 install -r /path/to/macbook_data/agent/requirements.txt
pip3 install -r /path/to/macbook_data/agent/os/macos/requirements.txt
```

### 4.3 Configure agent.toml

```bash
sudo cp /path/to/macbook_data/agent/config/agent.toml.example \
        /Library/Jarvis/config/agent.toml
sudo nano /Library/Jarvis/config/agent.toml
```

Key settings (minimum required):

```toml
[agent]
id   = "macbook-alice-001"          # UNIQUE per device — alphanumeric
name = "Alice MacBook Pro"          # display name

[manager]
url        = "https://jarvis.yourdomain.com"
tls_verify = true                   # MUST be true with real cert

[enrollment]
token    = "sk-enroll-xxxxxxxxxxxxxxxxxxxxxxxx"
keystore = "keychain"               # macOS Keychain — most secure
```

Lock down config:
```bash
sudo chmod 640 /Library/Jarvis/config/agent.toml
sudo chown root:wheel /Library/Jarvis/config/agent.toml
```

### 4.4 Register and start LaunchDaemons

```bash
# From the repo directory — generates and loads both plists
sudo python3 -c "
import sys
sys.path.insert(0, '/path/to/macbook_data')
from agent.os.macos.launchd import install_plist
install_plist('both')
print('Done.')
"

# Verify
sudo launchctl list com.jarvis.agent
sudo launchctl list com.jarvis.watchdog
```

Check enrollment in logs:
```bash
tail -f /Library/Jarvis/logs/agent-stdout.log
# Look for: "Enrollment successful. API key stored in keychain."
```

### 4.5 Confirm agent appears on manager

```bash
curl -s https://jarvis.yourdomain.com/api/v1/agents | python3 -m json.tool
```

---

## Phase 5 — Install Windows Agent

Run PowerShell **as Administrator** on each Windows endpoint.

### 5.1 Prepare the installer files

Download or copy to `C:\Temp\jarvis-install\`:
- `jarvis-agent.exe`
- `jarvis-watchdog.exe`
- `agent\os\windows\installer\install.ps1`

```powershell
# Create staging directory
New-Item -ItemType Directory -Force -Path C:\Temp\jarvis-install
cd C:\Temp\jarvis-install
```

### 5.2 Run the installer

```powershell
.\install.ps1 `
    -ManagerUrl  "https://jarvis.yourdomain.com" `
    -EnrollToken "sk-enroll-xxxxxxxxxxxxxxxxxxxxxxxx" `
    -AgentId     "win-desktop-bob-001" `
    -AgentName   "Bob Desktop" `
    -TlsVerify   $true          # true because we have a real cert
```

The installer:
1. Creates `C:\Program Files (x86)\Jarvis\{bin,config,data,security,spool,logs}`
2. Applies ACLs: `SYSTEM` + `Admins` only — no regular user read access
3. Registers `MacIntelAgent` and `MacIntelWatchdog` Windows Services
4. Sets failure recovery: restart after 60s, up to 3 times

Verify:
```powershell
Get-Service MacIntelAgent, MacIntelWatchdog | Select-Object Name, Status
# Both should show: Running

# Watch logs for enrollment
Get-Content "C:\Program Files (x86)\Jarvis\logs\agent.log" -Tail 20 -Wait
# Look for: Enrollment successful
```

---

## Phase 6 — Verify Everything End-to-End

### 6.1 Health check

```bash
curl -s https://jarvis.yourdomain.com/health
# {"status": "ok", "agents": 2, "payloads": 150}
```

### 6.2 List all enrolled agents

```bash
curl -s https://jarvis.yourdomain.com/api/v1/agents | python3 -m json.tool
```

### 6.3 Inspect section data

```bash
# Replace macbook-alice-001 with your actual agent_id
curl -s "https://jarvis.yourdomain.com/api/v1/agents/macbook-alice-001/metrics" \
  | python3 -m json.tool
```

### 6.4 Open the dashboard

Navigate to `https://jarvis.yourdomain.com` in your browser.  
The TLS cert is real (Let's Encrypt) — no certificate warning.

### 6.5 Check Jarvis findings

```bash
curl -s "https://jarvis.yourdomain.com/api/v1/jarvis/macbook-alice-001/summary" \
  | python3 -m json.tool
```

---

## Phase 7 — Key Management

Use the admin token from Phase 3.

```bash
MANAGER="https://jarvis.yourdomain.com"
ADMIN_TOKEN="sk-admin-xxxxxxxx"    # from docker logs
```

### List all agent keys
```bash
curl -s -H "X-Admin-Token: $ADMIN_TOKEN" $MANAGER/api/v1/keys | python3 -m json.tool
```

### Rotate a key (if agent is compromised)
```bash
curl -s -X POST -H "X-Admin-Token: $ADMIN_TOKEN" \
     $MANAGER/api/v1/keys/macbook-alice-001/rotate | python3 -m json.tool
# Returns new key ONE TIME only. Agent must re-enroll after this.
```

### Revoke a key immediately
```bash
curl -s -X POST -H "X-Admin-Token: $ADMIN_TOKEN" \
     $MANAGER/api/v1/keys/macbook-alice-001/revoke
```

### Set 90-day expiry on a key
```bash
curl -s -X PATCH \
     -H "X-Admin-Token: $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"expires_in_days": 90}' \
     $MANAGER/api/v1/keys/macbook-alice-001/expiry
```

---

## Phase 8 — Ongoing Security Operations

### 8.1 EBS Snapshots (daily backup)

```bash
# Create a snapshot of the data volume
VOLUME_ID=$(aws ec2 describe-instances --instance-ids $INSTANCE \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName==`/dev/xvdb`].Ebs.VolumeId' \
  --output text)

aws ec2 create-snapshot \
  --volume-id $VOLUME_ID \
  --description "Jarvis manager data $(date +%Y-%m-%d)"
```

Automate with AWS Data Lifecycle Manager (DLM) for daily snapshots with 7-day retention.

### 8.2 Log forwarding to CloudWatch

```bash
# On the EC2 instance
dnf install -y amazon-cloudwatch-agent

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/opt/jarvis/logs/manager.log",
            "log_group_name": "/jarvis/manager",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
EOF

systemctl enable --now amazon-cloudwatch-agent
```

### 8.3 Enable AWS GuardDuty

```bash
# Enable in your region
aws guardduty create-detector --enable --finding-publishing-frequency ONE_HOUR
```

GuardDuty will alert on unusual API calls, port scans, crypto mining, and exfiltration.

### 8.4 Patch manager regularly

```bash
# On the EC2 instance — pull latest image and restart
cd /opt/jarvis/app
git pull origin main
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

### 8.5 Rotate admin and enrollment tokens periodically

```bash
# Generate new tokens
NEW_ENROLL=$(python3 -c "import secrets; print('sk-enroll-' + secrets.token_urlsafe(18))")
NEW_ADMIN=$(python3 -c "import secrets; print('sk-admin-' + secrets.token_urlsafe(24))")

# Update .env
sed -i "s/^ENROLLMENT_TOKENS=.*/ENROLLMENT_TOKENS=$NEW_ENROLL/" /opt/jarvis/app/.env
sed -i "s/^ADMIN_TOKEN=.*/ADMIN_TOKEN=$NEW_ADMIN/" /opt/jarvis/app/.env

# Restart manager to pick up new tokens
docker compose -f docker-compose.prod.yml up -d --force-recreate manager

echo "New enrollment token: $NEW_ENROLL"
echo "New admin token:      $NEW_ADMIN"
```

---

## Option B — No Domain Name (IP + Self-Signed TLS, Port 8443)

Use this if you don't have a domain name yet.

### Security Group changes

Replace port 443 with 8443:
```bash
aws ec2 authorize-security-group-ingress --group-id $SG \
  --protocol tcp --port 8443 --cidr 0.0.0.0/0
# Note: do NOT open port 80 (no Let's Encrypt needed)
```

### .env changes

```bash
PUBLIC_IP=<YOUR_ELASTIC_IP>
BIND_PORT=8443
# Leave DOMAIN blank
```

### Start with dev compose

```bash
docker compose up -d   # NOT docker-compose.prod.yml
```

### Agent config change (Option B only)

```toml
[manager]
url        = "https://<ELASTIC_IP>:8443"
tls_verify = false     # self-signed cert — only acceptable in dev/internal
```

> **Warning:** `tls_verify=false` means the agent accepts any certificate.
> Only use on trusted internal networks. Migrate to Option A (real cert) as soon as possible.

---

## Security Controls Summary

| Layer | Control | Status |
|-------|---------|--------|
| **AWS Network** | Security Group: ports 443+80 only | Required |
| **AWS Network** | No port 22 from internet (SSM only) | Recommended |
| **AWS Host** | IMDSv2 enforced (HttpTokens=required) | Required |
| **AWS Host** | EBS encrypted at rest (KMS) | Required |
| **AWS Host** | Automatic security updates (dnf-automatic) | Required |
| **AWS Host** | fail2ban brute-force protection | Recommended |
| **AWS Detection** | GuardDuty enabled | Recommended |
| **AWS Backup** | Daily EBS snapshots (DLM) | Recommended |
| **AWS Audit** | CloudTrail + CloudWatch logs | Recommended |
| **Transport** | TLS 1.3 via Let's Encrypt (Caddy) | Required |
| **App: Enrollment** | One-time `sk-enroll-*` token | Required |
| **App: Admin API** | `sk-admin-*` token, separate from enroll | Required |
| **App: Per-agent** | Each agent has its own 256-bit key | Built-in |
| **App: Payload** | AES-256-GCM + HMAC-SHA256 + HKDF | Built-in |
| **App: Replay** | ±300s timestamp + nonce dedup | Built-in |
| **App: CORS** | Locked to `https://jarvis.yourdomain.com` | Set in .env |
| **App: Key expiry** | 90-day default (`DEFAULT_KEY_EXPIRY_DAYS=90`) | Set in .env |
| **macOS Agent** | API key in Keychain (never in config file) | Built-in |
| **Windows Agent** | API key in DPAPI Credential Manager | Built-in |
| **Windows Agent** | Binary/config ACLs: SYSTEM+Admins only | Built-in |

---

## Quick Reference — Ports

| Port | Open to | Service | Required |
|------|---------|---------|----------|
| 443 | 0.0.0.0/0 | HTTPS — agents + dashboard | Yes (Option A) |
| 80 | 0.0.0.0/0 | HTTP — Let's Encrypt challenge only | Yes (Option A) |
| 8443 | 0.0.0.0/0 | HTTPS self-signed — agents + dashboard | Yes (Option B) |
| 22 | Your IP /32 | SSH emergency | Optional |

---

## Troubleshooting

### Manager won't start

```bash
docker compose -f docker-compose.prod.yml logs manager
docker compose -f docker-compose.prod.yml logs caddy
```

### Let's Encrypt fails

```bash
# Check DNS resolved correctly
dig +short jarvis.yourdomain.com
# Must return your Elastic IP — if not, wait for DNS propagation

# Check port 80 is open (LE uses HTTP-01 challenge)
curl -v http://jarvis.yourdomain.com/

# Check Caddy logs
docker compose -f docker-compose.prod.yml logs caddy
```

### Agent stuck enrolling

```bash
# macOS
tail -50 /Library/Jarvis/logs/agent-stdout.log
tail -50 /Library/Jarvis/logs/agent-stderr.log

# Windows
Get-Content "C:\Program Files (x86)\Jarvis\logs\agent.log" -Tail 50

# Common causes:
# 1. Wrong enrollment token  → check docker compose logs manager
# 2. Clock skew > 5 minutes  → sync NTP on agent
# 3. TLS error               → if Option B, set tls_verify=false
# 4. Wrong URL               → test: curl https://jarvis.yourdomain.com/health
```

### Re-enroll an agent (key was rotated)

**macOS:**
```bash
# Delete keychain entry
security delete-generic-password -s com.jarvis.agent -a <agent_id>
# Restart agent — it will re-enroll automatically
sudo launchctl kickstart -k system/com.jarvis.agent
```

**Windows:**
```powershell
# Remove credential
cmdkey /delete:jarvis:<agent_id>
# Restart service
Restart-Service MacIntelAgent
```
