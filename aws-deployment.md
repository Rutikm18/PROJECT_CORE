# AWS Deployment Guide — AttackLens

Complete step-by-step guide to deploy AttackLens on AWS EC2 with CI/CD.

---

## Prerequisites

| Requirement | Details |
|---|---|
| AWS Account | Active account with billing enabled |
| EC2 Instance | `t3.medium` (2 vCPU, 4GB RAM) or larger recommended |
| EBS Volume | 30GB+ gp3 root volume |
| Domain (optional) | For Let's Encrypt TLS. IP-only mode works without one |
| GitHub Repo | Code pushed to a GitHub repository |
| IAM Permissions | EC2, ECR, SSM, IAM access for CI/CD |

---

## Phase 1: EC2 Instance Setup

### Step 1.1 — Launch EC2 Instance

1. Go to **AWS Console → EC2 → Launch Instance**
2. Configure:
   - **Name**: `attacklens-prod`
   - **AMI**: Ubuntu Server 24.04 LTS (ami-0c55b159cbfafe1f0 or latest)
   - **Instance type**: `t3.medium` (recommended) or `t3.small` (minimum)
   - **Key pair**: Create or select an existing key pair (`.pem` file)
   - **Storage**: 30GB gp3 EBS volume
   - **Network**: Default VPC, auto-assign public IP = **Yes**

3. Under **Advanced details → User data**, paste the contents of `ec2-userdata.sh` from this repo. This auto-installs Docker, Git, sets up swap, kernel tuning, and daily backups.

4. Click **Launch**

### Step 1.2 — Configure Security Group

Create or configure a security group with these inbound rules:

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 22 | TCP | Your IP only (e.g., `203.0.113.0/32`) | SSH access |
| 80 | TCP | `0.0.0.0/0` | HTTP redirect + Let's Encrypt ACME |
| 443 | TCP | `0.0.0.0/0` | HTTPS (if using domain) |
| 8443 | TCP | `0.0.0.0/0` | HTTPS self-signed (if IP-only) |

**Do NOT open**: 8080 (manager), 5432 (postgres), 5672 (rabbitmq) — these are internal only.

### Step 1.3 — SSH Into the Instance

```bash
chmod 400 your-key.pem
ssh -i your-key.pem ubuntu@<ec2-public-ip>
```

Verify the bootstrap completed:
```bash
cat /var/log/attacklens-bootstrap.log
```

You should see `=== Bootstrap complete ===` at the end.

If the bootstrap didn't run (no user data), install manually:
```bash
bash install.sh
```

---

## Phase 2: Application Deployment

### Step 2.1 — Clone the Repository

If `ec2-userdata.sh` didn't auto-clone:
```bash
cd ~
git clone https://github.com/<your-org>/attacklens.git
cd attacklens
```

For private repos, use a deploy key:
```bash
# On your local machine:
ssh-keygen -t ed25519 -f ~/.ssh/attacklens-deploy -N ""

# Add the public key to GitHub → Settings → Deploy Keys
# On EC2:
git clone git@github.com:<your-org>/attacklens.git
```

### Step 2.2 — Generate Configuration

```bash
cd ~/attacklens
bash env.sh
```

The wizard asks 3 questions:

1. **Public IP** — press Enter to accept auto-detected value
2. **Domain?** — type `n` for IP-only mode, `y` if you have a domain pointing to this IP
3. **Enrollment token?** — type `n` for open enrollment (simplest)

This generates:
- `.env` — all environment variables + auto-generated secrets
- `Caddyfile` — TLS reverse proxy config

### Step 2.3 — Start All Services

```bash
docker compose up -d
```

This starts 5 containers:
- `attacklens-postgres` — PostgreSQL 16 (manager + intel + threat_intel databases)
- `attacklens-rabbitmq` — RabbitMQ 3.13 (async ingest queue)
- `attacklens-caddy` — Caddy 2 (TLS reverse proxy)
- `attacklens-manager` — FastAPI application (detection engine + dashboard API)
- `attacklens-threat-intel` — Threat intelligence service (NVD/IOC feed sync)

### Step 2.4 — Verify Health

```bash
# Check all containers are running
docker compose ps

# Check manager health endpoint
curl http://localhost:8080/health

# Run the monitoring dashboard
./scripts/monitor.sh
```

### Step 2.5 — Access the Dashboard

Open in your browser:
- **IP-only mode**: `https://<ec2-public-ip>:8443` (accept self-signed cert warning)
- **Domain mode**: `https://your-domain.com`

Get the admin token:
```bash
grep ADMIN_TOKEN .env
```

---

## Phase 3: CI/CD Pipeline Setup

### Step 3.1 — Create ECR Repository

```bash
aws ecr create-repository \
  --repository-name attacklens \
  --region us-east-1 \
  --image-scanning-configuration scanOnPush=true
```

Note the repository URI: `<account-id>.dkr.ecr.us-east-1.amazonaws.com/attacklens`

### Step 3.2 — Create IAM User for CI/CD

1. Go to **AWS Console → IAM → Users → Create User**
2. Name: `attacklens-cicd`
3. Attach inline policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:PutImage",
        "ecr:ListImages",
        "ecr:DescribeImages",
        "ecr:BatchDeleteImage"
      ],
      "Resource": "*"
    }
  ]
}
```

4. Create access key → **Security credentials → Create access key**
5. Save the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

### Step 3.3 — Configure EC2 for ECR Access

Attach an IAM role to your EC2 instance:

1. **AWS Console → EC2 → Instances → Select your instance**
2. **Actions → Security → Modify IAM role**
3. Create a new role with `AmazonEC2ContainerRegistryReadOnly` policy
4. Attach the role to the instance

Verify on EC2:
```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com
```

### Step 3.4 — Set GitHub Secrets

Go to **GitHub → your repo → Settings → Secrets and variables → Actions → New repository secret**:

| Secret Name | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM user access key from Step 3.2 |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key from Step 3.2 |
| `AWS_ACCOUNT_ID` | Your 12-digit AWS account ID |
| `EC2_HOST` | EC2 public IP or DNS name |
| `EC2_USER` | `ubuntu` (default) |
| `EC2_SSH_KEY` | Full contents of your `.pem` file |

### Step 3.5 — Verify CI/CD Pipeline

The pipeline (`.github/workflows/deploy.yml`) runs on every push to `main`:

1. **Test** — runs unit tests
2. **Build** — builds Docker images for manager + threat-intel
3. **Push** — pushes to ECR with `latest` tag + commit SHA tag
4. **Deploy** — SSHes into EC2, pulls latest images, restarts containers
5. **Health check** — polls `/health` endpoint for 60s

Test it:
```bash
git push origin main
```

Watch the pipeline: **GitHub → Actions tab → Deploy to EC2**

---

## Phase 4: Domain & TLS Setup (Optional)

### Step 4.1 — Route DNS

1. **Route 53 → Hosted Zones → Create Record**
2. Type: `A` record
3. Name: `attacklens.yourdomain.com`
4. Value: your EC2 public IP
5. TTL: 300 seconds

Wait for DNS propagation:
```bash
dig attacklens.yourdomain.com
```

### Step 4.2 — Reconfigure for Domain Mode

On EC2:
```bash
cd ~/attacklens
bash env.sh
# When asked "Do you have a domain?" → type y
# Enter: attacklens.yourdomain.com
# Enter admin email: admin@yourdomain.com
```

Restart:
```bash
docker compose down
docker compose up -d
```

Caddy will automatically obtain a Let's Encrypt certificate on first request.

### Step 4.3 — Update Security Group

Change port `8443` rule to `443` (standard HTTPS). Remove the `8443` rule.

---

## Phase 5: Backup & Recovery

### Step 5.1 — Manual Backup

```bash
# Backup all databases + secrets
sudo ./scripts/backup.sh /backup/attacklens

# The backup creates:
#   /backup/attacklens/<timestamp>/manager.dump
#   /backup/attacklens/<timestamp>/intel.dump
#   /backup/attacklens/<timestamp>/threat_intel.dump
#   /backup/attacklens/<timestamp>/.secrets
```

### Step 5.2 — Automated Daily Backups

If you used `ec2-userdata.sh`, daily backups are already configured via cron.

Verify:
```bash
cat /etc/cron.daily/attacklens-backup
```

Backups run at midnight daily, retained for 30 days.

### Step 5.3 — S3 Backup (Recommended)

Create an S3 bucket:
```bash
aws s3 mb s3://attacklens-backups --region us-east-1
```

Add S3 permissions to the EC2 IAM role, then:
```bash
sudo ./scripts/backup.sh /backup/attacklens --s3-bucket attacklens-backups
```

### Step 5.4 — Restore from Backup

```bash
# Stop services
docker compose down

# Restore
sudo ./scripts/backup.sh /backup/attacklens/<timestamp> --restore

# Restart
docker compose up -d
```

---

## Phase 6: Monitoring & Maintenance

### Step 6.1 — Health Monitoring

```bash
# Full health report
./scripts/monitor.sh

# Live dashboard (refreshes every 5s)
./scripts/monitor.sh --watch

# Quick status check
./scripts/monitor.sh --quick
```

### Step 6.2 — View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f manager
docker compose logs -f postgres
docker compose logs -f caddy

# Last 100 lines
docker compose logs --tail=100 manager
```

### Step 6.3 — Restart Services

```bash
# Restart everything
docker compose restart

# Restart one service
docker compose restart manager

# Full rebuild (after code changes)
docker compose down
docker compose up -d --build
```

### Step 6.4 — Update to Latest Version

```bash
cd ~/attacklens
git pull
docker compose pull
docker compose up -d --remove-orphans
docker image prune -f
```

Or via CI/CD: just `git push main`.

---

## Phase 7: Scaling & High Availability

### Step 7.1 — HA Mode (2 Manager Replicas + Nginx LB)

For production with high availability:

```bash
docker compose -f docker-compose.ha.yml up -d
```

This starts:
- 2 manager replicas (active-active)
- Nginx load balancer with TLS termination
- Shared Postgres + RabbitMQ
- WebSocket sticky routing via `ip_hash`

### Step 7.2 — RDS Migration (Managed Postgres)

For higher reliability, move Postgres to RDS:

1. **AWS Console → RDS → Create database**
   - Engine: PostgreSQL 16
   - Instance: `db.t3.small`
   - Storage: 20GB gp3
   - Public access: No
   - VPC: Same as EC2
   - Security group: Allow 5432 from EC2's security group

2. Update `.env`:
```bash
# Replace the DATABASE_URL to point to RDS
DATABASE_URL=postgresql://attacklens:<password>@<rds-endpoint>:5432
```

3. Remove the postgres service from docker-compose:
```bash
# Create override file
cat > docker-compose.override.yml << 'EOF'
services:
  postgres:
    profiles: ["disabled"]
EOF
```

4. Restart:
```bash
docker compose down
docker compose up -d
```

### Step 7.3 — Auto Scaling Group

For auto-healing:

1. Create an AMI from your configured EC2 instance
2. **AWS Console → EC2 → Launch Templates → Create**
   - Use the AMI
   - User data: `ec2-userdata.sh`
   - IAM role: same as original
   - Security group: same as original
3. **Auto Scaling Groups → Create**
   - Min: 1, Max: 3, Desired: 1
   - Health check: ELB on port 8443
4. **Load Balancer → Application Load Balancer**
   - Listener: HTTPS 443 → target group port 8443
   - Health check path: `/health`

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker compose logs manager | tail -30

# Common issues:
# - Port already in use: sudo lsof -i :8080
# - .env missing: bash env.sh
# - Postgres not ready: docker compose logs postgres
```

### Health check fails

```bash
# Is the manager container running?
docker compose ps manager

# Is it listening on 8080?
curl -v http://localhost:8080/health

# Check if Postgres is ready
docker compose exec postgres pg_isready -U attacklens
```

### CI/CD pipeline fails

```bash
# Check ECR login from EC2
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com

# Check SSH access from GitHub Actions
ssh -i your-key.pem ubuntu@<ec2-ip> "echo OK"

# Check IAM permissions
aws sts get-caller-identity
```

### Disk full

```bash
# Check disk usage
df -h

# Clean Docker
docker system prune -af
sudo apt clean

# Check log sizes
sudo du -sh /var/lib/docker/containers/*/  | sort -rh | head -5
```

### OOM (Out of Memory)

```bash
# Check memory
free -h

# Check swap
swapon --show

# If no swap, create it:
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## Quick Reference

| Action | Command |
|---|---|
| One-click install | `bash install.sh` |
| Start | `docker compose up -d` |
| Stop | `docker compose down` |
| Restart | `docker compose restart` |
| Logs | `docker compose logs -f` |
| Status | `docker compose ps` |
| Health | `curl http://localhost:8080/health` |
| Monitor | `./scripts/monitor.sh` |
| Backup | `sudo ./scripts/backup.sh /backup` |
| Restore | `sudo ./scripts/backup.sh /backup/<ts> --restore` |
| Deploy manually | `./scripts/deploy.sh ubuntu@<ip>` |
| Update | `git pull && docker compose pull && docker compose up -d` |
