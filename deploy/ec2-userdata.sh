#!/bin/bash
# =============================================================================
#  ec2-userdata.sh — EC2 bootstrap script for AttackLens
#
#  Paste this into EC2 User Data (or pass as --user-data) when launching the
#  instance. This automates the entire first-boot setup.
#
#  Prerequisites:
#    1. Attach an IAM instance role with access to the SSM parameter store
#       and ECR (if using CI/CD pipeline)
#    2. Add security group rules: SSH(22), HTTPS(443), Application(8443)
#    3. Use a 30GB+ gp3 EBS root volume
#
#  After boot:
#    SSH in, then:
#      cd /home/ubuntu/attacklens
#      sudo docker compose up -d
#
#  To restore from backup:
#      sudo ./scripts/backup.sh /tmp/backup/20250101T000000Z --restore
# =============================================================================
set -euo pipefail

exec > /var/log/attacklens-bootstrap.log 2>&1
echo "=== AttackLens bootstrap starting: $(date) ==="

# ── System packages ───────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y -qq \
  docker.io \
  docker-compose-plugin \
  git \
  curl \
  htop \
  jq \
  awscli \
  unattended-upgrades \
  fail2ban

# ── Docker ────────────────────────────────────────────────────────────────────
systemctl enable docker && systemctl start docker
usermod -aG docker ubuntu

# ── Swap (critical for t3.micro/nano — prevents OOM) ─────────────────────────
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  # Lower swappiness for better performance
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-swap.conf
  sysctl -p /etc/sysctl.d/99-swap.conf
fi

# ── Clone repo ────────────────────────────────────────────────────────────────
cd /home/ubuntu
if [ ! -d attacklens ]; then
  # Attempt to clone from GitHub (SSH key must be set up)
  if git clone git@github.com:your-org/attacklens.git 2>/dev/null; then
    echo "Repository cloned from GitHub"
  else
    echo "WARNING: GitHub clone failed — create /home/ubuntu/attacklens manually."
    echo "  git clone <repo-url> /home/ubuntu/attacklens"
    echo "  cd /home/ubuntu/attacklens && bash env.sh && docker compose up -d"
    mkdir -p attacklens
  fi
fi

chown -R ubuntu:ubuntu /home/ubuntu/attacklens

# ── Docker logging limits (prevents disk fill-up) ─────────────────────────────
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'DOCKER_JSON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
DOCKER_JSON
systemctl restart docker

# ──── Unattended upgrades ────────────────────────────────────────────────────
dpkg-reconfigure -f noninteractive unattended-upgrades

# ──── Fail2ban (basic SSH protection) ─────────────────────────────────────────
systemctl enable fail2ban && systemctl start fail2ban

# ──── Kernel tuning ───────────────────────────────────────────────────────────
cat >> /etc/sysctl.d/99-attacklens.conf << 'SYSCTL'
# AttackLens performance tuning

# Network — high-throughput connections
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535

# Connection tracking
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 86400

# Time-wait recycling
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# Ephemeral port range (for outbound connections)
net.ipv4.ip_local_port_range = 1024 65535

# File descriptors
fs.file-max = 2097152
SYSCTL
sysctl -p /etc/sysctl.d/99-attacklens.conf

# ── Set up daily backup cron ──────────────────────────────────────────────────
cat > /etc/cron.daily/attacklens-backup << 'CRON'
#!/bin/bash
BACKUP_DIR="/backup/attacklens"
mkdir -p "$BACKUP_DIR"
cd /home/ubuntu/attacklens
/home/ubuntu/attacklens/scripts/backup.sh "$BACKUP_DIR" backup 2>&1 | logger -t attacklens-backup
# Keep backups for 30 days
find "$BACKUP_DIR" -maxdepth 1 -type d -mtime +30 -exec rm -rf {} + 2>/dev/null
CRON
chmod +x /etc/cron.daily/attacklens-backup

echo "=== Bootstrap complete: $(date) ==="
echo "Next step: SSH in, cd ~/attacklens, run: bash env.sh && docker compose up -d"
