# Quick Start Guide — End-to-End Setup

Get the full mac_intel stack running in under 10 minutes.

```
Mac (Agent) ──HTTPS──▶ EC2 (Manager + Caddy) ──▶ Dashboard
```

---

## Prerequisites

| Component | Where | Status |
|-----------|-------|--------|
| Manager   | EC2 (Ubuntu) | Docker Compose |
| macOS Agent | Your Mac | Python or PKG |
| Dashboard  | Browser | `http://<EC2_IP>` |

---

## Part 1 — Fix HTTPS on the Manager (EC2)

The macOS agent requires HTTPS. Run these commands **on your EC2 server**.

### 1a. SSH into EC2

```bash
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
```

### 1b. Fix the Caddyfile for HTTPS on port 8443

```bash
cd ~/jarvis

# Stop everything
docker compose down

# Write the correct Caddyfile
python3 - << 'PYEOF'
content = """{
    local_certs
}

:8443 {
    tls internal

    reverse_proxy jarvis-manager:8080 {
        header_up X-Real-IP {remote_host}
    }

    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        -Server
    }

    log {
        output stdout
        format json
    }
}
"""
with open("Caddyfile", "w") as f:
    f.write(content)
print("Caddyfile written:")
print(open("Caddyfile").read())
PYEOF
```

### 1c. Ensure .env has BIND_PORT=8443

```bash
grep BIND_PORT .env   # should show BIND_PORT=8443
# If not:
sed -i 's/^BIND_PORT=.*/BIND_PORT=8443/' .env
```

### 1d. Wipe stale Caddy volumes and restart

```bash
docker volume rm jarvis_caddy_data jarvis_caddy_config 2>/dev/null || true
docker compose up -d
sleep 20

# Verify HTTPS is working
curl -sk https://localhost:8443/health
# Expected: {"status":"ok","db":"ok",...}
```

### 1e. Open port 8443 in Security Group (if not already open)

```
AWS Console → EC2 → Security Groups → Inbound Rules → Add Rule
Type: Custom TCP | Port: 8443 | Source: 0.0.0.0/0
```

### 1f. Test from your Mac

```bash
curl -sk https://<EC2_PUBLIC_IP>:8443/health
# Expected: {"status":"ok",...}
```

---

## Part 2 — Install macOS Agent (Your Mac)

### Method A — Using Installer Script (Recommended)

The agent binaries are pre-built. Just run the installer.

```bash
cd /Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer

# Install with your EC2 manager URL
sudo bash install.sh \
  --manager-url  "https://<EC2_PUBLIC_IP>:8443" \
  --agent-name   "Rutik MacBook Air" \
  --tls-verify   false
```

> `--tls-verify false` is required because the manager uses a self-signed cert.

**Verify installation:**

```bash
# Check services running
sudo launchctl list | grep macintel

# Watch live logs
sudo tail -f /Library/Jarvis/logs/agent-stdout.log
```

Look for:
```
INFO enrollment complete agent_id=mac-xxxx key_len=64
INFO [metrics] sent 1 payload(s)
```

### Method B — Run from Source (No Installation, Dev Mode)

Useful for testing without installing system-wide services.

```bash
cd /Users/rutikmangale/Downloads/macbook_data

# Install Python dependencies
pip3 install -r agent/requirements.txt

# Create working directories
mkdir -p /tmp/jarvis-dev/{data,security,spool,logs}

# Write a minimal config
cat > /tmp/jarvis-dev/agent.toml << 'EOF'
[agent]
name = "Rutik MacBook Air Dev"

[manager]
url        = "https://<EC2_PUBLIC_IP>:8443"
tls_verify = false

[enrollment]
token    = ""
keystore = "keychain"

[paths]
install_dir  = "/tmp/jarvis-dev"
config_dir   = "/tmp/jarvis-dev"
log_dir      = "/tmp/jarvis-dev/logs"
data_dir     = "/tmp/jarvis-dev/data"
security_dir = "/tmp/jarvis-dev/security"
spool_dir    = "/tmp/jarvis-dev/spool"
pid_file     = "/tmp/jarvis-dev/agent.pid"

[logging]
level   = "INFO"
file    = "/tmp/jarvis-dev/logs/agent.log"
max_mb  = 10
backups = 3
EOF

# Run the agent (sudo needed for hardware UUID + network stats)
sudo python3 agent_v2.py --config /tmp/jarvis-dev/agent.toml
```

---

## Part 3 — Verify Agent Appears in Dashboard

1. Open `http://<EC2_PUBLIC_IP>` in your browser
2. Go to **Agents** panel in the sidebar
3. Your Mac should appear within 30 seconds of the agent starting

---

## Uninstall Agent (when needed)

```bash
sudo bash /Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/uninstall.sh
```

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| `url must start with https://` | Config has `http://` | Change to `https://` |
| `connection refused` | Port 8443 not open in Security Group | Add inbound rule TCP 8443 |
| `SSL certificate verify failed` | `tls_verify = true` with self-signed cert | Set `tls_verify = false` |
| `Invalid enrollment token` | Manager in token mode | Set `OPEN_ENROLLMENT=true` on manager |
| Agent not in dashboard after 60s | Enrollment failed | Check logs: `sudo tail -50 /Library/Jarvis/logs/agent-stdout.log` |
