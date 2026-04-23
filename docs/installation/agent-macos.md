# macOS Agent Installation Guide

The mac_intel agent runs as a persistent LaunchDaemon, collecting 22 categories
of endpoint telemetry and shipping them to the manager over HTTPS.

---

## Requirements

| | Detail |
|-|--------|
| macOS | 12 Monterey or later (Intel + Apple Silicon) |
| Architecture | arm64 (Apple Silicon) or x86_64 (Intel) |
| Privileges | Administrator (sudo) required for install |
| Network | HTTPS outbound to manager on port 8443 (or 80/443) |
| Python | 3.11+ (only needed for source-based install) |
| Disk | ~50 MB for binaries, ~200 MB spool buffer |

---

## Method A — Installer Script (Recommended)

Pre-built binaries are included in the repo. The installer sets up LaunchDaemons,
directories, ACLs, and starts the agent automatically.

### Step 1 — Navigate to the installer

```bash
cd /path/to/macbook_data/agent/os/macos/installer
```

### Step 2 — Run the installer

**Self-signed cert manager (most common):**
```bash
sudo bash install.sh \
  --manager-url "https://<EC2_PUBLIC_IP>:8443" \
  --agent-name  "Alice MacBook Pro" \
  --tls-verify  false
```

**Let's Encrypt cert manager (domain mode):**
```bash
sudo bash install.sh \
  --manager-url "https://jarvis.company.com" \
  --agent-name  "Alice MacBook Pro" \
  --tls-verify  true
```

**With enrollment token (if manager requires it):**
```bash
sudo bash install.sh \
  --manager-url  "https://<EC2_PUBLIC_IP>:8443" \
  --agent-name   "Alice MacBook Pro" \
  --enroll-token "sk-enroll-xxxxxxxx" \
  --tls-verify   false
```

### What the installer does

1. Creates `/Library/Jarvis/` directory structure
2. Copies binaries with restricted ACLs (root:wheel only)
3. Derives stable agent ID from hardware UUID
4. Generates `agent.toml` with your settings
5. Installs `com.macintel.agent` + `com.macintel.watchdog` LaunchDaemons
6. Starts both services immediately

### Step 3 — Verify

```bash
# Check services running
sudo launchctl list | grep macintel

# Expected output:
# <PID>  0  com.macintel.agent
# <PID>  0  com.macintel.watchdog

# Watch live logs
sudo tail -f /Library/Jarvis/logs/agent-stdout.log

# Look for successful enrollment:
# INFO enrollment complete agent_id=mac-xxxx key_len=64
# INFO [metrics] sent 1 payload(s)
```

Once enrolled, the agent appears in the manager dashboard within 30 seconds.

---

## Method B — Run from Source (Dev / Testing)

No installation required. Runs the agent directly from Python in a temp directory.
Useful for testing without setting up system-wide LaunchDaemons.

### Prerequisites

```bash
# Python 3.11+
python3 --version

# Install agent dependencies
cd /path/to/macbook_data
pip3 install -r agent/requirements.txt
```

### Create working directory and config

```bash
mkdir -p /tmp/jarvis-dev/{data,security,spool,logs}

cat > /tmp/jarvis-dev/agent.toml << 'EOF'
[agent]
name = "Alice MacBook Pro"

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
```

### Run the agent

```bash
cd /path/to/macbook_data

# sudo required for hardware UUID + network interface stats
sudo python3 agent_v2.py --config /tmp/jarvis-dev/agent.toml
```

Press `Ctrl+C` to stop. The agent cleans up gracefully.

---

## Method C — PKG Installer

A pre-built PKG is included for quick deployment without any config flags.

### Step 1 — Install the PKG

```bash
sudo installer -pkg \
  /path/to/macbook_data/agent/os/macos/pkg/dist/macintel-agent-2.0.0-arm64.pkg \
  -target /
```

### Step 2 — Configure

```bash
sudo nano /Library/Jarvis/agent.toml
```

Set at minimum:
```toml
[agent]
name = "Alice MacBook Pro"

[manager]
url        = "https://<EC2_PUBLIC_IP>:8443"
tls_verify = false
```

### Step 3 — Start

```bash
sudo launchctl load /Library/LaunchDaemons/com.macintel.agent.plist
sudo launchctl load /Library/LaunchDaemons/com.macintel.watchdog.plist
```

---

## Installation Layout

```
/Library/Jarvis/
├── bin/
│   ├── macintel-agent        ← main agent binary
│   └── macintel-watchdog     ← watchdog binary
├── agent.toml                ← configuration file
├── logs/
│   ├── agent-stdout.log      ← main log output
│   ├── agent-stderr.log      ← errors
│   └── watchdog-stdout.log   ← watchdog log
├── data/                     ← telemetry queue
├── spool/                    ← offline payload buffer
└── security/                 ← Keychain reference (no raw key)

/Library/LaunchDaemons/
├── com.macintel.agent.plist
└── com.macintel.watchdog.plist
```

ACL policy:
- `security/` — root only (Keychain reference)
- `bin/*.exe` — root:wheel read+execute
- `agent.toml` — root:wheel read (rw-r-----)

---

## Service Management

```bash
# Start agent
sudo launchctl load /Library/LaunchDaemons/com.macintel.agent.plist

# Stop agent
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist

# Restart agent
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist
sudo launchctl load   /Library/LaunchDaemons/com.macintel.agent.plist

# Status (shows PID if running)
sudo launchctl list | grep macintel

# Live logs
sudo tail -f /Library/Jarvis/logs/agent-stdout.log

# Watchdog log
sudo tail -f /Library/Jarvis/logs/watchdog-stdout.log
```

---

## Complete Uninstall

```bash
# Run uninstall script
sudo bash /path/to/macbook_data/agent/os/macos/installer/uninstall.sh

# Or manually:
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist    2>/dev/null
sudo launchctl unload /Library/LaunchDaemons/com.macintel.watchdog.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.macintel.agent.plist
sudo rm -f /Library/LaunchDaemons/com.macintel.watchdog.plist
sudo rm -rf /Library/Jarvis
security delete-generic-password -s "com.macintel.agent" 2>/dev/null
echo "Agent uninstalled cleanly."
```

---

## Reinstall / Re-enroll

```bash
# Uninstall first
sudo bash uninstall.sh

# Reinstall
sudo bash install.sh \
  --manager-url "https://<EC2_PUBLIC_IP>:8443" \
  --agent-name  "Alice MacBook Pro" \
  --tls-verify  false
```

On reinstall, the agent auto re-enrolls and receives a fresh HMAC key.

---

## Configuration Reference

`/Library/Jarvis/agent.toml`

```toml
# ── Agent identity ─────────────────────────────────────────────────────────
[agent]
name = "Alice MacBook Pro"      # shown in dashboard
# id auto-generated from hardware UUID — format: mac-<uuid>

# ── Manager connection ──────────────────────────────────────────────────────
[manager]
url             = "https://YOUR_MANAGER_IP:8443"
tls_verify      = false        # false = self-signed cert (IP-only mode)
                                # true  = Let's Encrypt (domain mode)
timeout_sec     = 30
retry_attempts  = 3
retry_delay_sec = 5

# ── Enrollment ──────────────────────────────────────────────────────────────
[enrollment]
token    = ""          # leave blank if OPEN_ENROLLMENT=true on manager
keystore = "keychain"  # always "keychain" on macOS

# ── Logging ─────────────────────────────────────────────────────────────────
[logging]
level   = "INFO"
file    = "/Library/Jarvis/logs/agent.log"
max_mb  = 10
backups = 3
```

---

## Troubleshooting

### Agent not appearing in dashboard

```bash
# Check services loaded
sudo launchctl list | grep macintel

# Check logs
sudo tail -50 /Library/Jarvis/logs/agent-stdout.log

# Common causes:
# 1. Wrong manager URL in agent.toml
# 2. tls_verify = true but manager using self-signed cert → set false
# 3. Firewall blocking port 8443
# 4. Wrong enrollment token
```

### "url must start with https://" error

The agent requires HTTPS. Make sure your manager has port 8443 open
with Caddy TLS enabled, then use `https://` in the URL.

### "SSL certificate verify failed"

Set `tls_verify = false` in `agent.toml` if the manager uses a self-signed cert.

### Re-enroll without uninstall

```bash
# Delete stored key (forces re-enrollment on next start)
security delete-generic-password -s "com.macintel.agent"

# Restart agent
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist
sudo launchctl load   /Library/LaunchDaemons/com.macintel.agent.plist
```

### Check what key is stored in Keychain

```bash
security find-generic-password -s "com.macintel.agent" -w
# Should print 64-character hex string (the HMAC key)
```

---

## Security Notes

- The agent runs as **root** (required for hardware UUID, network stats, SIP status)
- The HMAC key is stored in the **system Keychain** — accessible only by root
- Raw key material is **never written to disk** outside the Keychain
- All traffic to manager is **HTTPS + HMAC-signed** (replay-protected with nonce)
- Spool files contain telemetry JSON stored in `/Library/Jarvis/spool/` (root-only)
