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
| Network | HTTPS outbound to manager on port 8443 (or 443) |
| Disk | ~50 MB for binaries, ~200 MB spool buffer |

---

## Method A — PKG Installer (Recommended)

### Step 1 — Download the PKG

Copy `macintel-agent-2.0.0-arm64.pkg` (or `x86_64`) to the target Mac.

### Step 2 — Install

```bash
sudo installer -pkg macintel-agent-2.0.0-arm64.pkg -target /
```

This installs to `/Library/Jarvis/` with the following layout:

```
/Library/Jarvis/
├── bin/
│   ├── macintel-agent      ← main agent binary
│   └── macintel-watchdog   ← watchdog binary
├── agent.toml              ← configuration file
├── logs/
│   ├── agent.log           ← rotating log (10 MB × 3)
│   └── agent-stderr.log    ← stderr capture
├── spool/                  ← offline payload buffer
└── security/               ← keychain reference (no raw key)

/Library/LaunchDaemons/
├── com.macintel.agent.plist
└── com.macintel.watchdog.plist
```

### Step 3 — Configure

```bash
sudo nano /Library/Jarvis/agent.toml
```

Minimum required configuration:
```toml
[agent]
name = "Alice MacBook Pro"      # human-readable name shown in dashboard

[manager]
url        = "https://54.213.44.12:8443"   # your manager URL
tls_verify = false                          # false for self-signed cert
                                            # true  for Let's Encrypt
```

If enrollment token is required by your manager:
```toml
[enrollment]
token = "sk-enroll-xxxxxxxx"
```

Everything else (agent ID, log paths, collection schedules) is auto-configured.

### Step 4 — Start

```bash
# Load and start both services
sudo launchctl load /Library/LaunchDaemons/com.macintel.agent.plist
sudo launchctl load /Library/LaunchDaemons/com.macintel.watchdog.plist
```

### Step 5 — Verify

```bash
# Check services are running
sudo launchctl list | grep macintel

# Expected output:
# <PID>  0  com.macintel.agent
# <PID>  0  com.macintel.watchdog

# Watch live logs
sudo tail -f /Library/Jarvis/logs/agent.log

# Look for successful enrollment:
# INFO enrollment complete agent_id=mac-xxxx key_len=64
# INFO [metrics] sent 1 payload(s)
```

Once enrolled, the agent appears in the manager dashboard within 30 seconds.

---

## Method B — Manual Install from Source

Use this when building from source or in CI/CD.

### Prerequisites

```bash
# macOS developer tools
xcode-select --install

# Python 3.11+ via Homebrew
brew install python@3.11

# Python dependencies
cd macbook_data/agent
pip3 install -r requirements.txt
```

### Build the PKG

```bash
cd agent/os/macos/pkg
bash build_pkg.sh -v 2.0.0 -a arm64
# Output: dist/macintel-agent-2.0.0-arm64.pkg
```

Then follow Method A Step 2 onwards.

---

## Configuration Reference

Full `agent.toml` with all available options:

```toml
# ── Agent identity ─────────────────────────────────────────────────────────
[agent]
# Human-readable name shown in the dashboard
name = "Alice MacBook Pro"

# Agent ID — auto-generated from Hardware UUID if omitted
# Format: mac-<hardware-uuid-lowercase>
# id = "mac-a1b2c3d4-..."   # leave blank; auto-detected

# ── Manager connection ──────────────────────────────────────────────────────
[manager]
url             = "https://YOUR_MANAGER_IP:8443"
tls_verify      = false        # false = accept self-signed cert
timeout_sec     = 30
retry_attempts  = 3
retry_delay_sec = 5
max_queue_size  = 500

# ── Enrollment ──────────────────────────────────────────────────────────────
[enrollment]
token    = ""          # leave blank if OPEN_ENROLLMENT=true on manager
keystore = "keychain"  # always "keychain" on macOS

# ── Watchdog ────────────────────────────────────────────────────────────────
[watchdog]
enabled            = true
check_interval_sec = 30
max_restarts       = 5
restart_window_sec = 300

# ── Collection (all intervals are optional — defaults shown) ────────────────
[collection]
enabled  = true
tick_sec = 5            # orchestrator polling interval

# Individual section overrides (omit section to use defaults)
[collection.sections.metrics]
enabled = true; interval_sec = 10; send = true

[collection.sections.processes]
enabled = true; interval_sec = 10; send = true

[collection.sections.connections]
enabled = true; interval_sec = 10; send = true

# ── Logging ─────────────────────────────────────────────────────────────────
[logging]
level   = "INFO"             # DEBUG / INFO / WARNING / ERROR
file    = "/Library/Jarvis/logs/agent.log"
max_mb  = 10
backups = 3
```

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

# Status
sudo launchctl list | grep macintel

# Live logs
sudo tail -f /Library/Jarvis/logs/agent.log

# Watchdog logs
sudo tail -f /Library/Jarvis/logs/watchdog.log
```

---

## Complete Uninstall

```bash
# 1. Stop and unload services
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist    2>/dev/null
sudo launchctl unload /Library/LaunchDaemons/com.macintel.watchdog.plist 2>/dev/null

# 2. Remove LaunchDaemon plists
sudo rm -f /Library/LaunchDaemons/com.macintel.agent.plist
sudo rm -f /Library/LaunchDaemons/com.macintel.watchdog.plist

# 3. Remove installation directory
sudo rm -rf /Library/Jarvis

# 4. Remove Keychain entry (stored HMAC key)
security delete-generic-password -s "com.macintel.agent" 2>/dev/null

echo "Agent uninstalled cleanly."
```

---

## Reinstall (after uninstall)

```bash
# Follow Method A from Step 1
sudo installer -pkg macintel-agent-2.0.0-arm64.pkg -target /
sudo nano /Library/Jarvis/agent.toml    # re-enter manager URL + name
sudo launchctl load /Library/LaunchDaemons/com.macintel.agent.plist
sudo launchctl load /Library/LaunchDaemons/com.macintel.watchdog.plist
```

On reinstall the agent automatically re-enrolls with the manager and
receives a fresh HMAC key. No manual key management needed.

---

## Upgrade

```bash
# Install new PKG over existing installation
sudo installer -pkg macintel-agent-2.1.0-arm64.pkg -target /

# Services restart automatically via watchdog
# Verify:
sudo tail -10 /Library/Jarvis/logs/agent.log
```

---

## Troubleshooting

### Agent not appearing in dashboard

```bash
# Check services loaded
sudo launchctl list | grep macintel

# Check logs for errors
sudo tail -50 /Library/Jarvis/logs/agent.log

# Common causes:
# 1. Wrong manager URL in agent.toml
# 2. tls_verify = true but manager using self-signed cert → set false
# 3. Firewall blocking port 8443
# 4. Wrong enrollment token
```

### "attempted relative import" error in logs

This means the binary was built with the wrong entry point.
Rebuild with `agent/agent_entry.py` as the PyInstaller entry point:
```bash
cd agent/os/macos/pkg && bash build_pkg.sh -v 2.0.0 -a arm64
```

### TOML parse error at startup

All collection section lines must be on separate lines (semicolons are invalid TOML):
```toml
# WRONG:
[collection.sections.metrics]
enabled = true; interval_sec = 10; send = true

# CORRECT:
[collection.sections.metrics]
enabled      = true
interval_sec = 10
send         = true
```

### "No such file or directory: /Library/Jarvis/logs/agent.log"

```bash
sudo mkdir -p /Library/Jarvis/logs /Library/Jarvis/spool /Library/Jarvis/security
sudo chown -R root:wheel /Library/Jarvis
sudo chmod 755 /Library/Jarvis
```

### Checking what key is stored in Keychain

```bash
security find-generic-password -s "com.macintel.agent" -w
# Should print 64-character hex string (the HMAC key)
```

### Re-enroll without uninstall

```bash
# Delete stored key (forces re-enrollment on next start)
security delete-generic-password -s "com.macintel.agent"

# Restart agent
sudo launchctl unload /Library/LaunchDaemons/com.macintel.agent.plist
sudo launchctl load   /Library/LaunchDaemons/com.macintel.agent.plist
```

---

## Security Notes

- The agent runs as **root** (required for hardware UUID, network stats, SIP status)
- The HMAC key is stored in the **system Keychain** — accessible only by root
- Raw key material is **never written to disk** outside the Keychain
- All traffic to manager is **HTTPS + HMAC-signed** (replay-protected)
- Spool files contain telemetry JSON — stored in `/Library/Jarvis/spool/` (root-only)
- Logs contain process names, connection destinations — no credentials or key material
