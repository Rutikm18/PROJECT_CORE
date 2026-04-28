# AttackLens Agent — Management & Troubleshooting Guide

**Version:** 2.0.0 | **Platform:** macOS 13–26 (Ventura / Sonoma / Sequoia / Tahoe), arm64

---

## Table of Contents

1. [Installation](#1-installation)
2. [First-Time Setup](#2-first-time-setup)
3. [Service Management](#3-service-management)
4. [Configuration](#4-configuration)
5. [Rebuilding the Package](#5-rebuilding-the-package)
6. [Uninstall](#6-uninstall)
7. [Troubleshooting Reference](#7-troubleshooting-reference)

---

## 1. Installation

### Install from package

```bash
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /
```

The installer automatically:
- Detects the correct `python3` path and patches LaunchDaemon plists
- Installs Python dependencies: `psutil`, `cryptography`, `requests`, `tomli`
- Writes a complete `agent.toml` with all 22 collection sections
- Bootstraps `com.attacklens.agent` and `com.attacklens.watchdog` as LaunchDaemons in the **system domain**

### Verify installation

```bash
attacklens-service status
attacklens-service diagnose
```

---

## 2. First-Time Setup

### If manager IP was baked into the package

No action needed — the agent auto-enrolls on first contact.

### If manager IP needs to be set after install

```bash
sudo attacklens-service set-manager 34.224.174.38
```

This updates `agent.toml`, clears any stale API key, and restarts both services.
The agent will auto-enroll with the manager and store the API key in the macOS System Keychain.

### Confirm enrollment succeeded

```bash
sudo tail -20 /Library/AttackLens/logs/agent.log | grep -E "Enrollment|API key|running"
```

Expected output:
```
agent.enrollment INFO  Enrollment complete: agent_id=mac-xxxx  key never expires
agent INFO  API key ready (keystore backend=keychain, ...)
agent INFO  Agent running. tick=5s.
```

---

## 3. Service Management

### CLI reference

| Command | Requires Root | Description |
|---------|:---:|---------|
| `attacklens-service status` | no | Service state, config summary, recent log |
| `attacklens-service logs` | no | Follow live log (Ctrl+C to stop) |
| `attacklens-service config` | no | Print full `agent.toml` |
| `attacklens-service diagnose` | no | Network + install health check |
| `attacklens-service version` | no | Version + Python info |
| `sudo attacklens-service start` | yes | Start agent + watchdog |
| `sudo attacklens-service stop` | yes | Stop agent + watchdog |
| `sudo attacklens-service restart` | yes | Stop then start |
| `sudo attacklens-service reload` | yes | Hot config reload (SIGHUP, no restart) |
| `sudo attacklens-service set-manager <IP>` | yes | Update manager URL, clear key, restart |
| `sudo attacklens-service enroll` | yes | Clear API key, force re-enrollment |
| `sudo attacklens-service update-config` | yes | Regenerate `agent.toml` preserving identity |

`attacklens` is an alias for `attacklens-service` — both work identically.

### Start the agent

```bash
sudo attacklens-service start
```

### Stop the agent

```bash
sudo attacklens-service stop
```

### Restart the agent

```bash
sudo attacklens-service restart
```

### Check status

```bash
attacklens-service status
```

Expected healthy output:
```
  AttackLens Agent  v2.0.0
  Agent:    running  (PID 12345)
  Watchdog: running  (PID 12346)
  Manager:  http://34.224.174.38
  Name:     rutikmac1
  Enrollment: API key stored in Keychain
```

### Follow live logs

```bash
attacklens-service logs
```

### Force re-enrollment (new manager, stale key)

```bash
sudo attacklens-service enroll
sudo attacklens-service restart
```

---

## 4. Configuration

### Key paths

| Path | Description |
|------|-------------|
| `/Library/AttackLens/agent.toml` | Main config (root:wheel 644) |
| `/Library/AttackLens/logs/agent.log` | Rotating structured log (10 MB × 5) |
| `/Library/AttackLens/logs/agent-stderr.log` | Raw launchd stderr |
| `/Library/AttackLens/security/` | API key fallback (mode 700) |
| `/Library/AttackLens/spool/` | Offline send queue (auto-drains on reconnect) |
| `/Library/AttackLens/src/` | Bundled Python source |
| `/Library/AttackLens/bin/` | Bootstrap launchers + `generate_config.sh` |
| `/Library/LaunchDaemons/com.attacklens.agent.plist` | Agent LaunchDaemon |
| `/Library/LaunchDaemons/com.attacklens.watchdog.plist` | Watchdog LaunchDaemon |
| `/usr/local/bin/attacklens-service` | CLI tool |

### Update manager URL

```bash
sudo attacklens-service set-manager 34.224.174.38
# or with explicit port:
sudo attacklens-service set-manager http://34.224.174.38:8080
# or HTTPS:
sudo attacklens-service set-manager https://manager.example.com
```

### Edit config manually

```bash
sudo nano /Library/AttackLens/agent.toml
sudo attacklens-service reload    # hot reload — no restart needed
```

### Regenerate config (preserves agent ID and name)

```bash
sudo attacklens-service update-config
sudo attacklens-service restart
```

### Change collection intervals

Edit `/Library/AttackLens/agent.toml` under `[collection.sections.<name>]`:

```toml
[collection.sections.processes]
enabled      = true
interval_sec = 10     # collect every 10 seconds
send         = true
```

Then reload:
```bash
sudo attacklens-service reload
```

### View current config

```bash
attacklens-service config
```

---

## 5. Rebuilding the Package

Rebuild the `.pkg` whenever you change source code or configuration defaults.

### Build with baked-in manager IP

```bash
cd /path/to/repo/agent/os/macos/installer
bash build_pkg.sh 34.224.174.38
```

Output: `dist/attacklens-agent-2.0.0-arm64.pkg`

### Build with placeholder IP (set after install)

```bash
bash build_pkg.sh
```

### Install the new package

```bash
sudo installer -pkg dist/attacklens-agent-2.0.0-arm64.pkg -target /
```

The postinstall script stops any existing agent before installing, so upgrades are safe.

---

## 6. Uninstall

```bash
# Stop and unload services
sudo launchctl bootout system/com.attacklens.watchdog 2>/dev/null
sudo launchctl bootout system/com.attacklens.agent 2>/dev/null

# Remove files
sudo rm -f /Library/LaunchDaemons/com.attacklens.agent.plist \
           /Library/LaunchDaemons/com.attacklens.watchdog.plist
sudo rm -rf /Library/AttackLens
sudo rm -f /usr/local/bin/attacklens-service /usr/local/bin/attacklens

# Remove API key from Keychain
sudo security delete-generic-password -s "com.attacklens.agent" \
    /Library/Keychains/System.keychain 2>/dev/null

# Forget pkg receipt
sudo pkgutil --forget com.attacklens.agent 2>/dev/null

echo "Uninstall complete."
```

---

## 7. Troubleshooting Reference

### How to read exit codes

Run `attacklens-service status` and check the exit code:

| Exit Code | Meaning |
|-----------|---------|
| `running (PID XXXX)` | Agent is healthy |
| `stopped (last exit: 256)` | Python crashed — `sys.exit(1)`. Check `agent.log` |
| `stopped (last exit: 19968)` | Exit code 78 (`EX_CONFIG`) — see below |
| `not loaded` | LaunchDaemon not bootstrapped — run `sudo attacklens-service start` |

---

### Error: `stopped (last exit: 19968)` — Exit code 78

**Cause A: Service loaded in wrong domain (gui/ instead of system/)**

Symptom: `launchctl list com.attacklens.agent` (no sudo) shows it; `LimitLoadToSessionType = Aqua`

```bash
# Check which domain it's in
launchctl print system/com.attacklens.agent 2>&1 | head -3
launchctl print gui/$(id -u)/com.attacklens.agent 2>&1 | head -3
```

If output shows `gui/<uid>/...` — it's in the wrong domain.

Fix:
```bash
# Evict from wrong domain
sudo launchctl bootout gui/$(id -u)/com.attacklens.agent 2>/dev/null
sudo launchctl bootout gui/$(id -u)/com.attacklens.watchdog 2>/dev/null
# Load in correct domain
sudo attacklens-service start
```

**Cause B: macOS 15+ Sequoia / macOS 26 Tahoe background service approval**

Fix via command line:
```bash
sudo launchctl enable system/com.attacklens.agent
sudo launchctl enable system/com.attacklens.watchdog
sudo attacklens-service start
```

Fix via UI (if command line doesn't work):
```
System Settings → Privacy & Security → Login Items & Extensions
Toggle ON "AttackLens"
Then: sudo attacklens-service start
```

---

### Error: `stopped (last exit: 256)` — Python crashed

Check the log immediately:
```bash
sudo tail -30 /Library/AttackLens/logs/agent.log
sudo tail -30 /Library/AttackLens/logs/agent-stderr.log
```

**Cause A: `ModuleNotFoundError: No module named 'argparse'`**

The bootstrap launcher has `sys.path = [...]` (wipes stdlib) instead of `sys.path.insert(0, ...)`.

Fix:
```bash
sudo python3 -c "
with open('/Library/AttackLens/bin/run_agent.py','w') as f:
    f.write(\"import sys\nsys.path.insert(0,'/Library/AttackLens/src')\nfrom agent.agent_entry import main\nmain()\n\")
with open('/Library/AttackLens/bin/run_watchdog.py','w') as f:
    f.write(\"import sys\nsys.path.insert(0,'/Library/AttackLens/src')\nfrom agent.agent.watchdog import main\nmain()\n\")
print('Fixed')
"
sudo attacklens-service restart
```

**Cause B: `Enrollment failed: Manager enrollment request failed: timed out`**

The manager is unreachable at the configured URL.

```bash
# Check what URL is configured
attacklens-service config | grep url

# Test connectivity
curl -s --max-time 5 http://34.224.174.38/health

# Update if URL is wrong
sudo attacklens-service set-manager http://34.224.174.38
```

**Cause C: Missing Python dependencies**

```bash
sudo /usr/local/bin/python3 -m pip install psutil cryptography requests
# Python < 3.11 also needs:
sudo /usr/local/bin/python3 -m pip install tomli
sudo attacklens-service restart
```

---

### Error: `Manager URL is placeholder (YOUR_MANAGER_IP)`

```bash
sudo attacklens-service set-manager 34.224.174.38
```

---

### Error: `status` shows `—` for Manager / Agent ID / Name

`agent.toml` is not readable by non-root.

```bash
sudo chmod 644 /Library/AttackLens/agent.toml
```

---

### Full manual test (bypasses launchd — shows exact crash)

```bash
sudo /Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 \
    /Library/AttackLens/bin/run_agent.py \
    --config /Library/AttackLens/agent.toml
```

If it starts without errors, launchd is the issue (wrong domain or policy).
If it crashes, the traceback shows the exact Python error.

---

### Complete reinstall from scratch

```bash
# 1. Stop and remove everything
sudo launchctl bootout system/com.attacklens.watchdog 2>/dev/null
sudo launchctl bootout system/com.attacklens.agent 2>/dev/null
sudo launchctl bootout gui/$(id -u)/com.attacklens.agent 2>/dev/null
sudo launchctl bootout gui/$(id -u)/com.attacklens.watchdog 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.attacklens.agent.plist \
           /Library/LaunchDaemons/com.attacklens.watchdog.plist
sudo rm -rf /Library/AttackLens
sudo rm -f /usr/local/bin/attacklens-service /usr/local/bin/attacklens
sudo security delete-generic-password -s "com.attacklens.agent" \
    /Library/Keychains/System.keychain 2>/dev/null
sudo pkgutil --forget com.attacklens.agent 2>/dev/null

# 2. Reinstall
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /

# 3. Verify
attacklens-service status
attacklens-service diagnose
```

---

### Diagnostic checklist

Run `attacklens-service diagnose` for an automated check. Manual checks:

```bash
# 1. Is the service in the right domain?
launchctl print system/com.attacklens.agent 2>&1 | grep -E "state|program|pid"

# 2. Is python3 a real Mach-O binary?
file $(python3 -c "import os,sys; print(os.path.realpath(sys.executable))")

# 3. Can Python import the agent?
sudo python3 -c "
import sys; sys.path.insert(0,'/Library/AttackLens/src')
from agent.agent_entry import main; print('Import OK')
"

# 4. Is agent.toml valid TOML?
python3 -c "
import tomllib
with open('/Library/AttackLens/agent.toml','rb') as f: tomllib.load(f)
print('TOML valid')
"

# 5. Is the manager reachable?
curl -s --max-time 5 http://34.224.174.38/health

# 6. Is the API key in Keychain?
sudo security find-generic-password -s "com.attacklens.agent" \
    /Library/Keychains/System.keychain && echo "Key found" || echo "No key"

# 7. Last 20 log lines
sudo tail -20 /Library/AttackLens/logs/agent.log
```

---

*Built for AttackLens platform — managed endpoint telemetry for macOS.*
