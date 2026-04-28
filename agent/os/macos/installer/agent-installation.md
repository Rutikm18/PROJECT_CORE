# AttackLens Agent — Installation Guide

**Version:** 2.0.0  
**Platform:** macOS 13–26 (Ventura / Sonoma / Sequoia / Tahoe), arm64  
**Package:** `attacklens-agent-2.0.0-arm64.pkg`

---

## File Locations (Source / Build)

All installer-related files live under one directory:

```
/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/
```

| File | Full Path | Description |
|------|-----------|-------------|
| **Package (install this)** | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/dist/attacklens-agent-2.0.0-arm64.pkg` | Final `.pkg` — run with `sudo installer` |
| `build_pkg.sh` | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/build_pkg.sh` | Rebuilds the `.pkg` from source |
| `attacklens-service` | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/attacklens-service` | CLI service manager (bundled into pkg) |
| `generate_config.sh` | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/generate_config.sh` | Generates `agent.toml` (bundled into pkg) |
| `install.sh` | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/install.sh` | Legacy shell installer (not used) |
| `uninstall.sh` | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/uninstall.sh` | Shell uninstaller |
| `agent-installation.md` | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/agent-installation.md` | **This file** |
| `AGENT_MANAGEMENT.md` | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/AGENT_MANAGEMENT.md` | Day-2 ops & troubleshooting reference |
| `QUICKSTART.md` | `/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/QUICKSTART.md` | One-page cheat sheet |

### After install — files on the target Mac

| Path | Description |
|------|-------------|
| `/Library/AttackLens/agent.toml` | Main configuration |
| `/Library/AttackLens/logs/agent.log` | Rotating structured log (10 MB × 5) |
| `/Library/AttackLens/logs/agent-stderr.log` | Raw launchd stderr |
| `/Library/AttackLens/security/` | API key fallback (mode 700) |
| `/Library/AttackLens/spool/` | Offline send queue |
| `/Library/AttackLens/src/` | Bundled Python source |
| `/Library/AttackLens/bin/` | Bootstrap launchers + `generate_config.sh` |
| `/Library/LaunchDaemons/com.attacklens.agent.plist` | Agent LaunchDaemon |
| `/Library/LaunchDaemons/com.attacklens.watchdog.plist` | Watchdog LaunchDaemon |
| `/usr/local/bin/attacklens-service` | CLI tool |
| `/usr/local/bin/attacklens` | Alias → `attacklens-service` |

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Install](#2-install)
3. [Start & Verify](#3-start--verify)
4. [Enrollment](#4-enrollment)
5. [Service Management](#5-service-management)
6. [Configuration Reference](#6-configuration-reference)
7. [Upgrade](#7-upgrade)
8. [Uninstall](#8-uninstall)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| macOS | 13 (Ventura) | Tested through macOS 26 Tahoe |
| Architecture | arm64 (Apple Silicon) | Intel not supported by this package |
| Python | 3.11+ | Python.org installer recommended — Xcode CLT stub does not work |
| Disk space | ~50 MB | Includes source + logs |
| Network | TCP to manager | Port 80 (HTTP) or 443 (HTTPS) depending on your deployment |

### Verify Python is a real binary (not Xcode stub)

```bash
python3 -c "import os,sys; print(os.path.realpath(sys.executable))"
file "$(python3 -c 'import os,sys; print(os.path.realpath(sys.executable))')"
# Expected: Mach-O 64-bit executable arm64
```

If you see `Python is a command-line tool` or `/usr/bin/python3` — install Python from [python.org/downloads](https://python.org/downloads/).

---

## 2. Install

### Recommended: env file method

Write a small env file before running the installer. The postinstall script reads it, configures the agent, then deletes the file automatically.

**Step 1 — Write env file:**

```bash
echo "ATTACKLENS_MANAGER='72.61.228.62'" > /tmp/attacklens_envs
echo "ATTACKLENS_AGENT_NAME='MyMac'"    >> /tmp/attacklens_envs
```

Supported variables:

| Variable | Required | Example | Description |
|----------|:--------:|---------|-------------|
| `ATTACKLENS_MANAGER` | yes | `72.61.228.62` | Manager IP, `IP:PORT`, or full `http(s)://` URL. Bare IP defaults to `http://`. |
| `ATTACKLENS_AGENT_NAME` | no | `Rutik_arm64` | Human label shown in the dashboard (default: ComputerName) |
| `ATTACKLENS_TAGS` | no | `prod,security` | Comma-separated tags for grouping in the dashboard |
| `ATTACKLENS_TOKEN` | no | `sk-enroll-abc123` | Enrollment token — only required if the manager enforces token auth |

**Step 2 — Run the installer:**

```bash
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /
```

The installer automatically:
- Reads `/tmp/attacklens_envs` and applies all settings
- Finds the real Mach-O `python3` binary (resolves symlinks, validates magic bytes)
- Patches the LaunchDaemon plists to use that exact binary path
- Installs Python prerequisites: `psutil`, `cryptography`, `requests`, `tomli`
- Writes `/Library/AttackLens/agent.toml` with all 22 collection sections
- Registers `com.attacklens.agent` and `com.attacklens.watchdog` as system-domain LaunchDaemons
- Deletes `/tmp/attacklens_envs` (security cleanup)

**Step 3 — Start:**

```bash
sudo attacklens-service start
```

---

### Alternative: install first, configure after

```bash
# 1. Install (uses placeholder manager URL)
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /

# 2. Set manager (updates agent.toml, clears stale key, restarts)
sudo attacklens-service set-manager 72.61.228.62

# 3. Start
sudo attacklens-service start
```

---

## 3. Start & Verify

### Start the agent

```bash
sudo attacklens-service start
```

### Check status (no sudo required)

```bash
attacklens-service status
```

Expected healthy output:

```
  AttackLens Agent  v2.0.0
  ════════════════════════════════════════════════════
  Agent:         running  (PID 12345)
  Watchdog:      running  (PID 12346)
  ────────────────────────────────────────────────────
  Manager:       http://72.61.228.62
  Agent ID:      mac-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Name:          MyMac
  Install:       /Library/AttackLens
  Config:        /Library/AttackLens/agent.toml
  Python:        /Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13

  Enrollment: API key stored in Keychain
```

### Run connectivity check

```bash
attacklens-service diagnose
```

### Follow live logs

```bash
attacklens-service logs
# Ctrl+C to stop
```

---

## 4. Enrollment

Enrollment is fully automatic — no manual steps.

When the manager is reachable on first start:

1. Agent POSTs to `POST /api/v1/enroll` with the agent's hardware UUID and name
2. Manager returns an `api_key`
3. Agent stores the key in the **macOS System Keychain** under `com.attacklens.agent`

**If the manager is unreachable at install time** — the agent starts with a temporary key and retries enrollment every 60 seconds in the background. When the manager becomes available, enrollment completes automatically on the next retry. No restart is needed.

### Confirm enrollment succeeded

```bash
sudo tail -20 /Library/AttackLens/logs/agent.log | grep -E "Enrollment|API key|running"
```

Expected:

```
agent.enrollment INFO  Enrollment complete: agent_id=mac-xxxx  key never expires
agent INFO  API key ready (keystore backend=keychain, ...)
agent INFO  Agent running. tick=5s.
```

### Force re-enrollment (manager changed, stale key)

```bash
sudo attacklens-service enroll
sudo attacklens-service restart
```

Or change the manager and re-enroll in one step:

```bash
sudo attacklens-service set-manager 72.61.228.62
# This clears the old key and restarts automatically
```

---

## 5. Service Management

`attacklens` is an alias for `attacklens-service` — both work identically.

| Command | Root? | Description |
|---------|:-----:|-------------|
| `attacklens-service status` | no | Service state, config summary, Python path |
| `attacklens-service logs` | no | Follow live log (Ctrl+C to stop) |
| `attacklens-service config` | no | Print full `agent.toml` |
| `attacklens-service diagnose` | no | Network + install health check |
| `attacklens-service version` | no | Version + Python info |
| `sudo attacklens-service start` | yes | Start agent + watchdog |
| `sudo attacklens-service stop` | yes | Stop agent + watchdog |
| `sudo attacklens-service restart` | yes | Stop then start |
| `sudo attacklens-service reload` | yes | Hot config reload (SIGHUP — no restart) |
| `sudo attacklens-service set-manager <IP>` | yes | Update manager URL, clear key, restart |
| `sudo attacklens-service enroll` | yes | Clear API key, force re-enrollment |
| `sudo attacklens-service update-config` | yes | Regenerate `agent.toml` preserving agent ID + name |

---

## 6. Configuration Reference

### Key paths

| Path | Description |
|------|-------------|
| `/Library/AttackLens/agent.toml` | Main configuration (root:wheel, 644) |
| `/Library/AttackLens/logs/agent.log` | Rotating structured log (10 MB × 5 files) |
| `/Library/AttackLens/logs/agent-stderr.log` | Raw launchd stderr |
| `/Library/AttackLens/logs/agent-stdout.log` | Raw launchd stdout |
| `/Library/AttackLens/security/` | API key file fallback (mode 700) |
| `/Library/AttackLens/spool/` | Offline send queue — NDJSON+gzip, auto-drains on reconnect |
| `/Library/AttackLens/src/` | Bundled Python source |
| `/Library/AttackLens/bin/` | Bootstrap launchers + `generate_config.sh` |
| `/Library/LaunchDaemons/com.attacklens.agent.plist` | Agent LaunchDaemon |
| `/Library/LaunchDaemons/com.attacklens.watchdog.plist` | Watchdog LaunchDaemon |
| `/usr/local/bin/attacklens-service` | CLI tool |
| `/usr/local/bin/attacklens` | Alias → `attacklens-service` |

### Edit config

```bash
sudo nano /Library/AttackLens/agent.toml
sudo attacklens-service reload       # hot reload — no restart needed
```

### Regenerate config (preserves agent ID and name)

```bash
sudo attacklens-service update-config
sudo attacklens-service restart
```

### Collection sections and intervals

All 22 data collection sections are enabled by default. Intervals are configurable per section:

| Interval | Sections |
|----------|----------|
| 10 s | `metrics`, `connections`, `processes` |
| 30 s | `ports` |
| 2 min | `network`, `arp`, `mounts`, `battery`, `openfiles`, `services`, `users`, `hardware`, `containers` |
| 10 min | `storage`, `tasks` |
| 1 hr | `security`, `sysctl`, `configs`, `apps`, `packages`, `sbom` |
| disabled | `binaries` (off by default — can be enabled) |

To change an interval, edit `agent.toml`:

```toml
[collection.sections.processes]
enabled      = true
interval_sec = 30    # was 10
send         = true
```

Then reload:

```bash
sudo attacklens-service reload
```

---

## 7. Upgrade

Upgrading is the same as a fresh install — the postinstall script stops the existing agent before overwriting files.

```bash
# 1. Write env file (optional — keeps existing config if omitted)
echo "ATTACKLENS_MANAGER='72.61.228.62'" > /tmp/attacklens_envs

# 2. Install new package over existing
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /

# 3. Start
sudo attacklens-service start

# 4. Verify
attacklens-service status
```

The agent ID and API key are preserved across upgrades (ID comes from hardware UUID; key stays in Keychain).

---

## 8. Uninstall

```bash
# Stop and unload services
sudo launchctl bootout system/com.attacklens.watchdog 2>/dev/null || true
sudo launchctl bootout system/com.attacklens.agent    2>/dev/null || true

# Remove LaunchDaemon plists
sudo rm -f /Library/LaunchDaemons/com.attacklens.agent.plist \
           /Library/LaunchDaemons/com.attacklens.watchdog.plist

# Remove all agent files
sudo rm -rf /Library/AttackLens

# Remove CLI tools
sudo rm -f /usr/local/bin/attacklens-service /usr/local/bin/attacklens

# Remove API key from Keychain
sudo security delete-generic-password -s "com.attacklens.agent" \
    /Library/Keychains/System.keychain 2>/dev/null || true

# Forget pkg receipt
sudo pkgutil --forget com.attacklens.agent 2>/dev/null || true

echo "Uninstall complete."
```

---

## 9. Troubleshooting

### Quick diagnostic

```bash
attacklens-service diagnose
```

### Status shows `not loaded`

The LaunchDaemon isn't registered. Run:

```bash
sudo attacklens-service start
```

If it still shows `not loaded` after start, see **Exit code 78** below.

---

### Exit code 78 — `stopped (last exit: 19968)`

Exit code 78 (EX_CONFIG) means macOS rejected the LaunchDaemon. Two causes:

**Cause A: Service loaded in the wrong domain (`gui/` instead of `system/`)**

Symptom: `launchctl print gui/$(id -u)/com.attacklens.agent` succeeds (shows `Aqua` session type).

Fix:
```bash
sudo launchctl bootout gui/$(id -u)/com.attacklens.agent  2>/dev/null || true
sudo launchctl bootout gui/$(id -u)/com.attacklens.watchdog 2>/dev/null || true
sudo attacklens-service start
```

**Cause B: macOS 15+ Sequoia / macOS 26 Tahoe background service policy**

Fix via CLI:
```bash
sudo launchctl enable system/com.attacklens.agent
sudo launchctl enable system/com.attacklens.watchdog
sudo attacklens-service start
```

Fix via UI (if CLI doesn't work):
```
System Settings → Privacy & Security → Login Items & Extensions
Toggle ON "AttackLens"
Then: sudo attacklens-service start
```

---

### Exit code 256 — `stopped (last exit: 256)`

Python crashed (`sys.exit(1)`). Check logs:

```bash
sudo tail -40 /Library/AttackLens/logs/agent.log
sudo tail -40 /Library/AttackLens/logs/agent-stderr.log
```

**`ModuleNotFoundError: No module named 'argparse'` or similar stdlib error**

The bootstrap launcher has `sys.path = [...]` (overwrites stdlib). Fix:

```bash
sudo python3 -c "
with open('/Library/AttackLens/bin/run_agent.py','w') as f:
    f.write(\"import sys\nsys.path.insert(0,'/Library/AttackLens/src')\nfrom agent.agent_entry import main\nmain()\n\")
with open('/Library/AttackLens/bin/run_watchdog.py','w') as f:
    f.write(\"import sys\nsys.path.insert(0,'/Library/AttackLens/src')\nfrom agent.agent.watchdog import main\nmain()\n\")
"
sudo attacklens-service restart
```

**`Enrollment failed: timed out` — manager unreachable**

The agent now retries enrollment in the background, so this is no longer fatal. Verify the manager URL is correct:

```bash
attacklens-service config | grep url
curl -s --max-time 5 http://72.61.228.62/health
```

If wrong URL:
```bash
sudo attacklens-service set-manager 72.61.228.62
```

**Missing Python dependencies**

```bash
sudo /usr/local/bin/python3 -m pip install --upgrade psutil cryptography requests
# Python < 3.11 also needs:
sudo /usr/local/bin/python3 -m pip install --upgrade tomli
sudo attacklens-service restart
```

---

### Status shows `—` for Manager / Agent ID / Name

`agent.toml` is unreadable by non-root:

```bash
sudo chmod 644 /Library/AttackLens/agent.toml
```

---

### Manager URL still says `YOUR_MANAGER_IP`

No env file was present at install time. Set it now:

```bash
sudo attacklens-service set-manager 72.61.228.62
```

---

### Manual run (bypasses launchd — shows exact crash)

```bash
sudo /Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 \
    /Library/AttackLens/bin/run_agent.py \
    --config /Library/AttackLens/agent.toml
```

If it starts cleanly, launchd is the problem (wrong domain or policy).  
If it crashes, the traceback shows the exact Python error.

---

### Complete reinstall from scratch

```bash
# 1. Remove everything
sudo launchctl bootout system/com.attacklens.watchdog    2>/dev/null || true
sudo launchctl bootout system/com.attacklens.agent       2>/dev/null || true
sudo launchctl bootout gui/$(id -u)/com.attacklens.agent    2>/dev/null || true
sudo launchctl bootout gui/$(id -u)/com.attacklens.watchdog 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.attacklens.agent.plist \
           /Library/LaunchDaemons/com.attacklens.watchdog.plist
sudo rm -rf /Library/AttackLens
sudo rm -f /usr/local/bin/attacklens-service /usr/local/bin/attacklens
sudo security delete-generic-password -s "com.attacklens.agent" \
    /Library/Keychains/System.keychain 2>/dev/null || true
sudo pkgutil --forget com.attacklens.agent 2>/dev/null || true

# 2. Fresh install
echo "ATTACKLENS_MANAGER='72.61.228.62'" > /tmp/attacklens_envs
echo "ATTACKLENS_AGENT_NAME='MyMac'"    >> /tmp/attacklens_envs
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /
sudo attacklens-service start

# 3. Verify
attacklens-service status
attacklens-service diagnose
```

---

### Diagnostic checklist (manual)

```bash
# 1. Service domain and state
launchctl print system/com.attacklens.agent 2>&1 | grep -E "state|program|pid|domain"

# 2. Python binary is a real Mach-O (not Xcode stub)
file "$(python3 -c 'import os,sys; print(os.path.realpath(sys.executable))')"

# 3. Python can import the agent
sudo python3 -c "
import sys; sys.path.insert(0,'/Library/AttackLens/src')
from agent.agent_entry import main; print('Import OK')
"

# 4. TOML config is valid
python3 -c "
try:
    import tomllib
except ImportError:
    import tomli as tomllib
with open('/Library/AttackLens/agent.toml','rb') as f: tomllib.load(f)
print('TOML valid')
"

# 5. Manager is reachable
curl -s --max-time 5 http://72.61.228.62/health

# 6. API key exists in Keychain
sudo security find-generic-password -s "com.attacklens.agent" \
    /Library/Keychains/System.keychain && echo "Key found" || echo "No key — will enroll on next retry"

# 7. Last 20 log lines
sudo tail -20 /Library/AttackLens/logs/agent.log
```

---

## Security Model

- **API key** — auto-generated at enrollment → stored in **macOS System Keychain** (`com.attacklens.agent`). Never written to `agent.toml`.
- **Transport** — AES-256-GCM payload encryption + HMAC-SHA256. TLS 1.3 for HTTPS endpoints.
- **Key derivation** — HKDF-SHA256 from API key → separate `enc_key` + `mac_key`.
- **Replay protection** — ±300 s timestamp window + 96-bit nonce deduplication.
- **Offline queue** — failed sends spooled to `/Library/AttackLens/spool/` as NDJSON+gzip. Drains automatically when manager becomes reachable.
- **Permissions** — agent runs as `root`, config at 644, security dir at 700.

---

*AttackLens Agent v2.0.0 — managed endpoint telemetry for macOS arm64.*
