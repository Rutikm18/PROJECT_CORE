# macOS Agent — Change Log & Troubleshooting Reference

**Path:** `agent/os/macos/`  
**Last updated:** 2026-07-06

---

## Currently Running Agent

| Property | Value |
|---|---|
| **Mode** | Source (not the pkg binary) |
| **Process** | `python3 -m agent.agent.core --config agent.toml` |
| **PID** | 4123 (started 2026-05-25 12:14 PM) |
| **Python** | `/Library/Frameworks/Python.framework/Versions/3.13` |
| **Working dir** | `/Users/rutikmangale/Downloads/macbook_data/` |
| **Config file** | `/Users/rutikmangale/Downloads/macbook_data/agent.toml` |
| **Source entry** | `agent/agent/core.py` → `Orchestrator` + `Sender` |
| **Key file** | `agent/security/agent-001.key` |
| **Log file** | `agent/logs/agent.log` |
| **Spool file** | `agent/spool/unsent.ndjson` |

> **Note:** This is running from source, NOT from the installed pkg.  
> The built pkg (`attacklens-agent-1.1.0-arm64.pkg`) installs to  
> `/Library/AttackLens/bin/attacklens-agent` and uses `/Library/AttackLens/agent.toml`.  
> These are two separate agents — only the source one is currently active.

---

## Active Configuration

| Setting | Value | File |
|---|---|---|
| Manager URL | `http://127.0.0.1:8080` | `agent.toml` |
| TLS verify | `false` | `agent.toml` |
| Agent ID | `agent-001` | `agent.toml` |
| Keystore | `file` (`agent/security/agent-001.key`) | `agent.toml` |
| Spool dir | `agent/spool/unsent.ndjson` | `agent.toml` |
| Log file | `agent/logs/agent.log` | `agent.toml` |
| Binaries section | **enabled**, interval 86400s | `agent.toml` |

---

## Changes Made

### 2026-07-06 — Self-healing hardening (survive ANY config/plist/binary mismatch)

After the three install bugs below, every layer now defends itself — no single
stale config, wrong plist, or mismatched binary version can crash-loop the agent.

| Layer | File | Defense |
|---|---|---|
| Agent CLI | `agent/agent_entry.py` | Legacy invocation tolerance: `attacklens-agent --config X` (no subcommand) auto-maps to `run --config X`. Exit code 2 from a stale plist/watchdog is now impossible. |
| Watchdog | `agent/agent/watchdog.py` | **Fallback target resolution**: if the configured `[binaries] agent` path is missing, auto-switch to the first existing candidate (`attacklens-agent` → `run_agent.sh` → `run_agent.py`) instead of FATAL-looping. **Exit-2 self-adaptation**: if the agent exits 2 twice in a row, toggle the `run` subcommand form and retry — heals mixed-version installs automatically. |
| Service CLI | `pkg/attacklens-service` | New **`repair`** command (aliases `fix`, `heal`): one shot auto-fixes all known faults — stale `[binaries]` paths, plist missing `run`, missing wrapper/symlinks/exec bits, quarantine, stuck services. `diagnose` step 7 now scans for these faults and points at `repair`. |
| PKG installer | `pkg/build_pkg.sh` postinstall | On upgrade, migrates preserved configs (`run_agent.py` → native binary paths) and always ships the `run_agent.sh` compatibility wrapper. |

**One-command fix for any broken install:**
```bash
sudo attacklens-service repair
```

---

### 2026-07-06 — PKG v2.1.0 install bug fixes

Three bugs that caused the agent to crash-loop on every fresh v2.1.0 PKG install.
All are in source — the next PKG build (`build_pkg.sh`) will include all fixes.

---

#### Bug 1 — `generate_config.sh` wrong binary paths in `[binaries]`

**Symptom:** Watchdog log shows `FATAL: agent target not found at /Library/AttackLens/bin/run_agent.py`

**Root cause:** `installer/generate_config.sh` had the `[binaries]` section hardcoded
to `.py` entry-point paths from the old source-mode deployment:
```toml
[binaries]
agent    = "{install_dir}/bin/run_agent.py"    # ← doesn't exist in PKG install
watchdog = "{install_dir}/bin/run_watchdog.py" # ← doesn't exist in PKG install
```
The PKG ships native binaries named `attacklens-agent` and `attacklens-watchdog`.

**Fix** (`installer/generate_config.sh` line 147–148):
```toml
[binaries]
agent    = "{install_dir}/bin/attacklens-agent"
watchdog = "{install_dir}/bin/attacklens-watchdog"
```

**Live fix (already-installed Mac):**
```bash
sudo sed -i '' \
  's|/Library/AttackLens/bin/run_agent\.py|/Library/AttackLens/bin/run_agent.sh|g;
   s|/Library/AttackLens/bin/run_watchdog\.py|/Library/AttackLens/bin/attacklens-watchdog|g' \
  /Library/AttackLens/agent.toml
```

---

#### Bug 2 — `watchdog.py` `_build_cmd()` missing `run` subcommand

**Symptom:** Watchdog log shows `Agent exited with code 2` (argparse failure) in a crash loop.
`agent.log` is never created because the agent exits before opening it.

**Root cause:** `watchdog.py` `_build_cmd()` built the launch command for native
binaries as:
```
/Library/AttackLens/bin/attacklens-agent --config /Library/AttackLens/agent.toml
```
But `agent_entry.py` uses subcommand-based argparse — `--config` belongs to the
`run` subparser. Without `run`, argparse exits with code 2 on every launch.
The "default to run when no args" shortcut at line 65 of `agent_entry.py` only
fires when `len(sys.argv) == 1` (zero arguments), not when `--config` is present.

**Fix** (`agent/agent/watchdog.py` `_build_cmd()` line 174):
```python
# Before:
cmd = [self.agent_bin]

# After:
cmd = [self.agent_bin, "run"]  # native binary requires 'run' subcommand
```

**Live fix for already-installed Mac (wrapper script — no rebuild needed):**
```bash
# Create wrapper that inserts 'run' transparently
sudo tee /Library/AttackLens/bin/run_agent.sh > /dev/null << 'EOF'
#!/bin/bash
exec /Library/AttackLens/bin/attacklens-agent run "$@"
EOF
sudo chmod 755 /Library/AttackLens/bin/run_agent.sh

# Point agent.toml at the wrapper
sudo sed -i '' \
  's|/Library/AttackLens/bin/attacklens-agent"|/Library/AttackLens/bin/run_agent.sh"|g' \
  /Library/AttackLens/agent.toml
```

---

#### Bug 3 — `build_pkg.sh` agent plist missing `run` subcommand

**Symptom:** `com.attacklens.agent` LaunchDaemon (loaded directly by launchd, not
via watchdog) also exits with code 2 → KeepAlive restart loop, `agent.log` never created.

**Root cause:** The agent plist `ProgramArguments` array in `build_pkg.sh` had:
```xml
<string>/Library/AttackLens/bin/attacklens-agent</string>
<string>--config</string>
<string>/Library/AttackLens/agent.toml</string>
```
Same argparse failure as Bug 2 — no `run` subcommand.

**Fix** (`agent/os/macos/pkg/build_pkg.sh` plist section):
```xml
<string>/Library/AttackLens/bin/attacklens-agent</string>
<string>run</string>
<string>--config</string>
<string>/Library/AttackLens/agent.toml</string>
```

**Live fix for already-installed Mac:**
```bash
sudo python3 -c "
import plistlib
path = '/Library/LaunchDaemons/com.attacklens.agent.plist'
with open(path, 'rb') as f:
    p = plistlib.load(f)
args = p['ProgramArguments']
if 'run' not in args:
    args.insert(args.index('--config'), 'run')
with open(path, 'wb') as f:
    plistlib.dump(p, f)
print('Fixed:', args)
"
```

---

#### Full live-fix sequence (for already-installed v2.1.0 PKG)

Run these in order on any Mac that shows the crash-loop symptoms:

```bash
# 1. Fix agent.toml [binaries] paths and create run_agent.sh wrapper
sudo sed -i '' \
  's|/Library/AttackLens/bin/run_agent\.py|/Library/AttackLens/bin/run_agent.sh|g;
   s|/Library/AttackLens/bin/run_watchdog\.py|/Library/AttackLens/bin/attacklens-watchdog|g;
   s|/Library/AttackLens/bin/attacklens-agent"|/Library/AttackLens/bin/run_agent.sh"|g' \
  /Library/AttackLens/agent.toml

sudo tee /Library/AttackLens/bin/run_agent.sh > /dev/null << 'EOF'
#!/bin/bash
exec /Library/AttackLens/bin/attacklens-agent run "$@"
EOF
sudo chmod 755 /Library/AttackLens/bin/run_agent.sh

# 2. Patch the agent plist
sudo python3 -c "
import plistlib
path = '/Library/LaunchDaemons/com.attacklens.agent.plist'
with open(path, 'rb') as f: p = plistlib.load(f)
args = p['ProgramArguments']
if 'run' not in args: args.insert(args.index('--config'), 'run')
with open(path, 'wb') as f: plistlib.dump(p, f)
print('Agent plist fixed:', args)
"

# 3. Install attacklens-service CLI (if missing)
sudo cp agent/os/macos/pkg/attacklens-service /usr/local/bin/
sudo chmod 755 /usr/local/bin/attacklens-service

# 4. Restart both services
sudo launchctl bootout system/com.attacklens.watchdog 2>/dev/null || true
sudo launchctl bootout system/com.attacklens.agent    2>/dev/null || true
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.watchdog.plist

# 5. Verify
sleep 5
sudo launchctl list | grep attacklens   # both should have PIDs
sudo tail -20 /Library/AttackLens/logs/agent.log
```

---

### 2026-05-25 — Unified single binary (agent/build.sh)

**Goal:** One binary with all capabilities — no separate shell scripts, no
pkg installer pipeline, no `install.sh` / `generate_config.sh` dependencies.

**New files:**
- `agent/selfinstall.py` — pure Python cross-platform self-install. Handles
  macOS LaunchDaemon, Linux systemd, Windows Service registration, config
  generation, start/stop/status/reload/logs. No shell needed.
- `agent/agent_entry.py` (rewritten) — unified argparse CLI. Subcommands:
  `install`, `run`, `start`, `stop`, `status`, `reload`, `uninstall`, `logs`.
- `agent/build.sh` — single PyInstaller build script. Produces one binary
  (`agent/dist/attacklens-agent`) for the current platform.

**Build:**
```bash
cd /Users/rutikmangale/Downloads/macbook_data
bash agent/build.sh
```

**Install on any Mac (no pkg, no scripts):**
```bash
sudo agent/dist/attacklens-agent install --manager http://127.0.0.1:8080
```
- Writes `/Library/AttackLens/agent.toml` (hardware UUID → agent ID)
- Registers `com.attacklens.agent` LaunchDaemon (auto-start on boot)
- Symlinks to `/usr/local/bin/attacklens-agent`

**Daily commands:**
```bash
attacklens-agent status
attacklens-agent logs
sudo attacklens-agent stop
sudo attacklens-agent start
sudo attacklens-agent reload     # live config reload (SIGHUP)
sudo attacklens-agent uninstall
```

**Dev run (source, no install):**
```bash
PYTHONPATH=. python3 agent/agent_entry.py run --config agent.toml
# or after build:
agent/dist/attacklens-agent run --config agent.toml
```

---

### 2026-05-25 — Connectivity fix + binaries enabled

**Problem 1: No data reaching manager**
- Root cause: `agent.toml` had `url = "https://127.0.0.1:8443"` but the
  Caddyfile is configured with `auto_https off` and only listens on HTTP `:80`.
  Port 8443 in Docker has nothing answering TLS → TLS handshake reset on every
  attempt → 35,090 payloads (46 MB) accumulated in `agent/spool/unsent.ndjson`.
- Fix: Changed URL to `http://127.0.0.1:8080` (direct manager HTTP port).
- Cleared stale spool (old data from broken-connection period).
- Re-enrolled agent (old key cleared, fresh `agent-001.key` generated).

**Problem 2: Binaries section not sending**
- Root cause: `agent.toml` had `enabled = false` and `send = false` for
  `[collection.sections.binaries]` — disabled intentionally in the default config.
- Fix: Set both to `true`. Collector itself works (500 binaries found in test).
- Collector scans: `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`,
  `/Library/AttackLens/bin`, `/usr/sbin`, `/bin`, `/sbin` (max 500 files).
- Sends SHA-256 hash, size, permissions, SUID/SGID/world-writable flags.

**Error handling improvements (ingest.py + sender.py + core.py)**
- `ingest.py`: `store.write()` failure now returns HTTP 503 instead of HTTP 200
  — prevents silent permanent data loss (agent was treating 200 as "stored OK"
  and dropping payload from queue even when store write had failed).
- `ingest.py`: `db.insert_payload()` wrapped in try/except with clear log.
- `ingest.py`: `hub.broadcast()` failure now caught and logged at DEBUG (non-fatal).
- `sender.py`: HTTP error response body now logged alongside status code.
- `sender.py`: `ssl.SSLError`, `TimeoutError`, `OSError` split into distinct
  handlers with actionable messages.
- `sender.py`: HTTP 503 now explicitly handled (logs "will spool").
- `core.py`: Queue-full eviction logs the evicted section name and tells operator
  to check `max_queue_size` or network connectivity.

**Rebuilt arm64.pkg**
- Output: `agent/os/macos/pkg/dist/attacklens-agent-1.1.0-arm64.pkg` (21 MB)
- Manager URL baked in: `http://127.0.0.1:8080`
- Both binaries compiled for arm64 via PyInstaller 6.19.0 / Python 3.13.7
- Install: `sudo installer -pkg agent/os/macos/pkg/dist/attacklens-agent-1.1.0-arm64.pkg -target /`

---

## macOS Agent File Map

```
agent/os/macos/
├── collectors/
│   ├── base.py          — BaseCollector ABC, _run(), _run_json(), _sp_json()
│   │                      _get_env() extends PATH for LaunchDaemon context
│   │                      (adds /usr/local/bin, /opt/homebrew/bin)
│   ├── volatile.py      — metrics, connections, processes  (interval: 10s)
│   ├── network.py       — ports, network, arp, mounts      (interval: 30s–2min)
│   ├── system.py        — battery, openfiles, services,
│   │                      users, hardware, containers       (interval: 2min)
│   ├── posture.py       — security, sysctl, configs         (interval: 1hr)
│   └── inventory.py     — storage, tasks, apps, packages,
│                          binaries, sbom                    (interval: 10min–24hr)
├── normalizer.py        — maps raw collector output → canonical schema
├── keystore.py          — macOS Keychain read/write (security CLI)
├── launchd.py           — LaunchDaemon load/unload helpers
├── installer/           — install.sh, uninstall.sh, generate_config.sh
├── pkg/
│   ├── build_pkg.sh     — full PyInstaller → pkgbuild → productbuild pipeline
│   ├── entitlements.plist
│   ├── dist/            — built .pkg files
│   └── build/           — intermediate build artifacts (gitignored)
└── AGENT_CHANGES.md     — this file
```

---

## Section Reference

| Section | Collector | Interval | Notes |
|---|---|---|---|
| metrics | `MetricsCollector` | 10s | CPU, memory, disk I/O, net I/O |
| connections | `ConnectionsCollector` | 10s | Active TCP/UDP via psutil |
| processes | `ProcessesCollector` | 10s | Process list with hashes |
| ports | `PortsCollector` | 30s | Listening ports |
| network | `NetworkCollector` | 2min | Interface config, routing |
| arp | `ArpCollector` | 2min | ARP table |
| mounts | `MountsCollector` | 2min | Mounted volumes |
| battery | `BatteryCollector` | 2min | Charge, cycle count, health |
| openfiles | `OpenFilesCollector` | 2min | Open file handles per process |
| services | `ServicesCollector` | 2min | launchd service states |
| users | `UsersCollector` | 2min | Local user accounts |
| hardware | `HardwareCollector` | 2min | CPU, GPU, RAM, serial |
| containers | `ContainersCollector` | 2min | Docker/Podman containers |
| security | `SecurityCollector` | 1hr | SIP, Gatekeeper, FileVault, XProtect |
| sysctl | `SysctlCollector` | 1hr | Kernel security params |
| configs | `ConfigsCollector` | 1hr | SSH config, hosts file hashes |
| storage | `StorageCollector` | 10min | Disk volumes, usage |
| tasks | `TasksCollector` | 10min | crontab + launchd timers |
| apps | `AppsCollector` | 24hr | .app bundles, codesign status |
| packages | `PackagesCollector` | 24hr | brew, pip3, npm, gem, cargo |
| **binaries** | `BinariesCollector` | 24hr | **SHA-256 of executables in PATH dirs** |
| sbom | `SbomCollector` | 24hr | pip, brew, npm, gem with purls |

---

## Known Issues & Workarounds

### brew collector timeout (20s)
`brew info --installed --json=v2` times out on first run after macOS reboot
(brew daemon cold start). Warning in logs is expected and non-blocking.
Subsequent runs complete in <2s. No action needed.

### Binaries runs once per 24hr
The binaries section collects on startup then again every 86400s. To force
an immediate re-collect, send SIGHUP: `pkill -HUP -f agent.agent.core`

### HTTPS 8443 not working (Docker)
Caddy in this deployment uses `auto_https off` and only listens on HTTP `:80`.
Port 8443 in Docker has nothing serving TLS. Always use `http://....:8080` for
direct manager access in this environment. Do NOT use `https://....:8443`.

---

## Installation

### Option A — Run from source (dev, currently active)

No build step needed. Use this for local development and testing.

```bash
cd /Users/rutikmangale/Downloads/macbook_data

# 1. Install Python dependencies (once)
pip install -r agent/requirements.txt

# 2. Start agent
PYTHONPATH=. python3 -m agent.agent.core --config agent.toml

# 3. Verify it enrolled and is sending
tail -f agent/logs/agent.log
curl http://127.0.0.1:8080/api/v1/agents/agent-001
```

**Reload config without restarting** (e.g. after changing agent.toml):
```bash
pkill -HUP -f "agent.agent.core"
```

**Stop agent:**
```bash
pkill -f "agent.agent.core"
```

---

### Option B — Install arm64.pkg (production / other Macs)

Use this to deploy on any Apple Silicon Mac. The pkg installs a self-contained
binary to `/Library/AttackLens/` and registers a LaunchDaemon that auto-starts
on boot.

**Step 1 — Build the pkg** (run once, or after any code change):
```bash
cd /Users/rutikmangale/Downloads/macbook_data

# Dev build (manager on localhost)
VERSION=1.1.0 ARCH=arm64 \
  MANAGER_URL="http://127.0.0.1:8080" \
  TLS_VERIFY=false \
  bash agent/os/macos/pkg/build_pkg.sh

# Production build (bake in real manager URL)
VERSION=1.1.0 ARCH=arm64 \
  MANAGER_URL="https://your-manager.example.com" \
  TLS_VERIFY=true \
  bash agent/os/macos/pkg/build_pkg.sh
```

Output: `agent/os/macos/pkg/dist/attacklens-agent-1.1.0-arm64.pkg` (21 MB)

**Step 2 — Install the pkg:**
```bash
sudo installer -pkg agent/os/macos/pkg/dist/attacklens-agent-1.1.0-arm64.pkg -target /
```

What the installer does automatically:
- Copies binaries to `/Library/AttackLens/bin/`
- Generates `/Library/AttackLens/agent.toml` with hardware-derived agent ID
- Loads `com.attacklens.agent` and `com.attacklens.watchdog` LaunchDaemons
- Agent enrolls with manager on first run, stores key in macOS Keychain

**Step 3 — Verify:**
```bash
# Check service is running
launchctl list | grep attacklens

# Check logs
tail -f /Library/AttackLens/logs/agent.log

# Check manager sees it
curl http://127.0.0.1:8080/api/v1/agents
```

**Uninstall:**
```bash
sudo bash /Library/AttackLens/uninstall.sh
```

**MDM / Jamf / Mosyle silent deploy:**
Upload `attacklens-agent-1.1.0-arm64.pkg` directly — no pre/post scripts needed,
everything is handled inside the pkg.

---

### Key difference: source vs pkg

| | Source (Option A) | pkg (Option B) |
|---|---|---|
| Binary | `python3 -m agent.agent.core` | `/Library/AttackLens/bin/attacklens-agent` |
| Config | `macbook_data/agent.toml` | `/Library/AttackLens/agent.toml` |
| Key storage | `agent/security/agent-001.key` | macOS Keychain |
| Auto-start on boot | No | Yes (LaunchDaemon) |
| Watchdog | No | Yes |
| Use case | Dev / testing | Production / other Macs |

---

## Rebuild Commands

```bash
# Rebuild arm64.pkg (dev manager)
cd /Users/rutikmangale/Downloads/macbook_data
VERSION=1.1.0 ARCH=arm64 MANAGER_URL="http://127.0.0.1:8080" TLS_VERIFY=false \
  bash agent/os/macos/pkg/build_pkg.sh

# Rebuild arm64.pkg (production manager)
VERSION=1.1.0 ARCH=arm64 \
  MANAGER_URL="https://attacklens.example.com" \
  TLS_VERIFY=true \
  bash agent/os/macos/pkg/build_pkg.sh

# Install after build
sudo installer -pkg agent/os/macos/pkg/dist/attacklens-agent-1.1.0-arm64.pkg -target /

# Run from source (dev)
PYTHONPATH=. python3 -m agent.agent.core --config agent.toml
```

---

## Troubleshooting Playbook

### No data in manager dashboard
1. Check agent is running: `pgrep -la python | grep agent`
2. Check agent log: `tail -50 agent/logs/agent.log`
3. Confirm manager is up: `curl http://127.0.0.1:8080/health`
4. Verify URL in agent.toml matches working endpoint
5. Check spool: `wc -l agent/spool/unsent.ndjson` — large count = connectivity issue
6. Check manager received agent: `curl http://127.0.0.1:8080/api/v1/agents/agent-001`

### Specific section not appearing
1. Check `agent.toml` — is `enabled = true` and `send = true`?
2. Run collector manually:
   ```python
   python3 -c "
   import sys; sys.path.insert(0,'.')
   from agent.os.macos.collectors.inventory import BinariesCollector
   r = BinariesCollector().collect(); print(len(r), 'items')
   "
   ```
3. Check circuit breaker — if a collector fails 3× it opens for 60s:
   look for `circuit open` in logs for that section name.

### 401 errors / auth failures
- Agent key rejected by manager (key rotation, DB reset, or manager restart)
- Agent will auto-re-enroll after 3 consecutive 401s
- Manual fix: `rm agent/security/agent-001.key` then restart agent

### TLS/SSL errors
- Check `tls_verify` in agent.toml (set `false` for self-signed certs)
- If URL starts with `https://`, verify Caddy/nginx is running and TLS is configured
- In this Docker deployment, use `http://127.0.0.1:8080` (no TLS)

### Queue full / dropped items
- `max_queue_size = 500` in agent.toml (increase if needed)
- Queue fills when manager is unreachable; items spool to disk automatically
- After manager returns, spool is auto-drained on next `_SPOOL_RETRY_INTERVAL` (30s)

### Spool growing unboundedly
- Capped at `_SPOOL_MAX_BYTES = 50 MB` — oldest 10% trimmed when hit
- If spool is large: fix connectivity first, then spool auto-drains
- To clear manually (loses undelivered data): `> agent/spool/unsent.ndjson`
