# AttackLens Agent — Quick Start Guide

**Version:** 2.0.0  
**Platform:** macOS 13+ (Ventura / Sonoma / Sequoia / Tahoe), arm64

---

## Install

```bash
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /
```

The installer automatically:
- Detects and patches the correct `python3` path
- Installs `psutil`, `cryptography`, `requests`, `tomli` if missing
- Writes a complete `agent.toml` with all 22 collection sections
- Starts `com.attacklens.agent` and `com.attacklens.watchdog` as LaunchDaemons

---

## First-time setup (if manager IP wasn't baked into the pkg)

```bash
sudo attacklens-service set-manager 34.224.174.38
```

This updates the manager URL in `agent.toml`, clears any stale API key, and restarts both services. The agent will auto-enroll with the manager on first contact and store the API key in the macOS System Keychain.

---

## Service management

| Command | Root? | Description |
|---------|-------|-------------|
| `attacklens-service status` | no | Service + config summary, recent log tail |
| `attacklens-service logs` | no | Follow live log (Ctrl+C to stop) |
| `attacklens-service config` | no | Print full `agent.toml` |
| `attacklens-service diagnose` | no | Connectivity + install health check |
| `attacklens-service version` | no | Version + Python info |
| `sudo attacklens-service start` | yes | Start agent + watchdog |
| `sudo attacklens-service stop` | yes | Stop agent + watchdog |
| `sudo attacklens-service restart` | yes | Stop then start |
| `sudo attacklens-service reload` | yes | Hot config reload (SIGHUP, no restart) |
| `sudo attacklens-service set-manager <IP>` | yes | Update manager URL, restart |
| `sudo attacklens-service enroll` | yes | Clear API key, force re-enrollment |
| `sudo attacklens-service update-config` | yes | Regenerate `agent.toml` |

**`attacklens`** is an alias for `attacklens-service` — both work.

---

## Paths

| Path | Contents |
|------|----------|
| `/Library/AttackLens/agent.toml` | Configuration (root:wheel, 644) |
| `/Library/AttackLens/logs/agent.log` | Structured log (rotating, 10 MB × 5) |
| `/Library/AttackLens/logs/agent-stderr.log` | Raw launchd stderr |
| `/Library/AttackLens/security/` | API key fallback (mode 700, normally empty — key lives in Keychain) |
| `/Library/AttackLens/spool/` | Offline send queue (NDJSON+gzip, auto-drains on reconnect) |
| `/Library/AttackLens/src/` | Bundled Python source |
| `/Library/AttackLens/bin/` | Bootstrap launchers + `generate_config.sh` |
| `/Library/LaunchDaemons/com.attacklens.agent.plist` | Agent LaunchDaemon |
| `/Library/LaunchDaemons/com.attacklens.watchdog.plist` | Watchdog LaunchDaemon |
| `/usr/local/bin/attacklens-service` | Service CLI |
| `/usr/local/bin/attacklens` | Alias → `attacklens-service` |

---

## Troubleshooting

### Services show "not loaded" or exit code 78 (macOS 15+ / Tahoe)

macOS 15 (Sequoia) and macOS 26 (Tahoe) require background service approval for third-party software.

**Fix:**
```bash
# Allow the service in Privacy & Security
open "x-apple.systempreferences:com.apple.preference.security?Privacy_BackgroundServices"
# Toggle ON the AttackLens entry, then:
sudo attacklens-service start
```

Or via Terminal only:
```bash
sudo launchctl enable system/com.attacklens.agent
sudo launchctl enable system/com.attacklens.watchdog
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.watchdog.plist
```

### Status shows `—` for Manager / Agent ID / Name

The `agent.toml` is unreadable by non-root. Fix once:
```bash
sudo chmod 644 /Library/AttackLens/agent.toml
```

### Manager URL is placeholder (`YOUR_MANAGER_IP`)

```bash
sudo attacklens-service set-manager 34.224.174.38
```

### Agent crash — check the actual error

```bash
sudo tail -50 /Library/AttackLens/logs/agent-stderr.log
sudo tail -50 /Library/AttackLens/logs/agent.log
```

### Missing Python dependencies

```bash
sudo /usr/local/bin/python3 -m pip install psutil cryptography requests
# For Python < 3.11:
sudo /usr/local/bin/python3 -m pip install tomli
```

### Re-enrollment (wrong manager, stale key)

```bash
sudo attacklens-service enroll
sudo attacklens-service restart
```

### Full reinstall from scratch

```bash
sudo launchctl bootout system/com.attacklens.agent    2>/dev/null
sudo launchctl bootout system/com.attacklens.watchdog 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.attacklens.agent.plist \
           /Library/LaunchDaemons/com.attacklens.watchdog.plist
sudo rm -rf /Library/AttackLens
sudo rm -f /usr/local/bin/attacklens-service /usr/local/bin/attacklens
sudo pkgutil --forget com.attacklens.agent 2>/dev/null
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /
```

---

## Security model

- **API key** auto-generated at first manager contact → stored in **macOS System Keychain** (`com.attacklens.agent`). Never written to `agent.toml`.
- **Transport**: AES-256-GCM payload encryption + HMAC-SHA256, over TLS 1.3 (or HTTP on port 8080 for trusted networks).
- **Key derivation**: HKDF-SHA256 from API key → `enc_key` + `mac_key`.
- **Replay protection**: ±300 s timestamp window + 96-bit nonce deduplication.
- **Offline resilience**: failed sends spooled to `/Library/AttackLens/spool/` as NDJSON+gzip, drained automatically on reconnect.

---

## Collected data — 22 sections

| Interval | Sections |
|----------|---------|
| 10 s | `metrics`, `connections`, `processes` |
| 30 s | `ports` |
| 2 min | `network`, `arp`, `mounts`, `battery`, `openfiles`, `services`, `users`, `hardware`, `containers` |
| 10 min | `storage`, `tasks` |
| 1 hr | `security`, `sysctl`, `configs` |
| 24 hr | `apps`, `packages`, `sbom` (`binaries` disabled by default) |
| 60 s | `agent_health` (internal heartbeat, always-on) |

All intervals and enabled/disabled state are configurable per-section in `agent.toml`.

---

*Built for AttackLens platform — managed endpoint telemetry for macOS.*
