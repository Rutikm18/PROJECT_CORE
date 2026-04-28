# AttackLens Agent — Quick Start

**Version:** 2.0.0  
**Platform:** macOS 13+ (Ventura / Sonoma / Sequoia / Tahoe), arm64

---

## Install (3 commands)

```bash
# 1. Write env file with your manager IP
echo "ATTACKLENS_MANAGER='72.61.228.62'" > /tmp/attacklens_envs
echo "ATTACKLENS_AGENT_NAME='MyMac'"    >> /tmp/attacklens_envs

# 2. Install
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /

# 3. Start
sudo attacklens-service start
```

Check it's running:

```bash
attacklens-service status
```

---

## Service commands

| Command | Root? | Description |
|---------|-------|-------------|
| `attacklens-service status` | no | Service state, config summary |
| `attacklens-service logs` | no | Follow live log (Ctrl+C to stop) |
| `attacklens-service config` | no | Print full `agent.toml` |
| `attacklens-service diagnose` | no | Connectivity + install health check |
| `attacklens-service version` | no | Version + Python info |
| `sudo attacklens-service start` | yes | Start agent + watchdog |
| `sudo attacklens-service stop` | yes | Stop agent + watchdog |
| `sudo attacklens-service restart` | yes | Stop then start |
| `sudo attacklens-service reload` | yes | Hot config reload (no restart) |
| `sudo attacklens-service set-manager <IP>` | yes | Update manager URL, restart |
| `sudo attacklens-service enroll` | yes | Clear API key, force re-enrollment |
| `sudo attacklens-service update-config` | yes | Regenerate `agent.toml` |

`attacklens` is an alias for `attacklens-service` — both work.

---

## Paths

| Path | Contents |
|------|----------|
| `/Library/AttackLens/agent.toml` | Configuration (root:wheel, 644) |
| `/Library/AttackLens/logs/agent.log` | Structured log (rotating, 10 MB × 5) |
| `/Library/AttackLens/logs/agent-stderr.log` | Raw launchd stderr |
| `/Library/AttackLens/security/` | API key fallback (mode 700) |
| `/Library/AttackLens/spool/` | Offline send queue (NDJSON+gzip, auto-drains) |
| `/Library/AttackLens/src/` | Bundled Python source |
| `/Library/AttackLens/bin/` | Bootstrap launchers + `generate_config.sh` |
| `/Library/LaunchDaemons/com.attacklens.agent.plist` | Agent LaunchDaemon |
| `/Library/LaunchDaemons/com.attacklens.watchdog.plist` | Watchdog LaunchDaemon |
| `/usr/local/bin/attacklens-service` | Service CLI |
| `/usr/local/bin/attacklens` | Alias → `attacklens-service` |

---

## macOS 15+ / Tahoe — background service approval

If the agent shows exit code 78 after install, macOS needs to approve the daemon:

```bash
sudo launchctl enable system/com.attacklens.agent
sudo launchctl enable system/com.attacklens.watchdog
sudo attacklens-service start
```

Or via UI: **System Settings → Privacy & Security → Login Items & Extensions → toggle ON "AttackLens"**

---

## Troubleshooting

```bash
# Check logs
sudo tail -50 /Library/AttackLens/logs/agent.log
sudo tail -50 /Library/AttackLens/logs/agent-stderr.log

# Wrong manager URL?
sudo attacklens-service set-manager 72.61.228.62

# Re-enroll
sudo attacklens-service enroll && sudo attacklens-service restart

# Full reinstall
sudo launchctl bootout system/com.attacklens.agent 2>/dev/null || true
sudo launchctl bootout system/com.attacklens.watchdog 2>/dev/null || true
sudo rm -rf /Library/AttackLens /usr/local/bin/attacklens*
sudo pkgutil --forget com.attacklens.agent 2>/dev/null || true
sudo installer -pkg attacklens-agent-2.0.0-arm64.pkg -target /
sudo attacklens-service start
```

For detailed troubleshooting → see `agent-installation.md` or `AGENT_MANAGEMENT.md`.

---

## Collected data — 22 sections

| Interval | Sections |
|----------|---------|
| 10 s | `metrics`, `connections`, `processes` |
| 30 s | `ports` |
| 2 min | `network`, `arp`, `mounts`, `battery`, `openfiles`, `services`, `users`, `hardware`, `containers` |
| 10 min | `storage`, `tasks` |
| 1 hr | `security`, `sysctl`, `configs`, `apps`, `packages`, `sbom` |
| disabled | `binaries` (enable in `agent.toml`) |

---

## Security

- API key auto-generated at enrollment → stored in **macOS System Keychain** (`com.attacklens.agent`)
- AES-256-GCM + HMAC-SHA256 payload encryption, TLS 1.3 for HTTPS
- If manager unreachable at install: agent starts with temp key, auto-enrolls on 60 s retry when manager comes up

---

*Full guide: `agent-installation.md`*
