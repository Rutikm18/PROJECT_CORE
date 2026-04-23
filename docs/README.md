# mac_intel — SOC Intelligence Platform

A self-hosted endpoint telemetry and security operations platform.
Agents run on macOS and Windows, ship signed+encrypted telemetry to a central
manager, which correlates findings and provides a full SOC workflow dashboard.

---

## Quick Start

See [docs/installation/quick-start.md](installation/quick-start.md) for the full end-to-end guide.

### 1. Deploy Manager (AWS EC2)

```bash
git clone <repo> && cd macbook_data
bash env.sh          # interactive setup: generates .env + Caddyfile
docker compose up -d
```

### 2. Install Agent — macOS

```bash
# Using installer script (binaries pre-built in repo)
cd agent/os/macos/installer
sudo bash install.sh \
  --manager-url "https://<EC2_IP>:8443" \
  --agent-name  "My MacBook" \
  --tls-verify  false
```

### 3. Open Dashboard

```
http://<EC2_IP>         (HTTP, port 80)
https://<EC2_IP>:8443   (HTTPS, self-signed — accept cert warning)
```

Edit `/Library/Jarvis/agent.toml`:
```toml
[agent]
name = "Alice MacBook Pro"

[manager]
url        = "https://YOUR_SERVER_IP:8443"
tls_verify = false   # true if domain + Let's Encrypt
```

Start:
```bash
sudo launchctl load /Library/LaunchDaemons/com.macintel.agent.plist
```

### 3. Install Agent — Windows (Admin PowerShell)

```powershell
.\install.ps1 -ManagerUrl "https://YOUR_SERVER_IP:8443" -TlsVerify $false
```

---

## Architecture Overview

```
  macOS Agent          Windows Agent
      │                     │
      │  HTTPS + HMAC-SHA256 │
      └──────────┬───────────┘
                 │
          ┌──────▼──────┐
          │    Caddy     │  TLS termination (self-signed or Let's Encrypt)
          │  (port 8443) │
          └──────┬──────┘
                 │  plain HTTP
          ┌──────▼──────────────────────────┐
          │       Manager (FastAPI)          │
          │                                  │
          │  ┌──────────┐  ┌─────────────┐  │
          │  │  Ingest  │  │  SOC API    │  │
          │  │  Pipeline│  │  /api/v1/soc│  │
          │  └────┬─────┘  └──────┬──────┘  │
          │       │               │          │
          │  ┌────▼───────────────▼──────┐  │
          │  │      Jarvis Engine        │  │
          │  │  Correlation · Detection  │  │
          │  │  Behavioral · CVE Lookup  │  │
          │  └────────────┬─────────────┘  │
          │               │                 │
          │  ┌────────────▼─────────────┐  │
          │  │   Intel DB (SQLite WAL)   │  │
          │  │  findings · soc_activity  │  │
          │  │  soc_comments · timeline  │  │
          │  └──────────────────────────┘  │
          └──────────────────────────────────┘
```

---

## Module Index

| Module | Location | Purpose |
|--------|----------|---------|
| Manager | `manager/` | FastAPI server, APIs, Jarvis engine |
| Agent Core | `agent/agent/` | Collection orchestrator, sender, enrollment |
| macOS Collectors | `agent/os/macos/collectors/` | Platform-specific data collection |
| Windows Collectors | `agent/os/windows/collectors/` | Windows telemetry |
| Jarvis Engine | `manager/manager/jarvis/` | Correlation, detection, behavioral analysis |
| SOC API | `manager/manager/api/findings.py` | Full finding lifecycle API |
| Dashboard | `manager/dashboard/` | SOC UI (HTML/CSS/JS) |
| Deployment | `docker-compose.yml`, `env.sh` | One-command deployment |

---

## Detailed Documentation

- [Architecture](architecture.md) — Full system design
- [Manager Installation](installation/manager.md) — Docker deployment guide
- [macOS Agent Installation](installation/agent-macos.md) — macOS setup guide
- [Windows Agent Installation](installation/agent-windows.md) — Windows setup guide
