# mac_intel — macOS System Intelligence Platform

A two-component security telemetry platform for collecting deep macOS system data and visualising it in real-time on a remote dashboard — encrypted end-to-end over any network.

```
┌─────────────────────────┐     HTTPS / TLS 1.3      ┌─────────────────────────┐
│      macOS Machine      │  ──────────────────────▶  │     Manager Server      │
│                         │   AES-256-GCM payload     │                         │
│  agent/agent/core.py    │   HMAC-SHA256 signed      │  FastAPI + WebSocket    │
│  22 section collectors  │   gzip compressed         │  SQLite storage         │
│  agent.toml config      │                           │  Live dashboard         │
└─────────────────────────┘                           └─────────────────────────┘
                                                                 │
                                                                 ▼
                                                      https://SERVER:8443
```

---

## Table of Contents

- [Project Structure](#project-structure)
- [Quick Start — Run Locally](#quick-start--run-locally)
- [Quick Start — Run in Docker](#quick-start--run-in-docker)
- [Run the Agent](#run-the-agent)
- [Configuration Reference](#configuration-reference)
- [Collected Sections](#collected-sections)
- [Manager API](#manager-api)
- [Security Design](#security-design)
- [Developer Commands](#developer-commands)
- [Adding a New Collector](#adding-a-new-collector)
- [Troubleshooting](#troubleshooting)
- [Wire Format](#wire-format)

---

## Project Structure

```
macbook_data/
│
├── agent/                          ← macOS data collection component
│   └── agent/
│       ├── core.py                 ← orchestrator: schedules collectors, encrypts, sends
│       ├── sender.py               ← TLS 1.3 HTTPS sender with retry + backoff
│       ├── crypto.py               ← AES-256-GCM + HKDF + HMAC-SHA256
│       ├── config.py               ← validated config dataclasses (fail-fast)
│       └── collectors/             ← 22 modular collectors split by category
│           ├── __init__.py         ← COLLECTORS registry — add new ones here
│           ├── base.py             ← BaseCollector ABC + _run() helper
│           ├── volatile.py         ← metrics, connections, processes        (10 s)
│           ├── network.py          ← ports, network, arp, mounts            (30 s – 2 min)
│           ├── system.py           ← battery, openfiles, services,
│           │                          users, hardware, containers            (2 min)
│           ├── posture.py          ← security, sysctl, configs              (1 hr)
│           └── inventory.py        ← storage, tasks, apps, packages,
│                                      binaries, sbom                        (10 min – 24 hr)
│
├── manager/                        ← server component
│   ├── manager/
│   │   ├── server.py               ← FastAPI app factory
│   │   ├── auth.py                 ← 5-step verification pipeline
│   │   ├── db.py                   ← async SQLite (aiosqlite) storage
│   │   ├── ws_hub.py               ← WebSocket broadcast hub
│   │   ├── crypto.py               ← AES-256-GCM + HKDF + HMAC-SHA256
│   │   ├── config.py               ← env-var config with validation
│   │   ├── models.py               ← Pydantic response models
│   │   └── api/
│   │       ├── ingest.py           ← POST /api/v1/ingest router
│   │       └── agents.py           ← GET  /api/v1/agents/* router
│   ├── dashboard/
│   │   ├── templates/index.html    ← single-page live dashboard
│   │   └── static/                 ← CSS + JS (Chart.js, WebSocket client)
│   └── Dockerfile
│
├── shared/                         ← shared definitions (agent + manager)
│   ├── sections.py                 ← canonical list of all 22 section names
│   └── wire.py                     ← wire protocol constants + field names
│
├── tests/                          ← full test suite
│   ├── conftest.py                 ← shared fixtures
│   ├── unit/
│   │   ├── test_crypto.py          ← key derivation, encrypt/decrypt, tamper detection
│   │   ├── test_auth.py            ← replay prevention, timestamp window, HMAC
│   │   └── test_collectors.py      ← registry integrity, _run() safety, mocking
│   └── integration/
│       └── test_ingest.py          ← full HTTP pipeline with temp DB
│
├── .github/workflows/
│   ├── ci.yml                      ← tests + lint + security scan on every push
│   └── security.yml                ← weekly CVE scan (Monday 06:00 UTC)
│
├── agent.toml.example              ← copy to agent.toml and fill in key + URL
├── agent.toml                      ← your config (gitignored — contains API key)
├── docker-compose.yml              ← run manager in Docker
├── Makefile                        ← developer shortcuts
├── pyproject.toml                  ← ruff + mypy + pytest config
├── .env.example                    ← manager environment variable template
├── SECURITY.md                     ← threat model + hardening checklist
├── certs/                          ← TLS certificates (gitignored)
├── logs/                           ← log files (gitignored)
└── output/                         ← saved report snapshots (gitignored)
```

---

## Quick Start — Run Locally

### Prerequisites

- Python 3.11+
- macOS (for the agent)
- TLS certs already in `certs/` (self-signed certs are included for dev)

### Step 1 — Install dependencies

```bash
cd /path/to/macbook_data

pip3 install -r agent/requirements.txt
pip3 install -r manager/requirements.txt
```

### Step 2 — Generate an API key

```bash
python3 manager/scripts/keygen.py
```

Copy the printed `API Key` value — you need it in steps 3 and 4.

### Step 3 — Configure the agent

```bash
cp agent.toml.example agent.toml
```

Edit `agent.toml` and set:

```toml
[agent]
id   = "my-macbook"        # unique slug for this machine
name = "Rutik's MacBook"

[manager]
url        = "https://127.0.0.1:8443"
api_key    = "PASTE_YOUR_KEY_HERE"
tls_verify = false          # false for self-signed cert in dev
```

### Step 4 — Start the manager (Terminal 1)

```bash
cd /path/to/macbook_data

API_KEY="PASTE_YOUR_KEY_HERE" PYTHONPATH=. python3 -m uvicorn manager.manager.server:app \
  --host 0.0.0.0 \
  --port 8443 \
  --ssl-certfile certs/server.crt \
  --ssl-keyfile  certs/server.key \
  --log-level info
```

Wait for:
```
INFO:  Application startup complete.
INFO:  Uvicorn running on https://0.0.0.0:8443
```

### Step 5 — Start the agent (Terminal 2)

```bash
cd /path/to/macbook_data

PYTHONPATH=. python3 -m agent.agent.core --config agent.toml
```

You should see:
```
INFO agent  Starting mac_intel agent id=my-macbook
INFO agent  Crypto keys derived
INFO agent  Agent running. tick=5s.
INFO agent.sender  Sent metrics → 200
INFO agent.sender  Sent connections → 200
```

### Step 6 — Open the dashboard

```
https://localhost:8443
```

Click **Advanced → Proceed** to bypass the self-signed cert warning.

Or query the API directly:

```bash
# Health check
curl -k https://localhost:8443/health

# List agents
curl -k https://localhost:8443/api/v1/agents

# Latest metrics for your agent
curl -k "https://localhost:8443/api/v1/agents/my-macbook/metrics"
```

---

## Quick Start — Run in Docker

Docker runs the **manager only** (the agent must run natively on macOS — it needs host system APIs).

```bash
cd /path/to/macbook_data

# Export your API key
export API_KEY="PASTE_YOUR_KEY_HERE"

# Build and start
docker compose up --build

# Run in background
docker compose up -d

# Watch logs
docker compose logs -f

# Stop
docker compose down
```

Dashboard: **`https://localhost:8443`**

> **Note:** If you see a `version` warning, it's harmless — the `version` field has been removed from `docker-compose.yml`.

---

## Run the Agent

### Normal run

```bash
cd /path/to/macbook_data
PYTHONPATH=. python3 -m agent.agent.core --config agent.toml
```

### Full access run (recommended — gets complete data)

Some collectors (`lsof`, `fdesetup`, `csrutil`) need elevated access:

```bash
sudo -E PYTHONPATH=. python3 -m agent.agent.core --config agent.toml
```

`-E` preserves your environment variables (including `PYTHONPATH`).

### Reload config without restarting

Change any interval in `agent.toml`, then send SIGHUP — takes effect immediately:

```bash
kill -HUP $(pgrep -f "agent.agent.core")
```

### Install as a macOS service (auto-start on login)

```bash
bash agent/scripts/install.sh
launchctl load    ~/Library/LaunchAgents/com.mac-intel.agent.plist   # start
launchctl unload  ~/Library/LaunchAgents/com.mac-intel.agent.plist   # stop
```

---

## Configuration Reference

### `[agent]`

| Key | Default | Description |
|-----|---------|-------------|
| `id` | `"agent-001"` | Unique slug per machine (alphanumeric, hyphens OK) |
| `name` | `"My MacBook Air"` | Display name on the dashboard |
| `description` | `""` | Free-text description |

### `[manager]`

| Key | Default | Description |
|-----|---------|-------------|
| `url` | — | Manager HTTPS URL — **required** |
| `api_key` | — | 256-bit hex key from `keygen.py` — **required** |
| `tls_verify` | `true` | Set `false` for self-signed cert (dev only) |
| `timeout_sec` | `30` | HTTP request timeout |
| `retry_attempts` | `3` | Retries on 5xx / network error |
| `retry_delay_sec` | `5` | Initial retry delay (doubles on each retry) |
| `max_queue_size` | `500` | Drop oldest payload if outbound queue exceeds this |

### `[collection]`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Master on/off switch |
| `tick_sec` | `5` | How often the scheduler wakes up |

### Per-section `[collection.sections.<name>]`

| Key | Description |
|-----|-------------|
| `enabled` | `true` / `false` to activate this section |
| `interval_sec` | How often to collect (seconds) |
| `send` | `true` = send to manager, `false` = collect locally only |

### `[logging]`

| Key | Default | Description |
|-----|---------|-------------|
| `level` | `"INFO"` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `file` | `"logs/agent.log"` | Log file path (relative to project root) |
| `max_mb` | `10` | Rotate log at this size |
| `backups` | `3` | Number of rotated files to keep |

### Manager environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `API_KEY` | Yes | 256-bit master key — must match `agent.toml` |
| `BIND_HOST` | No | Default `0.0.0.0` |
| `BIND_PORT` | No | Default `8443` |
| `TLS_CERT` | No | Path to TLS certificate |
| `TLS_KEY` | No | Path to TLS private key |
| `CORS_ORIGINS` | No | Comma-separated allowed origins (default `*`) |
| `DB_PATH` | No | SQLite database path |
| `LOG_LEVEL` | No | Default `INFO` |

Copy `.env.example` to `.env` and fill in values.

---

## Collected Sections

| Section | Interval | Category | What it collects |
|---------|----------|----------|-----------------|
| `metrics` | 10 s | volatile | CPU %, RAM, swap, load average, I/O |
| `connections` | 10 s | volatile | All ESTABLISHED TCP connections |
| `processes` | 10 s | volatile | Top 80 processes by CPU + RAM |
| `ports` | 30 s | network | All TCP LISTEN + UDP sockets |
| `network` | 2 min | network | Interface IPs, MACs, DNS, WiFi SSID, routes |
| `arp` | 2 min | network | ARP table — hosts on local network |
| `mounts` | 2 min | network | Active filesystem mounts |
| `battery` | 2 min | system | Charge %, cycle count, condition, power source |
| `openfiles` | 2 min | system | Top 60 processes by open file descriptor count |
| `services` | 2 min | system | Running launchd daemons + login items |
| `users` | 2 min | system | Local users, groups, login history |
| `hardware` | 2 min | system | USB, Thunderbolt, Bluetooth |
| `containers` | 2 min | system | Docker / Podman containers and images |
| `storage` | 10 min | inventory | Disk usage per volume, diskutil list |
| `tasks` | 10 min | inventory | Crontabs, periodic scripts, launchd timers |
| `security` | 1 hr | posture | SIP, Gatekeeper, FileVault, Firewall, XProtect |
| `sysctl` | 1 hr | posture | Kernel security parameters |
| `configs` | 1 hr | posture | Shell rc, SSH config, /etc/hosts |
| `apps` | 24 hr | inventory | Installed .app bundles |
| `packages` | 24 hr | inventory | brew, pip, npm, gems |
| `binaries` | 24 hr | inventory | Executables in bin dirs (disabled by default) |
| `sbom` | 24 hr | inventory | Full software bill of materials |

---

## Manager API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/ingest` | Receive encrypted payload from agent |
| `GET` | `/api/v1/agents` | List all known agents |
| `GET` | `/api/v1/agents/{id}` | Agent detail + section timestamps |
| `GET` | `/api/v1/agents/{id}/{section}` | Section time-series data |
| `WS` | `/ws/{agent_id}?token=<key>` | Live WebSocket updates |
| `GET` | `/health` | Health check |
| `GET` | `/` | Dashboard UI |

---

## Security Design

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS 1.3 minimum (`ssl.TLSVersion.TLSv1_3`) |
| Confidentiality | AES-256-GCM encryption of every payload |
| Integrity | GCM authentication tag (16-byte tamper detection) |
| Authenticity | HMAC-SHA256 envelope signature |
| Key derivation | HKDF-SHA256, domain-separated `enc_key` + `mac_key` |
| Replay prevention | ±5 min timestamp window + per-nonce dedup cache |
| Verification order | schema → timestamp → nonce → HMAC → decrypt |

**The API key never travels on the wire.** Only payloads encrypted with HKDF-derived child keys are sent.

See [SECURITY.md](SECURITY.md) for the full threat model and hardening checklist.

---

## Developer Commands

```bash
make install          # install all dependencies + dev tools
make test             # run full test suite
make test-unit        # unit tests only
make test-integration # integration tests only
make test-coverage    # tests with HTML coverage report
make lint             # ruff + mypy
make lint-fix         # auto-fix ruff issues
make security         # bandit SAST + pip-audit CVE scan
make keygen           # generate a new 256-bit API key
make certs            # generate self-signed TLS certs (dev only)
make run-manager      # start manager (API_KEY must be exported)
make run-agent        # start agent (agent.toml must exist)
make docker-up        # build + start manager in Docker
make docker-down      # stop Docker services
make docker-logs      # tail manager container logs
make clean            # remove compiled files + test artifacts
```

---

## Adding a New Collector

Takes about 5 minutes:

**1. Add the collector class** to the appropriate file in `agent/agent/collectors/`:

```python
# agent/agent/collectors/system.py  (or whichever category fits)
class MyCollector(BaseCollector):
    name = "my_section"

    def collect(self) -> dict:
        return {
            "output": _run(["my_command", "--flag"]),
        }
```

**2. Register it** in `agent/agent/collectors/__init__.py`:

```python
from .system import MyCollector          # add import
COLLECTORS["my_section"] = MyCollector() # add to registry
```

**3. Add to shared section list** in `shared/sections.py`:

```python
SectionDef("my_section", "system", 120, "Description of what it collects"),
```

**4. Add to `agent.toml.example`**:

```toml
[collection.sections.my_section]
enabled      = true
interval_sec = 120
send         = true
```

**5. Run tests** to confirm nothing broke:

```bash
make test
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 Unauthorized` | API key mismatch | Ensure `API_KEY` env var on manager equals `api_key` in `agent.toml` |
| `FileNotFoundError` on certs | Wrong working directory | Always run from the project root (`macbook_data/`) |
| `ModuleNotFoundError` | `PYTHONPATH` not set | Prefix command with `PYTHONPATH=.` |
| Empty `lsof` / process data | Missing macOS permissions | Run agent with `sudo -E` |
| `Application startup complete` but still 401 | `API_KEY` was empty when manager started | Stop manager, set `API_KEY=...` on the same line as the command, restart |
| `RuntimeError: API_KEY is required` | Env var not exported | Use `API_KEY="..." python3 -m uvicorn ...` syntax |
| TLS certificate error in browser | Self-signed cert | Click Advanced → Proceed to continue |
| WebSocket `403` | Wrong or missing token | Dashboard uses `api_key` as the WS token — ensure keys match |
| Agent not connecting | Port 8443 not reachable | Check manager is running, firewall allows 8443 |

---

## Wire Format

Every payload sent from agent to manager:

```json
{
  "v":         1,
  "agent_id":  "agent-001",
  "timestamp": 1712345678.123,
  "nonce":     "<12-byte base64>",
  "ct":        "<AES-256-GCM ciphertext + GCM tag, base64>",
  "hmac":      "<HMAC-SHA256 over agent_id:timestamp:nonce:ct, hex>",
  "section":   "metrics"
}
```

The `ct` field decrypts to gzip-compressed JSON:

```json
{
  "section":      "metrics",
  "agent_id":     "agent-001",
  "agent_name":   "My MacBook Air",
  "collected_at": 1712345678,
  "data": { ... }
}
```

Verification order on the manager (cheapest first):
```
1. Schema check      — all required fields present
2. Timestamp window  — reject if |now - timestamp| > 5 min
3. Nonce dedup       — reject if nonce already seen
4. HMAC verify       — constant-time comparison
5. AES-256-GCM decrypt + decompress
```
