# mac_intel — macOS System Intelligence Platform

A two-component system for collecting deep macOS telemetry on any Mac and visualising it in real-time on a remote dashboard — securely, over any network.

```
┌──────────────────────┐    HTTPS/TLS 1.3    ┌──────────────────────┐
│   macOS Machine      │  ─────────────────▶  │   Manager Server     │
│                      │   AES-256-GCM        │                      │
│  agent/agent.py      │   HMAC-SHA256        │  manager/server.py   │
│  22 collectors       │   gzip-compressed    │  FastAPI + WebSocket │
│  agent.toml config   │                      │  SQLite storage      │
│                      │                      │  live dashboard      │
└──────────────────────┘                      └──────────────────────┘
                                                        │
                                                        ▼
                                               https://SERVER:8443
                                               (dark web dashboard)
```

---

## Directory Structure

```
macbook_data/
├── agent.toml.example       ← copy → agent.toml, fill in key + URL
├── agent.toml               ← your config (gitignored — contains API key)
│
├── agent/                   ← macOS data collection module
│   ├── agent.py             ← orchestrator: schedules 22 collectors, encrypts, sends
│   ├── sender.py            ← TLS 1.3 HTTPS sender with retry + backoff
│   ├── requirements.txt     ← Python deps for the agent
│   └── __init__.py
│
├── manager/                 ← remote server module
│   ├── server.py            ← FastAPI: ingest endpoint, REST API, WebSocket, dashboard
│   ├── db.py                ← async SQLite (aiosqlite) storage layer
│   ├── auth.py              ← 5-step verification pipeline
│   ├── ws_hub.py            ← WebSocket registry + broadcast
│   ├── requirements.txt     ← Python deps for the manager
│   ├── __init__.py
│   ├── data/                ← SQLite database (gitignored)
│   └── dashboard/
│       ├── templates/
│       │   └── index.html   ← single-page dashboard
│       └── static/
│           ├── css/dashboard.css
│           └── js/
│               ├── app.js       ← top-level coordinator
│               ├── charts.js    ← Chart.js CPU/mem/battery
│               ├── tables.js    ← process/port/SBOM tables
│               ├── security.js  ← security badge panel
│               └── ws_client.js ← WebSocket with auto-reconnect
│
├── shared/                  ← code shared by agent + manager
│   ├── crypto.py            ← AES-256-GCM + HKDF + HMAC
│   └── __init__.py
│
├── scripts/
│   ├── setup.sh             ← one-shot setup for agent or manager
│   └── keygen.py            ← generate 256-bit API key + derived keys
│
├── certs/                   ← TLS certificates (gitignored)
│   ├── server.crt
│   └── server.key
│
├── report.sh                ← one-time full system snapshot (32 sections)
├── watch.sh                 ← live terminal monitor (per-section intervals)
│
├── data/                    ← SQLite for legacy collector (gitignored)
├── logs/                    ← all log files (gitignored)
├── output/                  ← saved reports from report.sh (gitignored)
│
├── collector.sh             ← legacy JSON collector
├── daemon.sh                ← legacy daemon manager
├── storage.py               ← legacy SQLite ingest
└── monitor.py               ← legacy change monitor
```

---

## Security Design

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS 1.3 minimum (enforced via SSLContext) |
| Confidentiality | AES-256-GCM encryption of every payload |
| Integrity | GCM authentication tag (tamper detection) |
| Authenticity | HMAC-SHA256 envelope signature |
| Key derivation | HKDF-SHA256, domain-separated enc_key + mac_key |
| Replay prevention | ±5 min timestamp window + nonce dedup cache |
| Verification order | schema → timestamp → nonce → HMAC → decrypt (cheapest first) |

The API key never travels on the wire. Only payloads encrypted with keys derived from it are sent.

---

## Quick Start — Agent Side (macOS)

### 1. Install dependencies

```bash
cd /path/to/macbook_data
pip install -r agent/requirements.txt
```

### 2. Generate API key

```bash
python3 scripts/keygen.py
```

Copy the printed `API Key` value. You'll need it on both sides.

### 3. Configure the agent

```bash
cp agent.toml.example agent.toml
```

Edit `agent.toml`:
- Set `[agent] id` to a unique slug for this machine
- Set `[manager] url` to `https://<your-server-ip>:8443`
- Set `[manager] api_key` to the key from step 2
- If using self-signed cert: set `tls_verify = false`

### 4. Run the agent

```bash
# Run directly
python3 agent/agent.py --config agent.toml

# Or install as a macOS launchd service (auto-starts on login)
bash scripts/setup.sh agent
```

**Manage the service:**
```bash
launchctl unload  ~/Library/LaunchAgents/com.mac-intel.agent.plist   # stop
launchctl load    ~/Library/LaunchAgents/com.mac-intel.agent.plist   # start
```

**Reload config without restart (SIGHUP):**
```bash
kill -HUP $(pgrep -f agent.py)
```

---

## Quick Start — Manager Side (Server)

The manager runs on any Linux/macOS server reachable by the agent's network.

### 1. Install dependencies

```bash
pip install -r manager/requirements.txt
```

### 2. Generate TLS certificate

```bash
# Self-signed (dev/internal use)
bash scripts/setup.sh certs

# Or use Let's Encrypt for a public domain (recommended for production)
```

### 3. Set the API key environment variable

```bash
export API_KEY="<same key from keygen.py>"
```

### 4. Start the manager

```bash
python3 manager/server.py
```

Or with uvicorn directly (more control):

```bash
uvicorn manager.server:app \
  --host 0.0.0.0 \
  --port 8443 \
  --ssl-certfile certs/server.crt \
  --ssl-keyfile  certs/server.key
```

### 5. Open the dashboard

```
https://<your-server-ip>:8443
```

---

## One-Command Setup

```bash
# Agent machine
bash scripts/setup.sh agent

# Manager server
export API_KEY="<your-key>"
bash scripts/setup.sh manager
```

---

## Agent Configuration Reference (`agent.toml`)

### `[agent]`

| Key | Default | Description |
|-----|---------|-------------|
| `id` | `"agent-001"` | Unique agent identifier |
| `name` | `"My MacBook"` | Display name on dashboard |
| `description` | `""` | Free-text description |

### `[manager]`

| Key | Default | Description |
|-----|---------|-------------|
| `url` | — | Manager HTTPS URL (required) |
| `api_key` | — | 256-bit hex key from keygen.py (required) |
| `tls_verify` | `true` | Set `false` for self-signed cert |
| `timeout_sec` | `30` | HTTP request timeout |
| `retry_attempts` | `3` | Retries on 5xx / network error |
| `retry_delay_sec` | `5` | Initial retry delay (exponential backoff) |
| `max_queue_size` | `500` | Drop oldest if outbound queue exceeds this |

### `[collection]`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Master switch for all collection |
| `tick_sec` | `5` | Scheduler wake interval |

### Per-section (`[collection.sections.<name>]`)

| Key | Description |
|-----|-------------|
| `enabled` | Collect this section |
| `interval_sec` | How often to collect |
| `send` | Transmit to manager (false = local only) |

---

## Collected Sections

| Section | Interval | What it collects |
|---------|----------|-----------------|
| `metrics` | 10 s | CPU %, RAM, swap, battery charge |
| `connections` | 10 s | All ESTABLISHED TCP connections |
| `processes` | 10 s | Top processes by CPU + RAM |
| `ports` | 30 s | All LISTEN sockets (process, PID, proto, addr:port) |
| `network` | 2 min | Interface IPs, MACs, DNS, WiFi SSID, routing table |
| `battery` | 2 min | Charge %, cycle count, condition, power source |
| `openfiles` | 2 min | Top processes by open file descriptor count |
| `services` | 2 min | Running launchd daemons, plist paths, login items |
| `users` | 2 min | Local users, admins, groups, login history |
| `hardware` | 2 min | USB, Thunderbolt, Bluetooth, displays, audio |
| `containers` | 2 min | Docker / Podman: running containers and images |
| `arp` | 2 min | ARP table (hosts visible on local network) |
| `mounts` | 2 min | Active filesystem mounts |
| `storage` | 10 min | Disk usage per volume, diskutil list |
| `tasks` | 10 min | Crontabs, periodic scripts, launchd timers |
| `security` | 1 hr | SIP, Gatekeeper, FileVault, Firewall, pf rules, TCC |
| `sysctl` | 1 hr | Kernel parameters (net.*, security.*, kern.*) |
| `configs` | 1 hr | Shell rc, SSH config, authorized_keys, /etc/hosts |
| `apps` | 24 hr | Installed .app bundles + versions |
| `packages` | 24 hr | brew, pip, npm, gems, go bins, cargo bins |
| `binaries` | 24 hr | All executables in Homebrew + /usr/local (disabled by default) |
| `sbom` | 24 hr | Full SBOM across all package managers |

---

## Manager API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/ingest` | Receive encrypted payload from agent |
| `GET` | `/api/v1/agents` | List all known agents |
| `GET` | `/api/v1/agents/{id}` | Get latest snapshot for an agent |
| `GET` | `/api/v1/agents/{id}/{section}` | Get specific section history |
| `WS` | `/ws/{agent_id}` | Subscribe to real-time updates |
| `GET` | `/health` | Health check |
| `GET` | `/` | Dashboard UI |

---

## Local Tools (no manager needed)

### Full snapshot — 32 sections, saved to file

```bash
sudo bash report.sh
# Saved to: output/report_YYYYMMDD_HHMMSS.txt
```

### Live terminal monitor — volatile sections only

```bash
sudo bash watch.sh

# Custom intervals via env vars
WATCH_TICK=5 WATCH_INTERVAL_METRICS=10 WATCH_INTERVAL_PORTS=30 sudo bash watch.sh

# Specific sections only
WATCH_SECTIONS=ports,connections,processes sudo bash watch.sh
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `python3 not found` | Install Python 3.9+ via Homebrew: `brew install python` |
| TLS certificate error | Set `tls_verify = false` in `agent.toml` for self-signed cert |
| Agent not connecting | Verify manager URL and that port 8443 is open on the server |
| `API_KEY not set` | `export API_KEY="<your-key>"` before starting manager |
| `HMAC verify failed` | API keys on agent and manager don't match — regenerate with keygen.py |
| Empty lsof / process data | Run agent with `sudo` for full system access |
| `Another collection running` | Remove `/tmp/mac_intel_collector.lock` if stale |

---

## Wire Format

Every payload sent from agent to manager:

```json
{
  "v": 1,
  "agent_id": "agent-001",
  "timestamp": 1712345678.123,
  "nonce": "<12-byte base64>",
  "ct": "<AES-256-GCM ciphertext+tag, base64>",
  "hmac": "<HMAC-SHA256 over agent_id+timestamp+nonce+ct, hex>"
}
```

The `ct` field decrypts to gzip-compressed JSON:

```json
{
  "section": "processes",
  "collected_at": "2024-04-05T12:34:56Z",
  "data": [ ... ]
}
```
# PROJECT_CORE
