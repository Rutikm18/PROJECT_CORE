# AttackLens — Endpoint Security Intelligence Platform

AttackLens is a self-hosted, multi-tenant endpoint detection and response (EDR) platform. It collects rich telemetry from macOS endpoints, correlates it against 10+ live global threat intelligence feeds, applies AI-assisted analysis powered by Claude, and surfaces actionable findings through a real-time SOC dashboard.

---

## What It Does

| Layer | Capability |
|---|---|
| **Agent** | 25+ telemetry sections collected every 10 s–24 hr, encrypted AES-256-GCM, shipped over TLS 1.3 |
| **Async Ingest** | RabbitMQ pipeline decouples HTTP from storage — HTTP handler returns in < 5 ms |
| **Storage** | Three-tier hot/warm/cold NDJSON+gzip store with automatic tiering and retention |
| **Detection** | Rules + allowlist + behavioral baselines + 21-rule time-gated MITRE ATT&CK correlator |
| **Threat Intel** | 10+ live feeds: Feodo, ET, CISA KEV, ransomware.live, NVD/CVE, EPSS, ThreatFox, Spamhaus |
| **AI Analysis** | Claude-powered finding analysis, step-by-step remediation plans, CISO-grade prioritization |
| **Dashboard** | Live WebSocket SOC dashboard — findings, correlations, attack chains, asset registry |
| **Notifications** | SMTP / Microsoft Graph (Office 365 OAuth) email alerts for critical findings and daily digests |

---

## Architecture at a Glance

```
  macOS Endpoint
  ┌────────────────────────────────────────────────────┐
  │  attacklens-agent  (25+ section collectors)        │
  │  attacklens-watchdog  (launchd crash recovery)     │
  │                                                    │
  │  Payload pipeline:                                 │
  │  NDJSON → gzip → AES-256-GCM (96-bit nonce)       │
  │         → HMAC-SHA256 → HTTPS/TLS 1.3              │
  └───────────────────────┬────────────────────────────┘
                          │ HTTPS
  ┌───────────────────────▼────────────────────────────┐
  │  Caddy  (TLS termination: self-signed or ACME)     │
  └───────────────────────┬────────────────────────────┘
                          │ HTTP (internal Docker network)
  ┌───────────────────────▼────────────────────────────┐
  │               Manager  (FastAPI + Uvicorn)         │
  │                                                    │
  │  ┌──────────────┐    ┌─────────────────────────┐   │
  │  │ Ingest API   │───▶│  RabbitMQ               │   │
  │  │ /api/v1/     │    │  agent.telemetry queue  │   │
  │  └──────────────┘    └────────────┬────────────┘   │
  │                                   │                │
  │                      ┌────────────▼────────────┐   │
  │                      │  TelemetryWorker        │   │
  │                      │  • Three-tier file store│   │
  │                      │  • SQLite index         │   │
  │                      │  • WebSocket broadcast  │   │
  │                      │  • Publish jarvis.work  │   │
  │                      └────────────┬────────────┘   │
  │                                   │                │
  │                      ┌────────────▼────────────┐   │
  │                      │  Jarvis AI Engine       │   │
  │                      │  ┌───────────────────┐  │   │
  │                      │  │  Allowlist        │  │   │
  │                      │  │  Rules (26 rules) │  │   │
  │                      │  │  Behavioral (13s) │  │   │
  │                      │  │  Correlator (21r) │  │   │
  │                      │  │  NVD CVE lookup   │  │   │
  │                      │  └───────────────────┘  │   │
  │                      └────────────┬────────────┘   │
  │                                   │                │
  │                      ┌────────────▼────────────┐   │
  │                      │  AI Analyst (Claude)    │   │
  │                      │  Email Notifier         │   │
  │                      └─────────────────────────┘   │
  │                                                    │
  │  intel.db: findings, baselines, AI results         │
  │  manager.db: agents, keys, enrollment              │
  └───────────────────────┬────────────────────────────┘
                          │ HTTP (internal)
  ┌───────────────────────▼────────────────────────────┐
  │  Central Threat Intel Service  (separate container)│
  │  Feodo · ET · URLhaus · ThreatFox · Spamhaus       │
  │  CISA KEV · ransomware.live · HackerNews           │
  │  NVD/CVE · EPSS · AbuseIPDB · OTX · GreyNoise     │
  └────────────────────────────────────────────────────┘
```

---

## Quick Start (5 minutes)

### Prerequisites
- Docker + Compose v2 on a Linux server (AWS EC2, VPS, or on-prem)
- A public IP or domain name

### 1 — Deploy the Manager

```bash
git clone <repo-url> attacklens && cd attacklens

# Interactive wizard — auto-detects IP, generates secrets, writes .env + Caddyfile
bash env.sh

# Start the full stack (manager + threat-intel + rabbitmq + caddy)
docker compose up -d

# Verify
docker compose ps
curl http://localhost:8080/health
```

Open `https://YOUR_IP:8443` in a browser (accept the self-signed cert warning, or use a domain for Let's Encrypt).

### 2 — Enroll a macOS Agent

```bash
# On the endpoint — run the PKG installer
sudo installer -pkg attacklens-agent.pkg -target /

# Configure it
sudo /Library/AttackLens/bin/generate_config.sh \
  --manager-url https://YOUR_MANAGER_IP:8443 \
  --tls-verify false          # only if using self-signed cert

# Start it
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist

# Check status
sudo /Library/AttackLens/bin/attacklens-ctl status
```

Within 30 seconds the agent appears on the dashboard.

### 3 — Enable AI Analysis (optional)

Add your Anthropic API key to `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
```
Then restart: `docker compose restart manager`

---

## Key Features

### Detection Engine
- **Allowlist-first**: 60+ Apple system processes, 30+ CDN/cloud CIDR ranges, and 19 dual-use tool profiles suppress false positives before any rule fires
- **Process lineage**: Office/browser → shell spawn detection (T1566, T1189) with parent-child rule engine
- **Behavioral baselines**: Welford z-score + Shannon entropy + velocity detection across 13 telemetry sections
- **21 correlation rules**: Time-gated (6 h–168 h windows) to prevent stale noise from triggering alerts
- **Confidence scoring**: Every rule carries a 0.55–0.98 confidence weight; borderline findings are dampened

### Threat Intelligence
- 10+ feeds refreshed hourly — cached in `intel.db` so the detection engine never blocks on network
- NVD CVE lookups run async in a background worker (never blocks ingest)
- CISA KEV + EPSS scores boost composite risk scores (CVSS × EPSS × KEV × recency × asset tier)

### AI-Assisted SOC
- **Finding analysis**: Expert security commentary with threat context and risk factors
- **Remediation plans**: Step-by-step, OS-specific (macOS commands), cached per finding
- **CISO prioritization**: AI reranks findings by true business risk, not raw CVSS
- **Batch enrichment**: Background worker enriches unanalysed findings automatically

---

## Project Structure

```
attacklens/
├── agent/                         # macOS endpoint agent
│   ├── agent/                     # Core: enrollment, sender, orchestrator
│   │   ├── core.py                # Main collection loop + section scheduler
│   │   ├── enrollment.py          # Manager handshake + key exchange
│   │   └── sender.py              # Encrypted payload dispatch + spool
│   ├── os/macos/
│   │   ├── collectors/            # 25+ section collectors
│   │   │   ├── volatile.py        # metrics, connections, processes
│   │   │   ├── system.py          # services, users, hardware, containers
│   │   │   ├── inventory.py       # apps, packages, binaries, sbom
│   │   │   ├── posture.py         # security, sysctl, configs
│   │   │   └── network.py         # ports, network, arp, mounts
│   │   └── installer/             # PKG installer scripts + build tooling
│   └── config/agent.toml.example  # Full config reference
│
├── manager/                       # Manager service
│   ├── manager/
│   │   ├── api/                   # FastAPI route handlers
│   │   │   ├── ingest.py          # POST /api/v1/ingest
│   │   │   ├── agents.py          # Agent management endpoints
│   │   │   ├── findings.py        # Findings + correlations API
│   │   │   ├── remediation.py     # AI remediation + asset registry
│   │   │   └── threat.py          # Threat intel proxy endpoints
│   │   ├── jarvis/                # Detection engine
│   │   │   ├── allowlist.py       # FP suppression (Apple, CDN, dual-use)
│   │   │   ├── rules.py           # 26 process + 5 lineage + 5 obfusc rules
│   │   │   ├── behavioral.py      # Statistical anomaly detection (13 sections)
│   │   │   ├── correlator.py      # 21 time-gated ATT&CK correlation rules
│   │   │   ├── engine.py          # Main dispatcher + NVD worker
│   │   │   ├── feeds.py           # Threat feed manager
│   │   │   └── nvd.py             # NVD CVE lookup
│   │   ├── notifications/
│   │   │   └── email.py           # SMTP + Graph API notifier
│   │   ├── queue/                 # RabbitMQ producer/consumer/schemas
│   │   ├── threat/                # Scoring matrix + NVD sync worker
│   │   ├── workers/               # Async background task workers
│   │   ├── ai_analyst.py          # Claude API integration
│   │   ├── indexer.py             # IntelDB — findings, baselines, AI cache
│   │   ├── server.py              # FastAPI app factory + startup wiring
│   │   └── threat_intel_service.py # Central threat intel microservice
│   ├── dashboard/                 # Static SOC dashboard (HTML/CSS/JS)
│   ├── Dockerfile
│   └── ThreatIntel.Dockerfile
│
├── shared/                        # Wire protocol shared by agent and manager
├── docker-compose.yml             # Full production stack
├── env.sh                         # Interactive setup wizard
└── .env.example                   # Full environment variable reference
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PUBLIC_IP` | auto | Server public IP |
| `DOMAIN` | — | Domain for Let's Encrypt TLS |
| `BIND_PORT` | `8443` | Caddy listen port |
| `ADMIN_TOKEN` | generated | Dashboard admin token |
| `OPEN_ENROLLMENT` | `true` | Allow any agent to connect |
| `ENROLLMENT_TOKENS` | generated | Token(s) for closed enrollment |
| `ANTHROPIC_API_KEY` | — | Claude API key (AI features) |
| `AI_ANALYST_MODEL` | `claude-sonnet-4-6` | Claude model |
| `RABBITMQ_USER/PASS` | `jarvis/changeme` | RabbitMQ credentials |
| `SMTP_HOST/PORT/USER/PASS` | — | Email notifications |
| `OUTLOOK_CLIENT_ID/SECRET/TENANT` | — | Graph API email (alternative) |
| `ALERT_RECIPIENTS` | — | Email alert comma-separated list |
| `ABUSEIPDB_KEY` | — | AbuseIPDB API key |
| `OTX_KEY` | — | AlienVault OTX key |
| `GREYNOISE_KEY` | — | GreyNoise Community key |

---

## Security Model

| Layer | Mechanism |
|---|---|
| Transport | TLS 1.3 via Caddy (self-signed or Let's Encrypt ACME) |
| Payload | AES-256-GCM with 96-bit random nonce; HMAC-SHA256 integrity check |
| Replay protection | ±300 s timestamp window + nonce deduplication in manager DB |
| Authentication | Per-agent API keys stored in macOS System Keychain; never on disk |
| Network isolation | Manager is not directly internet-exposed; only reachable via Caddy |
| Credential storage | Keys in `manager.db`; findings in `intel.db`; never mixed |

---

## Service Management

```bash
# Full stack
docker compose up -d          # start
docker compose down           # stop
docker compose logs -f        # live logs

# Individual services
docker compose restart manager
docker compose restart threat-intel

# Agent (on endpoint)
sudo attacklens-ctl status    # agent + watchdog status
sudo attacklens-ctl restart   # restart both
sudo attacklens-ctl logs      # tail live log
sudo attacklens-ctl reload    # hot config reload (SIGHUP, no restart)
sudo attacklens-ctl enroll    # force re-enrollment
```

---

## Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Manager server | 2 vCPU, 4 GB RAM | 4 vCPU, 8 GB RAM |
| Docker | 20.10+ | latest |
| macOS agent | macOS 12 Monterey | macOS 14+ |
| Python (dev) | 3.11 | 3.12 |

---

## Contributing

1. Fork the repo and create a feature branch
2. Run `python -m pytest tests/` before opening a PR
3. All new detection rules require a `confidence` score and unit test

---

## Documentation

| Document | Description |
|---|---|
| `ARCHITECTURE.md` | System architecture and component design |
| `techarchitecture.md` | Deep technical architecture — data flows, protocols, algorithms |
| `STEP_BY_STEP.md` | Complete setup guide with every command |
| `INSTALLER.md` | Agent installation guide for macOS |
| `docs/` | Additional reference docs |
