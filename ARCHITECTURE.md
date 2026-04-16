# mac_intel Platform — Architecture Reference

## Overview

mac_intel is a **multi-OS endpoint security telemetry platform**.  
Agents run on macOS and Windows endpoints, collect system telemetry, encrypt it with AES-256-GCM, and ship it over TLS 1.3 to a central Manager.  
The Manager decrypts, indexes, runs Jarvis threat analysis, and surfaces findings on a live dashboard.

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         mac_intel Platform                                   ║
║                                                                              ║
║  LAYER 1 — AGENT  (macOS .pkg  /  Windows installer)                        ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║   macOS:   launchd → jarvis-watchdog → jarvis-agent                          ║
║   Windows: SCM     → MacIntelWatchdog → MacIntelAgent                        ║
║     │  22+ collectors: metrics, connections, ports, processes, inventory…    ║
║     │  Per-section circuit breaker (CLOSED → OPEN → HALF-OPEN)              ║
║     │  AES-256-GCM encrypt + HMAC-SHA256 sign per payload                   ║
║     │  Disk spool (50 MB, NDJSON) on manager outage                         ║
║     ▼                                                                        ║
║  LAYER 2 — TLS TRANSPORT                                                     ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║     HTTPS / TLS 1.3 minimum                                                  ║
║     Dev:  self-signed cert on port 8443                                      ║
║     Prod: Caddy reverse proxy → Let's Encrypt on port 443                   ║
║     ▼                                                                        ║
║  LAYER 3 — INGEST  (POST /api/v1/ingest)                                    ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║     Timestamp skew ±300 s → Nonce dedup → HMAC verify → AES decrypt        ║
║     Per-agent key lookup from agent_keys table                               ║
║     ▼                                                                        ║
║  LAYER 4 — RAW INDEXER  (TelemetryStore + SQLite)                           ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║     TelemetryStore: NDJSON+gzip, three-tier hot/warm/cold                   ║
║     SQLite: agents, agent_keys, payloads (manager.db)                       ║
║     API: GET /api/v1/agents/{id}/{section}                                   ║
║     WebSocket: WS /ws/{agent_id}  (live telemetry push)                     ║
║     ▼                                                                        ║
║  LAYER 5 — JARVIS ENGINE  (manager/jarvis/)                                 ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║     13 rule-based analyzers running concurrently                             ║
║     Global threat feed correlation (Feodo Tracker, Emerging Threats)        ║
║     NVD CVE lookup with CVSS scoring                                         ║
║     AbuseIPDB live IP reputation (optional)                                  ║
║     Welford online behavioral baseline + z-score anomaly detection           ║
║     MITRE ATT&CK technique/tactic mapping                                    ║
║     Fingerprint-based dedup (first_detected_at never changes on re-scan)    ║
║     ▼                                                                        ║
║  LAYER 6 — VERIFIED FINDINGS STORE  (intel.db)                              ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║     SQLite WAL + FTS5: findings, timeline, ioc_cache, cve_cache,            ║
║                         behavior_baseline, entity_state, change_timeline    ║
║     API: GET /api/v1/jarvis/{agent_id}/findings|summary|timeline|search     ║
║     ▼                                                                        ║
║  LAYER 7 — DASHBOARD  (dashboard/templates/index.html)                      ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║     Dark sidebar SPA: Overview · Agents · Jarvis Findings · Timeline ·      ║
║     Raw Telemetry. Fetches ONLY from verified findings via /api/v1/jarvis/* ║
║     WebSocket for live updates.                                              ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## End-to-End Data Flow

```
Agent collector thread (per section, per interval)
   │  normalize → wrap metadata → gzip → AES-256-GCM → HMAC-SHA256
   ▼
Agent sender thread
   │  POST /api/v1/ingest  (TLS 1.3)
   │  Exponential backoff + jitter; spool to disk on failure
   ▼
Manager: ingest.py
   1. Parse JSON envelope
   2. Timestamp skew check  (cheap, before crypto)
   3. Nonce dedup cache check
   4. Lookup api_key from agent_keys WHERE agent_id = envelope.agent_id
   5. HKDF-SHA256 → enc_key + mac_key
   6. Constant-time HMAC verify
   7. AES-256-GCM decrypt
   8. Upsert agent registry (last_seen, last_ip)
   9. TelemetryStore.write()   →  NDJSON+gzip  (hot/warm/cold)
  10. SQLite INSERT INTO payloads
  11. asyncio.create_task(jarvis.process(agent_id, section, data))
  12. WebSocket broadcast to live subscribers
   ▼
JarvisEngine.process()
   │  13 analyzers run concurrently (asyncio)
   │  Feed/NVD/AbuseIPDB async lookups
   ▼
IntelDB.upsert_finding()
   │  Same fingerprint?   → UPDATE last_detected_at only
   │  New?                → INSERT + timeline "added"
   │  Changed fingerprint → UPDATE all + timeline "modified"
   ▼
Dashboard → /api/v1/jarvis/* endpoints
```

---

## Enrollment Flow (First Run)

```
Agent startup
   │
   ├─ 1. Check keystore for existing API key
   │       ├─ Found → normal operation (skip enrollment)
   │       └─ Not found → BEGIN ENROLLMENT
   │
   ├─ 2. POST /api/v1/enroll
   │       Header: X-Enrollment-Token: <operator one-time token>
   │       Body:   {agent_id, agent_name, hostname, os, arch, ts}
   │
   ├─ 3. Manager validates token
   │       → generates secrets.token_hex(32)  (256-bit key)
   │       → stores agent_id → api_key in agent_keys table
   │       → returns {ok: true, api_key: "<64hex>", expires_at: <ts>}
   │
   └─ 4. Agent stores api_key in keystore (Keychain / DPAPI)
           → NEVER written to config file
```

Security properties:
- Manager generates and owns the key; agent only stores it.
- A leaked enrollment token cannot expose existing agents' session keys.
- Operator can rotate/revoke keys independently via `POST /api/v1/keys/{id}/rotate`.
- Token is transmitted over TLS 1.3 only; discarded after enrollment.

---

## Cryptography

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Transport | TLS 1.3 | Minimum enforced on both agent and manager |
| Key derivation | HKDF-SHA256 | 256-bit api_key → enc_key + mac_key |
| Payload encryption | AES-256-GCM | 96-bit random nonce per message |
| Integrity (defense-in-depth) | HMAC-SHA256 | Over agent_id:timestamp:nonce:ciphertext |
| Compression | gzip level 6 | Applied before encryption |
| Replay prevention | Timestamp ±300 s + nonce cache | Nonce cached 300 s, evicted hourly |

Envelope format (wire protocol):
```json
{
  "v": 1,
  "agent_id": "laptop-001",
  "timestamp": 1712700000,
  "nonce": "<base64 96-bit>",
  "ct": "<base64 AES-GCM ciphertext + tag>",
  "hmac": "<hex HMAC-SHA256>",
  "section": "metrics"
}
```

---

## Key Management API

All endpoints require `X-Admin-Token` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/keys` | List all agent key metadata (no secrets) |
| `GET` | `/api/v1/keys/{agent_id}` | Single agent key metadata |
| `POST` | `/api/v1/keys/{agent_id}/rotate` | Generate new 256-bit key (returned once) |
| `PATCH` | `/api/v1/keys/{agent_id}/expiry` | Set/extend/clear expiry (0 = never) |
| `POST` | `/api/v1/keys/{agent_id}/revoke` | Revoke key (agent cannot ingest) |
| `DELETE` | `/api/v1/keys/{agent_id}` | Hard-delete (agent must re-enroll) |

The raw key hex is **never returned** except on `POST /rotate` (one-time visibility).

---

## Agent: macOS

### Process Hierarchy
```
launchd (KeepAlive=true)
  └── /Library/Jarvis/bin/jarvis-watchdog  [com.jarvis.watchdog]
        └── /Library/Jarvis/bin/jarvis-agent  [com.jarvis.agent]
```

### Directory Layout
```
/Library/Jarvis/
  bin/        755 root:wheel   jarvis-agent, jarvis-watchdog
  config/     750 root:wheel   agent.toml
  data/       755 root:wheel   telemetry queue
  security/   700 root:wheel   API key file (fallback keystore)
  spool/      755 root:wheel   offline spool (50 MB max)
  logs/       755 root:wheel   agent.log, watchdog.log, stderr/stdout
/Library/LaunchDaemons/
  com.jarvis.agent.plist
  com.jarvis.watchdog.plist
```

### Key Storage
1. **Primary**: macOS Keychain — `keyring` service `com.jarvis.agent`, account = agent_id
2. **Fallback**: `/Library/Jarvis/security/<agent_id>.key` — mode 0600, root:wheel

### Collectors (22 sections)

| Section | Interval | What It Collects |
|---------|----------|------------------|
| `metrics` | 10 s | CPU %, memory %, load avg, swap |
| `connections` | 10 s | TCP/UDP connections (psutil or lsof) |
| `processes` | 10 s | Running processes |
| `ports` | 30 s | Listening ports |
| `network` | 120 s | Network interfaces |
| `battery` | 120 s | Battery level and status |
| `openfiles` | 120 s | Open file handles |
| `services` | 120 s | launchd services |
| `users` | 120 s | Logged-in users |
| `hardware` | 120 s | CPU/RAM/GPU/disk inventory |
| `containers` | 120 s | Running Docker containers |
| `arp` | 120 s | ARP table |
| `mounts` | 120 s | Mounted filesystems |
| `storage` | 600 s | Disk usage |
| `tasks` | 600 s | Scheduled tasks |
| `security` | 3600 s | SIP, Gatekeeper, FileVault posture |
| `sysctl` | 3600 s | Kernel parameters |
| `configs` | 3600 s | Key system configuration files |
| `apps` | 86400 s | Installed applications |
| `packages` | 86400 s | Package manager inventory |
| `sbom` | 86400 s | Software bill of materials |
| `binaries` | 86400 s | SUID/SGID/world-writable binaries (opt-in) |

---

## Agent: Windows

### Process Hierarchy
```
Service Control Manager
  └── MacIntelWatchdog  (depends on MacIntelAgent)
        └── MacIntelAgent
```

### Directory Layout
```
C:\Program Files (x86)\Jarvis\
  bin\        SYSTEM+Admins RX only    jarvis-agent.exe, jarvis-watchdog.exe
  config\     SYSTEM+Admins R only     agent.toml
  data\       SYSTEM+Admins full       telemetry queue
  security\   SYSTEM full only         API key (DPAPI encrypted)
  spool\      SYSTEM+Admins full       offline spool
  logs\       SYSTEM+Admins full       agent.log
```

### Key Storage
1. **Primary**: Windows Credential Manager — DPAPI-backed via `keyring` WinVault
2. **Fallback**: `security\<agent_id>.key.dpapi` — `CRYPTPROTECT_LOCAL_MACHINE` + icacls SYSTEM-only

---

## Agent: Circuit Breaker (per section)

```
CLOSED → [3 consecutive failures] → OPEN (skip section, cooldown 60 s)
OPEN   → [cooldown expired]       → HALF-OPEN (send 1 probe)
HALF-OPEN → [probe succeeds]      → CLOSED
HALF-OPEN → [probe fails]         → OPEN (reset cooldown)
```

Every 60 s the agent emits an `agent_health` section payload listing circuit breaker state per section.

---

## Agent: Disk Spool

- **Format**: NDJSON, one envelope per line, gzip compressed
- **Max size**: 50 MB; trims oldest 10% when full
- **Trigger**: manager unreachable (connectivity probe to `/health` fails)
- **Drain**: automatic on reconnect
- **Writes**: atomic (temp file → rename)

---

## Manager Module Layout

```
manager/
  manager/
    server.py          # FastAPI app factory, lifespan, middleware
    db.py              # SQLite async (WAL): agents, agent_keys, payloads
    store.py           # TelemetryStore: NDJSON+gzip hot/warm/cold
    indexer.py         # IntelDB: verified findings (intel.db) + FTS5
    crypto.py          # HKDF + AES-256-GCM + HMAC-SHA256
    ws_hub.py          # WebSocket broadcast hub
    api/
      ingest.py        # POST /api/v1/ingest
      enroll.py        # POST /api/v1/enroll
      agents.py        # GET  /api/v1/agents[/{id}/{section}]
      keys.py          # GET|POST|PATCH|DELETE /api/v1/keys/* (admin)
      jarvis.py        # GET  /api/v1/jarvis/* (verified findings)
    jarvis/
      engine.py        # JarvisEngine orchestrator + 13 analyzers
      correlator.py    # Cross-section correlation
      rules.py         # Detection rules + MITRE ATT&CK mapping
      behavioral.py    # Welford online z-score anomaly detection
      feeds.py         # FeedManager: Feodo, Emerging Threats, AbuseIPDB
      nvd.py           # CVELookup: NVD REST API v2 + CVSS parsing
  Dockerfile           # Multi-stage, non-root user (uid 1000: jarvis)
  scripts/
    entrypoint.sh      # Auto-generates TLS cert + tokens on first boot
  requirements.txt
```

---

## Manager: REST API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/ingest` | Per-agent HMAC | Receive encrypted telemetry |
| `POST` | `/api/v1/enroll` | Enrollment token | Register new agent |
| `GET` | `/api/v1/agents` | — | List all agents |
| `GET` | `/api/v1/agents/{id}` | — | Agent detail + section timestamps |
| `GET` | `/api/v1/agents/{id}/{section}` | — | Paginated section data |
| `GET` | `/api/v1/keys` | Admin token | List key metadata |
| `POST` | `/api/v1/keys/{id}/rotate` | Admin token | Rotate agent key |
| `PATCH` | `/api/v1/keys/{id}/expiry` | Admin token | Set key expiry |
| `POST` | `/api/v1/keys/{id}/revoke` | Admin token | Revoke key |
| `DELETE` | `/api/v1/keys/{id}` | Admin token | Hard-delete key |
| `GET` | `/api/v1/jarvis/{id}/findings` | — | Verified findings |
| `GET` | `/api/v1/jarvis/{id}/summary` | — | Finding counts by severity |
| `GET` | `/api/v1/jarvis/{id}/timeline` | — | Change timeline |
| `GET` | `/api/v1/jarvis/{id}/search` | — | FTS5 finding search |
| `GET` | `/health` | — | Health check + store stats |
| `WS` | `/ws/{agent_id}` | — | Live telemetry WebSocket |

---

## Manager: SQLite Schema

### manager.db

```sql
agents (
  agent_id    TEXT PRIMARY KEY,
  name        TEXT,
  last_seen   REAL,    -- Unix timestamp
  last_ip     TEXT,
  created_at  REAL
)

agent_keys (
  agent_id       TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
  api_key_hex    TEXT NOT NULL,       -- 64 hex chars (256-bit key)
  enrolled_at    REAL,
  enrollment_ip  TEXT,
  expires_at     REAL,               -- NULL = never expires
  revoked        INTEGER DEFAULT 0,
  rotated_at     REAL,
  key_label      TEXT
)

payloads (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id      TEXT,
  section       TEXT,
  collected_at  REAL,
  received_at   REAL,
  data          TEXT                 -- JSON
)
-- Index: (agent_id, section, collected_at DESC)
```

### intel.db (Verified Findings)

| Table | Purpose |
|-------|---------|
| `findings` | Deduplicated findings (UNIQUE agent+category+item_key) |
| `findings_fts` | FTS5 virtual table, auto-synced via triggers |
| `ioc_cache` | Threat feed IP/domain cache (24h TTL) |
| `cve_cache` | NVD CVE lookup cache (24h TTL) |
| `cve_entries` | Individual CVE records with CVSS scores |
| `behavior_baseline` | Welford online stats per agent+metric |
| `entity_state` | Last known state fingerprint per entity |
| `change_timeline` | Immutable log: added / modified / resolved |

---

## Manager: TelemetryStore (Three-Tier)

```
data/
  hot/   <agent_id>/<section>/YYYY-MM-DD.ndjson.gz   (current day)
  warm/  <agent_id>/<section>/YYYY-MM-DD.ndjson.gz   (last 7 days)
  cold/  <agent_id>/<section>/YYYY-MM-DD.ndjson.gz   (older)
```

Files are rotated daily. API queries scan tiers in order: hot → warm → cold.

---

## Deployment: Docker (Dev — Self-Signed TLS)

```
docker-compose.yml
  manager:
    image: jarvis-manager:latest
    port:  8443 (HTTPS, self-signed cert auto-generated)
    env:   PUBLIC_IP, ENROLLMENT_TOKENS, ADMIN_TOKEN, BIND_PORT
    vols:  ./data, ./certs, ./logs
```

On first boot `entrypoint.sh`:
1. Generates RSA-4096 self-signed cert valid 10 years (SAN includes `PUBLIC_IP`)
2. Auto-generates `sk-enroll-*` enrollment token and `sk-admin-*` admin token
3. Persists both to `/app/data/.secrets`
4. Prints credential banner to stdout (visible in `docker compose logs manager`)

---

## Deployment: Docker (Prod — Caddy + Let's Encrypt)

```
docker-compose.prod.yml
  caddy:
    image: caddy:2-alpine
    ports: 80, 443
    config: Caddyfile → auto TLS from Let's Encrypt
  manager:
    expose: 8080 (plain HTTP behind Caddy)
    env:   TLS_DISABLED=1, DOMAIN
```

Agent config: `tls_verify = true` (real CA cert).

---

## Jarvis Engine: Detection Coverage

| Analyzer | Data Source | Algorithm | External Feeds | Severity |
|----------|-------------|-----------|----------------|----------|
| ports | ports | Rule match vs 28 malicious ports | — | Critical–Low |
| processes | processes | 16 compiled regex patterns | — | Critical–Medium |
| connections | connections | IP reputation lookup | Feodo + ET + AbuseIPDB | Critical–High |
| services | services | Label/path pattern match | — | High–Medium |
| apps | apps | Signature/notarization check | — | Medium–Low |
| packages | packages | 25 risky tool rules | NVD CVE | Critical–Low |
| network | network | Interface fingerprint diff | — | High–Medium |
| users | users | UID-0, service shell check | — | Critical–Medium |
| tasks | tasks | cmdline pattern match | — | High–Medium |
| security | security | SIP/GK/FileVault posture | — | Critical–Medium |
| configs | configs | Config regex patterns | — | High–Medium |
| binaries | binaries | SUID/SGID/world-writable | — | High–Medium |
| behavioral | all sections | Welford z-score \|z\|>3.0σ | — | Critical–Low |

### Threat Feed Refresh

| Feed | Interval | Format |
|------|----------|--------|
| Feodo Tracker (IP blocklist) | 1 h | CSV |
| Emerging Threats (IP rules) | 1 h | TXT |
| AbuseIPDB (IP reputation) | On-demand | JSON |
| NVD CVE v2 | On-demand (7 s rate limit) | JSON |

---

## Security Controls Summary

| Control | Mechanism |
|---------|-----------|
| Transport encryption | TLS 1.3 minimum (both directions) |
| Payload encryption | AES-256-GCM (96-bit random nonce) |
| Payload integrity | HMAC-SHA256, constant-time comparison |
| Key derivation | HKDF-SHA256 (enc_key + mac_key from api_key) |
| Replay prevention | ±300 s timestamp window + 96-bit nonce dedup |
| Per-agent isolation | Key lookup by agent_id; HMAC fail ≠ valid data |
| Enrollment auth | One-time `sk-enroll-*` token over TLS only |
| Admin API auth | `sk-admin-*` token, separate from enrollment |
| Key storage (macOS) | Keychain (primary), 0600 file (fallback) |
| Key storage (Windows) | DPAPI Credential Manager (primary), DPAPI file (fallback) |
| Key never in config | api_key absent from agent.toml in all environments |
| Key expiry | Optional per-agent; `DEFAULT_KEY_EXPIRY_DAYS` env |
| Key revocation | `POST /api/v1/keys/{id}/revoke` (immediate) |
| Binary ACLs (Windows) | SYSTEM+Admins RX only; no user-writable paths |
| Directory ACLs (macOS) | security/ chmod 700 root:wheel |
| Manager process | Non-root uid 1000 (jarvis) inside container |
| Circuit breaker | Prevents cascading failures from broken collectors |
| Disk spool | Atomic writes; trims on overflow; never stores decrypted data |
