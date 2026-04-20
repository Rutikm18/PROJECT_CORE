# mac_intel — System Architecture

## 1. High-Level Design

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENDPOINTS                                    │
│                                                                     │
│   ┌─────────────────┐         ┌──────────────────────┐             │
│   │  macOS Agent    │         │   Windows Agent      │             │
│   │                 │         │                      │             │
│   │ ┌─────────────┐ │         │ ┌──────────────────┐ │             │
│   │ │ Collectors  │ │         │ │   Collectors     │ │             │
│   │ │ (22 types)  │ │         │ │  (22 types)      │ │             │
│   │ └──────┬──────┘ │         │ └────────┬─────────┘ │             │
│   │        │ gather │         │          │ gather    │             │
│   │ ┌──────▼──────┐ │         │ ┌────────▼─────────┐ │             │
│   │ │ Orchestrator│ │         │ │  Orchestrator    │ │             │
│   │ │ tick_sec=5  │ │         │ │  tick_sec=5      │ │             │
│   │ └──────┬──────┘ │         │ └────────┬─────────┘ │             │
│   │        │ ndjson │         │          │ ndjson    │             │
│   │ ┌──────▼──────┐ │         │ ┌────────▼─────────┐ │             │
│   │ │   Sender    │ │         │ │    Sender        │ │             │
│   │ │ HMAC+gzip   │ │         │ │  HMAC+gzip       │ │             │
│   │ │ spool+retry │ │         │ │  spool+retry     │ │             │
│   │ └──────┬──────┘ │         │ └────────┬─────────┘ │             │
│   └────────┼────────┘         └──────────┼───────────┘             │
│            │                             │                          │
│            └──────────────┬──────────────┘                          │
│                           │ HTTPS (TLS 1.2+)                        │
│                           │ POST /api/v1/ingest                     │
└───────────────────────────┼─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│                         MANAGER                                     │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                  Caddy Reverse Proxy                         │  │
│  │           TLS termination (self-signed or ACME)              │  │
│  │                      Port 8443 / 443                         │  │
│  └─────────────────────────┬────────────────────────────────────┘  │
│                             │ plain HTTP :8080                      │
│  ┌──────────────────────────▼───────────────────────────────────┐  │
│  │                   FastAPI Application                        │  │
│  │                                                              │  │
│  │  ┌────────────┐ ┌─────────────┐ ┌────────────┐ ┌─────────┐ │  │
│  │  │  /ingest   │ │  /enroll    │ │  /soc/*    │ │  /keys  │ │  │
│  │  │  Payload   │ │  Auto-gen   │ │  SOC API   │ │  Admin  │ │  │
│  │  │  receiver  │ │  HMAC key   │ │  Lifecycle │ │  API    │ │  │
│  │  └─────┬──────┘ └─────────────┘ └────────────┘ └─────────┘ │  │
│  │        │                                                     │  │
│  │  ┌─────▼──────────────────────────────────────────────────┐ │  │
│  │  │               Jarvis Engine                            │ │  │
│  │  │                                                        │ │  │
│  │  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  │ │  │
│  │  │  │  Analyzers  │  │  Behavioral  │  │ Correlation │  │ │  │
│  │  │  │  12 types   │  │  Baseline    │  │  Engine     │  │ │  │
│  │  │  └──────┬──────┘  └──────────────┘  └─────────────┘  │ │  │
│  │  │         │                                              │ │  │
│  │  │  ┌──────▼──────────────────────────────────────────┐  │ │  │
│  │  │  │         Threat Intelligence Feeds                │  │ │  │
│  │  │  │  AbuseIPDB · NVD/CVE · Rule-based detection     │  │ │  │
│  │  │  └─────────────────────────────────────────────────┘  │ │  │
│  │  └────────────────────────┬───────────────────────────────┘ │  │
│  │                            │                                 │  │
│  │  ┌─────────────────────────▼─────────────────────────────┐  │  │
│  │  │                  Intel DB (SQLite WAL)                 │  │  │
│  │  │                                                        │  │  │
│  │  │  findings  │ soc_activity │ soc_comments │ correlations│  │  │
│  │  │  change_timeline  │  behavior_baseline │  ioc_cache   │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Flow

### 2a. Agent → Manager (Ingest)

```
1. Collector gathers data (CPU, ports, processes, etc.)
2. Orchestrator batches payloads with section + timestamp
3. Sender compresses with gzip, signs with HMAC-SHA256
4. POST /api/v1/ingest  (header: X-Agent-ID, X-HMAC-SHA256, X-Collected-At, X-Nonce)
5. Manager validates HMAC against stored agent key
6. Manager checks nonce cache (replay prevention, 60s window)
7. Payload stored in payloads table
8. Jarvis Engine processes payload async:
   a. Route section → analyzer
   b. Emit raw findings
   c. Behavioral analysis
   d. Upsert into intel.db with dedup fingerprint
   e. Assign SLA deadline (Critical=4h, High=24h, Medium=7d, Low=30d)
   f. Log soc_activity entry (action=created)
   g. Every 3 payloads: run cross-section correlation
```

### 2b. Enrollment

```
1. Agent generates local hardware UUID (mac-<uuid> / win-<guid>)
2. POST /api/v1/enroll  {agent_id, name, token (if required)}
3. Manager validates token (or open enrollment)
4. Manager generates 256-bit HMAC key (secrets.token_hex(32))
5. Manager stores key in agent_keys table
6. Manager returns {api_key, manager_version} to agent
7. Agent stores key in:
   - macOS: Keychain (com.macintel.agent)
   - Windows: DPAPI-encrypted credential store
```

### 2c. SOC Workflow

```
Finding Created (status=new, sla_due set)
    │
    ▼ Analyst triages
Triaging (status=triaging)
    │
    ▼ Investigation begins
Investigating (status=investigating)
    │
    ├─→ False Positive (status=false_positive) ──────────────────┐
    ├─→ Accepted Risk  (status=accepted_risk)  ──────────────────┤
    ▼                                                             │
In Remediation (status=in_remediation)                           │
    │                                                             │
    ▼ Fix applied                                                 │
Remediated (status=remediated)                                   │
    │                                                             │
    ▼ Fix verified                                                │
Verified (status=verified) ──────────────────────────────────────┤
    │                                                             │
    ▼                                                             │
Closed (status=closed) ──────────────────────────────────────────┘
```

---

## 3. Database Schema

### manager.db (operational)

| Table | Purpose |
|-------|---------|
| `agents` | Enrolled endpoint registry |
| `agent_keys` | Per-agent HMAC keys with expiry + revocation |
| `payloads` | Raw telemetry sections (indexed by agent+section+ts) |

### intel.db (intelligence)

| Table | Purpose |
|-------|---------|
| `findings` | Correlated security findings (SOC-extended) |
| `findings_fts` | FTS5 full-text search index |
| `soc_activity` | Audit log of every analyst action per finding |
| `soc_comments` | Analyst investigation notes |
| `correlations` | Cross-section attack chain correlations |
| `change_timeline` | Append-only entity change history |
| `behavior_baseline` | Welford running mean/stddev per metric |
| `entity_state` | Last-known fingerprint for change detection |
| `ioc_cache` | Threat feed IP/domain cache |
| `cve_cache` | NVD CVE lookup cache |
| `cve_entries` | Deduplicated CVE records |

### SOC Fields Added to `findings`

| Column | Type | Purpose |
|--------|------|---------|
| `status` | TEXT | SOC workflow state (new→closed) |
| `assignee` | TEXT | Responsible analyst |
| `sla_due` | REAL | Unix epoch deadline for resolution |
| `closed_at` | REAL | When finding was closed |
| `priority` | INTEGER | 0=normal, 1=escalated |
| `analyst_notes` | TEXT | Free-form investigation notes |

---

## 4. SLA Policy

| Severity | SLA Window | Rationale |
|----------|-----------|-----------|
| Critical | 4 hours | Active exploitation risk; immediate response required |
| High | 24 hours | Significant risk; same business day |
| Medium | 7 days | Moderate risk; weekly sprint |
| Low | 30 days | Low risk; monthly review cycle |
| Info | 90 days | Informational; quarterly review |

SLA is set at finding creation time (`first_detected_at + sla_hours × 3600`).
If a finding is re-activated after closure, the SLA restarts.

---

## 5. Security Controls

### Transport
- All agent→manager traffic: HTTPS (TLS 1.2+)
- Caddy handles TLS; manager never sees raw TLS
- Self-signed cert (IP-only) or Let's Encrypt (domain)

### Authentication
- Per-agent HMAC-SHA256 keys (256-bit)
- Keys stored encrypted in OS keychain (macOS Keychain / Windows DPAPI)
- Keys never logged, never transmitted after enrollment
- Key expiry configurable (`DEFAULT_KEY_EXPIRY_DAYS`)
- Admin API protected by `ADMIN_TOKEN` (sk-admin-... format)
- Enrollment protected by `ENROLLMENT_TOKENS` or open (configurable)

### Replay Prevention
- Every ingest payload includes `X-Nonce` (random 16-byte hex)
- Manager caches nonces for 60 seconds
- Duplicate nonces rejected with 409

### Source Code Protection
- Docker image compiles all `.py` → `.pyc` (optimized)
- Source `.py` files deleted from image
- Only Caddy entrypoint shell script + bytecode in final image

### Data Isolation
- Manager runs as uid 1000 (jarvis) — no root privileges
- Intel DB and manager DB are separate SQLite files
- Payload data retention: SQLite WAL with configurable cleanup

---

## 6. Agent Architecture

### Collection Schedule

| Section | Interval | Purpose |
|---------|----------|---------|
| metrics | 10s | CPU, memory, disk I/O |
| connections | 10s | Active network connections |
| processes | 10s | Running processes |
| ports | 30s | Listening ports |
| network | 2m | Network interfaces |
| battery | 2m | Battery status |
| services | 2m | System services / LaunchDaemons |
| users | 2m | User accounts |
| hardware | 2m | Hardware inventory |
| storage | 10m | Disk usage |
| security | 1h | SIP, Gatekeeper, FileVault, Firewall |
| apps | 24h | Installed applications |
| packages | 24h | Package manager inventory |
| sbom | 24h | Software bill of materials |

### Reliability Controls

- **Spool queue**: Failed sends written to `spool/` directory (NDJSON)
- **Circuit breaker**: Per-section breaker (CLOSED→OPEN→HALF-OPEN)
  - Opens after 5 consecutive failures
  - Half-open after 60s cooldown
  - Emits `agent_health` section with breaker states
- **Retry**: Exponential backoff, configurable `retry_attempts`
- **Watchdog**: Separate service that monitors and restarts main agent

---

## 7. API Reference

### SOC API (`/api/v1/soc/`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | KPIs, charts, SLA data for SOC dashboard |
| GET | `/sla` | SLA breach + warning report |
| GET | `/findings` | Paginated findings (global, all filters) |
| GET | `/findings/{id}` | Single finding with comments + activity |
| PATCH | `/findings/{id}` | Update status, assignee, notes, priority |
| POST | `/findings/{id}/comments` | Add analyst comment |
| GET | `/findings/{id}/comments` | List comments |
| GET | `/findings/{id}/activity` | Activity audit log |
| POST | `/bulk` | Bulk status/assignee update (max 200) |

### Jarvis API (`/api/v1/jarvis/`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{agent_id}/summary` | Severity counts + max score |
| GET | `/{agent_id}/findings` | Per-agent findings list |
| GET | `/{agent_id}/findings/{id}` | Single finding detail |
| GET | `/{agent_id}/timeline` | Change event log |
| GET | `/{agent_id}/search` | FTS5 full-text search |
| POST | `/{agent_id}/resolve/{id}` | Mark resolved |
| GET | `/{agent_id}/correlations` | Attack chain correlations |

### Key Management API (`/api/v1/keys/`) — Admin token required

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List all agent keys |
| POST | `/{agent_id}/rotate` | Rotate agent key |
| POST | `/{agent_id}/revoke` | Revoke agent key |
| PATCH | `/{agent_id}/expiry` | Set key expiry |
| DELETE | `/{agent_id}` | Hard delete key (agent must re-enroll) |
