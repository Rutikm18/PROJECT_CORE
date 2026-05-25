# AttackLens Platform — Comprehensive System Audit
> Audit date: 2026-05-19 · Scope: manager/ (FastAPI) + dashboard/ (React/TypeScript)

---

## 1. System Architecture Overview

### 1.1 Component Map

```
┌──────────────────────────────────────────────────────────────────┐
│              AGENT (macOS / Linux / Windows)                     │
│  collectors → gzip+JSON → AES-256-GCM + HMAC-SHA256 envelope     │
└──────────┬────────────────────────────────────────┬─────────────┘
           │ HTTPS POST /api/v1/enroll              │ HTTPS POST /api/v1/ingest
           ▼                                        ▼
┌──────────────────────────────────────────────────────────────────┐
│                FastAPI Manager  (server.py)                      │
│  CORS · Rate limiter · Global exception handler                  │
│  Auth surfaces:                                                  │
│    per-agent HMAC key  ← mandatory for /ingest                   │
│    ADMIN_TOKEN (X-Admin-Token) ← /keys/*                         │
│    ENROLLMENT_TOKEN ← /enroll  (skip if OPEN_ENROLLMENT=true)    │
│    WS master API_KEY ← /ws/{id}?token=                           │
├──────────────────────────────────────────────────────────────────┤
│ 15 API Routers                                                   │
│  /ingest  /agents  /enroll  /attacklens  /keys  /soc  /threat    │
│  /raw  /assets  /posture  /detection  /accuracy  /settings       │
│  /remediation  + /ws/{id}  /health                               │
├────────────────────────────────┬─────────────────────────────────┤
│ Sync hot-path                  │ Queue path (RABBITMQ_URL)        │
│ Ingest → rate_limit            │ Ingest → publish agent.tel      │
│ → key_lookup → decrypt         │ TelemetryConsumer → store+db     │
│ → nonce_dedup → store.write    │ AttackLensWorker → engine        │
│ → db.insert → engine.process   │ ChunkTracker → correlation       │
│ → hub.broadcast                │ → hub.broadcast                  │
└────────────────────────────────┴─────────────────────────────────┘
           │                                        │
           ▼                                        ▼
  ┌──────────────────┐                   ┌──────────────────────┐
  │   manager.db     │                   │      intel.db        │
  │  agents          │                   │  findings + FTS5     │
  │  agent_keys      │                   │  correlations        │
  │  payloads        │                   │  soc_activity/cmt    │
  │  agent_sessions  │                   │  org_settings/audit  │
  │  nonce_cache     │                   │  nvd_cve_local+FTS5  │
  └──────────────────┘                   │  asset_registry      │
           │                             │  cisa_kev/epss       │
           ▼                             │  ai_analysis/remed.  │
  ┌─────────────────────────────────┐    └──────────────────────┘
  │ data/index.db (TelemetryIndex)  │
  │ data/hot/…/HH-MM.ndjson.gz     │
  │ data/warm/…/HH.ndjson.gz       │
  │ data/cold/…/DD.ndjson.gz       │
  │ data/latest/…/section.ndjson.gz│
  └─────────────────────────────────┘

Background workers (asyncio tasks):
  _cleanup_store (1h) · _expire_chunks (5m)
  ThreatIntelWorker · NVDSyncWorker · EnrichmentWorker
  TelemetryWorker · TelemetryConsumer · AttackLensWorker
  AttackLensEngine._nvd_worker (2s sleep)
```

### 1.2 Data Flow (ingest, sync mode)

```
POST /api/v1/ingest
 1. parse JSON envelope
 2. check REQUIRED_ENVELOPE_FIELDS
 3. |time.time() - envelope.timestamp| > 300 → 400
 4. rate_limiter.check_rate(raw_agent_id)        # token bucket (10r/s, burst 30)
 5. rate_limiter.agent_slot(timeout=8s)          # max 4 concurrent per agent
 6. db.get_agent_key(agent_id)                   # reader pool
 7. crypto.decrypt(envelope, enc_key, mac_key)   # HMAC-SHA256 then AES-256-GCM
 8. db.check_and_store_nonce(nonce, ttl=300)     # DB-backed dedup
 9. db.upsert_agent(agent_id, name, ip)
10a. producer.publish(tel) → 202 (queue mode)
10b. store.write() + db.insert_payload() + engine.process() + hub.broadcast() (sync)
```

### 1.3 Storage Tiers

| Tier   | Granularity | Retention | Notes |
|--------|-------------|-----------|-------|
| hot    | per-minute  | 24 h      | Every event rewrites bucket |
| warm   | per-hour    | 90 d      | Every event rewrites bucket |
| cold   | per-day     | 365 d     | Every event rewrites bucket |
| latest | single file | n/a       | Last snapshot, always overwritten |

**Note**: All three tiers written on every ingest event (performance issue P1).

---

## 2. Database Design

### 2.1 manager.db

WAL mode · FK on · 4 reader pool + 1 writer lock

| Table           | Key Columns                                      | Purpose                     |
|-----------------|--------------------------------------------------|-----------------------------|
| `agents`        | PK `agent_id`                                    | Enrolled agent registry     |
| `agent_keys`    | PK `agent_id`, `api_key_hex`, `revoked`          | Per-agent HMAC keys         |
| `payloads`      | `agent_id`, `section`, `collected_at`, `data`    | Raw JSON archive            |
| `agent_sessions`| `agent_id`, `connected_at`, `disconnected_at`    | WS session history          |
| `nonce_cache`   | PK `nonce`, `expires_at`                         | Replay attack prevention    |

Indexes: `idx_payloads_agent_section_ts`, `idx_payloads_received`, `idx_payloads_section`, `idx_nonce_exp`

### 2.2 intel.db

| Table               | UNIQUE constraint                 | Purpose                         |
|---------------------|-----------------------------------|---------------------------------|
| `findings`          | `(agent_id, category, item_key)`  | Detection results + SOC workflow|
| `findings_fts`      | FTS5 content table                | Full-text search                |
| `correlations`      | `(agent_id, rule_id)`             | Multi-signal attack chains      |
| `soc_activity`      | —                                 | Analyst action audit log        |
| `soc_comments`      | —                                 | Per-finding analyst notes       |
| `soc_actions`       | —                                 | Remediation action tracking     |
| `nvd_cve_local`     | PK `cve_id`                       | NVD mirror for offline lookups  |
| `nvd_cve_fts`       | FTS5                              | Package keyword search          |
| `org_settings`      | PK `key`                          | Platform + org configuration    |
| `settings_audit`    | —                                 | Settings change history         |
| `asset_registry`    | `(agent_id, asset_type, name)`    | Enriched asset inventory        |
| `cisa_kev`          | PK `cve_id`                       | CISA Known Exploited Vulns      |
| `epss_scores`       | PK `cve_id`                       | EPSS exploit probability        |
| `ai_analysis`       | `(finding_id, os_type)`           | Cached AI remediation responses |
| `remediation_plans` | `(agent_id, finding_id)`          | Generated remediation plans     |

Migrations: `_SOC_MIGRATIONS` list + external_id backfill (indexer.py:526-539)

---

## 3. API Inventory (all 40+ endpoints)

| Auth Level | Endpoints |
|------------|-----------|
| Per-agent HMAC | `POST /ingest` |
| X-Admin-Token  | `GET/POST/PATCH/DELETE /keys/*` |
| Enrollment token (optional) | `POST /enroll` |
| **NONE** ⚠️ | All other 35+ endpoints |

Full endpoint list:

```
GET  /health                              # DB ping + store stats
WS   /ws/{agent_id}?token=               # Live telemetry push

POST /api/v1/ingest                       # [HMAC auth] Agent telemetry
POST /api/v1/enroll                       # [Token optional] Agent registration

GET  /api/v1/agents                       # All agents + online status
GET  /api/v1/agents/{id}                  # Agent detail + sessions
GET  /api/v1/agents/{id}/sections         # Section freshness
GET  /api/v1/agents/{id}/{section}        # Time-series data

GET/POST/PATCH/DELETE /api/v1/keys/*      # [Admin auth] Key management

GET  /api/v1/soc/dashboard                # KPIs, charts, SLA data
GET  /api/v1/soc/sla                      # SLA breach report
GET  /api/v1/soc/findings                 # Findings list (all filters)
GET  /api/v1/soc/findings/{id}            # Finding detail
PATCH /api/v1/soc/findings/{id}           # Update status/assignee/notes
POST /api/v1/soc/findings/{id}/close      # Quick close
POST /api/v1/soc/findings/{id}/accept-risk
POST /api/v1/soc/findings/{id}/false-positive
POST /api/v1/soc/findings/{id}/reopen
POST /api/v1/soc/findings/{id}/open
GET/POST /api/v1/soc/findings/{id}/comments
GET  /api/v1/soc/findings/{id}/activity
POST /api/v1/soc/bulk                     # Bulk action (max 200)
GET  /api/v1/soc/metrics                  # MTTR, WoW, FP rate
GET  /api/v1/soc/historical               # 6-month trend

GET  /api/v1/threat/intel/dashboard       # Threat intel overview
GET  /api/v1/threat/intel/actors          # Threat actor profiles
GET  /api/v1/threat/intel/news            # Security news feed
GET  /api/v1/threat/intel/kev             # CISA KEV list
GET  /api/v1/threat/intel/epss/top        # Top EPSS scores

GET  /api/v1/raw/agents                   # Agents with telemetry
GET  /api/v1/raw/sections                 # Available sections
GET  /api/v1/raw/count                    # Record count (⚠️ loads 1M rows)
GET  /api/v1/raw/query                    # Paginated telemetry explorer

GET  /api/v1/assets                       # Asset inventory
GET  /api/v1/assets/{id}                  # Asset detail
GET  /api/v1/assets/topology              # Network topology

GET  /api/v1/posture/agents               # CIS scores all agents
GET  /api/v1/posture/{agent_id}           # Full CIS benchmark report

GET  /api/v1/detection/{summary,packages,ports,persistence,network,processes,all}

GET  /api/v1/accuracy/report              # Precision/calibration/FP metrics

GET  /api/v1/settings                     # Org settings + license + roles
PUT  /api/v1/settings                     # Update settings
GET  /api/v1/settings/license             # License status
GET  /api/v1/settings/roles               # Role matrix
GET  /api/v1/settings/audit               # Change history
GET  /api/v1/settings/export              # ⚠️ Unmasked export
POST /api/v1/settings/reset               # Factory reset
POST /api/v1/settings/import              # Restore from export

GET/POST /api/v1/remediation/*            # AI-generated remediation plans
GET  /api/v1/attacklens/*                 # Detection engine endpoints
GET  /api/v1/dashboard/ws-token           # ⚠️ EXPOSES MASTER API KEY
```

---

## 4. Test Results

Environment: Python 3.13.7, pytest 9.0.2, pytest-asyncio 1.3.0

| Suite | Collected | Pass | Fail | Error |
|-------|-----------|------|------|-------|
| `tests/unit/test_auth.py` | 7 | **7** | 0 | 0 |
| `tests/unit/test_enroll_api.py` | 13 | 1 | **12** | 0 |
| `tests/integration/test_ingest.py` | 10 | 0 | 0 | **10** |
| `tests/integration/test_attacklens_pipeline.py` | 40 | 0 | 0 | **40** |
| **Total** | **70** | **8** | **12** | **50** |

### Root causes

**Unit failures** — `MockDB.upsert_agent_key` signature stale:
```
TypeError: MockDB.upsert_agent_key() got an unexpected keyword argument 'expires_at'
```
Production signature (`db.py:163`): `(agent_id, key_hex, enrolled_ip, expires_at=None, label=None)`
Mock signature (`test_enroll_api.py:39`): only accepts `enrolled_ip`
→ Fix: update mock to match production signature.

**Integration errors** — hard `import aio_pika` at module level even when RabbitMQ not configured:
```
ModuleNotFoundError: No module named 'aio_pika'
```
`server.py:40` unconditionally imports `QueueProducer` which imports `aio_pika`.
→ Fix: lazy import inside the `if rabbitmq_url:` branch.

### What the passing tests prove
`test_auth.py` validates all security-critical crypto guarantees:
- Valid envelope round-trip ✓
- Missing field rejection ✓
- Timestamp window ±300 s ✓
- HMAC tamper detection (constant-time `hmac.compare_digest`) ✓
- Nonce replay rejection ✓

---

## 5. Edge Cases & Issues Found

### CRITICAL

| ID | Component | Issue |
|----|-----------|-------|
| **C1** | All routers except `/keys`, `/ingest`, `/enroll` | **No authentication** on 35+ endpoints. SOC mutations, settings reset, AI calls, bulk finding close — all unauthenticated. |
| **C2** | `server.py:365-368` `/dashboard/ws-token` | Returns master `API_KEY` in plaintext to anonymous callers. |
| **C3** | `server.py:279` | `OPEN_ENROLLMENT=true` by default — any host can self-enroll as a trusted agent. |
| **C4** | `server.py:125-137` | `CORS_ORIGINS="*"` + `allow_credentials=True` — broken combination; explicitly enables CORS for every origin. |

### HIGH

| ID | Component | Issue |
|----|-----------|-------|
| **H1** | `api/raw.py:73-93` | `/raw/count` loads up to 1,000,000 rows just to call `len()`. Replace with `SELECT COUNT(*)`. |
| **H2** | `db.py:469` | `data LIKE '%term%'` — full table scan on 380 MB payloads table. User-controlled, effectively a DoS vector. |
| **H3** | `indexer.py:1176` | `bulk_update_findings` = N×1 loop: one UPDATE + COMMIT per id while holding write lock. 200 items = ~200 serialised COMMITs starving every other writer. |
| **H4** | `store.py:338` | Append = decompress entire file → add line → recompress. Three tiers per event. O(n²) recompression. |
| **H5** | `api/ingest.py:97` | Rate limit applied to **unauthenticated** envelope `agent_id`. Attacker can deny service to any agent by spoofing its ID. |
| **H6** | `server.py:375-378` | No `API_KEY` set → every WebSocket connection accepted with no auth. |
| **H7** | `server.py:377` | `token.lower() == master.lower()` — non-constant-time compare on a 256-bit secret. |
| **H8** | `db.py:130` | Nonce `DELETE` runs inside the write lock on every single ingest request. |
| **H9** | `api/settings.py:474` | `GET /settings/export` returns unmasked `license_key` to anonymous callers. |
| **H10** | `indexer.py:506` | `self._conn = self._pool._write_conn` — 24+ call sites bypass the pool write lock. Concurrent writes can interleave transactions. |

### MEDIUM

| ID | Issue |
|----|-------|
| **M1** | `update_finding` accepts any status without transition validation. Illegal state jumps (e.g., `verified→new`) leave `closed_at` stale. |
| **M2** | `get_soc_findings` FTS JOIN has triply-nested subquery for agent name. |
| **M3** | `pool._maybe_gc` inspects `sem._value` (private asyncio API). |
| **M4** | `api/keys.py:40` admin token compare is `!=` not `hmac.compare_digest`. |
| **M5** | `crypto.py:131-138` error messages include raw exception text, leaked back as 401 detail. |
| **M6** | `chunk_tracker.py:54` late chunks after TTL expiry re-fire correlation. |
| **M7** | `store._prune_dir` cutoff math off-by-one — can delete current-day bucket at UTC midnight. |
| **M8** | 7-day dashboard trend runs 7 separate SQL queries; one GROUP BY query would suffice. |

### LOW / INFO

| ID | Issue |
|----|-------|
| **L1** | No `AbortController` on in-flight fetches in 9 React pages — unmount races. |
| **L2** | `useCountUp` animates every 30 ms per tile; use `requestAnimationFrame`. |
| **L3** | `patchFinding` / `bulkAction` errors swallowed silently — no user toast. |
| **L4** | App uses `useState` routing instead of `react-router` — no deep links or browser back. |
| **L5** | No code splitting; all 15 pages loaded eagerly on first paint (~1 MB JS). |
| **L6** | `aio_pika` is a hard import even when RabbitMQ not configured. |

---

## 6. Security Findings

| Category | Finding | Severity |
|----------|---------|----------|
| Auth bypass | 35+ unauthenticated data-plane endpoints | CRITICAL |
| Credential disclosure | `/ws-token` exposes master key | CRITICAL |
| Open enrollment | Default permits any host to enroll | CRITICAL |
| CORS misconfiguration | Wildcard + credentials | CRITICAL |
| Unmasked secret | `/settings/export` reveals license_key | HIGH |
| WS auth bypass | No master key → accept all WS | HIGH |
| Timing attack | Non-constant-time WS token + admin token comparison | HIGH |
| DoS — hot path | Nonce cleanup DELETE on every ingest | HIGH |
| DoS — agent starvation | Rate limit on unauthenticated agent_id | HIGH |
| DoS — memory | `/raw/count` loads 1M rows | HIGH |
| SQL DoS | `LIKE '%x%'` on 380 MB table, user-controlled | HIGH |
| **Crypto** (GOOD) | AES-256-GCM + HKDF + HMAC-SHA256 + `hmac.compare_digest` on crypto paths | ✅ Correct |
| **TLS** (GOOD) | HTTPS/8443 + Caddy in docker-compose | ✅ OK |
| **SQL injection** (GOOD) | All user values via `?` placeholders; sort/column names via allowlists | ✅ Safe |

---

## 7. Performance Findings

| ID | Issue | Impact |
|----|-------|--------|
| **P1** | Three-tier recompress-on-append per event | CPU saturation at scale |
| **P2** | `/raw/count` loads 1M rows for `len()` | OOM risk |
| **P3** | `bulk_update_findings` N+1 commits | Write lock starvation |
| **P4** | Nonce cleanup on hot ingest path | Write lock starvation |
| **P5** | 18+ sequential queries in `get_dashboard_stats` | Dashboard latency |
| **P6** | Triply-nested agent-name subquery in FTS path | Index miss |
| **P7** | Engine spawns unbounded tasks per payload | Memory pressure at burst |
| **P8** | `_nvd_worker` queue maxsize=200 drops silently | Lost enrichment |

---

## 8. Frontend Quality

19 page components, ~13,400 lines TypeScript/React.

**Good patterns**: explicit typed interfaces per page, loading/error states, 30-60s auto-refresh with cleanup, debounced search, optimistic localStorage updates.

**Issues**:

| ID | File | Issue |
|----|------|-------|
| F1 | 9 pages | No `AbortController` — setState on unmounted component |
| F2 | Dashboard, ThreatQueue | `useCountUp` fires every 30ms; use rAF |
| F3 | ThreatQueue | Fetch errors silently swallowed, no toast |
| F4 | DeepAnalysis | Error detail only shows HTTP code, not message |
| F5 | App.tsx | No react-router — no deep links, no back button |
| F6 | App.tsx | No code splitting; all pages in one 1MB chunk |
| F7 | Sidebar.tsx | `_conn` direct usage pattern spread across API layer |
| F8 | Multiple | `setInterval` patterns without Page Visibility guard |

---

## 9. Work Completed Summary

### Backend

| Area | What was built |
|------|----------------|
| Ingest pipeline | Envelope verify, HMAC+AES-GCM, per-agent rate limit, nonce dedup, sync + queue modes |
| Key management | Enrollment, rotate, expire, revoke, delete, admin-gated |
| Three-tier store | Hot/warm/cold NDJSON.gz with file index, cleanup, promotion |
| Detection engine | 12 section analyzers, rule library, allowlist, behavioral baseline (Welford), correlation, MITRE mapping |
| Threat intel | Feodo, ET, ThreatFox feeds, NVD mirror+FTS, CISA KEV, EPSS, IOC cache |
| SOC workflow | 10-state findings, comments, activity log, SLA, bulk actions, MTTR/WoW, historical trend |
| Asset registry | Enriched from telemetry, subnet topology |
| Posture/CIS | 15+ macOS benchmark checks |
| Settings | Org profile, license ring, RBAC matrix, audit log, export/import/reset |
| AI analyst | Anthropic Claude integration, finding analysis, cached remediation plans |
| Email notifier | Notification hooks (SMTP-configured) |
| WebSocket hub | Live dashboard push |
| Queue path | RabbitMQ producer/consumer with DLQ, prefetch, chunked fan-out |
| NVD sync | Bulk CVE sync worker with optional API key |

### Frontend (15 pages)

Dashboard · ThreatQueue (Findings) · ExecutionThreats · NetworkThreats ·
VulnerabilitySurface · PersistenceBackdoors · IdentityAccess · SecurityPosture ·
CISCompliance · ThreatIntelligence · Timeline · AssetRegistry · DeepAnalysis ·
DetectionAccuracy · Settings

Plus: Sidebar (live agent fleet + new-finding badges) · TopHeader (RBAC + clock) ·
RBAC context · Detection shared blueprint · Component library

---

## 10. Recommendations (Prioritised)

### Must fix before production

1. **Add auth to all data-plane routes** — FastAPI `Depends` with Bearer token or admin header
2. **Remove or auth-gate `/ws-token`** — never return the master key over HTTP
3. **Default `OPEN_ENROLLMENT=false`** — require `ENROLLMENT_TOKENS` at startup
4. **Lock CORS** — reject `CORS_ORIGINS=*` in production
5. **Gate `/settings/export`** with admin auth
6. **Constant-time compare** on WS token and admin token (`hmac.compare_digest`)
7. **Reject WS when no API_KEY set** — fail closed

### High priority reliability

8. Fix `/raw/count` — `SELECT COUNT(*)` query
9. Move nonce cleanup off hot path — 60 s background sweep with LIMIT
10. Rewrite `bulk_update_findings` — single batched UPDATE + executemany activity
11. Fix `aio_pika` import — lazy inside `if rabbitmq_url:` block
12. Fix `MockDB.upsert_agent_key` mock — update to match production signature

### Architecture cleanup

13. Add state-machine transition validation in `update_finding`
14. Encapsulate all `intel_db._conn` writes inside IntelDB methods (through pool lock)
15. Add `AbortController` to all React fetch hooks
16. Add Page Visibility guard to auto-refresh intervals
17. Add code splitting (`React.lazy`) per page
18. Adopt `react-router` for proper URL navigation

---

## Appendix — Key File Reference

```
manager/manager/server.py              FastAPI app factory + router mounting
manager/manager/api/ingest.py          Ingest endpoint + rate limiting
manager/manager/api/enroll.py          Agent enrollment
manager/manager/api/keys.py            Key management (admin-gated)
manager/manager/api/findings.py        SOC workflow + bulk actions
manager/manager/api/settings.py        Org settings + audit
manager/manager/api/raw.py             Raw telemetry explorer
manager/manager/api/agents.py          Agent registry
manager/manager/api/posture.py         CIS benchmark
manager/manager/api/detection.py       Detection category views
manager/manager/api/accuracy.py        Precision/calibration metrics
manager/manager/api/threat.py          Threat intelligence feeds
manager/manager/api/assets.py          Asset registry
manager/manager/api/remediation.py     AI remediation plans
manager/manager/api/attacklens.py      Detection engine API
manager/manager/db.py                  manager.db pool + queries
manager/manager/indexer.py             intel.db pool + all intel queries
manager/manager/store.py               Three-tier NDJSON.gz store
manager/manager/index.py               TelemetryIndex SQLite
manager/manager/pool.py                SQLitePool (4 readers + 1 writer)
manager/manager/crypto.py              AES-256-GCM + HMAC-SHA256
manager/manager/auth.py                Envelope verify + replay check
manager/manager/chunk_tracker.py       Chunked payload correlation gate
manager/manager/ws_hub.py              WebSocket broadcast hub
manager/manager/ai_analyst.py          Anthropic Claude integration
manager/manager/attacklens/engine.py   12-section detection engine
manager/manager/queue/producer.py      RabbitMQ producer (aio_pika)
manager/manager/workers/               Telemetry/AttackLens/Intel workers
manager/tests/unit/test_auth.py        ✅ 7/7 PASS — crypto guarantees
manager/tests/unit/test_enroll_api.py  ❌ 12 FAIL — stale mock
manager/tests/integration/             ❌ 50 ERROR — aio_pika missing
```

---

*Generated by automated architecture audit + manual code review · AttackLens v1.0*
