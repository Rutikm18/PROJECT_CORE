# AttackLens — Solution Implementation Log

> Every task is documented here as it's completed.  
> Format per task: **What**, **Why**, **Algorithm/Design**, **Files Changed**, **API contracts**.

---

## Task 1 — Multi-Agent System Design

**Date:** 2026-05-13  
**Status:** ✅ Complete

### Problem
The existing codebase had four critical architectural issues:
1. `Database` opened a new aiosqlite connection per SQL call — O(n) connection overhead at scale
2. `IntelDB` had a single `asyncio.Lock` serialising ALL reads AND writes — massive bottleneck
3. Nonce cache was in-memory only — replay attacks possible across restarts
4. No rate limiting — one agent could flood the ingest endpoint and starve others
5. CORS `*` in production — security gap
6. No production HA path (single instance, no load balancer)

### Solution

#### 1. `manager/manager/pool.py` (NEW)

`SQLitePool` — persistent connection pool using asyncio.Queue as a semaphore-based LIFO stack:
- **Readers**: N persistent aiosqlite connections checked out via `asyncio.Queue`. SQLite WAL mode allows truly concurrent reads across connections.
- **Writer**: 1 persistent connection protected by `asyncio.Lock`. SQLite serialises writers at the C level anyway; holding the lock prevents Python-level contention.
- **Pragmas per connection**: `WAL`, `NORMAL` sync, 64MB cache, `mmap_size=256MB`, `busy_timeout=5000ms`

`TokenBucket` — O(1) rate limiter per agent:
- Refills at `rate` tokens/second, capped at `capacity`
- No background goroutine — lazy refill on each `consume()` call
- Stores `_last` timestamp (monotonic), computes `elapsed * rate` tokens added

`AgentRateLimiter` — combines TokenBucket + asyncio.Semaphore per agent:
- `check_rate()` — token bucket check, returns False if limit exceeded → HTTP 429
- `agent_slot()` — asynccontextmanager, acquires semaphore with timeout → HTTP 429 if queue full
- GC every 5 minutes: evicts idle agents from dicts to bound memory growth

#### 2. `manager/manager/db.py` (REWRITTEN)

- `Database.__init__` creates `SQLitePool(readers=4)`
- `Database.init()` calls `pool.init()` then runs schema + migrations
- All reads use `async with self._pool.read() as db:` — concurrent
- All writes use `async with self._pool.write() as db:` — serialised
- `nonce_cache` table added to schema — DB-backed nonce dedup survives restarts
- `check_and_store_nonce()` — atomic INSERT with UNIQUE constraint; cleans expired nonces inline
- Added `query_payloads()` and `get_distinct_sections()` for Deep Analysis module

#### 3. `manager/manager/indexer.py` (PATCHED)

Bridge migration (minimal risk):
- Added `SQLitePool(readers=3)` in `init()`
- Aliased `self._conn = self._pool._write_conn` — all existing write code unchanged
- `_fetchone()` and `_fetchall()` now use `async with self._pool.read()` — concurrent reads
- Result: dashboard stats, FTS5 searches, finding queries now run concurrently instead of serialised

#### 4. `manager/manager/api/ingest.py` (REWRITTEN)

New pipeline order: parse → schema → timestamp → **rate limit** → **concurrency slot** → key lookup → decrypt → **DB nonce check** → extract → upsert → queue/sync

- Rate limit: `rate_limiter.check_rate(agent_id)` → 429 with `Retry-After: 1` header
- Concurrency: `async with rate_limiter.agent_slot(agent_id, timeout=8.0)` → 429 if full
- Nonce: `db.check_and_store_nonce(nonce, REPLAY_WINDOW_SECONDS)` → DB-backed, restart-safe

#### 5. `manager/manager/server.py` (PATCHED)

- `AgentRateLimiter` instantiated at startup, wired into `make_ingest_router()`
- CORS: explicit `allow_methods` and `allow_headers` lists; origins default to `[]` (same-origin) unless `CORS_ORIGINS` env is set
- `await db.close()` added to shutdown sequence
- Old in-memory nonce eviction task removed
- Env vars: `AGENT_RATE`, `AGENT_BURST`, `AGENT_SLOTS`

#### 6. `nginx/nginx.conf` (NEW)

Production TLS load balancer:
- HTTP → HTTPS redirect
- `upstream manager_http` — `least_conn` for stateless API requests
- `upstream manager_ws` — `ip_hash` for sticky WebSocket sessions (same agent always hits same replica)
- `limit_req_zone` — nginx-level DDoS protection (50 req/s ingest, 100 req/s API)
- `limit_conn_zone` — max 50 concurrent connections per IP
- TLS: TLSv1.2+, ECDHE ciphers, HSTS 1 year, session cache
- Security headers: `X-Frame-Options DENY`, `X-Content-Type-Options nosniff`, `Referrer-Policy`
- WS proxy: `proxy_read_timeout 3600s`, buffering disabled for real-time events

#### 7. `docker-compose.ha.yml` (NEW)

Active-active HA:
- `manager-1` + `manager-2`: both mount the same `manager_data` named volume (shared SQLite DB)
- `rabbitmq`: HA message queue, health-checked before managers start
- `nginx`: routes traffic across both replicas
- `internal` network: managers + RabbitMQ cannot reach internet directly
- `external` network: only nginx faces public traffic

### Failure Modes Handled

| Failure | Behaviour |
|---------|-----------|
| Manager crash | Nginx health checks remove it from upstream in ≤5s; RabbitMQ holds unprocessed messages |
| Manager restart | DB-backed nonces prevent replay; agents re-enrol automatically |
| RabbitMQ restart | Workers reconnect with exponential back-off (5s → 60s max) |
| Single agent flood | Token bucket (10 req/s) + semaphore (4 concurrent) blocks it; other agents unaffected |
| DB write contention | SQLitePool write lock; WAL allows concurrent reads during writes |
| CORS abuse | Explicit origin whitelist via `CORS_ORIGINS` env |

---

## Task 2 — Raw Data / Deep Analysis Module

**Date:** 2026-05-13  
**Status:** ✅ Complete — Build verified (Vite production build: 1624 modules, 0 errors)

### Problem
The existing `RawDataPage` was a static mock with hardcoded dropdowns and zero API integration. No real data, no filtering, no search.

### Solution

#### 1. `manager/manager/api/raw.py` (NEW)

Four REST endpoints mounted at `/api/v1/raw`:

```
GET /api/v1/raw/agents          → list all agents (id + name + last_seen + status)
GET /api/v1/raw/sections        → distinct sections, optionally filtered by agent_id
GET /api/v1/raw/query           → paginated payload query with all filters
GET /api/v1/raw/count           → total count for current filter set (for pagination)
```

Query params for `/query` and `/count`:
- `agent_id` — filter to one agent
- `section` — filter to one data section (processes, connections, packages, etc.)
- `start` / `end` — Unix timestamps for time window
- `search` — substring search against JSON payload body
- `limit` / `offset` — pagination (default limit 200)

**Search algorithm:**
- Primary: `data LIKE '%search%'` — SQLite index-scan on `idx_payloads_agent_section_ts`
- For pure time+agent+section queries: covered by composite index `(agent_id, section, collected_at DESC)` — O(log n) lookup
- For large datasets (>1M rows): the `idx_payloads_received` and `idx_payloads_section` indexes added in Task 1 enable section-wide queries without full scans

**Security:** No auth required for read (same as other API routes); admin-only routes use `ADMIN_TOKEN`.

#### 2. `DeepAnalysis.tsx` (NEW — replaces static `RawDataPage`)

**Features:**
- Agent selector dropdown (populated from API)
- Section/category selector (populated from API, filtered by selected agent)
- Time range presets: Last 5m / 1h / 6h / 24h / 7d / Custom
- Free-text search field with 300ms debounce
- Live record count badge
- Paginated data table: timestamp, agent, section, record count, JSON preview (first 120 chars)
- Row click → JSON detail panel (formatted, scrollable)
- Auto-refresh every 30s (paused when detail panel is open)
- Empty state, loading skeleton, error handling

**State management:** `useState` + `useEffect` + `useCallback` (no external state library needed for this complexity level).

**API integration:** All data from real endpoints. Zero hardcoded mock data.

#### 3. `App.tsx` (PATCHED)
- Removed static `RawDataPage` function
- Imported `DeepAnalysis` from new file
- Wired `"raw-data"` route to `<DeepAnalysis />`

#### 4. `Sidebar.tsx` (PATCHED)
- "Raw Data" label → "Deep Analysis" to match the module's actual purpose

### Index Strategy for Large Data

```sql
-- Already exists (Task 1 additions):
idx_payloads_agent_section_ts  ON payloads(agent_id, section, collected_at DESC)
idx_payloads_received          ON payloads(received_at DESC)
idx_payloads_section           ON payloads(section, collected_at DESC)

-- Query plan for typical filter (agent + section + time range):
--   Uses idx_payloads_agent_section_ts → O(log n + k) where k = result rows
--   No full table scan even with millions of payload rows
```

---

## Task 3 — Asset Registry Module

**Date:** 2026-05-13  
**Status:** ✅ Complete — Vite build clean (0 errors, 1624 modules)

### Problem
Static mock data — hardcoded agents, no real system info, no MAC/RAM/battery/process data, no topology view.

### Solution

#### 1. `manager/manager/db.py` — `get_latest_section_per_agent(section)` (NEW method)

One SQL query for ALL agents' latest payload for any section (metrics, battery, network, etc.):
```sql
SELECT p.agent_id, p.data FROM payloads p
INNER JOIN (SELECT agent_id, MAX(collected_at) FROM payloads WHERE section=? GROUP BY agent_id) latest
ON p.agent_id=latest.agent_id AND p.collected_at=latest.max_ts AND p.section=?
```
O(n log n) via covered index. Called 6 times concurrently via `asyncio.gather` — total latency = single slowest query, not sum.

#### 2. `manager/manager/api/assets.py` (NEW) — 3 endpoints

**`GET /api/v1/assets`** — Enriched list. 6 concurrent batch queries:
- `get_all_agents()` → identity + last_seen + last_ip
- `intel_db.list_assets()` → asset_registry meta (tier, owner, department, importance)
- `get_latest_section_per_agent("metrics")` → cpu_percent, mem_percent, mem_total_mb, mem_available_mb, cpu_cores, cpu_freq_mhz, load_1m/5m, uptime_sec
- `get_latest_section_per_agent("battery")` → charge_pct, charging, condition, cycle_count
- `get_latest_section_per_agent("network")` → primary IP + MAC via `_extract_primary_interface()` (prefers en0→en1→eth0→first valid)
- `get_latest_section_per_agent("processes")` → process_count

**`GET /api/v1/assets/topology`** — Subnet grouping + ARP peers:
- Groups assets by /24 subnet (first 3 IP octets)
- Returns ARP table peers (other hosts seen on LAN) for diagram edge data

**`GET /api/v1/assets/{agent_id}`** — Full single-asset detail:
- All of the above + storage, users, sessions, findings summary

#### 3. `AssetRegistry.tsx` (REWRITE — real data, two views)

**Table view:**
- Columns: hostname/agent_id, OS, IP+MAC (2 lines), CPU bar, RAM bar + used/total, battery icon + %, process count, uptime, tier badge, last seen
- Detail panel on row click: full system info in sections (Identity, Network, CPU, Memory, Battery)
- Filter bar: free-text search across hostname/IP/MAC/OS/owner
- Tier summary cards at bottom: critical/important/standard with live vs away count

**Topology view (SVG):**
- Assets grouped into /24 subnet bands (alternating background)
- Each asset = circle node with OS emoji icon, status dot, hostname, IP, CPU mini-bar
- ARP-based edges drawn between known LAN peers (dashed lines)
- Selection ring (orange dashed) when node clicked → opens detail panel
- Legend: online/stale/offline color coding
- Pure SVG, no external lib required

### Status thresholds
- `online` = last_seen < 90s
- `stale` = 90–300s (was `healthy` in old mock)
- `offline` = >300s

---

## Task 4 — Threat Intelligence Module

**Date:** 2026-05-14
**Status:** ✅ Complete — Vite build clean (0 errors)

### Problem
`ThreatIntelligence.tsx` was 100% static mock data. No real CVEs, no real feeds, no actors, no news.

### Solution

#### 1. `manager/manager/api/threat.py` — 5 new endpoints

**`GET /api/v1/threat/intel/dashboard`** (primary UI endpoint):
- Fetches 9 data sources concurrently via `asyncio.gather`: feeds, NVD stats, KEV count, actor count, top CVEs, recent KEV entries, threat actors, security news, IP IOC count
- Adds EPSS top scores via direct `_fetchall` query
- Enriches each CVE with `is_kev` flag + `epss` score + `_priority_label()` — a human-readable priority string combining CVSS + KEV + EPSS
- `_priority_label()` logic: "CRITICAL – Actively Exploited" (KEV), "CRITICAL – High Exploit Probability" (CVSS≥9 + EPSS≥50%), "HIGH – Patch Immediately", etc.

**`GET /api/v1/threat/intel/actors`** — threat actor list (active_only filter)  
**`GET /api/v1/threat/intel/news`** — recent security news (hours window + limit)  
**`GET /api/v1/threat/intel/kev`** — CISA KEV list  
**`GET /api/v1/threat/intel/epss/top`** — top EPSS exploitability scores  

#### 2. `ThreatIntelligence.tsx` — Complete rewrite (real data, 6 panels)

**KPI strip (5 cards):** KEV count · NVD total + critical count · Threat actors · IOC cache size · Active feeds / total feeds

**CVE Table** (`CVETable`):
- Columns: CVE-ID (with KEV badge) · Severity · CVSS score (colour-coded) · EPSS bar + % · Priority label · Published date
- Click-to-expand: shows full description + CWE IDs
- Empty state: "NVD sync pending" message

**KEV Panel** (`KEVPanel`):
- Red left-border cards for each CISA KEV entry
- Shows: CVE-ID · vulnerability name · vendor/product · date added · due date · required action

**Feed Health** (`FeedPanel`):
- Table: source name · entry count · last updated · status dot (live/ok/error/degraded)
- Error count shown inline when >0

**Threat Actors** (`ActorsPanel`):
- Grouped by active status with pulsing red dot
- Shows: name · aliases · description · countries · TTP technique tags

**Security News** (`NewsPanel`):
- Cards with: source badge · severity badge · title · summary · CVE references · external link

**Data handling:**
- `parseJsonArr()` safely handles both JSON strings and arrays from DB
- All panels have empty states with descriptive messages (what to do to get data)
- Auto-refreshes every 60s

---

## Task 5 — Security Posture Module

**Date:** 2026-05-14
**Status:** ✅ Complete — Vite build clean (0 errors)

### Problem
`SecurityPosture.tsx` used 100% hardcoded control data. No real agent checks, no actual SIP/FileVault/Gatekeeper values.

### Solution

#### 1. `manager/manager/api/posture.py` (NEW) — CIS Benchmark engine

**16 checks mapped to real agent payload fields:**

| ID | Check | Data Source | CIS Control |
|---|---|---|---|
| SIP | System Integrity Protection | `security.sip` | 4 |
| FV2 | FileVault Encryption | `security.filevault` | 3 |
| GK | Gatekeeper | `security.gatekeeper` | 4 |
| FW | Application Firewall | `security.firewall` | 12 |
| SB | Secure Boot | `security.secure_boot` | 4 |
| AU | Auto Updates | `security.auto_update` | 7 |
| SCR | Screensaver Lock | `security.screensaver_lock` | 4 |
| STO | Screensaver Timeout ≤5min | `security.screensaver_idle_sec` | 4 |
| SSH | SSH Password Auth | `security.remote_login + ssh_password_auth` | 5 |
| SRL | SSH Root Login | `security.ssh_permit_root_login` | 5 |
| SCN | Screen Sharing | `security.screen_sharing` | 4 |
| ARD | Apple Remote Desktop | `security.remote_management` | 4 |
| XP | XProtect Updated | `security.xprotect_version` | 10 |
| CFG | No Suspicious Configs | `configs[].suspicious` | 4 |
| DT | Developer Tools | `security.dev_tools` | 4 |
| LM | Lockdown Mode | `security.lockdown_mode` | 4 |

**Score algorithm:** Weighted sum by severity (critical=10, high=6, medium=3, low=1). WARN = 0.5 × weight. Unknown checks excluded from denominator. Score 0–100 → Grade A/B/C/D/F.

**Scale architecture:**
- `GET /api/v1/posture/agents` — 3 batch queries (security+sysctl+configs), Python-side check evaluation, O(1) regardless of agent count
- `GET /api/v1/posture/{agent_id}` — per-agent full report with groups + suspicious configs + sysctl security params

#### 2. `SecurityPosture.tsx` — Two-view design

**Overview (all agents):**
- Sorted worst-first by score
- Stacked bar (green/amber/red) per agent showing pass/warn/fail ratio
- Score number + grade letter colour-coded to A–F scale
- Click any row → load detail for that agent

**Detail (one agent):**
- SVG score gauge (circular arc, 0–100)
- CIS group breakdown: stacked bar per group (CIS-3 Data Protection, CIS-4 Secure Config, etc.)
- Failing checks summary strip (all fail badges at a glance)
- Status filter buttons: All / FAIL / WARN / PASS / N/A
- Expandable check rows: click to see actual value + remediation step (amber box)
- Suspicious config panel: shows flagged files with content preview
- Notable sysctl security params table

---

## Task 6 — Detection Module

**Date:** 2026-05-14
**Status:** ✅ Complete — Vite build clean (0 errors, 1626 modules)

### Problem
All four detection pages (VulnerabilitySurface, NetworkThreats, PersistenceBackdoors, ExecutionThreats) were 100% static mocks with hardcoded findings. No real Jarvis engine output shown.

### Solution

#### 1. `manager/manager/api/detection.py` (NEW) — 6 endpoints

All read from the `findings` table in `intel.db` (populated by the Jarvis engine):

| Endpoint | Categories | Notes |
|---|---|---|
| `/summary` | all | Counts per category+severity; used for sidebar badges |
| `/packages` | package | CVE findings: CVSS + EPSS + KEV + risk score + action plan |
| `/ports` | port | Open-port threat findings |
| `/persistence` | service, task, config, binary | Concurrent gather of 4 categories, merged + sorted |
| `/network` | connection | Feed-confirmed IOC matches |
| `/processes` | process, app | Concurrent gather, merged |
| `/all` | all | Full SOC findings view with all filters |

Each finding enriched by `_enrich()`: parses JSON fields (evidence, action_plan, cve_ids), adds `confidence_pct` (source→confidence lookup), `impact` (category-specific), `cat_meta`, `sla_status`.

**Source→confidence mapping**: `feed:feodo=0.97`, `nvd=0.88`, `rule:process_lineage=0.88`, `abuseipdb=0.78`, `rule:risky_package=0.72`, `behavioral=0.70`.

#### 2. `DetectionShared.tsx` (NEW) — shared detection infrastructure

- `useDetectionData(url)` — fetch + 30s auto-refresh hook
- `DetectionFilters` — agent / severity / search filter bar with 300ms debounce
- `SevBadge`, `SlaBadge` — consistent severity + SLA status chips
- `FindingDetail` — full right-panel: scores, validation, description, impact, remediation steps, evidence JSON
- `GenericDetectionPage` — drop-in page template: takes `columns[]` array for custom cell renderers

#### 3. Four detection pages rewritten

All use `GenericDetectionPage` or `useDetectionData` directly:
- `VulnerabilitySurface.tsx` — CVSS, EPSS, KEV columns
- `NetworkThreats.tsx` — feed source chip, confidence, risk score
- `PersistenceBackdoors.tsx` — sub-type chip (service/task/config/binary), rule ID
- `ExecutionThreats.tsx` — category, confidence, risk score, rule ID

## Task 6.1 — Detection Accuracy & Calibration

**Date:** 2026-05-14
**Status:** ✅ Complete — Vite build clean

### Problem
No visibility into whether Jarvis detection rules are producing accurate findings vs generating false positives. No way to check calibration or correlation integrity.

### Solution

#### 1. `manager/manager/api/accuracy.py` (NEW) — 4 endpoints

**`GET /api/v1/accuracy/report`** — comprehensive accuracy report:
- Fetches all active findings (limit 5000) + correlations concurrently
- Computes 5 analysis dimensions: source stats, category stats, validation coverage, FP risk, correlation integrity
- Returns in one call; designed for the UI to render immediately without waterfall requests

**Precision estimation methodology:**
- True Positive proxies: finding source in {feed:feodo, feed:emerging, nvd, abuseipdb} OR kev=True OR epss_score ≥ 0.5
- False Positive proxies: dual-use source AND no TP proxy signal AND confidence < 0.70
- Precision estimate = TP_proxy_count / total (per source and overall)

**`GET /api/v1/accuracy/fp_risk`** — FP candidates with reasons + recommendation

**`GET /api/v1/accuracy/calibration`** — per-source: prior confidence vs observed validation rate. Calibration gap > 20 = rule needs tuning.

**`GET /api/v1/accuracy/correlation`** — correlation chain integrity: verifies each signal in `attack_chain`/`signals` exists as an active finding. Orphaned signals = stale correlations.

#### 2. `Accuracy.tsx` (NEW) — 4-tab accuracy dashboard

- **Overview tab**: source precision table + category precision table + validation coverage bars (KEV/EPSS/feed-confirmed/exploit/unvalidated)
- **Calibration tab**: stacked bar chart (prior vs observed per rule) + full table with calibration_gap and "over_confident/under_confident/well_calibrated" status + action recommendation
- **FP Risk tab**: table of high-risk findings with per-finding reasons and recommendation; green "all clear" state when none
- **Correlation Integrity tab**: summary cards (total/well-supported/orphaned/integrity%) + detail table of chains with orphaned signals

#### 3. Sidebar + routing

- New "Detection Accuracy" item in Management group with `FlaskConical` icon
- `PageId` type extended with `"accuracy"`

---

## Task 7 — Main Dashboard

**Date:** 2026-05-14
**Status:** ✅ Complete — Vite build clean (0 errors)

### Problem
CommandCenter was all static mock data. ThreatQueue had hardcoded findings. No RBAC. No live timestamps. No improvement metrics.

### Solution

#### 1. `findings.py` — `GET /api/v1/soc/metrics` (NEW)
Returns improvement metrics computed from DB:
- `mttr_hours` — mean time to resolve (avg of resolved_at - first_detected_at for findings closed in last 30 days)
- `closed_this_week` / `closed_last_week` + `wow_improvement_pct` — week-over-week closure rate change
- `fp_rate_pct` — false positives / total (last 30 days)
- `accepted_risk` — count of accepted-risk findings
- `actions_this_week` — soc_activity breakdown by action type

#### 2. `RBACContext.tsx` (NEW)
- Three roles: `admin` (full access), `analyst` (update findings + comments), `viewer` (read-only)
- `can(action)` permission check against permission map
- Role persisted in `localStorage`, changeable from TopHeader
- In production: replace `loadRole()` with JWT claim extraction

#### 3. `CommandCenter` in `App.tsx` (REWRITTEN — real data)
Fetches concurrently: `/api/v1/soc/dashboard` + `/api/v1/soc/metrics`

Panels:
- **KPI row**: Active Findings (red if > 0), Critical, SLA Breached, Resolved Today, MTTR (colour-coded by threshold)
- **Finding Distribution**: Severity bar chart (dynamic max scaling) + Status distribution bars
- **7-Day Trend**: Stacked bar chart — critical/high/medium/low segments per day, height-scaled to max day
- **By Category**: Mini bar chart per category
- **Improvement Metrics**: MTTR, closed this week, WoW%, FP rate, accepted risk — all from `/soc/metrics`
- **SLA Compliance**: Per-severity compliance bars with on-time/breached counts
- **Top Agents**: Agents with most findings + critical/high chips

All zero-mock: empty states shown gracefully when no data yet.

#### 4. `ThreatQueue.tsx` (REWRITTEN — full workflow)
Fetches from `/api/v1/soc/findings` with full filter support.

Features:
- **Multi-select checkboxes** + bulk actions (Triage, Resolve, Accept Risk, False Positive)
- **Inline row actions** per finding: Triage → Investigate → Resolve | Accept Risk | Mark FP | Reopen
- **RBAC-gated**: `can("update_finding")`, `can("bulk_action")`, `can("add_comment")` — viewer sees no buttons
- **SLA badge** per row: ok/warning/breached with due timestamp when breached
- **Activity panel** (right side): opens on 🔬 button click — shows soc_activity log + comments with timestamps, plus comment input box for analyst+
- All actions call `PATCH /api/v1/soc/findings/{id}` and are logged to `soc_activity` table with actor + timestamp
- **Dual timestamps**: first_detected_at + last_detected_at per row

#### 5. `TopHeader.tsx` (REWRITTEN)
- Live clock (updates every second) — shows current time in header
- Live indicator (green pulsing dot)
- **RBAC role dropdown**: click to switch admin/analyst/viewer — persists in localStorage
  - Each role shows icon + label + description of permissions
  - Current role shown with ✓ checkmark
- User avatar changes colour by role (red=admin, blue=analyst, gray=viewer)
- Breadcrumb shows current page name (dynamic from `activePage` prop)

---

## Task 8 — UI/UX Color & Theme
*Pending*
