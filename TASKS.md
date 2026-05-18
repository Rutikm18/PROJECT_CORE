# AttackLens Platform — Task Tracker

> **Session recovery file.** If context is lost, resume from the last ✅ task.  
> Platform: **Attack Surface Monitor** (not traditional SOC/SIEM).  
> Stack: FastAPI + SQLite (aiosqlite) backend · React + TypeScript + Tailwind frontend.  
> Root: `manager/manager/` (backend) · `manager/dashboard/templates/Build Smart AttackLens Platform/src/` (frontend)

---

## Priority Order & Status

| # | Task | Status | Key Files |
|---|------|--------|-----------|
| 1 | Multi-Agent System Design | ✅ Done | `pool.py`, `db.py`, `indexer.py`, `api/ingest.py`, `server.py`, `nginx/nginx.conf`, `docker-compose.ha.yml` |
| 2 | Raw Data / Deep Analysis Module | ✅ Done | `api/raw.py`, `DeepAnalysis.tsx`, `App.tsx`, `Sidebar.tsx` |
| 3 | Asset Registry Module | ✅ Done | `api/assets.py`, `db.py` (+batch query), `AssetRegistry.tsx` |
| 4 | Threat Intelligence Module | ✅ Done | `api/threat.py` (+5 endpoints), `ThreatIntelligence.tsx` |
| 5 | Security Posture Module | ✅ Done | `api/posture.py` (16-check CIS engine), `SecurityPosture.tsx` |
| 6 | Detection Module | ✅ Done | `api/detection.py`, `DetectionShared.tsx`, all 4 detection pages |
| 6.1 | Detection Accuracy & Calibration | ✅ Done | `api/accuracy.py`, `Accuracy.tsx` — precision, FP risk, calibration, correlation integrity |
| 7 | Main Dashboard | ✅ Done | `findings.py` (+metrics), `CommandCenter` real data, `ThreatQueue` real workflow, `RBACContext`, `TopHeader` RBAC |
| 8 | UI/UX — Color & Theme | ✅ Done | `theme.css` (14 missing vars), `globals.css` (utility classes), `Sidebar.tsx` (active indicator, visual polish) |

---

## Task Specs

### Task 1 — Multi-Agent System Design ✅
**Goal:** Handle large number of concurrent agents without bottlenecks, failure points, or security gaps.

**Implemented:**
- `manager/manager/pool.py` — `SQLitePool` (WAL, readers=4/3), `TokenBucket` (O(1)), `AgentRateLimiter` (semaphore per agent)
- `manager/manager/db.py` — Full rewrite: pool-backed, DB-backed nonce table (restart-safe), `query_payloads()`, `get_distinct_sections()`
- `manager/manager/indexer.py` — `SQLitePool` readers=3; `_fetchone/_fetchall` are now concurrent reads
- `manager/manager/api/ingest.py` — Token bucket rate limit (10 req/s, burst 30) + per-agent semaphore (max 4 concurrent)
- `manager/manager/server.py` — `AgentRateLimiter` wired, CORS fixed (no more wildcard by default), pool shutdown in `shutdown()`
- `nginx/nginx.conf` — Production TLS load balancer: `/ws/` ip_hash sticky, `/api/v1/ingest` rate zone, upstream health checks
- `docker-compose.ha.yml` — Active-active: nginx + manager-1 + manager-2 + RabbitMQ on shared volume

**Algorithms:** Token bucket · asyncio.Semaphore fair queue · SQLite WAL readers pool · LIFO stack (asyncio.Queue)

---

### Task 2 — Raw Data / Deep Analysis Module ✅
**Goal:** Replace static `RawDataPage` with a real data explorer. Filters: time range, agent, section/category, free-text search. Fast indexing for large datasets.

**Implemented:**
- `manager/manager/api/raw.py` — REST endpoints: `GET /api/v1/raw/agents`, `/sections`, `/query`, `/count`
- `manager/dashboard/templates/.../src/app/pages/DeepAnalysis.tsx` — Full interactive page
- Updated `App.tsx` — removed static `RawDataPage`, imported `DeepAnalysis`
- Updated `Sidebar.tsx` — "Raw Data" → "Deep Analysis"

**Search algorithm:** SQLite FTS5 for text search on payload data; composite index `(agent_id, section, collected_at DESC)` for time-range + filter queries. Debounced input (300ms). Pagination (200 rows/page).

---

### Task 3 — Asset Registry Module 🔲
**Goal:** Show full system-level asset info: RAM, processes running, memory available, battery, IP, MAC, last seen, status. Add topology/architecture diagram built from IP addresses.

**Plan:**
- Backend: `GET /api/v1/assets` (enriched from agent payloads: hardware section), `GET /api/v1/assets/{id}/detail`
- Frontend: `AssetRegistry.tsx` with real data + topology diagram (force-directed graph using D3 or Recharts)
- Data sources: agent `hardware`, `metrics`, `network` sections → enrich `asset_registry` table

---

### Task 4 — Threat Intelligence Module 🔲
**Goal:** Real threat intel with exploitability scores, trending, priority. AI summaries in plain language.

**Plan:**
- Backend: `GET /api/v1/threat/overview`, `/feeds`, `/actors`, `/news`, `/cves`
- Frontend: `ThreatIntelligence.tsx` with live feed data, EPSS trending chart, AI summary panel
- Data: `intel.db` tables — `threat_actors`, `security_news`, `epss_scores`, `cisa_kev`, `nvd_cve_local`

---

### Task 5 — Security Posture Module 🔲
**Goal:** CIS benchmark checks per OS, real-time, large-data design.

**Plan:**
- Backend: Map agent `security` payloads to CIS controls; cache per-agent posture scores
- Frontend: `SecurityPosture.tsx` — per-control pass/fail table, trend charts, OS-specific views
- Design for scale: posture scores pre-computed at ingest time, indexed by agent+control+ts

---

### Task 6 — Detection Module 🔲
**Goal:** Evidence-based detections only. Each finding must have: evidence + timestamps + metadata + validation (KEV/threat intel) + risk score + impact + AI remediation.

**Sub-modules:**
- **Packages CVE** — compare installed pkg versions against NVD local mirror (FTS5 search)
- **Open Ports** — flag non-standard ports, cross-reference threat intel for C2 port signatures
- **Persistence / Backdoors** — launchagents, cron jobs, login items, kernel extensions
- **Network Threats** — IOC correlation of active connections against Feodo/ThreatFox/AbuseIPDB

---

### Task 7 — Main Dashboard 🔲
**Goal:** High-level overview with real numbers. SLA tracking. Finding workflow (resolve/open/accept/false-positive). RBAC (roles: admin, analyst, viewer). Timestamps on all actions.

**Plan:**
- Backend: `GET /api/v1/soc/dashboard` (already partially in `indexer.py`), `PATCH /api/v1/soc/findings/{id}`
- Frontend: CommandCenter with live stats, SLA breach alerts, per-finding action buttons
- DB: `soc_activity`, `soc_comments`, `soc_actions` tables already exist — wire to UI

---

### Task 8 — UI/UX Color & Theme 🔲
**Goal:** Clean white base, one primary palette (AttackLens brand orange), proper severity color coding. No colour overload.

**Plan:**
- Palette: `#FF6B35` (brand orange), green `#16A34A` (improvements/pass), red `#DC2626` (critical), amber `#D97706` (high), blue `#2563EB` (info/medium), gray scale
- Apply: CSS variables in `index.html` or global CSS, consistently applied via Tailwind custom tokens
- UX: sidebar icon refresh, compact card grid, status badge consistency

---

## Architecture Reference

```
Agents (macOS/Windows/Linux)
   │ TLS POST /api/v1/ingest (HMAC signed, AES-256-GCM encrypted)
   │ WS  /ws/{agent_id}
   ▼
Nginx (TLS LB)  ←— nginx/nginx.conf
   ├── ip_hash  /ws/ → WS sticky sessions
   └── least_conn /api/ → manager-1, manager-2
         │
         ├── manager-1 (FastAPI + SQLitePool readers=4)
         └── manager-2 (FastAPI + SQLitePool readers=4)
               │
               ├── manager.db (agents, payloads, nonces, sessions)
               ├── intel.db   (findings, CVEs, IOCs, threat intel, AI cache)
               └── RabbitMQ   (telemetry queue + jarvis.work queue)
```

## DB Schema Quick Reference

**manager.db tables:** `agents`, `agent_keys`, `payloads`, `agent_sessions`, `nonce_cache`  
**intel.db tables:** `findings`, `findings_fts` (FTS5), `correlations`, `change_timeline`, `soc_activity`, `soc_comments`, `soc_actions`, `ioc_cache`, `cve_cache`, `cve_entries`, `nvd_cve_local`, `nvd_cve_fts` (FTS5), `cisa_kev`, `epss_scores`, `threat_actors`, `security_news`, `ai_analysis`, `remediation_plans`, `asset_registry`, `org_groups`, `behavior_baseline`, `entity_state`, `feed_health`

## Key Env Vars
```
API_KEY           — master key (64 hex chars)
RABBITMQ_URL      — amqp://... (optional; sync fallback if unset)
CORS_ORIGINS      — comma-separated origins (default: same-origin)
AGENT_RATE        — token bucket rate req/s (default: 10)
AGENT_BURST       — token bucket burst (default: 30)
AGENT_SLOTS       — max concurrent per agent (default: 4)
ANTHROPIC_API_KEY — for AI analyst + remediation
OPEN_ENROLLMENT   — true/false (default: true)
```
