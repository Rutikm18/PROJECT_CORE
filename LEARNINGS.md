# Learnings

A running glossary of concepts/patterns introduced into this project, with a short definition and why this project specifically needed it. Append-only — run `/learnings` at the end of a session to update it.

## 2026-06-23

### Bounded worker-pool executor (backpressure)
**What:** A fixed number of worker tasks draining one bounded `asyncio.Queue`, instead of spawning a task per unit of work. Producers do a non-blocking `put_nowait`; a full queue drops-and-counts rather than blocking or growing.
**Why:** Ingest dispatched detection via unbounded `asyncio.create_task` per payload — under a burst that piles thousands of in-flight `process()` coroutines into memory, all contending for IntelDB's single write lock (a thundering herd that slows every writer). The executor caps concurrent detection so the write-lock queue stays shallow and ingest latency stays flat.

### Ephemeral-port suppression (detection FP control)
**What:** Treating listeners on the dynamic/ephemeral port range (≥49152) differently from fixed service ports. Dev tools and runtimes grab a fresh ephemeral port each run, so keying a finding on that port number makes findings churn endlessly.
**Why:** `wildcard_bind` keyed its dedup item_key on the port; VS Code/Docker ephemeral ports minted a new finding every scan that never deduped or auto-resolved → unbounded growth. 16,616 of 16,632 findings were this. Excluding ephemeral ports from the generic exposure rule (real backdoors are still caught by the high-risk-port and unknown-process rules) collapsed it to 1 real finding.

### Allowlist case-normalization
**What:** Lowercasing both the allowlist entries and the value being matched, so membership checks actually fire.
**Why:** The wildcard-bind process allowlist had mixed-case entries (`mDNSResponder`, `ControlCenter`) but the agent emits process names lowercased and the matcher lowercased only the input — so those entries silently never matched, letting stock-macOS daemons keep generating alerts. A latent bug that only the real-data replay exposed.

### SQLite query plans (`EXPLAIN QUERY PLAN`)
**What:** A SQL command that shows whether a query uses an index (`SEARCH`) or reads every row (`SCAN`), without actually running it.
**Why:** Used to prove, not guess, that Attack Terrain pages were slow. Found `category='process'` queries doing a full `SCAN` at 839ms because no index covered `(is_active, category)` without an `agent_id` filter — confirmed the fix dropped it to 2ms before writing any code.

### Composite/covering indexes
**What:** An index on multiple columns in the order a query filters/sorts by, so SQLite can satisfy the whole `WHERE ... ORDER BY` from the index alone.
**Why:** The existing indexes all required `agent_id` as the first column. Every fleet-wide (no-agent-filter) dashboard query couldn't use them. Added `(is_active, category, composite_score)`, `(is_active, severity, composite_score)`, `(is_active, agent_id)`, and `(first_detected_at)` to match the actual query shapes.

### Tiered data retention (hot/warm/cold)
**What:** Storing the same data at different time-resolutions with different expiry windows — fine-grained for recent data, coarse for older data, all deleted past a max age.
**Why:** Raw telemetry had no retention at all (`payloads` table grew forever). Built a single `RAW_TELEMETRY_RETENTION_DAYS` setting (default 30) driving hot=24h/warm=7d/cold=30d, with a Settings UI to change it and an archive option that just stops pruning the cold tier instead of deleting it.

### Read-time exclusion vs. write-time deletion
**What:** Two ways to "hide" stale data — delete it from storage (write-time, permanent), or filter it out only when reading (read-time, reversible).
**Why:** An agent silent for 16 days still had 794 findings marked "active," polluting every dashboard view. Chose read-time filtering (`live_agent_ids` parameter) so the data isn't destroyed — if that agent ever reports again, its findings reappear automatically with zero loss.

### SQLite corruption recovery (`.recover`, `ANALYZE`, `VACUUM`)
**What:** `.recover` rebuilds a SQL dump from a corrupted database by walking raw b-tree pages instead of trusting the schema; `ANALYZE` rebuilds the query planner's statistics; `VACUUM` rewrites the file to reclaim space and defragment.
**Why:** The live `intel.db` failed `PRAGMA integrity_check` (disk image malformed). Recovered on a disposable copy first, verified zero duplicate rows and matching counts, then swapped it in — never touched the live file until the copy was proven clean. Learned the hard way that `.recover`'s rebuilt database has no `ANALYZE` statistics, which alone caused some queries to run 100x slower until rebuilt.

### FTS5 (SQLite full-text search) and cross-database joins
**What:** FTS5 is SQLite's built-in full-text-search virtual table. SQLite databases are single files — you cannot `JOIN` a table in one `.db` file against a table in a different `.db` file without an explicit `ATTACH`.
**Why:** The Incidents search box crashed every request with "no such table: agents" — leftover code joined against a table that lives in a completely different database file (`manager.db`, not `intel.db`). Fixed by dropping the dead, unused join.

### Fleet-wide (cross-host) correlation
**What:** Detection rules that fire on patterns across multiple agents (e.g. the same malware hash on 3+ machines) rather than within one agent's data.
**Why:** The existing correlation engine only ever looked at one agent at a time, so it structurally couldn't see a campaign spanning hosts. Built as a separate `FleetCorrelator` reading a bounded global snapshot, stored under a reserved `__fleet__` pseudo-agent ID so it can't recurse on its own output.

### Settings as a generic key/value store
**What:** One `org_settings` table (key, value, updated_at) plus an audit-log table, instead of a dedicated column/table per setting.
**Why:** Reused this existing pattern for data-retention settings instead of inventing a new mechanism — new settings are just new keys, with validation in the API layer (Pydantic), not the schema.

### React route-based code splitting (`lazy()` + `Suspense`)
**What:** Only download a page's JavaScript when the user actually navigates to it, instead of bundling the whole app into one file.
**Why:** Verified (didn't assume) this was already done correctly here — confirmed "slow tabs" was backend query latency, not a frontend bundling problem, before touching any frontend code.

### Custom Claude Code slash commands
**What:** A markdown file in `.claude/commands/` (project-only) or `~/.claude/commands/` (global) becomes invocable as `/<filename>` — its content is the instruction Claude follows when you run it.
**Why:** This file's existence — `/learnings` is the command that keeps it updated going forward.

---

# Study Roadmap

Topics to learn to understand this project deeply, ordered foundational → specialized. Each lists *why it matters here* and *where to see it in the code*. This is a reference section (not the dated changelog above).

## Tier 1 — Foundations (the spine of the manager)

### 1. Async Python / asyncio
The entire manager is one async event loop. Until this clicks, the hot path is opaque.
- Concepts: event loop, coroutines, `await`, `asyncio.create_task`, `Queue`, `Semaphore`, `Lock`, `gather`, backpressure, why blocking calls are forbidden in async code.
- Where: `manager/attacklens/engine.py` (bounded worker pool), `manager/api/ingest.py` (request pipeline), `manager/pool.py` (locks/semaphores).
- Litmus test: explain why unbounded `create_task` per payload was a bug and how the bounded queue fixes it.

### 2. SQLite as a real database
This project runs two SQLite DBs (`manager.db`, `intel.db`) as its primary store — no Postgres. Its quirks ARE the performance model.
- Concepts: WAL mode, the single-writer / many-reader model, `PRAGMA` (synchronous, cache_size, busy_timeout, mmap), indexes & composite indexes, `EXPLAIN QUERY PLAN` (SEARCH vs SCAN), FTS5 full-text search, `ANALYZE`/`VACUUM`, corruption + `.recover`, why you can't JOIN across two `.db` files.
- Where: `manager/indexer.py` (schema, indexes, FTS5), `manager/pool.py` (WAL pragmas, write lock), `manager/store.py` (tiered file store + index).
- Litmus test: why did one category query take 839ms with an index present, and what index fixed it?

### 3. FastAPI / ASGI web layer
Every endpoint and the ingest entrypoint live here.
- Concepts: routers & router factories, request lifecycle, `Depends` injection, lifespan/startup events, `StaticFiles`, Pydantic models & validation.
- Where: `manager/server.py` (app factory, wiring, startup), `manager/api/*.py` (routers), `manager/models.py`.

## Tier 2 — The domain (security detection)

### 4. Detection engineering fundamentals
The core value of the product. This is *the* area to go deep on.
- Concepts: the signal → cluster → finding pipeline; true/false positives & negatives and the tradeoff; allowlisting & baselining; dedup via stable fingerprints/item_keys; auto-resolution of stale findings; severity vs confidence; "only act on data that actually came from an agent."
- Where: `manager/attacklens/engine.py` (`process`, `_dispatch`), `manager/attacklens/detections/*.py` (18 detection modules), `manager/attacklens/config.py` (tunables).
- Litmus test: why was 99.9% of findings false positives, and what three bugs caused it?

### 5. MITRE ATT&CK framework
The shared vocabulary every finding maps to.
- Concepts: tactics vs techniques, technique IDs (e.g. T1571), mapping a raw observation to a technique.
- Where: `mitre_technique`/`mitre_tactic` fields throughout `detections/*.py` and `rules.py`.

### 6. Threat intelligence & vulnerability scoring
How raw findings get risk-ranked.
- Concepts: CVE/NVD, CVSS (severity), EPSS (exploit probability), CISA KEV (known-exploited), IOC feeds, corroboration across sources.
- Where: `manager/attacklens/nvd.py`, `manager/attacklens/feeds.py`, the `multipliers`/`penalties` in `config.py`, `manager/threat/scoring.py`.

### 7. Correlation: per-host vs fleet-wide
Turning isolated findings into campaigns.
- Concepts: per-agent correlation (a kill-chain on one host) vs cross-host/fleet correlation (the same campaign across many hosts — distributed C2, worm propagation, supply-chain outbreak); a reserved pseudo-agent for fleet results.
- Where: `manager/attacklens/correlator.py` (per-agent), `manager/attacklens/fleet_correlator.py` (cross-host).

## Tier 3 — Transport, storage & scale

### 8. Cryptography for telemetry
How the agent→manager channel is secured.
- Concepts: AES-256-GCM (authenticated encryption), HMAC, key derivation, nonce + replay-window protection, idempotent retries.
- Where: `manager/crypto.py`, `manager/api/ingest.py` (steps 6–8: key lookup, decrypt, nonce dedup).

### 9. Time-series / tiered storage & retention
Where raw telemetry physically lives and how it ages out.
- Concepts: hot/warm/cold tiers, retention windows, NDJSON + gzip, delete vs archive, pruning by age, a separate index DB over the files.
- Where: `manager/store.py`, `manager/api/settings.py` (retention settings), the hourly cleanup job in `server.py`.

### 10. System design for scale & resilience
The "large amount of data" half.
- Concepts: backpressure, bounded queues + worker pools, rate limiting (token bucket), per-agent fairness (semaphores), idempotency, the single-writer bottleneck, observability/metrics counters, graceful degradation (drop-and-count vs block).
- Where: `manager/pool.py` (`TokenBucket`, `AgentRateLimiter`), `engine.py` (detection executor), `ingest.py` (`/ingest/health` stats).

### 11. Message queues (the scale-out path)
The architecture the system is *meant* to use at high volume.
- Concepts: producer/consumer, RabbitMQ, prefetch as backpressure, queue mode vs sync mode, durable hand-off.
- Where: `manager/queue/`, `manager/workers/` (telemetry + attacklens workers).

## Tier 4 — Edges

### 12. macOS internals (the telemetry source)
You can't judge a detection's accuracy without knowing what normal looks like.
- Concepts: launchd daemons, code signing & notarization, SIP/Gatekeeper/FileVault/Firewall, processes/ports, the ephemeral (dynamic) port range, why daemons like `netbiosd`/`mDNSResponder` legitimately wildcard-bind.
- Where: the data shapes flowing into `detections/port_listener.py`, `engine._security`, `manager/api/posture.py`. (Agent code is outside `manager/` but its output defines every field here.)

### 13. React dashboard
The operator-facing surface.
- Concepts: route-based code splitting (`React.lazy` + `Suspense`), one chunk per page, calling the JSON APIs, build output served by FastAPI `StaticFiles`.
- Where: `manager/dashboard/templates/.../src/app/` (`App.tsx`, `pages/*.tsx`).

### 14. Testing strategy here
How correctness is proven in this repo.
- Concepts: pytest (+ async tests in AUTO mode), the accuracy harness, module self-tests, and the project's strongest pattern — *replaying real agent payloads* through detection to measure FP/TP before/after a change.
- Where: `manager/tests/unit/`, `manager/tests/accuracy/`, the `if __name__ == "__main__"` self-tests inside `detections/*.py`.

### 15. Data provenance & integrity
A cross-cutting principle worth understanding on its own.
- Concepts: every finding is stamped with where in the raw telemetry it came from, so any incident is verifiable against Deep Analysis; never trust derived/stale data over live agent data.
- Where: `engine._stamp_provenance`, the `_source` evidence field, `manager/api/raw.py`.

**Suggested path:** 1 → 2 → 3 give you the machinery; 4 is the heart (spend the most time here); 6–7 and 8–11 deepen domain + scale; 12–15 round it out. If you only learn three: **async Python, SQLite-at-scale, and detection-engineering fundamentals.**
