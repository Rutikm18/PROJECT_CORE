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

## 2026-06-24

### Config files that declare intent but are never loaded
**What:** `.env` documented `ATTACKLENS_VALIDATION=true` etc., but nothing in the actual startup paths (`start.sh`, `scripts/run_manager.sh`, `docker-compose.yml`/`.ha.yml`) sourced `.env` or forwarded those specific vars into the process/container environment — so the file's values silently had zero effect regardless of deployment method.
**Why:** Found while debugging why the precision-validation pipeline appeared "disabled by default" despite `.env` saying otherwise. Fixed by sourcing `.env` in both shell scripts and explicitly listing the 3 vars in both compose files' `environment:` blocks.

### Dormant detection modules (built but never dispatched)
**What:** 15 of 17 fully-built `detections/*.py` modules (each with a uniform `analyze(agent_id, section, data, db, hostname)` entry point and already re-exported from `detections/__init__.py`) were never added to `AttackLensEngine._DETECTION_MODULE_ROUTES` — only `port_listener` and `user_account` were wired in. Verified via `grep` showing zero imports outside each module's own file.
**Why:** A module existing, tested, and exported is not the same as it running. Wired in the 4 with zero section-name overlap with existing inline analyzers (`sysctl_monitor`→"sysctl", `arp_spoofing`→"arp", `container_security`→"containers", `sbom_posture`→"sbom") after confirming each against the agent's real `COLLECTORS` section names — left 11 overlapping ones (same section as an existing inline analyzer) for a separate pass requiring side-by-side behavioral comparison first.

### Single-signal confidence floors (cross_matrix.py CROSS_LAYER_PATTERNS)
**What:** The deterministic confidence engine (`confidence.py`) multiplies weight × strength × layer/KEV/EPSS/TI/asset multipliers — a single-layer, non-CVE pattern match (e.g. a hardcoded malicious port, a UID-0 clone) mathematically can't clear the 0.95 promotion gate without cross-layer corroboration. `cross_matrix.py` already had a `matched_floor()` escape hatch for exactly this (used by 7 pre-existing `STANDALONE_RULES`), but it was never extended to the rule_ids the live detection modules actually emit.
**Why:** Confirmed via a failing test (`test_malicious_port_creates_finding`, port 4444/Metasploit scored ~0.39 confidence) that turning on validation would silently suppress exactly the findings it's supposed to protect. Added floor entries for 7 hand-verified, individually-unambiguous rule_ids (`uid_zero_clone`, `hidden_user`, `sysctl_critical`, `arp:duplicate_ip_mapping`, `arp:gateway_mac_changed`, `cs:privileged_host_network`, `cs:exposed_mgmt_port`, `rule:security_posture`) — deliberately not a blanket floor per module, since e.g. `high_risk_port`'s underlying port list mixes genuine backdoors with common legitimate services (SSH/RDP).

### Two independent gates both need the same floor
**What:** The validation pipeline has two separate confidence calculations — `confidence.py`'s deterministic gate (threshold 0.95) and `ai_validator.py`'s weighted precision score (threshold 0.90, AI-optional) — and they don't share state. `ai_validator.py`'s docstring claimed to use "cross-layer floor from cross_matrix" but `_cross_layer_score()` never actually called it.
**Why:** Fixing only the first gate left findings rejected at the second with `ti_corroboration=0.00`. Added a second deterministic-floor override in `ai_validator.py` mirroring the existing KEV-corroboration override, keyed on `cluster.confidence >= confidence_threshold` (i.e. "the first gate already vouched for this at the highest tier") rather than requiring multi-layer coverage, since a standalone floor's whole point is not needing that.

### `setdefault` vs `or`-chains hide which field actually wins
**What:** `_adapt_module_finding()` uses `f.setdefault("source", rule)`, which never overrides — but several modules' own `build_alert()` helpers (`arp_spoofing.py`, `container_security.py`) pre-set `"source"` to a generic module-level constant (e.g. `"rule:arp_spoofing"`) even when the more-specific `"rule_id"` field was already correctly set (e.g. `"arp:duplicate_ip_mapping"`). `_dispatch_to_signals`'s `f.get("source") or f.get("rule_id")` then picked the less-specific one every time.
**Why:** This silently defeated the cross_matrix floors above for 2 of the 4 newly-wired modules — their specific rule_id was right there, just never reached. Fixed by flipping precedence to `f.get("rule_id") or f.get("source")` — safe because every module sets `rule_id` correctly, `source` is the less-trustworthy field.

### Validation-pipeline findings silently lost their descriptive title and correct category
**What:** `_emit_finding_from_cluster()` (the function that writes a promoted cluster to the `findings` table) used `f"[{rule_id}] {severity} detection"` as a fallback title (the real title lived on the original finding dict, not on the `Signal.evidence` it was checking) and used the raw section name (`"ports"`) as `category` instead of mapping it through `_SECTION_CATEGORY` (`"port"`) — silently mismatching every `/api/v1/detection/*` endpoint's category filter.
**Why:** Found via a unit test (`test_ports_routed_through_module_end_to_end`) asserting `category == "port"` that failed only under validation mode despite the underlying detection logic being correct. Fixed by carrying `title`/`description` through `Signal.evidence` under reserved `_title`/`_description` keys (stripped before persistence) and by reusing `_SECTION_CATEGORY` in the promotion path.

## 2026-06-25

### Postgres service was missing from the production compose files
**What:** The SQLite→Postgres migration updated the code (which reads `DATABASE_URL`, default `postgresql://...@localhost:5432`) but never updated `docker-compose.yml`/`.ha.yml`: neither declared a `postgres` service or set `DATABASE_URL`, and `docker-compose.yml` still carried a dead `THREAT_INTEL_DB=/app/data/intel.db` SQLite path. Inside a container `localhost:5432` resolves to the container itself → `ConnectionRefusedError [Errno 111]`, crash-looping `threat-intel` and blocking `manager` (which `depends_on` it healthy).
**Why:** Containers reach each other by service name, never `localhost`. Added a `postgres` service on the shared `attacklens_internal`/`internal` network and `DATABASE_URL=...@postgres:5432` to both apps with a `depends_on: condition: service_healthy` gate. The standalone `docker-compose.postgres.yml` is dev-only (separate project/network) — not reachable from the app stack.

### docker-compose.ha.yml `<<` merge cycle
**What:** Each manager replica's `environment:` block did `<<: *manager-base`, merging the *whole* service anchor (build/depends_on/volumes/networks) back into a key of the same service → `cycle detected: node at path services.manager-1.environment references node at path services.manager-1`, so the file didn't parse at all.
**Why:** A YAML merge-key target must be shape-appropriate for where it's merged. Split into a flat `x-manager-env` (env vars only, safe to merge inside `environment:`) and `x-manager-base` (full service template, merged at service level).

### TelemetryIndex (raw-payload store) stayed on SQLite through the Postgres migration
**What:** `index.py`'s `TelemetryIndex` (the hot/warm/cold raw-telemetry index behind `/api/v1/raw` / Deep Analysis) still uses `aiosqlite` — only `manager.db`/`intel.db` moved to Postgres. But `aiosqlite` had been dropped from `manager/requirements.txt`, so the freshly-built image crashed at import (`ModuleNotFoundError: No module named 'aiosqlite'`).
**Why:** A partial migration leaves real residual deps. Re-added `aiosqlite>=0.20.0`. The raw index is deliberately not in Postgres (append-only blob store, different access pattern), so the dep is load-bearing, not vestigial.

### IPv4/IPv6 split hides a port collision (agent ingest silently eaten)
**What:** A stray `python -m http.server 8080 --bind 127.0.0.1` held **IPv4** `127.0.0.1:8080` while Docker's port-forward held the **IPv6** wildcard `*:8080`. The agent posts to `http://127.0.0.1:8080` (literal IPv4) → every payload hit the stray server → `501`, zero reached the manager. `curl localhost:8080/health` resolved to IPv6 → real manager → looked healthy, masking it.
**Why:** When ingest counters are flat but health is green, check `lsof -nP -iTCP:<port> -sTCP:LISTEN` for a *non-Docker* listener and test IPv4 (`127.0.0.1`) vs IPv6 (`[::1]`) separately — Docker's wildcard forward only re-binds the freed IPv4 after the squatter dies (no container recreate needed here).

### Strict validation vs. a benign host = empty dashboard (deferred to a later phase)
**What:** With `ATTACKLENS_VALIDATION=true`, a healthy Mac's 539 signals produced 557 clusters all rejected `low_confidence` (single-layer findings can't clear the 0.95 gate, and `ANTHROPIC_API_KEY` was unset so the AI gate over-rejects), so `/api/v1/detection/*` returned nothing while raw/Deep-Analysis data was fully present.
**Why:** Validation/precision-gating is a next-phase concern until the mechanism is fully integrated; set both flags to `false` in `.env` so the legacy emission path writes every detected finding straight to the dashboard (0→18 active for the live host). The calibration groundwork (floors, gate fixes) remains in place for when it's re-enabled.

### Cumulative-subprocess hang froze the heavy macOS collectors
**What:** `security`/`sysctl`/`packages`/`apps` each fan out into many sequential `_run()` shell-outs (security ≈20: `systemsetup`, `csrutil`, `spctl`, `pwpolicy`, `system_profiler`…; packages: `brew`/`gem`/`cargo`). Each call had its own per-command timeout, but the *sum* exceeded the orchestrator's 25 s per-section timeout, so the section timed out and the agent emitted `{"error":"…possible hang"}` as the section's data — visible verbatim on the dashboard — losing every field, not just the slow one. The agent's own `agent_health` circuit-breaker heartbeat (per-section `state`/`failures`/`last_result`) is what pinpointed it without root access to the agent logs.
**Why:** Added a thread-local per-section *budget* in `collectors/base.py` (`set_run_budget`/`run_budget_remaining`): `_run()` caps each call to the time remaining and skips once spent, and the orchestrator arms it (section_timeout − 3 s margin) on each collector's worker thread. A heavy collector now degrades to PARTIAL data within budget (verified: SecurityCollector returns 13/38 fields under a 1 s budget) instead of hanging. Per-item loops (`apps`, `binaries`) poll `run_budget_remaining()` to stop early. Also stopped enqueueing the `{"error":…}` blob on hard timeout — it overwrote the last-good snapshot in the store; the failure is already carried by the circuit breaker / heartbeat. Deploy via `build_pkg.sh` (rsyncs repo `agent/` into the pkg) + reinstall.

### Queue pipeline reliability — Phase 1 (silent-loss + DLQ black hole + real-time correlation)
**What:** Architecture review of the agent→manager→detection pipeline surfaced three real defects. (1) `TelemetryWorker._process` wrapped every side effect (`store.write`, `insert_payload`, broadcast, `publish_attacklens_work`) in `try/except: log` and then acked the message regardless — so a failed store (lost provenance) or a failed detection fan-out (silently no detection, on a security tool) was at-most-once silent loss. (2) The fanout DLQ `mac_intel.dead` had **zero consumers** — any nack'd message was lost forever. (3) Per-host correlation only ran on every 3rd payload (`count % 3`), so 2/3 of events — and any attack chain in the gap — went uncorrelated.
**Why:** (1) Reclassified the two side effects into CRITICAL (`store.write`, fan-out — re-raise so `msg.process()` nacks→DLQ) vs BEST-EFFORT (raw index, WS broadcast — stay non-fatal); re-processing is safe because store.write is idempotent per (agent,section,ts) and detection dedups by fingerprint. (2) Added `workers/dlq_replayer.py`: drains the DLQ, routes each message back to its origin queue via the `x-death` header (queue→routing-key fallback), retries with exponential backoff, and PARKS+alerts poison messages after `max_attempts` using an own `x-replay-attempts` header. (3) Replaced the sampling with a per-agent coalescing scheduler (`_request_correlation`/`_correlation_loop`): every payload requests a pass, but at most one runs per agent — a request mid-flight sets a dirty flag for exactly one more run, so it's correlate-on-every-event with bounded DB load.

### Queue pipeline reliability — Phase 2 (outbox + reconciler) & Phase 3 deferral
**What:** "Raw is stored, so detection is reprocessable" was asserted in comments but had no implementation — a payload stored but whose detection hand-off was lost (worker crash between store and fan-out, DLQ retry exhaustion, sync-path drop) was never re-detected, and nothing noticed.
**Why:** Added a `payload_ledger` table (`db.py`) acting as both outbox and reconciliation record: the telemetry worker writes a row `received` after store.write; `engine.process` marks it `processed` after detection (keyed on the same agent/section/collected_at). A new `workers/reconciler.py` (`PayloadReconciler`) periodically finds received-but-unprocessed sections past a grace window, replays the section's current snapshot (`store.latest`) to `attacklens.work`, and collapses the backlog (`ledger_reconcile_section`) — snapshot-based detection means re-driving the latest payload recovers current state, so we don't replay every missed historical payload; a section that keeps failing crosses `max_attempts` and gives up (surfacing as ledger lag on `/ingest/health`). **Phase 3 (consistent-hash partitioning, stateful correlation windows, Kafka/HA) was deliberately NOT built** — current load is 1 agent through 1 detection worker, so it would be premature optimization; instead it's specified with adoption triggers + exact touchpoints in `docs/adr-001-detection-pipeline-scaleout.md`, execution-ready when a trigger fires.

### Ledger key drift + dual telemetry consumers
**What:** Verifying the ledger, the `payload_ledger` pending count climbed instead of staying near-zero. Two causes: (1) `collected_at` float/int drift — `ledger_received` (often int seconds from the agent) and `ledger_processed` (a `time.time()` fallback when collected_at is absent) wrote DIFFERENT keys for the same payload, leaving a phantom 'pending' row the reconciler then needlessly replayed; (2) `server.py` runs BOTH `TelemetryWorker` and `TelemetryConsumer` as competing consumers of `agent.telemetry` — near-duplicates doing identical store+fanout work — and only `TelemetryWorker` wrote `ledger_received`.
**Why:** (1) Added `Database._ledger_key()` flooring collected_at to integer seconds, applied in every ledger read/write so received/processed always collapse to one row. (2) Added `ledger_received` to `TelemetryConsumer` so the ledger is consistent regardless of which consumer wins a message. The dual-consumer redundancy itself is pre-existing and flagged for consolidation (keep the higher-throughput `TelemetryConsumer`, port the Phase-1 critical-nack, drop `TelemetryWorker`) — not yet done.

### Finding triage lifecycle — one state machine, exposed on every page
**What:** Findings already had stable ids (`external_id` AL-F-xxxxxxxx, backfilled + unique-indexed) and lifecycle endpoints (close/accept-risk/false-positive/reopen, PATCH, comments, activity), but the state machine was duplicated in ~11 places (terminal-status tuples in `update_finding`, `_sla_status`, `detection._enrich`, `findings.py`), no endpoint told the UI which actions were valid for a finding's current state, and the quick-action endpoints didn't validate transitions (you could "close" an already-closed finding).
**Why:** Added `manager/finding_lifecycle.py` (top-level, NOT under `attacklens/` — importing it from `indexer.py` via the package would trigger `attacklens/__init__→engine→fleet_correlator→indexer`, a circular import) as the single source of truth: status vocabulary, ACTIVE/TERMINAL/RESOLUTION sets, the action→target-status map with allowed-from states, and `available_actions(status)`. Wired `available_actions` + `is_terminal` + a guaranteed `external_id` into BOTH `detection._enrich` (Attack Terrain Origin/Vector/Citadels + All Incidents) and `findings.list/detail` (Validated Findings), so all three pages render consistent, correct action buttons. Added a unified transition-validated `POST /soc/findings/{id}/action` (409 + the allowed actions when illegal; enforces `needs_reason` for accept-risk) that the named endpoints now funnel through, plus `GET /soc/lifecycle` exposing the whole state machine. Centralized the scattered terminal-status checks in `indexer.py` on `finding_lifecycle.is_terminal`.

### update_finding dropped status-change activity (uncommitted audit rows)
**What:** Marking a finding false-positive persisted the status but the status-change row vanished from the activity log, while a reopen's did persist. `update_finding` ran `self._conn.commit()` only after the finding UPDATE, then did the `_log_activity` INSERT with NO subsequent commit — so the audit row hung uncommitted until some later write flushed it, and the resolved-status `_append_timeline` call (same uncommitted transaction) could abort and roll the audit row back with it.
**Why:** Commit the activity log immediately after writing it (before the best-effort timeline append), and wrap `_append_timeline` in its own try/except + commit/rollback so a secondary-view write can never destroy the authoritative audit trail. Verified live: `new → false_positive` now logs reliably.

### Frontend triage wiring (Vite dashboard)
**What:** The React dashboard pages (Validated Findings / All Incidents / Attack Terrain Origin·Vector·Citadels) showed findings but had no way to act on them from the shared detail drawer.
**Why:** Added `StatusChip` + `FindingActions` to `DetectionShared.tsx` (the shared module behind `GenericDetectionPage`/`TerrainDetectionPage` → the `FindingDetail` drawer used by Incidents + all terrain pages). `FindingActions` renders exactly the server's `finding.available_actions`, POSTs to the unified `/api/v1/soc/findings/{id}/action`, prompts for a reason when `needs_reason`, surfaces a 409 inline, and calls `onChanged` (wired to the list `refetch`) so the board refreshes. The dashboard is a Vite app whose `vite build` outDir is `manager/dashboard/static` (served by FastAPI StaticFiles, live-mounted via the `./manager/dashboard` Docker volume) — so a `npm run build` is enough to deploy the UI; no manager image rebuild. ThreatQueue (Validated Findings) already had its own working action endpoints + a client-side `STATUS_MAP` (a candidate to later replace with the server `available_actions`).

### Canonical terrain field — consistent incident id across All Incidents & Attack Terrain
**What:** `external_id` was already on every finding (so inherently identical across views) but wasn't shown in list rows, and "terrain" (origin/vector/citadels/identity/posture) was computed in THREE independent places that could drift — backend `terrain_validators.CATEGORY_TO_TERRAIN` plus two client copies (`Incidents.tsx terrainOf`, `ThreatQueue.tsx CAT_CONFIG`) — so the same finding could land in different terrain buckets across pages.
**Why:** Exposed a single server-authoritative `terrain` field on every finding via `terrain_for()` in BOTH `detection._enrich` (All Incidents + Attack Terrain pages) and `findings._with_lifecycle` (Validated Findings). Frontend renders `IdChip` (click-to-copy `external_id`) + `StatusChip` in the SHARED table title cell (one edit → every detection/terrain page) and a `TerrainChip` keyed on the server `terrain` (deleted Incidents.tsx's duplicate map). Result: the same finding shows the same id and the same terrain bucket everywhere. The `terrain` field is Python → baked into the manager image (needs a manager rebuild); frontend-only changes ride the volume mount. **Validated Findings** (precision ≥ configured threshold) was already wired (`validated_only` resolves per-agent→per-terrain→global; Settings→Validation auto-recomputes); it shows 0 only because the default 0.9 exceeds current legacy precision scores (max ~0.8) — an operator calibration in Settings, not a code gap.

## 2026-07-03

### Word-boundary regex in detection patterns
**What:** Using `\b` anchors (e.g. `r"(?i)\b(bash|sh|zsh)\b"`) instead of bare alternation so that short tokens like "sh" don't match inside longer words like "crash", "SharedArrayBuffer", or "AuthenticationServices".
**Why:** The parent-child spawn rules (office app → shell) fired on every Chromium Helper and macOS ExtensionKit process because "sh" is a substring of their names. Adding `\b` on both sides of the alternation group reduced the match space to genuine interpreter names only, with no legitimate processes lost.

### Empty process name guard in port detection
**What:** Skipping a port listener finding when the process name is the empty string rather than emitting a finding with an unknown owner.
**Why:** macOS's port collector can't resolve a PID to a process name when the listener lives in Docker Desktop's internal network namespace. Without a name the risk-assessment (wildcard_bind, high_risk_port) is meaningless — applied the guard to both `detect_wildcard_bind` and `detect_high_risk_port`. Genuinely dangerous ports are still caught by other rules even without a process name.

### Apple com.apple. prefix guard for service detection
**What:** Skipping pattern-based service detection for any LaunchDaemon/Agent whose label starts with `com.apple.`.
**Why:** `SUSPICIOUS_SERVICE_PATTERNS` matched "crypto" in `com.apple.CryptoTokenKit.ahp` — a legitimate Apple smart-card/security-token framework — and emitted a CRITICAL "cryptominer service" finding. Apple ships hundreds of first-party daemons using reverse-DNS labels; any keyword pattern will hit at least one. Prefix-excluding the whole `com.apple.` namespace is the right boundary.

### Precision score seeding at finding creation
**What:** `_make_finding` (in both `engine.py` and `behavioral.py`) and `_adapt_module_finding` should set `precision_score` from the rule's `confidence` value or a severity-based default (`critical→0.70`, `high→0.62`, `medium→0.50`, `low→0.35`) so no finding starts life at 0.0.
**Why:** Pre-existing findings had `precision_score=0`, which made them invisible to the Validated Findings view (threshold 0.9) and produced misleading dashboard averages. Manual DB seeds were repeatedly overwritten by the UPSERT path — the only durable fix was seeding at the Python level so every generated finding carries a non-zero floor from the moment it's emitted.

### Metrics-based behavioral detection with consecutive-reading state
**What:** Detecting resource-abuse attacks (cryptominer T1496, ransomware T1486, data exfiltration T1048, memory injection T1499) by comparing CPU/disk/net/memory metrics against fixed thresholds, counting consecutive high readings per agent in a `_metrics_state` dict, and only firing after `_CONSEC_NEEDED=2` consecutive readings above threshold.
**Why:** A single high CPU reading is a compile job or a backup. Two consecutive readings (across separate agent telemetry cycles) is the behavioral fingerprint of sustained resource abuse. Without the consecutive-reading gate the metrics rules produced a false positive on every developer build.

### Apple system app notarization vs. third-party notarization
**What:** Apps bundled under `/System/Applications/` and `/System/Library/` are signed DIRECTLY by Apple using an internal certificate — they are exempt from the third-party notarization requirement and legitimately report `notarized=False`.
**Why:** The `_apps()` detection rule was flagging Calculator, Calendar, Chess, etc. as "Non-notarized application" at medium severity. Fixed by skipping any app whose `path` starts with an entry in `APPLE_SYSTEM_PATH_PREFIXES` before evaluating signing/notarization — the same prefix list already used by `is_apple_system_process()`.

## 2026-07-05

### Per-user SCA checks via shell loops over /Users
**What:** SCA `c:` rules can audit every user account (not just the console user) by looping over `/Users/*` in `/bin/sh`, reading each home's plist with `plutil -extract <key> raw`, echoing a `violation <user>` line per offender, and asserting `-> !r:violation` (all-negative pattern: passes only when no violations print, vacuously true when no user has the pref). TCC-protected paths (Safari's container) skip on "not permitted" output so an unreadable profile isn't misreported as a violation.
**Why:** CIS Apple macOS controls like AirDrop, AirPlay Receiver, screensaver idle time, Safari auto-open and Terminal Secure Keyboard Entry are per-user preferences; checking only the current user would pass a machine where any other account is misconfigured. Implemented in `sca_apple_macos.yml` (expanded 27 → 57 checks covering CIS sections 1–6).

### PyInstaller onefile data bundling for policy files
**What:** PyInstaller `--onefile` only bundles Python modules it can trace — package data files (like SCA policy `.yml`s) are silently omitted unless passed with `--add-data "src:dest"`, where `dest` mirrors the package path so `os.path.dirname(__file__)`-relative lookups resolve inside `sys._MEIPASS`.
**Why:** The binary PKG's frozen agent shipped with the SCA engine but zero policies (`BUILTIN_POLICY_DIR` was empty at runtime), so `sca` sections would come back empty on deployed endpoints. Fixed in `pkg/build_pkg.sh` with `--add-data agent/agent/sca/policies/sca_apple_macos.yml:agent/agent/sca/policies` plus explicit `agent.agent.sca` / `yaml` hidden-imports.

### launchctl bootstrap error 5 = already loaded
**What:** `launchctl bootstrap system <plist>` fails with "Bootstrap failed: 5: Input/output error" when the service is already in the system domain; the robust load sequence is bootout → enable → bootstrap, with `kickstart -k` as the fallback when bootstrap still reports 5.
**Why:** The PKG postinstall used legacy `launchctl load -w`, so users following modern docs (`bootstrap`) hit error 5 on any reinstall and read it as a broken install. Postinstall, the new `pkg/attacklens-service` CLI, and the watchdog's service subcommands all now use the bootout-first pattern.

### Dual-purpose daemon binaries (foreground default + service subcommands)
**What:** A LaunchDaemon-managed binary can keep its plist contract (`binary --config path` = run foreground) while adding an optional positional subcommand (`status|start|stop|restart|logs`) that delegates to `launchctl` — argparse `nargs="?"` with `default="run"`.
**Why:** Users naturally typed `attacklens-watchdog start` and got "unrecognized arguments" because the watchdog only accepted `--config`; giving both binaries human-facing subcommands makes the CLI match user intuition without touching the plists. Implemented in `agent/agent/watchdog.py`.

## 2026-07-04

### SCA policy format (CIS benchmarking)
**What:** A YAML policy schema for Security Configuration Assessment: `policy` metadata, a `requirements` block gating host applicability, and `checks` whose `rules` are compact strings (`f:` file, `d:` directory, `c:` command, `p:` process, `r:` registry) with `-> pattern` content matching (`r:` regex, `n:... compare` numeric, `!` negation, `&&` same-line conjunction) combined by `condition: all/any/none`.
**Why:** The agent needed CIS benchmark testing capability; adopting the de-facto industry SCA policy schema means the entire public library of CIS policies (the user supplied the Distribution Independent Linux v2.0.0 one, 190 checks) runs unmodified, instead of inventing a bespoke check DSL. Implemented in `agent/agent/sca/engine.py` with policies under `agent/agent/sca/policies/`.

### All-negative pattern semantics in SCA rules
**What:** When every minterm in a content pattern is negated (`!r:...`), the rule passes only if EVERY line satisfies it (i.e. no line matches the forbidden form) — vacuously true for empty content. A pattern with at least one positive minterm passes if ANY line satisfies all minterms.
**Why:** CIS policies express "ensure no line enables X" as `-> !r:pattern`; treating it with any-line semantics would make the rule pass whenever a single innocent line existed, silently green-lighting misconfigured hosts.

### Injectable command runner for OS-agnostic engines
**What:** The SCA engine takes a `runner(cmd, timeout) -> (rc, stdout)` callable instead of shelling out directly; the macOS collector injects a budget-aware runner built on the section-budget thread-local (`run_budget_remaining`), and `rc=None` maps to `not_applicable` rather than `failed`.
**Why:** Keeps the engine platform-independent (Linux/Windows collectors can wrap their own runners) and preserves the agent's core resilience contract — a slow command degrades one check instead of blowing the 25s section timeout; unprivileged dev runs (systemsetup demanding admin) report not_applicable instead of false FAILs.

### Per-section timeout_sec override
**What:** Sections in `_DEFAULT_SECTIONS` (and `SectionConfig` in agent.toml) can carry `timeout_sec` to override the global 25s collector deadline; `sca` uses 60s.
**Why:** A full CIS scan runs ~30 shell probes sequentially (~1s each for systemsetup/pwpolicy); under the default 25s budget the tail of the checklist would degrade to not_applicable on every cold run. SectionConfig also had to gain the field — `SectionConfig(**cfg)` would have raised TypeError on a toml override.

### Password policy and security controls layer
**What:** `manager/security_policy.py` — PBKDF2-HMAC-SHA256 (600k iterations, stdlib only) for password hashing; `validate_password()` enforcing 16-char min, four character classes, 128-char max, common-password blocklist; `SECURITY_HEADERS` dict (HSTS, CSP, X-Frame-Options, Permissions-Policy, Referrer-Policy); lockout constants (IP: 5/15min, account: 10/30min).
**Why:** The original auth used plaintext `hmac.compare_digest` against an env-var password. Upgrading to PBKDF2 makes offline brute-force ~600k× harder; dual IP+account lockout prevents credential stuffing across multiple IPs; security headers close clickjacking, MIME-sniffing, and referrer-leakage vectors. Also added a fake PBKDF2 call on unknown email (timing oracle prevention) and single-session enforcement (new login revokes all previous JTIs).

### Idle timeout (frontend auto-logout)
**What:** `AuthContext.tsx` listens to `mousedown`, `keydown`, `scroll`, `touchstart` etc. and resets a `setTimeout` on each event. No activity for `idle_minutes` (server-configured, default 30 min) triggers `logout("idle")`, which clears storage and records an `al_logout_reason=idle` in `sessionStorage`. The `LoginPage` reads that flag to show "signed out due to inactivity" instead of a generic error.
**Why:** Absolute JWT expiry (8h) alone leaves an unattended logged-in browser exposed for hours. Idle timeout closes that window on unattended workstations — a core CIS macOS benchmark requirement for session lock.

### Dashboard authentication (login page + JWT session)
**What:** A complete auth layer: `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` in `manager/api/auth_ui.py`; `AuthContext.tsx` and `LoginPage.tsx` on the frontend. JWT signed with HMAC-SHA256 (stdlib only — no new deps). httpOnly+SameSite=Strict cookie plus JSON bearer token for SPA dual delivery.
**Why:** The dashboard had no authentication at all — any browser that reached port 8080 had full admin access. Security properties implemented: rate limiting (5 failures/IP → 15-min lockout), constant-time credential comparison (`hmac.compare_digest`), no user enumeration (identical 401 for wrong email or wrong password), token revocation on logout (JTI blacklist), and local expiry checked client-side to avoid stale-token flashes.

## 2026-06-29

### "Changes not showing on the dashboard" was stale index.html caching
**What:** After a frontend rebuild, new UI didn't appear in the browser even though the manager was serving the new content-hashed bundles. The Vite SPA's `index.html` (the entry that points at the hashed JS/CSS) was served with NO `Cache-Control` header, so browsers cached it heuristically and kept loading the OLD bundle references.
**Why:** The fix is the standard SPA caching split — content-hashed assets under `/static` are immutable (safe to long-cache, their name changes when content changes), but `index.html` must be `no-cache` so the browser always re-fetches the current entry. Added `Cache-Control: no-cache, no-store, must-revalidate` to the `dashboard()` route's `index.html` response in `server.py`. Diagnosis tip: this looks like "my code didn't deploy" but the served bundle was correct all along — check the index.html cache headers and compare the served entry-hash to the build output before assuming a deploy failure.

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
