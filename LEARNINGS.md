# Learnings

## 2026-07-06

### Subcommand argparse breaks daemon invocations silently
**What:** `argparse` with `add_subparsers` exits code 2 when a caller passes only flags (`--config X`) without a subcommand; under launchd `KeepAlive` this becomes an infinite restart loop with no log file ever created.
**Why:** The v2.1.0 PKG's plist and watchdog both invoked `attacklens-agent --config ...` without `run`, so the agent crash-looped every 10s and `agent.log` never existed. Fixed by prepending `run` in `agent_entry.py` when the first arg starts with `-`.

### Watchdog fallback-target resolution
**What:** When a supervisor's configured child-binary path is missing (stale config), try an ordered list of known-good candidate paths before declaring FATAL.
**Why:** Preserved-on-upgrade `agent.toml` files still pointed `[binaries]` at removed `run_agent.py`, making the watchdog FATAL-loop; the fallback in `watchdog.py` `_resolve_fallback()` auto-switches to the native binary.

### Exit-code-2 self-adaptation in a process supervisor
**What:** If a supervised child exits 2 (argparse rejection) twice consecutively, toggle the CLI shape (with/without the `run` subcommand) and retry.
**Why:** Heals mixed-version installs (old agent binary + new watchdog or vice versa) without operator action; implemented in `watchdog.py` `_check_and_maybe_restart()`.

### One-shot idempotent `repair` command in the service CLI
**What:** A single `sudo attacklens-service repair` command that detects and fixes every known install fault (config paths, plist args, wrappers, exec bits, quarantine, stuck launchd services), then reloads and verifies.
**Why:** The troubleshooting session required ~10 manual commands across three separate faults; `repair` codifies them so any broken install recovers in one step, and `diagnose` step 7 detects the same faults read-only.

### PKG postinstall config migration on upgrade
**What:** postinstall preserves existing `agent.toml` on upgrade, so schema/path changes must be migrated in-place with idempotent `sed` in the postinstall itself.
**Why:** Fresh configs got the corrected binary paths but upgraded machines kept the broken ones; `build_pkg.sh` postinstall now rewrites legacy `.py` entry-script paths to the native binaries.

### macOS sudo drops /usr/local/bin from PATH
**What:** `sudo <cmd>` on macOS uses a restricted `secure_path` that excludes `/usr/local/bin`, so `sudo attacklens-service` fails with "command not found" even when the plain command works.
**Why:** Confused live troubleshooting; docs now use full paths (`sudo /usr/local/bin/attacklens-service`) or shell aliases.

## 2026-07-07

### .dockerignore patterns are context-root-relative
**What:** A `.dockerignore` line like `data/` only matches `data/` at the build-context root — it does NOT match `manager/data/`. Nested paths need their own explicit entries (or a `**/` prefix).
**Why:** `manager/data/` (447 MB — manager.db + hot/warm/cold telemetry tiers) was silently copied into every image by `COPY manager/`, inflating both images to 1.36 GB and causing the EC2 disk-full build failures. Explicit `manager/data/`, `manager/logs/`, and `agent/` entries cut the images to 364 MB and 314 MB.

### Verify a stripped-source image by importing inside it
**What:** When a Dockerfile deletes `.py` source after `compileall` and trims requirements, missing transitive dependencies only surface at runtime — so smoke-test with `docker run --entrypoint python3 <image> -c "import <entry module>"` after every build.
**Why:** The threat-intel requirements subset (4 of 11 packages) was validated by statically tracing the full import chain (threat_intel_service → indexer/pg_pool → attacklens engine → detections/threat = only fastapi, asyncpg, aiohttp external), then confirmed by importing the app object inside the built image.

### Docker requirements split for multi-service images
**What:** When a monorepo builds two images from one `requirements.txt`, create a service-specific subset (e.g. `requirements-threat-intel.txt`) listing only what that service's entry-point actually imports.
**Why:** `ThreatIntel.Dockerfile` was installing all 11 packages including `anthropic`, `aio-pika`, and `aiosmtplib` which are manager-only; the subset (fastapi, uvicorn, asyncpg, aiohttp) cuts install time and image size significantly.

### Source stripping in a multi-stage Dockerfile
**What:** Add a build stage that runs `python -m compileall -b` then deletes all `*.py` source (except empty `__init__.py` stubs) so the final image ships only `.pyc` bytecode.
**Why:** `ThreatIntel.Dockerfile` lacked this stage and copied the full `.py` source tree into every image; mirroring the pattern already in `manager/Dockerfile` closes the gap.

### Postgres-native size functions in retention stats
**What:** `pg_total_relation_size('payloads')` and `pg_database_size(current_database())` return exact on-disk byte counts for a table and the whole database without a full-table scan; safe to include in a `COUNT(*) + SUM(...)` aggregate query.
**Why:** The retention dashboard showed only estimated payload bytes (`SUM(LENGTH(data))`); adding the Postgres system-catalog functions lets the Settings panel show true table and DB footprints.

### Client-side periodic refresh for live storage stats
**What:** `setInterval` in a React `useEffect` with a cleanup that calls `clearInterval` on unmount keeps the storage widget current without the user navigating away and back.
**Why:** The retention panel previously loaded stats once on mount; with 1-day retention and frequent ingestion, numbers became stale within minutes — 60-second auto-refresh plus a manual refresh button keeps the display accurate.

### 1-day minimum retention period
**What:** The `retention_period_months=0` sentinel now maps to 1 day (was 7 days), making the default the smallest possible hot dataset.
**Why:** EC2 disk pressure from 381 MB node_modules and a growing payloads table made a 7-day minimum too generous for demo/single-agent deployments; 1-day default dramatically reduces steady-state storage cost.

## 2026-07-09

### Vite `base` path and static asset references in React
**What:** When Vite is configured with `base: '/static/'`, all public-directory assets (e.g. `public/logo-icon.svg`) are served at `/static/logo-icon.svg`, not `/logo-icon.svg`. React components must use the full `/static/` prefix in `src` attributes.
**Why:** LoginPage.tsx used `src="/logo-icon.svg"` (missing the prefix), causing a 404 — the logo never rendered on the login screen. Sidebar.tsx had the correct `/static/logo-icon.svg` reference; aligning LoginPage to match fixed it.

### Post-emission Finding Validation Layer (NVD + CISA KEV + ExploitDB)
**What:** `attacklens/finding_validator.py` validates emitted findings (by CVE ID) against NVD, CISA KEV, and ExploitDB via the existing `IntelPipeline.enrich_cve()`. Produces a `FindingValidationReport` with a `verdict` (CONFIRMED / CORROBORATED / DISPUTED / UNVERIFIED / N/A) and a multiplicative confidence adjustment.
**Why:** The existing 8-gate cluster validator fires before a finding is emitted; after emission, analysts need authoritative TI corroboration to prioritize triage. KEV membership or a public exploit (ExploitDB / Metasploit) is the strongest upgrade signal; missing NVD entry is a credibility reduction.

### Multiplicative confidence model for TI validation
**What:** `confidence_after = base × nvd_mult × kev_mult × exploit_mult` clamped to [0, 1]. KEV adds 1.60×, ExploitDB/Metasploit adds 1.25×, EPSS ≥ 0.50 adds 1.10×, absent NVD entry reduces to 0.70×.
**Why:** Additive models saturate at 1.0 too easily when multiple sources agree; multiplicative compounding gives stronger boosts to findings that hit KEV + high CVSS + exploit simultaneously, while NVD-absent findings still get a meaningful credibility penalty.

### Finding lifecycle recommendation from TI verdict
**What:** `_recommended_action(verdict, current_status)` maps validation verdicts to canonical lifecycle actions: CONFIRMED → "investigate", CORROBORATED → "open", DISPUTED → "false_positive". Actions are checked against `finding_lifecycle.can_transition()` before being surfaced.
**Why:** Verdict alone is not enough — the analyst needs a concrete next step. Gating on the lifecycle state machine prevents nonsensical recommendations (e.g. suggesting "open" on an already-closed finding).

### React `key` prop as external-filter remount pattern
**What:** Passing `key={terrain + statusFilter + validatedOnly}` to `TerrainDetectionPage` forces a full remount (resetting all internal state) when the parent changes top-level filter values. This avoids lifting the entire filter state up into the parent.
**Why:** `Incidents.tsx` needed terrain chips and status tabs that live outside `TerrainDetectionPage`, but re-initializing the inner filter state on every parent render would be expensive and error-prone. A `key` remount is the cleanest way to say "start fresh with these new initial values."

### localStorage-backed case management for MVP SOC workflows
**What:** `ALCase` objects (id/title/description/priority/status/assignee/tags/findings/timestamps) are serialized to `localStorage["al_cases"]`. CRUD helpers (`loadCases`, `saveCases`, `createCase`) are plain functions that sync synchronously, no backend required.
**Why:** Adding a full case-management DB schema and API endpoints for an MVP would have blocked the feature. localStorage gives analysts a working create/close/tag workflow immediately, and the case store can be migrated to a backend endpoint later without changing the component interface.

### Timeline view grouped by calendar day
**What:** `TimelineView` in `Incidents.tsx` sorts findings by `last_detected_at` descending, groups into day buckets using `toLocaleDateString`, and renders each group as a collapsible timeline section with severity-colored dots and a timeline connector line.
**Why:** CrowdStrike Falcon and Cortex XDR both surface incident timelines as a core analyst workflow — chronological grouping lets SOC teams understand attack progression across a day rather than just sorted score tables.

### Provider-agnostic AI integration layer
**What:** `manager/ai/base.py` defines an abstract `AIProvider` with a single `chat()` method. `manager/ai/providers.py` implements four concrete providers (Anthropic, OpenAI, Gemini, Ollama) all over `aiohttp` — no SDK dependencies. `manager/ai/finding_analyzer.py` drives them with shared structured prompts that produce consistent JSON regardless of provider.
**Why:** The original `ai_analyst.py` was Anthropic-only (imported `anthropic` SDK). Enterprise customers need provider choice — some use OpenAI via Azure, others want free local Ollama for data-sovereignty reasons. The abstraction means analysis + remediation prompts only need to be written once.

### Customer-managed API key encryption (AES-256-GCM + HKDF)
**What:** `manager/ai/key_store.py` derives a 256-bit AES key from `JWT_SECRET` via HKDF-SHA256, encrypts the customer's API key with AES-256-GCM (random 96-bit nonce per write), and stores the result in `data/ai_provider.enc`. Only a masked preview (`sk-abc…xyz4`) is ever returned to the UI.
**Why:** Storing API keys in plaintext `.env` or the DB is a common misconfiguration risk. Tying encryption to `JWT_SECRET` (which the operator already protects) means a compromised DB file or disk snapshot can't expose the AI key without also compromising the JWT secret — raising the attack bar.

### Lightweight models for cost-efficient security analysis
**What:** Each provider defaults to its cheapest fast model for finding validation: `claude-haiku-4-5`, `gpt-4o-mini`, `gemini-1.5-flash`, `llama3.2:3b` (Ollama). Remediation plans use the same model but with higher token budgets (2000 vs 800). Token counts are tracked per call and logged.
**Why:** Running analysis on every finding at Sonnet/GPT-4 prices makes the feature too expensive for bulk use. Haiku costs ~$0.001/finding and GPT-4o-mini ~$0.0003/finding — both fast enough for interactive use in the drawer without noticeable latency.

### AI analysis cache columns must round-trip JSON lists as lists
**What:** `get_ai_analysis` / `get_remediation_plan` now deserialize their JSON-string columns (`risk_factors`, `ioc_matches`, `steps`, etc.) back into Python lists before returning. Added `provider`/`urgency`/`mitre_context`/`latency_ms` (and remediation `compensating`/`tokens_used`) columns via `_SOC_MIGRATIONS` + the `CREATE TABLE` so multi-provider metadata survives a cache round-trip.
**Why:** `get_ai_analysis` previously returned `risk_factors` as the raw JSON *string*; the AI-tab UI calls `.map()` on it, so the first (fresh) generation rendered but reopening the drawer (cache hit) crashed with a TypeError. The new provider-agnostic fields were also silently dropped on write, so urgency/MITRE/provider changed between first view and reload.

### Peek-before-generate to avoid silent LLM spend
**What:** Added `GET /api/v1/ai/analysis/{id}` and `GET /api/v1/ai/remediation/{id}` cache-only endpoints (404 if absent). The FindingDetail AI tab peeks these on mount and only calls the paid `POST /analyze|/remediate` on an explicit button click.
**Why:** The mount effect originally POSTed to `/analyze`, which *generates* when the cache misses — so merely opening the AI tab on an un-analyzed finding spent an API call with no user intent. Splitting read (GET, free) from generate (POST, paid) makes cost explicit and user-driven.

### Prompt-injection hardening for endpoint-sourced finding text
**What:** Finding free-text (title/description/evidence/recommendation) is wrapped in `<untrusted>…</untrusted>` tags via `_wrap_untrusted` (which neutralizes tag-breakout), and the shared `SYSTEM_PROMPT` instructs the model to treat that content as data-not-instructions and only emit standard remediation commands.
**Why:** Those fields come from monitored endpoints that may be attacker-controlled (malicious process/package names). Injected verbatim into the LLM prompt, a crafted finding could steer the model to emit a malicious shell command shown with a copy-to-clipboard button — a real risk for a security product where analysts run suggested commands.

### Unified exploitability score (threat-likelihood × asset context)
**What:** `threat/exploitability.py` computes a 0–100 exploitability score from six factors (CVSS, EPSS, KEV, exploit availability, vulnerability recency, asset criticality) as a weighted base ESCALATED by active-exploitation floors (KEV→90, weaponized+CVSS≥7→78, EPSS≥0.5→70, any exploit→55) and amplified +10% for crown-jewel assets. Returns a band + fully auditable per-factor breakdown. Computed at the single write chokepoint (`upsert_finding`) so every emit path is consistent; recency uses the CVE publication date (`cve_published_ts`, resolved from `cve_entries`/`nvd_cve_local`).
**Why:** The existing `composite_score` (RiskScoreMatrix) never used `exploit_available` and its "recency" was telemetry freshness, not CVE age — so a theoretically-severe CVE with no exploit could outrank a KEV-listed one. A flat weighted sum has the same flaw; the escalation-floor design (mirroring Tenable VPR / CISA SSVC) guarantees actively-exploited vulns can never rank below their exploitation tier. Verified: "CVSS 9.8 only, no exploit/KEV" → 24/low, while a KEV+weaponized peer → 100/critical.

### Verifying multi-column SQL INSERT/UPDATE edits by placeholder count
**What:** After adding `exploitability_score`/`exploitability_band` to `upsert_finding`'s INSERT (45 cols) and UPDATE, a regex check counted `?` placeholders + literal values against the column list and caught an off-by-one (2 columns added, only 1 `?`).
**Why:** The big positional INSERT/UPDATE statements in `indexer.py` use bare `?` with a parallel params tuple — a miscount silently shifts every value one column over (or errors at runtime under load, not at import). Counting placeholders vs columns programmatically before running is far cheaper than debugging a corrupted write path.

### Standardized integration reliability layer
**What:** `manager/integrations/` provides a shared resilience layer for every external dependency: typed errors (Transient/Permanent/RateLimited/CircuitOpen), a `RetryPolicy` (exp backoff + full jitter, honours Retry-After, retries only 429/5xx/network), a generalized three-state `CircuitBreaker`, an `IntegrationRegistry` (per-integration metrics: calls/success/fail/retries/timeouts, p50/p95/p99 latency, breaker state), and a `ResilientHTTPClient` composing them (timeouts + retries + breaker + fallback + metrics). Exposed via `GET /api/v1/integrations/health`. The AI providers were refactored off their ad-hoc `_with_retries` onto this client.
**Why:** Reliability was inconsistent — `intel/sources.py` had a good breaker but it was local; AI providers/feeds/nvd each rolled their own retry with no shared observability, no jitter, and 4xx errors were retried wastefully. One standardized path makes failure handling uniform and gives operators a single health surface (breaker-open→HTTP 503, degraded→207) that uptime probes can alert on.

### 4xx must fail fast; only retry transient failures
**What:** `ResilientHTTPClient` maps 429→RateLimited (retry, honour Retry-After), 5xx/network/timeout→Transient (retry with backoff), and other 4xx→Permanent (no retry, fail immediately). The circuit breaker counts all failures but permanent errors short-circuit the retry loop.
**Why:** Retrying a 400/401/403 wastes latency and quota and can trip rate limits — the request will never succeed as-is. Distinguishing transient from permanent at the transport layer means callers never re-implement this and quota isn't burned on doomed retries.

### Offline validation harnesses for accuracy + performance
**What:** `tests/validation/test_detection_accuracy.py` scores a labeled corpus of 10 attack scenarios and asserts band accuracy (100%) plus ranking-integrity invariants (KEV always critical, active-exploitation outranks theoretical high-CVSS, monotonic tier ordering). `scripts/perf/loadtest.py` is an async load generator measuring p50/p90/p95/p99 latency, throughput (req/s), and data efficiency (MB/s) against any deployment, with `--slo-p95-ms`/`--max-error-rate` gating for CI and a `--selftest` that validates its own percentile math with no server.
**Why:** Detection quality and performance need to be regression-tested, but the full engine needs the live DB/pipeline. Splitting out the pure scoring-accuracy corpus and a deployment-agnostic load driver lets both run in CI (accuracy fully offline; perf against the AWS host) without standing up the whole stack.

### Default bootstrap credential surfaced only while active
**What:** `/api/v1/auth/policy` returns a `default_credentials` block whose `active`/`email`/`password` are populated ONLY when `_USING_DEFAULT_CREDENTIALS` is true — i.e. the operator has set neither `DASHBOARD_PASSWORD_HASH` nor a custom `DASHBOARD_PASSWORD`. The login page reads it and, when active, renders a first-run card with the credential plus copy + "Autofill & sign in" buttons.
**Why:** The login footer already promised "Password shown on first login screen" but nothing showed it. Surfacing the built-in default is a legitimate first-run convenience (cf. Jenkins initialAdminPassword), but must never leak an operator-set credential — so the backend gates exposure on the default actually being in use, and we only ever expose the known hardcoded default (operator passwords exist only as a hash anyway).

## 2026-07-11

### Write-through in-memory LRU dedup cache for ingest
**What:** `IngestDeduplicator` holds an `OrderedDict` (LRU) of `(agent_id, category, item_key) → _CacheEntry`. Every `upsert_finding` call hits `check()` first; "unchanged" hits are counted and batched into a single 30-second `UPDATE findings SET last_detected_at, scan_count, consecutive_unchanged` instead of individual DB reads/writes.
**Why:** Most agent telemetry is repetitive (same process/network state across scans). Without a cache, each re-submission triggers a DB SELECT + conditional UPDATE — at 160 findings/scan × 6 scans/hour the hit rate reached 73% in testing, cutting DB ops by ~96% for stable environments.

### Three-path upsert: miss / unchanged / changed
**What:** `upsert_finding` now returns one of three strings: "miss" (cache cold, DB SELECT required), "unchanged" (cache hit, content hash identical — batched heartbeat only), or "changed" (cache hit but content differs — triggers DB UPDATE and cache refresh).
**Why:** Collapsing "miss" and "changed" into the same code path while short-circuiting "unchanged" before any DB I/O gives the tightest possible separation. The `consecutive_unchanged` counter (new DB column) lets analysts know how long a finding has been stable without a full history scan.

### Content fingerprinting vs identity key separation
**What:** A finding's identity key is `(agent_id, category, item_key)` (immutable). Its content fingerprint is SHA-256 of mutable fields only: severity, score, title, description, mitre_technique, source, cve_ids. These are computed separately so the cache can distinguish "same finding, same content" from "same finding, updated content."
**Why:** Using the full row as the fingerprint would cause false "unchanged" hits when transient fields (last_detected_at, scan_count) change; using only the identity key would mean any severity change goes undetected. Separating the two concepts avoids both failure modes.

### React Router v7 SPA catch-all on FastAPI
**What:** A wildcard `@app.get("/{full_path:path}")` route registered LAST in server.py returns `index.html` for any path that doesn't start with `api/` or `static/`. This makes direct URL access and browser-refresh on client-side routes work correctly.
**Why:** FastAPI served only `/` for the SPA; navigating to `/settings` or refreshing `/findings` returned a 404. The catch-all must be registered after all API routes so it never shadows real endpoints.

### React Router v7 root layout for shared context providers
**What:** A route with `element: <RootLayout />` (no `path`) and `children` for all routes provides a single `AuthProvider` + `RBACProvider` instance that is shared by both `/login` and the authenticated shell. This avoids double-wrapping that would give each route a separate auth state.
**Why:** Naive router designs wrap `AuthProvider` per route branch (login separately from the app shell), so `ProtectedRoute` checks a different auth instance than the one that `LoginPage` writes to — the guard never sees the fresh token.

### URL-param tab navigation (replace useState with useParams + useNavigate)
**What:** Instead of `useState<TabId>`, deep-linked tabs read their active state from `useParams()` and write it with `navigate(\`/section/${newTab}\`)`. The router provides `/intelligence/:tab` and `/settings/:section` routes; both components validate the param against an allowlist and fall back to a default.
**Why:** `useState` tabs break bookmarking, browser back/forward, and direct deep-links (e.g. sharing `/settings/retention` or `/intelligence/kev`). URL-driven state costs nothing extra and the browser's history stack is the right home for navigation position.

### Feature-based page directory structure
**What:** Pages are organised under `src/app/pages/{domain}/{sub-route}/index.tsx` (e.g. `terrain/origin/index.tsx`, `settings/retention/index.tsx`). Each file is a thin re-export pointing at the real implementation still in the flat `pages/` directory. The router imports flat implementations directly; the directories exist as the canonical source-of-truth URL namespace.
**Why:** A flat `pages/` directory with 20+ files has no information about which routes are related or how they nest. Feature folders make the URL tree visible in the filesystem and give each route segment a clear home for future colocation (loaders, error boundaries, sub-components).

### Expert SOC ThreatIntelligence page architecture
**What:** `ThreatIntelligence.tsx` was rewritten as a five-tab SOC workspace: IOC Triage (sortable/filterable table with status, risk score, bulk ops, multi-format export), CVE Intel, KEV Mandates (SLA countdown), Hunt Queries (per-IOC Splunk/KQL/Suricata/Sigma queries), and Feed Status. Each IOC opens a full slide-out panel with category intelligence, incident response playbook, block-in targets, copyable hunt queries, and external validation refs.
**Why:** The old page was read-only — no action surfaced on each IOC. A real SOC analyst needs category-specific playbooks, one-click export to firewall ACL / Suricata rules, pre-built SIEM queries per IOC value, and CISA KEV due-date tracking with overdue alerting in a single workflow.

## 2026-07-11

### Domain-specific KPI header pattern for terrain pages
**What:** Each Attack Terrain page (Origin/Vector/Citadels) now mounts its own `useDetectionData` call against the same endpoint as the underlying `TerrainDetectionPage`, computes domain-specific aggregate stats (CVSS ≥9, KEV count, malware count, active C2, etc.) and renders them as a 5-tile KPI strip above the table. Browser HTTP cache deduplicates the identical GET requests so there is no actual double-fetch cost.
**Why:** The generic TerrainDetectionPage KPIs (Total/Critical/High/KEV/MITRE) lack domain meaning — an Origin analyst needs avg CVSS and EPSS rates, a Vector analyst needs feed source breakdown and C2 confidence, a Citadels analyst needs malware vs script vs lateral-movement split. Domain stats turn the page from a generic table into a terrain-aware SOC workspace.

### `initialKevOnly` / `initialExploitOnly` / `initialCategoryFilter` / `initialSearch` props on TerrainDetectionPage
**What:** Added four optional initial-filter props to `TerrainPageProps` and the `TerrainDetectionPage` function signature. They seed the `TerrainFilterState` `useState` on first mount. Combined with `key={pageKey}`, the parent can set wrapper-level toggles (e.g. "KEV Only" button) that take effect on remount without lifting the entire filter state into the parent.
**Why:** Terrain page wrapper controls (package manager chips, KEV-only button, category chips) had no mechanism to communicate their state to TerrainDetectionPage's internal filter bar. The `key`-remount pattern with initial props is the correct React pattern for this: parent owns the coarse filter state, child owns UI-level refinements on top of it.

### Terrain-specific alert banners as priority signals
**What:** Each terrain page shows a red/amber alert strip when actionable conditions exist: Origin shows a count of KEV+exploit combinations with a CISA KEV link; Vector highlights high-risk C2 connections; Citadels highlights malware detection count with MITRE TA0002 link. The strip is hidden when no findings qualify.
**Why:** SOC analysts scan pages quickly — a colored strip that says "2 KEV vulnerabilities with active exploit" is immediately triageable, whereas a number buried in a KPI tile is not. Matches the priority-surfacing model of CrowdStrike and Cortex XDR.

### Incidents page terrain-tab counts + severity distribution bar
**What:** Incidents.tsx fetches the full dataset with a second `useDetectionData` call to compute per-terrain finding counts (shown as chip badges on terrain tabs) and a severity distribution bar (stacked proportional bar + count legend) that updates as the filter state changes.
**Why:** Terrain tabs with counts let an analyst immediately see where incidents are concentrated without clicking each tab. The severity bar provides the same information as four separate count tiles but in a more visual, scannable format that's faster to parse under time pressure.

## 2026-07-12

### Shared-component bulk selection via `Set<number>` + `POST /api/v1/soc/bulk`
**What:** Bulk selection state (`Set<number>` named `bulkSel`) with `toggleOne`, `toggleAll`, `clearBulkSel`, and `doBulk` lives inside `TerrainDetectionPage` in `DetectionShared.tsx`. `doBulk` posts `{ finding_ids, action, value, actor }` to `/api/v1/soc/bulk`, clears the set, and calls `refetch()`. The toolbar (6 actions: Triage/Investigate/Remediate/Close/FalsePos/AcceptRisk) is RBAC-gated via `can("bulk_action")` from `useRBAC`.
**Why:** All four terrain pages (Origin/Vector/Citadels + Incidents list) use `TerrainDetectionPage` as their table host, so implementing bulk selection once in the shared component propagates it everywhere. Replicating ThreatQueue's standalone bulk pattern inside the shared component avoids copy-pasting across four page files.

### `e.stopPropagation()` on a cell for dual-action row click
**What:** The checkbox `<td>` has its own `onClick={e => { e.stopPropagation(); toggleOne(f.id); }}`, while the parent `<tr>` retains `onClick={() => setSelected(...)}` to open the detail drawer. The cell renders `CheckSquare` or `Square` and an orange row background when `bulkSel.has(f.id)`.
**Why:** Without `stopPropagation`, clicking the checkbox both selects the row AND opens the drawer — conflicting intents. Stopping propagation on the cell is the minimal fix: checkbox-click stays a pure toggle, row-click-elsewhere still opens the drawer normally.

## 2026-07-13

### FastAPI 404 exception handler as SPA catch-all replacement
**What:** Replace `@app.get("/{full_path:path}")` SPA catch-all with `@app.exception_handler(404)` that checks the request path — API/static paths return `JSONResponse(404)`, all other 404s return `index.html`. This means no route is registered that can shadow real API routes.
**Why:** The catch-all GET route was intercepting `GET /api/v1/custom-correlations` despite being registered after the API router. The exception handler fires only when no route matches, so it can never shadow a real route — eliminating the route-ordering race entirely.

### IntelDB write pattern: `_conn.execute()` + `_conn.commit()`
**What:** `IntelDB` exposes `_fetchone(sql, args)` and `_fetchall(sql, args)` for reads. Writes must go through `await intel_db._conn.execute(sql, args)` followed by `await intel_db._conn.commit()`. There is no `_execute()` method.
**Why:** The original Custom Correlation API used `intel_db._execute()` which does not exist, causing every write to raise `AttributeError` (surfaced as a 500 or 404 depending on which handler ran). Replacing all write calls with the correct pattern fixed the CRUD API.

### SQL column names from `indexer._SCHEMA`: use `last_detected_at` / `first_detected_at`
**What:** The `findings` table has `last_detected_at` and `first_detected_at` columns. There is no `detected_at` or `created_at` column on findings.
**Why:** Multiple query strings in `custom_correlations.py` and `custom_correlator.py` ordered by `detected_at DESC` or filtered on `detected_at`, hitting "column does not exist" errors. Correcting to `last_detected_at` fixed ordering and time-window filtering.

### Base `CREATE TABLE` must include migration columns
**What:** Columns added later via `_SOC_MIGRATIONS` must also exist in the base `CREATE TABLE` statement in `_SCHEMA`; otherwise a fresh database (no prior migrations) initializes without those columns, causing runtime errors on any query that references them.
**Why:** `consecutive_unchanged` and `content_changed_at` were only in `_SOC_MIGRATIONS`, so fresh Postgres DBs (e.g. in CI) failed `upsert_finding` with "column does not exist". Adding both to the base `CREATE TABLE findings` fixed fresh-start initialization.

### React Router v6.4 data-router errorElement vs class ErrorBoundary
**What:** `createBrowserRouter` has its own route-level error handling that intercepts render errors BEFORE they bubble to class-based `ErrorBoundary` components in the React tree. The default UI is the "Unexpected Application Error!" dev overlay. Fix: add `errorElement: <RouteErrorPage />` to each route object; `RouteErrorPage` uses `useRouteError()` and `isRouteErrorResponse()` to display a clean error UI with retry/dashboard buttons.
**Why:** A `ReferenceError` in `DeepAnalysis.tsx` (`showSmartSearch` used before declaration) caused the entire page to show React Router's ugly dev error UI, not our custom `ErrorBoundary`. Class boundaries only work for errors that bubble past the router, not inside it.

### `score ?? 0` guard before `.toFixed()` on API-supplied numeric fields
**What:** Fields like `composite_score` and `score` from detection API payloads are typed as `number` but can be absent at runtime (API may not include them). Calling `.toFixed()` on `undefined` throws `TypeError: undefined has no method toFixed`. Guard with `?? 0` at the assignment site.
**Why:** `ThreatQueue`, `Incidents`, and `DeepAnalysis` all showed blank pages (caught by ErrorBoundary) when findings lacked score fields, which is normal for findings in certain states (e.g. newly ingested, not yet scored).

### FastAPI SPA 404 handler must check `request.method`
**What:** The `@app.exception_handler(404)` SPA handler that serves `index.html` for unknown paths must also check `request.method == "GET"`. Without this, a `POST`/`PUT`/`DELETE` to an unknown path returns `200 OK` with HTML content instead of `404 JSON`, confusing API clients.
**Why:** FastAPI exception handlers receive ALL 404s regardless of HTTP method. API clients sending a mutating request to a wrong path were silently receiving HTML and misinterpreting it as a success.

### `cases.py` GET returning 404 for no-case-yet causes console noise
**What:** `GET /api/v1/cases/{finding_id}` used to raise `HTTPException(404)` when no case had been opened. Changed to return `{}` (empty object). The frontend should treat an empty response as "no case yet" rather than an error.
**Why:** The UI polls this endpoint whenever a finding detail drawer is opened, including for newly-ingested findings that have never had a case. 404-as-normal-flow generated console noise and required null-guards on every call site.

## 2026-07-21

### Git-derived app version surfaced on the dashboard
**What:** Version scheme is `1.0.<commit-count>` computed from `git rev-list --count HEAD`. `deploy.yml` computes it (with `fetch-depth: 0` so the count isn't 1 from a shallow clone) and passes `APP_VERSION`/`APP_COMMIT`/`APP_BUILT_AT` as Docker build-args → `ENV` in the image. `manager/manager/version.py` resolves version from env first, then git, then `1.0.0-dev`, cached with `lru_cache`. Exposed via `/api/v1/meta` and `/health`; the Dashboard header fetches `/api/v1/meta` and renders a `v1.0.N` badge.
**Why:** User wanted the dashboard to show a version that auto-advances on every GitHub push without manual bumps or bot commits. Deriving the patch number from commit count means each push increments it for free; baking it in at build time avoids needing `.git` inside the stripped-source runtime image.

## 2026-07-23

### macOS boot-persistence self-repair beyond RunAtLoad
**What:** `agent/os/macos/boot_persistence.py` guarantees the agent auto-starts after shutdown/reboot. The base auto-start is already the LaunchDaemon's `RunAtLoad=true` + `KeepAlive=true`; the new module hardens the gaps RunAtLoad can't cover. `ensure_boot_persistence()` verifies the plist exists, is well-formed (`_analyze_plist` regex-checks RunAtLoad/KeepAlive/binary/label), is `root:wheel`/`0644`, is launchd-`enabled` (a `launchctl disable`d job never fires RunAtLoad even though the plist is present — a persistence-defeat vector), and is loaded — then repairs each drift (rewrite plist, chown/chmod, `launchctl enable`, re-bootstrap). It runs at agent startup (`on_agent_startup` in `core.py`, macOS-guarded) and on every `self_heal` cycle. Repair requires root and is verify-only otherwise; bootstrap is throttled (`_BOOTSTRAP_MIN_GAP_SEC`) so the 5-min self_heal cadence can't thrash launchctl. Added `is_enabled()`/`enable()` to `launchd.py` (parses both `print-disabled` formats: `=> true` and `=> disabled`).
**Why:** RunAtLoad alone silently fails to survive a reboot if an attacker or botched uninstall deletes/disables the plist — KeepAlive can't save a job that no longer exists at boot. Self-repair on a root-run agent rewrites its own persistence so the *next* boot still starts it.

### Reboot detection via kernel boot-time marker + clean-stop flag
**What:** `detect_boot_transition()` persists a marker (`/Library/AttackLens/boot_state.json`: kernel `boot_time`, `last_seen`, `clean_stop`). On startup it compares the stored kernel boot time (psutil `boot_time()`, falling back to `sysctl -n kern.boottime`) to the live one; a change = the box rebooted since the agent last ran. It emits a `system_boot` telemetry event (new `Orchestrator.emit_event()` public wrapper over `_enqueue`) with estimated `downtime_sec` (new boot minus last heartbeat) and `clean_shutdown` (True only if the agent got a graceful SIGTERM → `mark_clean_stop()` in `core._shutdown`; a power loss/panic/SIGKILL leaves it False → reported unexpected). A 60s daemon thread `touch_heartbeat()` keeps `last_seen` fresh for accurate downtime, and must NOT reset `clean_stop`.
**Why:** Unexpected reboots are a real security signal (attackers reboot to clear volatile state or apply persistence). The clean-stop flag distinguishes an orderly reboot from a hard power loss without parsing system logs.

### Wake-from-sleep resume via monotonic-gap detection in the sender loop
**What:** `Sender._drain_loop` measures `time.monotonic()` between its ~1s iterations; a jump past `_WAKE_GAP_SEC` (30s) means the process was suspended (system slept/hibernated). On resume it forces `self._online = False` and resets the probe backoff, so a spool built up while asleep drains immediately instead of waiting out the offline backoff (up to 30s). Generic (not macOS-only) and safe — if the link is actually fine the reprobe restores online in ~2s at negligible cost.
**Why:** After wake, cached sockets are dead and the network may have changed; the existing offline backoff could delay reconnect/drain by up to 30s. The monotonic-gap trick detects sleep with zero extra dependencies or OS wake hooks.

### macOS reboot failure: login keychain is locked for a root daemon at boot
**What:** The runtime keystore is `agent/agent/keystore.py` (not `agent/os/macos/keystore.py`, which is unused by `core`). Its `store_key(backend="keychain")` wrote the key to the login keychain via `keyring` and returned **without** a file copy. The agent runs as a root LaunchDaemon that starts at boot with **no user login session** → the macOS login keychain is locked → `load_key` returns nothing → the process stays up (KeepAlive happy, nothing crashes) but can't authenticate, so it churns on enrollment / delivers zero telemetry. Fix: (1) `store_key` now **always mirrors the key to the ACL-restricted file** (`/Library/AttackLens/security/<id>.key`, 0600 root-only) even for the `keychain` backend — the only storage a root daemon can read at boot; (2) fresh pkg installs generate `keystore = "file"` (`generate_config.sh`); (3) `_obtain_api_key` mirrors a keychain-loaded key to the file on startup so older keychain-only installs self-heal on first run; (4) the pkg postinstall now polls `launchctl print system/com.attacklens.agent` for a PID and dumps `agent-stderr.log` if the daemon didn't reach `running`, surfacing crash-loops at install time instead of after a reboot.
**Why:** "Works interactively, dead after restart" is the classic macOS system-daemon trap — the login keychain simply does not exist before a user logs in. Boot-critical secrets for a root daemon must live in the System keychain or a root-owned file, never the login keychain. Documented as TROUBLESHOOT.md Issue 5c.

### Agent edge-case hardening sweep (config, singleton, disk-full, clock-skew)
**What:** Four production-agent failure classes hardened with tests. (1) **Single-instance guard** (`agent/agent/single_instance.py`, `fcntl.flock`): the `com.attacklens.agent` LaunchDaemon runs the agent directly AND the `com.attacklens.watchdog` LaunchDaemon spawns the agent as a child (`watchdog.py` `subprocess.Popen`) — both with RunAtLoad/KeepAlive, so two agents could race on the shared `unsent.ndjson` spool (duplicate telemetry, `drain()` read-then-remove corruption). `core.main` now acquires an advisory lock (5s wait covers restart overlap) and a duplicate exits cleanly; POSIX-only no-op elsewhere. (2) **Config robustness**: `core.load_config` was a raw `tomllib.load` with no error handling — a missing file / malformed TOML / missing `[manager].url` crashed the daemon into a launchd restart-loop. Now raises `ConfigError` with an operator-actionable message and `main` exits 78 (EX_CONFIG) once instead of looping; `_print_status` uses a RAW parse (must work when config is invalid). (3) **Disk-full**: `DiskSpool.write` never raises (ENOSPC/EROFS/non-serialisable → counted-dropped, trims on ENOSPC to free room); the sender send-path is fully try-wrapped so no surprise kills the delivery thread. (4) **Clock-skew**: the collector scheduler runs on `time.time()`, so a backward NTP correction after boot would stall all collection; `Orchestrator._maybe_reseed_on_skew` re-seeds the schedule on a backward jump > `_CLOCK_SKEW_BACKWARD_SEC` (60s). +38 tests.
**Why:** These are the recurring failure modes of long-running endpoint agents — duplicate instances, unreadable/partial config, exhausted disk, and non-monotonic clocks. Each previously had a path to silent total failure (dead thread, restart loop, or stalled collection); all now degrade safely and visibly. The single-instance finding also surfaced a latent topology bug: both the agent and watchdog LaunchDaemons start an agent.

### Single-supervisor LaunchDaemon topology (fix the duplicate-agent root cause)
**What:** Live diagnosis on the dev Mac showed TWO `attacklens-agent run` processes — pid 549 (parent launchd, the `com.attacklens.agent` daemon) and a second spawned by the watchdog chain, one burning ~16% CPU — because the pkg postinstall bootstrapped BOTH `com.attacklens.agent` (runs the agent directly) and `com.attacklens.watchdog` (spawns an agent via `subprocess.Popen`), each with `RunAtLoad`/`KeepAlive`. Fix in `pkg/build_pkg.sh` postinstall: start ONLY the agent daemon, and `launchctl disable` + `bootout` the watchdog (plus `pkill -f "attacklens-agent run"` to clear a dual-daemon orphan). launchd's own `KeepAlive` already provides crash recovery, so the agent-only topology is the supported default; the watchdog model is opt-in (disable agent, bootstrap only watchdog — never both). The `single_instance.py` `flock` guard remains as defense-in-depth (lock at `/Library/AttackLens/attacklens-agent.lock`). Also confirmed the user's "agent not up" was compounded by the **manager stack being down** (no `attacklens-*` containers; `docker compose up -d` needed) — the agent was healthy but had nowhere to deliver.
**Why:** Two agents race on the shared `unsent.ndjson` spool (duplicate telemetry + `drain()` read-then-remove corruption) and waste CPU. "Only one launchd job may start the agent" is the invariant; running both is the bug, and it must be fixed at the source (which daemon gets bootstrapped), not just masked by the runtime lock.

## 2026-07-26

### Agent resilience hardening — tranche 1 (supervision, manifest, dedup logging, overlap, Retry-After)
**What:** Implemented the Critical/High "auto-troubleshooting" core of a 15-row resilience matrix (design in `docs/superpowers/specs/2026-07-26-agent-resilience-hardening-design.md`). Four net-new/modified pieces: (1) **Supervision tree** (`agent/agent/supervision.py`) — a `HeartbeatRegistry` where sender/orchestrator pulse `last_alive` each loop iteration and `last_success` on real progress; a pure `evaluate()` verdict (healthy/escalate/restart) + bounded `RestartTracker`; `core.main` runs a supervisor thread that ESCALATEs (throttled log) a worker that's alive-but-not-delivering (e.g. manager down) and, for a wedged/dead thread (stale `last_alive` > 300 s), calls `os._exit(70)` so launchd does a clean restart — single lifecycle owner, never a competing supervisor. (2) **Install manifest + SHA-256** (`agent/agent/manifest.py`) — `verify_component()` checks path/size/checksum with fail-fast ordering; mismatch → `should_degrade` (stop, don't retry-loop); absent manifest is a non-degrading rollout state. (3) **Structured deduped logging** (`agent/agent/obs.py`) — `log_throttled(key,…)` emits first occurrence then ≤1×/interval with a `suppressed=N` count + `key=value` fields. (4) Orchestrator **per-collector overlap lock** (`_inflight` set, `skipped_overlap` counter in `agent_health`) so a section slower than its interval isn't double-submitted; and sender now **honors `Retry-After`** (delta-seconds or HTTP-date, capped 120 s, interruptible) instead of only logging it. 36 new tests; full agent suite 512 green.
**Why:** These close the "main process healthy while a worker is silently dead/wedged" gap (KeepAlive never fires because nothing crashes), stop retry-looping on a tampered/missing binary, prevent log floods that bury the real signal, and respect the manager's backpressure. Heartbeat/loss/overlap counters are surfaced in `agent_health` so degraded agents are observable, not just internally handled. Tranche 2 (adaptive backpressure, fair 80/20 replay scheduler + checkpoints, process-group collector kill + typed results, startup spool recovery, metric validation) is designed and staged.

## 2026-07-28

### Detection coverage: wired 11 dormant detection modules + added mount_monitor
**What:** Audit of `manager/manager/attacklens/` found that 11 rich detection modules (`lateral_movement`, `exfiltration`, `covert_channel`, `persistence`, `service_monitor`, `scheduled_task`, `privilege_escalation`, `binary_integrity`, `defense_evasion`, `app_vulnerability`, `package_vulnerability`) were imported in `detections/__init__.py` but had **0 references** and were **not in `engine._DETECTION_MODULE_ROUTES`** — so they never ran. Fix: imported them in `engine.py` and wired each to its verified section guard in the route map (e.g. `connections → [lateral_movement, exfiltration, covert_channel]`, `binaries → [privilege_escalation, binary_integrity]`, `processes → [covert_channel, exfiltration, privilege_escalation, defense_evasion]`, `services → [persistence, service_monitor]`, `tasks → [persistence, scheduled_task]`). Route modules run IN PLACE OF the inline `_dispatch` analyzer (they're the richer path — baselines, allowlists, MITRE, first-run FP seeding); `_rulepack` + behavioral still run for every section, so routing only upgrades coverage. Also added a net-new `detections/mount_monitor.py` (routed for the previously-undetected `mounts`/`storage` sections) that fires on a new mount appearing after a per-agent baseline — classifying removable media (T1091), network shares (T1021.002), and new local mounts (T1074), with DB-backed `entity_state` first-seen so it never re-fires known mounts. 10 new tests (coverage-map + FakeDB mount detection); 341 manager tests collect clean.
**Why:** "All telemetry should pass through detection" — every section already reached `engine.process` (worker has no section filter), but a big body of written detection logic was silently inert and two sections (`mounts`/`storage`) had no dedicated detector. The `fn.__name__` gotcha: all modules export `analyze`, imported as aliases, so `__name__` is always `"analyze"` — identify the source module via `__module__`. Postgres-backed engine integration tests (`test_engine_module_routing`) can't run without a live DB, so wiring is verified via a pure route-map/coverage assertion + FakeDB smoke of the new detector.
