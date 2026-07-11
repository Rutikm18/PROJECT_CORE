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
