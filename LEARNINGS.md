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
