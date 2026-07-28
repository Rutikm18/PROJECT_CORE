# Design — macOS Agent Resilience & Auto-Troubleshooting Hardening

**Date:** 2026-07-26
**Scope:** `agent/os/macos/` + shared `agent/agent/` (the runtime the macOS agent uses)
**Driver:** the 15-row priority matrix (Critical → Low). This doc maps each row to the *current*
code, the gap, the concrete solution, and how it is **verified**, then groups the work into
implementation tranches.

**Guiding invariant (system-design lens):** the agent is a root LaunchDaemon whose only jobs are
(1) *never lose security telemetry silently* and (2) *always recover itself*. Every mechanism below
serves one of those two. `launchd` is the single lifecycle owner; everything in-process is a
*supervised worker* that either recovers or escalates to a clean process exit so launchd restarts it.

---

## 0. Current-state summary (already shipped this program)

Several matrix rows are already fully or partially satisfied by prior work — the design builds on
them, it does not duplicate:

- **Single lifecycle owner** (row 7) — DONE: `pkg/build_pkg.sh` now starts only the agent daemon and
  disables the watchdog; `single_instance.py` `flock` guard prevents duplicate agents.
- **Boot / reboot auto-restart** — DONE: `boot_persistence.py` self-repairs the plist and
  detects reboots; launchd `RunAtLoad`+`KeepAlive` bring the agent up when the machine powers on.
- **Collector isolation** (row 10) — DONE: thread-pool execution + per-section circuit breakers +
  per-section wall-clock budget (`collectors/base.py`, `core.py`).
- **Credential chain / boot-safe secrets** (row 13) — DONE: `keystore.py` keychain→file chain,
  `0600` validation, boot-safe file default.
- **Disk-full / non-raising spool, config fail-fast, clock-skew** — DONE this program.

---

## 1. Row-by-row design

Legend — **T1** = implement now (this tranche), **T2/T3** = staged next.

### Critical

**R1 — Watchdog target missing → immutable install manifest + checksum.** *(T1)*
- Current: `watchdog._verify_binary()` checks `X_OK` + world-writable only; a corrupt/replaced
  binary passes. No integrity check.
- Design: `agent/agent/manifest.py` — an install manifest (`/Library/AttackLens/manifest.json`,
  root-owned `0644`) recording `{path, version, sha256, size}` per managed binary, written at
  install. `verify_component(name)` recomputes SHA-256 and compares. Watchdog + agent validate at
  startup; on mismatch/missing → **degraded/stopped state** (structured alert + stop retrying),
  never a 30 s retry loop. Manifest itself is validated (missing → warn-and-continue in a
  transition window; present-but-mismatch → degrade).
- Verify: unit tests — good checksum passes; tampered file fails; missing manifest → typed
  `manifest_absent`; wrong size short-circuits before hashing.

**R2 — Sender crashes on missing spool → `DurableSpool` encapsulation + degraded mode.** *(T1 formalize)*
- Current: `DiskSpool.__init__` does `makedirs`; `write()` is now non-raising (ENOSPC/EROFS →
  counted-dropped). Sender never touches raw paths except through `DiskSpool`.
- Design: formalize the contract — `DiskSpool` validates dir existence + permissions at init,
  exposes `healthy()`; on unrecoverable filesystem error it flips a `degraded` flag surfaced in
  `agent_health` (instead of a dead thread). No sender code path constructs file paths directly.
- Verify: tests — init on a read-only dir → `healthy()==False` + degraded flag; write during
  degraded never raises; existing `test_spool_disk_full.py` continues to pass.

**R3 — Telemetry silently dropped → bounded durable queue + explicit loss policy + metrics/alert.** *(T1)*
- Current: in-memory queue overflow spills the *oldest* to disk spool (no silent drop);
  `dropped_trim`/`dropped_corrupt` counters exist.
- Design: make the loss policy **explicit and typed**. `LossPolicy = drop_oldest_to_spool` (default,
  current behavior) with a hard fallback `reject_and_count` only when the spool itself is degraded.
  Every drop increments a typed counter (`{reason: queue_overflow_spooled | spool_degraded_dropped |
  encrypt_failed}`) and, above a threshold, raises a **health alert** flag included in the
  `agent_health` heartbeat (`telemetry_loss` block). Security telemetry is never trimmed without a
  counter + alert.
- Verify: tests — overflow spills and increments the right counter; a degraded spool increments
  `spool_degraded_dropped` and sets the alert; heartbeat carries the loss block.

### High

**R4 — Sender can't match collector throughput → adaptive backpressure.** *(T2)*
- Current: overflow spills to disk (no loss) but collectors keep full rate.
- Design: a shared `Backpressure` signal derived from queue depth + spool size. When queue >
  soft-threshold, the orchestrator **slows low-priority collectors** (inventory/posture) by
  stretching their effective interval; volatile security sections keep cadence. Batching/compression
  already exist (gzip); add connection reuse. Restores rate when pressure clears.
- Verify: tests — synthetic high queue depth stretches low-priority intervals but not volatile ones;
  clears on drain.

**R5 — Large replay backlog blocks live telemetry → fair replay scheduler (80/20) + checkpoints.** *(T2)*
- Current: on reconnect the sender drains the whole spool into the queue (can starve live data +
  replays everything after a restart).
- Design: a **fair scheduler** in the sender — reserve ~80% of send capacity for live queue items,
  ~20% for replay, enforced with a token bucket. Persist a **replay checkpoint** (byte offset /
  line cursor in `unsent.ndjson`) so a restart resumes mid-spool instead of replaying from zero.
  Live telemetry always makes progress during a large backlog.
- Verify: tests — with a big spool + live items, live throughput ≥ live-share; checkpoint advances
  and survives a simulated restart (no double-send).

**R6 — Main healthy while sender dead → supervision tree + heartbeats.** *(T1)*
- Current: orchestrator/sender threads are guarded but there is no cross-thread liveness check; a
  wedged (not crashed) sender is invisible. `agent_health` shows queue depth only.
- Design: `agent/agent/supervision.py` — a `HeartbeatRegistry` where each worker publishes
  `last_alive` + `last_success` timestamps. A `Supervisor` loop (in `core.main`) evaluates staleness:
  `alive but no success` → escalate; `stale alive` (thread wedged/dead) → **bounded restart**; after
  N failed restarts in a window → `sys.exit(non-zero)` so launchd performs a clean full restart
  (single lifecycle owner, row 7). Heartbeats + verdicts are surfaced in `agent_health`.
- Verify: tests (pure policy) — fresh heartbeats → healthy; stale `last_success` with fresh
  `last_alive` → `escalate`; stale `last_alive` → `restart`; repeated restart failures → `terminate`.

**R7 — Multiple lifecycle owners → one owner (launchd) + identity checks.** *(DONE)*
- Shipped: single-supervisor topology + `single_instance.py` `flock`. Supervision (R6) reinforces it
  by escalating to process exit rather than spawning competing supervisors.

### Medium

**R8 — Collector timeout → cancellation + process-group cleanup + typed results.** *(T2)*
- Current: `subprocess.run(timeout=…)` kills the direct child on timeout but not its process *tree*;
  collector failures surface as exceptions/`""`.
- Design: run subprocesses in their **own process group** (`start_new_session=True`) and on timeout
  `killpg` the whole tree. Collectors return a **typed result** `CollectorOutcome{status: success |
  timeout | permission_denied | unsupported | error, data}` instead of throwing into the
  orchestrator; the orchestrator maps status → circuit-breaker + health without losing the reason.
- Verify: tests — a child that spawns a grandchild is fully reaped on timeout; each status maps to
  the expected breaker action.

**R9 — Heavy collectors too frequent / overlapping runs → per-collector lock.** *(T1, partial)*
- Current: the tick loop sets `_last_run` before submit, but a collector *slower than its interval*
  can be re-submitted while still running → overlap.
- Design: an in-flight set/lock per section — the orchestrator skips submitting a section whose prior
  run hasn't completed, recording a `skipped_overlap` counter. (Per-collector scheduling already
  exists via per-section intervals; this closes the overlap hole.)
- Verify: test — a section whose run exceeds its interval is not double-submitted; counter increments.

**R10 — One slow collector delays the whole cycle → isolation + circuit breakers.** *(DONE)*
- Shipped: thread pool + per-collector timeout + per-section circuit breaker + budget.

**R11 — Spool corruption / concurrent access → single writer + atomic ops + recovery.** *(T2)*
- Current: single-writer now enforced by `single_instance.py`; `DiskSpool` uses a lock, atomic
  `os.replace` on trim, and skips corrupt lines on drain.
- Design: add **startup recovery validation** (scan-and-quarantine a truncated tail line into
  `unsent.ndjson.corrupt` with a counter) and keep the option of a SQLite-WAL spool behind an
  interface if file-based proves insufficient (deferred — the single-writer + atomic-rename model is
  sufficient now).
- Verify: test — a spool with a truncated final line recovers cleanly, quarantines the bad tail,
  counts it.

**R12 — Manager unavailable / rate-limiting → classify + honor Retry-After + network breaker.** *(T1, partial)*
- Current: classifies `401/429/503/4xx`, exponential backoff + jitter; **logs but does not honor**
  `Retry-After`; offline probe backoff acts as a soft breaker.
- Design: **honor `Retry-After`** (parse seconds or HTTP-date, sleep that long capped at a max)
  before the next attempt on `429/503`; formalize a **network circuit breaker** (open after N
  consecutive network failures → stop hammering, spool directly, half-open probe on cadence — largely
  the existing `_online` state, made explicit + counted). Never retry permanent `4xx`.
- Verify: tests — `Retry-After: 5` delays ≥5 s (capped); breaker opens after N failures and
  half-opens on probe.

**R13 — Credential backend unavailable → provider chain, fail closed.** *(DONE)*
- Shipped: keychain→file chain, `0600`+ownership validation, boot-safe default, backend logged.

### Low

**R14 — Invalid platform metric → typed null + rate-limited warnings.** *(T2)*
- Current: some bounds checks (e.g. `cpu_freq`); ad-hoc.
- Design: a small `validate_metric(value, lo, hi)` returning `value | None` with an
  `unsupported_metric` status; warnings routed through the rate-limiter (R15).
- Verify: test — out-of-range → `None` + status; warning emitted once per interval.

**R15 — Repeated identical errors flood logs → structured + deduped + rate-limited logging.** *(T1)*
- Current: plain logging; repeated identical errors spam the log.
- Design: `agent/agent/obs.py` — a `log_throttled(key, level, msg, **fields)` helper that emits the
  first occurrence immediately, then at most once per interval per `key`, appending a
  `suppressed=N` count and structured fields (`component, code, retry_count, queue_depth, spool_size,
  recovery_action`). Used by sender/orchestrator/supervisor hot paths.
- Verify: tests — N identical calls in a window emit once with `suppressed=N-1`; a new key emits
  immediately; interval reset re-emits.

---

## 2. Tranches

- **T1 (this change):** R1 manifest+checksum, R3 explicit loss policy+metrics+alert, R6 supervision
  tree+heartbeats, R9 per-collector overlap lock, R12 honor Retry-After + explicit network breaker
  counters, R15 structured deduped logging, R2 `DurableSpool.healthy()`/degraded formalization.
  All with unit tests. These deliver the Critical items + the "auto-troubleshooting" supervision core.
- **T2:** R4 adaptive backpressure, R5 fair replay scheduler + checkpoints, R8 process-group kill +
  typed collector results, R11 startup spool recovery, R14 metric validation.
- **T3 (optional):** SQLite-WAL spool backend behind the `DurableSpool` interface if file-based
  proves insufficient under load.

## 3. Cross-cutting verification

- Every new module is pure-logic where possible (heartbeat/supervisor decisions, checksum compare,
  loss-policy accounting, throttle accounting) so it is unit-testable without root, launchd, or a
  live manager.
- Wiring changes (sender/orchestrator publishing heartbeats, honoring Retry-After) are covered by
  targeted tests + the existing full suite must stay green (476+).
- Health visibility: supervision verdicts, telemetry-loss counters, and manifest state are all
  surfaced in the `agent_health` heartbeat so the manager/dashboard can see degraded agents — the
  auto-troubleshooting mechanism is observable, not just internal.

## 4. File-level change list

**New:** `agent/agent/obs.py` (R15), `agent/agent/manifest.py` (R1), `agent/agent/supervision.py` (R6).
**Modified (T1):** `agent/agent/sender.py` (DurableSpool.healthy/degraded, honor Retry-After, network
breaker counters, heartbeat publish), `agent/agent/core.py` (per-collector overlap lock, loss-policy
counters + alert in `_enqueue`/`_emit_health`, supervisor loop + heartbeat publish, wire obs).
**Tests:** `test_obs.py`, `test_manifest.py`, `test_supervision.py`, `test_collector_overlap.py`,
extend `test_spool_disk_full.py` / sender tests for Retry-After + degraded spool.
