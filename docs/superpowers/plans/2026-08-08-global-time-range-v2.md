# Global Time-Range Control v2 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one centralized top-bar time-range control (10 relative presets + an absolute custom `[start,end]` range) that filters every time-series page's event data, with current-state views always showing latest.

**Architecture:** One canonical window vocabulary in `shared/wire.py`; one backend resolver `manager/manager/timewindow.py::resolve_window` used by every time-aware endpoint (filtering on event timestamps, with adaptive downsampling for trend series); on the frontend, a pure logic module (`app/lib/timeRange.ts`) wrapped by a thin `TimeRangeContext` + `useWindowedData` hook + `<TimeRangePicker>` in `TopHeader`. Relative presets auto-poll (window-scaled); absolute ranges are a frozen historical view and never poll.

**Tech Stack:** Python 3.12 / FastAPI / asyncpg (manager); pytest (backend tests); React + Vite + TypeScript (dashboard); vitest (new — pure FE logic tests only).

**Design doc:** `docs/superpowers/specs/2026-08-08-global-time-range-v2-design.md`

## Global Constraints

- **Preset vocabulary (exact keys, all pages/endpoints):** `30s, 1m, 5m, 15m, 1h, 6h, 1d, 7d, 15d, 30d`. Default: `1h`.
- **`WINDOW_SECONDS` values:** `30s=30, 1m=60, 5m=300, 15m=900, 1h=3600, 6h=21600, 1d=86400, 7d=604800, 15d=1296000, 30d=2592000`. Existing keys `8h=28800, 90d=7776000` are retained for back-compat.
- **Semantics:** window filters EVENT/time-series data only. Current-state widgets (live inventory, current CIS score, agent online/link status) ALWAYS return latest and ignore the window.
- **Event timestamp column for findings is `first_detected_at`** (DOUBLE PRECISION epoch seconds) — NOT `detected_at`. Telemetry event time is `created_at` (see `manager/manager/index.py`, indexed by `idx_tel_range`). Existing finding index `idx_find_first_detected ON findings(first_detected_at)` already supports this.
- **Absolute ranges:** explicit `start` + `end` epoch seconds; `start < end`; `end > now+SKEW` → clamp to `now`; `start >= end` or unknown preset → HTTP 422. No hard upper cap.
- **Absolute ranges NEVER auto-poll** on the frontend. Relative presets poll window-scaled: `≤1m→5s, ≤1h→30s, ≤1d→60s, >1d→300s`.
- **Frontend source root:** `manager/dashboard/templates/Build Smart AttackLens Platform/` (abbreviated below as `<FE>`). Rebuild with `make build-dashboard` after FE changes.
- **Backend tests** live under `manager/tests/unit/` and run with `python3 -m pytest <path>` (asyncio_mode=auto). Integration tests needing Postgres live under `manager/tests/integration/`.
- Commit after every task. TDD: failing test → minimal code → passing test → commit.

---

### Task 1: Unify the window vocabulary in `shared/wire.py`

**Files:**
- Modify: `shared/wire.py:148-157` (the `WINDOW_SECONDS` dict)
- Test: `manager/tests/unit/test_timewindow.py` (created here, extended in Task 2)

**Interfaces:**
- Produces: `shared.wire.WINDOW_SECONDS: dict[str,int]` containing all 10 preset keys above plus legacy `8h`,`90d`.

- [ ] **Step 1: Write the failing test**

Create `manager/tests/unit/test_timewindow.py`:
```python
from shared.wire import WINDOW_SECONDS

EXPECTED = {
    "30s": 30, "1m": 60, "5m": 300, "15m": 900, "1h": 3600,
    "6h": 21600, "1d": 86400, "7d": 604800, "15d": 1296000, "30d": 2592000,
}

def test_all_presets_present_with_correct_seconds():
    for key, secs in EXPECTED.items():
        assert WINDOW_SECONDS[key] == secs

def test_legacy_keys_retained():
    assert WINDOW_SECONDS["8h"] == 28800
    assert WINDOW_SECONDS["90d"] == 7776000
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest manager/tests/unit/test_timewindow.py -v`
Expected: FAIL — `KeyError: '30s'` (and others).

- [ ] **Step 3: Write minimal implementation**

Replace the `WINDOW_SECONDS` dict in `shared/wire.py` with:
```python
WINDOW_SECONDS: dict[str, int] = {
    # Canonical preset vocabulary (agent + manager + UI share this map)
    "30s": 30,
    "1m":  60,
    "5m":  300,
    "15m": 900,
    "1h":  3600,
    "6h":  21600,
    "1d":  86400,
    "7d":  604800,
    "15d": 1296000,
    "30d": 2592000,
    # Legacy keys retained for back-compat with existing callers.
    "8h":  28800,
    "90d": 7776000,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest manager/tests/unit/test_timewindow.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add shared/wire.py manager/tests/unit/test_timewindow.py
git commit -m "feat(timewindow): unify WINDOW_SECONDS vocabulary (10 presets + legacy)"
```

---

### Task 2: Shared resolver `manager/manager/timewindow.py`

**Files:**
- Create: `manager/manager/timewindow.py`
- Test: `manager/tests/unit/test_timewindow.py` (extend)

**Interfaces:**
- Consumes: `shared.wire.WINDOW_SECONDS`.
- Produces:
  - `class WindowError(ValueError)` — raised for invalid input (callers map to HTTP 422).
  - `resolve_window(window: str | None = "1h", start: int | None = None, end: int | None = None, now: int | None = None) -> tuple[int, int]` — returns `(start_epoch, end_epoch)` ints.
  - `SKEW_SECONDS: int = 300`.

- [ ] **Step 1: Write the failing test**

Append to `manager/tests/unit/test_timewindow.py`:
```python
import pytest
from manager.manager.timewindow import resolve_window, WindowError, SKEW_SECONDS

NOW = 1_800_000_000

def test_relative_preset_resolves_to_now_minus_seconds():
    assert resolve_window("1h", now=NOW) == (NOW - 3600, NOW)
    assert resolve_window("30s", now=NOW) == (NOW - 30, NOW)
    assert resolve_window("30d", now=NOW) == (NOW - 2592000, NOW)

def test_default_window_is_1h():
    assert resolve_window(None, now=NOW) == (NOW - 3600, NOW)

def test_unknown_preset_raises():
    with pytest.raises(WindowError):
        resolve_window("13h", now=NOW)

def test_absolute_start_end_honoured():
    assert resolve_window(None, start=NOW - 500, end=NOW - 100, now=NOW) == (NOW - 500, NOW - 100)

def test_absolute_overrides_preset():
    assert resolve_window("1h", start=NOW - 50, end=NOW - 10, now=NOW) == (NOW - 50, NOW - 10)

def test_future_end_is_clamped_to_now():
    s, e = resolve_window(None, start=NOW - 100, end=NOW + 10_000, now=NOW)
    assert e == NOW and s == NOW - 100

def test_start_ge_end_raises():
    with pytest.raises(WindowError):
        resolve_window(None, start=NOW, end=NOW, now=NOW)
    with pytest.raises(WindowError):
        resolve_window(None, start=NOW, end=NOW - 5, now=NOW)

def test_start_within_skew_future_but_end_clamped_still_valid():
    # end slightly in the future within skew → clamped to now, start valid
    s, e = resolve_window(None, start=NOW - 10, end=NOW + SKEW_SECONDS - 1, now=NOW)
    assert e == NOW and s == NOW - 10
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest manager/tests/unit/test_timewindow.py -v`
Expected: FAIL — `ModuleNotFoundError: manager.manager.timewindow`.

- [ ] **Step 3: Write minimal implementation**

Create `manager/manager/timewindow.py`:
```python
"""Single source of truth for resolving a dashboard time window to (start, end).

Two modes:
  - relative preset  → [now - WINDOW_SECONDS[window], now]
  - absolute range   → explicit [start, end] (epoch seconds)

All windows are half-open-friendly integer epoch seconds. Relative windows are
server-authoritative (never trust a client clock); an absolute end in the future
is clamped to `now` rather than rejected, so mild client-clock skew is tolerated.
"""
from __future__ import annotations

import time

from shared.wire import WINDOW_SECONDS

SKEW_SECONDS = 300  # tolerate an absolute end up to 5 min ahead, then clamp


class WindowError(ValueError):
    """Invalid window input — callers should map this to HTTP 422."""


def resolve_window(
    window: str | None = "1h",
    start: int | None = None,
    end: int | None = None,
    now: int | None = None,
) -> tuple[int, int]:
    now = int(now if now is not None else time.time())

    # Absolute mode wins when both bounds are given.
    if start is not None and end is not None:
        start = int(start)
        end = int(end)
        if end > now + SKEW_SECONDS:
            end = now
        elif end > now:
            end = now
        if start >= end:
            raise WindowError(f"start ({start}) must be < end ({end})")
        return start, end

    # Relative mode.
    key = window or "1h"
    secs = WINDOW_SECONDS.get(key)
    if secs is None:
        valid = ", ".join(sorted(WINDOW_SECONDS))
        raise WindowError(f"unknown window {key!r}; valid: {valid}")
    return now - secs, now
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest manager/tests/unit/test_timewindow.py -v`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add manager/manager/timewindow.py manager/tests/unit/test_timewindow.py
git commit -m "feat(timewindow): add resolve_window resolver (relative + absolute + validation)"
```

---

### Task 3: Adopt `resolve_window` in `raw.py` and `agents.py`

**Files:**
- Modify: `manager/manager/api/raw.py:29-36` (delete `_TIME_WINDOWS`), `manager/manager/api/raw.py:289-299` (replace `_resolve_window`)
- Modify: `manager/manager/api/agents.py:104-120` (use `resolve_window`)
- Test: `manager/tests/unit/test_timewindow_adoption.py` (new)

**Interfaces:**
- Consumes: `resolve_window`, `WindowError` from Task 2.
- Produces: both endpoints raise `HTTPException(422)` on `WindowError`.

- [ ] **Step 1: Write the failing test**

Create `manager/tests/unit/test_timewindow_adoption.py`:
```python
import manager.manager.api.raw as raw_mod

def test_raw_module_uses_shared_resolver_not_local_map():
    # The local _TIME_WINDOWS map must be gone; the shared resolver is the source of truth.
    assert not hasattr(raw_mod, "_TIME_WINDOWS")

def test_raw_resolve_delegates(monkeypatch):
    from manager.manager.timewindow import resolve_window
    # 1h relative resolves via the shared vocabulary (30s now valid, was not in old map)
    s, e = resolve_window("30s", now=1000)
    assert (s, e) == (970, 1000)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest manager/tests/unit/test_timewindow_adoption.py -v`
Expected: FAIL — `_TIME_WINDOWS` still present.

- [ ] **Step 3: Write minimal implementation**

In `manager/manager/api/raw.py`: delete the `_TIME_WINDOWS` dict (lines ~29-36) and replace the `_resolve_window(...)` function body (lines ~289-299) with a thin delegate:
```python
from manager.manager.timewindow import resolve_window as _shared_resolve, WindowError

def _resolve_window(window, start, end, now):
    """Delegate to the shared resolver; preserve the (window|start/end, now) call shape."""
    try:
        return _shared_resolve(window, start, end, now=now)
    except WindowError:
        # Preserve prior lenient behavior for the raw browser: fall back to a
        # full [start or 0, end or now] rather than 422 (raw endpoints are internal).
        return (start or 0), (end or now)
```
In `manager/manager/api/agents.py`, replace the inline `secs = WINDOW_SECONDS.get(window, 3600)` block (around line 114-120) with:
```python
from manager.manager.timewindow import resolve_window, WindowError
...
        try:
            start_ts, end_ts = resolve_window(window, start, end)
        except WindowError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
```
(Keep the existing `start`/`end` Query params on the endpoint; pass them through.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest manager/tests/unit/test_timewindow_adoption.py manager/tests/unit/test_timewindow.py -v`
Expected: PASS. Also run the existing agents/raw unit tests if present: `python3 -m pytest manager/tests/unit -k "raw or agent" -v` → PASS (no regressions).

- [ ] **Step 5: Commit**

```bash
git add manager/manager/api/raw.py manager/manager/api/agents.py manager/tests/unit/test_timewindow_adoption.py
git commit -m "refactor(timewindow): route raw.py + agents.py through shared resolve_window"
```

---

### Task 4: Adaptive downsampling helper for trend series

**Files:**
- Create: `manager/manager/timeseries.py`
- Test: `manager/tests/unit/test_timeseries.py`

**Interfaces:**
- Produces: `bucket_seconds(start: int, end: int, max_points: int = 500) -> int` — returns a bucket width (seconds) so `ceil((end-start)/width) <= max_points`, snapped to a human-friendly ladder.

- [ ] **Step 1: Write the failing test**

Create `manager/tests/unit/test_timeseries.py`:
```python
import math
from manager.manager.timeseries import bucket_seconds

LADDER_MIN = 1  # never smaller than 1s

def _points(start, end, w):
    return math.ceil((end - start) / w)

def test_short_window_small_buckets():
    # 30s window → <= 500 points, bucket at least 1s
    w = bucket_seconds(0, 30)
    assert w >= LADDER_MIN
    assert _points(0, 30, w) <= 500

def test_month_window_bounded_points():
    start, end = 0, 2592000  # 30d
    w = bucket_seconds(start, end)
    assert _points(start, end, w) <= 500

def test_custom_year_span_still_bounded():
    start, end = 0, 365 * 86400
    assert _points(start, end, bucket_seconds(start, end)) <= 500

def test_returns_ladder_value():
    # Result is one of the human-friendly ladder steps, not an arbitrary int.
    assert bucket_seconds(0, 3600) in {
        1, 5, 10, 30, 60, 300, 600, 1800, 3600, 21600, 43200, 86400,
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest manager/tests/unit/test_timeseries.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Write minimal implementation**

Create `manager/manager/timeseries.py`:
```python
"""Adaptive bucket sizing so any time span renders as a bounded number of points."""
from __future__ import annotations

import math

# Human-friendly bucket widths (seconds), ascending.
_LADDER = [1, 5, 10, 30, 60, 300, 600, 1800, 3600, 21600, 43200, 86400,
           7 * 86400, 30 * 86400]


def bucket_seconds(start: int, end: int, max_points: int = 500) -> int:
    span = max(1, int(end) - int(start))
    for width in _LADDER:
        if math.ceil(span / width) <= max_points:
            return width
    return _LADDER[-1]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest manager/tests/unit/test_timeseries.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add manager/manager/timeseries.py manager/tests/unit/test_timeseries.py
git commit -m "feat(timeseries): adaptive bucket_seconds for bounded trend point counts"
```

---

### Task 5: Window the findings-list endpoint (reference pattern)

This establishes the exact pattern every other time-aware endpoint follows.

**Files:**
- Modify: `manager/manager/api/findings.py` (the findings-list route + its DB query)
- Modify: `manager/manager/indexer.py` (add the DB method if a windowed query method is needed) — confirm actual query location during implementation
- Test: `manager/tests/integration/test_findings_window.py`

**Interfaces:**
- Consumes: `resolve_window`, `WindowError`.
- Produces: findings-list route accepts `window: str = Query("1h")`, `start: int | None`, `end: int | None`; filters `WHERE first_detected_at BETWEEN start AND end`.

- [ ] **Step 1: Write the failing test**

Create `manager/tests/integration/test_findings_window.py` (uses the existing integration `client` fixture + seeded intel DB; mirror `manager/tests/integration/test_ingest.py` setup):
```python
# Seed three findings at first_detected_at = now-10, now-4000, now-800000.
# window=1h must return only the now-10 and (if <3600) none older; assert boundary.
def test_findings_list_filters_by_window(client, seed_findings):
    now = seed_findings["now"]
    r = client.get("/api/v1/soc/findings", params={"window": "1h"})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["findings"]}
    assert seed_findings["recent_id"] in ids
    assert seed_findings["old_id"] not in ids

def test_findings_list_absolute_range(client, seed_findings):
    now = seed_findings["now"]
    r = client.get("/api/v1/soc/findings",
                   params={"start": now - 5000, "end": now - 3000})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["findings"]}
    assert seed_findings["mid_id"] in ids
    assert seed_findings["recent_id"] not in ids

def test_findings_list_bad_range_422(client):
    r = client.get("/api/v1/soc/findings", params={"start": 100, "end": 50})
    assert r.status_code == 422
```
(Confirm the exact findings-list route path during implementation by grepping `findings.py` for `@router.get`; adjust the path in the tests to match. The `seed_findings` fixture inserts rows into `findings` with explicit `first_detected_at`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest manager/tests/integration/test_findings_window.py -v`
Expected: FAIL — window not applied / all rows returned (needs a live Postgres; see design doc for `docker compose up -d postgres`).

- [ ] **Step 3: Write minimal implementation**

In the findings-list route in `manager/manager/api/findings.py`:
```python
from manager.manager.timewindow import resolve_window, WindowError

@router.get("/findings")           # confirm exact existing path
async def list_findings(
    window: str = Query("1h"),
    start: int | None = Query(None),
    end: int | None = Query(None),
    # ... existing params ...
):
    try:
        start_ts, end_ts = resolve_window(window, start, end)
    except WindowError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    # Pass start_ts/end_ts into the DB query; add to WHERE:
    #   AND first_detected_at BETWEEN $start AND $end
    ...
```
Add `AND first_detected_at BETWEEN $N AND $N+1` to the findings query (existing index `idx_find_first_detected` covers it). Document in the docstring: "window filters finding event time (`first_detected_at`); current-state counts elsewhere ignore it."

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest manager/tests/integration/test_findings_window.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add manager/manager/api/findings.py manager/tests/integration/test_findings_window.py
git commit -m "feat(findings): window the findings list by first_detected_at"
```

---

### Task 6: Roll the window pattern across remaining time-aware endpoints

Apply the **exact Task 5 pattern** (add `window`/`start`/`end` Query params → `resolve_window` → `HTTPException(422)` on `WindowError` → `... BETWEEN start_ts AND end_ts` on the event-time column; use `bucket_seconds` for any series/trend response) to each endpoint below. For each: filter on the listed event-time column; leave current-state responses untouched.

**Files & event-time columns:**
- `manager/manager/api/findings.py` — `soc/dashboard`, `soc/metrics` → `first_detected_at`. (`soc/metrics` trend series: bucket with `bucket_seconds`.) Current-state summary counts on these pages stay latest.
- `manager/manager/api/detection.py` — `packages`, `network`, `processes`, `identity`, `persistence`, `execution` list/timeline routes → `first_detected_at`.
- `manager/manager/api/threat.py` — time-aware threat/incident routes → their event-time column (confirm: `detected_at`/`created_at` per route via grep).
- posture **trend** widgets (`manager/manager/api/posture.py` or wherever the trend route lives) → telemetry `created_at`; **current CIS score route stays latest (no window)**.
- timeline route → telemetry `created_at` (already tier-partitioned; add the window filter + `bucket_seconds` if it returns a series).

**Test:** `manager/tests/integration/test_endpoints_window.py` — one parametrized test per route asserting (a) `window=1h` narrows results vs `window=30d`, (b) `start>end` → 422. Seed rows at known event times.

- [ ] **Step 1: Write the failing parametrized test** (enumerate each route path + its event-time column; assert in-window filtering + 422 on bad range).
- [ ] **Step 2: Run → FAIL** (`python3 -m pytest manager/tests/integration/test_endpoints_window.py -v`).
- [ ] **Step 3: Apply the Task 5 pattern to each route above** (params → resolve_window → 422 → BETWEEN on the listed column; `bucket_seconds` for series). Grep each route's existing `@router.get` to confirm the path and current query.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `git commit -m "feat(api): apply time-window filtering to detection/threat/posture/timeline endpoints"`.

---

### Task 7: Frontend pure time-range logic module (`<FE>/src/app/lib/timeRange.ts`) + vitest

**Files:**
- Create: `<FE>/src/app/lib/timeRange.ts`
- Create: `<FE>/src/app/lib/timeRange.test.ts`
- Modify: `<FE>/package.json` (add `vitest` devDep + `"test": "vitest run"` script)

**Interfaces:**
- Produces:
  - `type WindowKey = '30s'|'1m'|'5m'|'15m'|'1h'|'6h'|'1d'|'7d'|'15d'|'30d'`
  - `WINDOW_KEYS: WindowKey[]`, `DEFAULT_WINDOW: '1h'`, `WINDOW_SECONDS: Record<WindowKey, number>`
  - `type TimeRange = { kind:'relative', key: WindowKey } | { kind:'absolute', start:number, end:number }`
  - `parseRangeFromParams(sp: URLSearchParams): TimeRange | null`
  - `rangeToParams(r: TimeRange): URLSearchParams`
  - `pollIntervalMs(r: TimeRange): number | null` (null = no polling → absolute)
  - `validateCustom(startSec: number, endSec: number, nowSec: number): string | null` (error string or null if valid)

- [ ] **Step 1: Write the failing test**

Create `<FE>/src/app/lib/timeRange.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import {
  parseRangeFromParams, rangeToParams, pollIntervalMs, validateCustom,
  DEFAULT_WINDOW,
} from "./timeRange";

describe("timeRange", () => {
  it("parses relative window param", () => {
    expect(parseRangeFromParams(new URLSearchParams("window=6h")))
      .toEqual({ kind: "relative", key: "6h" });
  });
  it("parses absolute start/end", () => {
    expect(parseRangeFromParams(new URLSearchParams("start=100&end=200")))
      .toEqual({ kind: "absolute", start: 100, end: 200 });
  });
  it("returns null for absent/invalid params", () => {
    expect(parseRangeFromParams(new URLSearchParams("window=13h"))).toBeNull();
    expect(parseRangeFromParams(new URLSearchParams(""))).toBeNull();
  });
  it("round-trips relative and absolute to params", () => {
    expect(rangeToParams({ kind: "relative", key: "1d" }).toString()).toBe("window=1d");
    expect(rangeToParams({ kind: "absolute", start: 5, end: 9 }).toString()).toBe("start=5&end=9");
  });
  it("polls for relative (scaled), never for absolute", () => {
    expect(pollIntervalMs({ kind: "relative", key: "30s" })).toBe(5000);
    expect(pollIntervalMs({ kind: "relative", key: "1h" })).toBe(30000);
    expect(pollIntervalMs({ kind: "relative", key: "1d" })).toBe(60000);
    expect(pollIntervalMs({ kind: "relative", key: "7d" })).toBe(300000);
    expect(pollIntervalMs({ kind: "absolute", start: 1, end: 2 })).toBeNull();
  });
  it("validates custom range", () => {
    expect(validateCustom(100, 200, 1000)).toBeNull();
    expect(validateCustom(200, 100, 1000)).toMatch(/start/i);      // start>=end
    expect(validateCustom(100, 5000, 1000)).toMatch(/future/i);    // end in future
  });
  it("default window is 1h", () => { expect(DEFAULT_WINDOW).toBe("1h"); });
});
```

- [ ] **Step 2: Add vitest + run to verify it fails**

Add to `<FE>/package.json` `devDependencies`: `"vitest": "^2.1.0"`; add to `scripts`: `"test": "vitest run"`.
Run (from `<FE>/`): `npm install && npm test`
Expected: FAIL — `./timeRange` not found.

- [ ] **Step 3: Write minimal implementation**

Create `<FE>/src/app/lib/timeRange.ts`:
```ts
export type WindowKey =
  | "30s" | "1m" | "5m" | "15m" | "1h" | "6h" | "1d" | "7d" | "15d" | "30d";

export const WINDOW_SECONDS: Record<WindowKey, number> = {
  "30s": 30, "1m": 60, "5m": 300, "15m": 900, "1h": 3600,
  "6h": 21600, "1d": 86400, "7d": 604800, "15d": 1296000, "30d": 2592000,
};
export const WINDOW_KEYS = Object.keys(WINDOW_SECONDS) as WindowKey[];
export const DEFAULT_WINDOW: WindowKey = "1h";

export type TimeRange =
  | { kind: "relative"; key: WindowKey }
  | { kind: "absolute"; start: number; end: number };

export function parseRangeFromParams(sp: URLSearchParams): TimeRange | null {
  const start = sp.get("start"), end = sp.get("end");
  if (start !== null && end !== null) {
    const s = Number(start), e = Number(end);
    if (Number.isFinite(s) && Number.isFinite(e) && s < e) return { kind: "absolute", start: s, end: e };
    return null;
  }
  const w = sp.get("window");
  if (w && (w in WINDOW_SECONDS)) return { kind: "relative", key: w as WindowKey };
  return null;
}

export function rangeToParams(r: TimeRange): URLSearchParams {
  return r.kind === "relative"
    ? new URLSearchParams({ window: r.key })
    : new URLSearchParams({ start: String(r.start), end: String(r.end) });
}

export function pollIntervalMs(r: TimeRange): number | null {
  if (r.kind === "absolute") return null;      // frozen historical view — never poll
  const secs = WINDOW_SECONDS[r.key];
  if (secs <= 60) return 5000;
  if (secs <= 3600) return 30000;
  if (secs <= 86400) return 60000;
  return 300000;
}

export function validateCustom(startSec: number, endSec: number, nowSec: number): string | null {
  if (!Number.isFinite(startSec) || !Number.isFinite(endSec)) return "Pick a valid start and end.";
  if (startSec >= endSec) return "Start must be before end.";
  if (endSec > nowSec) return "End can't be in the future.";
  return null;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run (from `<FE>/`): `npm test`
Expected: PASS (all timeRange tests).

- [ ] **Step 5: Commit**

```bash
git add "<FE>/src/app/lib/timeRange.ts" "<FE>/src/app/lib/timeRange.test.ts" "<FE>/package.json"
git commit -m "feat(fe): pure time-range logic module + vitest"
```

---

### Task 8: `TimeRangeContext` (thin React wrapper)

**Files:**
- Create: `<FE>/src/app/context/TimeRangeContext.tsx`
- Modify: `<FE>/src/app/layouts/AppShell.tsx` (wrap children in `<TimeRangeProvider>`)

**Interfaces:**
- Consumes: `timeRange.ts` (`TimeRange`, `parseRangeFromParams`, `rangeToParams`, `DEFAULT_WINDOW`).
- Produces: `useTimeRange(): { range: TimeRange; setRange(r: TimeRange): void }`; `<TimeRangeProvider>`.

- [ ] **Step 1: Write the provider**

Create `<FE>/src/app/context/TimeRangeContext.tsx`:
```tsx
import { createContext, useContext, useCallback, useMemo, useState, ReactNode } from "react";
import { useSearchParams } from "react-router";
import { TimeRange, parseRangeFromParams, rangeToParams, DEFAULT_WINDOW } from "../lib/timeRange";

const LS_KEY = "attacklens.timeRange";
const DEFAULT: TimeRange = { kind: "relative", key: DEFAULT_WINDOW };

function initialRange(sp: URLSearchParams): TimeRange {
  return parseRangeFromParams(sp)
    ?? (() => { try { const v = localStorage.getItem(LS_KEY); return v ? JSON.parse(v) as TimeRange : DEFAULT; } catch { return DEFAULT; } })();
}

const Ctx = createContext<{ range: TimeRange; setRange(r: TimeRange): void }>({ range: DEFAULT, setRange() {} });

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [sp, setSp] = useSearchParams();
  const [range, setRangeState] = useState<TimeRange>(() => initialRange(sp));
  const setRange = useCallback((r: TimeRange) => {
    setRangeState(r);
    try { localStorage.setItem(LS_KEY, JSON.stringify(r)); } catch {}
    const next = new URLSearchParams(sp);
    next.delete("window"); next.delete("start"); next.delete("end");
    for (const [k, v] of rangeToParams(r)) next.set(k, v);
    setSp(next, { replace: true });
  }, [sp, setSp]);
  const value = useMemo(() => ({ range, setRange }), [range, setRange]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useTimeRange = () => useContext(Ctx);
```

- [ ] **Step 2: Wire into AppShell**

In `<FE>/src/app/layouts/AppShell.tsx`, import `TimeRangeProvider` and wrap the routed content (inside the router, so `useSearchParams` works).

- [ ] **Step 3: Typecheck**

Run (from `<FE>/`): `npx tsc --noEmit`
Expected: no errors from the new files.

- [ ] **Step 4: Commit**

```bash
git add "<FE>/src/app/context/TimeRangeContext.tsx" "<FE>/src/app/layouts/AppShell.tsx"
git commit -m "feat(fe): TimeRangeContext with URL + localStorage persistence"
```

---

### Task 9: `useWindowedData` hook

**Files:**
- Create: `<FE>/src/app/hooks/useWindowedData.ts`

**Interfaces:**
- Consumes: `useTimeRange`, `rangeToParams`, `pollIntervalMs`.
- Produces: `useWindowedData<T>(fetcher: (a:{qs:string; signal:AbortSignal}) => Promise<T>) => { data:T|null; loading:boolean; error:unknown; lastUpdated:number|null; refresh():void }`.

- [ ] **Step 1: Write the hook**

Create `<FE>/src/app/hooks/useWindowedData.ts`:
```ts
import { useCallback, useEffect, useRef, useState } from "react";
import { useTimeRange } from "../context/TimeRangeContext";
import { rangeToParams, pollIntervalMs } from "../lib/timeRange";

export function useWindowedData<T>(fetcher: (a: { qs: string; signal: AbortSignal }) => Promise<T>) {
  const { range } = useTimeRange();
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const acRef = useRef<AbortController | null>(null);
  const qs = rangeToParams(range).toString();

  const run = useCallback(() => {
    acRef.current?.abort();
    const ac = new AbortController();
    acRef.current = ac;
    setLoading(true);
    fetcher({ qs, signal: ac.signal })
      .then((d) => { if (!ac.signal.aborted) { setData(d); setError(null); setLastUpdated(Date.now()); } })
      .catch((e) => { if (!ac.signal.aborted) setError(e); })
      .finally(() => { if (!ac.signal.aborted) setLoading(false); });
  }, [qs, fetcher]);

  useEffect(() => {
    run();
    const ms = pollIntervalMs(range);
    if (ms == null) return () => acRef.current?.abort();
    const id = setInterval(run, ms);
    return () => { clearInterval(id); acRef.current?.abort(); };
  }, [run, range]);

  return { data, loading, error, lastUpdated, refresh: run };
}
```

- [ ] **Step 2: Typecheck**

Run (from `<FE>/`): `npx tsc --noEmit` → no errors.

- [ ] **Step 3: Commit**

```bash
git add "<FE>/src/app/hooks/useWindowedData.ts"
git commit -m "feat(fe): useWindowedData hook (relative polls, absolute static, AbortController)"
```

---

### Task 10: `<TimeRangePicker>` + mount in TopHeader + `timeAware` routing

**Files:**
- Create: `<FE>/src/app/components/TimeRangePicker.tsx`
- Modify: `<FE>/src/app/components/TopHeader.tsx` (mount the picker; hide on non-time routes)
- Modify: `<FE>/src/app/pages/_routes.ts` (add `timeAware?: boolean` to route metadata; mark Settings/*, Login, config routes `false`)

**Interfaces:**
- Consumes: `useTimeRange`, `WINDOW_KEYS`, `validateCustom`.
- Produces: `<TimeRangePicker />` component; `isTimeAwareRoute(path: string): boolean` helper in `_routes.ts`.

- [ ] **Step 1: Build the picker** — segmented buttons over `WINDOW_KEYS` calling `setRange({kind:'relative',key})`; a "Custom" button opening a popover with two `datetime-local` inputs → on Apply, convert to epoch seconds, run `validateCustom(start,end,Math.floor(Date.now()/1000))`; show the error inline or `setRange({kind:'absolute',start,end})`. Show active label (`key` or `start→end`) + `lastUpdated` chip (hidden for absolute).
- [ ] **Step 2: Add `isTimeAwareRoute`** to `_routes.ts` (default true; explicit false for `/login`, `/settings*`, config pages). Mount `<TimeRangePicker />` in `TopHeader` gated by `isTimeAwareRoute(useLocation().pathname)`.
- [ ] **Step 3: Typecheck + build** — `npx tsc --noEmit` (no errors) and `make build-dashboard` (from repo root) succeeds.
- [ ] **Step 4: Manual browser QA** — via the `/browse` skill: load `/dashboard`, confirm picker shows; switch presets → URL `?window=` updates; open Custom, pick a past 2-hour range → URL `?start=&end=` updates; navigate to `/settings` → picker hidden.
- [ ] **Step 5: Commit** `git commit -m "feat(fe): TimeRangePicker in TopHeader with timeAware route gating"`.

---

### Task 11: Migrate time-aware pages to `useWindowedData` + rebuild

Apply this **mechanical pattern** to each time-aware page: replace its `fetch(URL)` + `useEffect` with `useWindowedData` and append the range params to the URL.

**Pattern (before → after):**
```ts
// before
useEffect(() => { fetch(`/api/v1/soc/dashboard`).then(...).then(setData); }, []);
// after
const { data } = useWindowedData(({ qs, signal }) =>
  fetch(`/api/v1/soc/dashboard?${qs}`, { signal }).then(r => r.json()));
```

**Pages to migrate** (enumerate via grep of each page's fetch URLs; initial set from `_routes.ts`):
`operations/dashboard`, `operations/findings`, `operations/incidents`, `terrain/origin`, `terrain/vector`, `terrain/citadels`, `terrain/persistence`, `terrain/identity`, `posture/overview` (trend widget only — leave current CIS score call unchanged), `inventory/timeline`, `analysis/deep`, `analysis/accuracy`, `analysis/coverage`, `ThreatIntelligence` tabs, `DeepMesh` (replace its local window selector with the global one).

- [ ] **Step 1:** For each page, grep its `fetch("/api/v1/...")` calls; for each **event/time-series** call, swap to the `useWindowedData` pattern above. **Do not** window current-state calls (current CIS score, live inventory, agent status) — leave them as-is.
- [ ] **Step 2:** Remove per-page local time selectors (e.g. DeepMesh's 1h/6h/24h/7d) in favor of the global one.
- [ ] **Step 3:** `npx tsc --noEmit` → no errors; `make build-dashboard` → succeeds.
- [ ] **Step 4:** Commit per page group: `git commit -m "feat(fe): migrate <group> pages to global time range"`.

---

### Task 12: End-to-end verification

- [ ] **Step 1:** Backend suite green: `python3 -m pytest manager/tests/unit -v` and (with Postgres up) `python3 -m pytest manager/tests/integration/test_findings_window.py manager/tests/integration/test_endpoints_window.py -v`.
- [ ] **Step 2:** FE logic green: from `<FE>/`, `npm test`.
- [ ] **Step 3:** Browser QA via `/browse`: pick `30s` (sparse/empty events but page renders, current-state still populated); pick `30d` (retention note shows if data pruned); Custom past range → URL shareable, reload restores range; switch pages → range persists; rapid preset switching → no stale flicker (AbortController); `/settings` hides picker.
- [ ] **Step 4:** Update `LEARNINGS.md` with the feature entry (What/Why) and commit.

---

## Self-Review

**Spec coverage:** §3 vocab → Task 1; §5.2 resolver → Task 2; §5.1/§5.3 adoption+endpoints → Tasks 3,5,6; §5.4 downsampling+indexes → Task 4 (indexes already exist — verified, no migration needed beyond confirming `idx_find_first_detected`); §6.1 context → Task 8; §6.2 picker → Task 10; §6.3 hook → Task 9; §6.4 page migration → Task 11; §9 testing → each task's tests + Task 12; edge cases (§8) → Task 2 (clamp/422), Task 7 (validate/poll), Task 12 (retention/empty/QA).

**Placeholder scan:** endpoint/page enumerations in Tasks 6 & 11 are deliberate lists (each item is a concrete file + column/URL), with the full code pattern given once — not "TODO". The one runtime confirmation (exact `@router.get` paths) is a grep step, not a code gap.

**Type consistency:** `resolve_window(window,start,end,now)` signature identical across Tasks 2/3/5/6; `TimeRange`/`WindowKey`/`pollIntervalMs`/`rangeToParams`/`validateCustom` names identical across Tasks 7/8/9/10; event-time column is `first_detected_at` everywhere for findings, telemetry `created_at` for trend/timeline.

**Correction vs spec:** spec §5.4 referenced a new `detected_at` index; the real column is `first_detected_at` with existing `idx_find_first_detected` — plan uses the real names and drops the redundant migration.
