# Design — Global Time-Range Control v2 (presets + absolute custom range)

**Date:** 2026-08-08
**Status:** Approved design → ready for implementation plan
**Supersedes:** `2026-07-25-global-time-range-design.md` (approved but never implemented — none of
`timewindow.py` / `TimeRangeContext` / `TimeRangePicker` / `useWindowedData` exist yet).
**Scope:** `shared/wire.py` + `manager/` (FastAPI API) + `manager/dashboard/` (React/Vite SPA).

---

## 1. Overview

Add one centralized **time-range control in the dashboard top bar** that governs the data window
across every time-series page. It offers **relative presets** (`30s, 1m, 5m, 15m, 1h, 6h, 1d, 7d,
15d, 30d`, default `1h`) and a **custom absolute range** (explicit start + end date-time). Changing
it refetches every mounted time-aware page for that window. Relative presets auto-refresh live on a
window-scaled poll; absolute ranges are a frozen historical view and do not poll. Pages with no time
dimension (Settings, Login, config) ignore the control and hide the picker.

## 2. Goals / Non-goals

**Goals**
- One global control, mounted once in `TopHeader`, honored by every time-series page.
- 10 relative presets + a first-class **absolute custom `[start, end]`** range with no hard cap.
- Refetch on change; live auto-poll for relative presets only.
- Window persists across navigation + reload (URL query is source of truth, localStorage fallback).
- One canonical window vocabulary shared by agent, manager, and UI.
- Long/absolute ranges stay cheap via indexes + adaptive downsampling, not by restricting range.

**Non-goals (v1 — YAGNI)**
- **Historical time-travel of current state.** The window filters *events*; current-state widgets
  (live inventory, current CIS score, agent online/link status) always show latest. No "as-of"
  reconstruction of state that today only stores its latest value.
- Per-page independent windows (the control is global by design).
- Server-side aggregate result caching (add later only if profiling shows a hotspot).

## 3. Confirmed decisions (from brainstorming)

| Question | Decision |
|---|---|
| Core semantics | **Windowed event filter.** Window filters findings/detections/telemetry/trends/timeline. Current-state views ignore it and show latest. |
| Custom range | **Absolute past `[start, end]`**, both explicit, `start < end`, `end ≤ now`. **No hard cap.** |
| Why a cap was mentioned | Performance only — handled by indexes + downsampling + limits, not by capping the range. |
| Presets / default | `30s, 1m, 5m, 15m, 1h, 6h, 1d, 7d, 15d, 30d`; default **1h**. |
| Live refresh | Relative presets auto-poll (window-scaled). **Absolute ranges never poll** (static historical view; manual refresh only). |
| Approach | Context + `useWindowedData` hook + per-endpoint `window`/`start`/`end`, with URL+localStorage persistence. |

## 4. Current-state findings (grounding)

- `shared/wire.py::WINDOW_SECONDS` already defines a canonical map; `manager/manager/api/agents.py`
  already implements `window → start/end` with `Query(default="1h")` + `start`/`end` overrides;
  `manager/manager/api/raw.py` has its own `_TIME_WINDOWS` + `_resolve_window(window, start, end, now)`.
  **Two resolvers exist and disagree on the vocabulary** — this design unifies them into one.
- Frontend source lives under
  `manager/dashboard/templates/Build Smart AttackLens Platform/src/app/`; base files present today:
  `layouts/AppShell.tsx`, `components/TopHeader.tsx`, `pages/_routes.ts`. Pages fetch via raw
  `fetch("/api/v1/...")` with per-page URL constants; **no central API client, no TimeRange state**.
- The built dashboard is regenerated with `make build-dashboard` (vite → `manager/dashboard/static`,
  then copy `index.html`). The running manager serves the built `static/` bundle, so FE changes need
  a rebuild to take effect.
- **Retention default is 1 day** (`retention_period_months=0` → 1 day). A 30d preset or a month-wide
  custom range therefore legitimately returns mostly-empty data — the UI must explain this, not look
  broken.

## 5. Backend design

### 5.1 Canonical window vocabulary (`shared/wire.py`)
Make `WINDOW_SECONDS` the single superset covering all 10 presets:
`30s=30, 1m=60, 5m=300, 15m=900, 1h=3600, 6h=21600, 1d=86400, 7d=604800, 15d=1296000, 30d=2592000`
(existing keys retained for back-compat). One vocabulary for agent, manager, and UI.

### 5.2 Shared resolver (`manager/manager/timewindow.py` — new)
```
resolve_window(window: str | None = "1h",
               start: int | None = None,
               end:   int | None = None,
               now:   int | None = None) -> tuple[int, int]   # (start_epoch, end_epoch)
```
- Absolute mode: if `start` and `end` are both given, they win. Validate `start < end`;
  `end > now + SKEW` → clamp `end = now` (never trust a future client clock); `start ≥ end` → HTTP 422.
- Relative mode: `end = now`; `start = now - WINDOW_SECONDS[window]`. Unknown `window` → HTTP 422 with
  the valid set in the message.
- `now` defaults to server `time.time()` — relative windows are always server-authoritative.
- Replaces the inline logic in `agents.py` and the `_TIME_WINDOWS`/`_resolve_window` in `raw.py`
  (both refactored to call this). Single source of truth for window math.

### 5.3 Endpoint application + semantics
Each **time-series** endpoint gains `window: str = Query("1h")` plus optional `start`/`end`, and
filters on the **event timestamp** — `first_detected_at` for findings (verified column name in
`manager/manager/indexer.py`), telemetry `created_at` — never a row-write timestamp:
`WHERE <event_ts> BETWEEN start AND end`.

Endpoints to update (the ones time-aware pages call): `soc/dashboard`, `soc/metrics`,
`detection/*` (packages, network, processes, identity, persistence, execution), `findings` list,
`threat/*`, incidents, timeline, and posture **trend** widgets. The exact set is finalized in
planning by grepping each time-aware page's fetch URLs.

**Semantics rule (documented in each endpoint docstring):** the window filters event/finding/trend
data only. **Point-in-time state — current CIS score, live asset inventory, agent link/online
status — always returns latest and ignores `window`/`start`/`end`.**

### 5.4 Indexing + performance (system design)
- Findings already have `idx_find_first_detected(first_detected_at)` and telemetry has
  `idx_tel_range(created_at)` (verified in `indexer.py`/`index.py`) — so **no new index is required**;
  long ranges become index scans as-is. Add a composite `(agent_id, first_detected_at)` only if a
  per-agent windowed finding query shows up in profiling.
- **Adaptive server-side downsampling** for chart/trend endpoints: choose a bucket interval so the
  returned point count is bounded (≤ ~500) regardless of span — 30s window → sub-second/second
  buckets; 30d → hourly buckets. Keeps a 30-day chart as cheap to render as a 1-hour one. Buckets are
  computed in SQL (`date_trunc` / integer-division on epoch) so the DB does the aggregation.
- **List endpoints:** `LIMIT` + time-desc ordering (+ keyset pagination where a page needs more than
  the cap). `raw.py` already limits.
- **Guardrails:** a per-request statement timeout and a **soft** UI warning on very large custom
  spans; never a hard rejection of a valid `[start, end]`.
- **Retention interaction:** when the requested start predates the oldest retained row, endpoints may
  return an `oldest_available` hint so the UI can show "data before `<t>` was pruned by retention."

## 6. Frontend design

### 6.1 `TimeRangeContext` (`app/context/TimeRangeContext.tsx` — new)
- State is a discriminated union:
  `type TimeRange = { kind:'relative', key: WindowKey } | { kind:'absolute', start:number, end:number }`.
- Provides `{ range, setRange(r), toParams() }` where `toParams()` yields `?window=<key>` for relative
  or `?start=<epoch>&end=<epoch>` for absolute.
- Source-of-truth precedence: **URL query → localStorage → default `{relative,'1h'}`**. On `setRange`,
  write both the URL query (shareable/bookmarkable, survives reload) and localStorage.
- Provided in `AppShell` so every routed page shares it. Exposes a typed `WINDOW_KEYS` list mirroring
  the backend vocabulary (single FE constant, no drift).

### 6.2 `<TimeRangePicker>` (`app/components/TimeRangePicker.tsx` — new)
- Segmented/dropdown control of the 10 presets **plus** a "Custom" entry that opens a popover with two
  date-time inputs (start, end). Inline validation: `start < end`, `end ≤ now`; soft warning when the
  span is very large. Confirm applies an absolute range.
- Mounted in `TopHeader`. Shows the active range (preset label or `start → end`) + an "updated Ns ago"
  freshness chip fed by the hook (chip hidden/frozen for absolute ranges).
- **Hidden on non-time routes** via a `timeAware` flag added to route metadata (`_routes.ts`).
  Non-time routes: Settings/*, Login, config pages (e.g. correlation rules), and any page without a
  time dimension.

### 6.3 `useWindowedData` hook (`app/hooks/useWindowedData.ts` — new)
```
useWindowedData(fetcher: (params: {qs: string, signal: AbortSignal}) => Promise<T>, opts?)
  → { data, loading, error, lastUpdated, refresh }
```
- Reads `range` from `TimeRangeContext`; passes the resolved query string to `fetcher`.
- **Refetches immediately when the range changes.**
- **Live auto-poll only for relative ranges**, window-scaled: `≤1m → 5s`, `≤1h → 30s`, `≤1d → 60s`,
  `>1d → 300s`. **Absolute ranges never poll** (static historical view); `refresh()` is manual only.
- Uses `AbortController` to cancel in-flight requests on range change / unmount (prevents stale
  overwrites and races; last selection wins).
- A tiny `withWindow(url, params)` helper merges the time params into an existing query string.

### 6.4 Page migration
Each time-aware page swaps its `fetch()`/`useEffect` block for `useWindowedData` (or minimally adds
the time params to the fetch URL + effect dependency). Mechanical, ~one edit per page; pages hitting
several endpoints call the hook once per endpoint. Partial rollout is safe: a not-yet-migrated page
simply ignores the global range until migrated (endpoints default to `1h` = today's behavior).

## 7. Data flow

```
TopHeader <TimeRangePicker> → setRange(relative|absolute)
  → TimeRangeContext updates URL (?window= | ?start=&end=) + localStorage
    → every mounted time-aware page's useWindowedData sees the new range
      → refetch GET /api/v1/<endpoint>?<time params>   (AbortController cancels prior)
        → resolve_window(window|start,end) → [start,end]
          → WHERE <event_ts> BETWEEN start AND end   (+ adaptive buckets for charts)
            → windowed JSON → page renders → freshness chip resets
  ⟳ relative only: window-scaled poll repeats the fetch to keep the window live
     absolute: no poll (frozen range); manual refresh() only
```

## 8. Edge cases

- Invalid/absent params (FE or BE) → default `1h`; BE returns 422 only for an explicitly bad value
  (unknown preset, `start ≥ end`).
- Absolute `end` in the future → clamped to server `now`.
- Very short window (30s/1m) with no recent events → normal empty state, **not** an error. Most
  sections collect hourly/daily, so short windows are legitimately sparse.
- Rapid range switching → AbortController cancels superseded requests; last selection wins.
- Range that predates retention (e.g. 30d with 1-day retention) → returns what exists + an
  `oldest_available`-driven note; not an error, not "broken".
- Point-in-time widgets (current CIS, asset inventory, online status) → unaffected by the window.
- Non-time pages → picker hidden; any stray time param ignored server-side.
- Clock skew → relative windows use server `now`; absolute future-end clamped. No client-clock trust.
- Very large custom span → soft warning + downsampling keep it responsive; never a hard block.

## 9. Testing (implemented after spec approval)

**Backend**
- `resolve_window`: each of the 10 presets → correct `[start,end]`; absolute `start/end` honored;
  `start ≥ end` → 422; unknown window → 422; future `end` → clamped; boundary inclusivity.
- Endpoint filter: seed findings/telemetry at known event timestamps; assert only in-window rows
  returned per range; `created_at` vs event-timestamp correctness.
- Downsampling: returned point count bounded (≤ cap) across 30s…30d and a wide custom span.
- Migration idempotent; new indexes present.

**Frontend**
- `TimeRangeContext`: precedence (URL > localStorage > default); `setRange` writes both; relative vs
  absolute serialization round-trips through the URL.
- `useWindowedData`: range change → exactly one refetch; relative polls at scaled cadence; **absolute
  does not poll**; AbortController cancels superseded request; `lastUpdated` advances on success.
- `<TimeRangePicker>`: hidden on `timeAware:false` routes; reflects active range; custom validation
  (`start < end`, `end ≤ now`); soft warning on large span.

## 10. Rollout / scope

Effort is mostly mechanical: unify the window map (1 file) + shared resolver (1 file) + refactor the
two existing resolvers to it; add `window`/`start`/`end` + event-time filtering + downsampling to
~10–15 endpoints; add the finding-time indexes (migration); FE context/picker/hook (3 files) + route
`timeAware` flags + `AppShell` provider; migrate ~15–20 pages. Ship backend first (endpoints accept
the params, default `1h` = current behavior), then the FE control, then page-by-page migration so a
partial rollout never breaks a page.

## 11. File-level change list (initial)

**Backend**
- `shared/wire.py` — extend `WINDOW_SECONDS` to the 10-preset superset.
- `manager/manager/timewindow.py` — new `resolve_window` (absolute + relative + validation).
- `manager/manager/api/agents.py` — refactor inline logic to `resolve_window`.
- `manager/manager/api/raw.py` — replace `_TIME_WINDOWS`/`_resolve_window` with the shared resolver.
- `manager/manager/api/findings.py` (soc/dashboard, soc/metrics, findings list) — add time params +
  event-time filter (+ downsampling for metric/trend series).
- `manager/manager/api/detection.py`, `threat.py`, `posture.py` (trend widgets), incidents/timeline
  endpoints — add time params + event-time filter.
- `manager/manager/db.py` (or migration) — `idx_findings_detected`, `idx_findings_agent_detected`;
  optional `oldest_available` helper.

**Frontend** (`manager/dashboard/templates/Build Smart AttackLens Platform/src/app/`)
- `context/TimeRangeContext.tsx` — new.
- `components/TimeRangePicker.tsx` — new; mounted in `components/TopHeader.tsx`.
- `hooks/useWindowedData.ts` — new (+ `withWindow` helper).
- `pages/_routes.ts` (+ router config) — add `timeAware` flag.
- `layouts/AppShell.tsx` — wrap in `TimeRangeProvider`.
- Time-aware pages — migrate fetches to `useWindowedData`.
- Rebuild: `make build-dashboard`.

## 12. Risks / open items

- **Endpoint enumeration** — the exact list of endpoints each time-aware page calls is finalized in
  planning (grep each page's fetch URLs); §5.3/§11 is the initial set.
- **`first_detected_at` completeness** — the column is `NOT NULL` in the `findings` DDL, so every
  finding has an event time; no fallback needed. (Corrected from the initial `detected_at` assumption.)
- **Downsampling fidelity** — long-range charts show bucketed aggregates, not raw points (standard for
  observability). Accepted; documented so exact-value expectations are set.
- **Long-range aggregate cost** on heavy endpoints — mitigated by indexes + downsampling + scaled
  poll; revisit with a short-TTL server cache only if profiling shows a hotspot.
