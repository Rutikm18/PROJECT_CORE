# Design — Global Time-Range Control for the Dashboard

**Date:** 2026-07-25
**Status:** Approved design → ready for implementation plan
**Scope:** `manager/` (FastAPI API) + `manager/dashboard/` (React/Vite SPA) + `shared/wire.py`

---

## 1. Overview

Add a single, centralized **time-range selector in the dashboard top bar** that controls the
data window shown across all time-series pages. Selecting a range (5m / 15m / 1h / 7h / 1d / 15d
/ 30d / 90d / 180d) refetches every time-aware page for that window, and the data **auto-refreshes
live** on a window-scaled poll so the current window stays fresh. Pages with no time dimension
(Settings, Login, config screens) ignore the control and the picker is hidden there.

## 2. Goals / Non-goals

**Goals**
- One global control, mounted once in `TopHeader`, that every time-series page honors.
- 9 preset windows; default `1h` on first load.
- Refetch on change **and** live auto-poll (window-scaled cadence).
- Window persists across navigation and reload (URL query + localStorage).
- Reuse the existing canonical `WINDOW_SECONDS` vocabulary end-to-end.

**Non-goals (v1 — YAGNI)**
- Custom arbitrary start/end date-range picker (presets only for v1; backend resolver still
  accepts explicit `start`/`end` for future use).
- Per-page independent windows (the control is global by design).
- Server-side aggregate caching (add later only if long-window polling proves heavy).
- Changing point-in-time semantics of current-state widgets (see §5.3).

## 3. Decisions (from brainstorming)

| Question | Decision |
|---|---|
| Refresh behavior | On-change **and** live auto-poll, cadence scaled by window |
| Page scope | All time-series pages honor it; non-time pages ignore it and hide the picker |
| Ranges / default | 9 presets: 5m, 15m, 1h, 7h, 1d, 15d, 30d, 90d, 180d; default **1h** |
| Approach | Context + windowed-fetch hook + per-endpoint `window` param (recommended A), with URL+localStorage persistence |

## 4. Current-state findings (grounding)

- `shared/wire.py::WINDOW_SECONDS` already defines a canonical map (`5m,15m,1h,8h,1d,7d,30d,90d`),
  and `manager/manager/api/agents.py` already implements a `window → start/end` pattern with
  `Query(default="1h")` + `start`/`end` overrides. **We extend and centralize this.**
- SOC endpoints (`/api/v1/soc/dashboard`, `/api/v1/soc/metrics`) are served by
  `manager/manager/api/findings.py` (mounted at `/api/v1/soc` in `server.py:455`). They currently
  return all-time / current data — **no window param yet**.
- Findings live in `intel.db` with `detected_at` / `created_at` / `updated_at` columns. Telemetry
  index (`manager/manager/index.py`) has `created_at REAL` + `idx_tel_range`. **No `findings(detected_at)`
  index confirmed → add one.**
- Frontend pages fetch via **raw `fetch("/api/v1/...")`** with per-page URL constants; there is
  **no central API client**. Layout is `app/layouts/AppShell.tsx`; top bar is
  `app/components/TopHeader.tsx`; route map is `app/pages/_routes.ts`.

## 5. Backend design

### 5.1 Canonical window vocabulary (`shared/wire.py`)
Extend `WINDOW_SECONDS` to a superset that includes the 9 presets:
`7h=25200`, `15d=1296000`, `180d=15552000` (keep existing `8h`, `7d`). One vocabulary shared by
agent, manager, and UI.

### 5.2 Shared resolver (`manager/manager/timewindow.py` — new)
```
resolve_window(window: str = "1h",
               start: int | None = None,
               end: int | None = None) -> tuple[int, int]
```
- `end` defaults to `now`; `start` defaults to `end - WINDOW_SECONDS[window]`.
- Explicit `start`/`end` (epoch seconds) override the preset.
- Unknown `window` → HTTP 422 (with the valid set in the message).
- Generalizes the logic currently inline in `agents.py`; `agents.py` is refactored to use it.

### 5.3 Endpoint application + semantics
Each time-series endpoint gains `window: str = Query("1h")` (+ optional `start`/`end`) and filters
by the finding's **`detected_at`** (when it happened), not `created_at` (when the row was written):
`WHERE detected_at BETWEEN start AND end`.

Endpoints to update (the ones time-aware pages call): `soc/dashboard`, `soc/metrics`,
`detection/*` (packages, network, processes, identity, persistence, execution), `findings` list,
`threat/*`, incidents, timeline, and posture **trend** widgets.

**Semantics rule (explicit per endpoint):** the window filters *event/finding* data. **Point-in-time
state — current CIS score, live asset inventory, link/online status — always shows latest and
ignores the window.** Only the finding/trend widgets attached to those pages honor it. This is
documented in each endpoint's docstring so behavior is unambiguous.

### 5.4 Indexing + performance
- Add `CREATE INDEX IF NOT EXISTS idx_findings_detected ON findings(detected_at)` and
  `idx_findings_agent_detected ON findings(agent_id, detected_at)` so 90d/180d scans stay fast.
- Short windows (5m/1h) hit hot/indexed data; long windows lean on the index. Telemetry-backed
  views (timeline/raw) already read the time-partitioned tiers via `idx_tel_range`.
- Long-window polling load is bounded by the frontend's **window-scaled poll cadence** (§6.3),
  not a fixed 30s. Server-side aggregate caching is deferred (non-goal) unless profiling shows need.

## 6. Frontend design

### 6.1 `TimeRangeContext` (`app/context/TimeRangeContext.tsx` — new)
- Provides `{ window: WindowKey, setWindow(w) }`.
- Provided in `AppShell` so every routed page shares it.
- Source of truth order: **URL `?window=` → localStorage → default `1h`**. On `setWindow`, write
  both the URL query (so it's shareable/bookmarkable and survives reload) and localStorage.
- Exposes a typed `WINDOW_KEYS` list mirroring the backend vocabulary (single FE constant).

### 6.2 `<TimeRangePicker>` (`app/components/TimeRangePicker.tsx` — new)
- Segmented / dropdown control of the 9 presets, mounted in `TopHeader`.
- **Hidden on non-time routes** via a `timeAware` flag added to the route metadata (`_routes.ts` /
  router config). Non-time routes: Settings/*, Login, CustomCorrelationRules (config), and any
  page without a time dimension.
- Shows the active window + an "updated Ns ago" freshness chip fed by the hook.

### 6.3 `useWindowedData` hook (`app/hooks/useWindowedData.ts` — new)
```
useWindowedData(fetcher: (params: {window, signal}) => Promise<T>, opts?)
  → { data, loading, error, lastUpdated, refresh }
```
- Reads `window` from `TimeRangeContext`.
- **Refetches immediately when `window` changes.**
- **Live auto-poll** on a window-scaled interval: `≤1h → 30s`, `≤1d → 60s`, `>1d → 300s`.
- Uses `AbortController` to cancel in-flight requests on window change / unmount (prevents stale
  overwrites and races).
- A tiny `withWindow(url, window)` helper merges `?window=` into an existing query string.

### 6.4 Page migration
Each time-aware page swaps its `fetch()`/`useEffect` block for `useWindowedData` (or minimally adds
`window` to the fetch URL + effect dependency). Mechanical, ~one edit per page. Pages that render
several endpoints call the hook once per endpoint (or batch in one fetcher). ~15–20 pages.

## 7. Data flow

```
TopHeader <TimeRangePicker> → setWindow(w)
  → TimeRangeContext updates URL ?window= + localStorage
    → every mounted time-aware page's useWindowedData sees new window
      → refetch GET /api/v1/<endpoint>?window=w   (+ AbortController cancels prior)
        → resolve_window(w) → [start,end]
          → WHERE detected_at BETWEEN start AND end
            → windowed JSON → page renders → freshness chip resets
  ⟳ window-scaled poll repeats the fetch to keep the window live
```

## 8. Edge cases

- Invalid/absent `window` (FE or BE) → default `1h`; BE returns 422 only for an explicitly bad value.
- Empty window (e.g. 5m with no recent findings) → normal empty state, **not** an error.
- Rapid window switching → AbortController cancels superseded requests; last selection wins.
- Point-in-time widgets (current CIS, asset inventory) → unaffected by window (§5.3).
- Non-time pages → picker hidden, window param ignored server-side if ever sent.
- Long window + fast poll → prevented by window-scaled cadence (§6.3).
- Clock: all windows computed against server `now` at request time (no client-clock trust).

## 9. Testing

**Backend**
- `resolve_window`: each of the 9 presets → correct `[start,end]`; explicit `start/end` override;
  unknown window → 422.
- Endpoint filter: seed findings at known `detected_at`; assert only in-window rows returned for a
  given `window`; boundary inclusivity.
- Index presence smoke (migration idempotent).

**Frontend**
- `TimeRangeContext`: precedence (URL > localStorage > default); `setWindow` writes both.
- `useWindowedData`: window change triggers exactly one refetch; poll cadence scales by window;
  AbortController cancels prior request; `lastUpdated` advances on success.
- `<TimeRangePicker>`: hidden on `timeAware:false` routes; reflects active window.

## 10. Rollout / scope

The bulk of effort is mechanical: extend the window map (1 file), add resolver (1 file), add
`window` to ~10 endpoints + finding-time index (migration), then FE context/picker/hook (3 files)
and migrate ~15–20 pages. Ship backend first (endpoints accept `window`, default `1h` = today's
behavior for short windows), then the FE control, then page-by-page migration so partial rollout
never breaks a page (a page not yet migrated simply ignores the global window until migrated).

## 11. File-level change list (initial)

**Backend**
- `shared/wire.py` — extend `WINDOW_SECONDS` (7h/15d/180d).
- `manager/manager/timewindow.py` — new `resolve_window`.
- `manager/manager/api/agents.py` — refactor to use `resolve_window`.
- `manager/manager/api/findings.py` (soc/dashboard, soc/metrics, findings list) — add `window`.
- `manager/manager/api/detection.py`, `threat.py`, `posture.py` (trend widgets), incidents/timeline
  endpoints — add `window`.
- `manager/manager/db.py` (or migration) — `idx_findings_detected`, `idx_findings_agent_detected`.

**Frontend** (`manager/dashboard/templates/Build Smart AttackLens Platform/src/app/`)
- `context/TimeRangeContext.tsx` — new.
- `components/TimeRangePicker.tsx` — new; mounted in `components/TopHeader.tsx`.
- `hooks/useWindowedData.ts` — new (+ `withWindow` helper).
- `pages/_routes.ts` (+ router config) — add `timeAware` flag.
- `layouts/AppShell.tsx` — wrap in `TimeRangeProvider`.
- Time-aware pages — migrate fetches to `useWindowedData`.

## 12. Risks / open items

- **Long-window aggregate cost** on 90d/180d for heavy endpoints — mitigated by indexes + scaled
  poll; revisit with a short-TTL server cache if profiling shows hotspots.
- **Endpoint enumeration** — the exact list of endpoints each time-aware page calls is finalized
  during planning (grep each page's fetch URLs); the list in §5.3/§11 is the initial set.
- **`detected_at` completeness** — confirm all finding sources populate `detected_at`; fall back to
  `created_at` per-source only if a source leaves it null.
