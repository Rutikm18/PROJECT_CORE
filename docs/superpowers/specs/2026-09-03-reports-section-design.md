# Reports Section — Design Spec

**Date:** 2026-09-03  
**Status:** Approved  
**Product:** AttackLens — Agentic Exposure Management Platform

---

## Overview

Add a **Reports** section to the AttackLens dashboard sidebar. It provides two distinct, export-ready report types that let operators extract structured data from the platform as CSV or Excel files.

The feature is front-end only (client-side export via SheetJS). No new backend API endpoints are required; it reuses existing APIs.

---

## Architecture

### New Files

| File | Purpose |
|---|---|
| `src/app/pages/Reports.tsx` | Two-tab Reports page component |
| `src/app/lib/exportUtils.ts` | Pure export functions: `toCSV(rows, cols)`, `toXLSX(rows, cols, filename)` |

### Modified Files

| File | Change |
|---|---|
| `src/app/components/Sidebar.tsx` | Add `{ label: "Reports", to: "/reports", icon: FileText }` to the "Inventory & Analysis" nav group |
| `src/app/router/index.tsx` | Add `{ path: "reports", element: <S><Reports /></S> }` under the authenticated shell children |

### Dependency

Install `xlsx` (SheetJS community edition) via npm. It runs entirely client-side — no server involvement. CSV export requires no new dependency.

---

## Tab 1: Telemetry Export

Exports raw telemetry rows from Deep Analysis (all sections) and DeepMesh (`developer_security` section).

### API Used

`GET /api/v1/raw/query` — same endpoint as Deep Analysis.

### Filter Bar

Three controls displayed in a horizontal bar:

1. **Time Window** — segmented button group: `1h | 6h | 24h | 7d` (default: `24h`)
2. **Agent** — native `<select>`: "All Agents" or a specific agent ID/name. Populated from `/api/v1/raw/agents`.
3. **Sections** — multi-select popover. Lists all 25+ available sections with their icons and current record counts (fetched per section from `/api/v1/raw/count`). User checks/unchecks. "DeepMesh" maps to `developer_security` section.

### Preview Table

- Columns: `Timestamp | Agent | Section | Records | Preview`
- Max 200 rows shown in the UI (for performance)
- Counter: "X total records match your filters" (from `/api/v1/raw/count`)
- Updates live as filters change (debounced 300ms)

### Export Columns (per row in the file)

| Column | Source field |
|---|---|
| `timestamp` | `collected_at` converted to ISO 8601 |
| `agent_id` | `agent_id` |
| `agent_name` | resolved from agents list |
| `section` | `section` |
| `record_count` | `record_count` |
| `ingest_lag_s` | `received_at - collected_at` |
| `data` | `data` JSON-stringified |

### Export Actions

- **Download CSV** — streams all matching rows (no preview limit), one file
- **Download Excel (.xlsx)** — same data, auto-column widths, frozen header row

For exports, fetch all pages from `/api/v1/raw/query` (loop until exhausted) before generating the file. Show a spinner + "Fetching X rows…" during multi-page fetches.

---

## Tab 2: Incident Report

Exports incident/finding data with full forensic detail matching what operators need for audits, stakeholder reporting, and remediation tracking.

### API Used

`GET /api/v1/detection/all` — same endpoint as the Incidents / ThreatQueue pages.

### Filter Bar

Four controls:

1. **Time Window** — `1h | 6h | 24h | 7d | All` (default: `7d`). "All" passes no time filter to the API, returning every finding ever stored. Use `rangeToParams()` from `timeRange.ts` for the standard windows; for "All", omit `start` and `end` params entirely.
2. **Terrain/Category** — multi-select popover: `Origin | Vector | Citadels | Mesh | Identity | Posture | All`
3. **Severity** — multi-select: `Critical | High | Medium | Low | Info`
4. **Status** — single-select dropdown: `All | New | Triaging | Investigating | In Remediation | Remediated`

### Preview Table

Compact rows (one per finding):
- Severity badge | Title | Terrain chip | Asset/Agent | Last Detected | Confidence %
- Max 100 rows shown in UI
- Counter: "Showing X of Y findings"

### Export Columns (per finding in the file)

| Column | Source field | Notes |
|---|---|---|
| `asset_agent_id` | `agent_id` | |
| `asset_hostname` | `agent_hostname` (from agent list lookup) | |
| `first_detected_at` | `first_detected_at` → ISO 8601 | |
| `last_detected_at` | `last_detected_at` → ISO 8601 | |
| `incident_title` | `title` | |
| `category` | `category` | |
| `terrain` | `terrain` | |
| `severity` | `severity` | |
| `description` | `description` | |
| `business_impact` | `impact` | |
| `remediation` | `action_plan` (JSON-stringified if array) | |
| `actions_performed` | `available_actions` (joined) | |
| `validation_score_pct` | `precision_score * 100` | |
| `confidence_pct` | `confidence_pct` | |
| `source` | `source` | |
| `rule_id` | `rule_id` | |
| `mitre_technique` | `mitre_technique` | |
| `mitre_tactic` | `mitre_tactic` | |
| `cve_ids` | `cve_ids` (comma-joined) | |
| `cvss_score` | `cvss_score` | |
| `kev` | `kev` → "Yes"/"No" | |
| `exploit_available` | `exploit_available` → "Yes"/"No" | |
| `status` | `status` | |
| `scan_count` | `scan_count` | |
| `ai_verdict` | `ai_verdict.label` | tp/fp/uncertain |
| `ai_confidence_pct` | `ai_verdict.confidence * 100` | |
| `ai_reasoning` | `ai_verdict.reasoning` | |
| `external_id` | `external_id` | |
| `finding_uid` | `finding_uid` | |

### Export Actions

- **Download CSV** — all matching findings, comma-separated
- **Download Excel (.xlsx)** — same data with severity-colour-coded rows:
  - Critical → light red fill (`#FEE2E2`)
  - High → light amber fill (`#FEF3C7`)
  - Medium → light blue fill (`#DBEAFE`)
  - Low / Info → no fill

For exports, fetch all pages from `/api/v1/detection/all` before generating. Show progress: "Fetching X findings…".

---

## UI Theme

Consistent with existing product design:

- **Page accent color**: Teal/blue-violet gradient `linear-gradient(90deg, #6366f1, #8b5cf6, #a78bfa)` — distinct from orange (Deep Analysis) and pure violet (sidebar brand)
- **Header bar**: 3px top accent bar, `FileText` icon, white `rounded-2xl shadow-card` card
- **Tab bar**: Two tabs styled identically to ThreatIntelligence tabs — pill buttons, active = white bg + shadow
- **Filter bar**: Same horizontal chip/select pattern as the Deep Analysis header
- **Export buttons**: Primary action button with `Download` icon — `bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl px-4 py-2 text-sm font-semibold`
- **Loading state**: Spinner in button + progress text "Fetching N rows…"

---

## Sidebar Placement

Added to the **"Inventory & Analysis"** group, below DeepMesh and above Custom Rules:

```
Inventory & Analysis
  Timeline & History
  Deep Analysis
  DeepMesh             [Beta]
  Reports              ← new
  Custom Rules         [Soon]
  Asset Registry
```

Route: `/reports`. The Telemetry Export tab is the default active tab on initial load. Tab state is local React state (no URL param needed for MVP).

---

## Error Handling

- If fetch fails during export: show an inline error banner "Export failed: [error message]. Try again."
- If no data matches filters: disable export buttons, show "No data matches the current filters" in the preview area
- Large exports (>10,000 rows): show a confirmation dialog "This will export ~X rows. Continue?" before fetching all pages

---

## Out of Scope

- Scheduled/automated report delivery (email, S3) — future work
- PDF export — future work
- Saved filter presets — future work
- Server-side export endpoint — not needed; client-side is sufficient for current data volumes
