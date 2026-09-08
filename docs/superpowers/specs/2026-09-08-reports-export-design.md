# Reports Export — Design Spec (Deep, Everything-in-One-Workbook)

**Date:** 2026-09-08
**Status:** Approved
**Product:** AttackLens — Agentic Exposure Management Platform
**Supersedes / extends:** `2026-09-03-reports-section-design.md` (the original 2-tab Reports page). This spec keeps that page and expands the export to a comprehensive multi-sheet workbook, adds **evidence** and **timeline history**, and adds a **Phase B backend export endpoint**.

---

## 1. Goal

Let an operator export a complete forensic report of the platform's state — **Deep Analysis + DeepMesh (AI security) telemetry, all incidents across every attack terrain, and per-incident evidence, scores, remediation, actions, and full timeline history** — as a single Excel workbook (or per-sheet CSV).

Delivered in two phases, built **one after the other**:

- **Phase A — client-side** (ship first): reuse existing APIs, assemble the workbook in the browser with SheetJS. Zero backend changes.
- **Phase B — backend endpoint** (after A): `GET /api/v1/reports/export` assembles the same workbook server-side with SQL joins (no N+1), streams the file. The front-end routes large exports here automatically.

Both phases emit the **identical 5-sheet workbook** (§3), so output is stable across engines.

---

## 2. Data sources & field mappings (ground truth)

| Dataset | Endpoint | Notes |
|---|---|---|
| Incidents | `GET /api/v1/detection/all` | Enriched findings. `evidence` is already returned as a **parsed dict** (`detection.py` normalises `("evidence", {})`). `action_plan` (list), `available_actions`, `precision_score`, `confidence_pct`, MITRE/CVE fields, `ai_verdict{label,confidence,reasoning}`, `finding_uid`, `external_id`. |
| Timeline | `GET /api/v1/findings/{id}/timeline` | Per-incident. Merged case events + SOC activity (`indexer.get_finding_timeline`). Each event: `source` (`case`/`soc_activity`), `actor`, `action`, `from_status`, `to_status`, `note`, `created_at` (epoch), `elapsed` (label), `changed_fields`, `metadata`, `finding_uid`. |
| Telemetry | `GET /api/v1/raw/query` | Deep Analysis rows for all sections; supports agent + time-window + section filters. Fields: `collected_at`, `received_at`, `agent_id`, `section`, `record_count`, `data`. Agent names from `GET /api/v1/raw/agents`. Counts from `GET /api/v1/raw/count`. |
| DeepMesh | `GET /api/v1/raw/query` | Same as telemetry, filtered to the `developer_security` section (AI/developer security). |

Timeline is the only dataset **not** available in bulk — hence the phased approach (Phase A fetches it per-incident; Phase B batches it in SQL).

---

## 3. Workbook structure (5 sheets)

CSV mode emits one file per sheet (CSV cannot hold multiple tables); Excel emits one `.xlsx`. Excel gets frozen header rows, auto column widths, and severity-colour-coded Incident rows (Critical `#FEE2E2`, High `#FEF3C7`, Medium `#DBEAFE`, Low/Info none).

### 3.1 `Summary` (1 row / cover)
`generated_at` (ISO), `platform`, `time_window`, `filters_applied` (human string), `total_incidents`, `incidents_by_severity` (Critical/High/Medium/Low/Info counts), `incidents_by_terrain`, `incidents_by_status`, `total_timeline_events`, `deep_analysis_rows`, `deepmesh_rows`.

### 3.2 `Incidents` (1 row per finding) — from `/api/v1/detection/all`
Carries the full column set from the 2026-09-03 spec **plus `evidence`**:
`finding_id`, `finding_uid`, `external_id`, `asset_agent_id`, `asset_hostname`, `first_detected_at`, `last_detected_at`, `incident_title`, `category`, `terrain`, `severity`, `status`, `description`, `business_impact`, `confidence_pct`, `validation_score_pct`, `source`, `rule_id`, `mitre_tactic`, `mitre_technique`, `cve_ids`, `cvss_score`, `kev`, `exploit_available`, `ai_verdict`, `ai_confidence_pct`, `ai_reasoning`, `remediation`, `actions_performed`, `scan_count`, **`evidence`** (JSON-stringified).

### 3.3 `Timeline` (1 row per event) — from `/api/v1/findings/{id}/timeline`
`finding_id`, `finding_uid`, `incident_title`, `severity`, `terrain`, `event_time` (from `created_at` → ISO), `elapsed`, `source`, `actor`, `action`, `from_status`, `to_status`, `note`, `changed_fields` (JSON), `metadata` (JSON). Sorted by `finding_id`, then `event_time` ascending.

### 3.4 `Deep Analysis` (1 row per telemetry record) — from `/api/v1/raw/query` (all sections)
`timestamp` (`collected_at` → ISO), `agent_id`, `agent_name`, `section`, `record_count`, `ingest_lag_s` (`received_at - collected_at`), `data` (JSON-stringified).

### 3.5 `DeepMesh (AI Security)` (1 row per record) — from `/api/v1/raw/query` (`developer_security`)
Same columns as `Deep Analysis`, filtered to `developer_security`.

---

## 4. Phase A — client-side (ship first)

Front-end app root: `manager/dashboard/templates/Build Smart AttackLens Platform/` (Vite/React, `base: /static/`, builds to `../../static/`).

### New files (paths relative to app root `src/app/`)
| File | Purpose |
|---|---|
| `pages/Reports.tsx` | Reports page: three sections/tabs — **Telemetry Export**, **Incident Report**, and **Full Report** (all 5 sheets in one workbook). Filter bars per the 2026-09-03 spec (time window, agent, sections; time window, terrain, severity, status). |
| `lib/exportUtils.ts` | Pure functions: `toCSV(rows, cols)`, `toXLSX(sheets: {name, rows, cols, colorBy?}[], filename)` (multi-sheet, frozen header, auto-width, severity fill). |
| `lib/reportData.ts` | Fetchers: paginate `/detection/all` and `/raw/query` to exhaustion; `fetchTimelines(ids, {concurrency:6, onProgress})` for the per-incident N+1 with a bounded pool; `buildSummary(...)`. |

### Modified files
| File | Change |
|---|---|
| `components/Sidebar.tsx` | Add `Reports` item to the "Inventory & Analysis" group (below DeepMesh). |
| `router/index.tsx` (and/or `pages/_routes.ts`) | Add `{ path: "reports", element: <Reports/> }` under the authenticated shell. |
| `package.json` | Add `xlsx` (SheetJS community). |

### Mechanics
- Fetch **all pages** before building the file; show progress ("Fetching N incidents…", "Timeline 40/120…").
- Timeline: bounded-concurrency pool (~6) over incident ids; a failed single timeline degrades that incident's events to empty, never aborts the export.
- Confirm dialog on > 10,000 total rows before fetching.
- Reuse existing patterns from `Incidents.tsx` / `DeepAnalysis.tsx` / `DeepMesh.tsx` for the API client, `timeRange.ts`, terrain/severity chips, and page theming.
- Build: `npm run build` in the app root regenerates `manager/dashboard/static/` (served read-only by the manager; the compose bind-mount picks it up without a manager rebuild).

---

## 5. Phase B — backend export endpoint (after A works)

### New file
`manager/manager/api/reports.py` → `make_reports_router(intel_db, db)`:

`GET /api/v1/reports/export`
- Query params: `type=all|incident|telemetry` (default `all`), `format=xlsx|csv` (default `xlsx`), plus the same filters as the UI (`window`/`start`/`end`, `agent`, `sections`, `terrain`, `severity`, `status`).
- Builds the identical 5 sheets: findings + `evidence` from one query; timeline batched across `finding_timeline` + `soc_activity` for the matched ids (no N+1); telemetry/deepmesh from the raw store.
- `xlsx` → stream via `xlsxwriter` into a `BytesIO`; `csv` → a zip of per-sheet CSVs. Returns `StreamingResponse` with `Content-Disposition: attachment; filename="attacklens-report-<ts>.xlsx"`.
- Guarded by `require_session` (and/or admin token) and tenant-scoped, matching sibling routers.

### Modified files
| File | Change |
|---|---|
| `manager/manager/server.py` | Register `make_reports_router(...)` alongside the other routers. |
| manager requirements (`pyproject.toml`) | Add `xlsxwriter`. |
| `lib/reportData.ts` (front-end) | When total rows exceed a threshold (or a "Server export" toggle is on), `GET /api/v1/reports/export` and download the streamed file instead of building client-side. |

---

## 6. Error handling
- Fetch failure mid-export → inline banner "Export failed: <msg>. Try again." (client) / `500` JSON (server); partial per-incident timeline failures never abort.
- No data matches filters → disable export buttons, show "No data matches the current filters."
- Large exports (> 10k rows, client) → confirmation dialog.

## 7. Testing
- **Phase A:** unit-test `exportUtils.toCSV`/column mapping and `reportData` pagination + timeline pool (mock fetch); render test that Reports mounts and the export buttons enable/disable on data. Follow the existing `*.test.ts(x)` patterns in `pages/`.
- **Phase B:** unit-test the row-assembly/field-mapping helpers (pure, no I/O); an API test that `/reports/export?type=incident&format=csv` returns the expected header row + one finding, and that it is session-guarded (401 without a session) and tenant-scoped. Follow `manager/tests/unit/` patterns (`test_finding_query_contract.py`, `test_all_incidents_filter.py`).

## 8. Out of scope (future)
- Scheduled/emailed report delivery; PDF export; saved filter presets; per-sheet pivot/summary charts.
