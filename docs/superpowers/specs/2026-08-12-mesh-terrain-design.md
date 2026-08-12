# Design: "Mesh" — Attack Terrain section for deep-mesh incidents

**Date:** 2026-08-12
**Status:** Approved (design) — pending implementation plan
**Author:** AttackLens dashboard team

## 1. Goal

Add a 4th **Attack Terrain** section — **Mesh** — that surfaces incidents from the
existing `developer_security` (deep-mesh) detection module: the AI / coding-agent
tooling attack surface (editor extensions, MCP servers, CLI/PATH, browser & native
messaging, git overrides, credential exposure, listeners, dev containers).

Attack Terrain becomes: **Origin · Vector · Citadels · Mesh**.

Non-goals: the raw telemetry viewer (`DeepMesh.tsx` at `/analysis/deepmesh`) stays
as-is; a new detection engine (the `developer_security` module already emits findings).

## 2. Key insight / why this is small

Deep-mesh detections already exist. `attacklens/detections/developer_security.py`
emits findings with `category: "developer_security"` and rules `AL-DEV-001…009`.
But `developer_security` is **not** in the `CATEGORY_TO_TERRAIN` map, so
`terrain_for()` defaults them to `origin` — they are **mislabeled into Origin today**.

The feature is: give them their own terrain bucket and a page. Data comes from the
same endpoint every terrain uses — `GET /api/v1/detection/all?terrain_id=mesh`.

## 3. Architecture / data flow

```
agent developer_security collector ──▶ ingest ──▶ detection engine
  (developer_security snapshot)                     (developer_security.py, AL-DEV-00x)
                                                          │ findings, category=developer_security
                                                          ▼
                                            upsert_finding → terrain_for() → terrain_id="mesh"
                                                          ▼
                          GET /api/v1/detection/all?terrain_id=mesh  ──▶  MeshThreats.tsx
```

Mesh mirrors `ExecutionThreats` (Citadels) structurally: KPI header → filter controls
→ shared `TerrainDetectionPage` table. **One structural difference:** every deep-mesh
finding shares `category: developer_security`, so the page sub-divides by **capability
(`rule_id`)**, not by category.

## 4. Backend changes

| File | Change |
|---|---|
| `manager/manager/attacklens/terrain_validators.py` (~L54) | Add `"mesh": ["developer_security"]` to the terrain→categories dict feeding `CATEGORY_TO_TERRAIN`. Makes `terrain_for()` return `mesh`. |
| `manager/manager/api/settings.py` (L163–174) | Add `mesh` to `VALIDATION_TERRAINS`, `VALIDATION_TERRAIN_CATEGORIES`, `VALIDATION_TERRAIN_LABELS` (the mirror). Required or the Settings→Validation page rejects a `mesh` threshold (`unknown` check at L288). Label: `"Mesh (Developer & Agent Tooling)"`. |
| `manager/manager/indexer.py` `upsert_finding` (~L1166) | **No change** — already calls `terrain_for()`; new findings auto-tag `mesh` once the map is updated. |
| `manager/manager/indexer.py` migrations (~L1071) | **One-time backfill** (idempotent, mirrors existing pattern): `UPDATE findings SET terrain_id='mesh' WHERE category='developer_security' AND terrain_id IN ('origin','')`. This moves existing mislabeled findings out of Origin into Mesh. |
| `manager/manager/api/detection.py` (L468) | Cosmetic: add `mesh` to the `terrain_id` param description. Column filtering already works. |

Optional (not v1-blocking): a `MESH_CRITERIA` list in `terrain_validators.py`
(`TERRAIN_CRITERIA`) for the "Validated" toggle. Without it, the validated view falls
back to `ORIGIN_CRITERIA` — harmless since validation is opt-in and off by default.

## 5. Frontend changes

| File | Change |
|---|---|
| `pages/MeshThreats.tsx` **(new)** | Clone of `ExecutionThreats.tsx`. Fetches `terrain_id=mesh`. Accent violet (`#7C3AED`, matches DeepMesh), icon `Radio`, header **"Mesh — Developer & Agent Threats"**, subtitle "AI-tool & coding-agent attack surface · extensions · MCP · CLI · browser · credentials". |
| `router/index.tsx` | Lazy-import `MeshThreats`; add `{ path: "mesh", element: <S><MeshThreats/></S> }` under `terrain` children. |
| `components/Sidebar.tsx` | Add `{ label: "Mesh", to: "/terrain/mesh", icon: Radio, badgeColor: "red" }` to the Attack Terrain group; add `developer_security`, `mcp`, `extension`, `agent` → `/terrain/mesh` in `CAT_MAP` so badge counts route to Mesh. |
| `pages/_routes.ts` | Add `mesh: "/terrain/mesh"` under `terrain`. |

## 6. The bespoke part — capability KPIs & chips

Rule → capability mapping (from `developer_security.py`):

| Rule | Capability | Severity |
|---|---|---|
| AL-DEV-001 | Editor Extensions | high |
| AL-DEV-002 | MCP Servers | medium/high |
| AL-DEV-003 | PATH / CLI | high |
| AL-DEV-004 | Browser (native msg + perms) | high |
| AL-DEV-005 | Browser / Native Msg host | high |
| AL-DEV-006 | Git overrides | medium |
| AL-DEV-007 | Credential exposure | high |
| AL-DEV-008 | Listeners (all-interfaces) | medium |
| AL-DEV-009 | Runtime / Container | critical |

- **KPI tiles (5):** Total · Critical+High · Agent Tooling (MCP + Extensions) ·
  Credentials Exposed · Network-Exposed (Listeners).
- **Filter chips:** Extensions · MCP · CLI/PATH · Browser · Git · Credentials ·
  Listeners · Runtime — rendered only when count > 0 (same pattern as Citadels),
  filtering the table by `rule_id`.
- **Table columns:** Capability (derived from `rule_id`) · Confidence · Risk · MITRE.

## 7. Data completeness — payload truncation

Deep-mesh snapshots are capped at the **agent** in
`agent/os/macos/collectors/developer_security.py` `_bounded_snapshot()`
(`_MAX_SNAPSHOT_BYTES`, ~6 MB; trims largest lists in half until it fits ~4 MB target).
On truncation it sets `collection.partial = true`, `payload_truncated = true`, and
records `payload_truncations` (path, original_count, retained_count).

Consequence: on a very large dev/AI-tooling host, some items never reach detection →
Mesh can under-count, silently.

**In scope:** Mesh surfaces a **"partial data"** badge when a host's snapshot was
truncated (data already present in the envelope). No silent incompleteness.

**Out of scope (separate follow-up spec):** true "capture all data" — a *collection*
change, not UI: raise `_MAX_SNAPSHOT_BYTES`, or chunked / multi-part deep-mesh uploads
reassembled server-side. Tracked separately; does not block this section.

## 8. Testing

- Backend: `terrain_for({"category":"developer_security"}) == "mesh"`; backfill UPDATE
  moves an origin-tagged dev-sec row to mesh; `/detection/all?terrain_id=mesh` returns
  only dev-sec findings; settings accepts a `mesh` validation threshold.
- Frontend: `MeshThreats` renders KPIs + capability chips from a mocked `terrain_id=mesh`
  response; capability chip filters the table by `rule_id`; partial-data badge shows when
  `payload_truncated` present.

## 9. Files touched (summary)

**Create:** `pages/MeshThreats.tsx`
**Modify:** `terrain_validators.py`, `api/settings.py`, `indexer.py`, `api/detection.py`,
`router/index.tsx`, `components/Sidebar.tsx`, `pages/_routes.ts`
**Tests:** backend terrain/backfill/settings tests; `MeshThreats` component test.

## 10. Decisions locked

1. Name = **Mesh**, route `/terrain/mesh`, page `MeshThreats.tsx`.
2. Routing = **re-tag** `developer_security` → `mesh` (map + one-time backfill); removed
   from Origin.
3. Truncation = ship partial-data badge now; chunked-collection "all data" is a separate
   follow-up spec.
