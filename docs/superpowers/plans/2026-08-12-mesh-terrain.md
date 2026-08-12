# Mesh Terrain Section Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a 4th Attack Terrain section, "Mesh", surfacing deep-mesh (`developer_security`) incidents in a page that mirrors the existing terrain sections.

**Architecture:** The `developer_security` detection module already emits findings (`category: "developer_security"`, rules `AL-DEV-001…009`). Today they default into the Origin terrain because `developer_security` is unmapped. We register a new `mesh` terrain (map + settings mirror + one-time backfill), then add a `MeshThreats.tsx` page that fetches `GET /api/v1/detection/all?terrain_id=mesh` — the same endpoint every terrain uses. The one structural difference: Mesh sub-divides by **capability (`rule_id`)** instead of `category` (all findings share one category).

**Tech Stack:** FastAPI + aiosqlite (`manager/manager`), React 19 + React Router + Tailwind + lucide-react (`manager/dashboard/templates/Build Smart AttackLens Platform/src/app`), pytest (backend), vitest (frontend).

## Global Constraints

- Terrain vocabulary is the single source of truth in TWO mirrored places — `attacklens/terrain_validators.py` (`CATEGORY_TO_TERRAIN`) and `api/settings.py` (`VALIDATION_TERRAIN*`). Any new terrain MUST be added to both or the Settings→Validation page rejects it (`unknown` check, `settings.py:288`).
- Section name is **Mesh**; route `/terrain/mesh`; page file `MeshThreats.tsx`; header copy **"Mesh — Developer & Agent Threats"**.
- Findings for this terrain carry `category: "developer_security"` and rule ids `AL-DEV-001`…`AL-DEV-009`.
- Accent color violet `#7C3AED` (matches the existing DeepMesh viewer), nav icon `Radio`.
- Frontend absolute base dir: `manager/dashboard/templates/Build Smart AttackLens Platform/src/app` (referred to below as `<APP>`).
- Backfill/migrations live in `manager/manager/indexer.py`; follow the existing numbered try/except backfill blocks (`indexer.py:1071`) — idempotent, `commit()` on success, `rollback()` on exception.
- Per project CLAUDE.md: append a **What/Why** entry to `LEARNINGS.md` under a `## 2026-08-12` heading when new patterns land (append-only).

---

### Task 1: Register the `mesh` terrain (backend mapping + settings mirror)

**Files:**
- Modify: `manager/manager/attacklens/terrain_validators.py:54-60`
- Modify: `manager/manager/api/settings.py:163-174`
- Modify: `manager/manager/api/detection.py:468` (cosmetic param doc)
- Test: `manager/tests/unit/test_mesh_terrain.py`

**Interfaces:**
- Produces: `terrain_for({"category": "developer_security"}) == "mesh"`; `"mesh" in VALIDATION_TERRAINS`; `VALIDATION_TERRAIN_CATEGORIES["mesh"] == ["developer_security"]`.

- [ ] **Step 1: Write the failing test**

Create `manager/tests/unit/test_mesh_terrain.py`:

```python
from manager.attacklens.terrain_validators import terrain_for, CATEGORY_TO_TERRAIN
from manager.api.settings import (
    VALIDATION_TERRAINS,
    VALIDATION_TERRAIN_CATEGORIES,
    VALIDATION_TERRAIN_LABELS,
)


def test_developer_security_maps_to_mesh():
    assert CATEGORY_TO_TERRAIN["developer_security"] == "mesh"
    assert terrain_for({"category": "developer_security"}) == "mesh"


def test_mesh_registered_in_settings_mirror():
    assert "mesh" in VALIDATION_TERRAINS
    assert VALIDATION_TERRAIN_CATEGORIES["mesh"] == ["developer_security"]
    assert "mesh" in VALIDATION_TERRAIN_LABELS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd manager && python -m pytest tests/unit/test_mesh_terrain.py -v`
Expected: FAIL — `KeyError: 'developer_security'` / `assert 'mesh' in [...]`.

- [ ] **Step 3: Add `mesh` to the terrain map**

In `manager/manager/attacklens/terrain_validators.py`, the dict literal at lines 54-60 currently ends with `"posture": [...]`. Add the `mesh` entry:

```python
for _t, _cats in {
    "citadels": ["execution","process","script","container","persistence","service","task","malware"],
    "vector":   ["network","connection","port","arp","covert","lateral","mount"],
    "origin":   ["package","vulnerability","sbom","config","binary","sysctl","app","open_file","storage"],
    "identity": ["user","identity","account","credential"],
    "posture":  ["security","posture","sip","firewall","agent_health","battery","hardware"],
    "mesh":     ["developer_security"],
}.items():
```

- [ ] **Step 4: Add `mesh` to the settings mirror**

In `manager/manager/api/settings.py`:

Line 163 — add `"mesh"`:
```python
VALIDATION_TERRAINS: list[str] = ["citadels", "vector", "origin", "identity", "posture", "mesh"]
```

Line 164-170 (`VALIDATION_TERRAIN_CATEGORIES` dict) — add entry:
```python
    "mesh":     ["developer_security"],
```

Line 171-174 (`VALIDATION_TERRAIN_LABELS` dict) — add entry:
```python
    "mesh":     "Mesh (Developer & Agent Tooling)",
```

- [ ] **Step 5: Cosmetic — extend the endpoint param doc**

In `manager/manager/api/detection.py:468`, change:
```python
        terrain_id: Optional[str] = Query(None, description="citadels|vector|origin|identity|posture"),
```
to:
```python
        terrain_id: Optional[str] = Query(None, description="citadels|vector|origin|identity|posture|mesh"),
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd manager && python -m pytest tests/unit/test_mesh_terrain.py -v`
Expected: PASS (2 tests).

- [ ] **Step 7: Commit**

```bash
git add manager/manager/attacklens/terrain_validators.py manager/manager/api/settings.py manager/manager/api/detection.py manager/tests/unit/test_mesh_terrain.py
git commit -m "feat(terrain): register mesh terrain for developer_security findings"
```

---

### Task 2: One-time backfill — re-tag existing deep-mesh findings out of Origin

**Files:**
- Modify: `manager/manager/indexer.py` (add a backfill block after the existing terrain backfill at `indexer.py:1071-1082`)
- Test: `manager/tests/unit/test_mesh_backfill.py`

**Interfaces:**
- Consumes: findings table column `terrain_id` (TEXT), `category` (TEXT).
- Produces: after startup migration, all rows with `category='developer_security'` and `terrain_id IN ('origin','')` have `terrain_id='mesh'`.

- [ ] **Step 1: Write the failing test**

Create `manager/tests/unit/test_mesh_backfill.py`. This tests the exact SQL statement standalone against an in-memory sqlite DB (no fixtures needed):

```python
import sqlite3

# The corrective backfill statement, kept identical to indexer.py.
MESH_BACKFILL_SQL = (
    "UPDATE findings SET terrain_id='mesh' "
    "WHERE category='developer_security' AND terrain_id IN ('origin', '')"
)


def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, category TEXT, terrain_id TEXT)")
    return c


def test_backfill_moves_devsec_from_origin_to_mesh():
    c = _db()
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('developer_security','origin')")
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('developer_security','')")
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('package','origin')")
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('developer_security','mesh')")
    c.execute(MESH_BACKFILL_SQL)
    rows = dict(
        (cat + "|" + tid, n)
        for cat, tid, n in c.execute(
            "SELECT category, terrain_id, COUNT(*) FROM findings GROUP BY category, terrain_id"
        )
    )
    # both origin/'' developer_security rows moved to mesh (2 already-mesh + 2 moved = 3? no: 1 was mesh)
    assert rows.get("developer_security|mesh") == 3          # 1 pre-existing + 2 moved
    assert "developer_security|origin" not in rows
    assert rows.get("package|origin") == 1                   # untouched


def test_backfill_is_idempotent():
    c = _db()
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('developer_security','origin')")
    c.execute(MESH_BACKFILL_SQL)
    c.execute(MESH_BACKFILL_SQL)  # second run is a no-op
    (n,) = c.execute(
        "SELECT COUNT(*) FROM findings WHERE terrain_id='mesh'"
    ).fetchone()
    assert n == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd manager && python -m pytest tests/unit/test_mesh_backfill.py -v`
Expected: PASS at the SQL level immediately (this test pins the statement). If it fails, the SQL string is wrong — fix it here first.

> Note: this test guards the SQL contract. The next step wires the SAME statement into `indexer.py` startup so production data is migrated.

- [ ] **Step 3: Add the backfill block to indexer startup**

In `manager/manager/indexer.py`, immediately AFTER the existing block that ends at line 1082 (`await self._conn.rollback()` of block "6. Backfill terrain_id…"), insert:

```python
        # 6b. Corrective backfill: developer_security findings were historically
        # defaulted into the 'origin' terrain (before the mesh terrain existed).
        # Move them to their own 'mesh' terrain. Idempotent — only touches rows
        # still tagged origin/''.
        try:
            await self._conn.execute(
                "UPDATE findings SET terrain_id='mesh' "
                "WHERE category='developer_security' AND terrain_id IN ('origin', '')"
            )
            await self._conn.commit()
        except Exception:
            await self._conn.rollback()
```

- [ ] **Step 4: Run the backend suite to verify nothing regressed**

Run: `cd manager && python -m pytest tests/unit/test_mesh_backfill.py tests/unit/test_raw_deepmesh.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add manager/manager/indexer.py manager/tests/unit/test_mesh_backfill.py
git commit -m "feat(terrain): backfill developer_security findings from origin to mesh"
```

---

### Task 3: MeshThreats page (capability model + KPIs + chips + table)

**Files:**
- Create: `<APP>/pages/MeshThreats.tsx`
- Test: `<APP>/pages/MeshThreats.capabilities.test.ts`

**Interfaces:**
- Consumes: `TerrainDetectionPage`, `useDetectionData`, `DetectionFinding` from `./DetectionShared` (already exported). `TerrainDetectionPage` accepts `apiUrl, accent, emptyMsg, columns, initialKevOnly?, initialExploitOnly?, initialSearch?` (verified at `DetectionShared.tsx:3748`).
- Produces: default export `MeshThreats`; named exports `CAPABILITIES: Capability[]`, `capabilityForRule(ruleId?: string): Capability | undefined`.

- [ ] **Step 1: Write the failing test** (pure capability logic — the bespoke part)

Create `<APP>/pages/MeshThreats.capabilities.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { CAPABILITIES, capabilityForRule } from "./MeshThreats";

describe("mesh capability mapping", () => {
  it("maps each AL-DEV rule to exactly one capability", () => {
    const rules = ["AL-DEV-001","AL-DEV-002","AL-DEV-003","AL-DEV-004",
                   "AL-DEV-005","AL-DEV-006","AL-DEV-007","AL-DEV-008","AL-DEV-009"];
    for (const r of rules) {
      expect(capabilityForRule(r), `rule ${r}`).toBeDefined();
    }
  });

  it("groups both browser rules under one capability", () => {
    expect(capabilityForRule("AL-DEV-004")!.key).toBe("browser");
    expect(capabilityForRule("AL-DEV-005")!.key).toBe("browser");
  });

  it("returns undefined for unknown / missing rule", () => {
    expect(capabilityForRule("AL-DEV-999")).toBeUndefined();
    expect(capabilityForRule(undefined)).toBeUndefined();
  });

  it("every capability declares at least one rule and a search keyword", () => {
    for (const c of CAPABILITIES) {
      expect(c.rules.length).toBeGreaterThan(0);
      expect(c.search.length).toBeGreaterThan(0);
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npx vitest run src/app/pages/MeshThreats.capabilities.test.ts`
Expected: FAIL — cannot resolve `./MeshThreats`.

- [ ] **Step 3: Create the page**

Create `<APP>/pages/MeshThreats.tsx`:

```tsx
/**
 * MeshThreats — Mesh terrain (developer & AI-agent tooling attack surface).
 *
 * Surfaces incidents from the developer_security detection module (AL-DEV-00x):
 * editor extensions, MCP servers, CLI/PATH, browser & native messaging, git
 * overrides, credential exposure, listeners, dev containers.
 *
 * Structurally mirrors ExecutionThreats (Citadels). The one difference: every
 * finding shares category="developer_security", so the page sub-divides by
 * CAPABILITY (rule_id) instead of by category. Chip/KPI counts are computed
 * precisely from rule_id; a chip click filters the shared table via
 * initialSearch (each AL-DEV rule title contains its capability keyword).
 */
import { useState, useMemo, type ReactNode } from "react";
import {
  Radio, CheckCircle2, AlertTriangle, Shield, Database,
  ExternalLink, KeyRound, Puzzle, Activity,
} from "lucide-react";
import {
  TerrainDetectionPage, useDetectionData, type DetectionFinding,
} from "./DetectionShared";
import { cn } from "../../lib/utils";

// ── Capability model (rule_id → capability) ─────────────────────────────────
export interface Capability {
  key: string; label: string; rules: string[]; search: string;
}
export const CAPABILITIES: Capability[] = [
  { key: "extension",  label: "Extensions",  rules: ["AL-DEV-001"],               search: "editor extension" },
  { key: "mcp",        label: "MCP",         rules: ["AL-DEV-002"],               search: "MCP server" },
  { key: "cli",        label: "CLI/PATH",    rules: ["AL-DEV-003"],               search: "search path" },
  { key: "browser",    label: "Browser",     rules: ["AL-DEV-004", "AL-DEV-005"], search: "messaging" },
  { key: "git",        label: "Git",         rules: ["AL-DEV-006"],               search: "Git execution" },
  { key: "credential", label: "Credentials", rules: ["AL-DEV-007"],               search: "Credential file" },
  { key: "listener",   label: "Listeners",   rules: ["AL-DEV-008"],               search: "listens on all" },
  { key: "runtime",    label: "Runtime",     rules: ["AL-DEV-009"],               search: "container" },
];

const RULE_TO_CAP: Record<string, Capability> = {};
for (const c of CAPABILITIES) for (const r of c.rules) RULE_TO_CAP[r] = c;

export function capabilityForRule(ruleId?: string): Capability | undefined {
  return ruleId ? RULE_TO_CAP[ruleId] : undefined;
}

// ── Cell renderers ──────────────────────────────────────────────────────────
function RiskScore({ f }: { f: DetectionFinding }) {
  const s   = f.composite_score ?? f.score;
  const cls = s >= 8 ? "text-red-600 bg-red-50 border-red-200"
              : s >= 6 ? "text-amber-600 bg-amber-50 border-amber-200"
              :          "text-blue-600 bg-blue-50 border-blue-200";
  return (
    <div className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-black tabular-nums", cls)}>
      {s.toFixed(1)}<span className="text-[8px] font-normal opacity-60">/10</span>
    </div>
  );
}

function ConfPct({ f }: { f: DetectionFinding }) {
  const pct   = f.confidence_pct ?? 70;
  const color = pct >= 85 ? "text-green-600" : pct >= 70 ? "text-blue-600" : "text-amber-600";
  return <span className={cn("text-[10px] font-bold tabular-nums", color)}>{pct}%</span>;
}

function CapabilityChipCell({ f }: { f: DetectionFinding }) {
  const cap = capabilityForRule(f.rule_id);
  return (
    <span className="text-[9px] font-semibold px-2 py-0.5 rounded-full border bg-violet-50 text-violet-700 border-violet-200">
      {cap?.label ?? "Developer"}
    </span>
  );
}

// ── KPI stat tile (identical pattern to ExecutionThreats) ───────────────────
function StatTile({
  label, value, sub, icon, valueClass, warn = false,
}: {
  label: string; value: string | number; sub?: string;
  icon: ReactNode; valueClass: string; warn?: boolean;
}) {
  return (
    <div className={cn(
      "flex-1 rounded-xl border px-4 py-3 transition-all",
      warn ? "bg-red-50 border-red-200 shadow-sm" : "bg-white border-gray-100"
    )}>
      <div className={cn("mb-1 opacity-60", warn ? "text-red-500" : "text-gray-400")}>{icon}</div>
      <div className={cn("text-xl font-black tabular-nums leading-none", valueClass)}>{value}</div>
      {sub && <div className="text-[9px] text-gray-400 mt-0.5 font-medium">{sub}</div>}
      <div className="text-[10px] text-gray-500 font-semibold mt-1">{label}</div>
    </div>
  );
}

type CapFilter = "all" | string;

// ── Main ────────────────────────────────────────────────────────────────────
export default function MeshThreats() {
  const [validatedOnly, setValidatedOnly] = useState(false);
  const [capFilter,     setCapFilter]     = useState<CapFilter>("all");

  const baseUrl = validatedOnly
    ? "/api/v1/detection/all?terrain_id=mesh&validated_only=true"
    : "/api/v1/detection/all?terrain_id=mesh";
  const statsUrl = `${baseUrl}&limit=500`;

  const { findings: raw } = useDetectionData(statsUrl);

  const countForCap = (cap: Capability) =>
    raw.filter(f => cap.rules.includes(f.rule_id ?? "")).length;

  const stats = useMemo(() => {
    const byCap = (key: string) => {
      const cap = CAPABILITIES.find(c => c.key === key);
      return cap ? raw.filter(f => cap.rules.includes(f.rule_id ?? "")).length : 0;
    };
    return {
      total:       raw.length,
      criticalHigh: raw.filter(f => f.severity === "critical" || f.severity === "high").length,
      agentTooling: byCap("mcp") + byCap("extension"),
      credentials:  byCap("credential"),
      listeners:    byCap("listener"),
    };
  }, [raw]);

  const selectedCap = CAPABILITIES.find(c => c.key === capFilter);
  const pageKey = `${validatedOnly}:${capFilter}`;

  return (
    <div className="space-y-0 pb-6">
      {/* ── Domain header + KPIs ─────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-xl bg-violet-50 border border-violet-100 flex items-center justify-center flex-shrink-0">
            <Radio className="w-4.5 h-4.5" style={{ color: "#7C3AED" }} />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-gray-900">Mesh — Developer &amp; Agent Threats</h2>
            <p className="text-[10px] text-gray-400 mt-0.5">
              AI-tool &amp; coding-agent attack surface · extensions · MCP servers · CLI/PATH · browser · credentials · listeners
            </p>
          </div>
          <a
            href="https://attack.mitre.org/tactics/TA0002/"
            target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-violet-50 border border-violet-200 text-violet-700 rounded-xl hover:bg-violet-100 transition-all flex-shrink-0"
          >
            <ExternalLink className="w-3 h-3" />MITRE ATT&amp;CK
          </a>
        </div>

        <div className="flex gap-2">
          <StatTile label="Mesh Incidents" value={stats.total} sub="total findings"
            icon={<Database className="w-3.5 h-3.5" />} valueClass="text-gray-800" />
          <StatTile label="Critical / High" value={stats.criticalHigh} sub="severity ≥ high"
            icon={<AlertTriangle className="w-3.5 h-3.5" />}
            valueClass={stats.criticalHigh > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.criticalHigh > 0} />
          <StatTile label="Agent Tooling" value={stats.agentTooling} sub="MCP + extensions"
            icon={<Puzzle className="w-3.5 h-3.5" />}
            valueClass={stats.agentTooling > 0 ? "text-violet-600" : "text-gray-600"} />
          <StatTile label="Credentials Exposed" value={stats.credentials} sub="secret file perms"
            icon={<KeyRound className="w-3.5 h-3.5" />}
            valueClass={stats.credentials > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.credentials > 0} />
          <StatTile label="Network Exposed" value={stats.listeners} sub="all-interface listeners"
            icon={<Activity className="w-3.5 h-3.5" />}
            valueClass={stats.listeners > 0 ? "text-orange-600" : "text-gray-600"} />
        </div>
      </div>

      {/* ── Filter controls ──────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 pt-4 pb-3 space-y-3">
        {/* Capability chips */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">Capability</span>
          <div className="flex items-center gap-1 flex-wrap">
            <button
              onClick={() => setCapFilter("all")}
              className={cn("flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                capFilter === "all" ? "bg-violet-600 text-white border-violet-600 shadow-sm"
                  : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50")}
            >
              All
            </button>
            {CAPABILITIES.map(c => {
              const count = countForCap(c);
              if (count === 0) return null;
              return (
                <button
                  key={c.key}
                  onClick={() => setCapFilter(c.key)}
                  className={cn("flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                    capFilter === c.key ? "bg-violet-600 text-white border-violet-600 shadow-sm"
                      : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50")}
                >
                  {c.label}
                  <span className={cn("ml-0.5 text-[8px] font-black px-1 rounded",
                    capFilter === c.key ? "bg-white/20 text-white" : "bg-gray-100 text-gray-600")}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Validated toggle */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="inline-flex bg-gray-100 rounded-lg p-0.5">
            <button
              onClick={() => setValidatedOnly(false)}
              className={cn("px-3 py-1.5 rounded-md text-[10px] font-bold transition-all",
                !validatedOnly ? "bg-white text-violet-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              All Mesh
            </button>
            <button
              onClick={() => setValidatedOnly(true)}
              className={cn("flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold transition-all",
                validatedOnly ? "bg-white text-emerald-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              <CheckCircle2 className="w-3 h-3" />Validated
            </button>
          </div>

          {stats.credentials > 0 && (
            <div className="flex items-start gap-2.5 px-3 py-2 bg-red-50 border border-red-200 rounded-xl ml-auto">
              <Shield className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
              <div className="text-[10px] text-red-900 leading-relaxed">
                <span className="font-bold">Playbook: </span>
                rotate any credential in an over-permissive file, then tighten perms to <code className="font-mono text-[9px] bg-red-100 px-1 rounded">600</code>.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Main detection table ─────────────────────────────────────────── */}
      <TerrainDetectionPage
        key={pageKey}
        apiUrl={baseUrl}
        accent="violet"
        emptyMsg={
          validatedOnly
            ? "No validated findings in Mesh."
            : "No developer/agent-tooling findings yet. Findings appear when the developer_security collector reports a risky component."
        }
        initialSearch={selectedCap?.search}
        columns={[
          { key: "rule_id",         label: "Capability", render: f => <CapabilityChipCell f={f} /> },
          { key: "confidence_pct",  label: "Confidence", render: f => <ConfPct f={f} /> },
          { key: "composite_score", label: "Risk",       render: f => <RiskScore f={f} /> },
          { key: "mitre_technique", label: "MITRE",      render: f => <span className="text-[9px] font-mono text-gray-400 truncate max-w-[80px] block">{f.mitre_technique ?? "—"}</span> },
        ]}
      />
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npx vitest run src/app/pages/MeshThreats.capabilities.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Typecheck the new page**

Run: `cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npx tsc --noEmit`
Expected: no errors referencing `MeshThreats.tsx`.

- [ ] **Step 6: Commit**

```bash
git add "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/MeshThreats.tsx" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/MeshThreats.capabilities.test.ts"
git commit -m "feat(fe): MeshThreats terrain page with capability KPIs and chips"
```

---

### Task 4: Wire the route + navigation

**Files:**
- Modify: `<APP>/router/index.tsx` (lazy import + terrain child route)
- Modify: `<APP>/pages/_routes.ts` (terrain block)
- Modify: `<APP>/components/Sidebar.tsx` (nav item + CAT_MAP)

**Interfaces:**
- Consumes: default export `MeshThreats` from `../pages/MeshThreats` (Task 3).
- Produces: reachable route `/terrain/mesh`; sidebar "Mesh" link under Attack Terrain; badge routing `developer_security → /terrain/mesh`.

- [ ] **Step 1: Add the lazy import + route**

In `<APP>/router/index.tsx`, in the lazy-imports block (after the `ExecutionThreats` import, ~line 55):
```tsx
const MeshThreats        = lazy(() => import("../pages/MeshThreats"));
```

In the `terrain` children array (~line 138), add after the `citadels` route:
```tsx
              { path: "mesh",         element: <S><MeshThreats /></S> },
```

- [ ] **Step 2: Add the route constant**

In `<APP>/pages/_routes.ts`, in the `terrain` object (~line 92), add:
```ts
    mesh:        "/terrain/mesh",
```

- [ ] **Step 3: Add the sidebar nav item + badge mapping**

In `<APP>/components/Sidebar.tsx`, in the "Attack Terrain" group `items` array (~line 78), add after the `Citadels` item:
```tsx
      { label: "Mesh",      to: "/terrain/mesh",        icon: Radio,       badgeColor: "red"   },
```
(`Radio` is already imported at the top of Sidebar.tsx.)

In the `CAT_MAP` object (~line 40), add mesh routing so new/critical badge counts land on the Mesh nav item:
```tsx
  developer_security: "/terrain/mesh", mcp: "/terrain/mesh",
  extension: "/terrain/mesh",          agent: "/terrain/mesh",
```

- [ ] **Step 4: Typecheck + build the frontend**

Run: `cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npx tsc --noEmit && npm run build`
Expected: build succeeds; no type errors.

- [ ] **Step 5: Manual smoke check**

Start the manager (or use the existing dev server), open `/terrain/mesh`. Expected: the Mesh page renders with the header "Mesh — Developer & Agent Threats", KPI tiles, capability chips (those with counts), and the detection table. The sidebar shows "Mesh" under Attack Terrain and highlights it as active.

- [ ] **Step 6: Commit**

```bash
git add "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/router/index.tsx" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/_routes.ts" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/components/Sidebar.tsx"
git commit -m "feat(fe): wire /terrain/mesh route and Attack Terrain nav item"
```

---

### Task 5 (optional): Partial-data badge for truncated deep-mesh snapshots

Deep-mesh snapshots are capped at the agent (`agent/os/macos/collectors/developer_security.py` `_bounded_snapshot`, ~6 MB) and set `collection.partial = true` / `payload_truncated = true` when trimmed. The raw list endpoint already returns `summary.partial` per record (metadata-only, cheap). This task surfaces a banner so Mesh never silently under-counts. It does NOT capture the dropped data (that is a separate collection-side follow-up spec).

**Files:**
- Modify: `<APP>/pages/MeshThreats.tsx` (add a partial-data banner)
- Test: `<APP>/pages/MeshThreats.partial.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/raw/query?section=developer_security&include_data=false&limit=50` → `{ rows: { summary: { partial: boolean } | null }[] }`.
- Produces: exported pure helper `countPartialHosts(rows): number`.

- [ ] **Step 1: Write the failing test**

Create `<APP>/pages/MeshThreats.partial.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { countPartialHosts } from "./MeshThreats";

describe("countPartialHosts", () => {
  it("counts rows whose summary.partial is true", () => {
    const rows = [
      { summary: { partial: true } },
      { summary: { partial: false } },
      { summary: null },
      { summary: { partial: true } },
    ];
    expect(countPartialHosts(rows)).toBe(2);
  });

  it("returns 0 for empty / undefined", () => {
    expect(countPartialHosts([])).toBe(0);
    expect(countPartialHosts(undefined)).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npx vitest run src/app/pages/MeshThreats.partial.test.ts`
Expected: FAIL — `countPartialHosts` is not exported.

- [ ] **Step 3: Add the helper + banner**

In `<APP>/pages/MeshThreats.tsx`, add the exported helper near `capabilityForRule`:

```ts
export function countPartialHosts(
  rows?: { summary: { partial?: boolean } | null }[],
): number {
  if (!rows) return 0;
  return rows.filter(r => r.summary?.partial === true).length;
}
```

Add a fetch inside `MeshThreats` (reuse the same pattern as the stats fetch). After the existing `const { findings: raw } = useDetectionData(statsUrl);` line, add:

```tsx
  const [partialHosts, setPartialHosts] = useState(0);
  useEffect(() => {
    let dead = false;
    fetch("/api/v1/raw/query?section=developer_security&include_data=false&limit=50", { credentials: "include" })
      .then(r => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((d: { rows?: { summary: { partial?: boolean } | null }[] }) => {
        if (!dead) setPartialHosts(countPartialHosts(d.rows));
      })
      .catch(() => { /* silent — badge simply won't show */ });
    return () => { dead = true; };
  }, []);
```

Add `useEffect` to the React import at the top:
```tsx
import { useState, useMemo, useEffect, type ReactNode } from "react";
```

Render the banner directly under the domain header block (right before the "Filter controls" div):

```tsx
      {partialHosts > 0 && (
        <div className="flex items-center gap-3 px-5 py-2 bg-amber-50 border-b border-amber-200">
          <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0" />
          <span className="text-[11px] text-amber-900 font-semibold">
            {partialHosts} {partialHosts === 1 ? "host" : "hosts"} reported truncated deep-mesh telemetry —
            some tooling was dropped at collection, so incident counts may be incomplete for those hosts.
          </span>
        </div>
      )}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npx vitest run src/app/pages/MeshThreats.partial.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Typecheck**

Run: `cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/MeshThreats.tsx" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/MeshThreats.partial.test.ts"
git commit -m "feat(fe): surface partial-data badge for truncated deep-mesh telemetry"
```

---

### Task 6: Document the learning

**Files:**
- Modify: `LEARNINGS.md`

- [ ] **Step 1: Append a What/Why entry**

Under a `## 2026-08-12` heading (create it if absent — append-only, never rewrite existing entries), add:

```markdown
- **Mesh Attack Terrain section** — Added a 4th terrain (`/terrain/mesh`, `MeshThreats.tsx`) surfacing `developer_security` (deep-mesh) incidents.
  **What:** Registered `developer_security → mesh` in `terrain_validators.CATEGORY_TO_TERRAIN` + the `settings.py` `VALIDATION_TERRAIN*` mirror, backfilled existing findings out of `origin` in `indexer.py`, and cloned the ExecutionThreats page — but sub-divided by capability (`rule_id` → AL-DEV-00x) instead of `category`, since all deep-mesh findings share one category.
  **Why:** Deep-mesh detections already existed but defaulted into Origin (unmapped category). A dedicated terrain fixes the mislabeling; capability-based chips replace category chips because category is uniform. Chip/KPI counts derive from `rule_id`; chip clicks filter via `initialSearch` (rule titles contain their capability keyword) since `TerrainDetectionPage` has no `rule_id` filter prop.
```

- [ ] **Step 2: Commit**

```bash
git add LEARNINGS.md
git commit -m "docs(learnings): mesh attack terrain section"
```

---

## Self-Review

**Spec coverage:**
- §2/§3 register mesh terrain → Task 1. ✓
- §4 backfill (re-tag out of Origin) → Task 2. ✓
- §4 endpoint param doc → Task 1 Step 5. ✓
- §5 new page + accent/icon/header → Task 3. ✓
- §5 route/nav/_routes → Task 4. ✓
- §6 capability KPIs/chips/columns → Task 3. ✓
- §7 partial-data badge → Task 5. ✓
- §8 tests → Tasks 1,2,3,5 each ship tests. ✓
- LEARNINGS requirement → Task 6. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code; commands have expected output. ✓

**Type consistency:** `capabilityForRule` / `CAPABILITIES` / `Capability` used consistently across Tasks 3 & 5; `countPartialHosts` signature matches its test; `TerrainDetectionPage` props used (`apiUrl, accent, emptyMsg, columns, initialSearch`) all exist in `TerrainPageProps`. ✓

**Known trade-off (documented, not a gap):** capability chip *filtering* uses `initialSearch` keyword matching (chip *counts* are precise via `rule_id`). If precise server-side rule filtering is later wanted, add `rule_id` to `FILTER_FIELDS` + an `initialAdv` prop on `TerrainDetectionPage` — deliberately out of scope here to avoid editing the 4,100-line shared file.
