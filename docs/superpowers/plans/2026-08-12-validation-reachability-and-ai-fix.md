# Validation Pipeline — Reachability Enrichment & AI Verdict Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan was produced with superpowers:systematic-debugging (root cause) + superpowers:writing-plans.

**Goal:** Make the Validated-Findings terrain checklist reflect reality — stop `Package actively running` and `Service reachable` from being structurally 0%, and turn the `AI analyst verdict` into an independent, grounded signal instead of a silent no-op that rubber-stamps KEV.

**Architecture:** Phase 1 is **manager-only**. Introduce a single shared reachability module that joins the agent's *raw telemetry* (`payloads` table: processes / ports / packages sections) — not the `findings` table (alerts only) — to answer "is this vulnerable package running, and is a listening port owned by it?". Wire that one module into all three enrichment sites so they stop disagreeing. Then fix the AI half: resolve the LLM provider through the existing `ai/` provider abstraction (killing the `_get_provider` AttributeError), make provider+model settings-configurable (default `claude-haiku-4-5-20251001`), feed reachability into the prompt, and drop the rubric shortcut that makes the LLM echo KEV. Phase 2 (agent-side authoritative pkg↔proc↔port linkage across macOS/Windows/Linux) is scoped separately and is **out of scope for this plan**.

**Tech Stack:** Python 3.13, asyncio, SQLite/Postgres via the manager's `IntelDB` (`_fetchall`/`_fetchone`), pytest + pytest-asyncio, the manager's `ai/` provider abstraction (`ProviderConfig`, `AIProvider`, `build_provider`, `load_config`).

## Global Constraints

- **No agent changes in this plan.** Phase 1 uses only data the manager already stores. Anything requiring new agent telemetry is deferred to the Phase 2 spec.
- **Reuse existing section constants.** Import `PORT_SECTIONS` from `manager/manager/attacklens/detections/port_listener.py` and `PACKAGE_SECTIONS` from `manager/manager/attacklens/detections/package_vulnerability.py`. Do not re-hardcode section-name lists.
- **All three enrichment sites must agree.** After this plan, `_enrich_cluster` (engine.py:1260), the legacy path (engine.py:1138), and the indexer rescore (indexer.py:3842) must all populate the same cross-layer keys via the same shared function. No divergent inline copies.
- **Fail loud, not silent.** Every place that currently swallows a criterion/AI failure into a 0 or a skip must attach a human-readable reason to `terrain_validation` diagnostics. `except Exception: pass` and bare `log.debug(...)` swallows in the validation path are not acceptable for new code.
- **Backwards compatible defaults.** `validation_pipeline_enabled` and `ai_validation_enabled` stay `False` by default (config.py:32,114). This plan does not flip production behavior; it makes the pipeline correct *when enabled*. Enablement is a deliberate, separate operational decision (Task 9).
- **Model default:** `claude-haiku-4-5-20251001` for the per-cluster verdict (base.py `DEFAULT_MODELS["anthropic"]`). Provider+model overridable via Settings → Validation.
- **Preserve the anchor-floor invariant** in `terrain_validators.evaluate_finding` (KEV/UID-0/etc. → score ≥ 0.80). Do not remove it; the fixes must not regress the "one smoking gun = high confidence" behavior.

---

## Root Cause Analysis (the "why")

Direct code evidence, gathered before any fix (systematic-debugging Phase 1–2).

### R1 — The primary promotion path never computes reachability (wiring gap)
`manager/manager/attacklens/engine.py:1260` `_enrich_cluster()` is the enrichment used by the **live** cluster→finding path (called at engine.py:998). Its returned `enriched` dict (lines 1372–1385) contains `kev_hit`, `epss_scores`, `malicious_ip_hit`, `malicious_hash_hit`, `exploit_available`, `threat_intel_source_count`, `asset_tier`, `host_class`, `compensating_controls`, `cve_ids`, `malicious_ips`, `malicious_hashes` — and **omits** `package_running`, `port_open`, `paired_with_persistence`, `cross_layer_match`, `controls_disabled_count`.

The terrain criteria then fall through to the finding's own evidence:
- `package_running` → `e.get("package_running") or _ev(f).get("running") or _ev(f).get("process_present")` (terrain_validators.py:206)
- `service_reachable` → `e.get("port_open") or _ev(f).get("port") or _ev(f).get("listen")` (terrain_validators.py:213)

A package/vulnerability finding never carries `running`/`port`/`listen` in its own evidence, so both evaluate to `0.0` — **structurally, every time**. This zeroing also hits `persistence_paired` (citadels) and `multi_controls_off` (posture), because those enriched keys are missing too. Only the legacy path (engine.py:1188) and the indexer rescore (indexer.py:3878) populate them at all.

### R2 — Even where computed, the correlation reads the wrong table
The legacy path (engine.py:1143–1168) and the indexer rescore (indexer.py:3842–3868) compute `package_running`/`port_open` by peeking at **sibling `findings`** on the same agent. But `findings` are *alerts* — benign running processes and benign listening ports are never emitted as findings. So the peek almost always returns nothing → `0%`. Two further defects:
- `package_running` requires a `process`-category finding whose evidence substring-contains `ev.get("name")` (the package name). Wrong key for many SCA findings, and naive substring fails for bundled/renamed binaries (e.g. `libwebp` inside `Google Chrome`).
- `port_open` fires on **any** `port` finding on the host (engine.py:1164 / indexer.py:3856) — it never checks the port belongs to the vulnerable package, directly contradicting its own description ("port belonging to the vulnerable package"). Both under- and over-triggers.

**The authoritative data exists** in the `payloads` table (`manager/manager/db.py:60`): raw agent sections `processes`, ports (`PORT_SECTIONS`), and packages (`PACKAGE_SECTIONS`) with `pid`/`exe`/`process_name`/`bind_ip`. The code just never reads it for reachability.

### R3 — The AI verdict path throws and abstains silently (integration regression)
`ai_validator.py:448` calls `ai_analyst._get_provider()`. `server.py:425` attaches an `AIAnalyst` (ai_analyst.py) — which has **no** `_get_provider` method (only `FindingAnalyzer`/`InvestigationGraph` do). So `_ai_evaluate_cluster` raises `AttributeError`, caught at ai_validator.py:126 → `ai_error="llm_error:AttributeError"`, `ai_verdict=None` → AI abstains. In the live cluster path the "senior SOC analyst" LLM **never actually runs**; the system quietly degrades to deterministic factors and the failure is only a `log.warning`.

### R4 — When it does run, the AI double-counts KEV/EPSS and is blind to reachability
The prompt rubric (ai_validator.py:520–528) instructs `tp, confidence ≥ 0.9` whenever KEV / malicious-hash / 3-layer is present. But KEV/EPSS/exploit already drive the deterministic criteria `kev_listed` (0.25 + anchor floor), `epss_high` (0.15), `public_exploit` (0.15). So the AI at weight 0.10 restates the same feeds rather than adding orthogonal judgment; `_ai_score` maps `tp`→`max(0.5, conf)`, so a KEV vuln yields ~100% AI — a rubber-stamp. Worse, `_build_ai_prompt`'s `enrich_summary` (ai_validator.py:492–505) omits `package_running`/`port_open`, so even a working LLM cannot reason about the single most decision-relevant fact for a vuln finding: is it actually reachable/loaded?

### R5 — Silent degradation everywhere masks the "why"
`validation_pipeline_enabled` and `ai_validation_enabled` default `False` (config.py:32,114). Criterion exceptions are counted as `0` (terrain_validators.py:561–563), AI errors become a warning, enrichment errors are `log.debug` swallows (engine.py:1176). The analyst sees `0%` / `100%` with no explanation of whether it's "genuinely not met" vs "no telemetry available" vs "LLM never ran". The checklist looks authoritative while being partly inoperative.

**Net effect the user observed:** `Package actively running 0%` and `Service reachable 0%` (R1 + R2), `AI analyst verdict 100%` (R4, and/or a stored verdict since R3 blocks fresh ones), while the KEV anchor floor still pushes the overall percentage over threshold — so the finding "passes" while its checklist is visibly broken.

---

## Solution Overview (maps to the three chosen directions)

1. **Reachability — phased, manager-first.** New `attacklens/reachability.py` reads the latest `payloads` for `processes` / ports / packages, builds a real `package ↔ process ↔ listening-port` join, and returns the cross-layer flags. One shared entry point wired into all three enrichment sites. Historical findings backfilled via the indexer rescore.
2. **AI — rewire + ground on reachability.** Validator resolves its provider via the `ai/` abstraction (`load_config`/`build_provider`), injectable for tests (kills R3). Prompt gains reachability + running/listening context and drops the KEV→0.9 shortcut (fixes R4). Errors surface as diagnostics (fixes R5 for AI).
3. **Model/provider — configurable in Settings.** New `validation_ai_provider` / `validation_ai_model` org-settings keys, resolved in `ai_validator`, exposed in Settings → Validation, default `claude-haiku-4-5-20251001`.

---

## File Structure

**Create**
- `manager/manager/attacklens/reachability.py` — shared reachability join over raw payloads. Single responsibility: given `(idb, agent_id, finding/pkg identity)`, return `{package_running, port_open, running_matches, listening_matches, diagnostics}`.
- `tests/unit/test_reachability.py` — unit tests for the join (matching, negatives, missing-payload diagnostics).
- `tests/unit/test_terrain_reachability_wiring.py` — asserts all three enrichment sites populate the flags identically.
- `tests/unit/test_ai_provider_resolution.py` — asserts the validator resolves a provider without an `AIAnalyst._get_provider` and abstains cleanly when unconfigured.
- `docs/superpowers/plans/2026-08-12-validation-reachability-and-ai-fix.md` — this plan.

**Modify**
- `manager/manager/attacklens/engine.py` — `_enrich_cluster` (~1372) and legacy enrichment (~1138) call the shared reachability function.
- `manager/manager/indexer.py` — rescore path (~3842) calls the shared reachability function; remove the inline sibling-finding peek.
- `manager/manager/attacklens/terrain_validators.py` — `package_running`/`service_reachable` evaluators consume the new flags; add per-criterion `reason`; keep anchor floor intact.
- `manager/manager/attacklens/ai_validator.py` — provider resolution via `ai/` abstraction; settings-driven provider/model; reachability in the prompt; drop KEV→0.9 rubric line; surface `ai_error`.
- `manager/manager/api/settings.py` — read/write `validation_ai_provider` + `validation_ai_model`.
- `manager/manager/attacklens/config.py` — document the two new settings keys (no default behavior change).
- `LEARNINGS.md` — append the reachability-from-payloads pattern and the provider-abstraction fix.

---

### Task 1: Shared reachability module (payloads-based join)

**Files:**
- Create: `manager/manager/attacklens/reachability.py`
- Test: `tests/unit/test_reachability.py`

**Interfaces:**
- Consumes: `idb` with `async _fetchall(sql, params)`; the `payloads` table `(agent_id, section, collected_at, data)`; `PORT_SECTIONS` (port_listener.py), `PACKAGE_SECTIONS` (package_vulnerability.py).
- Produces:
  - `def canonical_name(s: str) -> str` — lowercased basename without version/arch/extension suffixes.
  - `async def compute_reachability(idb, agent_id: str, package_name: str, installed_paths: list[str] | None = None) -> dict` returning:
    ```python
    {
      "package_running": bool,
      "port_open": bool,
      "running_matches": list[dict],   # [{"pid","exe","name"}]
      "listening_matches": list[dict], # [{"port","bind_ip","pid","process_name"}]
      "diagnostics": dict,             # {"processes_seen":int,"ports_seen":int,"reason":str}
    }
    ```

- [ ] **Step 1: Confirm the real section names (evidence, not guessing)**

Run:
```bash
python - <<'PY'
from manager.manager.attacklens.detections.port_listener import PORT_SECTIONS
from manager.manager.attacklens.detections.package_vulnerability import PACKAGE_SECTIONS
print("PORT_SECTIONS:", sorted(PORT_SECTIONS))
print("PACKAGE_SECTIONS:", sorted(PACKAGE_SECTIONS))
PY
```
Expected: prints the frozensets (e.g. PORT_SECTIONS includes `ports`/`listening_ports`/`network`; PACKAGE_SECTIONS includes `packages`/`sbom`/`sca`). Record the printed values — the module imports these constants, so no hardcoding is needed. Process section is `processes`.

- [ ] **Step 2: Write the failing test**

```python
# tests/unit/test_reachability.py
import json
import pytest
from manager.manager.attacklens import reachability as R


class FakeIDB:
    """Minimal IntelDB stub returning canned latest-payload rows."""
    def __init__(self, payloads_by_section: dict[str, dict]):
        self._by_section = payloads_by_section  # {section: parsed_data_dict}

    async def _fetchall(self, sql, params):
        # compute_reachability asks for the latest row of a given section
        section = params[1]
        data = self._by_section.get(section)
        return [{"data": json.dumps(data)}] if data is not None else []


def test_canonical_name_strips_version_and_arch():
    assert R.canonical_name("openssl-3.0.11-1.el9.x86_64") == "openssl"
    assert R.canonical_name("/usr/bin/nginx") == "nginx"
    assert R.canonical_name("Python.framework/Versions/3.11/python3") == "python3"


@pytest.mark.asyncio
async def test_running_and_reachable_true_when_process_and_port_owned_by_package():
    idb = FakeIDB({
        "processes": {"processes": [
            {"pid": 42, "exe": "/usr/sbin/nginx", "name": "nginx"},
        ]},
        "ports": {"ports": [
            {"port": 443, "bind_ip": "0.0.0.0", "pid": 42, "process_name": "nginx"},
        ]},
    })
    out = await R.compute_reachability(idb, "agentA", "nginx")
    assert out["package_running"] is True
    assert out["port_open"] is True
    assert out["listening_matches"][0]["port"] == 443
    assert "reason" in out["diagnostics"]


@pytest.mark.asyncio
async def test_port_open_false_when_listening_port_owned_by_other_process():
    idb = FakeIDB({
        "processes": {"processes": [{"pid": 9, "exe": "/usr/bin/curl", "name": "curl"}]},
        "ports": {"ports": [{"port": 22, "bind_ip": "0.0.0.0", "pid": 1, "process_name": "sshd"}]},
    })
    out = await R.compute_reachability(idb, "agentA", "curl")
    assert out["package_running"] is True     # curl process is running
    assert out["port_open"] is False          # but the listening port is sshd's, not curl's


@pytest.mark.asyncio
async def test_missing_payloads_reports_diagnostic_reason():
    idb = FakeIDB({})  # no processes/ports payloads at all
    out = await R.compute_reachability(idb, "ghost", "openssl")
    assert out["package_running"] is False
    assert out["port_open"] is False
    assert out["diagnostics"]["processes_seen"] == 0
    assert "no process telemetry" in out["diagnostics"]["reason"].lower()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_reachability.py -v`
Expected: FAIL — `AttributeError: module 'reachability' has no attribute 'canonical_name'` / `compute_reachability`.

- [ ] **Step 4: Write the implementation**

```python
# manager/manager/attacklens/reachability.py
"""
manager/manager/attacklens/reachability.py — package ↔ process ↔ port join.

Answers, for a vulnerable package on one agent:
  • package_running — is a process backed by this package currently running?
  • port_open       — is there a LISTENING port whose owning process is this package?

Source of truth is the raw `payloads` table (processes / ports / packages
sections), NOT the findings table. Findings are alerts; benign running
processes and benign listening ports are never findings, which is exactly why
the old sibling-finding peek returned 0% for real vuln findings.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Optional

from .detections.port_listener import PORT_SECTIONS
from .detections.package_vulnerability import PACKAGE_SECTIONS

log = logging.getLogger("manager.attacklens.reachability")

PROCESS_SECTIONS: frozenset[str] = frozenset({"processes"})

_VERSION_SUFFIX = re.compile(r"[-_.]\d[\w.+~]*$")   # trailing version/arch chunk
_EXT = re.compile(r"\.(exe|app|framework|dylib|so|dll)$", re.I)


def canonical_name(s: str) -> str:
    """Lowercased basename with version/arch/extension noise stripped."""
    if not s:
        return ""
    base = os.path.basename(str(s).strip().replace("\\", "/"))
    base = _EXT.sub("", base)
    prev = None
    while base != prev:                 # strip repeated version tails
        prev = base
        base = _VERSION_SUFFIX.sub("", base)
    return base.lower()


async def _latest_section(idb, agent_id: str, sections: frozenset[str]) -> list[dict]:
    """Return parsed rows from the most recent payload across candidate sections."""
    rows: list[dict] = []
    for section in sections:
        try:
            got = await idb._fetchall(
                "SELECT data FROM payloads WHERE agent_id=? AND section=? "
                "ORDER BY collected_at DESC LIMIT 1",
                (agent_id, section),
            )
        except Exception as exc:
            log.debug("payload fetch failed agent=%s section=%s: %s", agent_id, section, exc)
            got = []
        for r in got:
            try:
                data = json.loads(r["data"]) if isinstance(r["data"], str) else (r["data"] or {})
            except (json.JSONDecodeError, TypeError):
                continue
            # tolerate {"processes":[...]} / {"ports":[...]} / bare list shapes
            if isinstance(data, dict):
                for v in data.values():
                    if isinstance(v, list):
                        rows.extend(x for x in v if isinstance(x, dict))
            elif isinstance(data, list):
                rows.extend(x for x in data if isinstance(x, dict))
    return rows


def _proc_names(proc: dict) -> set[str]:
    return {canonical_name(proc.get("name") or ""),
            canonical_name(proc.get("exe") or proc.get("path") or "")} - {""}


async def compute_reachability(
    idb,
    agent_id: str,
    package_name: str,
    installed_paths: Optional[list[str]] = None,
) -> dict:
    pkg = canonical_name(package_name)
    path_names = {canonical_name(p) for p in (installed_paths or [])} - {""}
    targets = ({pkg} | path_names) - {""}

    procs = await _latest_section(idb, agent_id, PROCESS_SECTIONS)
    ports = await _latest_section(idb, agent_id, PORT_SECTIONS)

    running_matches: list[dict] = []
    running_pids: set[Any] = set()
    for p in procs:
        if targets & _proc_names(p):
            running_matches.append({"pid": p.get("pid"),
                                    "exe": p.get("exe") or p.get("path") or "",
                                    "name": p.get("name") or ""})
            if p.get("pid") is not None:
                running_pids.add(str(p.get("pid")))

    listening_matches: list[dict] = []
    for e in ports:
        state = str(e.get("state") or e.get("status") or "").upper()
        is_listen = ("LISTEN" in state) or bool(e.get("listening")) or (state == "")
        if not is_listen:
            continue
        owner = {canonical_name(e.get("process_name") or ""),
                 canonical_name(e.get("exe") or "")} - {""}
        pid_match = str(e.get("pid")) in running_pids if e.get("pid") is not None else False
        if (targets & owner) or pid_match:
            listening_matches.append({"port": e.get("port") or e.get("local_port"),
                                      "bind_ip": e.get("bind_ip") or e.get("addr") or "",
                                      "pid": e.get("pid"),
                                      "process_name": e.get("process_name") or ""})

    if not procs:
        reason = "no process telemetry in latest payload for this agent"
    elif not running_matches:
        reason = f"package '{pkg}' not found among {len(procs)} running processes"
    elif not listening_matches:
        reason = f"'{pkg}' running (pid {sorted(running_pids)}) but owns no listening port"
    else:
        reason = f"'{pkg}' running and reachable on {[m['port'] for m in listening_matches]}"

    return {
        "package_running": bool(running_matches),
        "port_open": bool(listening_matches),
        "running_matches": running_matches,
        "listening_matches": listening_matches,
        "diagnostics": {"processes_seen": len(procs), "ports_seen": len(ports), "reason": reason},
    }
```

- [ ] **Step 5: Run the tests and make sure they pass**

Run: `python -m pytest tests/unit/test_reachability.py -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add manager/manager/attacklens/reachability.py tests/unit/test_reachability.py
git commit -m "feat(validation): payloads-based package↔process↔port reachability join

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Wire reachability into the primary cluster path (`_enrich_cluster`)

**Files:**
- Modify: `manager/manager/attacklens/engine.py:1372-1385` (the `enriched = {...}` in `_enrich_cluster`)
- Test: `tests/unit/test_terrain_reachability_wiring.py`

**Interfaces:**
- Consumes: `compute_reachability` (Task 1); the cluster's primary package identity (`cluster.entity_key` and the primary signal's evidence `name`).
- Produces: `_enrich_cluster` now returns an `enriched` dict that additionally contains `package_running`, `port_open`, and echoes `reachability_diagnostics`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_terrain_reachability_wiring.py
import json
import pytest


class _Sig:
    def __init__(self, evidence, data_point="packages", rule_id="r", layer="surface"):
        self.evidence = evidence
        self.data_point = data_point
        self.rule_id = rule_id
        self.layer = layer
        self.strength = 0.9
        self.weight = 0.9
        self.severity_hint = "high"
        self.entity_key = evidence.get("name", "pkg")


class _Cluster:
    def __init__(self, agent_id, signals):
        self.agent_id = agent_id
        self.signals = signals
        self.entity_key = signals[0].entity_key
        self.layers_covered = {"surface"}
        self.confidence = 0.9
        self.id = 1


@pytest.mark.asyncio
async def test_enrich_cluster_populates_reachability(engine_with_payloads):
    engine, _ = engine_with_payloads   # fixture: agent has nginx proc + :443 listener
    cluster = _Cluster("agentA", [_Sig({"name": "nginx", "cve_id": "CVE-2024-0001"})])
    enriched = await engine._enrich_cluster(cluster)
    assert enriched["package_running"] is True
    assert enriched["port_open"] is True
    assert "reachability_diagnostics" in enriched
```

Add the `engine_with_payloads` fixture in `tests/unit/conftest.py` (or top of this file) that builds an `AttackLensEngine` with a stub `IntelDB` whose `_fetchall` returns the nginx `processes` + `:443` `ports` payloads, mirroring the FakeIDB in Task 1. Reuse the FakeIDB pattern; expose it as `engine._idb`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_terrain_reachability_wiring.py::test_enrich_cluster_populates_reachability -v`
Expected: FAIL — `KeyError: 'package_running'` (key absent from `_enrich_cluster` output).

- [ ] **Step 3: Implement — add reachability to `_enrich_cluster`**

In `engine.py`, inside `_enrich_cluster`, immediately before `enriched = {` (currently line ~1372), add:

```python
        # Reachability: join raw processes/ports payloads to decide whether the
        # vulnerable package is actually running and whether a listening port is
        # owned by it. Uses the payloads table (full inventory), not findings.
        from .reachability import compute_reachability
        pkg_name = ""
        for s in cluster.signals:
            pkg_name = (s.evidence or {}).get("name") or (s.evidence or {}).get("package") or ""
            if pkg_name:
                break
        try:
            reach = await compute_reachability(self._idb, cluster.agent_id, str(pkg_name))
        except Exception as exc:
            log.warning("reachability failed agent=%s: %s", cluster.agent_id, exc)
            reach = {"package_running": False, "port_open": False,
                     "diagnostics": {"reason": f"reachability error: {exc}"}}
```

Then add these keys to the `enriched = {` dict literal:

```python
            "package_running":           reach["package_running"],
            "port_open":                 reach["port_open"],
            "reachability_diagnostics":  reach["diagnostics"],
```

- [ ] **Step 4: Run the test and make sure it passes**

Run: `python -m pytest tests/unit/test_terrain_reachability_wiring.py::test_enrich_cluster_populates_reachability -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add manager/manager/attacklens/engine.py tests/unit/test_terrain_reachability_wiring.py tests/unit/conftest.py
git commit -m "fix(validation): populate reachability in primary _enrich_cluster path

Closes the wiring gap where package_running/port_open were structurally 0% in
the live promotion path (R1).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Unify the legacy + indexer enrichment on the shared function

**Files:**
- Modify: `manager/manager/attacklens/engine.py:1143-1168` (legacy sibling peek)
- Modify: `manager/manager/indexer.py:3842-3868` (rescore sibling peek)
- Test: `tests/unit/test_terrain_reachability_wiring.py` (add cross-path agreement test)

**Interfaces:**
- Consumes: `compute_reachability` (Task 1).
- Produces: identical `package_running`/`port_open` semantics across all three sites; the naive sibling-`process`/`any-port` peek is deleted.

- [ ] **Step 1: Write the failing test (all paths agree)**

```python
@pytest.mark.asyncio
async def test_all_paths_agree_on_reachability(engine_with_payloads):
    """Legacy enrich, cluster enrich, and reachability module must all agree."""
    from manager.manager.attacklens.reachability import compute_reachability
    engine, idb = engine_with_payloads
    direct = await compute_reachability(idb, "agentA", "nginx")
    # legacy path helper is refactored to call compute_reachability, so a finding
    # for nginx must yield the same flags the module returns.
    f = {"agent_id": "agentA", "category": "package",
         "evidence": json.dumps({"name": "nginx"})}
    legacy = await engine._legacy_reachability_for_finding(f)   # thin wrapper added in Step 3
    assert legacy["package_running"] == direct["package_running"] is True
    assert legacy["port_open"] == direct["port_open"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_terrain_reachability_wiring.py::test_all_paths_agree_on_reachability -v`
Expected: FAIL — `AttributeError: ... has no attribute '_legacy_reachability_for_finding'`.

- [ ] **Step 3: Implement — replace both sibling peeks with the shared call**

In `engine.py`, add a small wrapper method on the engine class:

```python
    async def _legacy_reachability_for_finding(self, f: dict) -> dict:
        """Shared reachability for the legacy per-finding path (mirrors _enrich_cluster)."""
        from .reachability import compute_reachability
        ev = f.get("evidence")
        if isinstance(ev, str):
            try:
                ev = json.loads(ev)
            except json.JSONDecodeError:
                ev = {}
        pkg = (ev or {}).get("name") or (ev or {}).get("package") or ""
        return await compute_reachability(self._idb, f.get("agent_id", ""), str(pkg))
```

Then in the legacy enrichment block (engine.py:1143–1168) **delete** the `for row in sibs:` loop that sets `package_running`/`port_open` from sibling findings, and replace the two assignments feeding the enriched dict with:

```python
        _reach = await self._legacy_reachability_for_finding(f)
        package_running = _reach["package_running"]
        port_open = _reach["port_open"]
```

Keep the `paired_persist`/`controls_off` sibling logic (those are persistence/security findings, which legitimately *are* alerts). In `indexer.py:3842–3868`, do the same: delete the `for s in sibs:` branches that set `port_open`/`package_running`, and set them from `compute_reachability(self, agent_id, pkg_name)` (the indexer's `self` is the IntelDB, so pass `self`). Leave the persistence/security sibling branches as-is.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/unit/test_terrain_reachability_wiring.py -v`
Expected: PASS (all wiring tests).

- [ ] **Step 5: Commit**

```bash
git add manager/manager/attacklens/engine.py manager/manager/indexer.py tests/unit/test_terrain_reachability_wiring.py
git commit -m "refactor(validation): unify all enrichment sites on payloads reachability (R2)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Fix terrain criteria semantics + per-criterion diagnostics

**Files:**
- Modify: `manager/manager/attacklens/terrain_validators.py:200-214` (evaluators) and `:589-599` (item dict)
- Test: `tests/unit/test_validation_accuracy.py` (extend the existing file)

**Interfaces:**
- Consumes: `enriched["package_running"]`, `enriched["port_open"]`, `enriched.get("reachability_diagnostics")`.
- Produces: each returned criterion item gains a `reason: str`; `service_reachable` no longer credits an unrelated port.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_validation_accuracy.py  (append)
from manager.manager.attacklens.terrain_validators import evaluate_finding


def test_service_reachable_requires_package_owned_port():
    f = {"category": "package", "cvss_score": 9.1,
         "evidence": {"name": "nginx"}, "cve_ids": ["CVE-2024-0001"]}
    # port_open False → criterion not met, with an explanatory reason
    tv = evaluate_finding(f, {"package_running": True, "port_open": False,
                              "reachability_diagnostics": {"reason": "owns no listening port"}})
    reach = next(c for c in tv["criteria"] if c["name"] == "service_reachable")
    assert reach["met"] == 0.0
    assert "listening port" in reach["reason"].lower()

    tv2 = evaluate_finding(f, {"package_running": True, "port_open": True,
                               "reachability_diagnostics": {"reason": "reachable on [443]"}})
    reach2 = next(c for c in tv2["criteria"] if c["name"] == "service_reachable")
    assert reach2["met"] == 1.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_validation_accuracy.py::test_service_reachable_requires_package_owned_port -v`
Expected: FAIL — `KeyError: 'reason'` (criteria items have no `reason` yet).

- [ ] **Step 3: Implement — reason strings on every criterion**

In `terrain_validators.py`, extend each criterion dict with an optional `reason` callable, defaulting to `None`. In `evaluate_finding`, after computing `met`, compute a reason:

```python
        reason = ""
        if c["name"] in ("package_running", "service_reachable"):
            reason = (enriched.get("reachability_diagnostics") or {}).get("reason", "")
        elif c["name"] == "ai_verdict_tp":
            reason = (ai_verdict or {}).get("reasoning", "") if isinstance(ai_verdict, dict) else ""
```

and add `"reason": reason,` to the `items.append({...})` dict (terrain_validators.py:589). The `package_running`/`service_reachable` evaluators already read `e.get("package_running")`/`e.get("port_open")` first (lines 206/213) — that path is now populated, so no evaluator-logic change is required beyond confirming the `enriched` flag wins over the stale evidence fallbacks.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/unit/test_validation_accuracy.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add manager/manager/attacklens/terrain_validators.py tests/unit/test_validation_accuracy.py
git commit -m "feat(validation): per-criterion reason strings + package-owned port semantics

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Backfill historical findings via rescore

**Files:**
- Modify: `manager/manager/indexer.py:3780-3919` (the rescore function — verify it now emits non-zero reachability)
- Test: `manager/tests/unit/test_stream_detection_integration.py` (add a rescore assertion) or a new `tests/unit/test_rescore_reachability.py`

**Interfaces:**
- Consumes: Task 3 changes (rescore already calls `compute_reachability`).
- Produces: a runnable, idempotent backfill; historical `terrain_validation` blobs get real reachability + reasons.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_rescore_reachability.py
import json, pytest


@pytest.mark.asyncio
async def test_rescore_sets_reachability_from_payloads(indexer_with_payloads):
    idb = indexer_with_payloads   # nginx package finding + nginx proc + :443 payload
    result = await idb.rescore_all_findings(only_unscored=False, limit=100)
    assert result["updated"] >= 1
    row = await idb._fetchone(
        "SELECT terrain_validation FROM findings WHERE item_key='nginx'", ())
    tv = json.loads(row["terrain_validation"])
    reach = next(c for c in tv["criteria"] if c["name"] == "service_reachable")
    assert reach["met"] == 1.0
```

(Use the actual rescore method name found at indexer.py:3780; substitute it for `rescore_all_findings`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_rescore_reachability.py -v`
Expected: FAIL before Task 3 wiring is present in the fixture path (or PASS-through if fixture already includes it — then assert the `reason` field is populated to force the check).

- [ ] **Step 3: Implement**

No new production code if Task 3 is complete; this task confirms the end-to-end backfill. If the rescore path still references removed sibling variables, fix the leftovers. Provide the operator runbook line:

```bash
# One-shot backfill after deploy (dry example — use the real admin entrypoint):
python -m manager.manager.admin rescore --all
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/unit/test_rescore_reachability.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_rescore_reachability.py manager/manager/indexer.py
git commit -m "test(validation): rescore backfills reachability from payloads

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Fix the AI provider disconnect (rewire to the `ai/` abstraction)

**Files:**
- Modify: `manager/manager/attacklens/ai_validator.py:440-476` (`_ai_evaluate_cluster`) and `:88-131` (`validate_with_ai` provider handling)
- Test: `tests/unit/test_ai_provider_resolution.py`

**Interfaces:**
- Consumes: `manager.manager.ai.key_store.load_config`, `manager.manager.ai.providers.build_provider`, `manager.manager.ai.base.AIProvider`.
- Produces: `async def _resolve_validation_provider(idb) -> Optional[AIProvider]` — returns a provider from settings/key-store, or `None` (clean abstain) when unconfigured. `_ai_evaluate_cluster` accepts an explicit `provider` (injectable for tests) instead of calling `ai_analyst._get_provider()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_ai_provider_resolution.py
import pytest
from manager.manager.attacklens import ai_validator as V
from manager.manager.ai.base import AIProvider, AIResponse, ProviderConfig


class FakeProvider(AIProvider):
    def __init__(self):
        self._cfg = ProviderConfig(provider="anthropic", api_key="x", model="claude-haiku-4-5-20251001")
        self._http = None
    async def chat(self, user_prompt, *, max_tokens=1500):
        return AIResponse(text='{"verdict":"tp","confidence":0.72,"reasoning":"reachable + KEV"}',
                          model=self._cfg.model, provider="anthropic")
    async def health_check(self):
        return True, "ok"


class _Sig:
    rule_id="r"; layer="surface"; data_point="packages"; strength=0.9; weight=0.9
    severity_hint="high"; entity_key="nginx"; evidence={"name":"nginx"}


class _Cluster:
    agent_id="agentA"; entity_key="nginx"; layers_covered={"surface"}
    signals=[_Sig()]; confidence=0.9


@pytest.mark.asyncio
async def test_evaluate_cluster_uses_injected_provider_no_get_provider_needed():
    v = await V._ai_evaluate_cluster(_Cluster(), {"kev_hit": True}, provider=FakeProvider())
    assert v.label == "tp"
    assert 0.7 <= v.confidence <= 0.75
    assert v.used_llm is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_provider_resolution.py -v`
Expected: FAIL — `_ai_evaluate_cluster()` currently takes `ai_analyst` and calls `ai_analyst._get_provider()`; the `provider=` kwarg does not exist.

- [ ] **Step 3: Implement**

Change `_ai_evaluate_cluster` signature and body:

```python
async def _ai_evaluate_cluster(cluster, enriched: dict, provider) -> AiVerdict:
    from ..ai.base import AIProvider
    prompt = _build_ai_prompt(cluster, enriched)
    resp, _used = await _chat_with_fallback(provider, prompt, 900, None)
    parsed = AIProvider.parse_json(resp.text) if resp.text.strip() else {}
    # ... rest unchanged ...
```

Add the resolver and update `validate_with_ai` to use it (keeping the `ai_analyst` parameter for backward-compat but no longer calling `_get_provider` on it):

```python
async def _resolve_validation_provider(idb):
    """Resolve the LLM provider for the per-cluster verdict via the ai/ abstraction."""
    from ..ai.key_store import load_config
    from ..ai.providers import build_provider
    from ..ai.base import ProviderConfig, DEFAULT_MODELS
    settings = await _load_validation_settings(idb)
    prov = settings.get("ai_provider")
    model = settings.get("ai_model")
    cfg = load_config()                      # customer-configured key store
    if cfg is None:
        return None                          # unconfigured → clean abstain
    if prov:                                 # settings override provider/model
        cfg = ProviderConfig(provider=prov, api_key=cfg.api_key if cfg.provider == prov else "",
                             model=model or DEFAULT_MODELS.get(prov, ""))
        if not cfg.api_key:
            return None
    return build_provider(cfg)
```

In `validate_with_ai`, replace the `_ai_evaluate_cluster(cluster, enriched, ai_analyst)` call with:

```python
        provider = await _resolve_validation_provider(idb)
        if provider is None:
            ai_error = "no_provider_configured"
        else:
            try:
                ai_verdict = await _ai_evaluate_cluster(cluster, enriched, provider)
            except asyncio.TimeoutError:
                ai_error = "llm_timeout"
            except Exception as exc:
                ai_error = f"llm_error:{type(exc).__name__}"
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/unit/test_ai_provider_resolution.py tests/unit/test_ai_validator.py -v`
Expected: PASS (new test passes; existing `test_ai_validator.py` still green — adjust its call sites if they invoked `_ai_evaluate_cluster` with an analyst).

- [ ] **Step 5: Commit**

```bash
git add manager/manager/attacklens/ai_validator.py tests/unit/test_ai_provider_resolution.py
git commit -m "fix(validation): resolve LLM provider via ai/ abstraction (kills _get_provider AttributeError, R3)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Settings-configurable provider + model

**Files:**
- Modify: `manager/manager/attacklens/ai_validator.py:624-683` (`_load_validation_settings` — add two keys)
- Modify: `manager/manager/api/settings.py` (accept/return `validation_ai_provider`, `validation_ai_model`)
- Modify: `manager/manager/attacklens/config.py` (document keys)
- Test: `tests/unit/test_ai_validator.py` (settings resolution)

**Interfaces:**
- Consumes: `org_settings` rows `validation_ai_provider`, `validation_ai_model`.
- Produces: `_load_validation_settings` result gains `ai_provider: str|None`, `ai_model: str|None`; consumed by `_resolve_validation_provider` (Task 6).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_ai_validator.py  (append)
import pytest
from manager.manager.attacklens import ai_validator as V


class KVDB:
    def __init__(self, kv): self._kv = kv
    async def _fetchall(self, sql, params):
        return [{"key": k, "value": v} for k, v in self._kv.items()]


@pytest.mark.asyncio
async def test_validation_settings_expose_provider_and_model():
    V.invalidate_validation_settings_cache()
    idb = KVDB({"validation_ai_provider": "anthropic",
                "validation_ai_model": "claude-haiku-4-5-20251001"})
    s = await V._load_validation_settings(idb)
    assert s["ai_provider"] == "anthropic"
    assert s["ai_model"] == "claude-haiku-4-5-20251001"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_validator.py::test_validation_settings_expose_provider_and_model -v`
Expected: FAIL — `KeyError: 'ai_provider'`.

- [ ] **Step 3: Implement**

In `_load_validation_settings`, add the two keys to the `SELECT ... WHERE key IN (...)` list and to the returned `data` dict:

```python
        "ai_provider": kv.get("validation_ai_provider") or None,
        "ai_model":    kv.get("validation_ai_model") or None,
```

In `api/settings.py`, add both keys to the allowed validation-settings whitelist for GET/PUT (follow the existing `validation_global_threshold` handling), and call `invalidate_validation_settings_cache()` on PUT so changes propagate immediately. In `config.py`, add a comment block documenting the two keys and the `claude-haiku-4-5-20251001` default.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/unit/test_ai_validator.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add manager/manager/attacklens/ai_validator.py manager/manager/api/settings.py manager/manager/attacklens/config.py tests/unit/test_ai_validator.py
git commit -m "feat(validation): settings-configurable verdict provider/model (default claude-haiku-4-5)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Ground the AI prompt on reachability + drop the KEV→0.9 shortcut

**Files:**
- Modify: `manager/manager/attacklens/ai_validator.py:479-543` (`_build_ai_prompt`) and `:520-528` (rubric)
- Test: `tests/unit/test_ai_validator.py` (prompt-content assertions)

**Interfaces:**
- Consumes: `enriched["package_running"]`, `enriched["port_open"]`, `enriched.get("reachability_diagnostics")`.
- Produces: the prompt's `enrich_summary` includes reachability; the rubric no longer forces `confidence ≥ 0.9` purely from KEV/hash.

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_prompt_includes_reachability_and_no_kev_conf_shortcut():
    from manager.manager.attacklens.ai_validator import _build_ai_prompt

    class _S:  rule_id="r"; layer="surface"; data_point="packages"; strength=0.9
    _S.weight=0.9; _S.severity_hint="high"; _S.entity_key="nginx"; _S.evidence={"name":"nginx"}
    class _C:  agent_id="a"; entity_key="nginx"; layers_covered={"surface"}; signals=[_S()]; confidence=0.9

    prompt = _build_ai_prompt(_C(), {"kev_hit": True, "package_running": True,
                                     "port_open": False,
                                     "reachability_diagnostics": {"reason": "owns no listening port"}})
    assert "package_running" in prompt
    assert "port_open" in prompt or "reachable" in prompt.lower()
    # The rubric must NOT hard-wire confidence to KEV alone:
    assert "confidence ≥ 0.9" not in prompt
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_validator.py::test_prompt_includes_reachability_and_no_kev_conf_shortcut -v`
Expected: FAIL — reachability keys absent from prompt; `confidence ≥ 0.9` present.

- [ ] **Step 3: Implement**

In `_build_ai_prompt`, add reachability to `enrich_summary`:

```python
        "package_running":            enriched.get("package_running"),
        "port_open":                  enriched.get("port_open"),
        "reachability":               (enriched.get("reachability_diagnostics") or {}).get("reason"),
```

Wrap untrusted finding-derived fields in `<untrusted>…</untrusted>` (base.py `SYSTEM_PROMPT` already instructs the model to treat those as data). Replace the rubric block so KEV establishes *ground truth of exploitability in the wild* but the model must weigh **reachability** for confidence:

```
Decision rubric (apply in order; reachability drives confidence):
  1. KEV-listed CVE or malicious-hash present → this is a real, known-exploited
     issue. If the package is also running AND a listening port is owned by it
     → tp with high confidence. If installed but NOT running/reachable → tp but
     temper confidence (0.55–0.7) and say so in reasoning.
  2. Three layers (surface+exposure+execution) covered → tp.
  3. Surface-only, not running, no KEV/hash/EPSS≥0.7 → fp.
  4. Sanctioned pattern (pentest box, monitoring agent) → fp, cite indicators.
  5. Otherwise → uncertain.
Judge reachability independently — do not restate the KEV/EPSS feeds as your verdict.
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/unit/test_ai_validator.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add manager/manager/attacklens/ai_validator.py tests/unit/test_ai_validator.py
git commit -m "fix(validation): ground AI verdict on reachability, drop KEV→0.9 shortcut (R4)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: Surface AI/enrichment diagnostics + enablement runbook

**Files:**
- Modify: `manager/manager/attacklens/engine.py:1460-1497` (stamp `ai_error`/diagnostics onto the finding) and `manager/manager/attacklens/terrain_validators.py:613-623` (include diagnostics in the result)
- Modify: `LEARNINGS.md`, `docs/architecture.md` (validation section)
- Test: `tests/unit/test_validation_accuracy.py` (diagnostics surfaced)

**Interfaces:**
- Consumes: `PrecisionResult.ai_error` (ai_validator.py), `reachability_diagnostics`.
- Produces: `terrain_validation` blob carries a top-level `diagnostics` object; findings show *why* a criterion is met/not-met/skipped.

- [ ] **Step 1: Write the failing test**

```python
def test_terrain_validation_surfaces_diagnostics():
    from manager.manager.attacklens.terrain_validators import evaluate_finding
    tv = evaluate_finding(
        {"category": "package", "cvss_score": 9.1, "evidence": {"name": "nginx"}},
        {"package_running": False, "port_open": False,
         "reachability_diagnostics": {"reason": "no process telemetry", "processes_seen": 0}},
    )
    assert tv["diagnostics"]["reachability"]["reason"] == "no process telemetry"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_validation_accuracy.py::test_terrain_validation_surfaces_diagnostics -v`
Expected: FAIL — result has no top-level `diagnostics`.

- [ ] **Step 3: Implement**

In `evaluate_finding`'s returned dict (terrain_validators.py:613), add:

```python
        "diagnostics": {"reachability": enriched.get("reachability_diagnostics") or {}},
```

In `engine.py` where the finding is stamped (around 1460), when `precision is not None and precision.ai_error`, add `f["terrain_validation"]["diagnostics"]["ai_error"] = precision.ai_error` after `evaluate_finding` returns. Append the pattern to `LEARNINGS.md` under today's date (per project rule): the payloads-based reachability join and the provider-abstraction fix. Add an operator note: to actually gate on this, set `ATTACKLENS_VALIDATION=true` and `ATTACKLENS_AI_VALIDATION=true` and configure a provider via `POST /api/v1/ai/provider`.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/unit/ -k "validation or reachability or ai_" -v`
Expected: PASS (full validation suite green).

- [ ] **Step 5: Commit**

```bash
git add manager/manager/attacklens/terrain_validators.py manager/manager/attacklens/engine.py LEARNINGS.md docs/architecture.md tests/unit/test_validation_accuracy.py
git commit -m "feat(validation): surface reachability + ai_error diagnostics; document enablement (R5)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Verification (whole-plan)

Run the full affected suite and confirm green before claiming done (superpowers:verification-before-completion):

```bash
python -m pytest tests/unit/test_reachability.py \
                 tests/unit/test_terrain_reachability_wiring.py \
                 tests/unit/test_validation_accuracy.py \
                 tests/unit/test_ai_provider_resolution.py \
                 tests/unit/test_ai_validator.py \
                 tests/unit/test_rescore_reachability.py -v
```
Expected: all PASS. Then manually re-open one Origin (package/CVE) finding in Validated Findings and confirm: `Package actively running` and `Service reachable` reflect real payload state with a hover reason, and `AI analyst verdict` shows a confidence that tracks reachability (not a flat 100% on KEV alone).

## Self-Review notes (author)

- **Spec coverage:** R1→Tasks 2–3; R2→Tasks 1,3; R3→Task 6; R4→Task 8; R5→Tasks 4,9; model-config choice→Task 7; phased/manager-first choice→Phase 1 only (Phase 2 explicitly deferred). ✅
- **Type consistency:** `compute_reachability` return keys (`package_running`, `port_open`, `diagnostics.reason`, `running_matches`, `listening_matches`) are used verbatim in Tasks 2–5, 8–9. `_resolve_validation_provider`/`_ai_evaluate_cluster(provider=…)` consistent across Tasks 6–8. ✅
- **Placeholder scan:** section names are resolved by importing existing frozensets (Task 1 Step 1), not guessed; the rescore method name and admin entrypoint are flagged to be substituted with the real symbols found at indexer.py:3780. Confirm those two names during execution.
- **Open confirmations for the executor (do these in-task, don't assume):** (a) exact `PORT_SECTIONS`/`PACKAGE_SECTIONS` contents; (b) the rescore method's real name/signature at indexer.py:3780; (c) whether `port_listener` payload entries expose `state`/`listening` so the LISTEN filter in Task 1 is accurate — if not, treat all entries in `PORT_SECTIONS` as listeners (they already are, by that module's contract).

## Out of scope (Phase 2 — separate spec)

Agent-side authoritative linkage: SCA emits package→installed-files, process collector emits pid→exe→loaded-libs, network collector emits listen-port→pid, across macOS/Windows/Linux; manager consumes an explicit join instead of inferring from payload sections. This raises coverage from "telemetry we happen to have" to "complete inventory" and lets reachability be exact rather than best-effort.
