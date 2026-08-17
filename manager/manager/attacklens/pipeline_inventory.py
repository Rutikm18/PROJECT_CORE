"""
manager/manager/attacklens/pipeline_inventory.py — Self-describing inventory of
every validation engine point.

Validation in AttackLens is not one function: a finding passes through payload
schema checks, an allowlist, eight deterministic correlation gates, reachability
enrichment, a per-terrain weighted rubric, an optional LLM verdict under a strict
response contract, threshold resolution, and an append-only decision ledger —
each in a different module, each with its own configuration and its own failure
policy. Answering "why is this finding not validated?" previously meant reading
eight files.

This module is the map. It exists so Settings → Validation Pipeline can list
every stage with its live configuration, what it covers, and how it fails.

Design rule: **derive, never restate.** Gate names come from
``validation._GATES``, criteria come from ``terrain_validators.TERRAIN_CRITERIA``,
factor weights come from ``ai_validator.PRECISION_WEIGHTS``, and failure
behaviour comes from ``validation_error_policy.decide_validation_error``. A gate
added to the engine shows up here automatically; a stage whose description drifts
from its code is a test failure, not a silently stale page.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .config import ENGINE_CONFIG
from .terrain_catalog import all_terrains


# ── Value resolution ─────────────────────────────────────────────────────────

_TRUTHY = {"1", "true", "yes", "on"}


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool = False) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUTHY


@dataclass(frozen=True)
class ConfigKey:
    """One knob that changes a stage's behaviour, plus where it is set."""

    key: str
    source: str           # env | engine_config | settings | constant
    description: str
    resolve: Optional[Callable[[], Any]] = None

    def snapshot(self) -> dict:
        value: Any = None
        error = ""
        if self.resolve is not None:
            try:
                value = self.resolve()
            except Exception as exc:      # a broken probe must not 500 the page
                error = str(exc)[:200]
        return {
            "key": self.key,
            "source": self.source,
            "description": self.description,
            # `settings` keys are resolved by the API layer against the DB;
            # value stays None here so the caller can tell "not yet resolved"
            # from "resolved to null".
            "value": value,
            "error": error,
        }


@dataclass(frozen=True)
class Stage:
    """One validation engine point."""

    id: str
    name: str
    kind: str             # schema|allowlist|gate|enrichment|scoring|model|policy|threshold|ledger|orchestration
    module: str           # repo-relative path, so the UI can point at the source
    purpose: str
    # Which dashboard sections this stage decides. "*" means every terrain.
    covers: tuple[str, ...] = ("*",)
    # Stage name understood by validation_error_policy.decide_validation_error.
    # None means this stage sits outside that policy (it runs before the
    # per-finding decision loop).
    error_policy_stage: Optional[str] = None
    config_keys: tuple[ConfigKey, ...] = ()
    # Named sub-checks, derived from the engine at call time.
    checks: Callable[[], list[dict]] = field(default=lambda: [])

    def snapshot(self) -> dict:
        try:
            checks = self.checks()
        except Exception as exc:
            checks = []
            check_error = str(exc)[:200]
        else:
            check_error = ""
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "module": self.module,
            "purpose": self.purpose,
            "covers": list(self.covers),
            "error_policy": _error_policy_summary(self.error_policy_stage),
            "config": [key.snapshot() for key in self.config_keys],
            "checks": checks,
            "check_count": len(checks),
            "check_error": check_error,
        }


# ── Failure behaviour, read from the real policy ─────────────────────────────

def _error_policy_summary(stage: Optional[str]) -> Optional[dict]:
    """Ask the actual policy how this stage fails, for low and high severity.

    Reading the policy instead of describing it keeps the page honest: change
    validation_error_policy.py and this text changes with it.
    """
    if stage is None:
        return None
    from .validation_error_policy import decide_validation_error

    low = decide_validation_error(stage, "medium", "probe")
    high = decide_validation_error(stage, "critical", "probe")
    authoritative = decide_validation_error(
        stage, "critical", "probe", authoritative_evidence=True,
    )
    return {
        "stage": stage,
        "on_failure_default": {"state": low.state, "action": low.action},
        "on_failure_high_severity": {"state": high.state, "action": high.action},
        "with_authoritative_evidence": {
            "state": authoritative.state, "action": authoritative.action,
        },
        "fails_closed": low.action == "fail_closed",
    }


# ── Check builders (derived from the live engine) ────────────────────────────

def _gate_checks() -> list[dict]:
    """The eight correlation gates, in execution order, from validation._GATES."""
    from .validation import _GATES

    checks = []
    for index, (name, fn) in enumerate(_GATES, start=1):
        doc = (getattr(fn, "__doc__", "") or "").strip()
        # First sentence of the gate's own docstring — the single source of
        # truth for what it enforces.
        summary = " ".join(doc.split())
        checks.append({
            "id": name,
            "order": index,
            "label": name.split("_", 1)[-1].replace("_", " ").title(),
            "description": summary,
            "short_circuits": True,
        })
    return checks


def _terrain_criteria_checks() -> list[dict]:
    """Every terrain rubric with its criteria, weights, and anchor flags."""
    from .terrain_validators import GENERIC_CRITERIA, TERRAIN_CRITERIA

    labels = {definition.id: definition.label for definition in all_terrains()}
    rubrics: list[dict] = []
    sources = list(TERRAIN_CRITERIA.items()) + [("generic", GENERIC_CRITERIA)]
    for terrain_id, criteria in sources:
        items = [
            {
                "name": c["name"],
                "label": c["label"],
                "description": c["description"],
                "weight": round(float(c.get("weight", 0.0)), 3),
                "is_anchor": bool(c.get("anchor")),
            }
            for c in criteria
        ]
        rubrics.append({
            "id": terrain_id,
            "order": len(rubrics) + 1,
            "label": labels.get(terrain_id, terrain_id.title()),
            "description": (
                "Fallback rubric for behavioural and compliance anomalies and "
                "any unmapped terrain."
                if terrain_id == "generic"
                else f"Criteria scored for {labels.get(terrain_id, terrain_id)} findings."
            ),
            "criteria": items,
            "criteria_count": len(items),
            "weight_total": round(sum(item["weight"] for item in items), 3),
            "anchor_count": sum(1 for item in items if item["is_anchor"]),
        })
    return rubrics


def _precision_factor_checks() -> list[dict]:
    """The weighted precision factors behind the AI promotion decision."""
    from .ai_validator import PRECISION_WEIGHTS

    descriptions = {
        "ai_verdict":         "LLM senior-analyst TP/FP call under the strict response contract.",
        "ti_corroboration":   "Independent threat-intel confirmation (KEV, EPSS, malicious IP/hash).",
        "cross_layer":        "Evidence spans more than one telemetry layer.",
        "baseline_anomaly":   "Deviation from the host's learned behavioural baseline.",
        "asset_criticality":  "Crown-jewel and server tiers raise the stakes of the same evidence.",
        "fp_history_damping": "Per-rule, per-host-class false-positive history damps the score.",
    }
    return [
        {
            "id": name,
            "order": index,
            "label": name.replace("_", " ").title(),
            "description": descriptions.get(name, ""),
            "weight": round(float(weight), 3),
        }
        for index, (name, weight) in enumerate(PRECISION_WEIGHTS.items(), start=1)
    ]


def _response_contract_checks() -> list[dict]:
    """Fields the model must return, and the versions pinning the contract."""
    from .validation_model import (
        VALIDATION_JSON_SCHEMA,
        VALIDATION_PROMPT_VERSION,
        VALIDATION_RESPONSE_SCHEMA_VERSION,
    )

    properties = VALIDATION_JSON_SCHEMA.get("properties", {})
    required = set(VALIDATION_JSON_SCHEMA.get("required", []))
    checks = [
        {
            "id": name,
            "order": index,
            "label": name.replace("_", " ").title(),
            "description": (
                f"type={spec.get('type', 'any')}"
                + (f", enum={spec.get('enum')}" if spec.get("enum") else "")
            ),
            "required": name in required,
        }
        for index, (name, spec) in enumerate(properties.items(), start=1)
    ]
    checks.append({
        "id": "versions",
        "order": len(checks) + 1,
        "label": "Contract versions",
        "description": (
            f"prompt={VALIDATION_PROMPT_VERSION}, "
            f"schema={VALIDATION_RESPONSE_SCHEMA_VERSION}, "
            "additionalProperties=False, evidence refs must exist in the prompt"
        ),
        "required": True,
    })
    return checks


def _threshold_checks() -> list[dict]:
    """The resolution order the engine uses to pick a finding's threshold."""
    return [
        {"id": "agent", "order": 1, "label": "Per-agent override",
         "description": "Settings → Validation, per-agent threshold. Most specific; wins outright."},
        {"id": "terrain", "order": 2, "label": "Per-terrain override",
         "description": "Settings → Validation, per-terrain threshold. Used when the agent has none."},
        {"id": "global", "order": 3, "label": "Global threshold",
         "description": "Settings → Validation, global threshold. The fallback for every finding."},
        {"id": "anchor_floor", "order": 4, "label": "Anchor floor",
         "description": (
             "Independent of the threshold: one fully-met anchor criterion floors the "
             "terrain score at 0.80, so a single smoking-gun signal cannot be diluted "
             "by absent secondary evidence."
         )},
    ]


def _ledger_checks() -> list[dict]:
    """What the append-only decision ledger preserves per run."""
    return [
        {"id": "run_uid", "order": 1, "label": "Run identity",
         "description": "run_uid + run_key, unique per (finding, evidence revision)."},
        {"id": "scores", "order": 2, "label": "Score breakdown",
         "description": "model_score, terrain_score, validation_score, threshold_used."},
        {"id": "gate_results", "order": 3, "label": "Gate results",
         "description": "Per-gate outcome JSON — the reason a finding was rejected."},
        {"id": "provenance", "order": 4, "label": "Model provenance",
         "description": "provider, model, generation_id, prompt_version, schema_version."},
        {"id": "cost", "order": 5, "label": "Cost and tokens",
         "description": "tokens_used and cost_usd — the durable spend record."},
        {"id": "error", "order": 6, "label": "Failure detail",
         "description": "error_class and error_message when the run did not complete."},
    ]


# ── The inventory ────────────────────────────────────────────────────────────

_ALL_TERRAINS = tuple(definition.id for definition in all_terrains())


STAGES: tuple[Stage, ...] = (
    Stage(
        id="ingest_schema",
        name="Payload schema validation",
        kind="schema",
        module="manager/manager/api/ingest.py",
        purpose=(
            "First gate on the data itself. Counts per-field gaps in agent payloads so "
            "an empty criterion can be traced to missing telemetry rather than a broken "
            "rule, and optionally rejects incomplete payloads outright."
        ),
        config_keys=(
            ConfigKey(
                "ATTACKLENS_INGEST_STRICT_PAYLOAD", "env",
                "Reject payloads missing required fields with HTTP 422 instead of "
                "accepting them and recording a schema gap.",
                lambda: _env_bool("ATTACKLENS_INGEST_STRICT_PAYLOAD"),
            ),
        ),
    ),
    Stage(
        id="allowlist",
        name="Allowlist suppression",
        kind="allowlist",
        module="manager/manager/attacklens/allowlist.py",
        purpose=(
            "Table-backed and static suppression of known-benign entities. Backs gate "
            "G2 — an allowlist hit ends validation before any scoring runs."
        ),
    ),
    Stage(
        id="correlation_gates",
        name="Deterministic correlation gates",
        kind="gate",
        module="manager/manager/attacklens/validation.py",
        purpose=(
            "Eight sequential gates run against a correlated cluster before it may "
            "become a finding. The first failure short-circuits and is recorded as the "
            "rejection reason."
        ),
        config_keys=(
            ConfigKey(
                "validation_pipeline_enabled", "engine_config",
                "When false the gates score and log but emit findings unconditionally "
                "(shadow mode). Set ATTACKLENS_VALIDATION=true to enforce.",
                lambda: bool(ENGINE_CONFIG.get("validation_pipeline_enabled")),
            ),
            ConfigKey(
                "confidence_threshold", "engine_config",
                "Cluster confidence required to promote to a finding (gate G5 re-checks "
                "this after applying compensating-control penalties).",
                lambda: ENGINE_CONFIG.get("confidence_threshold"),
            ),
            ConfigKey(
                "quality_floor_strength", "engine_config",
                "Default signal-strength floor for gate G7, overridden by the "
                "Settings → Validation minimum strength.",
                lambda: ENGINE_CONFIG.get("quality_floor_strength"),
            ),
            ConfigKey(
                "active_finding_dedup_hours", "engine_config",
                "Window in which a second finding for the same cluster is a duplicate "
                "(gate G3).",
                lambda: ENGINE_CONFIG.get("active_finding_dedup_hours"),
            ),
            ConfigKey(
                "recent_fp_window_days", "engine_config",
                "Rolling window used to decide whether a rule is FP-prone (gate G6).",
                lambda: ENGINE_CONFIG.get("recent_fp_window_days"),
            ),
            ConfigKey(
                "correlation_window_sec", "engine_config",
                "Default signal time-spread limit for gate G8. Persistence and "
                "supply-chain rules use their own longer windows.",
                lambda: {
                    "default": ENGINE_CONFIG.get("correlation_window_sec"),
                    "persistence": ENGINE_CONFIG.get("correlation_window_sec_persistence"),
                    "supply_chain": ENGINE_CONFIG.get("correlation_window_sec_supply_chain"),
                },
            ),
        ),
        checks=_gate_checks,
    ),
    Stage(
        id="reachability",
        name="Reachability enrichment",
        kind="enrichment",
        module="manager/manager/attacklens/reachability.py",
        purpose=(
            "Answers whether a vulnerable package is actually running or network-exposed "
            "by reading the latest processes and ports inventory, not the findings table. "
            "Feeds the Origin criteria package_running and service_reachable; returns n/a "
            "rather than 0 when the telemetry cannot answer, so the weight is dropped "
            "instead of counting against the finding."
        ),
        covers=("origin",),
    ),
    Stage(
        id="terrain_scoring",
        name="Per-terrain criteria scoring",
        kind="scoring",
        module="manager/manager/attacklens/terrain_validators.py",
        purpose=(
            "Each finding is scored against its own terrain's weighted rubric. Criteria "
            "that cannot apply are dropped from the weight pool rather than scored zero, "
            "and one fully-met anchor criterion floors the result at 0.80. This score is "
            "what the Validated Findings threshold filters on."
        ),
        covers=_ALL_TERRAINS,
        error_policy_stage="terrain",
        checks=_terrain_criteria_checks,
    ),
    Stage(
        id="cve_enrichment",
        name="CVE multi-source validation",
        kind="enrichment",
        module="manager/manager/attacklens/finding_validator.py",
        purpose=(
            "Cross-checks a finding's CVEs against NVD, EPSS, CISA KEV and exploit "
            "availability to produce a per-CVE verdict and a recommended action."
        ),
        covers=("origin",),
    ),
    Stage(
        id="ai_verdict",
        name="AI precision verdict",
        kind="model",
        module="manager/manager/attacklens/ai_validator.py",
        purpose=(
            "An LLM senior-analyst TP/FP opinion combined with five deterministic "
            "factors into a weighted precision score. The model is one input among "
            "several and cannot approve a finding the deterministic factors veto; when "
            "it does not run, its weight is dropped rather than counted as zero."
        ),
        error_policy_stage="model",
        config_keys=(
            ConfigKey(
                "ai_validation_enabled", "engine_config",
                "Master switch for the AI precision layer.",
                lambda: bool(ENGINE_CONFIG.get("ai_validation_enabled")),
            ),
            ConfigKey(
                "ATTACKLENS_AI_VALIDATION", "env",
                "Environment override that enables the AI precision layer.",
                lambda: _env_bool("ATTACKLENS_AI_VALIDATION"),
            ),
            ConfigKey(
                "ai_precision_threshold", "engine_config",
                "Aggregate precision score required to promote a cluster.",
                lambda: ENGINE_CONFIG.get("ai_precision_threshold"),
            ),
            ConfigKey(
                "validation_use_ai_verdict", "settings",
                "Settings → Validation toggle. Turning it off keeps the deterministic "
                "factors and drops the model's weight.",
            ),
        ),
        checks=_precision_factor_checks,
    ),
    Stage(
        id="response_contract",
        name="Model response contract",
        kind="policy",
        module="manager/manager/attacklens/validation_model.py",
        purpose=(
            "Strict, provider-neutral schema the model output must satisfy: exact field "
            "set, bounded confidence, and key_evidence entries that must reference "
            "evidence_ref identifiers actually present in the prompt. A response that "
            "fails is an error, never a silently-accepted verdict — which is what stops "
            "a compromised endpoint's text from steering the decision."
        ),
        error_policy_stage="model",
        checks=_response_contract_checks,
    ),
    Stage(
        id="threshold_resolution",
        name="Threshold resolution",
        kind="threshold",
        module="manager/manager/attacklens/ai_validator.py",
        purpose=(
            "Picks the threshold a finding is judged against: per-agent beats "
            "per-terrain beats global. This is the knob that decides what reaches the "
            "Validated Findings page."
        ),
        covers=_ALL_TERRAINS,
        config_keys=(
            ConfigKey(
                "validation_global_threshold", "settings",
                "Global terrain-score threshold applied when no override matches.",
            ),
            ConfigKey(
                "validation_terrain_thresholds", "settings",
                "Per-terrain overrides, keyed by terrain id.",
            ),
            ConfigKey(
                "validation_agent_thresholds", "settings",
                "Per-agent overrides, keyed by agent id.",
            ),
            ConfigKey(
                "validation_agent_priorities", "settings",
                "Per-agent priority tier, which shifts confidence and precision deltas.",
            ),
            ConfigKey(
                "validation_min_strength", "settings",
                "Signal-strength floor enforced by gate G7.",
            ),
            ConfigKey(
                "TERRAIN_VALIDATION_THRESHOLD", "constant",
                "Built-in default for the Validated Findings page, deliberately at or "
                "below the 0.80 anchor floor so anchored findings stay visible.",
                lambda: _terrain_default_threshold(),
            ),
        ),
        checks=_threshold_checks,
    ),
    Stage(
        id="error_policy",
        name="Stage failure policy",
        kind="policy",
        module="manager/manager/attacklens/validation_error_policy.py",
        purpose=(
            "Decides what a failure in each stage means. Terrain, evidence-integrity and "
            "persistence failures fail closed because their output is the decision "
            "itself; a failed model or corroborator can require review but can never "
            "suppress endpoint evidence."
        ),
    ),
    Stage(
        id="decision_ledger",
        name="Validation decision ledger",
        kind="ledger",
        module="manager/manager/indexer.py (validation_runs)",
        purpose=(
            "Append-only record of every validation decision. The findings row is the "
            "current projection; this table preserves the evidence revision, policy "
            "version, gate results, model provenance and cost behind each change."
        ),
        error_policy_stage="persistence",
        checks=_ledger_checks,
    ),
    Stage(
        id="recompute",
        name="Retroactive recompute",
        kind="orchestration",
        module="manager/manager/indexer.py (validation_recompute_jobs)",
        purpose=(
            "Rescoring historical findings after a settings change. Jobs are durable and "
            "resume from a cursor, so a threshold change never requires one "
            "uninterruptible table scan."
        ),
        error_policy_stage="persistence",
    ),
)


def _terrain_default_threshold() -> float:
    from .ai_validator import TERRAIN_VALIDATION_THRESHOLD

    return TERRAIN_VALIDATION_THRESHOLD


# ── Public API ───────────────────────────────────────────────────────────────

def stage_ids() -> tuple[str, ...]:
    return tuple(stage.id for stage in STAGES)


def terrain_rubrics() -> list[dict]:
    """Every terrain's scoring rubric — criteria, weights, and anchor flags."""
    return _terrain_criteria_checks()


def build_inventory() -> list[dict]:
    """Snapshot every stage with its live configuration and derived checks."""
    return [
        {"order": index, **stage.snapshot()}
        for index, stage in enumerate(STAGES, start=1)
    ]


def settings_config_keys() -> tuple[str, ...]:
    """Config keys the API layer must resolve against the settings table."""
    return tuple(
        key.key
        for stage in STAGES
        for key in stage.config_keys
        if key.source == "settings"
    )


def apply_settings_values(inventory: list[dict], settings: dict) -> list[dict]:
    """Fill in `settings`-sourced config values on an inventory snapshot."""
    for stage in inventory:
        for entry in stage.get("config", []):
            if entry.get("source") == "settings":
                entry["value"] = settings.get(entry["key"])
    return inventory


__all__ = [
    "ConfigKey",
    "STAGES",
    "Stage",
    "apply_settings_values",
    "build_inventory",
    "settings_config_keys",
    "stage_ids",
    "terrain_rubrics",
]
