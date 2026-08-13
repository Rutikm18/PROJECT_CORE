"""
manager/manager/attacklens/ai_validator.py — AI-powered TP/FP validation.

A senior-SOC-analyst-shaped second opinion that runs *after* the deterministic
8-gate pipeline and *before* a finding is emitted.

Design:
  • The deterministic gates are precise but rigid — they fire on rule logic.
    They cannot judge contextual signals like "this is the security team's
    sanctioned pentest box" or "this DNS-tunnel pattern is from a sanctioned
    monitoring agent we've seen for months".
  • The AI verdict adds that contextual reasoning by sending the full evidence
    bundle to Claude with a strict TP/FP/uncertain output schema.
  • The AI vote is one of several inputs to a weighted precision score; we do
    not trust the LLM alone. The other inputs are deterministic facts:
        - TI corroboration score        (KEV/EPSS/IP/hash sources)
        - Asset criticality multiplier  (crown-jewel boosts)
        - Behavioural baseline drift    (new-vs-known)
        - FP-history damping            (per-rule, per-host-class)
        - Cross-layer floor             (from cross_matrix)
  • Final precision score ≥ 0.90 → promote.  Below → reject with the lowest-
    contributing factor as the diagnostic.

The whole layer can be toggled per-engine via ATTACKLENS_AI_VALIDATION env var
(or ENGINE_CONFIG['ai_validation_enabled']) and degrades cleanly if no Claude
key is configured — the deterministic factors alone still produce a score.
"""
from __future__ import annotations

import asyncio
import html
import inspect
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .config import ENGINE_CONFIG
from .terrain_catalog import all_terrains, terrain_for_category

log = logging.getLogger("manager.attacklens.ai_validator")


# ── Precision-score weights ─────────────────────────────────────────────────
# Sum to 1.0. Tuned for ≥0.90 calibration: AI verdict carries the most weight
# but cannot single-handedly approve a finding the deterministic factors veto.
PRECISION_WEIGHTS: dict[str, float] = {
    "ai_verdict":         0.35,
    "ti_corroboration":   0.25,
    "cross_layer":        0.15,
    "baseline_anomaly":   0.10,
    "asset_criticality":  0.08,
    "fp_history_damping": 0.07,
}
PRECISION_THRESHOLD = 0.90

# Minimum factor contributions for a TP — caller can short-circuit when missing
# (e.g. AI says FP with >0.85 confidence → reject regardless of other factors).
AI_VETO_CONFIDENCE = 0.85


@dataclass
class AiVerdict:
    label:       str = "uncertain"      # "tp" | "fp" | "uncertain"
    confidence:  float = 0.0             # 0–1
    reasoning:   str = ""
    key_evidence: list[str] = field(default_factory=list)
    risk_factors: list[str] = field(default_factory=list)
    used_llm:    bool = False
    tokens_used: int = 0
    provider: str = ""
    model: str = ""
    generation_id: str = ""
    upstream_provider: str = ""
    finish_reason: str = ""
    cost_usd: float = 0.0
    prompt_version: str = ""
    schema_version: str = ""


@dataclass
class PrecisionResult:
    score:     float                            # 0–1 final precision
    promoted:  bool                             # score ≥ threshold AND no veto
    factors:   dict[str, float]                  # per-factor contributions
    ai:        Optional[AiVerdict]
    rejection_reason: Optional[str] = None       # populated when promoted=False
    ai_error:         Optional[str] = None       # populated when LLM call failed
    threshold_used:   Optional[float] = None     # echoed back for traceability
    review_required:  bool = False                # model recommends review; never suppresses alone
    # Explainability: which factor contributed most / least to the decision
    top_factor:    Optional[str] = None          # factor with highest weighted contribution
    bottom_factor: Optional[str] = None          # factor with lowest weighted contribution (for promoted=True visibility)


# ── Public entrypoint ───────────────────────────────────────────────────────

async def validate_with_ai(
    cluster,
    enriched: dict,
    idb,
    feeds,
    ai_analyst,
    *,
    threshold: float = PRECISION_THRESHOLD,
) -> PrecisionResult:
    """
    Compute the final precision score for a cluster after the deterministic
    gates have already passed.  Returns a PrecisionResult with full provenance.

    `ai_analyst` may be None (no key configured) — we skip the LLM vote and
    rely on the deterministic factors, still producing a valid score.
    """
    # 1. Deterministic factor scores ────────────────────────────────────────
    factors = {
        "ti_corroboration":   _ti_corroboration_score(enriched),
        "cross_layer":        _cross_layer_score(cluster),
        "baseline_anomaly":   await _baseline_anomaly_score(cluster, idb),
        "asset_criticality":  _asset_criticality_score(enriched),
        "fp_history_damping": await _fp_damping_score(cluster, enriched, idb),
    }

    # 2. AI verdict (optional but heavily weighted) ─────────────────────────
    ai_verdict: Optional[AiVerdict] = None
    ai_error:   Optional[str]      = None
    from .validation_model import resolve_validation_model
    try:
        validation_model = resolve_validation_model(ai_analyst)
    except Exception as exc:
        validation_model = None
        ai_error = f"provider_config_error:{type(exc).__name__}"
    if validation_model is None:
        if ai_error is None:
            ai_error = "no_analyst" if ai_analyst is None else "analyst_disabled"
    else:
        try:
            ai_verdict = await _ai_evaluate_cluster(
                cluster, enriched, validation_model,
            )
        except asyncio.TimeoutError:
            ai_error = "llm_timeout"
            log.warning("AI verdict timed out — degrading to deterministic factors")
        except Exception as exc:
            ai_error = f"llm_error:{type(exc).__name__}"
            log.warning(
                "AI verdict failed (degrading gracefully) for cluster agent=%s: %s",
                getattr(cluster, "agent_id", "?"), exc,
            )

    # The AI is the *senior reviewer*, not a blocker. It exists to tighten
    # precision on deterministic-ambiguous cases and to add contextual veto
    # power for clear FPs. It must not down-rank a finding that the
    # deterministic factors already strongly support.
    ai_abstains = (
        ai_verdict is None
        or ai_verdict.label == "uncertain"
        or ai_verdict.confidence < 0.4
    )

    if ai_abstains:
        # Synthesise an AI-equivalent score from the deterministic factors so
        # the weighted sum stays calibrated. Pessimistic when factors are weak,
        # generous when they are strong — preserves overall threshold behaviour.
        factors["ai_verdict"] = _factors_only_estimate(factors)
    else:
        factors["ai_verdict"] = _ai_to_score(ai_verdict)

    # 3. High-confidence model FP is a review recommendation, not a deletion
    # authority. Endpoint evidence is untrusted and models are probabilistic;
    # only a separate deterministic suppression policy may hide a signal.
    if (
        ai_verdict
        and ai_verdict.label == "fp"
        and ai_verdict.confidence >= AI_VETO_CONFIDENCE
        and ai_verdict.reasoning
    ):
        # Authoritative deterministic hits do not even require the extra review.
        deterministic_truth = bool(
            enriched.get("kev_hit") or enriched.get("malicious_hash_hit")
        )
        if not deterministic_truth:
            score = _weighted_sum(factors)
            _weighted_v = {k: PRECISION_WEIGHTS.get(k, 0.0) * v for k, v in factors.items()}
            return PrecisionResult(
                score=round(score, 3),
                promoted=True,
                factors=factors,
                ai=ai_verdict,
                rejection_reason=(
                    f"ai_review:confidence={ai_verdict.confidence:.2f} "
                    f"reason={ai_verdict.reasoning[:160]}"
                ),
                ai_error=ai_error,
                threshold_used=threshold,
                review_required=True,
                top_factor=max(_weighted_v, key=_weighted_v.get) if _weighted_v else None,
                bottom_factor=min(_weighted_v, key=_weighted_v.get) if _weighted_v else None,
            )

    # 4. Weighted aggregate ──────────────────────────────────────────────────
    score = _weighted_sum(factors)

    # 4a. Deterministic floor — if KEV (or malicious-hash) corroborates AND we
    # have cross-layer coverage AND the rule is not chronically FP, promote
    # regardless of the LLM's enthusiasm. A real SOC analyst would never argue
    # with a KEV-confirmed multi-layer detection on the basis of LLM nuance.
    kev_corroborated = bool(
        enriched.get("kev_hit") or enriched.get("malicious_hash_hit")
    )
    multi_layer = len(getattr(cluster, "layers_covered", set()) or set()) >= 2
    clean_rule  = factors["fp_history_damping"] >= 0.70
    if kev_corroborated and multi_layer and clean_rule:
        score = max(score, threshold)

    # 4b. Same override for single-signal deterministic floors (cross_matrix.py
    # CROSS_LAYER_PATTERNS) — e.g. a UID-0 clone or duplicate ARP mapping. These
    # were individually hand-verified as "individually catastrophic" and don't
    # need cross-layer corroboration to be trusted (that's the whole point of a
    # standalone floor) — only the FP-history safety net still applies.
    from .cross_matrix import matched_floor
    cross_matrix_floor_hit = matched_floor(cluster) is not None
    if cross_matrix_floor_hit and clean_rule:
        score = max(score, threshold)

    # 5. Cluster confidence boundary — never promote anything the base
    #    confidence engine already considered fragile (< 0.6) even if the LLM
    #    is enthusiastic.
    base_conf = getattr(cluster, "confidence", None)
    if base_conf is not None and base_conf < 0.6 and score >= threshold:
        _weighted_bc = {k: PRECISION_WEIGHTS.get(k, 0.0) * v for k, v in factors.items()}
        return PrecisionResult(
            score=round(score, 3),
            promoted=False,
            factors=factors,
            ai=ai_verdict,
            rejection_reason=(
                f"base_confidence_floor:cluster.confidence={base_conf:.2f} "
                f"is below 0.60 floor even though precision={score:.2f}"
            ),
            ai_error=ai_error,
            threshold_used=threshold,
            top_factor=max(_weighted_bc, key=_weighted_bc.get) if _weighted_bc else None,
            bottom_factor=min(_weighted_bc, key=_weighted_bc.get) if _weighted_bc else None,
        )

    promoted = score >= threshold
    reason: Optional[str] = None
    weighted = {k: PRECISION_WEIGHTS.get(k, 0.0) * v for k, v in factors.items()}
    top_k    = max(weighted, key=weighted.get) if weighted else None
    bot_k    = min(weighted, key=weighted.get) if weighted else None
    if not promoted:
        lowest = min(factors.items(), key=lambda kv: kv[1])
        reason = f"precision={score:.2f} < {threshold:.2f}; weakest={lowest[0]}={lowest[1]:.2f}"

    return PrecisionResult(
        score=round(score, 3),
        promoted=promoted,
        factors=factors,
        ai=ai_verdict,
        rejection_reason=reason,
        ai_error=ai_error,
        threshold_used=threshold,
        top_factor=top_k,
        bottom_factor=bot_k,
    )


# ── Deterministic factor scoring ────────────────────────────────────────────

def _ti_corroboration_score(enriched: dict) -> float:
    """
    Each independent authoritative TI source adds weight, capped at 1.0.
        KEV present          → 0.45
        malicious-hash hit   → 0.35
        public exploit avail → 0.30  (ExploitDB / Metasploit / PoC)
        malicious-IP hit     → 0.25
        EPSS ≥ 0.7           → 0.20  (≥ 0.5 → 0.10)
        ≥ 2 corroborating sources → +0.10 bonus
    """
    score = 0.0
    sources = 0
    if enriched.get("kev_hit"):
        score += 0.45
        sources += 1
    if enriched.get("malicious_hash_hit"):
        score += 0.35
        sources += 1
    # Public exploit code (ExploitDB/Metasploit/PoC) — strong "weaponised"
    # signal derived deterministically from NVD references; weighted just below
    # a malicious-hash hit and above a single malicious-IP hit.
    if enriched.get("exploit_available"):
        score += 0.30
        sources += 1
    if enriched.get("malicious_ip_hit"):
        score += 0.25
        sources += 1
    epss_scores = enriched.get("epss_scores") or []
    if epss_scores:
        max_epss = max(epss_scores)
        if max_epss >= 0.7:
            score += 0.20
            sources += 1
        elif max_epss >= 0.5:
            score += 0.10
    if sources >= 2:
        score += 0.10
    return min(1.0, score)


def _cross_layer_score(cluster) -> float:
    """
    Multi-layer clusters are far more credible than single-layer.
      1 layer → 0.40   (surface-only configuration finding)
      2 layers → 0.70  (e.g. vulnerable package + exposed port)
      3 layers → 1.00  (surface + exposure + execution — exploit chain)
    """
    n = len(getattr(cluster, "layers_covered", set()) or set())
    return {0: 0.0, 1: 0.40, 2: 0.70}.get(n, 1.0)


async def _baseline_anomaly_score(cluster, idb) -> float:
    """
    Has this rule_id/entity_key combination ever produced a finding for this
    agent before? Brand-new + immediately high-confidence = high precision
    (attackers move fast). Recurring patterns score lower because they more
    often turn out to be benign noise that nobody allowlisted yet.
    """
    try:
        agent_id = cluster.agent_id
        entity   = cluster.entity_key
        # Use the cheapest signal we have: prior rejection / promotion counts
        row = await idb._fetchone(
            "SELECT COUNT(*) AS n FROM signal_clusters "
            "WHERE agent_id=? AND entity_key=? AND status IN ('rejected','low_confidence') "
            "AND created_at >= ?",
            (agent_id, entity, time.time() - 30 * 86400),
        )
        rejections = row["n"] if row else 0
    except Exception:
        rejections = 0

    # 0 rejections → fully novel (0.95)
    # 1-2 rejections → mild (0.80)
    # 3-5 rejections → suspicious of FP pattern (0.55)
    # > 5 rejections → strong FP pattern (0.30)
    if rejections == 0:
        return 0.95
    if rejections <= 2:
        return 0.80
    if rejections <= 5:
        return 0.55
    return 0.30


def _asset_criticality_score(enriched: dict) -> float:
    """
    Crown-jewel and server-tier assets demand a higher precision bar, but the
    contribution to *this* factor scales the *upside*: a TP on a crown-jewel
    is more important to surface than a TP on an endpoint sandbox.
    """
    tier = (enriched.get("asset_tier") or "endpoint").lower()
    return {
        "crown_jewel": 1.00,
        "server":      0.85,
        "workstation": 0.65,
        "endpoint":    0.50,
        "unknown":     0.40,
    }.get(tier, 0.40)


async def _fp_damping_score(cluster, enriched: dict, idb) -> float:
    """
    Penalise rules whose recent FP rate is high. 1.0 = clean rule(s);
    0.0 = chronically FP. We use the lowest score across the cluster's
    rule_ids so one bad rule drags the cluster down.
    """
    rule_ids = sorted({s.rule_id for s in cluster.signals})
    host_class = enriched.get("host_class", "unknown")
    window = int(ENGINE_CONFIG.get("recent_fp_window_days", 7))
    try:
        rate = await idb.get_fp_rate_for_rules(rule_ids, host_class=host_class, window_days=window)
    except Exception:
        rate = 0.0
    # rate ∈ [0,1]; invert and clamp.
    return max(0.0, 1.0 - rate)


# ── AI verdict ───────────────────────────────────────────────────────────────

def _is_transient_error(exc: Exception) -> bool:
    """Classify retryable provider errors without message-string matching."""
    from ..integrations.resilience import TransientError
    return isinstance(exc, (TransientError, asyncio.TimeoutError))


async def _ai_evaluate_cluster(cluster, enriched: dict, validation_model) -> AiVerdict:
    """
    Ask the LLM to act as a senior SOC analyst and emit a structured TP/FP/uncertain
    verdict.  The prompt is heavily constrained: JSON only, exact schema, no prose.
    The ValidationModel adapter owns provider resolution, structured transport,
    and strict local response validation.
    """
    from .validation_model import resolve_validation_model
    prompt = _build_ai_prompt(cluster, enriched)
    evaluate_method = getattr(type(validation_model), "evaluate", None)
    model = (
        validation_model
        if inspect.iscoroutinefunction(evaluate_method)
        else resolve_validation_model(validation_model)
    )
    if model is None:
        raise RuntimeError("No validation model configured")
    timeout_s = max(5.0, min(120.0, float(
        ENGINE_CONFIG.get("ai_validation_timeout_sec", 45.0)
    )))
    verdict = await asyncio.wait_for(model.evaluate(prompt), timeout=timeout_s)
    return AiVerdict(
        label=verdict.label,
        confidence=verdict.confidence,
        reasoning=verdict.reasoning,
        key_evidence=verdict.key_evidence,
        risk_factors=verdict.risk_factors,
        used_llm=True,
        tokens_used=verdict.tokens_used,
        provider=verdict.provider,
        model=verdict.model,
        generation_id=verdict.generation_id,
        upstream_provider=verdict.upstream_provider,
        finish_reason=verdict.finish_reason,
        cost_usd=verdict.cost_usd,
        prompt_version=verdict.prompt_version,
        schema_version=verdict.schema_version,
    )


def _build_ai_prompt(cluster, enriched: dict) -> str:
    """Render the cluster + enrichment into a senior-SOC-analyst prompt."""
    def safe(value: Any, limit: int = 1000) -> str:
        return html.escape(str(value)[:limit], quote=True)

    signal_lines = []
    for index, s in enumerate(cluster.signals[:8], start=1):
        ev = safe(json.dumps(s.evidence, default=str), 280)
        signal_lines.append(
            f"  • evidence_ref=evidence:signal:{index}:{safe(s.rule_id, 100)}  "
            f"rule={safe(s.rule_id, 100)}  "
            f"layer={safe(s.layer, 100)}  data_point={safe(s.data_point, 100)}  "
            f"strength={s.strength:.2f}  weight={s.weight:.2f}\n"
            f"    severity_hint={safe(s.severity_hint, 100)}  "
            f"entity_key={safe(s.entity_key, 200)}\n"
            f"    evidence={ev}"
        )
    signals_block = "\n".join(signal_lines) or "  (no signals)"

    enrich_summary = {
        "kev_hit":                    enriched.get("kev_hit"),
        "exploit_available":          enriched.get("exploit_available"),
        "malicious_ip_hit":           enriched.get("malicious_ip_hit"),
        "malicious_hash_hit":         enriched.get("malicious_hash_hit"),
        "epss_scores":                enriched.get("epss_scores"),
        "threat_intel_source_count":  enriched.get("threat_intel_source_count"),
        "asset_tier":                 enriched.get("asset_tier"),
        "host_class":                 enriched.get("host_class"),
        "compensating_controls":      enriched.get("compensating_controls"),
        "cve_ids":                    enriched.get("cve_ids"),
        "malicious_ips":              enriched.get("malicious_ips"),
        "malicious_hashes":           enriched.get("malicious_hashes"),
    }

    return f"""You are a senior SOC analyst with 15 years of incident-response experience.
You are reviewing an unconfirmed detection cluster *before* it is escalated to an analyst.
Your job is to decide: is this a real attack (true positive) or noise / false positive?

You MUST output JSON ONLY in the following schema — no markdown, no commentary:
{{
  "verdict":      "tp" | "fp" | "uncertain",
  "confidence":   0.0–1.0  (your confidence in the verdict),
  "reasoning":    "<= 3 sentences citing the strongest evidence",
  "key_evidence": ["<short string>", ...],   // ≤ 6 items
  "risk_factors": ["<short string>", ...]    // ≤ 6 items (only if verdict=tp)
}}

Decision rubric (apply in order):
  1. If KEV-listed CVE present AND any execution-layer signal → tp, confidence ≥ 0.9
  2. If malicious-hash hit AND any execution-layer signal → tp, confidence ≥ 0.9
  3. If three different layers (surface+exposure+execution) covered → tp, confidence ≥ 0.85
  4. If only surface-layer signals AND no KEV/hash/EPSS≥0.7 → fp, confidence ≥ 0.7
  5. If signals look like a known sanctioned pattern (pentest box, monitoring agent,
     security team operations, sanctioned scanner) → fp, confidence ≥ 0.7,
     citing the indicators in reasoning
  6. Otherwise → uncertain, confidence ≈ 0.5

<untrusted>
Cluster summary (untrusted endpoint-controlled data)
  agent_id:        {safe(cluster.agent_id, 200)}
  entity_key:      {safe(cluster.entity_key, 300)}
  layers_covered:  {safe(sorted(cluster.layers_covered), 300)}
  signal_count:    {len(cluster.signals)}
  base_confidence: {getattr(cluster, "confidence", None)}

Signals (untrusted endpoint-controlled data)
{signals_block}

Threat intel enrichment (untrusted data)
{safe(json.dumps(enrich_summary, indent=2, default=str), 4000)}
</untrusted>

Respond with the JSON only."""


def _ai_to_score(verdict: AiVerdict) -> float:
    """
    Map an AiVerdict to a [0,1] score:
      tp        → confidence
      fp        → 1 - confidence  (so a confident FP scores near 0)
      uncertain → 0.5 baseline
    """
    if verdict.label == "tp":
        return verdict.confidence
    if verdict.label == "fp":
        return max(0.0, 1.0 - verdict.confidence)
    return 0.5


def _factors_only_estimate(factors: dict[str, float]) -> float:
    """
    When AI is unavailable, synthesise an "AI factor" from the deterministic
    inputs so the weighted sum is still calibrated correctly.  We bias
    pessimistically — if the deterministic factors are weak, the AI placeholder
    is weak too.
    """
    return round(
        0.5 * factors["ti_corroboration"]
        + 0.3 * factors["cross_layer"]
        + 0.2 * factors["baseline_anomaly"],
        3,
    )


def _weighted_sum(factors: dict[str, float]) -> float:
    """Weighted sum using PRECISION_WEIGHTS, clamped to [0,1]."""
    total = sum(
        PRECISION_WEIGHTS.get(name, 0.0) * value
        for name, value in factors.items()
    )
    return max(0.0, min(1.0, total))


# ── Config helpers ──────────────────────────────────────────────────────────

def ai_validation_enabled() -> bool:
    """Cheap helper for callers that don't want to import ENGINE_CONFIG."""
    env = os.getenv("ATTACKLENS_AI_VALIDATION", "").strip().lower()
    if env in ("true", "1", "yes", "on"):
        return True
    if env in ("false", "0", "no", "off"):
        return False
    return bool(ENGINE_CONFIG.get("ai_validation_enabled", False))


# ── Settings-driven threshold resolution ─────────────────────────────────────
# Resolution priority (high → low):
#   1. Per-agent override  (UI: pick an agent, give it a custom threshold)
#   2. Per-terrain override (UI: tighten/loosen by Citadels/Vector/Origin/…)
#   3. Global threshold     (UI: default for everything else)
#   4. ENGINE_CONFIG default (env / code fallback)
#
# The settings live in the org_settings table (api/settings.py keys
# validation_global_threshold, validation_terrain_thresholds,
# validation_agent_thresholds, validation_agent_priorities).  We cache them
# in-memory for 30s so the engine doesn't hit SQLite on every cluster.

_SETTINGS_TTL_SEC  = 30.0
_settings_cache: dict = {"loaded_at": 0.0, "data": None}


# Backward-compatible derived map for existing imports. The catalog owns the
# assignments; threshold resolution uses terrain_for_category directly.
_CATEGORY_TO_TERRAIN: dict[str, str] = {
    category: definition.id
    for definition in all_terrains()
    for category in definition.categories
}


async def _load_validation_settings(idb) -> dict:
    """Cached fetch of the validation settings from org_settings."""
    import json as _json
    now = time.time()
    if (_settings_cache["data"] is not None
            and now - _settings_cache["loaded_at"] < _SETTINGS_TTL_SEC):
        return _settings_cache["data"]

    try:
        rows = await idb._fetchall(
            "SELECT key, value FROM org_settings "
            "WHERE key IN ('validation_global_threshold',"
            "              'validation_terrain_thresholds',"
            "              'validation_agent_thresholds',"
            "              'validation_agent_priorities',"
            "              'validation_use_ai_verdict',"
            "              'validation_min_strength')",
            (),
        )
        kv = {r["key"]: r["value"] for r in rows}
    except Exception as exc:
        log.debug("validation settings load failed: %s", exc)
        kv = {}

    try:
        terrain_thr = _json.loads(kv.get("validation_terrain_thresholds") or "{}")
    except _json.JSONDecodeError:
        terrain_thr = {}
    try:
        agent_thr = _json.loads(kv.get("validation_agent_thresholds") or "{}")
    except _json.JSONDecodeError:
        agent_thr = {}
    try:
        agent_priorities_raw = _json.loads(kv.get("validation_agent_priorities") or "{}")
    except _json.JSONDecodeError:
        agent_priorities_raw = {}
    try:
        from .asset_priority import normalize_agent_priorities
        agent_priorities = normalize_agent_priorities(agent_priorities_raw)
    except Exception:
        agent_priorities = {}

    try:
        global_thr = float(kv.get("validation_global_threshold")
                           or ENGINE_CONFIG.get("ai_precision_threshold", PRECISION_THRESHOLD))
    except (TypeError, ValueError):
        global_thr = PRECISION_THRESHOLD

    use_ai = (kv.get("validation_use_ai_verdict", "true") or "true").lower() == "true"
    try:
        min_strength = float(
            kv.get("validation_min_strength")
            or ENGINE_CONFIG.get("quality_floor_strength", 0.6)
        )
    except (TypeError, ValueError):
        min_strength = float(ENGINE_CONFIG.get("quality_floor_strength", 0.6))

    data = {
        "global":  global_thr,
        "terrain": {str(k): float(v) for k, v in terrain_thr.items()},
        "agent":   {str(k): float(v) for k, v in agent_thr.items()},
        "agent_priorities": agent_priorities,
        "use_ai":  use_ai,
        "min_strength": max(0.0, min(1.0, min_strength)),
    }
    _settings_cache["loaded_at"] = now
    _settings_cache["data"]      = data
    return data


def invalidate_validation_settings_cache() -> None:
    """Force the next resolve call to re-read from DB. Settings PUT handlers
    can call this for instant propagation; otherwise the 30s TTL takes care."""
    _settings_cache["loaded_at"] = 0.0
    _settings_cache["data"]      = None


async def resolve_threshold(idb, agent_id: str, category: str) -> float:
    """
    Return the precision threshold for this (agent, category) pair, applying
    overrides in priority order.  Always returns a value in [0, 1].
    """
    settings = await _load_validation_settings(idb)
    # 1. per-agent override
    if agent_id and agent_id in settings["agent"]:
        return max(0.0, min(1.0, settings["agent"][agent_id]))
    # 2. per-terrain override
    terrain = terrain_for_category(category)
    if terrain and terrain in settings["terrain"]:
        return max(0.0, min(1.0, settings["terrain"][terrain]))
    # 3. global
    return max(0.0, min(1.0, float(settings["global"])))


async def resolve_agent_priority(idb, agent_id: str):
    """Return the configured AssetPriorityProfile for an agent."""
    from .asset_priority import priority_for_agent
    settings = await _load_validation_settings(idb)
    return priority_for_agent(agent_id, settings.get("agent_priorities") or {})


async def use_ai_verdict_for(idb) -> bool:
    """Settings-driven master switch for the LLM verdict step."""
    settings = await _load_validation_settings(idb)
    return bool(settings.get("use_ai", True))


async def resolve_min_strength(idb) -> float:
    """Return the live Settings → Validation G7 signal-strength floor."""
    settings = await _load_validation_settings(idb)
    return float(settings.get(
        "min_strength", ENGINE_CONFIG.get("quality_floor_strength", 0.6),
    ))
