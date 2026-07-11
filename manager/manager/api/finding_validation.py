"""
manager/manager/api/finding_validation.py — Finding Validation REST API.

Endpoints:
  POST /api/v1/findings/{id}/validate        — validate a single finding
  POST /api/v1/findings/validate-batch       — validate up to 20 findings
  GET  /api/v1/findings/{id}/validation      — retrieve last validation report (cached)

The validation layer cross-references each finding's CVE IDs against:
  • NVD (NIST) — CVE existence, CVSS score, version applicability
  • CISA KEV   — known-exploitation confirmation
  • ExploitDB + Metasploit + PoC-GitHub — public exploit availability

Verdicts:
  CONFIRMED     — KEV hit or (CVSS ≥ 7 + exploit available)
  CORROBORATED  — NVD found, CVSS ≥ 4
  DISPUTED      — NVD found, CVSS < 4, finding severity is high/critical
  UNVERIFIED    — CVE IDs present but not in NVD
  N/A           — no CVE IDs (network IOC, behavioral finding, etc.)
"""
from __future__ import annotations

import json
import logging
import time
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..attacklens.finding_validator import FindingValidator

log = logging.getLogger("manager.api.finding_validation")

router = APIRouter(prefix="/api/v1/findings", tags=["finding-validation"])


# ── Dependency helpers ────────────────────────────────────────────────────────

def _pipeline(req: Request):
    p = getattr(req.app.state, "intel_pipeline", None)
    if p is None:
        raise HTTPException(503, detail="IntelPipeline not initialized")
    return p


def _intel_db(req: Request):
    d = getattr(req.app.state, "intel_db", None)
    if d is None:
        raise HTTPException(503, detail="IntelDB not initialized")
    return d


# ── Request models ────────────────────────────────────────────────────────────

class ValidateBatchRequest(BaseModel):
    finding_ids: list[int] = Field(..., min_length=1, max_length=20,
                                    description="Finding IDs to validate (max 20)")
    auto_apply:  bool       = Field(
        default=False,
        description="If true, write confidence + action back to each finding",
    )
    concurrency: int        = Field(default=4, ge=1, le=8)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/{finding_id}/validate")
async def validate_finding(
    finding_id: int,
    auto_apply: bool = Query(
        default=False,
        description="Apply recommended action and update confidence in the DB",
    ),
    pipeline=Depends(_pipeline),
    idb=Depends(_intel_db),
) -> dict:
    """
    Validate a single finding against NVD, CISA KEV, and ExploitDB.

    Returns a validation report with:
    - `verdict`             — CONFIRMED / CORROBORATED / DISPUTED / UNVERIFIED / N/A
    - `confidence_before`   — original confidence score (0–1)
    - `confidence_after`    — adjusted confidence after TI cross-reference
    - `recommended_action`  — lifecycle action to take (or null)
    - `cve_validations`     — per-CVE breakdown from all sources
    - `auto_applied`        — whether the action was automatically applied
    """
    finding = await _get_finding(finding_id, idb)
    validator = FindingValidator(pipeline)
    report = await validator.validate(
        finding,
        concurrency=4,
        auto_apply=auto_apply,
        intel_db=idb if auto_apply else None,
    )
    return report.to_dict()


@router.post("/validate-batch")
async def validate_findings_batch(
    body: ValidateBatchRequest,
    pipeline=Depends(_pipeline),
    idb=Depends(_intel_db),
) -> dict:
    """
    Validate up to 20 findings in parallel.

    Returns a list of validation reports in the same order as `finding_ids`.
    Individual failures are surfaced in the report's `cve_validations[].source_errors`
    rather than failing the entire batch.
    """
    findings = []
    missing: list[int] = []
    for fid in body.finding_ids:
        try:
            f = await _get_finding(fid, idb)
            findings.append(f)
        except HTTPException:
            missing.append(fid)

    if not findings:
        raise HTTPException(404, detail=f"None of the requested findings were found: {body.finding_ids}")

    validator = FindingValidator(pipeline)
    reports = await validator.validate_batch(
        findings,
        concurrency=body.concurrency,
        auto_apply=body.auto_apply,
        intel_db=idb if body.auto_apply else None,
    )

    return {
        "reports":      [r.to_dict() for r in reports],
        "count":        len(reports),
        "missing_ids":  missing,
        "validated_at": time.time(),
    }


@router.get("/{finding_id}/validation")
async def get_validation_report(
    finding_id: int,
    idb=Depends(_intel_db),
) -> dict:
    """
    Return the most recent cached validation report for a finding.

    Reads the `validation_verdict`, `confidence`, and `validated_at` columns
    that auto_apply writes. Returns 404 if the finding has never been validated.
    """
    finding = await _get_finding(finding_id, idb)

    verdict      = finding.get("validation_verdict")
    validated_at = finding.get("validated_at")

    if not verdict:
        raise HTTPException(
            404,
            detail=(
                f"Finding {finding_id} has not been validated yet. "
                "POST /validate to run validation."
            ),
        )

    cve_ids = finding.get("cve_ids") or "[]"
    if isinstance(cve_ids, str):
        try:
            cve_ids = json.loads(cve_ids)
        except (json.JSONDecodeError, TypeError):
            cve_ids = []

    return {
        "finding_id":    finding_id,
        "agent_id":      finding.get("agent_id"),
        "verdict":       verdict,
        "validated_at":  validated_at,
        "confidence":    finding.get("confidence"),
        "status":        finding.get("status"),
        "cve_ids":       cve_ids,
        "note": "Re-run POST /validate to refresh with latest threat intel.",
    }


# ── Exploitability score ──────────────────────────────────────────────────────

@router.get("/{finding_id}/exploitability")
async def get_exploitability(
    finding_id: int,
    persist: bool = Query(
        default=False,
        description="Write the recomputed score+band back to the finding",
    ),
    idb=Depends(_intel_db),
) -> dict:
    """
    Compute the unified exploitability score for a finding — combining CVSS,
    EPSS, KEV status, exploit availability, vulnerability recency, and asset
    criticality — with a fully auditable per-factor breakdown.

    Vulnerability recency uses the CVE publication date (looked up from the
    local NVD/CVE cache) for accuracy; falls back to neutral when unknown.
    """
    from ..threat.exploitability import exploitability_scorer

    finding = await _get_finding(finding_id, idb)

    # Deserialize exploit_sources so the scorer can grade by source count.
    srcs = finding.get("exploit_sources")
    if isinstance(srcs, str):
        try:
            finding["exploit_sources"] = json.loads(srcs) if srcs else []
        except (json.JSONDecodeError, TypeError):
            finding["exploit_sources"] = []

    # Resolve the most accurate vulnerability recency from CVE publication date.
    cve_ids = finding.get("cve_ids")
    if isinstance(cve_ids, str):
        try:
            cve_ids = json.loads(cve_ids)
        except (json.JSONDecodeError, TypeError):
            cve_ids = []
    published_ts = 0.0
    for cid in (cve_ids or []):
        if isinstance(cid, str):
            try:
                published_ts = await idb.get_cve_published_ts(cid)
            except Exception:
                published_ts = 0.0
            if published_ts:
                break

    result = exploitability_scorer.compute(
        finding, cve_published_ts=published_ts or None,
    )

    if persist:
        try:
            async with idb._lock:
                await idb._conn.execute(
                    "UPDATE findings SET exploitability_score=?, exploitability_band=? WHERE id=?",
                    (result.score, result.band, finding_id),
                )
                await idb._conn.commit()
        except Exception as exc:
            log.warning("Failed to persist exploitability for finding %s: %s", finding_id, exc)

    out = result.to_dict()
    out["finding_id"] = finding_id
    return out


@router.post("/exploitability/backfill")
async def backfill_exploitability(
    limit: int = Query(default=5000, ge=1, le=50000,
                       description="Max active findings to (re)score"),
    idb=Depends(_intel_db),
) -> dict:
    """
    Compute and persist the exploitability score for existing active findings
    that don't have one yet (score/band still at defaults). One-time helper for
    databases populated before the score existed; new findings get scored at emit.
    """
    from ..threat.exploitability import exploitability_scorer

    rows = []
    try:
        async with idb._pool.read() as conn:
            async with conn.execute(
                "SELECT * FROM findings WHERE is_active=1 "
                "AND (exploitability_score=0 OR exploitability_band='') "
                "ORDER BY composite_score DESC LIMIT ?",
                (limit,),
            ) as cur:
                rows = await cur.fetchall()
    except Exception as exc:
        raise HTTPException(503, f"DB error: {exc}")

    scored = 0
    for row in rows:
        f = dict(row)
        srcs = f.get("exploit_sources")
        if isinstance(srcs, str):
            try:
                f["exploit_sources"] = json.loads(srcs) if srcs else []
            except (json.JSONDecodeError, TypeError):
                f["exploit_sources"] = []
        cve_ids = f.get("cve_ids")
        if isinstance(cve_ids, str):
            try:
                cve_ids = json.loads(cve_ids)
            except (json.JSONDecodeError, TypeError):
                cve_ids = []
        published_ts = 0.0
        for cid in (cve_ids or []):
            if isinstance(cid, str):
                try:
                    published_ts = await idb.get_cve_published_ts(cid)
                except Exception:
                    published_ts = 0.0
                if published_ts:
                    break
        result = exploitability_scorer.compute(f, cve_published_ts=published_ts or None)
        try:
            async with idb._lock:
                await idb._conn.execute(
                    "UPDATE findings SET exploitability_score=?, exploitability_band=? WHERE id=?",
                    (result.score, result.band, f["id"]),
                )
                await idb._conn.commit()
            scored += 1
        except Exception as exc:
            log.warning("backfill: finding %s failed: %s", f.get("id"), exc)

    return {"scored": scored, "candidates": len(rows), "at": time.time()}


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_finding(finding_id: int, idb) -> dict:
    """Fetch a single finding by numeric ID from intel.db."""
    try:
        finding = await idb.get_finding_by_id(finding_id)
    except Exception as exc:
        log.warning("DB error fetching finding %s: %s", finding_id, exc)
        raise HTTPException(503, detail=f"Database error: {exc}")
    if finding is None:
        raise HTTPException(404, detail=f"Finding {finding_id} not found")
    return finding
