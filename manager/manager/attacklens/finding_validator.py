"""
manager/manager/attacklens/finding_validator.py — Finding Validation Layer.

Validates an emitted finding (already in the DB) against authoritative threat
intelligence sources:

  1. NVD (NIST National Vulnerability Database)
       CVE existence, CVSS score, CWE, version applicability, references.

  2. CISA KEV (Known Exploited Vulnerabilities)
       Whether any attached CVE has confirmed in-the-wild exploitation.
       This is the highest-signal indicator: KEV = real exploitation, not theory.

  3. ExploitDB / Metasploit / PoC-GitHub
       Public exploit availability, surfaced through the IntelPipeline sources
       (ExploitDBSource, MetasploitSource, PocGithubSource) and the exploit_available
       flag already extracted from NVD references.

This layer sits AFTER the 8-gate cluster validator (attacklens/validation.py)
and AFTER the terrain validator (attacklens/terrain_validators.py). It answers
a different question: "Given this emitted finding, what do authoritative TI
sources say about the underlying CVE(s)?"

─── Confidence Model ────────────────────────────────────────────────────────
  final = base × nvd_mult × kev_mult × exploit_mult    clamped [0.0, 1.0]

  base         = finding's existing confidence (0..1) or 0.50 if not set.

  nvd_mult     CVSS ≥ 9.0 → 1.40  (critical — max severity confirmed by NVD)
               CVSS ≥ 7.0 → 1.20  (high)
               CVSS ≥ 4.0 → 1.05  (medium — corroborated but modest)
               CVSS ≥ 0.1 → 0.85  (low — NVD found, scores it as minimal risk)
               not found  → 0.70  (CVE unknown to NVD — credibility reduced)

  kev_mult     in CISA KEV → 1.60  (exploitation confirmed by CISA)
               not in KEV  → 1.00

  exploit_mult exploit in ExploitDB or Metasploit     → 1.25
               EPSS ≥ 0.50 (high empirical probability) → 1.10
               no exploit signal                        → 1.00

─── Verdict ────────────────────────────────────────────────────────────────
  Evaluated on the highest-severity CVE attached to the finding.

  CONFIRMED     KEV hit  OR  (CVSS ≥ 7 AND exploit_available)
  CORROBORATED  NVD found with CVSS ≥ 4, no exploit/KEV
  DISPUTED      NVD found with CVSS < 4 but finding severity is high/critical
  UNVERIFIED    CVE IDs present but none found in NVD
  N/A           Finding has no CVE IDs (network IOC, behavioral, etc.)

─── Lifecycle Recommendation ────────────────────────────────────────────────
  CONFIRMED     → recommend "investigate"  (auto-escalate, high confidence)
  CORROBORATED  → recommend "open"         (move to triage)
  DISPUTED      → recommend "false_positive" (low severity, analyst should confirm)
  UNVERIFIED    → no auto-action; confidence reduced; analyst must decide
  N/A           → no-op (CVE validation not applicable)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..intel.pipeline import IntelPipeline

from .. import finding_lifecycle as lc

log = logging.getLogger("manager.attacklens.finding_validator")

# ── Verdict constants ────────────────────────────────────────────────────────

VERDICT_CONFIRMED    = "CONFIRMED"
VERDICT_CORROBORATED = "CORROBORATED"
VERDICT_DISPUTED     = "DISPUTED"
VERDICT_UNVERIFIED   = "UNVERIFIED"
VERDICT_NA           = "N/A"

# ── Confidence model multipliers ──────────────────────────────────────────────

_NVD_MULT: list[tuple[float, float]] = [
    (9.0, 1.40),
    (7.0, 1.20),
    (4.0, 1.05),
    (0.1, 0.85),
]
_NVD_MULT_NOT_FOUND = 0.70

_KEV_MULT     = 1.60
_EXPLOIT_MULT = 1.25   # confirmed public exploit (ExploitDB / Metasploit)
_EPSS_MULT    = 1.10   # high EPSS with no confirmed exploit


@dataclass
class SourceResult:
    """Per-CVE result from one authoritative source."""
    source:    str             # "nvd" | "cisa_kev" | "exploitdb" | "metasploit" | "epss"
    found:     bool
    data:      dict = field(default_factory=dict)
    latency_ms: float = 0.0
    error:     Optional[str] = None


@dataclass
class CVEValidation:
    """Enrichment result for a single CVE ID."""
    cve_id:           str
    nvd_found:        bool
    cvss_score:       Optional[float]
    severity:         str                      # "critical"|"high"|"medium"|"low"|"info"
    in_kev:           bool
    exploit_available: bool                    # ExploitDB or Metasploit hit
    epss_score:       Optional[float]
    sources_used:     list[str] = field(default_factory=list)
    source_errors:    list[str] = field(default_factory=list)
    raw:              dict      = field(default_factory=dict)


@dataclass
class FindingValidationReport:
    """
    Complete validation outcome for a finding.
    Stored as JSON in finding.validation_report (not yet a DB column; stored in
    finding.extra or surfaced via the API response only until a migration adds
    the column).
    """
    finding_id:        int
    agent_id:          str
    validated_at:      float
    verdict:           str                        # one of VERDICT_* constants
    confidence_before: float
    confidence_after:  float
    cve_validations:   list[CVEValidation]        # one per CVE ID
    recommended_action: Optional[str]             # canonical action key or None
    recommended_label:  Optional[str]             # human-readable label
    auto_applied:      bool = False               # True if we mutated the finding
    notes:             str  = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cve_validations"] = [asdict(cv) for cv in self.cve_validations]
        return d


# ── Multiplier helpers ────────────────────────────────────────────────────────

def _nvd_mult(cvss: Optional[float]) -> float:
    if cvss is None:
        return _NVD_MULT_NOT_FOUND
    for threshold, mult in _NVD_MULT:
        if cvss >= threshold:
            return mult
    return _NVD_MULT_NOT_FOUND


def _epss_mult(epss: Optional[float], exploit_avail: bool) -> float:
    if exploit_avail:
        return _EXPLOIT_MULT
    if epss is not None and epss >= 0.50:
        return _EPSS_MULT
    return 1.0


def _verdict(cve_validations: list[CVEValidation], finding_severity: str) -> str:
    """Derive overall verdict from all CVE results."""
    if not cve_validations:
        return VERDICT_NA

    # Evaluate on the best (highest-signal) CVE
    best = max(
        cve_validations,
        key=lambda cv: (
            cv.in_kev,
            cv.exploit_available,
            cv.cvss_score or 0.0,
        ),
    )

    if not best.nvd_found:
        return VERDICT_UNVERIFIED

    if best.in_kev or (
        best.cvss_score is not None
        and best.cvss_score >= 7.0
        and best.exploit_available
    ):
        return VERDICT_CONFIRMED

    if best.cvss_score is not None and best.cvss_score >= 4.0:
        return VERDICT_CORROBORATED

    # NVD found, CVSS < 4, but the finding itself is high/critical
    if finding_severity in ("critical", "high"):
        return VERDICT_DISPUTED

    return VERDICT_CORROBORATED  # low severity, low CVSS — still corroborated


def _recommended_action(
    verdict: str,
    current_status: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """
    Return (canonical_action_key, label) or (None, None) if no auto-action is
    appropriate. Never recommends an action that the lifecycle forbids from
    the current status.
    """
    candidates: dict[str, str] = {
        VERDICT_CONFIRMED:    "investigate",
        VERDICT_CORROBORATED: "open",
        VERDICT_DISPUTED:     "false_positive",
    }
    action = candidates.get(verdict)
    if action is None:
        return None, None
    if not lc.can_transition(current_status, action):
        return None, None
    spec = lc.ACTIONS.get(action)
    return action, (spec["label"] if spec else action)


# ── Main validator class ──────────────────────────────────────────────────────

class FindingValidator:
    """
    Validates a finding against NVD, CISA KEV, and ExploitDB.

    Usage:
        validator = FindingValidator(intel_pipeline)
        report = await validator.validate(finding_dict)
    """

    def __init__(self, pipeline: "IntelPipeline") -> None:
        self._pipeline = pipeline

    async def validate(
        self,
        finding: dict,
        *,
        concurrency: int = 4,
        auto_apply:  bool = False,
        intel_db=None,
    ) -> FindingValidationReport:
        """
        Validate a finding.

        Args:
            finding:     dict from IntelDB.get_findings / upsert_finding
            concurrency: max parallel CVE lookups (default 4)
            auto_apply:  if True and intel_db is given, write confidence +
                         action back to the finding row
            intel_db:    IntelDB instance; required only when auto_apply=True
        """
        finding_id   = finding.get("id", 0)
        agent_id     = finding.get("agent_id", "")
        t0           = time.time()
        base_conf    = float(finding.get("confidence") or 0.50)
        current_status = finding.get("status") or lc.NEW
        sev          = (finding.get("severity") or "").lower()

        # Extract CVE IDs — stored as a JSON list in the finding row
        raw_cve_ids = finding.get("cve_ids") or "[]"
        if isinstance(raw_cve_ids, str):
            try:
                cve_ids: list[str] = json.loads(raw_cve_ids)
            except (json.JSONDecodeError, TypeError):
                cve_ids = []
        else:
            cve_ids = list(raw_cve_ids)

        cve_ids = [c.strip().upper() for c in cve_ids if c and c.strip()]

        # Validate each CVE concurrently
        sem = asyncio.Semaphore(concurrency)

        async def _validate_one(cve_id: str) -> CVEValidation:
            async with sem:
                return await self._validate_cve(cve_id)

        cve_results: list[CVEValidation] = []
        if cve_ids:
            cve_results = await asyncio.gather(*[_validate_one(c) for c in cve_ids])

        # Aggregate confidence multipliers across all CVEs (use best multipliers)
        if cve_results:
            best_cvss     = max((cv.cvss_score or 0.0) for cv in cve_results)
            any_kev       = any(cv.in_kev for cv in cve_results)
            any_exploit   = any(cv.exploit_available for cv in cve_results)
            best_epss     = max((cv.epss_score or 0.0) for cv in cve_results)

            nm = _nvd_mult(best_cvss if any(cv.nvd_found for cv in cve_results) else None)
            km = _KEV_MULT if any_kev else 1.0
            em = _epss_mult(best_epss, any_exploit)
        else:
            nm = km = em = 1.0

        confidence_after = min(1.0, base_conf * nm * km * em)
        confidence_after = round(confidence_after, 4)

        verdict = _verdict(list(cve_results), sev)
        rec_action, rec_label = _recommended_action(verdict, current_status)

        report = FindingValidationReport(
            finding_id        = finding_id,
            agent_id          = agent_id,
            validated_at      = t0,
            verdict           = verdict,
            confidence_before = round(base_conf, 4),
            confidence_after  = confidence_after,
            cve_validations   = list(cve_results),
            recommended_action = rec_action,
            recommended_label  = rec_label,
            notes             = self._build_notes(verdict, cve_results),
        )

        if auto_apply and intel_db is not None:
            await self._apply(report, finding, intel_db, rec_action)
            report.auto_applied = True

        return report

    async def validate_batch(
        self,
        findings: list[dict],
        *,
        concurrency: int = 4,
        auto_apply:  bool = False,
        intel_db=None,
    ) -> list[FindingValidationReport]:
        """Validate multiple findings, up to 20 at a time."""
        findings = findings[:20]
        sem = asyncio.Semaphore(concurrency)

        async def _one(f: dict) -> FindingValidationReport:
            async with sem:
                return await self.validate(
                    f,
                    concurrency=concurrency,
                    auto_apply=auto_apply,
                    intel_db=intel_db,
                )

        return await asyncio.gather(*[_one(f) for f in findings])

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _validate_cve(self, cve_id: str) -> CVEValidation:
        """Enrich one CVE via the IntelPipeline and extract what we need."""
        t0 = time.time()
        try:
            enriched = await self._pipeline.enrich_cve(cve_id)
        except Exception as exc:
            log.warning("IntelPipeline.enrich_cve(%s) failed: %s", cve_id, exc)
            return CVEValidation(
                cve_id=cve_id,
                nvd_found=False,
                cvss_score=None,
                severity="unknown",
                in_kev=False,
                exploit_available=False,
                epss_score=None,
                source_errors=[str(exc)],
            )

        nvd   = enriched.get("nvd") or {}
        kev   = enriched.get("kev")
        epss  = enriched.get("epss") or {}
        exdb  = enriched.get("exploitdb") or {}
        msf   = enriched.get("metasploit") or {}
        poc   = enriched.get("poc_github") or {}

        nvd_found = bool(nvd and nvd.get("cve_id"))
        cvss_score = (
            nvd.get("cvss_score")
            if nvd_found
            else enriched.get("composite_score")
        )
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (TypeError, ValueError):
                cvss_score = None

        severity = nvd.get("severity") or enriched.get("severity") or "info"

        # KEV: from the CISA KEV source (the pipeline sets kev = {cve_id, ...} or None)
        in_kev = kev is not None and bool(kev)

        # Exploit availability: ExploitDB hit, Metasploit module, or NVD reference flag
        exploit_available = (
            bool(exdb and exdb.get("exploit_ids"))
            or bool(msf and msf.get("modules"))
            or bool(poc and poc.get("count", 0) > 0)
            or bool(nvd.get("exploit_available"))
        )

        # EPSS
        epss_score: Optional[float] = None
        raw_epss = epss.get("epss") if epss else enriched.get("epss_score")
        if raw_epss is not None:
            try:
                epss_score = float(raw_epss)
            except (TypeError, ValueError):
                pass

        sources_used = [
            s for s in ["nvd", "kev", "epss", "exploitdb", "metasploit", "poc_github"]
            if enriched.get(s) is not None
        ]

        source_errors = enriched.get("_source_errors") or []

        return CVEValidation(
            cve_id           = cve_id,
            nvd_found        = nvd_found,
            cvss_score       = cvss_score,
            severity         = severity,
            in_kev           = in_kev,
            exploit_available= exploit_available,
            epss_score       = epss_score,
            sources_used     = sources_used,
            source_errors    = list(source_errors) if isinstance(source_errors, list) else [],
            raw              = {
                "nvd":        nvd,
                "kev":        kev,
                "epss":       epss,
                "exploitdb":  exdb,
                "metasploit": msf,
            },
        )

    async def _apply(
        self,
        report: FindingValidationReport,
        finding: dict,
        intel_db,
        action: Optional[str],
    ) -> None:
        """Persist confidence update and optional status transition."""
        finding_id = report.finding_id
        agent_id   = report.agent_id
        try:
            # Update confidence in place by upserting the full finding with
            # the new confidence value; a lightweight path avoids re-running
            # full detection.
            updated = dict(finding)
            updated["confidence"] = report.confidence_after
            updated["validation_verdict"] = report.verdict
            updated["validated_at"]       = report.validated_at

            # Persist status transition if the action is valid
            if action and lc.can_transition(finding.get("status"), action):
                new_status = lc.target_status(action)
                if new_status:
                    updated["status"] = new_status
                    log.info(
                        "finding %s: auto-applied action=%s → status=%s (verdict=%s)",
                        finding_id, action, new_status, report.verdict,
                    )

            await intel_db.upsert_finding(updated, time.time())

        except Exception as exc:
            log.warning("Failed to auto-apply validation to finding %s: %s", finding_id, exc)

    @staticmethod
    def _build_notes(verdict: str, cve_results: list[CVEValidation]) -> str:
        parts: list[str] = []
        if verdict == VERDICT_CONFIRMED:
            kev_cves = [cv.cve_id for cv in cve_results if cv.in_kev]
            if kev_cves:
                parts.append(f"KEV confirmed: {', '.join(kev_cves)}")
            exp_cves = [cv.cve_id for cv in cve_results if cv.exploit_available and not cv.in_kev]
            if exp_cves:
                parts.append(f"Exploit available: {', '.join(exp_cves)}")
        elif verdict == VERDICT_CORROBORATED:
            parts.append("CVE(s) present in NVD with moderate or higher CVSS")
        elif verdict == VERDICT_DISPUTED:
            parts.append("NVD CVSS < 4 but finding is rated high/critical — analyst review required")
        elif verdict == VERDICT_UNVERIFIED:
            parts.append("CVE ID(s) not found in NVD; check for typo or very recent disclosure")
        elif verdict == VERDICT_NA:
            parts.append("No CVE IDs attached; TI validation not applicable")
        return "; ".join(parts)


# ── Module-level convenience function ────────────────────────────────────────

async def validate_finding(
    finding: dict,
    pipeline: "IntelPipeline",
    *,
    concurrency: int = 4,
    auto_apply:  bool = False,
    intel_db=None,
) -> FindingValidationReport:
    """
    One-shot validation of a single finding.  Convenience wrapper around
    FindingValidator for callers that don't keep a long-lived instance.
    """
    validator = FindingValidator(pipeline)
    return await validator.validate(
        finding,
        concurrency=concurrency,
        auto_apply=auto_apply,
        intel_db=intel_db,
    )
