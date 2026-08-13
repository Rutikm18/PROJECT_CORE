"""Explicit failure policy for each validation stage.

The policy intentionally separates an unavailable source from negative
evidence.  A failed model or corroborator may require review, but it can never
silently suppress endpoint evidence.  Failures in the deterministic terrain
engine or evidence-integrity boundary fail closed because their output is the
decision itself.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationErrorDecision:
    state: str
    action: str
    reason: str


def decide_validation_error(
    stage: str,
    severity: str,
    error_class: str,
    *,
    authoritative_evidence: bool = False,
) -> ValidationErrorDecision:
    """Return the auditable state transition for one stage failure."""
    normalized_stage = str(stage or "").strip().lower()
    normalized_severity = str(severity or "info").strip().lower()
    reason = f"{normalized_stage or 'unknown'}:{error_class or 'unknown'}"

    if normalized_stage in {"terrain", "evidence_integrity", "persistence"}:
        return ValidationErrorDecision("error", "fail_closed", reason)

    if authoritative_evidence and normalized_stage in {"model", "corroboration"}:
        return ValidationErrorDecision(
            "continue", "deterministic_continue", reason,
        )

    if normalized_stage == "model":
        if normalized_severity in {"critical", "high"}:
            return ValidationErrorDecision(
                "needs_review", "degrade_to_review", reason,
            )
        return ValidationErrorDecision(
            "continue", "deterministic_continue", reason,
        )

    if normalized_stage == "corroboration":
        if normalized_severity in {"critical", "high"}:
            return ValidationErrorDecision(
                "needs_review", "degrade_to_review", reason,
            )
        return ValidationErrorDecision(
            "continue", "inconclusive_continue", reason,
        )

    return ValidationErrorDecision("needs_review", "degrade_to_review", reason)
