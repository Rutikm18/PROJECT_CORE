from __future__ import annotations

import pytest

from manager.manager.attacklens.finding_validator import FindingValidator
from manager.manager.intel.pipeline import build_source_freshness


def test_source_freshness_distinguishes_available_not_found_and_error() -> None:
    result = build_source_freshness(
        ["nvd", "kev", "exploitdb"],
        {"nvd": {"cve_id": "CVE-2026-1234"}},
        {"exploitdb": "circuit open"},
        observed_at=1_000.0,
        source_health={"exploitdb": {"loaded_at": 100.0}},
    )

    assert result["nvd"]["status"] == "available"
    assert result["kev"]["status"] == "not_found"
    assert result["exploitdb"]["status"] == "error"
    assert result["exploitdb"]["error"] == "circuit open"
    assert result["exploitdb"]["source_updated_at"] == 100.0


@pytest.mark.asyncio
async def test_finding_validator_surfaces_named_corroboration_stage() -> None:
    class Pipeline:
        async def enrich_cve(self, cve_id: str) -> dict:
            return {
                "nvd": {"cve_id": cve_id, "cvss_score": 8.1, "severity": "high"},
                "kev": None,
                "_source_errors": {"epss": "timeout"},
                "_source_freshness": {
                    "nvd": {"status": "available", "observed_at": 2_000.0},
                    "epss": {"status": "error", "observed_at": 2_000.0},
                },
            }

    report = await FindingValidator(Pipeline()).validate({
        "id": 7,
        "agent_id": "agent-a",
        "severity": "high",
        "confidence": 0.7,
        "status": "new",
        "cve_ids": ["CVE-2026-1234"],
    })

    stage = report.to_dict()["corroboration_stage"]
    assert stage["name"] == "authoritative_corroboration"
    assert stage["status"] == "partial"
    assert stage["sources_used"] == ["nvd"]
    assert stage["source_errors"] == {"CVE-2026-1234:epss": "timeout"}
    assert stage["freshness"]["CVE-2026-1234"]["nvd"]["status"] == "available"
