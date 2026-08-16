"""
Regression tests for the "Validated Findings page is nearly empty" defect.

Two root causes, both fixed here:

  1. The page's default threshold defaulted to the 0.90 AI-precision *promotion*
     gate, but the terrain score floors a single-anchor "smoking gun" finding at
     0.80. So every definitive finding (KEV CVE, malicious-hash IOC, SIP off, …)
     was filtered out and the page came up empty. The default must sit at/below
     the anchor floor.

  2. Reachability criteria (package_running / service_reachable) scored 0 when
     unconfirmed, but a vulnerable *library* is never itself a process — 0 is
     wrong, it should be n/a. Scoring 0 dragged every library CVE below any
     threshold. They now return n/a (dropped from the weight pool).
"""
from __future__ import annotations

import pytest

from manager.manager.attacklens.terrain_validators import evaluate_finding
from manager.manager.attacklens.ai_validator import (
    TERRAIN_VALIDATION_THRESHOLD,
    _load_validation_settings,
    invalidate_validation_settings_cache,
)

# The anchor floor hardcoded in terrain_validators.evaluate_finding.
_ANCHOR_FLOOR = 0.80


class _EmptyOrgSettingsDB:
    """Manager/intel DB stub with no org_settings rows → pure defaults."""

    async def _fetchall(self, *_args, **_kwargs):
        return []


def _kev_library_finding() -> dict:
    """A KEV-listed CVE in a library that is NOT itself a running process —
    the single most common Validated-Findings case, and the one that vanished."""
    return {
        "category": "package",
        "terrain_id": "origin",
        "kev": True,
        "cvss_score": 9.1,
        "evidence": {"name": "openssl", "cve_id": "CVE-2022-3602"},
    }


def test_default_page_threshold_is_at_or_below_anchor_floor():
    # The invariant that keeps definitive findings visible: a single smoking-gun
    # signal floors the score at 0.80, so the page filter must not exceed that.
    assert TERRAIN_VALIDATION_THRESHOLD <= _ANCHOR_FLOOR


@pytest.mark.asyncio
async def test_load_validation_settings_defaults_to_terrain_threshold():
    invalidate_validation_settings_cache()
    try:
        settings = await _load_validation_settings(_EmptyOrgSettingsDB())
        assert settings["global"] == TERRAIN_VALIDATION_THRESHOLD
    finally:
        invalidate_validation_settings_cache()


def test_definitive_kev_finding_passes_default_threshold():
    report = evaluate_finding(_kev_library_finding(), {"kev_hit": True}, None)
    assert report["anchor_hit"] is True
    # Was 0.80 vs a 0.90 default → hidden. Now 0.80 ≥ 0.75 default → visible.
    assert report["score"] >= TERRAIN_VALIDATION_THRESHOLD


def test_unconfirmed_reachability_is_na_not_zero():
    report = evaluate_finding(_kev_library_finding(), {"kev_hit": True}, None)
    status = {c["name"]: c["status"] for c in report["criteria"]}
    assert status["package_running"] == "skipped"
    assert status["service_reachable"] == "skipped"
    # A skipped criterion contributes nothing and is not counted as met.
    reach = [c for c in report["criteria"] if c["name"] == "package_running"][0]
    assert reach["skipped"] is True and reach["contribution"] == 0.0


def test_confirmed_reachability_still_counts_as_met():
    report = evaluate_finding(
        {"category": "package", "terrain_id": "origin", "evidence": {"name": "nginx"}},
        {"package_running": True, "port_open": True},
        None,
    )
    status = {c["name"]: c["status"] for c in report["criteria"]}
    assert status["package_running"] == "met"
    assert status["service_reachable"] == "met"


def test_weak_non_anchor_finding_still_hidden_no_flood():
    # Precision guard: dropping unconfirmed reachability must NOT inflate a weak
    # finding across the bar. Non-KEV, moderate CVSS, no EPSS/exploit/AI.
    report = evaluate_finding(
        {"category": "package", "terrain_id": "origin", "cvss_score": 8.0,
         "evidence": {"name": "log4j-core"}},
        {},
        None,
    )
    assert report["anchor_hit"] is False
    assert report["score"] < TERRAIN_VALIDATION_THRESHOLD
