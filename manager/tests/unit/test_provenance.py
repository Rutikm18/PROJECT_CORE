"""
manager/tests/unit/test_provenance.py — raw-evidence provenance.

Every finding must be verifiable against the raw telemetry shown in Deep
Analysis. The engine stamps each finding's evidence with `_source`
(agent_id / section / collected_at) pointing at the raw payload it came from,
and the detection API lifts that to top-level `source_*` fields so an analyst
can locate the exact raw row via /api/v1/raw/query.
"""
from __future__ import annotations

from manager.manager.api.detection import _enrich
from manager.manager.attacklens.engine import AttackLensEngine


def test_stamp_provenance_sets_source():
    ev: dict = {"port": 4444, "pid": 9}
    AttackLensEngine._stamp_provenance(ev, "mac-1", "ports", 1_700_000_000.0)
    assert ev["_source"] == {
        "agent_id": "mac-1", "section": "ports", "collected_at": 1_700_000_000,
    }


def test_stamp_provenance_does_not_overwrite():
    # A multi-section cluster's primary signal keeps its own provenance.
    ev = {"_source": {"agent_id": "mac-1", "section": "processes", "collected_at": 1}}
    AttackLensEngine._stamp_provenance(ev, "mac-1", "ports", 999.0)
    assert ev["_source"]["section"] == "processes"   # unchanged


def test_stamp_provenance_handles_missing_collected_at():
    ev: dict = {}
    AttackLensEngine._stamp_provenance(ev, "mac-1", "ports", None)
    assert ev["_source"]["collected_at"] is None


def test_enrich_lifts_provenance_to_top_level():
    raw_finding = {
        "agent_id": "mac-1",
        "category": "port",
        "evidence": {"port": 4444, "_source": {
            "agent_id": "mac-1", "section": "ports", "collected_at": 1_700_000_000,
        }},
    }
    out = _enrich(raw_finding)
    assert out["source_section"] == "ports"
    assert out["source_collected_at"] == 1_700_000_000
    assert out["source_agent_id"] == "mac-1"


def test_enrich_without_provenance_does_not_crash():
    out = _enrich({"agent_id": "mac-1", "category": "port", "evidence": {"port": 22}})
    assert "source_section" not in out or out.get("source_section") is None
