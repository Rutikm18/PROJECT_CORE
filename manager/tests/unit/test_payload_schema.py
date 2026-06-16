"""
manager/tests/unit/test_payload_schema.py — ingest payload-schema validation.

Historically only the envelope was validated; the decrypted payload was read
with silent defaults, so missing/empty inner fields became stored blanks with no
signal. These tests pin the new contract: validate_payload reports exactly which
required fields are missing/empty, distinguishes an empty collection from a
broken payload, and flags a collector-error section — and the ingest counter
turns those reports into a per-field metric.
"""
from __future__ import annotations

from shared.wire import (
    RECOMMENDED_PAYLOAD_FIELDS,
    REQUIRED_PAYLOAD_FIELDS,
    validate_payload,
)


def _full_payload(**overrides):
    p = {
        "agent_id": "mac-001",
        "section": "metrics",
        "collected_at": 1_700_000_000,
        "agent_name": "Rutik's Mac",
        "os": "macos",
        "os_version": "14.4",
        "arch": "arm64",
        "hostname": "rutik-mbp",
        "data": {"cpu": 12.5},
    }
    p.update(overrides)
    return p


# ── Happy path ────────────────────────────────────────────────────────────

def test_complete_payload_is_ok():
    r = validate_payload(_full_payload())
    assert r["ok"] is True
    assert r["missing"] == [] and r["empty"] == []
    assert r["recommended_missing"] == []
    assert r["data_empty"] is False and r["data_error"] is False


# ── Required fields ─────────────────────────────────────────────────────────

def test_missing_required_field_flagged():
    p = _full_payload()
    del p["agent_id"]
    r = validate_payload(p)
    assert r["ok"] is False
    assert "agent_id" in r["missing"]


def test_empty_required_field_flagged_separately_from_missing():
    r = validate_payload(_full_payload(section=""))
    assert r["ok"] is False
    assert "section" in r["empty"]
    assert "section" not in r["missing"]


# ── data: empty vs error vs present ─────────────────────────────────────────

def test_empty_data_is_distinct_signal():
    r = validate_payload(_full_payload(data={}))
    assert r["ok"] is False
    assert r["data_empty"] is True
    assert r["data_error"] is False


def test_collector_error_section_detected():
    r = validate_payload(_full_payload(data={"error": "timed out"}))
    assert r["ok"] is False
    assert r["data_error"] is True
    assert r["data_empty"] is False


# ── Recommended fields degrade but don't break routability ──────────────────

def test_missing_recommended_field_does_not_fail_ok():
    p = _full_payload()
    del p["hostname"]
    r = validate_payload(p)
    assert r["ok"] is True                       # still routable
    assert "hostname" in r["recommended_missing"]


def test_blank_recommended_field_reported():
    r = validate_payload(_full_payload(hostname=""))
    assert "hostname" in r["recommended_missing"]
    assert r["ok"] is True


# ── Defensive ───────────────────────────────────────────────────────────────

def test_non_mapping_payload_is_not_ok():
    r = validate_payload(None)  # type: ignore[arg-type]
    assert r["ok"] is False
    assert set(r["missing"]) == set(REQUIRED_PAYLOAD_FIELDS)


def test_contract_constants_are_disjoint():
    # A field can't be both required and merely recommended.
    assert REQUIRED_PAYLOAD_FIELDS.isdisjoint(RECOMMENDED_PAYLOAD_FIELDS)


# ── Observability counter (ingest module) ───────────────────────────────────

def test_schema_gap_counter_accumulates():
    from manager.manager.api import ingest as ing

    ing._SCHEMA_GAPS.clear()
    r = validate_payload(_full_payload(data={"error": "x"}, hostname=""))
    ing._record_schema_gaps("mac-001", "metrics", r)
    stats = ing.schema_gap_stats()
    assert stats.get("data_error") == 1
    assert stats.get("recommended_missing:hostname") == 1
