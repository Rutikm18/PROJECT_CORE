"""
manager/tests/unit/test_ingest_health.py — per-stage ingest observability.

The pipeline has silent failure modes (queue workers down, insert_payload
non-fatal, swallowed detection errors). These counters turn "no data" into
"data stopped at stage X" so an operator can pinpoint the break.
"""
from __future__ import annotations

from manager.manager.api import ingest as ing


def setup_function(_):
    ing._INGEST_STATS.clear()
    ing._LAST_INGEST_ERROR.update({"stage": None, "error": None, "ts": None})


def test_stage_counter_increments():
    ing._stat("received")
    ing._stat("received")
    ing._stat("stored_raw")
    s = ing.ingest_stats()
    assert s["counters"]["received"] == 2
    assert s["counters"]["stored_raw"] == 1


def test_note_error_records_stage_and_last_error():
    ing._note_error("index", "disk full")
    s = ing.ingest_stats()
    assert s["counters"]["index_failed"] == 1
    assert s["last_error"]["stage"] == "index"
    assert "disk full" in s["last_error"]["error"]


def test_ingest_stats_shape():
    s = ing.ingest_stats()
    # Stable shape the health endpoint depends on.
    assert set(s) >= {"counters", "last_error", "schema_gaps", "strict_payload"}
    assert isinstance(s["counters"], dict)
    assert isinstance(s["strict_payload"], bool)
