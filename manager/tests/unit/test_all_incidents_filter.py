"""
manager/tests/unit/test_all_incidents_filter.py — All Incidents threshold filter.

The All Incidents page (GET /api/v1/detection/all) now applies the configured
Settings → Validation threshold: only findings whose precision_score ≥ threshold
are shown. This pins the data-layer contract that endpoint relies on — a
below-threshold finding is excluded by the precision floor, and dropping the
floor (validated_only=false) brings it back.

Uses pg_intel_dsn (conftest.py) — a freshly CREATEd, then DROPped, real
Postgres database per test.
"""
from __future__ import annotations

import time

from manager.manager.indexer import IntelDB


async def _seed(idb, item_key, precision):
    await idb.upsert_finding(
        {"agent_id": "a1", "category": "port", "item_key": item_key,
         "title": item_key, "severity": "high", "precision_score": precision},
        time.time(),
    )


async def test_precision_floor_filters_all_incidents(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "high_conf", 0.95)
        await _seed(idb, "low_conf", 0.50)

        # All Incidents with the threshold applied (e.g. global 0.90) → only high.
        above = {r["item_key"] for r in await idb.get_soc_findings(min_precision=0.90)}
        assert "high_conf" in above
        assert "low_conf" not in above

        # validated_only=false equivalent (no floor) → both visible.
        everything = {r["item_key"] for r in await idb.get_soc_findings()}
        assert {"high_conf", "low_conf"} <= everything
    finally:
        await idb.close()


async def test_ninety_percent_bar_shows_only_above(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "p_92", 0.92)
        await _seed(idb, "p_88", 0.88)
        # Set bar to 0.90 → 0.92 shows, 0.88 hidden ("set 90% → ≥90% only").
        keys = {r["item_key"] for r in await idb.get_soc_findings(min_precision=0.90)}
        assert keys == {"p_92"}
    finally:
        await idb.close()
