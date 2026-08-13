from __future__ import annotations

import pytest

from manager.manager.indexer import IntelDB


@pytest.mark.asyncio
async def test_validation_observability_surfaces_privacy_safe_alerts() -> None:
    db = object.__new__(IntelDB)

    async def fetchall(query: str, _args: tuple):
        if "FROM findings" in query:
            return [
                {"validation_state": "validated", "n": 8},
                {"validation_state": "needs_review", "n": 2},
            ]
        if "GROUP BY status" in query:
            return [{"status": "validated", "n": 4}]
        if "GROUP BY provider,model" in query:
            return [{
                "provider": "openrouter", "model": "approved/model", "calls": 3,
                "tokens": 90, "cost_usd": 0.03, "latency_seconds": 0.2,
            }]
        if "error_class" in query:
            return [{"error_class": "llm_timeout", "n": 1}]
        if "validation_recompute_jobs" in query:
            return [{"state": "running", "n": 1, "oldest_created_at": 1.0}]
        if "rule_fp_stats" in query:
            return [{"rule_id": "AL-DEV-001", "tp": 9, "fp": 1}]
        raise AssertionError(query)

    async def fetchone(query: str, _args: tuple):
        assert "terrain_id NOT IN" in query
        return {"n": 2}

    db._fetchall = fetchall
    db._fetchone = fetchone

    report = await db.get_validation_observability(hours=24)

    assert report["current_states"] == {"validated": 8, "needs_review": 2}
    assert report["providers"][0]["provider"] == "openrouter"
    assert report["providers"][0]["latency_ms"] == 200.0
    assert report["false_positive_by_rule"][0]["false_positive_rate"] == 0.1
    assert report["analyst_overrides"] == 1
    assert {alert["code"] for alert in report["alerts"]} == {
        "unknown_terrain", "validation_errors", "validation_backlog",
    }
    assert "prompt" not in str(report).lower()
