from __future__ import annotations

import pytest

from manager.manager.indexer import IntelDB, _SCHEMA, build_validation_run_record


def test_validation_run_schema_is_append_only_and_idempotent() -> None:
    assert "CREATE TABLE IF NOT EXISTS validation_runs" in _SCHEMA
    assert "run_key" in _SCHEMA
    assert "UNIQUE(finding_id, run_key)" in _SCHEMA


def test_validation_run_record_preserves_decision_provenance() -> None:
    finding = {
        "finding_uid": "finding-uid",
        "agent_id": "agent-a",
        "validation_state": "validated",
        "validation_policy_version": "terrain-v1",
        "effective_validation_threshold": 0.75,
        "model_precision_score": 0.91,
        "terrain_score": 0.80,
        "validation_score": 0.80,
        "terrain_validation": {"criteria": [{"id": "rule", "passed": True}]},
        "validation_corroboration": {
            "name": "authoritative_corroboration",
            "status": "partial",
            "source_errors": {"epss": "timeout"},
        },
        "ai_verdict": {
            "provider": "openrouter",
            "model": "anthropic/claude-3.5-haiku",
            "generation_id": "gen-1",
            "prompt_version": "validation-v2",
            "schema_version": "validation-response-v1",
            "tokens_used": 88,
        },
    }

    first = build_validation_run_record(7, finding, "evidence-sha", 1_700_000_000)
    second = build_validation_run_record(7, finding, "evidence-sha", 1_700_000_001)

    assert first["run_key"] == second["run_key"]
    assert first["run_uid"] != second["run_uid"]
    assert first["finding_id"] == 7
    assert first["evidence_revision"] == "evidence-sha"
    assert first["status"] == "validated"
    assert first["policy_version"] == "terrain-v1"
    assert first["provider"] == "openrouter"
    assert first["model"] == "anthropic/claude-3.5-haiku"
    assert first["generation_id"] == "gen-1"
    assert first["gate_results"]["terrain"] == finding["terrain_validation"]
    assert first["gate_results"]["corroboration"] == finding["validation_corroboration"]


@pytest.mark.asyncio
async def test_validation_run_insert_is_conflict_safe() -> None:
    class Connection:
        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple]] = []

        async def execute(self, query: str, args: tuple) -> None:
            self.calls.append((query, args))

    db = object.__new__(IntelDB)
    db._conn = Connection()
    finding = {
        "finding_uid": "finding-uid",
        "agent_id": "agent-a",
        "validation_state": "needs_review",
        "validation_policy_version": "terrain-v1",
        "terrain_score": 0.4,
        "validation_score": 0.4,
    }

    await db._insert_validation_run(8, finding, "evidence-sha", 123.0)

    query, args = db._conn.calls[0]
    assert "ON CONFLICT (finding_id,run_key) DO NOTHING" in query
    assert len(args) == 24
    assert args[2] == 8
    assert args[7] == "needs_review"


@pytest.mark.asyncio
async def test_validation_runs_are_shaped_for_api() -> None:
    async def fetchall(_query: str, args: tuple) -> list[dict]:
        assert args == (9, 25)
        return [{"id": 1, "gate_results": '{"criteria": []}'}]

    db = object.__new__(IntelDB)
    db._fetchall = fetchall

    rows = await db.get_validation_runs(9, limit=25)

    assert rows == [{"id": 1, "gate_results": {"criteria": []}}]
