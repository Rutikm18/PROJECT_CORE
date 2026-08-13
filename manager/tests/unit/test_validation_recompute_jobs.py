from __future__ import annotations

import time

import pytest

from manager.manager.indexer import IntelDB


async def _seed(idb: IntelDB, count: int) -> None:
    for index in range(count):
        await idb.upsert_finding({
            "agent_id": f"agent-{index % 3}",
            "category": "developer_security" if index % 2 else "port",
            "item_key": f"finding-{index}",
            "title": f"Finding {index}",
            "severity": "high",
            "score": 8.0,
            "source": "rule:test",
            "rule_id": "AL-DEV-003" if index % 2 else "port-test",
            "evidence": {"path": f"/tmp/{index}"},
        }, time.time())


@pytest.mark.asyncio
async def test_recompute_job_is_bounded_resumable_and_avoids_sibling_n_plus_one(
    pg_intel_dsn,
) -> None:
    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        await _seed(idb, 12)
        job = await idb.create_validation_recompute_job(target_limit=12)

        original_fetchall = idb._fetchall
        finding_reads: list[str] = []

        async def counted(sql, args):
            if "FROM findings" in sql:
                finding_reads.append(sql)
            return await original_fetchall(sql, args)

        idb._fetchall = counted  # type: ignore[method-assign]
        first = await idb.run_validation_recompute_batch(job["job_uid"], batch_size=5)
        assert first is not None
        assert first["state"] == "running"
        assert first["scanned"] == first["updated"] == 5
        assert first["cursor_id"] > 0
        # One candidate page + one sibling-context preload, independent of N.
        assert len(finding_reads) == 2

        finding_reads.clear()
        second = await idb.run_validation_recompute_batch(job["job_uid"], batch_size=5)
        final = await idb.run_validation_recompute_batch(job["job_uid"], batch_size=5)
        assert second is not None and final is not None
        assert second["scanned"] == 10
        assert final["state"] == "completed"
        assert final["scanned"] == final["updated"] == 12
        assert sum(final["histogram"].values()) == 12
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_recompute_job_can_be_cancelled_and_not_resumed(pg_intel_dsn) -> None:
    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        await _seed(idb, 4)
        job = await idb.create_validation_recompute_job(target_limit=4)
        cancelled = await idb.cancel_validation_recompute_job(job["job_uid"])
        resumed = await idb.run_validation_recompute_batch(job["job_uid"], batch_size=2)

        assert cancelled is not None and cancelled["state"] == "cancelled"
        assert resumed is not None and resumed["state"] == "cancelled"
        assert resumed["scanned"] == resumed["updated"] == 0
    finally:
        await idb.close()
