"""
manager/tests/unit/test_payload_ledger.py — outbox/reconciliation ledger.

Pins the event-level detection outbox and durable chunk completion against real
Postgres (pg_manager_dsn / conftest).
"""
from __future__ import annotations

import time

import pytest

from manager.manager.db import Database


async def _db(dsn) -> Database:
    d = Database(dsn)
    await d.init()
    # Ledger has an FK-free schema, but received/processed reference agent rows
    # only implicitly — seed an agent so any incidental joins are safe.
    await d.upsert_agent("agent-1", "T", "127.0.0.1")
    return d


async def test_received_then_processed_transitions(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        await d.ledger_received(
            "agent-1", "ports", 1000.0, event_id="event-1", data=[{"port": 22}],
        )
        lag = await d.ledger_lag()
        assert lag["pending"] == 1

        assert await d.ledger_chunk_processed("event-1", 0, 1, signal_count=3)
        assert (await d.ledger_lag())["pending"] == 1
        await d.ledger_correlated("event-1")
        lag = await d.ledger_lag()
        assert lag["pending"] == 0
    finally:
        await d.close()


async def test_same_agent_section_timestamp_keeps_distinct_events(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        await d.ledger_received(
            "agent-1", "metrics", 1782477291, event_id="event-a", data={"cpu_pct": 1},
        )
        await d.ledger_received(
            "agent-1", "metrics", 1782477291, event_id="event-b", data={"cpu_pct": 2},
        )
        assert (await d.ledger_lag())["pending"] == 2
        assert await d.ledger_chunk_processed("event-a", 0, 1)
        await d.ledger_correlated("event-a")
        assert (await d.ledger_lag())["pending"] == 1
    finally:
        await d.close()


async def test_received_is_idempotent(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        kwargs = {"event_id": "event-2", "data": [{"port": 80}]}
        await d.ledger_received("agent-1", "ports", 2000.0, **kwargs)
        await d.ledger_received("agent-1", "ports", 2000.0, **kwargs)
        lag = await d.ledger_lag()
        assert lag["pending"] == 1
    finally:
        await d.close()


async def test_processed_without_received_still_terminal(pg_manager_dsn):
    """Sync path may process a payload that was never ledger_received — it must
    still record a terminal processed state, not look perpetually pending."""
    d = await _db(pg_manager_dsn)
    try:
        await d.ledger_processed("agent-1", "users", 3000.0, signal_count=0)
        lag = await d.ledger_lag()
        assert lag["pending"] == 0
    finally:
        await d.close()


async def test_reconciler_query_respects_grace_window(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        # Fresh receipt (now) — inside grace, must NOT be in the work-list yet.
        await d.ledger_received(
            "agent-1", "ports", 4000.0, event_id="fresh", data=[{"port": 80}],
        )
        rows = await d.ledger_unprocessed_events(grace_sec=120, max_attempts=5)
        assert rows == []

        # A receipt well in the past — outside grace, must appear.
        await d.ledger_received(
            "agent-1", "packages", 4100.0, event_id="old", data=[{"name": "x"}],
        )
        # backdate its received_at directly
        async with d._pool.write() as db:
            await db.execute(
                "UPDATE detection_events SET received_at = ? WHERE event_id='old'",
                (time.time() - 600,),
            )
            await db.commit()
        rows = await d.ledger_unprocessed_events(grace_sec=120, max_attempts=5)
        assert [r["event_id"] for r in rows] == ["old"]
    finally:
        await d.close()


async def test_chunk_completion_is_durable_and_exactly_once(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        data = [{"name": str(i)} for i in range(75)]
        await d.ledger_received(
            "agent-1", "apps", 5000.0, event_id="chunked", data=data, chunk_total=2,
        )
        assert not await d.ledger_chunk_processed("chunked", 1, 2, signal_count=2)
        assert not await d.ledger_chunk_processed("chunked", 1, 2, signal_count=2)
        assert await d.ledger_chunk_processed("chunked", 0, 2, signal_count=1)
        assert await d.ledger_chunk_processed("chunked", 0, 2, signal_count=1)
        await d.ledger_correlated("chunked")
        assert not await d.ledger_chunk_processed("chunked", 0, 2, signal_count=1)
        assert (await d.ledger_lag())["pending"] == 0
        payload = await d.ledger_event_payload("chunked")
        assert payload["data"] == data
    finally:
        await d.close()


async def test_reconciler_query_respects_max_attempts(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        await d.ledger_received(
            "agent-1", "sbom", 6000.0, event_id="give-up", data=[{"name": "x"}],
        )
        async with d._pool.write() as db:
            await db.execute(
                "UPDATE detection_events SET received_at = ?, attempts = 5 "
                "WHERE event_id='give-up'",
                (time.time() - 600,),
            )
            await db.commit()
        # attempts (5) >= max_attempts (5) → excluded from the work-list (gave up).
        rows = await d.ledger_unprocessed_events(grace_sec=120, max_attempts=5)
        assert all(r["event_id"] != "give-up" for r in rows)
    finally:
        await d.close()


async def test_upgrade_adds_correlation_completion_without_replaying_old_rows(
    pg_manager_dsn,
):
    d = await _db(pg_manager_dsn)
    try:
        await d.ledger_processed(
            "agent-1", "metrics", 7000.0, event_id="pre-upgrade",
        )
        async with d._pool.write() as db:
            await db.execute("DROP INDEX IF EXISTS idx_detection_events_incomplete")
            await db.execute("ALTER TABLE detection_events DROP COLUMN correlated_at")
            await db.commit()
    finally:
        await d.close()

    upgraded = Database(pg_manager_dsn)
    await upgraded.init()
    try:
        assert (await upgraded.ledger_lag())["pending"] == 0
        async with upgraded._pool.read() as db:
            async with db.execute(
                "SELECT correlated_at FROM detection_events WHERE event_id=?",
                ("pre-upgrade",),
            ) as cur:
                row = await cur.fetchone()
        assert row["correlated_at"] is not None
    finally:
        await upgraded.close()
