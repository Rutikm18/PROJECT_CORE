"""
manager/tests/unit/test_payload_ledger.py — outbox/reconciliation ledger.

Pins the Phase-2 mechanism that makes "raw is stored, so it's reprocessable"
actually true: every stored payload is recorded 'received', marked 'processed'
once detection runs, and the reconciler's work-list is exactly the
received-but-not-processed backlog past a grace window. Verifies the ledger
state transitions, the grace/attempt filtering of the reconciler query, the
backlog-collapse, and the health lag metric — against a real Postgres
(pg_manager_dsn / conftest).
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
        await d.ledger_received("agent-1", "ports", 1000.0)
        lag = await d.ledger_lag()
        assert lag["pending"] == 1

        await d.ledger_processed("agent-1", "ports", 1000.0, signal_count=3)
        lag = await d.ledger_lag()
        assert lag["pending"] == 0
    finally:
        await d.close()


async def test_collected_at_float_drift_maps_to_same_row(pg_manager_dsn):
    """received and processed for the SAME payload must collapse to one ledger
    row even when collected_at drifts in fractional precision across the pipeline
    (e.g. a time.time() fallback). The key is floored to the second."""
    d = await _db(pg_manager_dsn)
    try:
        await d.ledger_received("agent-1", "metrics", 1782477291)          # int
        await d.ledger_processed("agent-1", "metrics", 1782477291.322768)  # drifted float, same second
        lag = await d.ledger_lag()
        assert lag["pending"] == 0, "float drift within the same second must not leave a phantom pending row"
    finally:
        await d.close()


async def test_received_is_idempotent(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        await d.ledger_received("agent-1", "ports", 2000.0)
        await d.ledger_received("agent-1", "ports", 2000.0)   # dup — no error, no double row
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
        await d.ledger_received("agent-1", "ports", 4000.0)
        rows = await d.ledger_unprocessed_sections(grace_sec=120, max_attempts=5)
        assert rows == []

        # A receipt well in the past — outside grace, must appear.
        await d.ledger_received("agent-1", "packages", 4100.0)
        # backdate its received_at directly
        async with d._pool.write() as db:
            await db.execute(
                "UPDATE payload_ledger SET received_at = ? WHERE section='packages'",
                (time.time() - 600,),
            )
            await db.commit()
        rows = await d.ledger_unprocessed_sections(grace_sec=120, max_attempts=5)
        secs = {r["section"] for r in rows}
        assert "packages" in secs and "ports" not in secs
    finally:
        await d.close()


async def test_reconcile_section_collapses_backlog(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        for ts in (5000.0, 5001.0, 5002.0):
            await d.ledger_received("agent-1", "apps", ts)
        assert (await d.ledger_lag())["pending"] == 3

        # Reconcile up to the latest — the whole backlog collapses to processed.
        n = await d.ledger_reconcile_section("agent-1", "apps", 5002.0)
        assert n == 3
        assert (await d.ledger_lag())["pending"] == 0
    finally:
        await d.close()


async def test_reconciler_query_respects_max_attempts(pg_manager_dsn):
    d = await _db(pg_manager_dsn)
    try:
        await d.ledger_received("agent-1", "sbom", 6000.0)
        async with d._pool.write() as db:
            await db.execute(
                "UPDATE payload_ledger SET received_at = ?, attempts = 5 WHERE section='sbom'",
                (time.time() - 600,),
            )
            await db.commit()
        # attempts (5) >= max_attempts (5) → excluded from the work-list (gave up).
        rows = await d.ledger_unprocessed_sections(grace_sec=120, max_attempts=5)
        assert all(r["section"] != "sbom" for r in rows)
    finally:
        await d.close()
