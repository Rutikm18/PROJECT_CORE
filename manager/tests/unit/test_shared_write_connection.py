"""
manager/tests/unit/test_shared_write_connection.py — the shared write
connection must survive a failure, and must not be used by two coroutines at
once.

IntelDB._conn is a single long-lived connection that every writer in the
process shares. Two defects made that arrangement fail in production for days,
both presenting as the same log line — "cannot commit; the transaction is in
error state" — across settings, detection, dedup and case management at once:

  * PgConnection.commit()/rollback() assigned `self._tx = None` *after*
    awaiting. When the await raised (dropped backend, statement timeout,
    concurrent use), the dead Transaction stayed installed. asyncpg then marks
    it FAILED, _ensure_tx() early-returns on `self._tx is not None` so its
    self-healing ROLLBACK never runs, and every subsequent commit on that
    connection raises — until the process restarts.

  * Serialising access was left to each call site and applied at roughly half
    of them. An asyncpg connection cannot be shared concurrently: the loser
    gets "another operation is in progress" and its write is silently lost.
"""
from __future__ import annotations

import asyncio

import pytest

from manager.manager.pg_pool import PgConnection


class _ExplodingTx:
    """Stands in for an asyncpg Transaction whose commit/rollback fails, which
    is what a dropped backend or a concurrent operation produces."""

    def __init__(self) -> None:
        self.rollback_called = False

    async def commit(self):
        raise RuntimeError("cannot commit; the transaction is in error state")

    async def rollback(self):
        self.rollback_called = True
        raise RuntimeError("connection already gone")


def _conn_with(tx) -> PgConnection:
    conn = PgConnection.__new__(PgConnection)   # no real socket needed
    conn._raw = None
    conn._writable = True
    conn._tx = tx
    conn.row_factory = None
    return conn


# ── The wedge ────────────────────────────────────────────────────────────────

async def test_failed_commit_does_not_leave_the_transaction_installed():
    tx = _ExplodingTx()
    conn = _conn_with(tx)

    with pytest.raises(RuntimeError):
        await conn.commit()

    # The whole defect in one assertion: a non-None _tx here means _ensure_tx()
    # will early-return forever and never reach its self-healing ROLLBACK.
    assert conn._tx is None


async def test_failed_commit_attempts_to_reset_the_connection():
    tx = _ExplodingTx()
    with pytest.raises(RuntimeError):
        await _conn_with(tx).commit()
    assert tx.rollback_called is True


async def test_failed_rollback_does_not_leave_the_transaction_installed():
    conn = _conn_with(_ExplodingTx())
    with pytest.raises(RuntimeError):
        await conn.rollback()
    assert conn._tx is None


async def test_commit_is_a_noop_without_an_open_transaction():
    conn = _conn_with(None)
    await conn.commit()          # must not raise
    assert conn._tx is None


# ── The lost writes ──────────────────────────────────────────────────────────

async def test_write_txn_serialises_concurrent_writers(pg_intel_dsn):
    """Twenty coroutines writing through write_txn without holding the lock
    themselves. Before write_txn took the lock, all but one failed with
    "another operation is in progress" and their rows were silently dropped."""
    from manager.manager.indexer import IntelDB

    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        async with idb.write_txn() as conn:
            await conn.execute("CREATE TABLE concurrency_probe(id int primary key)")

        async def writer(n: int):
            async with idb.write_txn() as conn:
                await conn.execute("INSERT INTO concurrency_probe(id) VALUES($1)", (n,))

        results = await asyncio.gather(
            *[writer(i) for i in range(20)], return_exceptions=True
        )
        failures = [r for r in results if isinstance(r, BaseException)]
        assert not failures, f"concurrent writers failed: {failures[:3]}"

        row = await idb._fetchone("SELECT count(*) AS n FROM concurrency_probe", ())
        assert row["n"] == 20, "writes were accepted but lost"
    finally:
        await idb.close()


async def test_write_txn_is_reentrant_for_callers_already_holding_the_lock(pg_intel_dsn):
    """Several call sites wrap write_txn in `async with idb._lock`. Moving the
    lock into write_txn would deadlock every one of them with a plain
    asyncio.Lock, so re-entry by the owning task has to work."""
    from manager.manager.indexer import IntelDB

    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        async with idb.write_txn() as conn:
            await conn.execute("CREATE TABLE reentrant_probe(id int primary key)")

        async def nested(n: int):
            async with idb._lock:                     # outer, as callers do today
                async with idb.write_txn() as conn:   # inner, must not deadlock
                    await conn.execute(
                        "INSERT INTO reentrant_probe(id) VALUES($1)", (n,)
                    )

        await asyncio.wait_for(
            asyncio.gather(*[nested(i) for i in range(10)]), timeout=30
        )
        row = await idb._fetchone("SELECT count(*) AS n FROM reentrant_probe", ())
        assert row["n"] == 10
    finally:
        await idb.close()


async def test_lock_is_released_when_the_body_raises(pg_intel_dsn):
    """A reentrant lock that leaks a hold on the error path would wedge every
    later writer just as thoroughly as the bug it replaced."""
    from manager.manager.indexer import IntelDB

    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        with pytest.raises(RuntimeError):
            async with idb.write_txn():
                raise RuntimeError("boom")
        assert idb._lock.locked() is False

        # And the connection is still usable.
        async with idb.write_txn() as conn:
            await conn.execute("CREATE TABLE after_failure(id int)")
    finally:
        await idb.close()
