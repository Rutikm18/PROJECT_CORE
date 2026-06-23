"""
manager/manager/pg_pool.py — Postgres connection pool, API-compatible with
the original pool.py's SQLitePool.

Why a compatibility shim instead of rewriting every call site: db.py and
indexer.py have ~150 query call sites written against aiosqlite's specific
API shape (`?` placeholders, `await conn.execute(...)` AND
`async with conn.execute(...) as cur:` both working, implicit
transaction-per-commit). Reproducing that exact shape against asyncpg here
means the migration touches SCHEMA + actual SQL syntax differences (the part
that matters), not ~150 mechanical call-site rewrites (the part that
doesn't).

Two things this shim must get right that aiosqlite's semantics depend on:

  1. `?` → `$1,$2,...` placeholder translation. asyncpg requires positional
     `$N` parameters; SQLite/aiosqlite use `?`. Translated once per query,
     not per call site.

  2. Implicit transactions. sqlite3/aiosqlite default to "a transaction is
     open from the first write statement until .commit()/.rollback()" —
     the existing code relies on this for atomicity (e.g. upsert_finding's
     INSERT, then a SELECT to read back the new id, then an UPDATE, all
     inside one commit). asyncpg has no implicit-transaction mode — every
     statement autocommits unless you explicitly wrap it. This pool opens a
     transaction on the FIRST statement after the last commit/rollback (or
     after checkout) and keeps it open until .commit() is called, mirroring
     the old behavior exactly — and re-opens a fresh one immediately after,
     since the existing code sometimes calls .commit() more than once
     within one `async with pool.write()` block.
"""
from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from typing import Any, Optional, Sequence

import asyncpg

log = logging.getLogger("manager.pg_pool")

_QMARK_RE = re.compile(r"\?")


def _translate(query: str) -> str:
    """'? ? ?' -> '$1 $2 $3'. Cached per unique query string by the caller's
    query patterns being a small, fixed set (not per-call dynamic SQL), so no
    cache is needed here — re.sub on a short string is microseconds."""
    counter = iter(range(1, 10_000))
    return _QMARK_RE.sub(lambda _m: f"${next(counter)}", query)


def _is_returning_rows(query: str) -> bool:
    q = query.strip().upper()
    return q.startswith(("SELECT", "WITH", "EXPLAIN", "PRAGMA")) or " RETURNING " in q


class _Cursor:
    """Mimics aiosqlite's Cursor: .fetchone()/.fetchall()/.rowcount, plus
    being awaitable as a no-op (the result is already materialized).

    Rows are raw asyncpg.Record objects — NOT wrapped — because Record already
    satisfies every access pattern aiosqlite.Row (modeled on sqlite3.Row) does:
    positional (`row[0]`), by-name (`row["col"]`), `dict(row)`, `len(row)`, and
    value-iteration. Verified directly against asyncpg before relying on it —
    wrapping rows in a custom dict subclass would have silently broken every
    positional-index call site in db.py/indexer.py (there are over a dozen)."""

    def __init__(self, rows: list[asyncpg.Record], rowcount: int):
        self._rows = rows
        self.rowcount = rowcount
        self._idx = 0

    async def fetchone(self) -> Optional[asyncpg.Record]:
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    async def fetchall(self) -> list[asyncpg.Record]:
        rest = self._rows[self._idx:]
        self._idx = len(self._rows)
        return rest

    def __aiter__(self):
        return self

    async def __anext__(self) -> asyncpg.Record:
        row = await self.fetchone()
        if row is None:
            raise StopAsyncIteration
        return row


class _Execute:
    """Dual-protocol result of conn.execute(...): usable as
    `await conn.execute(...)` (returns a _Cursor) AND as
    `async with conn.execute(...) as cur:` (same _Cursor, no-op exit) — the
    exact two call shapes used throughout db.py/indexer.py."""

    __slots__ = ("_coro",)

    def __init__(self, coro):
        self._coro = coro

    def __await__(self):
        return self._coro.__await__()

    async def __aenter__(self) -> _Cursor:
        return await self._coro

    async def __aexit__(self, *exc) -> bool:
        return False


class PgConnection:
    """API-compatible stand-in for an aiosqlite.Connection, backed by one
    asyncpg.Connection. row_factory is accepted-and-ignored (kept so existing
    `db.row_factory = aiosqlite.Row` lines don't need to be deleted)."""

    def __init__(self, raw: asyncpg.Connection, writable: bool):
        self._raw = raw
        self._writable = writable
        self._tx: Optional[asyncpg.transaction.Transaction] = None
        self.row_factory = None  # accepted for API compatibility, unused

    async def _ensure_tx(self) -> None:
        if not self._writable or self._tx is not None:
            return
        if self._raw.is_in_transaction():
            # Self-healing recovery: asyncpg's own bookkeeping says a
            # transaction is already open on this raw connection, but our
            # wrapper lost track of it (self._tx is None) — e.g. a prior
            # commit()/rollback() never got the chance to run if a coroutine
            # was cancelled between the SQL executing and our state update.
            # Connection.transaction().start() would unconditionally raise
            # "cannot use Connection.transaction() in a manually started
            # transaction" here (observed live) instead of recovering — force
            # the connection back to a known state first.
            try:
                await self._raw.execute("ROLLBACK")
            except Exception:
                pass
        tx = self._raw.transaction()
        try:
            await tx.start()
        except BaseException:
            # If start() itself fails or is cancelled (observed during app
            # shutdown — a background task's write was in-flight when
            # shutdown cancelled it), self._tx must NOT be left pointing at
            # a constructed-but-never-started Transaction. Anything that
            # later sees self._tx is not None (e.g. write()'s "auto-commit
            # what the caller forgot" safety net) would call .commit() on
            # it and asyncpg raises "transaction is not yet started".
            self._tx = None
            raise
        self._tx = tx

    async def _on_error(self, exc: BaseException) -> None:
        """Postgres-specific: unlike SQLite, ANY failed statement poisons the
        REST of the current transaction (InFailedSQLTransactionError) until a
        rollback — catching the Python exception alone isn't enough, every
        later statement on this connection fails too until the transaction is
        reset. This is called from every write path so existing call sites'
        `except Exception: pass`-style handling (written against SQLite's much
        more forgiving behavior — a caught error there doesn't affect later
        statements) keeps working unchanged against Postgres. The original
        exception is always re-raised unchanged after rolling back."""
        if self._tx is not None:
            try:
                await self._tx.rollback()
            except Exception:
                pass  # connection may already be unusable; let the original exc propagate
            self._tx = None

    async def _run(self, query: str, params: Sequence[Any]) -> _Cursor:
        await self._ensure_tx()
        pg_query = _translate(query)
        args = tuple(params)
        try:
            if _is_returning_rows(pg_query):
                records = await self._raw.fetch(pg_query, *args)
                return _Cursor(records, len(records))
            status = await self._raw.execute(pg_query, *args)
            # asyncpg status strings: "INSERT 0 1", "UPDATE 3", "DELETE 2", "CREATE TABLE"
            parts = status.split()
            rowcount = int(parts[-1]) if parts and parts[-1].isdigit() else 0
            return _Cursor([], rowcount)
        except Exception as exc:
            await self._on_error(exc)
            raise

    def execute(self, query: str, params: Sequence[Any] = ()) -> _Execute:
        return _Execute(self._run(query, params))

    async def executemany(self, query: str, seq_of_params: Sequence[Sequence[Any]]) -> None:
        await self._ensure_tx()
        pg_query = _translate(query)
        try:
            await self._raw.executemany(pg_query, [tuple(p) for p in seq_of_params])
        except Exception as exc:
            await self._on_error(exc)
            raise

    def executescript(self, sql: str) -> _Execute:
        """asyncpg's execute() natively runs multiple ;-separated statements
        in one call (unlike aiosqlite, which needed this separate method) —
        schema-creation scripts work unchanged. Dual-protocol return (like
        execute()) because the existing code calls this BOTH ways:
        `await conn.executescript(...)` (db.py) AND
        `async with conn.executescript(...): pass` (indexer.py)."""
        async def _run():
            await self._ensure_tx()
            try:
                await self._raw.execute(sql)
            except Exception as exc:
                await self._on_error(exc)
                raise
            return None
        return _Execute(_run())

    async def commit(self) -> None:
        if self._tx is not None:
            await self._tx.commit()
            self._tx = None
        # Mirrors sqlite3: a new implicit transaction starts on the next
        # write, so code that commits more than once per checkout still works.

    async def rollback(self) -> None:
        if self._tx is not None:
            await self._tx.rollback()
            self._tx = None


class PgPool:
    """Drop-in replacement for pool.py's SQLitePool. Same usage:

        pool = PgPool("postgresql://user:pass@host/dbname")
        await pool.init()
        async with pool.read() as conn: ...
        async with pool.write() as conn: ...
        await pool.close()

    Unlike SQLitePool there is no meaningful reader/writer distinction at the
    Postgres level (it handles concurrent writers natively) — read() and
    write() both draw from one asyncpg.Pool. write() additionally wraps the
    checkout in the implicit-transaction behavior described in PgConnection;
    read() does not (reads never need it, and skipping it avoids holding
    needless transactions open).
    """

    def __init__(self, dsn: str, readers: int = 4, min_size: int = 2, max_size: int = 10) -> None:
        self.dsn = dsn
        self._readers = readers  # kept for API/log-message parity; unused by asyncpg
        self._min_size = min_size
        self._max_size = max_size
        self._pool: Optional[asyncpg.Pool] = None

    async def init(self) -> None:
        self._pool = await asyncpg.create_pool(
            self.dsn, min_size=self._min_size, max_size=self._max_size,
        )
        log.info("PgPool ready: %s (pool size %d-%d)",
                 _redact_dsn(self.dsn), self._min_size, self._max_size)

    @asynccontextmanager
    async def read(self, timeout: float = 5.0):
        assert self._pool is not None, "PgPool.init() not called"
        async with self._pool.acquire(timeout=timeout) as raw:
            yield PgConnection(raw, writable=False)

    @asynccontextmanager
    async def write(self, timeout: float = 10.0):
        assert self._pool is not None, "PgPool.init() not called"
        async with self._pool.acquire(timeout=timeout) as raw:
            conn = PgConnection(raw, writable=True)
            try:
                yield conn
            finally:
                # Auto-commit any transaction the caller forgot to close
                # explicitly — never leave a connection checked back into
                # the pool mid-transaction.
                if conn._tx is not None:
                    await conn.commit()

    async def ping(self) -> bool:
        try:
            async with self.read(timeout=2.0) as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()


def _redact_dsn(dsn: str) -> str:
    return re.sub(r"://([^:]+):[^@]+@", r"://\1:***@", dsn)
