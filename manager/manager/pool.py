"""
manager/pool.py — SQLite connection pool + per-agent rate control.

Connection model (WAL mode):
  ReadPool  — N persistent aiosqlite connections, checked out via Queue.
              SQLite WAL allows multiple true concurrent readers.
  WriteConn — Single persistent connection with asyncio.Lock.
              SQLite serialises writers at the C level; we hold the lock
              so asyncio coroutines don't queue up inside SQLite itself.

Rate control per agent:
  TokenBucket  — classic token-bucket; allows short bursts while bounding
                 the steady-state request rate per agent.
  AgentQueue   — per-agent asyncio.Semaphore so a single misbehaving agent
                 (or network burst) never starves other agents.  Max
                 concurrent ingest calls per agent is bounded.

Algorithm choice rationale:
  Token bucket is O(1) per check, no background goroutine required, and
  supports bursts naturally (better UX than pure rate limiting).  The
  per-agent semaphore implements fair weighted-round-robin at the asyncio
  event-loop level: once all slots are occupied the event loop yields to
  other tasks (other agents) before re-scheduling the waiting coroutine.
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

import aiosqlite

log = logging.getLogger("manager.pool")

# ── Pragmas applied to every pooled connection ─────────────────────────────
_READ_PRAGMAS = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA cache_size   = -65536;
PRAGMA temp_store   = MEMORY;
PRAGMA busy_timeout = 5000;
PRAGMA mmap_size    = 268435456;
"""

_WRITE_PRAGMAS = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA cache_size   = -65536;
PRAGMA temp_store   = MEMORY;
PRAGMA busy_timeout = 10000;
PRAGMA mmap_size    = 268435456;
PRAGMA wal_autocheckpoint = 1000;
"""


class SQLitePool:
    """
    Persistent connection pool for a single SQLite (WAL-mode) database.

    Usage:
        pool = SQLitePool("data/manager.db", readers=4)
        await pool.init()

        async with pool.read() as conn:
            rows = await conn.execute("SELECT ...").fetchall()

        async with pool.write() as conn:
            await conn.execute("INSERT ...")
            await conn.commit()

        await pool.close()
    """

    def __init__(self, path: str, readers: int = 4) -> None:
        self.path = path
        self._readers = readers
        self._pool: asyncio.Queue[aiosqlite.Connection] = asyncio.Queue(readers)
        self._write_conn: Optional[aiosqlite.Connection] = None
        self._write_lock = asyncio.Lock()

    async def init(self) -> None:
        # Spin up reader connections
        for _ in range(self._readers):
            conn = await aiosqlite.connect(self.path)
            conn.row_factory = aiosqlite.Row
            await conn.executescript(_READ_PRAGMAS)
            await self._pool.put(conn)

        # Single write connection
        self._write_conn = await aiosqlite.connect(self.path)
        self._write_conn.row_factory = aiosqlite.Row
        await self._write_conn.executescript(_WRITE_PRAGMAS)

        log.info("SQLitePool ready: %s (readers=%d)", self.path, self._readers)

    @asynccontextmanager
    async def read(self, timeout: float = 5.0):
        """
        Check out a reader connection.  Waits up to *timeout* seconds before
        raising asyncio.TimeoutError (caller gets 503, not indefinite hang).
        """
        try:
            conn = await asyncio.wait_for(self._pool.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise RuntimeError("DB read-pool exhausted — all connections busy")
        try:
            yield conn
        finally:
            await self._pool.put(conn)

    @asynccontextmanager
    async def write(self):
        """Exclusive write access.  Writers are serialised; readers are not blocked."""
        async with self._write_lock:
            yield self._write_conn

    async def ping(self) -> bool:
        try:
            async with self.read(timeout=2.0) as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                await conn.close()
            except Exception:
                pass
        if self._write_conn:
            try:
                await self._write_conn.close()
            except Exception:
                pass


# ── Per-agent rate control ────────────────────────────────────────────────────

class TokenBucket:
    """
    Token-bucket rate limiter.

    Refills at *rate* tokens/second up to *capacity*.
    `consume()` is O(1) and lock-free (single-threaded asyncio).
    """

    __slots__ = ("rate", "capacity", "_tokens", "_last")

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self._tokens: float = capacity
        self._last: float = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    @property
    def available(self) -> float:
        now = time.monotonic()
        return min(self.capacity, self._tokens + (now - self._last) * self.rate)


class AgentRateLimiter:
    """
    Per-agent token bucket + bounded-concurrency semaphore.

    Prevents a single agent (or network burst) from monopolising the ingest
    path.  Other agents are always able to proceed.

    Policy (configurable via env or call-site):
      rate      — sustained ingest rate in requests/second per agent  (default 10)
      burst     — max burst size                                       (default 30)
      max_slots — max concurrent ingest requests per agent             (default 4)
    """

    def __init__(
        self,
        rate: float = 10.0,
        burst: float = 30.0,
        max_slots: int = 4,
    ) -> None:
        self._rate = rate
        self._burst = burst
        self._max_slots = max_slots
        self._buckets:    dict[str, TokenBucket]      = {}
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._last_gc: float = time.monotonic()

    def _get_bucket(self, agent_id: str) -> TokenBucket:
        if agent_id not in self._buckets:
            self._buckets[agent_id] = TokenBucket(self._rate, self._burst)
        return self._buckets[agent_id]

    def _get_sem(self, agent_id: str) -> asyncio.Semaphore:
        if agent_id not in self._semaphores:
            self._semaphores[agent_id] = asyncio.Semaphore(self._max_slots)
        return self._semaphores[agent_id]

    def check_rate(self, agent_id: str) -> bool:
        """Return False if agent exceeds sustained rate (caller should 429)."""
        return self._get_bucket(agent_id).consume()

    @asynccontextmanager
    async def agent_slot(self, agent_id: str, timeout: float = 8.0):
        """
        Acquire one concurrency slot for *agent_id*.
        Waits up to *timeout* seconds; raises asyncio.TimeoutError on overflow.
        Releasing the slot is guaranteed via the context manager.
        """
        sem = self._get_sem(agent_id)
        try:
            await asyncio.wait_for(sem.acquire(), timeout=timeout)
        except asyncio.TimeoutError:
            raise
        try:
            yield
        finally:
            sem.release()
            self._maybe_gc()

    def _maybe_gc(self) -> None:
        """Evict idle agent state every 5 minutes to bound memory growth."""
        now = time.monotonic()
        if now - self._last_gc < 300:
            return
        self._last_gc = now
        idle = [
            aid for aid, sem in self._semaphores.items()
            if sem._value == self._max_slots  # type: ignore[attr-defined]
        ]
        for aid in idle:
            self._buckets.pop(aid, None)
            self._semaphores.pop(aid, None)
        if idle:
            log.debug("AgentRateLimiter GC: evicted %d idle agents", len(idle))
