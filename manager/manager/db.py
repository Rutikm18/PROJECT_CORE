"""
manager/db.py — Async Postgres layer backed by PgPool.

Migrated from SQLite (SQLitePool) to Postgres (PgPool, manager/pg_pool.py) —
PgPool is API-compatible (same ?-placeholder query strings, same
read()/write() async-context-manager checkout), so this module's queries are
largely unchanged. What DID change is the schema DDL below (AUTOINCREMENT →
SERIAL, PRAGMAs removed — Postgres has no pragma concept and always enforces
foreign keys) and `path` → `dsn` (a postgresql:// connection string instead
of a file path).

All reads and writes go through one Postgres connection pool — unlike SQLite,
Postgres handles concurrent writers natively, so there's no single-writer
bottleneck to design around here.

Nonce deduplication is DB-backed so it survives manager restarts and works
correctly across multiple manager instances sharing this database (the
horizontal-scaling case SQLite couldn't support).
"""

import hashlib
import json
import time
import logging

from .pg_pool import PgPool

log = logging.getLogger("manager.db")


def _literal_contains_pattern(value: str) -> str:
    """Build a LIKE pattern that treats user input as literal text."""
    escaped = value.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id   TEXT PRIMARY KEY,
    name       TEXT DEFAULT '',
    last_seen  INTEGER DEFAULT 0,
    last_ip    TEXT DEFAULT '',
    created_at INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_keys (
    agent_id      TEXT PRIMARY KEY,
    api_key_hex   TEXT NOT NULL,
    enrolled_at   INTEGER NOT NULL,
    enrollment_ip TEXT DEFAULT '',
    expires_at    INTEGER DEFAULT 0,
    revoked       INTEGER DEFAULT 0,
    rotated_at    INTEGER DEFAULT 0,
    key_label     TEXT    DEFAULT '',
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payloads (
    id           BIGSERIAL PRIMARY KEY,
    event_id     TEXT UNIQUE,
    agent_id     TEXT NOT NULL,
    section      TEXT NOT NULL,
    collected_at INTEGER NOT NULL,
    received_at  INTEGER NOT NULL,
    data         TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
);

CREATE INDEX IF NOT EXISTS idx_payloads_agent_section_ts
    ON payloads(agent_id, section, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_payloads_received
    ON payloads(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_payloads_section
    ON payloads(section, collected_at DESC);

CREATE TABLE IF NOT EXISTS agent_sessions (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    connected_at    INTEGER NOT NULL,
    disconnected_at INTEGER DEFAULT 0,
    last_seen       INTEGER NOT NULL,
    last_ip         TEXT DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'connected',
    close_reason    TEXT DEFAULT '',
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_agent_ts
    ON agent_sessions(agent_id, connected_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_open
    ON agent_sessions(agent_id, status, last_seen DESC);

-- Nonce dedup table: survives restarts, bounded by TTL cleanup.
-- Index on expires_at allows O(log n) cleanup of expired nonces.
CREATE TABLE IF NOT EXISTS nonce_cache (
    nonce      TEXT PRIMARY KEY,
    expires_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonce_exp ON nonce_cache(expires_at);

-- Event-level durable detection outbox. event_id comes from the authenticated
-- ingest nonce, so two payloads collected in the same second never collide.
-- The exact raw data is retained here until processing succeeds, allowing the
-- reconciler to replay the missed EVENT instead of an unrelated latest snapshot.
CREATE TABLE IF NOT EXISTS detection_events (
    event_id       TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL,
    section        TEXT NOT NULL,
    collected_at   DOUBLE PRECISION NOT NULL,
    received_at    DOUBLE PRECISION NOT NULL,
    stored_at      DOUBLE PRECISION,
    payload_json   TEXT NOT NULL,
    metadata_json  TEXT NOT NULL DEFAULT '{}',
    chunk_total    INTEGER NOT NULL DEFAULT 1,
    chunk_size     INTEGER NOT NULL DEFAULT 50,
    processed_at   DOUBLE PRECISION,
    correlated_at  DOUBLE PRECISION,
    signal_count   INTEGER,
    attempts       INTEGER NOT NULL DEFAULT 0,
    last_attempt_at DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_detection_events_pending
    ON detection_events(received_at) WHERE processed_at IS NULL;
-- Durable per-chunk completion makes active-active detection workers safe: all
-- replicas converge through this table instead of process-local memory.
CREATE TABLE IF NOT EXISTS detection_event_chunks (
    event_id      TEXT NOT NULL REFERENCES detection_events(event_id) ON DELETE CASCADE,
    chunk_index   INTEGER NOT NULL,
    processed_at  DOUBLE PRECISION NOT NULL,
    signal_count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (event_id, chunk_index)
);
"""

_MIGRATIONS = [
    ("agent_keys", "expires_at",  "INTEGER DEFAULT 0"),
    ("agent_keys", "revoked",     "INTEGER DEFAULT 0"),
    ("agent_keys", "rotated_at",  "INTEGER DEFAULT 0"),
    ("agent_keys", "key_label",   "TEXT DEFAULT ''"),
    ("payloads", "event_id",      "TEXT"),
    ("detection_events", "stored_at", "DOUBLE PRECISION"),
    ("detection_events", "metadata_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("detection_events", "correlated_at", "DOUBLE PRECISION"),
]


class Database:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.path = dsn  # kept for any code/logs still reading .path
        self._pool = PgPool(dsn)

    async def init(self) -> None:
        await self._pool.init()
        async with self._pool.write() as db:
            await db.executescript(SCHEMA)
            await db.commit()
            for table, col, defn in _MIGRATIONS:
                # Postgres supports IF NOT EXISTS on ADD COLUMN directly —
                # no try/except-swallow needed (that was a SQLite workaround).
                await db.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {defn}")
                await db.commit()
            # Existing processed rows predate durable correlation tracking and
            # must not be replayed as a new backlog during rollout.
            await db.execute(
                "UPDATE detection_events SET correlated_at=processed_at "
                "WHERE processed_at IS NOT NULL AND correlated_at IS NULL"
            )
            await db.commit()
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_detection_events_incomplete "
                "ON detection_events(received_at) "
                "WHERE processed_at IS NULL OR correlated_at IS NULL"
            )
            await db.commit()
            await db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_payloads_event_id "
                "ON payloads(event_id)"
            )
            await db.commit()

    async def ping(self) -> bool:
        return await self._pool.ping()

    async def close(self) -> None:
        await self._pool.close()

    # ── Nonce cache (DB-backed, restart-safe) ─────────────────────────────────

    async def check_and_store_nonce(self, nonce: str, ttl: float) -> bool:
        """
        Returns True if nonce is new (accepted), False if already seen (replay).
        Cleanup of expired nonces runs probabilistically (~1% of calls).
        Uses a subquery for the row cap — standard SQLite doesn't support
        DELETE...LIMIT without SQLITE_ENABLE_UPDATE_DELETE_LIMIT.
        """
        import random
        now = time.time()
        expires_at = now + ttl
        async with self._pool.write() as db:
            # Probabilistic cleanup — avoids a DELETE scan on every hot-path call.
            if random.random() < 0.01:
                await db.execute(
                    # rowid is SQLite-only — nonce_cache's actual primary key
                    # (nonce) is the bounded-batch-delete handle in Postgres.
                    "DELETE FROM nonce_cache WHERE nonce IN "
                    "(SELECT nonce FROM nonce_cache WHERE expires_at < ? LIMIT 500)",
                    (now,),
                )
            try:
                await db.execute(
                    "INSERT INTO nonce_cache(nonce, expires_at) VALUES(?, ?)",
                    (nonce, expires_at),
                )
                await db.commit()
                return True
            except Exception:
                # UNIQUE constraint violation → replay attack
                await db.rollback()
                return False

    async def nonce_seen(self, nonce: str) -> bool:
        """Read-only check: has this nonce already been recorded?

        Used with `store_nonce` for idempotent, no-loss ingest: the nonce is
        recorded ONLY after the payload is durably persisted, so a `True` here
        means "already fully processed" (safe to ack idempotently), while a
        retry of a request whose persistence FAILED (e.g. 503) is NOT seen and
        gets reprocessed — no silent loss, no false "duplicate" 401.
        """
        async with self._pool.read() as db:
            async with db.execute(
                "SELECT 1 FROM nonce_cache WHERE nonce=? LIMIT 1", (nonce,)
            ) as cur:
                return await cur.fetchone() is not None

    async def store_nonce(self, nonce: str, ttl: float) -> None:
        """Record a nonce AFTER successful persistence (idempotent insert)."""
        now = time.time()
        async with self._pool.write() as db:
            try:
                await db.execute(
                    "INSERT INTO nonce_cache(nonce, expires_at) VALUES(?, ?) "
                    "ON CONFLICT (nonce) DO NOTHING",
                    (nonce, now + ttl),
                )
                await db.commit()
            except Exception:
                await db.rollback()

    # ── Agent key management ──────────────────────────────────────────────────

    async def get_agent_key(self, agent_id: str) -> str | None:
        async with self._pool.read() as db:
            async with db.execute(
                "SELECT api_key_hex, revoked, expires_at FROM agent_keys WHERE agent_id=?",
                (agent_id,),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        key_hex, revoked, expires_at = row
        if revoked:
            return None
        if expires_at and int(time.time()) > expires_at:
            return None
        return key_hex

    async def upsert_agent_key(
        self,
        agent_id: str,
        api_key_hex: str,
        enrolled_ip: str = "",
        expires_at: int = 0,
        label: str = "",
    ) -> None:
        now = int(time.time())
        async with self._pool.write() as db:
            await db.execute("""
                INSERT INTO agent_keys(
                    agent_id, api_key_hex, enrolled_at, enrollment_ip,
                    expires_at, revoked, rotated_at, key_label
                ) VALUES(?,?,?,?,?,0,0,?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    api_key_hex   = excluded.api_key_hex,
                    enrolled_at   = excluded.enrolled_at,
                    enrollment_ip = excluded.enrollment_ip,
                    expires_at    = excluded.expires_at,
                    revoked       = 0,
                    rotated_at    = ?,
                    key_label     = excluded.key_label
            """, (agent_id, api_key_hex, now, enrolled_ip, expires_at, label, now))
            await db.commit()

    async def get_key_meta(self, agent_id: str) -> dict | None:
        async with self._pool.read() as db:
            async with db.execute(
                """SELECT agent_id, enrolled_at, enrollment_ip,
                          expires_at, revoked, rotated_at, key_label
                   FROM agent_keys WHERE agent_id=?""",
                (agent_id,),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        d = dict(row)
        now = int(time.time())
        d["is_active"] = (not d["revoked"]) and (
            d["expires_at"] == 0 or now <= d["expires_at"]
        )
        return d

    async def list_key_meta(self) -> list[dict]:
        async with self._pool.read() as db:
            async with db.execute(
                """SELECT a.agent_id, a.name, a.last_seen, a.last_ip,
                          k.enrolled_at, k.enrollment_ip, k.expires_at,
                          k.revoked, k.rotated_at, k.key_label
                   FROM agents a
                   LEFT JOIN agent_keys k USING (agent_id)
                   ORDER BY a.last_seen DESC"""
            ) as cur:
                rows = await cur.fetchall()
        now = int(time.time())
        out = []
        for r in rows:
            d = dict(r)
            exp = d.get("expires_at") or 0
            rev = d.get("revoked") or 0
            d["is_active"] = bool(
                d.get("enrolled_at")
                and not rev
                and (exp == 0 or now <= exp)
            )
            out.append(d)
        return out

    async def revoke_key(self, agent_id: str) -> bool:
        async with self._pool.write() as db:
            cur = await db.execute(
                "UPDATE agent_keys SET revoked=1 WHERE agent_id=?", (agent_id,)
            )
            await db.commit()
            return cur.rowcount > 0

    async def set_key_expiry(self, agent_id: str, expires_at: int) -> bool:
        async with self._pool.write() as db:
            cur = await db.execute(
                "UPDATE agent_keys SET expires_at=?, revoked=0 WHERE agent_id=?",
                (expires_at, agent_id),
            )
            await db.commit()
            return cur.rowcount > 0

    async def delete_agent_key(self, agent_id: str) -> bool:
        async with self._pool.write() as db:
            cur = await db.execute(
                "DELETE FROM agent_keys WHERE agent_id=?", (agent_id,)
            )
            await db.commit()
            return cur.rowcount > 0

    # ── Agent registry ────────────────────────────────────────────────────────

    async def upsert_agent(self, agent_id: str, name: str, ip: str) -> None:
        now = int(time.time())
        async with self._pool.write() as db:
            async with db.execute(
                "SELECT last_seen FROM agents WHERE agent_id=?", (agent_id,)
            ) as cur:
                existing = await cur.fetchone()
            previous_last_seen = int(existing["last_seen"] or 0) if existing else 0
            starts_new_session = (
                previous_last_seen <= 0 or now - previous_last_seen >= 300
            )
            await db.execute("""
                INSERT INTO agents(agent_id, name, last_seen, last_ip, created_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    name=excluded.name,
                    last_seen=excluded.last_seen,
                    last_ip=excluded.last_ip
            """, (agent_id, name, now, ip, now))
            if starts_new_session:
                await db.execute("""
                    UPDATE agent_sessions
                    SET disconnected_at=?, status='disconnected',
                        close_reason=CASE WHEN close_reason='' THEN 'timeout' ELSE close_reason END
                    WHERE agent_id=? AND status='connected'
                """, (
                    min(previous_last_seen + 300, now) if previous_last_seen else now,
                    agent_id,
                ))
                await db.execute("""
                    INSERT INTO agent_sessions(
                        agent_id, connected_at, disconnected_at,
                        last_seen, last_ip, status, close_reason
                    ) VALUES(?,?,0,?,?,'connected','')
                """, (agent_id, now, now, ip))
            else:
                cur2 = await db.execute("""
                    UPDATE agent_sessions SET last_seen=?, last_ip=?
                    WHERE id = (
                        SELECT id FROM agent_sessions
                        WHERE agent_id=? AND status='connected'
                        ORDER BY connected_at DESC LIMIT 1
                    )
                """, (now, ip, agent_id))
                if cur2.rowcount == 0:
                    await db.execute("""
                        INSERT INTO agent_sessions(
                            agent_id, connected_at, disconnected_at,
                            last_seen, last_ip, status, close_reason
                        ) VALUES(?,?,0,?,?,'connected','')
                    """, (agent_id, previous_last_seen or now, now, ip))
            await db.commit()

    async def close_stale_agent_sessions(self, stale_after: int = 300) -> int:
        now = int(time.time())
        cutoff = now - stale_after
        async with self._pool.write() as db:
            cur = await db.execute("""
                UPDATE agent_sessions
                SET disconnected_at=CASE
                        WHEN last_seen + ? < ? THEN last_seen + ?
                        ELSE ?
                    END,
                    status='disconnected',
                    close_reason='timeout'
                WHERE status='connected' AND last_seen <= ?
            """, (stale_after, now, stale_after, now, cutoff))
            await db.commit()
            return cur.rowcount

    async def get_agent_sessions(self, agent_id: str, limit: int = 5) -> list[dict]:
        await self.close_stale_agent_sessions()
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT id, agent_id, connected_at, disconnected_at,
                       last_seen, last_ip, status, close_reason
                FROM agent_sessions WHERE agent_id=?
                ORDER BY connected_at DESC LIMIT ?
            """, (agent_id, limit)) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_agent_session_counts(self) -> dict[str, int]:
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT agent_id, COUNT(*) AS cnt FROM agent_sessions GROUP BY agent_id
            """) as cur:
                rows = await cur.fetchall()
        return {r[0]: int(r[1] or 0) for r in rows}

    async def insert_payload(
        self, agent_id: str, section: str, collected_at: int, data: dict,
        event_id: str = "",
    ) -> None:
        now = int(time.time())
        blob = json.dumps(data, default=str)
        async with self._pool.write() as db:
            try:
                await db.execute("""
                    INSERT INTO payloads(
                        event_id, agent_id, section, collected_at, received_at, data
                    ) VALUES(?,?,?,?,?,?)
                    ON CONFLICT (event_id) DO NOTHING
                """, (event_id or None, agent_id, section, collected_at, now, blob))
                await db.commit()
            except Exception:
                # Self-heal the FK to agents(agent_id). If the parent row is
                # missing — registration race, agent row evicted via ON DELETE
                # CASCADE, or an agent_id mismatch — a raw FOREIGN KEY failure
                # would SILENTLY drop telemetry (Deep Analysis goes empty while
                # ingest still returns 200). Raw data must never be lost to a
                # missing parent: ensure a stub agent row, then retry once.
                await db.rollback()
                await db.execute(
                    "INSERT INTO agents(agent_id, name, created_at, last_seen) "
                    "VALUES(?,?,?,?) ON CONFLICT (agent_id) DO NOTHING",
                    (agent_id, agent_id, now, now),
                )
                await db.execute("""
                    INSERT INTO payloads(
                        event_id, agent_id, section, collected_at, received_at, data
                    ) VALUES(?,?,?,?,?,?)
                    ON CONFLICT (event_id) DO NOTHING
                """, (event_id or None, agent_id, section, collected_at, now, blob))
                await db.commit()

    # ── Event-level detection outbox + durable chunk completion ──────────────

    @staticmethod
    def _legacy_event_id(
        agent_id: str, section: str, collected_at: float, data=None,
    ) -> str:
        """Stable fallback for old/direct callers that do not supply an event ID."""
        basis = json.dumps(
            [agent_id, section, float(collected_at), data],
            sort_keys=True, default=str, separators=(",", ":"),
        )
        return "legacy:" + hashlib.sha256(basis.encode()).hexdigest()

    async def ledger_received(
        self,
        agent_id: str,
        section: str,
        collected_at: float,
        *,
        event_id: str = "",
        data=None,
        chunk_total: int = 1,
        chunk_size: int = 50,
        stored: bool = False,
        metadata: dict | None = None,
    ) -> str:
        """Persist one exact event before detection fan-out; idempotent by ID."""
        event_id = event_id or self._legacy_event_id(agent_id, section, collected_at, data)
        now = time.time()
        payload_json = json.dumps(data, default=str, separators=(",", ":"))
        metadata_json = json.dumps(metadata or {}, default=str, separators=(",", ":"))
        stored_at = now if stored else None
        async with self._pool.write() as db:
            await db.execute("""
                INSERT INTO detection_events(
                    event_id, agent_id, section, collected_at, received_at, stored_at,
                    payload_json, metadata_json, chunk_total, chunk_size
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT (event_id) DO UPDATE SET
                    stored_at=COALESCE(detection_events.stored_at, excluded.stored_at),
                    metadata_json=CASE
                        WHEN detection_events.metadata_json='{}' THEN excluded.metadata_json
                        ELSE detection_events.metadata_json
                    END
            """, (
                event_id, agent_id, section, float(collected_at), now, stored_at,
                payload_json, metadata_json,
                max(1, int(chunk_total)), max(1, int(chunk_size)),
            ))
            async with db.execute(
                "SELECT agent_id, section, collected_at, payload_json, chunk_total, chunk_size "
                "FROM detection_events WHERE event_id=?",
                (event_id,),
            ) as cur:
                existing = await cur.fetchone()
            if (
                not existing
                or existing["agent_id"] != agent_id
                or existing["section"] != section
                or float(existing["collected_at"]) != float(collected_at)
                or existing["payload_json"] != payload_json
            ):
                await db.rollback()
                raise ValueError(f"event_id collision or missing event row: {event_id}")
            if int(existing["chunk_total"]) != max(1, int(chunk_total)):
                await db.rollback()
                raise ValueError(f"event_id {event_id} chunk_total changed")
            if int(existing["chunk_size"]) != max(1, int(chunk_size)):
                await db.rollback()
                raise ValueError(f"event_id {event_id} chunk_size changed")
            await db.commit()
        return event_id

    async def ledger_chunk_processed(
        self,
        event_id: str,
        chunk_index: int,
        chunk_total: int,
        *,
        signal_count: int = 0,
    ) -> bool:
        """Atomically record a chunk and return True only on event completion.

        The event row is locked, so chunks handled by different manager replicas
        cannot race. A duplicate delivery returns True only when detection is
        complete but correlation still requires retry.
        """
        now = time.time()
        index = int(chunk_index)
        total = max(1, int(chunk_total))
        if index < 0 or index >= total:
            raise ValueError(f"invalid chunk index {index}/{total} for {event_id}")
        async with self._pool.write() as db:
            try:
                async with db.execute(
                    "SELECT chunk_total, processed_at, correlated_at FROM detection_events "
                    "WHERE event_id=? FOR UPDATE",
                    (event_id,),
                ) as cur:
                    event = await cur.fetchone()
                if not event:
                    raise KeyError(f"detection event not found: {event_id}")
                if int(event["chunk_total"]) != total:
                    raise ValueError(f"event_id {event_id} chunk_total mismatch")
                if event["processed_at"] is not None:
                    await db.commit()
                    return event["correlated_at"] is None

                inserted = await db.execute("""
                    INSERT INTO detection_event_chunks(
                        event_id, chunk_index, processed_at, signal_count
                    ) VALUES(?,?,?,?)
                    ON CONFLICT (event_id, chunk_index) DO NOTHING
                """, (event_id, index, now, int(signal_count)))
                if not (getattr(inserted, "rowcount", 0) or 0):
                    await db.commit()
                    return False

                async with db.execute(
                    "SELECT COUNT(*) AS done, COALESCE(SUM(signal_count),0) AS signals "
                    "FROM detection_event_chunks WHERE event_id=?",
                    (event_id,),
                ) as cur:
                    progress = await cur.fetchone()
                if int(progress["done"]) < total:
                    await db.commit()
                    return False

                completed = await db.execute("""
                    UPDATE detection_events
                    SET processed_at=?, signal_count=?
                    WHERE event_id=? AND processed_at IS NULL
                """, (now, int(progress["signals"]), event_id))
                await db.commit()
                return bool(getattr(completed, "rowcount", 0))
            except Exception:
                await db.rollback()
                raise

    async def ledger_correlated(self, event_id: str) -> None:
        """Mark the integration pass durable after all correlation writes succeed."""
        async with self._pool.write() as db:
            cur = await db.execute(
                "UPDATE detection_events SET correlated_at=? "
                "WHERE event_id=? AND processed_at IS NOT NULL",
                (time.time(), event_id),
            )
            if not (getattr(cur, "rowcount", 0) or 0):
                await db.rollback()
                raise KeyError(f"detection event is not ready for correlation: {event_id}")
            await db.commit()

    async def ledger_processed(
        self,
        agent_id: str,
        section: str,
        collected_at: float,
        signal_count: int = 0,
        *,
        event_id: str = "",
    ) -> None:
        """Backward-compatible single-chunk completion for direct callers."""
        event_id = await self.ledger_received(
            agent_id, section, collected_at, event_id=event_id, data=None,
        )
        await self.ledger_chunk_processed(event_id, 0, 1, signal_count=signal_count)
        await self.ledger_correlated(event_id)

    async def ledger_unprocessed_events(
        self, grace_sec: float, max_attempts: int, limit: int = 200
    ) -> list[dict]:
        """Exact unprocessed events eligible for another replay attempt."""
        cutoff = time.time() - grace_sec
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT event_id, agent_id, section, collected_at, chunk_total,
                       chunk_size, attempts
                FROM detection_events
                WHERE (processed_at IS NULL OR correlated_at IS NULL)
                  AND received_at < ?
                  AND COALESCE(last_attempt_at, received_at) < ?
                  AND attempts < ?
                ORDER BY received_at ASC
                LIMIT ?
            """, (cutoff, cutoff, max_attempts, limit)) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def ledger_event_payload(self, event_id: str) -> dict | None:
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT event_id, agent_id, section, collected_at, stored_at,
                       payload_json, metadata_json, chunk_total, chunk_size
                FROM detection_events WHERE event_id=?
            """, (event_id,)) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        result = dict(row)
        result["data"] = json.loads(result.pop("payload_json"))
        result["metadata"] = json.loads(result.pop("metadata_json"))
        return result

    async def ledger_bump_attempt(self, event_id: str) -> None:
        """Record one event replay attempt, successful publish or not."""
        async with self._pool.write() as db:
            await db.execute("""
                UPDATE detection_events
                SET attempts=attempts+1, last_attempt_at=?
                WHERE event_id=? AND (processed_at IS NULL OR correlated_at IS NULL)
            """, (time.time(), event_id))
            await db.commit()

    async def ledger_lag(self) -> dict:
        """Health metric: how many payloads are stored-but-undetected, and the
        oldest one's age. Surfaced on /api/v1/ingest/health so a stuck detection
        pipeline is visible instead of silent."""
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT COUNT(*) AS pending, MIN(received_at) AS oldest
                FROM detection_events
                WHERE processed_at IS NULL OR correlated_at IS NULL
            """) as cur:
                row = await cur.fetchone()
        pending = int(row["pending"]) if row and row["pending"] else 0
        oldest = float(row["oldest"]) if row and row["oldest"] else 0.0
        return {
            "pending": pending,
            "oldest_age_sec": (time.time() - oldest) if oldest else 0.0,
        }

    async def prune_ledger(self, cutoff_ts: float) -> int:
        """Delete processed ledger rows older than cutoff (the unprocessed ones
        are kept — they are the reconciler's backlog). Returns rows deleted."""
        async with self._pool.write() as db:
            cur = await db.execute(
                "DELETE FROM detection_events WHERE processed_at IS NOT NULL "
                "AND correlated_at IS NOT NULL AND processed_at < ?",
                (float(cutoff_ts),),
            )
            await db.commit()
            return getattr(cur, "rowcount", 0) or 0

    async def prune_payloads(self, cutoff_ts: int) -> int:
        """Delete payload rows older than cutoff_ts. Returns rows deleted.

        This is the table Deep Analysis (/api/v1/raw/*) actually queries — it
        had NO retention at all before this: every raw telemetry row landed
        here and stayed forever, growing unbounded. Deletes in bounded batches
        so a multi-million-row backlog doesn't hold the write lock for one
        giant transaction (this runs on the same hourly cadence as
        TelemetryStore.cleanup() — see server.py's _cleanup_store).
        """
        deleted_total = 0
        async with self._pool.write() as db:
            while True:
                cur = await db.execute(
                    # rowid is SQLite-only — payloads has a real id (BIGSERIAL)
                    # primary key in Postgres, used as the batch-delete handle.
                    "DELETE FROM payloads WHERE id IN "
                    "(SELECT id FROM payloads WHERE collected_at < ? LIMIT 5000)",
                    (cutoff_ts,),
                )
                await db.commit()
                n = cur.rowcount or 0
                deleted_total += n
                if n < 5000:
                    break
        return deleted_total

    async def prune_agent_sessions(self, cutoff_ts: int) -> int:
        """Delete CLOSED session rows older than cutoff_ts. Returns rows deleted.

        Never deletes a session whose status is still 'connected' — an
        in-progress session has no end time to judge age by, and deleting it
        would corrupt the live connection-history view for an active agent.
        """
        async with self._pool.write() as db:
            cur = await db.execute(
                "DELETE FROM agent_sessions "
                "WHERE status != 'connected' AND last_seen < ?",
                (cutoff_ts,),
            )
            await db.commit()
            return cur.rowcount or 0

    async def get_all_agents(self) -> list:
        await self.close_stale_agent_sessions()
        async with self._pool.read() as db:
            async with db.execute(
                "SELECT * FROM agents ORDER BY last_seen DESC"
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def get_live_agent_ids(self, stale_after_sec: int) -> list[str]:
        """agent_ids that have reported within stale_after_sec — the basis for
        excluding a gone-dark agent's stale findings from fleet-wide views
        (intel.db is a separate database file; this lives here because
        last_seen lives here, and the caller composes the result into an
        `agent_id IN (...)` filter against intel.db's findings table)."""
        cutoff = int(time.time()) - stale_after_sec
        async with self._pool.read() as db:
            async with db.execute(
                "SELECT agent_id FROM agents WHERE last_seen >= ?", (cutoff,)
            ) as cur:
                return [r[0] for r in await cur.fetchall()]

    async def get_agent_last_seen(self, agent_id: str) -> float | None:
        """Single-agent last_seen — for the validation pipeline's G1 liveness
        gate (validation.py). Lighter than get_agent(): no stale-session
        side effect, just the one column the gate needs."""
        async with self._pool.read() as db:
            async with db.execute(
                "SELECT last_seen FROM agents WHERE agent_id=?", (agent_id,)
            ) as cur:
                row = await cur.fetchone()
                return float(row["last_seen"]) if row and row["last_seen"] else None

    async def get_agent(self, agent_id: str) -> dict | None:
        await self.close_stale_agent_sessions()
        async with self._pool.read() as db:
            async with db.execute(
                "SELECT * FROM agents WHERE agent_id=?", (agent_id,)
            ) as cur:
                row = await cur.fetchone()
                return dict(row) if row else None

    async def get_section_last_times(self, agent_id: str) -> dict:
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT section, MAX(collected_at) as last_ts
                FROM payloads WHERE agent_id=? GROUP BY section
            """, (agent_id,)) as cur:
                return {r[0]: r[1] for r in await cur.fetchall()}

    async def query_section(
        self,
        agent_id: str,
        section: str,
        limit: int = 100,
        start: int = 0,
        end: int = 0,
    ) -> list:
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT collected_at, received_at, data
                FROM payloads
                WHERE agent_id=? AND section=?
                  AND collected_at BETWEEN ? AND ?
                ORDER BY collected_at DESC LIMIT ?
            """, (agent_id, section, start, end or int(time.time()), limit)) as cur:
                rows = await cur.fetchall()
        return [
            {"collected_at": r[0], "received_at": r[1], "data": json.loads(r[2])}
            for r in rows
        ]

    async def get_latest_packages_per_agent(self) -> list[tuple[str, list]]:
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT p.agent_id, p.data
                FROM payloads p
                INNER JOIN (
                    SELECT agent_id, MAX(collected_at) AS max_ts
                    FROM payloads WHERE section = 'packages'
                    GROUP BY agent_id
                ) latest ON p.agent_id = latest.agent_id
                        AND p.collected_at = latest.max_ts
                        AND p.section = 'packages'
            """) as cur:
                rows = await cur.fetchall()
        result: list[tuple[str, list]] = []
        for agent_id, data_text in rows:
            try:
                data = json.loads(data_text) if data_text else []
                if isinstance(data, list):
                    result.append((agent_id, data))
            except Exception:
                pass
        return result

    # ── Raw data queries for the Deep Analysis module ─────────────────────────

    async def query_payloads(
        self,
        *,
        agent_id: str | None = None,
        section: str | None = None,
        start: int = 0,
        end: int = 0,
        search: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict]:
        """
        Flexible raw-data query used by the Deep Analysis UI.
        Combines exact index lookups with optional JSON-field search.
        All filters are optional and composable.
        """
        parts: list[str] = []
        args: list = []
        if agent_id:
            parts.append("agent_id=?")
            args.append(agent_id)
        if section:
            parts.append("section=?")
            args.append(section)
        if start:
            parts.append("collected_at >= ?")
            args.append(start)
        if end:
            parts.append("collected_at <= ?")
            args.append(end)
        if search and search.strip():
            pattern = _literal_contains_pattern(search)
            parts.append(
                "(data ILIKE ? ESCAPE '\\' OR agent_id ILIKE ? ESCAPE '\\' "
                "OR section ILIKE ? ESCAPE '\\')"
            )
            args.extend((pattern, pattern, pattern))

        where = ("WHERE " + " AND ".join(parts)) if parts else ""
        async with self._pool.read() as db:
            async with db.execute(
                f"SELECT id, agent_id, section, collected_at, received_at, data "
                f"FROM payloads {where} "
                f"ORDER BY collected_at DESC LIMIT ? OFFSET ?",
                (*args, limit, offset),
            ) as cur:
                rows = await cur.fetchall()

        result = []
        for r in rows:
            try:
                data = json.loads(r[5])
            except Exception:
                data = {}
            result.append({
                "id":           r[0],
                "agent_id":     r[1],
                "section":      r[2],
                "collected_at": r[3],
                "received_at":  r[4],
                "data":         data,
            })
        return result

    async def get_payload_by_id(self, payload_id: int) -> dict | None:
        """Fetch one full payload row by id — backs GET /raw/record for lazy
        loading a snapshot after a metadata-only list query."""
        async with self._pool.read() as db:
            async with db.execute(
                "SELECT id, agent_id, section, collected_at, received_at, data "
                "FROM payloads WHERE id=?",
                (payload_id,),
            ) as cur:
                r = await cur.fetchone()
        if r is None:
            return None
        try:
            data = json.loads(r[5])
        except Exception:
            data = {}
        return {
            "id":           r[0],
            "agent_id":     r[1],
            "section":      r[2],
            "collected_at": r[3],
            "received_at":  r[4],
            "data":         data,
        }

    async def count_payloads(
        self, *,
        agent_id: str | None = None,
        section:  str | None = None,
        start:    int | None = None,
        end:      int | None = None,
        search:   str | None = None,
    ) -> int:
        """Efficient COUNT(*) for the payload table — never loads row data."""
        parts: list[str] = []
        args:  list      = []
        if agent_id: parts.append("agent_id=?");       args.append(agent_id)
        if section:  parts.append("section=?");        args.append(section)
        if start:    parts.append("collected_at >= ?"); args.append(start)
        if end:      parts.append("collected_at <= ?"); args.append(end)
        if search and search.strip():
            pattern = _literal_contains_pattern(search)
            parts.append(
                "(data ILIKE ? ESCAPE '\\' OR agent_id ILIKE ? ESCAPE '\\' "
                "OR section ILIKE ? ESCAPE '\\')"
            )
            args.extend((pattern, pattern, pattern))
        where = ("WHERE " + " AND ".join(parts)) if parts else ""
        async with self._pool.read() as db:
            async with db.execute(
                f"SELECT COUNT(*) FROM payloads {where}", args
            ) as cur:
                row = await cur.fetchone()
        return row[0] if row else 0

    async def get_latest_section_per_agent(self, section: str) -> dict[str, dict]:
        """
        Return the most-recent payload for EACH agent for a given section.
        One SQL query regardless of agent count — O(n log n) via covered index.
        Returns {agent_id: data_dict}.
        """
        async with self._pool.read() as db:
            async with db.execute("""
                SELECT p.agent_id, p.data
                FROM payloads p
                INNER JOIN (
                    SELECT agent_id, MAX(collected_at) AS max_ts
                    FROM payloads WHERE section = ?
                    GROUP BY agent_id
                ) latest ON p.agent_id = latest.agent_id
                        AND p.collected_at = latest.max_ts
                        AND p.section = ?
            """, (section, section)) as cur:
                rows = await cur.fetchall()
        result: dict[str, dict] = {}
        for agent_id, data_text in rows:
            try:
                data = json.loads(data_text) if data_text else {}
                if isinstance(data, dict):
                    result[agent_id] = data
            except Exception:
                pass
        return result

    async def get_latest_section(self, agent_id: str, section: str):
        """Most-recent payload for ONE agent+section.

        Single covered-index lookup (idx_payloads_agent_section_ts) — does NOT
        scan/parse the whole fleet like get_latest_section_per_agent. Use this for
        single-agent detail views. Returns the parsed dict/list, or None.
        """
        async with self._pool.read() as db:
            async with db.execute(
                """SELECT data FROM payloads
                   WHERE agent_id = ? AND section = ?
                   ORDER BY collected_at DESC LIMIT 1""",
                (agent_id, section),
            ) as cur:
                row = await cur.fetchone()
        if not row or not row[0]:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None

    async def get_latest_sections(self, agent_id: str, sections: list[str]) -> dict:
        """Latest payload for ONE agent across MANY sections in a single query.

        Uses a per-section ROW_NUMBER() window (SQLite ≥ 3.25) over the covered
        index, so a detail view that needs 7 sections costs one round-trip and
        parses only this agent's rows — not the entire fleet × 7. Returns
        {section: data}; missing sections are simply absent.
        """
        if not sections:
            return {}
        placeholders = ",".join("?" * len(sections))
        async with self._pool.read() as db:
            async with db.execute(
                f"""SELECT section, data FROM (
                        SELECT section, data,
                               ROW_NUMBER() OVER (
                                   PARTITION BY section ORDER BY collected_at DESC
                               ) AS rn
                        FROM payloads
                        WHERE agent_id = ? AND section IN ({placeholders})
                    ) WHERE rn = 1""",
                (agent_id, *sections),
            ) as cur:
                rows = await cur.fetchall()
        out: dict = {}
        for section, data_text in rows:
            try:
                out[section] = json.loads(data_text) if data_text else {}
            except Exception:
                pass
        return out

    async def get_distinct_sections(self, agent_id: str | None = None) -> list[str]:
        if agent_id:
            async with self._pool.read() as db:
                async with db.execute(
                    "SELECT DISTINCT section FROM payloads WHERE agent_id=? ORDER BY section",
                    (agent_id,),
                ) as cur:
                    return [r[0] for r in await cur.fetchall()]
        else:
            async with self._pool.read() as db:
                async with db.execute(
                    "SELECT DISTINCT section FROM payloads ORDER BY section"
                ) as cur:
                    return [r[0] for r in await cur.fetchall()]
