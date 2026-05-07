"""manager/db.py — Async SQLite layer (aiosqlite)."""

import json
import time
import aiosqlite

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS agents (
    agent_id   TEXT PRIMARY KEY,
    name       TEXT DEFAULT '',
    last_seen  INTEGER DEFAULT 0,
    last_ip    TEXT DEFAULT '',
    created_at INTEGER DEFAULT 0
);

-- Per-agent API keys. The manager generates keys on enrollment and returns
-- them to the agent. Supports expiry and revocation.
CREATE TABLE IF NOT EXISTS agent_keys (
    agent_id      TEXT PRIMARY KEY,
    api_key_hex   TEXT NOT NULL,
    enrolled_at   INTEGER NOT NULL,
    enrollment_ip TEXT DEFAULT '',
    expires_at    INTEGER DEFAULT 0,   -- unix epoch; 0 = never expires
    revoked       INTEGER DEFAULT 0,   -- 1 = revoked
    rotated_at    INTEGER DEFAULT 0,   -- last rotation timestamp
    key_label     TEXT    DEFAULT '',  -- operator note
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payloads (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id     TEXT NOT NULL,
    section      TEXT NOT NULL,
    collected_at INTEGER NOT NULL,
    received_at  INTEGER NOT NULL,
    data         TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
);

CREATE INDEX IF NOT EXISTS idx_payloads_agent_section_ts
    ON payloads(agent_id, section, collected_at DESC);

CREATE TABLE IF NOT EXISTS agent_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
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
"""

# Idempotent migration: add new columns to agent_keys if upgrading from
# an older schema that didn't have them.
_MIGRATIONS = [
    ("agent_keys", "expires_at",  "INTEGER DEFAULT 0"),
    ("agent_keys", "revoked",     "INTEGER DEFAULT 0"),
    ("agent_keys", "rotated_at",  "INTEGER DEFAULT 0"),
    ("agent_keys", "key_label",   "TEXT DEFAULT ''"),
]


class Database:
    def __init__(self, path: str):
        self.path = path

    async def init(self):
        async with aiosqlite.connect(self.path) as db:
            await db.executescript(SCHEMA)
            await db.commit()
            # Apply migrations for any existing DBs that predate these columns
            for table, col, defn in _MIGRATIONS:
                try:
                    await db.execute(
                        f"ALTER TABLE {table} ADD COLUMN {col} {defn}"
                    )
                    await db.commit()
                except Exception:
                    pass  # column already exists

    async def ping(self) -> bool:
        try:
            async with aiosqlite.connect(self.path) as db:
                await db.execute("SELECT 1")
            return True
        except Exception:
            return False

    # ── Agent key management ──────────────────────────────────────────────────

    async def get_agent_key(self, agent_id: str) -> str | None:
        """
        Return the active 64-hex-char API key for agent_id.
        Returns None if the key is revoked or expired.
        """
        async with aiosqlite.connect(self.path) as db:
            async with db.execute(
                """SELECT api_key_hex, revoked, expires_at
                   FROM agent_keys WHERE agent_id=?""",
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
        """Store or update a per-agent API key (enrollment / key rotation)."""
        now = int(time.time())
        async with aiosqlite.connect(self.path) as db:
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
        """Return key metadata (not the key itself) for one agent."""
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
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
        """Return key metadata for all agents."""
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
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
        """Mark the key as revoked. Returns True if the key existed."""
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                "UPDATE agent_keys SET revoked=1 WHERE agent_id=?", (agent_id,)
            )
            await db.commit()
            return cur.rowcount > 0

    async def set_key_expiry(self, agent_id: str, expires_at: int) -> bool:
        """Set key expiry (unix epoch). 0 = never. Returns True if updated."""
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                "UPDATE agent_keys SET expires_at=?, revoked=0 WHERE agent_id=?",
                (expires_at, agent_id),
            )
            await db.commit()
            return cur.rowcount > 0

    async def delete_agent_key(self, agent_id: str) -> bool:
        """Hard-delete the key record. Agent must re-enroll to send data."""
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                "DELETE FROM agent_keys WHERE agent_id=?", (agent_id,)
            )
            await db.commit()
            return cur.rowcount > 0

    # ── Agent registry ────────────────────────────────────────────────────────

    async def upsert_agent(self, agent_id: str, name: str, ip: str):
        now = int(time.time())
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT last_seen FROM agents WHERE agent_id=?", (agent_id,)
            ) as cur:
                existing = await cur.fetchone()
            previous_last_seen = int(existing["last_seen"] or 0) if existing else 0
            starts_new_session = (
                previous_last_seen <= 0
                or now - previous_last_seen >= 300
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
                """, (min(previous_last_seen + 300, now) if previous_last_seen else now, agent_id))
                await db.execute("""
                    INSERT INTO agent_sessions(
                        agent_id, connected_at, disconnected_at,
                        last_seen, last_ip, status, close_reason
                    ) VALUES(?,?,0,?,?,'connected','')
                """, (agent_id, now, now, ip))
            else:
                cur = await db.execute("""
                    UPDATE agent_sessions
                    SET last_seen=?, last_ip=?
                    WHERE id = (
                        SELECT id FROM agent_sessions
                        WHERE agent_id=? AND status='connected'
                        ORDER BY connected_at DESC LIMIT 1
                    )
                """, (now, ip, agent_id))
                if cur.rowcount == 0:
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
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute("""
                UPDATE agent_sessions
                SET disconnected_at=CASE
                        WHEN last_seen + ? < ? THEN last_seen + ?
                        ELSE ?
                    END,
                    status='disconnected',
                    close_reason='timeout'
                WHERE status='connected'
                  AND last_seen <= ?
            """, (stale_after, now, stale_after, now, cutoff))
            await db.commit()
            return cur.rowcount

    async def get_agent_sessions(self, agent_id: str, limit: int = 5) -> list[dict]:
        await self.close_stale_agent_sessions()
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("""
                SELECT id, agent_id, connected_at, disconnected_at,
                       last_seen, last_ip, status, close_reason
                FROM agent_sessions
                WHERE agent_id=?
                ORDER BY connected_at DESC
                LIMIT ?
            """, (agent_id, limit)) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_agent_session_counts(self) -> dict[str, int]:
        async with aiosqlite.connect(self.path) as db:
            async with db.execute("""
                SELECT agent_id, COUNT(*) AS cnt
                FROM agent_sessions
                GROUP BY agent_id
            """) as cur:
                rows = await cur.fetchall()
        return {r[0]: int(r[1] or 0) for r in rows}

    async def insert_payload(self, agent_id: str, section: str,
                             collected_at: int, data: dict):
        async with aiosqlite.connect(self.path) as db:
            await db.execute("""
                INSERT INTO payloads(agent_id, section, collected_at, received_at, data)
                VALUES(?,?,?,?,?)
            """, (agent_id, section, collected_at, int(time.time()),
                  json.dumps(data, default=str)))
            await db.commit()

    async def get_all_agents(self) -> list:
        await self.close_stale_agent_sessions()
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM agents ORDER BY last_seen DESC"
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def get_agent(self, agent_id: str) -> dict | None:
        await self.close_stale_agent_sessions()
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM agents WHERE agent_id=?", (agent_id,)
            ) as cur:
                row = await cur.fetchone()
                return dict(row) if row else None

    async def get_section_last_times(self, agent_id: str) -> dict:
        async with aiosqlite.connect(self.path) as db:
            async with db.execute("""
                SELECT section, MAX(collected_at) as last_ts
                FROM payloads WHERE agent_id=?
                GROUP BY section
            """, (agent_id,)) as cur:
                return {r[0]: r[1] for r in await cur.fetchall()}

    async def query_section(self, agent_id: str, section: str,
                            limit: int = 100,
                            start: int = 0, end: int = 0) -> list:
        async with aiosqlite.connect(self.path) as db:
            async with db.execute("""
                SELECT collected_at, received_at, data
                FROM payloads
                WHERE agent_id=? AND section=?
                  AND collected_at BETWEEN ? AND ?
                ORDER BY collected_at DESC
                LIMIT ?
            """, (agent_id, section, start, end or int(time.time()), limit)) as cur:
                rows = await cur.fetchall()
        return [
            {"collected_at": r[0], "received_at": r[1],
             "data": json.loads(r[2])}
            for r in rows
        ]

    async def get_latest_packages_per_agent(self) -> list[tuple[str, list]]:
        """
        Return the most-recent packages payload for every agent.
        Used by ThreatIntelWorker for proactive CVE re-scanning.
        Returns list of (agent_id, packages_list) tuples.
        """
        import json as _json
        async with aiosqlite.connect(self.path) as db:
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
                data = _json.loads(data_text) if data_text else []
                if isinstance(data, list):
                    result.append((agent_id, data))
            except Exception:
                pass
        return result
