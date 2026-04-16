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
            await db.execute("""
                INSERT INTO agents(agent_id, name, last_seen, last_ip, created_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    name=excluded.name,
                    last_seen=excluded.last_seen,
                    last_ip=excluded.last_ip
            """, (agent_id, name, now, ip, now))
            await db.commit()

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
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM agents ORDER BY last_seen DESC"
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def get_agent(self, agent_id: str) -> dict | None:
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
