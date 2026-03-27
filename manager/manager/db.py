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


class Database:
    def __init__(self, path: str):
        self.path = path

    async def init(self):
        async with aiosqlite.connect(self.path) as db:
            await db.executescript(SCHEMA)
            await db.commit()

    async def ping(self) -> bool:
        try:
            async with aiosqlite.connect(self.path) as db:
                await db.execute("SELECT 1")
            return True
        except Exception:
            return False

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
