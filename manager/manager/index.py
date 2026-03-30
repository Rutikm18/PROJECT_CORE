"""
manager/manager/index.py — SQLite-backed file index for the time-series store.

Purpose
-------
The file store writes NDJSON+gzip files organised by date/hour buckets.
Without an index, a time-range query must scan the directory tree to find
relevant files. With an index, a single SQL query returns exactly which
files contain records in the requested window — O(1) regardless of
history depth or agent count.

Schema
------
    telemetry (
        id          INTEGER PRIMARY KEY,
        agent_id    TEXT    NOT NULL,
        section     TEXT    NOT NULL,
        os          TEXT,               -- "macos" | "linux" | "windows"
        hostname    TEXT,
        tier        TEXT    NOT NULL,   -- "hot" | "warm" | "cold"
        filepath    TEXT    NOT NULL UNIQUE,
        ts_min      REAL    NOT NULL,   -- earliest timestamp in the file
        ts_max      REAL    NOT NULL,   -- latest  timestamp in the file
        row_count   INTEGER DEFAULT 0,  -- number of NDJSON records
        size_bytes  INTEGER DEFAULT 0,  -- compressed file size
        created_at  REAL    NOT NULL,
        updated_at  REAL    NOT NULL
    )

    INDEX on (agent_id, section, ts_min, ts_max)

Usage
-----
    from manager.manager.index import TelemetryIndex

    idx = TelemetryIndex("data/index.db")
    await idx.init()

    # Record a new/updated file
    await idx.upsert_file(
        agent_id="a001", section="metrics", os="macos",
        hostname="Macbook", tier="hot",
        filepath="data/hot/a001/metrics/2024-04-05/14-30.ndjson.gz",
        ts_min=1712325000.0, ts_max=1712325600.0,
        row_count=60, size_bytes=4096,
    )

    # Query: which files cover a time range?
    files = await idx.query_files("a001", "metrics", start=t0, end=t1)
    for f in files:
        # open and stream f["filepath"]

    # Cleanup: remove index rows for deleted files
    await idx.delete_file("data/hot/a001/metrics/2024-04-05/14-30.ndjson.gz")
"""
from __future__ import annotations

import logging
import time
from typing import Any

import aiosqlite

log = logging.getLogger("manager.index")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS telemetry (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT    NOT NULL,
    section     TEXT    NOT NULL,
    os          TEXT,
    hostname    TEXT,
    tier        TEXT    NOT NULL,
    filepath    TEXT    NOT NULL UNIQUE,
    ts_min      REAL    NOT NULL,
    ts_max      REAL    NOT NULL,
    row_count   INTEGER DEFAULT 0,
    size_bytes  INTEGER DEFAULT 0,
    created_at  REAL    NOT NULL,
    updated_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tel_range
    ON telemetry (agent_id, section, ts_min, ts_max);
CREATE INDEX IF NOT EXISTS idx_tel_tier
    ON telemetry (tier, updated_at);
"""


class TelemetryIndex:

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def init(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_CREATE_TABLE)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.commit()
        log.info("TelemetryIndex ready at %s", self.db_path)

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    # ── Write ─────────────────────────────────────────────────────────────────

    async def upsert_file(
        self,
        agent_id: str,
        section: str,
        tier: str,
        filepath: str,
        ts_min: float,
        ts_max: float,
        os: str = "",
        hostname: str = "",
        row_count: int = 0,
        size_bytes: int = 0,
    ) -> None:
        """Insert or update an index row for a file."""
        now = time.time()
        await self._db.execute(
            """
            INSERT INTO telemetry
                (agent_id, section, os, hostname, tier, filepath,
                 ts_min, ts_max, row_count, size_bytes, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(filepath) DO UPDATE SET
                ts_min     = excluded.ts_min,
                ts_max     = excluded.ts_max,
                row_count  = excluded.row_count,
                size_bytes = excluded.size_bytes,
                os         = excluded.os,
                hostname   = excluded.hostname,
                updated_at = excluded.updated_at
            """,
            (agent_id, section, os, hostname, tier, filepath,
             ts_min, ts_max, row_count, size_bytes, now, now),
        )
        await self._db.commit()

    async def delete_file(self, filepath: str) -> None:
        """Remove an index row (call after deleting the actual file)."""
        await self._db.execute("DELETE FROM telemetry WHERE filepath=?", (filepath,))
        await self._db.commit()

    async def delete_agent(self, agent_id: str) -> int:
        """Remove all index rows for an agent. Returns number of rows deleted."""
        cur = await self._db.execute(
            "DELETE FROM telemetry WHERE agent_id=?", (agent_id,)
        )
        await self._db.commit()
        return cur.rowcount

    # ── Read ──────────────────────────────────────────────────────────────────

    async def query_files(
        self,
        agent_id: str,
        section: str,
        start: float,
        end: float,
        tiers: list[str] | None = None,
    ) -> list[dict]:
        """
        Return index rows whose time range overlaps [start, end].

        A file overlaps the query window when:
            ts_min <= end   AND   ts_max >= start

        Parameters
        ----------
        tiers : optional list of tiers to include ("hot", "warm", "cold").
                None = all tiers.

        Returns list of dicts with keys:
            filepath, tier, ts_min, ts_max, row_count, size_bytes, os, hostname
        """
        if tiers:
            placeholders = ",".join("?" * len(tiers))
            sql = f"""
                SELECT filepath, tier, ts_min, ts_max, row_count, size_bytes, os, hostname
                FROM telemetry
                WHERE agent_id=? AND section=?
                  AND ts_min <= ? AND ts_max >= ?
                  AND tier IN ({placeholders})
                ORDER BY ts_min ASC
            """
            params = [agent_id, section, end, start, *tiers]
        else:
            sql = """
                SELECT filepath, tier, ts_min, ts_max, row_count, size_bytes, os, hostname
                FROM telemetry
                WHERE agent_id=? AND section=?
                  AND ts_min <= ? AND ts_max >= ?
                ORDER BY ts_min ASC
            """
            params = [agent_id, section, end, start]

        async with self._db.execute(sql, params) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def list_agents(self) -> list[str]:
        """Return distinct agent IDs in the index."""
        async with self._db.execute(
            "SELECT DISTINCT agent_id FROM telemetry ORDER BY agent_id"
        ) as cur:
            return [r[0] for r in await cur.fetchall()]

    async def list_sections(self, agent_id: str) -> list[str]:
        """Return distinct section names for an agent."""
        async with self._db.execute(
            "SELECT DISTINCT section FROM telemetry WHERE agent_id=? ORDER BY section",
            (agent_id,),
        ) as cur:
            return [r[0] for r in await cur.fetchall()]

    async def get_section_latest(self, agent_id: str, section: str) -> float | None:
        """Return the latest ts_max across all files for agent+section."""
        async with self._db.execute(
            "SELECT MAX(ts_max) FROM telemetry WHERE agent_id=? AND section=?",
            (agent_id, section),
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row and row[0] is not None else None

    async def get_section_summary(self, agent_id: str) -> list[dict]:
        """
        Return one row per section with ts_min, ts_max, total_rows, total_bytes.
        Used by /api/v1/agents/{id} to show data freshness per section.
        """
        sql = """
            SELECT section,
                   MIN(ts_min)      AS earliest,
                   MAX(ts_max)      AS latest,
                   SUM(row_count)   AS total_rows,
                   SUM(size_bytes)  AS total_bytes,
                   COUNT(*)         AS file_count
            FROM telemetry
            WHERE agent_id=?
            GROUP BY section
            ORDER BY section
        """
        async with self._db.execute(sql, (agent_id,)) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Maintenance ───────────────────────────────────────────────────────────

    async def prune_before(self, cutoff: float, tier: str | None = None) -> int:
        """
        Delete index rows for files with ts_max < cutoff (they should be deleted
        from disk by the cleanup job before calling this).

        Returns number of rows deleted.
        """
        if tier:
            cur = await self._db.execute(
                "DELETE FROM telemetry WHERE ts_max < ? AND tier = ?",
                (cutoff, tier),
            )
        else:
            cur = await self._db.execute(
                "DELETE FROM telemetry WHERE ts_max < ?", (cutoff,)
            )
        await self._db.commit()
        return cur.rowcount

    async def stats(self) -> dict:
        """Return index-level statistics for health monitoring."""
        async with self._db.execute(
            """
            SELECT COUNT(*)         AS total_files,
                   COUNT(DISTINCT agent_id) AS agents,
                   SUM(row_count)   AS total_rows,
                   SUM(size_bytes)  AS total_bytes
            FROM telemetry
            """
        ) as cur:
            row = dict(await cur.fetchone())

        async with self._db.execute(
            "SELECT tier, COUNT(*) AS n FROM telemetry GROUP BY tier"
        ) as cur:
            tiers = {r[0]: r[1] for r in await cur.fetchall()}

        row["by_tier"] = tiers
        return row
