"""
manager/manager/indexer.py — Intel DB: findings index, change timeline, baseline.

Storage: intel.db (SQLite) — separate from manager.db to keep concerns isolated.

Algorithms:
  • SHA-256 fingerprinting  — dedup; only update when content changes
  • FTS5 virtual table      — full-text search across all findings
  • Welford baseline store  — persisted mean/m2/n for behavioral analysis
  • Change timeline         — append-only log; never mutates history

Dedup rule (user requirement):
  If (agent_id, category, item_key) already exists AND fingerprint is unchanged
  → only update last_detected_at + scan_count (NOT first_detected_at).
  If fingerprint changed → update all fields, add change_timeline entry.
  If new → insert fresh, add change_timeline entry.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Optional

import aiosqlite

log = logging.getLogger("manager.indexer")

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Findings ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id          TEXT    NOT NULL,
    category          TEXT    NOT NULL,
    item_key          TEXT    NOT NULL,
    fingerprint       TEXT    NOT NULL,
    severity          TEXT    NOT NULL DEFAULT 'info',
    score             REAL    NOT NULL DEFAULT 0,
    title             TEXT    NOT NULL DEFAULT '',
    description       TEXT,
    evidence          TEXT,
    recommendation    TEXT,
    source            TEXT,
    rule_id           TEXT,
    cve_ids           TEXT,
    cvss_score        REAL,
    cvss_vector       TEXT,
    mitre_technique   TEXT,
    mitre_tactic      TEXT,
    first_detected_at REAL    NOT NULL,
    last_detected_at  REAL    NOT NULL,
    scan_count        INTEGER NOT NULL DEFAULT 1,
    is_active         INTEGER NOT NULL DEFAULT 1,
    resolved_at       REAL,
    tags              TEXT,
    UNIQUE(agent_id, category, item_key)
);
CREATE INDEX IF NOT EXISTS idx_find_agent   ON findings(agent_id, severity, is_active);
CREATE INDEX IF NOT EXISTS idx_find_ts      ON findings(last_detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_find_score   ON findings(score DESC);
CREATE INDEX IF NOT EXISTS idx_find_cat     ON findings(agent_id, category);

-- ── FTS5 for full-text search ─────────────────────────────────────────────
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    title, description, evidence, tags, cve_ids,
    content=findings, content_rowid=id
);
CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
    INSERT INTO findings_fts(rowid,title,description,evidence,tags,cve_ids)
    VALUES(new.id,new.title,new.description,new.evidence,new.tags,new.cve_ids);
END;
CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts,rowid,title,description,evidence,tags,cve_ids)
    VALUES('delete',old.id,old.title,old.description,old.evidence,old.tags,old.cve_ids);
END;
CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts,rowid,title,description,evidence,tags,cve_ids)
    VALUES('delete',old.id,old.title,old.description,old.evidence,old.tags,old.cve_ids);
    INSERT INTO findings_fts(rowid,title,description,evidence,tags,cve_ids)
    VALUES(new.id,new.title,new.description,new.evidence,new.tags,new.cve_ids);
END;

-- ── IOC cache ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_cache (
    ioc_type   TEXT NOT NULL,
    ioc_value  TEXT NOT NULL,
    source     TEXT NOT NULL,
    severity   TEXT,
    confidence INTEGER DEFAULT 50,
    description TEXT,
    tags       TEXT,
    cached_at  REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY(ioc_type, ioc_value, source)
);
CREATE INDEX IF NOT EXISTS idx_ioc_val  ON ioc_cache(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_exp  ON ioc_cache(expires_at);

-- ── CVE cache ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key     TEXT PRIMARY KEY,
    data_json     TEXT NOT NULL,
    cached_at     REAL NOT NULL,
    expires_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id        TEXT PRIMARY KEY,
    description   TEXT,
    cvss_score    REAL,
    cvss_vector   TEXT,
    severity      TEXT,
    cwe_ids       TEXT,
    published_at  TEXT,
    modified_at   TEXT,
    affected_cpe  TEXT,
    cached_at     REAL NOT NULL
);

-- ── Behavioral baseline ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS behavior_baseline (
    agent_id      TEXT NOT NULL,
    metric        TEXT NOT NULL,
    mean          REAL DEFAULT 0,
    m2            REAL DEFAULT 0,
    stddev        REAL DEFAULT 0,
    min_val       REAL,
    max_val       REAL,
    sample_count  INTEGER DEFAULT 0,
    updated_at    REAL NOT NULL,
    PRIMARY KEY(agent_id, metric)
);

-- ── Entity state (for change detection) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS entity_state (
    agent_id    TEXT NOT NULL,
    category    TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    seen_at     REAL NOT NULL,
    PRIMARY KEY(agent_id, category, entity_key)
);

-- ── Change timeline ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS change_timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT    NOT NULL,
    category    TEXT    NOT NULL,
    change_type TEXT    NOT NULL,
    item_key    TEXT    NOT NULL,
    title       TEXT,
    item_data   TEXT,
    prev_data   TEXT,
    detected_at REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tl_agent ON change_timeline(agent_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_tl_cat   ON change_timeline(agent_id, category, detected_at DESC);
"""

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class IntelDB:
    """Async SQLite wrapper for the intel database."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._conn: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def init(self) -> None:
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        async with self._conn.executescript(_SCHEMA):
            pass
        await self._conn.commit()
        log.info("IntelDB initialised at %s", self._path)

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()

    # ── Findings ──────────────────────────────────────────────────────────────

    async def upsert_finding(self, f: dict, ts: float) -> str:
        """
        Upsert a finding.  Returns 'new' | 'updated' | 'unchanged'.
        Dedup rule: same fingerprint → only update last_detected_at + scan_count.
        """
        agent_id = f["agent_id"]
        category = f["category"]
        item_key = f["item_key"]
        fp = _fingerprint(f)

        evidence_j = json.dumps(f.get("evidence") or {}, default=str)
        tags_j     = json.dumps(f.get("tags") or [])
        cve_j      = json.dumps(f.get("cve_ids") or [])

        async with self._lock:
            row = await self._fetchone(
                "SELECT id, fingerprint, first_detected_at FROM findings "
                "WHERE agent_id=? AND category=? AND item_key=?",
                (agent_id, category, item_key),
            )
            if row is None:
                await self._conn.execute("""
                    INSERT INTO findings
                    (agent_id,category,item_key,fingerprint,severity,score,
                     title,description,evidence,source,rule_id,cve_ids,
                     cvss_score,cvss_vector,mitre_technique,mitre_tactic,
                     first_detected_at,last_detected_at,scan_count,is_active,tags)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,?)
                """, (agent_id, category, item_key, fp,
                      f.get("severity","info"), f.get("score",0),
                      f.get("title",""), f.get("description",""),
                      evidence_j, f.get("source",""), f.get("rule_id",""),
                      cve_j, f.get("cvss_score"), f.get("cvss_vector",""),
                      f.get("mitre_technique",""), f.get("mitre_tactic",""),
                      ts, ts, tags_j))
                await self._conn.commit()
                await self._append_timeline(agent_id, category, "added",
                                            item_key, f.get("title",""),
                                            evidence_j, None, ts)
                return "new"

            elif row["fingerprint"] != fp:
                await self._conn.execute("""
                    UPDATE findings SET
                        fingerprint=?, severity=?, score=?, title=?,
                        description=?, evidence=?, source=?, rule_id=?,
                        cve_ids=?, cvss_score=?, cvss_vector=?,
                        mitre_technique=?, mitre_tactic=?,
                        last_detected_at=?, scan_count=scan_count+1,
                        is_active=1, tags=?
                    WHERE agent_id=? AND category=? AND item_key=?
                """, (fp, f.get("severity","info"), f.get("score",0),
                      f.get("title",""), f.get("description",""),
                      evidence_j, f.get("source",""), f.get("rule_id",""),
                      cve_j, f.get("cvss_score"), f.get("cvss_vector",""),
                      f.get("mitre_technique",""), f.get("mitre_tactic",""),
                      ts, tags_j, agent_id, category, item_key))
                await self._conn.commit()
                await self._append_timeline(agent_id, category, "modified",
                                            item_key, f.get("title",""),
                                            evidence_j, row["fingerprint"], ts)
                return "updated"

            else:
                # Same fingerprint — only heartbeat update
                await self._conn.execute(
                    "UPDATE findings SET last_detected_at=?, scan_count=scan_count+1 "
                    "WHERE agent_id=? AND category=? AND item_key=?",
                    (ts, agent_id, category, item_key),
                )
                await self._conn.commit()
                return "unchanged"

    async def get_findings(self, agent_id: str, *,
                           severity: str | None = None,
                           category: str | None = None,
                           active_only: bool = True,
                           limit: int = 500,
                           offset: int = 0) -> list[dict]:
        parts = ["agent_id=?"]
        args: list = [agent_id]
        if severity:
            parts.append("severity=?");  args.append(severity)
        if category:
            parts.append("category=?");  args.append(category)
        if active_only:
            parts.append("is_active=1")
        where = " AND ".join(parts)
        rows = await self._fetchall(
            f"SELECT * FROM findings WHERE {where} "
            f"ORDER BY score DESC, last_detected_at DESC "
            f"LIMIT ? OFFSET ?",
            (*args, limit, offset),
        )
        return [dict(r) for r in rows]

    async def search_findings(self, agent_id: str, query: str,
                              limit: int = 100) -> list[dict]:
        """FTS5 full-text search."""
        rows = await self._fetchall(
            "SELECT f.* FROM findings f "
            "JOIN findings_fts fts ON f.id=fts.rowid "
            "WHERE f.agent_id=? AND findings_fts MATCH ? "
            "ORDER BY rank LIMIT ?",
            (agent_id, query, limit),
        )
        return [dict(r) for r in rows]

    async def get_summary(self, agent_id: str) -> dict:
        row = await self._fetchone(
            """SELECT
                SUM(CASE WHEN severity='critical' AND is_active=1 THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN severity='high'     AND is_active=1 THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN severity='medium'   AND is_active=1 THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN severity='low'      AND is_active=1 THEN 1 ELSE 0 END) AS low,
                SUM(CASE WHEN severity='info'     AND is_active=1 THEN 1 ELSE 0 END) AS info,
                COUNT(*) AS total,
                SUM(CASE WHEN is_active=1 THEN 1 ELSE 0 END) AS active,
                MAX(score) AS max_score
            FROM findings WHERE agent_id=?""",
            (agent_id,),
        )
        return dict(row) if row else {}

    async def mark_resolved(self, agent_id: str, finding_id: int) -> None:
        ts = time.time()
        async with self._lock:
            row = await self._fetchone(
                "SELECT category, item_key, title FROM findings WHERE agent_id=? AND id=?",
                (agent_id, finding_id),
            )
            await self._conn.execute(
                "UPDATE findings SET is_active=0, resolved_at=? WHERE agent_id=? AND id=?",
                (ts, agent_id, finding_id),
            )
            await self._conn.commit()
            if row:
                await self._append_timeline(
                    agent_id, row["category"], "resolved",
                    row["item_key"], row["title"], None, None, ts,
                )

    # ── Change timeline ───────────────────────────────────────────────────────

    async def get_timeline(self, agent_id: str, *,
                           category: str | None = None,
                           since: float = 0.0,
                           limit: int = 200) -> list[dict]:
        if category:
            rows = await self._fetchall(
                "SELECT * FROM change_timeline "
                "WHERE agent_id=? AND category=? AND detected_at>? "
                "ORDER BY detected_at DESC LIMIT ?",
                (agent_id, category, since, limit),
            )
        else:
            rows = await self._fetchall(
                "SELECT * FROM change_timeline "
                "WHERE agent_id=? AND detected_at>? "
                "ORDER BY detected_at DESC LIMIT ?",
                (agent_id, since, limit),
            )
        return [dict(r) for r in rows]

    async def _append_timeline(self, agent_id, category, change_type,
                               item_key, title, item_data, prev_fp, ts) -> None:
        await self._conn.execute(
            "INSERT INTO change_timeline "
            "(agent_id,category,change_type,item_key,title,item_data,prev_data,detected_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (agent_id, category, change_type, item_key, title, item_data, prev_fp, ts),
        )

    # ── IOC cache ─────────────────────────────────────────────────────────────

    async def upsert_ioc(self, *, ioc_type, ioc_value, source,
                         severity, confidence, description,
                         expires_at: float) -> None:
        await self._conn.execute("""
            INSERT INTO ioc_cache
            (ioc_type,ioc_value,source,severity,confidence,description,cached_at,expires_at)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(ioc_type,ioc_value,source) DO UPDATE SET
            severity=excluded.severity, confidence=excluded.confidence,
            description=excluded.description, cached_at=excluded.cached_at,
            expires_at=excluded.expires_at
        """, (ioc_type, ioc_value, source, severity, confidence,
              description, time.time(), expires_at))
        await self._conn.commit()

    async def get_ioc(self, ioc_value: str, source: str) -> Optional[dict]:
        row = await self._fetchone(
            "SELECT * FROM ioc_cache WHERE ioc_value=? AND source=? AND expires_at>?",
            (ioc_value, source, time.time()),
        )
        return dict(row) if row else None

    async def get_all_iocs(self, ioc_type: str) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM ioc_cache WHERE ioc_type=? AND expires_at>?",
            (ioc_type, time.time()),
        )
        return [dict(r) for r in rows]

    # ── CVE cache ─────────────────────────────────────────────────────────────

    async def get_cve_cache(self, cache_key: str) -> Optional[list]:
        row = await self._fetchone(
            "SELECT data_json FROM cve_cache WHERE cache_key=? AND expires_at>?",
            (cache_key, time.time()),
        )
        return json.loads(row["data_json"]) if row else None

    async def set_cve_cache(self, cache_key: str, data: list, ttl: int) -> None:
        now = time.time()
        await self._conn.execute("""
            INSERT INTO cve_cache(cache_key,data_json,cached_at,expires_at)
            VALUES(?,?,?,?)
            ON CONFLICT(cache_key) DO UPDATE SET
            data_json=excluded.data_json, cached_at=excluded.cached_at,
            expires_at=excluded.expires_at
        """, (cache_key, json.dumps(data), now, now + ttl))
        await self._conn.commit()

    async def upsert_cve(self, cve: dict) -> None:
        await self._conn.execute("""
            INSERT INTO cve_entries
            (cve_id,description,cvss_score,cvss_vector,severity,cwe_ids,
             published_at,modified_at,affected_cpe,cached_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
            cvss_score=excluded.cvss_score,severity=excluded.severity,
            description=excluded.description,cached_at=excluded.cached_at
        """, (cve["cve_id"], cve.get("description",""),
              cve.get("cvss_score"), cve.get("cvss_vector",""),
              cve.get("severity",""), json.dumps(cve.get("cwe_ids",[])),
              cve.get("published_at",""), cve.get("modified_at",""),
              json.dumps(cve.get("affected_cpe",[])), time.time()))
        await self._conn.commit()

    async def get_cve_by_id(self, cve_id: str) -> Optional[dict]:
        row = await self._fetchone(
            "SELECT * FROM cve_entries WHERE cve_id=?", (cve_id,))
        return dict(row) if row else None

    # ── Baseline ──────────────────────────────────────────────────────────────

    async def get_baseline(self, agent_id: str, metric: str) -> Optional[dict]:
        row = await self._fetchone(
            "SELECT * FROM behavior_baseline WHERE agent_id=? AND metric=?",
            (agent_id, metric),
        )
        return dict(row) if row else None

    async def upsert_baseline(self, agent_id: str, metric: str, data: dict) -> None:
        await self._conn.execute("""
            INSERT INTO behavior_baseline
            (agent_id,metric,mean,m2,stddev,min_val,max_val,sample_count,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(agent_id,metric) DO UPDATE SET
            mean=excluded.mean, m2=excluded.m2, stddev=excluded.stddev,
            min_val=excluded.min_val, max_val=excluded.max_val,
            sample_count=excluded.sample_count, updated_at=excluded.updated_at
        """, (agent_id, metric, data["mean"], data["m2"], data["stddev"],
              data["min_val"], data["max_val"], data["sample_count"], data["updated_at"]))
        await self._conn.commit()

    # ── Entity state ──────────────────────────────────────────────────────────

    async def get_entity_state(self, agent_id: str, category: str,
                               entity_key: str) -> Optional[dict]:
        row = await self._fetchone(
            "SELECT fingerprint, seen_at FROM entity_state "
            "WHERE agent_id=? AND category=? AND entity_key=?",
            (agent_id, category, entity_key),
        )
        return dict(row) if row else None

    async def set_entity_state(self, agent_id: str, category: str,
                               entity_key: str, fingerprint: str, ts: float) -> None:
        await self._conn.execute("""
            INSERT INTO entity_state(agent_id,category,entity_key,fingerprint,seen_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(agent_id,category,entity_key) DO UPDATE SET
            fingerprint=excluded.fingerprint, seen_at=excluded.seen_at
        """, (agent_id, category, entity_key, fingerprint, ts))
        await self._conn.commit()

    # ── Stats ─────────────────────────────────────────────────────────────────

    async def stats(self) -> dict:
        row = await self._fetchone("SELECT COUNT(*) AS n FROM findings", ())
        tl  = await self._fetchone("SELECT COUNT(*) AS n FROM change_timeline", ())
        ioc = await self._fetchone(
            "SELECT COUNT(*) AS n FROM ioc_cache WHERE expires_at>?", (time.time(),))
        return {
            "findings":     (row["n"] if row else 0),
            "timeline":     (tl["n"]  if tl  else 0),
            "ioc_cache":    (ioc["n"] if ioc else 0),
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _fetchone(self, sql: str, args: tuple) -> Optional[aiosqlite.Row]:
        async with self._conn.execute(sql, args) as cur:
            return await cur.fetchone()

    async def _fetchall(self, sql: str, args: tuple) -> list[aiosqlite.Row]:
        async with self._conn.execute(sql, args) as cur:
            return await cur.fetchall()


def _fingerprint(f: dict) -> str:
    """Stable SHA-256 fingerprint of a finding's mutable fields."""
    key_fields = {
        "severity":        f.get("severity"),
        "score":           f.get("score"),
        "title":           f.get("title"),
        "description":     f.get("description"),
        "mitre_technique": f.get("mitre_technique"),
        "source":          f.get("source"),
        "cve_ids":         sorted(f.get("cve_ids") or []),
    }
    blob = json.dumps(key_fields, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()
