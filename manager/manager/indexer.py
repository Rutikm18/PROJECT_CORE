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

-- ── Correlation chains ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS correlations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id        TEXT    NOT NULL,
    rule_id         TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'high',
    score           REAL    NOT NULL DEFAULT 0,
    confidence      INTEGER NOT NULL DEFAULT 0,
    title           TEXT    NOT NULL DEFAULT '',
    description     TEXT,
    recommendation  TEXT,
    attack_chain    TEXT,
    signals         TEXT,
    signal_count    INTEGER DEFAULT 0,
    first_detected  REAL    NOT NULL,
    last_detected   REAL    NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1,
    UNIQUE(agent_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_corr_agent ON correlations(agent_id, is_active, score DESC);

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

-- ── SOC workflow: analyst activity log ───────────────────────────────────
-- Records every analyst action on a finding (status change, assignment, etc.)
CREATE TABLE IF NOT EXISTS soc_activity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL,
    agent_id    TEXT    NOT NULL,
    action      TEXT    NOT NULL,   -- 'created','status_change','assigned','commented','escalated','resolved','false_positive','accepted_risk'
    actor       TEXT    DEFAULT 'system',
    old_value   TEXT    DEFAULT '',
    new_value   TEXT    DEFAULT '',
    detail      TEXT    DEFAULT '',
    created_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_act_finding ON soc_activity(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_act_agent   ON soc_activity(agent_id,   created_at DESC);

-- ── SOC workflow: analyst comments ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL,
    agent_id    TEXT    NOT NULL,
    analyst     TEXT    NOT NULL DEFAULT 'analyst',
    comment     TEXT    NOT NULL,
    created_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cmt_finding ON soc_comments(finding_id, created_at DESC);
"""

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# SLA hours by severity (Critical=4h, High=24h, Medium=7d, Low=30d, Info=90d)
_SLA_HOURS = {"critical": 4, "high": 24, "medium": 168, "low": 720, "info": 2160}

# Valid SOC workflow statuses
_SOC_STATUSES = {
    "new", "triaging", "investigating", "in_remediation",
    "remediated", "verified", "closed", "false_positive",
    "accepted_risk", "duplicate",
}

# Migrations: add SOC workflow columns to existing findings table
_SOC_MIGRATIONS = [
    ("findings",     "status",        "TEXT    DEFAULT 'new'"),
    ("findings",     "assignee",      "TEXT    DEFAULT ''"),
    ("findings",     "sla_due",       "REAL    DEFAULT 0"),
    ("findings",     "closed_at",     "REAL    DEFAULT NULL"),
    ("findings",     "priority",      "INTEGER DEFAULT 0"),
    ("findings",     "analyst_notes", "TEXT    DEFAULT ''"),
]


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
        # Apply SOC column migrations on existing databases
        for table, col, defn in _SOC_MIGRATIONS:
            try:
                await self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col} {defn}"
                )
                await self._conn.commit()
            except Exception:
                pass  # column already exists
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
                sev = f.get("severity", "info")
                sla_hours = _SLA_HOURS.get(sev, 2160)
                sla_due = ts + sla_hours * 3600
                await self._conn.execute("""
                    INSERT INTO findings
                    (agent_id,category,item_key,fingerprint,severity,score,
                     title,description,evidence,source,rule_id,cve_ids,
                     cvss_score,cvss_vector,mitre_technique,mitre_tactic,
                     first_detected_at,last_detected_at,scan_count,is_active,tags,
                     status,assignee,sla_due,priority,analyst_notes)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,?,
                           'new','',?,0,'')
                """, (agent_id, category, item_key, fp,
                      sev, f.get("score",0),
                      f.get("title",""), f.get("description",""),
                      evidence_j, f.get("source",""), f.get("rule_id",""),
                      cve_j, f.get("cvss_score"), f.get("cvss_vector",""),
                      f.get("mitre_technique",""), f.get("mitre_tactic",""),
                      ts, ts, tags_j, sla_due))
                await self._conn.commit()
                # Log creation in SOC activity
                cur2 = await self._conn.execute(
                    "SELECT id FROM findings WHERE agent_id=? AND category=? AND item_key=?",
                    (agent_id, category, item_key),
                )
                new_row = await cur2.fetchone()
                if new_row:
                    await self._log_activity(
                        new_row["id"], agent_id, "created", "system",
                        "", sev, f.get("title",""), ts,
                    )
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

    # ── Correlations ──────────────────────────────────────────────────────────

    async def upsert_correlation(self, c: dict, ts: float) -> None:
        """Upsert a cross-section correlation finding."""
        agent_id = c["agent_id"]
        rule_id  = c["rule_id"]
        chain_j  = json.dumps(c.get("attack_chain") or [], default=str)
        sigs_j   = json.dumps(c.get("signals") or [], default=str)

        async with self._lock:
            existing = await self._fetchone(
                "SELECT id, first_detected FROM correlations WHERE agent_id=? AND rule_id=?",
                (agent_id, rule_id),
            )
            if existing is None:
                await self._conn.execute("""
                    INSERT INTO correlations
                    (agent_id, rule_id, severity, score, confidence, title, description,
                     recommendation, attack_chain, signals, signal_count,
                     first_detected, last_detected, is_active)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)
                """, (agent_id, rule_id,
                      c.get("severity", "high"), c.get("score", 0),
                      c.get("confidence", 0), c.get("title", ""),
                      c.get("description", ""), c.get("recommendation", ""),
                      chain_j, sigs_j, c.get("signal_count", 0), ts, ts))
            else:
                await self._conn.execute("""
                    UPDATE correlations SET
                        severity=?, score=?, confidence=?, title=?, description=?,
                        recommendation=?, attack_chain=?, signals=?,
                        signal_count=?, last_detected=?, is_active=1
                    WHERE agent_id=? AND rule_id=?
                """, (c.get("severity", "high"), c.get("score", 0),
                      c.get("confidence", 0), c.get("title", ""),
                      c.get("description", ""), c.get("recommendation", ""),
                      chain_j, sigs_j, c.get("signal_count", 0), ts,
                      agent_id, rule_id))
            await self._conn.commit()

    async def get_correlations(self, agent_id: str) -> list[dict]:
        """Return active correlations for an agent, highest score first."""
        rows = await self._fetchall(
            "SELECT * FROM correlations WHERE agent_id=? AND is_active=1 "
            "ORDER BY score DESC, last_detected DESC",
            (agent_id,),
        )
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["attack_chain"] = json.loads(d.get("attack_chain") or "[]")
            except Exception:
                d["attack_chain"] = []
            try:
                d["signals"] = json.loads(d.get("signals") or "[]")
            except Exception:
                d["signals"] = []
            result.append(d)
        return result

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

    # ── SOC workflow ──────────────────────────────────────────────────────────

    async def get_soc_findings(
        self, *,
        agent_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        assignee: str | None = None,
        sla_breached: bool = False,
        active_only: bool = True,
        search: str | None = None,
        limit: int = 200,
        offset: int = 0,
        sort_by: str = "score",
    ) -> list[dict]:
        """Global findings list with full SOC filters."""
        parts: list[str] = []
        args: list = []
        if agent_id:
            parts.append("f.agent_id=?"); args.append(agent_id)
        if severity:
            parts.append("f.severity=?"); args.append(severity)
        if status:
            parts.append("f.status=?"); args.append(status)
        if category:
            parts.append("f.category=?"); args.append(category)
        if assignee:
            parts.append("f.assignee=?"); args.append(assignee)
        if sla_breached:
            parts.append("f.sla_due > 0 AND f.sla_due < ?")
            args.append(time.time())
        if active_only:
            parts.append("f.is_active=1")

        where = ("WHERE " + " AND ".join(parts)) if parts else ""
        valid_sorts = {"score": "f.score DESC", "last_detected_at": "f.last_detected_at DESC",
                       "severity": "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
                       "sla_due": "f.sla_due ASC"}
        order = valid_sorts.get(sort_by, "f.score DESC")

        if search:
            # Full-text search path
            rows = await self._fetchall(
                f"SELECT f.*, a.name AS agent_name FROM findings f "
                f"JOIN findings_fts fts ON f.id=fts.rowid "
                f"LEFT JOIN (SELECT agent_id, name FROM (SELECT DISTINCT agent_id, "
                f"(SELECT name FROM agents WHERE agents.agent_id=f2.agent_id LIMIT 1) AS name "
                f"FROM findings f2) sub) a ON f.agent_id=a.agent_id "
                f"{where} {'AND' if where else 'WHERE'} findings_fts MATCH ? "
                f"ORDER BY rank LIMIT ? OFFSET ?",
                (*args, search, limit, offset),
            )
        else:
            rows = await self._fetchall(
                f"SELECT f.* FROM findings f {where} "
                f"ORDER BY {order} LIMIT ? OFFSET ?",
                (*args, limit, offset),
            )

        result = []
        for r in rows:
            d = dict(r)
            d["sla_status"] = _sla_status(d.get("sla_due", 0), d.get("status", "new"))
            result.append(d)
        return result

    async def get_finding_by_id(self, finding_id: int) -> dict | None:
        row = await self._fetchone(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        )
        return dict(row) if row else None

    async def update_finding(
        self, finding_id: int, *,
        status: str | None = None,
        assignee: str | None = None,
        analyst_notes: str | None = None,
        priority: int | None = None,
        actor: str = "analyst",
    ) -> dict | None:
        """Update SOC workflow fields and log activity."""
        row = await self._fetchone(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        )
        if not row:
            return None
        old = dict(row)
        ts = time.time()

        sets: list[str] = []
        vals: list = []
        if status is not None and status in _SOC_STATUSES:
            sets.append("status=?"); vals.append(status)
            if status in ("closed", "false_positive", "accepted_risk", "verified"):
                sets.append("closed_at=?"); vals.append(ts)
                sets.append("is_active=0")
            elif old.get("status") in ("closed", "false_positive", "accepted_risk"):
                # Re-opening
                sets.append("closed_at=NULL")
                sets.append("is_active=1")
        if assignee is not None:
            sets.append("assignee=?"); vals.append(assignee)
        if analyst_notes is not None:
            sets.append("analyst_notes=?"); vals.append(analyst_notes)
        if priority is not None:
            sets.append("priority=?"); vals.append(priority)

        if not sets:
            return old

        async with self._lock:
            await self._conn.execute(
                f"UPDATE findings SET {', '.join(sets)} WHERE id=?",
                (*vals, finding_id),
            )
            await self._conn.commit()

            # Log activities
            if status is not None and status != old.get("status"):
                await self._log_activity(
                    finding_id, old["agent_id"], "status_change", actor,
                    old.get("status",""), status, "", ts,
                )
                if status in ("closed", "false_positive", "verified"):
                    await self._append_timeline(
                        old["agent_id"], old["category"], "resolved",
                        old["item_key"], old["title"], None, None, ts,
                    )
            if assignee is not None and assignee != old.get("assignee",""):
                await self._log_activity(
                    finding_id, old["agent_id"], "assigned", actor,
                    old.get("assignee",""), assignee, "", ts,
                )

        return await self.get_finding_by_id(finding_id)

    async def bulk_update_findings(
        self, finding_ids: list[int], *,
        status: str | None = None,
        assignee: str | None = None,
        priority: int | None = None,
        actor: str = "analyst",
    ) -> int:
        """Bulk update SOC workflow fields. Returns number of rows updated."""
        updated = 0
        for fid in finding_ids:
            result = await self.update_finding(
                fid, status=status, assignee=assignee,
                priority=priority, actor=actor,
            )
            if result:
                updated += 1
        return updated

    async def add_comment(
        self, finding_id: int, agent_id: str,
        analyst: str, comment: str,
    ) -> dict:
        ts = time.time()
        async with self._lock:
            await self._conn.execute(
                "INSERT INTO soc_comments(finding_id,agent_id,analyst,comment,created_at) "
                "VALUES(?,?,?,?,?)",
                (finding_id, agent_id, analyst, comment, ts),
            )
            await self._conn.commit()
            await self._log_activity(
                finding_id, agent_id, "commented", analyst, "", "", comment[:100], ts,
            )
        return {"finding_id": finding_id, "analyst": analyst, "comment": comment,
                "created_at": ts}

    async def get_comments(self, finding_id: int) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM soc_comments WHERE finding_id=? ORDER BY created_at ASC",
            (finding_id,),
        )
        return [dict(r) for r in rows]

    async def get_activity(self, finding_id: int) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM soc_activity WHERE finding_id=? ORDER BY created_at ASC",
            (finding_id,),
        )
        return [dict(r) for r in rows]

    async def _log_activity(
        self, finding_id: int, agent_id: str, action: str,
        actor: str, old_val: str, new_val: str, detail: str, ts: float,
    ) -> None:
        await self._conn.execute(
            "INSERT INTO soc_activity(finding_id,agent_id,action,actor,old_value,new_value,detail,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (finding_id, agent_id, action, actor, old_val, new_val, detail, ts),
        )

    # ── Dashboard & SLA analytics ─────────────────────────────────────────────

    async def get_dashboard_stats(self) -> dict:
        """Comprehensive stats for the SOC dashboard."""
        now = time.time()
        today_start = now - (now % 86400)  # approximate

        # KPI row
        kpi_row = await self._fetchone("""
            SELECT
                SUM(CASE WHEN is_active=1 THEN 1 ELSE 0 END)                                          AS total_active,
                SUM(CASE WHEN severity='critical' AND is_active=1 THEN 1 ELSE 0 END)                  AS critical,
                SUM(CASE WHEN severity='high'     AND is_active=1 THEN 1 ELSE 0 END)                  AS high,
                SUM(CASE WHEN severity='medium'   AND is_active=1 THEN 1 ELSE 0 END)                  AS medium,
                SUM(CASE WHEN severity='low'      AND is_active=1 THEN 1 ELSE 0 END)                  AS low,
                SUM(CASE WHEN severity='info'     AND is_active=1 THEN 1 ELSE 0 END)                  AS info,
                SUM(CASE WHEN sla_due > 0 AND sla_due < ? AND is_active=1 THEN 1 ELSE 0 END)          AS sla_breached,
                SUM(CASE WHEN closed_at >= ? THEN 1 ELSE 0 END)                                       AS resolved_today,
                COUNT(DISTINCT CASE WHEN is_active=1 THEN agent_id END)                               AS agents_with_findings
            FROM findings
        """, (now, today_start))

        # Severity distribution (all active)
        sev_rows = await self._fetchall(
            "SELECT severity, COUNT(*) AS cnt FROM findings WHERE is_active=1 "
            "GROUP BY severity", ()
        )

        # Status distribution (all active)
        status_rows = await self._fetchall(
            "SELECT status, COUNT(*) AS cnt FROM findings WHERE is_active=1 "
            "GROUP BY status", ()
        )

        # Category distribution
        cat_rows = await self._fetchall(
            "SELECT category, COUNT(*) AS cnt FROM findings WHERE is_active=1 "
            "GROUP BY category ORDER BY cnt DESC LIMIT 10", ()
        )

        # Top 5 agents by active finding count
        agent_rows = await self._fetchall("""
            SELECT f.agent_id,
                   COUNT(*) AS total,
                   SUM(CASE WHEN f.severity='critical' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN f.severity='high'     THEN 1 ELSE 0 END) AS high
            FROM findings f WHERE f.is_active=1
            GROUP BY f.agent_id ORDER BY total DESC LIMIT 5
        """, ())

        # 7-day trend (approximate using last_detected_at)
        trend = []
        for i in range(6, -1, -1):
            day_start = now - (i + 1) * 86400
            day_end   = now - i * 86400
            day_row = await self._fetchone("""
                SELECT
                    SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN severity='high'     THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN severity='medium'   THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN severity='low'      THEN 1 ELSE 0 END) AS low
                FROM findings WHERE first_detected_at >= ? AND first_detected_at < ?
            """, (day_start, day_end))
            import datetime
            date_str = datetime.datetime.utcfromtimestamp(day_end).strftime("%m/%d")
            trend.append({
                "date": date_str,
                "critical": day_row["critical"] or 0 if day_row else 0,
                "high":     day_row["high"]     or 0 if day_row else 0,
                "medium":   day_row["medium"]   or 0 if day_row else 0,
                "low":      day_row["low"]      or 0 if day_row else 0,
            })

        # SLA compliance by severity
        sla_compliance: dict = {}
        for sev in ("critical", "high", "medium", "low"):
            row = await self._fetchone("""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN sla_due=0 OR sla_due >= ? THEN 1 ELSE 0 END) AS on_time,
                    SUM(CASE WHEN sla_due > 0 AND sla_due < ?  THEN 1 ELSE 0 END) AS breached
                FROM findings WHERE severity=? AND is_active=1
            """, (now, now, sev))
            if row:
                sla_compliance[sev] = {
                    "total":   row["total"]   or 0,
                    "on_time": row["on_time"] or 0,
                    "breached":row["breached"]or 0,
                }

        return {
            "kpi": dict(kpi_row) if kpi_row else {},
            "severity_dist":  [{"severity": r["severity"], "count": r["cnt"]} for r in sev_rows],
            "status_dist":    [{"status":   r["status"],   "count": r["cnt"]} for r in status_rows],
            "category_dist":  [{"category": r["category"], "count": r["cnt"]} for r in cat_rows],
            "top_agents":     [dict(r) for r in agent_rows],
            "daily_trend":    trend,
            "sla_compliance": sla_compliance,
        }

    async def get_sla_report(self) -> list[dict]:
        """Return all active findings breaching or at risk of breaching SLA."""
        now = time.time()
        warn_threshold = now + 3600  # findings due in next 1 hour
        rows = await self._fetchall("""
            SELECT * FROM findings
            WHERE is_active=1 AND sla_due > 0 AND sla_due < ?
            ORDER BY sla_due ASC
        """, (warn_threshold,))
        result = []
        for r in rows:
            d = dict(r)
            d["sla_status"] = _sla_status(d.get("sla_due", 0), d.get("status", "new"))
            result.append(d)
        return result

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


def _sla_status(sla_due: float, status: str) -> str:
    """Return 'ok' | 'warning' | 'breached' | 'closed' based on SLA due time."""
    if status in ("closed", "false_positive", "accepted_risk", "verified", "duplicate"):
        return "closed"
    if not sla_due:
        return "ok"
    now = time.time()
    remaining = sla_due - now
    if remaining < 0:
        return "breached"
    # Warning when less than 20% of original window remains
    # Use a heuristic: warn if < 2 hours remaining
    if remaining < 7200:
        return "warning"
    return "ok"


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
