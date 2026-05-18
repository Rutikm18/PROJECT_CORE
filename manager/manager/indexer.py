"""
manager/manager/indexer.py — Intel DB: findings index, change timeline, baseline.

Storage: intel.db (SQLite) — separate from manager.db to keep concerns isolated.

Algorithms:
  • SHA-256 fingerprinting  — dedup; only update when content changes
  • FTS5 virtual table      — full-text search across all findings
  • Welford baseline store  — persisted mean/m2/n for behavioral analysis
  • Change timeline         — append-only log; never mutates history
  • SQLitePool (readers=3)  — concurrent reads, serialised writes

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

from .pool import SQLitePool

log = logging.getLogger("manager.indexer")

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Findings ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id       TEXT,
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
    composite_score   REAL    NOT NULL DEFAULT 0,
    epss_score        REAL    NOT NULL DEFAULT 0,
    kev               INTEGER NOT NULL DEFAULT 0,
    exploit_available INTEGER NOT NULL DEFAULT 0,
    exploit_sources   TEXT,
    asset_tier        TEXT    NOT NULL DEFAULT '',
    asset_importance  REAL    NOT NULL DEFAULT 0,
    priority_reason   TEXT,
    action_plan       TEXT,
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_find_external_id ON findings(external_id);
CREATE INDEX IF NOT EXISTS idx_find_agent   ON findings(agent_id, severity, is_active);
CREATE INDEX IF NOT EXISTS idx_find_ts      ON findings(last_detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_find_score   ON findings(score DESC);
CREATE INDEX IF NOT EXISTS idx_find_composite ON findings(composite_score DESC);
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
    attack_path      TEXT,
    blast_radius     TEXT,
    entry_points     TEXT,
    affected_assets  TEXT,
    likely_next_steps TEXT,
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

-- ── SOC workflow: durable action / remediation plan items ─────────────────
CREATE TABLE IF NOT EXISTS soc_actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL,
    agent_id    TEXT    NOT NULL,
    action_type TEXT    NOT NULL DEFAULT 'remediate',
    title       TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'open',
    owner       TEXT    NOT NULL DEFAULT '',
    due_at      REAL    DEFAULT 0,
    detail      TEXT    DEFAULT '',
    created_by  TEXT    NOT NULL DEFAULT 'system',
    created_at  REAL    NOT NULL,
    updated_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_finding ON soc_actions(finding_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_agent   ON soc_actions(agent_id, status, created_at DESC);

-- ── Threat intel feed health ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS feed_health (
    source        TEXT PRIMARY KEY,
    last_attempt  REAL NOT NULL DEFAULT 0,
    last_success  REAL NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    error_count   INTEGER NOT NULL DEFAULT 0,
    entry_count   INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'unknown'
);

-- ── NVD CVE local mirror (bulk-synced; separate from reactive cve_entries) ───
-- pkg_keywords is a space-separated token string extracted from CPE URIs and
-- the CVE description — indexed via FTS5 for sub-millisecond package lookups.
CREATE TABLE IF NOT EXISTS nvd_cve_local (
    cve_id        TEXT PRIMARY KEY,
    description   TEXT NOT NULL DEFAULT '',
    cvss_score    REAL,
    cvss_vector   TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'info',
    cwe_ids       TEXT NOT NULL DEFAULT '[]',
    cpe_uris      TEXT NOT NULL DEFAULT '[]',
    pkg_keywords  TEXT NOT NULL DEFAULT '',
    published_at  TEXT NOT NULL DEFAULT '',
    modified_at   TEXT NOT NULL DEFAULT '',
    synced_at     REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nvd_score ON nvd_cve_local(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_nvd_mod   ON nvd_cve_local(modified_at DESC);

CREATE VIRTUAL TABLE IF NOT EXISTS nvd_cve_fts USING fts5(
    cve_id UNINDEXED,
    pkg_keywords,
    content='nvd_cve_local', content_rowid=rowid
);
CREATE TRIGGER IF NOT EXISTS nvd_ai AFTER INSERT ON nvd_cve_local BEGIN
    INSERT INTO nvd_cve_fts(rowid, cve_id, pkg_keywords)
    VALUES(new.rowid, new.cve_id, new.pkg_keywords);
END;
CREATE TRIGGER IF NOT EXISTS nvd_ad AFTER DELETE ON nvd_cve_local BEGIN
    INSERT INTO nvd_cve_fts(nvd_cve_fts, rowid, cve_id, pkg_keywords)
    VALUES('delete', old.rowid, old.cve_id, old.pkg_keywords);
END;
CREATE TRIGGER IF NOT EXISTS nvd_au AFTER UPDATE ON nvd_cve_local BEGIN
    INSERT INTO nvd_cve_fts(nvd_cve_fts, rowid, cve_id, pkg_keywords)
    VALUES('delete', old.rowid, old.cve_id, old.pkg_keywords);
    INSERT INTO nvd_cve_fts(rowid, cve_id, pkg_keywords)
    VALUES(new.rowid, new.cve_id, new.pkg_keywords);
END;

-- ── NVD sync state (key/value for sync timestamps) ───────────────────────
CREATE TABLE IF NOT EXISTS nvd_sync_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- ── Organisation & platform settings ─────────────────────────────────────
-- Generic key/value store for all configurable settings.
-- Typed fields (dates, booleans, ints) are stored as strings; callers coerce.
CREATE TABLE IF NOT EXISTS org_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at REAL NOT NULL DEFAULT 0
);

-- ── CISA Known Exploited Vulnerabilities ─────────────────────────────────
CREATE TABLE IF NOT EXISTS cisa_kev (
    cve_id          TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL DEFAULT '',
    product         TEXT NOT NULL DEFAULT '',
    vuln_name       TEXT NOT NULL DEFAULT '',
    date_added      TEXT NOT NULL DEFAULT '',
    short_desc      TEXT NOT NULL DEFAULT '',
    required_action TEXT NOT NULL DEFAULT '',
    due_date        TEXT NOT NULL DEFAULT '',
    cached_at       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kev_date ON cisa_kev(date_added DESC);

-- ── EPSS scores ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id      TEXT PRIMARY KEY,
    epss        REAL NOT NULL DEFAULT 0,
    percentile  REAL NOT NULL DEFAULT 0,
    model_date  TEXT NOT NULL DEFAULT '',
    cached_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_scores(epss DESC);

-- ── Threat actors (ransomware.live, ThreatFox, etc.) ──────────────────────
CREATE TABLE IF NOT EXISTS threat_actors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    aliases     TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    active      INTEGER NOT NULL DEFAULT 1,
    countries   TEXT NOT NULL DEFAULT '[]',
    ttps        TEXT NOT NULL DEFAULT '[]',
    source      TEXT NOT NULL DEFAULT 'ransomware.live',
    first_seen  TEXT NOT NULL DEFAULT '',
    last_active TEXT NOT NULL DEFAULT '',
    cached_at   REAL NOT NULL,
    UNIQUE(name, source)
);
CREATE INDEX IF NOT EXISTS idx_actors_active ON threat_actors(active, cached_at DESC);

-- ── Security news feed (HackerNews, security blogs) ──────────────────────
CREATE TABLE IF NOT EXISTS security_news (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT NOT NULL,
    external_id  TEXT NOT NULL DEFAULT '',
    title        TEXT NOT NULL,
    url          TEXT NOT NULL DEFAULT '',
    summary      TEXT NOT NULL DEFAULT '',
    keywords     TEXT NOT NULL DEFAULT '[]',
    cve_refs     TEXT NOT NULL DEFAULT '[]',
    severity     TEXT NOT NULL DEFAULT 'info',
    published_at REAL NOT NULL DEFAULT 0,
    cached_at    REAL NOT NULL,
    UNIQUE(source, external_id)
);
CREATE INDEX IF NOT EXISTS idx_news_pub ON security_news(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_news_src ON security_news(source, cached_at DESC);

-- ── AI analysis cache per finding ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_analysis (
    finding_id      INTEGER PRIMARY KEY,
    model           TEXT NOT NULL DEFAULT 'claude-sonnet-4-6',
    analysis        TEXT NOT NULL DEFAULT '',
    threat_context  TEXT NOT NULL DEFAULT '',
    risk_factors    TEXT NOT NULL DEFAULT '[]',
    ioc_matches     TEXT NOT NULL DEFAULT '[]',
    news_context    TEXT NOT NULL DEFAULT '[]',
    actor_context   TEXT NOT NULL DEFAULT '[]',
    confidence      REAL NOT NULL DEFAULT 0,
    tokens_used     INTEGER NOT NULL DEFAULT 0,
    generated_at    REAL NOT NULL
);

-- ── AI-generated remediation plans ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS remediation_plans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   INTEGER NOT NULL,
    agent_id     TEXT NOT NULL,
    os_type      TEXT NOT NULL DEFAULT 'macos',
    model        TEXT NOT NULL DEFAULT 'claude-sonnet-4-6',
    steps        TEXT NOT NULL DEFAULT '[]',
    summary      TEXT NOT NULL DEFAULT '',
    effort       TEXT NOT NULL DEFAULT 'medium',
    risk_level   TEXT NOT NULL DEFAULT 'low',
    verification TEXT NOT NULL DEFAULT '[]',
    long_term    TEXT NOT NULL DEFAULT '[]',
    generated_at REAL NOT NULL,
    UNIQUE(finding_id, os_type)
);
CREATE INDEX IF NOT EXISTS idx_remed_finding ON remediation_plans(finding_id);
CREATE INDEX IF NOT EXISTS idx_remed_agent   ON remediation_plans(agent_id, generated_at DESC);

-- ── Asset registry (enriched from agent telemetry) ────────────────────────
CREATE TABLE IF NOT EXISTS asset_registry (
    agent_id    TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL DEFAULT '',
    os          TEXT NOT NULL DEFAULT '',
    os_version  TEXT NOT NULL DEFAULT '',
    arch        TEXT NOT NULL DEFAULT '',
    asset_tier  TEXT NOT NULL DEFAULT 'standard',
    asset_group TEXT NOT NULL DEFAULT '',
    importance  REAL NOT NULL DEFAULT 0.3,
    owner       TEXT NOT NULL DEFAULT '',
    department  TEXT NOT NULL DEFAULT '',
    tags        TEXT NOT NULL DEFAULT '[]',
    first_seen  REAL NOT NULL DEFAULT 0,
    last_seen   REAL NOT NULL DEFAULT 0
);

-- ── Org groups for priority weighting ────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_groups (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT '',
    importance    REAL NOT NULL DEFAULT 0.5,
    member_agents TEXT NOT NULL DEFAULT '[]',
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);
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
    ("findings",     "external_id",       "TEXT    DEFAULT ''"),
    ("findings",     "status",        "TEXT    DEFAULT 'new'"),
    ("findings",     "assignee",      "TEXT    DEFAULT ''"),
    ("findings",     "sla_due",       "REAL    DEFAULT 0"),
    ("findings",     "closed_at",     "REAL    DEFAULT NULL"),
    ("findings",     "priority",      "INTEGER DEFAULT 0"),
    ("findings",     "analyst_notes", "TEXT    DEFAULT ''"),
    ("findings",     "composite_score",   "REAL    DEFAULT 0"),
    ("findings",     "epss_score",        "REAL    DEFAULT 0"),
    ("findings",     "kev",               "INTEGER DEFAULT 0"),
    ("findings",     "exploit_available", "INTEGER DEFAULT 0"),
    ("findings",     "exploit_sources",   "TEXT    DEFAULT '[]'"),
    ("findings",     "asset_tier",        "TEXT    DEFAULT ''"),
    ("findings",     "asset_importance",  "REAL    DEFAULT 0"),
    ("findings",     "priority_reason",   "TEXT    DEFAULT ''"),
    ("findings",     "action_plan",       "TEXT    DEFAULT '[]'"),
    ("correlations",  "attack_path",       "TEXT    DEFAULT '[]'"),
    ("correlations",  "blast_radius",      "TEXT    DEFAULT '{}'"),
    ("correlations",  "entry_points",      "TEXT    DEFAULT '[]'"),
    ("correlations",  "affected_assets",   "TEXT    DEFAULT '[]'"),
    ("correlations",  "likely_next_steps", "TEXT    DEFAULT '[]'"),
    # AI enrichment columns
    ("findings", "ai_analysed",        "INTEGER DEFAULT 0"),
    ("findings", "threat_actor_match", "TEXT    DEFAULT ''"),
    ("findings", "news_refs",          "TEXT    DEFAULT '[]'"),
]


class IntelDB:
    """
    Async SQLite wrapper for the intel database.

    Uses SQLitePool: reader connections for all SELECT queries (concurrent),
    the write connection for all INSERT/UPDATE/DELETE (serialised via pool lock).
    self._conn is aliased to the pool's write connection for backwards
    compatibility with all existing write methods — no logic changes needed.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._pool: Optional[SQLitePool] = None
        self._conn: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()  # kept for write-serialisation within Python

    async def init(self) -> None:
        self._pool = SQLitePool(self._path, readers=3)
        await self._pool.init()
        # Alias write connection for all existing write code (zero changes needed)
        self._conn = self._pool._write_conn  # type: ignore[attr-defined]

        # Migrations must run before executescript so new columns exist
        # before _SCHEMA tries to build indexes that reference them.
        for table, col, defn in _SOC_MIGRATIONS:
            try:
                await self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col} {defn}"
                )
                await self._conn.commit()
            except Exception:
                pass  # column already exists, or table not yet created (fresh db)
        # Backfill external_id for existing rows so the UNIQUE index creation
        # doesn't fail on rows that all share the '' default.
        try:
            async with self._conn.execute(
                "SELECT id FROM findings WHERE external_id IS NULL OR external_id = ''"
            ) as cur:
                rows = await cur.fetchall()
            for row in rows:
                await self._conn.execute(
                    "UPDATE findings SET external_id=? WHERE id=?",
                    (_external_id(row[0]), row[0]),
                )
            if rows:
                await self._conn.commit()
        except Exception:
            pass  # findings table doesn't exist yet on a fresh db
        async with self._conn.executescript(_SCHEMA):
            pass
        await self._conn.commit()
        log.info("IntelDB initialised at %s (pool readers=3)", self._path)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._conn = None

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
        exploit_j  = json.dumps(f.get("exploit_sources") or [], default=str)
        action_j   = json.dumps(f.get("action_plan") or [], default=str)
        composite  = float(f.get("composite_score") or f.get("score") or 0)
        epss       = float(f.get("epss_score") or 0)
        kev        = 1 if f.get("kev") else 0
        exploit    = 1 if f.get("exploit_available") else 0
        asset_tier = str(f.get("asset_tier") or "")
        asset_imp  = float(f.get("asset_importance") or 0)
        priority_reason = str(f.get("priority_reason") or _priority_reason(f))

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
                     cvss_score,cvss_vector,composite_score,epss_score,kev,
                     exploit_available,exploit_sources,asset_tier,asset_importance,
                     priority_reason,action_plan,mitre_technique,mitre_tactic,
                     first_detected_at,last_detected_at,scan_count,is_active,tags,
                     status,assignee,sla_due,priority,analyst_notes)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,?,
                           'new','',?,0,'')
                """, (agent_id, category, item_key, fp,
                      sev, f.get("score",0),
                      f.get("title",""), f.get("description",""),
                      evidence_j, f.get("source",""), f.get("rule_id",""),
                      cve_j, f.get("cvss_score"), f.get("cvss_vector",""),
                      composite, epss, kev, exploit, exploit_j, asset_tier,
                      asset_imp, priority_reason, action_j,
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
                    external_id = _external_id(new_row["id"])
                    await self._conn.execute(
                        "UPDATE findings SET external_id=? WHERE id=?",
                        (external_id, new_row["id"]),
                    )
                    await self._ensure_default_actions(
                        new_row["id"], agent_id, f.get("action_plan") or [], ts,
                    )
                    await self._conn.commit()
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
                        composite_score=?, epss_score=?, kev=?,
                        exploit_available=?, exploit_sources=?, asset_tier=?,
                        asset_importance=?, priority_reason=?, action_plan=?,
                        mitre_technique=?, mitre_tactic=?,
                        last_detected_at=?, scan_count=scan_count+1,
                        is_active=1, tags=?
                    WHERE agent_id=? AND category=? AND item_key=?
                """, (fp, f.get("severity","info"), f.get("score",0),
                      f.get("title",""), f.get("description",""),
                      evidence_j, f.get("source",""), f.get("rule_id",""),
                      cve_j, f.get("cvss_score"), f.get("cvss_vector",""),
                      composite, epss, kev, exploit, exploit_j, asset_tier,
                      asset_imp, priority_reason, action_j,
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
        path_j   = json.dumps(c.get("attack_path") or [], default=str)
        blast_j  = json.dumps(c.get("blast_radius") or {}, default=str)
        entry_j  = json.dumps(c.get("entry_points") or [], default=str)
        assets_j = json.dumps(c.get("affected_assets") or [], default=str)
        next_j   = json.dumps(c.get("likely_next_steps") or [], default=str)
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
                     recommendation, attack_chain, attack_path, blast_radius, entry_points,
                     affected_assets, likely_next_steps, signals, signal_count,
                     first_detected, last_detected, is_active)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
                """, (agent_id, rule_id,
                      c.get("severity", "high"), c.get("score", 0),
                      c.get("confidence", 0), c.get("title", ""),
                      c.get("description", ""), c.get("recommendation", ""),
                      chain_j, path_j, blast_j, entry_j, assets_j, next_j,
                      sigs_j, c.get("signal_count", 0), ts, ts))
            else:
                await self._conn.execute("""
                    UPDATE correlations SET
                        severity=?, score=?, confidence=?, title=?, description=?,
                        recommendation=?, attack_chain=?, attack_path=?, blast_radius=?,
                        entry_points=?, affected_assets=?, likely_next_steps=?, signals=?,
                        signal_count=?, last_detected=?, is_active=1
                    WHERE agent_id=? AND rule_id=?
                """, (c.get("severity", "high"), c.get("score", 0),
                      c.get("confidence", 0), c.get("title", ""),
                      c.get("description", ""), c.get("recommendation", ""),
                      chain_j, path_j, blast_j, entry_j, assets_j, next_j,
                      sigs_j, c.get("signal_count", 0), ts,
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
            for key, default in (
                ("attack_path", []),
                ("blast_radius", {}),
                ("entry_points", []),
                ("affected_assets", []),
                ("likely_next_steps", []),
            ):
                d[key] = _json_value(d.get(key), default)
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

    async def list_cves(
        self,
        *,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        parts: list[str] = []
        args: list = []
        if severity:
            parts.append("severity=?")
            args.append(severity)
        where = ("WHERE " + " AND ".join(parts)) if parts else ""
        rows = await self._fetchall(
            f"SELECT * FROM cve_entries {where} "
            f"ORDER BY COALESCE(cvss_score, 0) DESC, modified_at DESC "
            f"LIMIT ? OFFSET ?",
            (*args, limit, offset),
        )
        return [dict(r) for r in rows]

    async def get_threat_intel_overview(self) -> dict:
        cve = await self._fetchone("SELECT COUNT(*) AS n FROM cve_entries", ())
        cve_sev = await self._fetchall(
            "SELECT severity, COUNT(*) AS n FROM cve_entries GROUP BY severity", ()
        )
        cve_recent = await self._fetchone(
            "SELECT COUNT(*) AS n FROM cve_entries WHERE cached_at>?",
            (time.time() - 86400,),
        )
        ioc = await self._fetchone(
            "SELECT COUNT(*) AS n FROM ioc_cache WHERE expires_at>?", (time.time(),)
        )
        findings = await self._fetchone(
            "SELECT COUNT(*) AS n FROM findings WHERE is_active=1", ()
        )
        mapped = await self._fetchone(
            "SELECT COUNT(*) AS n FROM findings WHERE is_active=1 AND cve_ids IS NOT NULL AND cve_ids!='[]'",
            (),
        )
        feeds = await self.get_all_feed_health()
        return {
            "cves": cve["n"] if cve else 0,
            "cves_cached_24h": cve_recent["n"] if cve_recent else 0,
            "ioc_cache": ioc["n"] if ioc else 0,
            "active_findings": findings["n"] if findings else 0,
            "mapped_findings": mapped["n"] if mapped else 0,
            "cve_by_severity": {r["severity"] or "info": r["n"] for r in cve_sev},
            "feeds": feeds,
            "datastores": [
                {"name": "manager.db", "role": "agent registry, sessions, raw payload index"},
                {"name": "intel.db", "role": "threat intel cache, findings, correlations, scoring matrix"},
            ],
            "pipeline": [
                "agent ingest",
                "RabbitMQ telemetry queue or sync fallback",
                "raw agent datastore",
                "threat intel refresh and NVD modified sync",
                "Jarvis rules, CVE matching, behavior baselines",
                "indexed findings and correlations API",
            ],
        }

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
        _TERMINAL_SET = {"closed","false_positive","accepted_risk","duplicate","verified","remediated"}
        if status == "__closed__":
            # Show all terminal-state findings (used by view=closed)
            placeholders = ",".join("?" * len(_TERMINAL_SET))
            parts.append(f"f.status IN ({placeholders})")
            args.extend(sorted(_TERMINAL_SET))
        elif status:
            parts.append("f.status=?"); args.append(status)
        if category:
            parts.append("f.category=?"); args.append(category)
        if assignee:
            parts.append("f.assignee=?"); args.append(assignee)
        if sla_breached:
            parts.append("f.sla_due > 0 AND f.sla_due < ?")
            args.append(time.time())
        # Terminal states always have is_active=0; applying is_active=1 would
        # return zero rows, so skip the filter when a terminal status is requested.
        _TERMINAL = {"closed","false_positive","accepted_risk","duplicate","verified","remediated"}
        if active_only and status not in _TERMINAL:
            parts.append("f.is_active=1")
        elif active_only and status in _TERMINAL:
            parts.append("f.is_active=0")   # terminal states are always inactive

        where = ("WHERE " + " AND ".join(parts)) if parts else ""
        valid_sorts = {"score": "f.score DESC", "last_detected_at": "f.last_detected_at DESC",
                       "composite_score": "f.composite_score DESC",
                       "priority": "f.priority DESC, f.composite_score DESC",
                       "kev": "f.kev DESC, f.composite_score DESC",
                       "exploit_available": "f.exploit_available DESC, f.composite_score DESC",
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
            d = _shape_finding(dict(r))
            d["sla_status"] = _sla_status(d.get("sla_due", 0), d.get("status", "new"))
            result.append(d)
        return result

    async def get_finding_by_id(self, finding_id: int) -> dict | None:
        row = await self._fetchone(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        )
        return _shape_finding(dict(row)) if row else None

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

    async def get_actions(self, finding_id: int) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM soc_actions WHERE finding_id=? ORDER BY status ASC, created_at ASC",
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

    async def _ensure_default_actions(
        self, finding_id: int, agent_id: str, action_plan: list, ts: float,
    ) -> None:
        if not action_plan:
            return
        existing = await self._fetchone(
            "SELECT COUNT(*) AS n FROM soc_actions WHERE finding_id=?",
            (finding_id,),
        )
        if existing and existing["n"]:
            return
        rows = []
        for item in action_plan[:8]:
            title = item.get("title") if isinstance(item, dict) else str(item)
            detail = item.get("detail", "") if isinstance(item, dict) else ""
            action_type = item.get("type", "remediate") if isinstance(item, dict) else "remediate"
            if title:
                rows.append((finding_id, agent_id, action_type, title, "open", "", 0,
                             detail, "system", ts, ts))
        if rows:
            await self._conn.executemany(
                "INSERT INTO soc_actions(finding_id,agent_id,action_type,title,status,owner,due_at,detail,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                rows,
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

    async def get_historical_trend(self, months: int = 6) -> list[dict]:
        """Monthly finding counts for the last N months (for 6-month dashboard chart)."""
        cutoff = time.time() - months * 30 * 86400
        rows = await self._fetchall("""
            SELECT
                strftime('%Y-%m', datetime(first_detected_at, 'unixepoch')) AS month,
                SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN severity='high'     THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN severity='medium'   THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN severity='low'      THEN 1 ELSE 0 END) AS low,
                COUNT(*) AS total
            FROM findings
            WHERE first_detected_at >= ?
            GROUP BY month
            ORDER BY month ASC
        """, (cutoff,))
        return [dict(r) for r in rows]

    # ── Stats ─────────────────────────────────────────────────────────────────

    async def stats(self) -> dict:
        row = await self._fetchone("SELECT COUNT(*) AS n FROM findings", ())
        tl  = await self._fetchone("SELECT COUNT(*) AS n FROM change_timeline", ())
        ioc = await self._fetchone(
            "SELECT COUNT(*) AS n FROM ioc_cache WHERE expires_at>?", (time.time(),))
        cve = await self._fetchone("SELECT COUNT(*) AS n FROM cve_entries", ())
        nvd = await self._fetchone("SELECT COUNT(*) AS n FROM nvd_cve_local", ())
        return {
            "findings":     (row["n"] if row else 0),
            "timeline":     (tl["n"]  if tl  else 0),
            "ioc_cache":    (ioc["n"] if ioc else 0),
            "cve_entries":  (cve["n"] if cve else 0),
            "nvd_local":    (nvd["n"] if nvd else 0),
        }

    # ── NVD local mirror ──────────────────────────────────────────────────────

    async def upsert_nvd_bulk(self, cves: list[dict]) -> int:
        """Batch upsert CVEs into local NVD mirror. Returns count written."""
        async with self._lock:
            await self._conn.executemany("""
                INSERT INTO nvd_cve_local
                (cve_id, description, cvss_score, cvss_vector, severity,
                 cwe_ids, cpe_uris, pkg_keywords, published_at, modified_at, synced_at)
                VALUES (:cve_id, :description, :cvss_score, :cvss_vector, :severity,
                        :cwe_ids, :cpe_uris, :pkg_keywords, :published_at, :modified_at, :synced_at)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description  = excluded.description,
                    cvss_score   = excluded.cvss_score,
                    cvss_vector  = excluded.cvss_vector,
                    severity     = excluded.severity,
                    cwe_ids      = excluded.cwe_ids,
                    cpe_uris     = excluded.cpe_uris,
                    pkg_keywords = excluded.pkg_keywords,
                    modified_at  = excluded.modified_at,
                    synced_at    = excluded.synced_at
            """, cves)
            await self._conn.commit()
        return len(cves)

    async def search_nvd_local(self, keyword: str, limit: int = 20) -> list[dict]:
        """FTS5 prefix search on local NVD mirror, ordered by CVSS score."""
        fts_term = keyword.strip() + "*"
        try:
            rows = await self._fetchall("""
                SELECT n.cve_id, n.description, n.cvss_score, n.cvss_vector,
                       n.severity, n.cwe_ids, n.cpe_uris, n.published_at, n.modified_at
                FROM nvd_cve_fts f
                JOIN nvd_cve_local n ON n.rowid = f.rowid
                WHERE nvd_cve_fts MATCH ?
                ORDER BY COALESCE(n.cvss_score, 0) DESC
                LIMIT ?
            """, (fts_term, limit))
            return [dict(r) for r in rows]
        except Exception as exc:
            log.debug("NVD FTS search failed, using LIKE fallback: %s", exc)
            rows = await self._fetchall("""
                SELECT cve_id, description, cvss_score, cvss_vector, severity,
                       cwe_ids, cpe_uris, published_at, modified_at
                FROM nvd_cve_local
                WHERE pkg_keywords LIKE ?
                ORDER BY COALESCE(cvss_score, 0) DESC
                LIMIT ?
            """, (f"%{keyword}%", limit))
            return [dict(r) for r in rows]

    async def get_nvd_state(self, key: str) -> Optional[str]:
        row = await self._fetchone(
            "SELECT value FROM nvd_sync_state WHERE key=?", (key,))
        return row["value"] if row else None

    async def set_nvd_state(self, key: str, value: str) -> None:
        await self._conn.execute("""
            INSERT INTO nvd_sync_state(key, value) VALUES(?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """, (key, value))
        await self._conn.commit()

    async def get_nvd_stats(self) -> dict:
        total  = await self._fetchone("SELECT COUNT(*) AS n FROM nvd_cve_local", ())
        by_sev = await self._fetchall(
            "SELECT severity, COUNT(*) AS n FROM nvd_cve_local GROUP BY severity", ())
        last_full  = await self.get_nvd_state("nvd_full_sync_at")
        last_delta = await self.get_nvd_state("nvd_delta_sync_at")
        return {
            "total":          total["n"] if total else 0,
            "by_severity":    {r["severity"]: r["n"] for r in by_sev},
            "last_full_sync": float(last_full  or 0),
            "last_delta_sync": float(last_delta or 0),
        }

    # ── Feed health ───────────────────────────────────────────────────────────

    async def record_feed_attempt(
        self,
        source:      str,
        *,
        success:     bool,
        entry_count: int  = 0,
        error:       str  = "",
    ) -> None:
        """
        Record the result of a feed fetch attempt.
        On success: resets error_count, updates last_success and entry_count.
        On failure: increments error_count, updates last_error.
        """
        now = time.time()
        if success:
            await self._conn.execute("""
                INSERT INTO feed_health(source,last_attempt,last_success,last_error,error_count,entry_count,status)
                VALUES(?,?,?,  '',      0,          ?,          'ok')
                ON CONFLICT(source) DO UPDATE SET
                    last_attempt=excluded.last_attempt,
                    last_success=excluded.last_success,
                    last_error='',
                    error_count=0,
                    entry_count=excluded.entry_count,
                    status='ok'
            """, (source, now, now, entry_count))
        else:
            await self._conn.execute("""
                INSERT INTO feed_health(source,last_attempt,last_success,last_error,error_count,entry_count,status)
                VALUES(?,?,           0,           ?,        1,           0,         'error')
                ON CONFLICT(source) DO UPDATE SET
                    last_attempt=excluded.last_attempt,
                    last_error=excluded.last_error,
                    error_count=error_count+1,
                    status=CASE WHEN error_count+1 >= 3 THEN 'error' ELSE 'degraded' END
            """, (source, now, error[:200]))
        await self._conn.commit()

    async def get_all_feed_health(self) -> list[dict]:
        """Return health record for every known feed source."""
        rows = await self._fetchall(
            "SELECT * FROM feed_health ORDER BY source ASC", ()
        )
        return [dict(r) for r in rows]

    # ── CISA KEV ──────────────────────────────────────────────────────────────

    async def upsert_cisa_kev(self, cve_id: str, data: dict) -> None:
        now = time.time()
        await self._conn.execute("""
            INSERT INTO cisa_kev
            (cve_id,vendor,product,vuln_name,date_added,short_desc,required_action,due_date,cached_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                vendor=excluded.vendor, product=excluded.product,
                vuln_name=excluded.vuln_name, date_added=excluded.date_added,
                short_desc=excluded.short_desc, required_action=excluded.required_action,
                due_date=excluded.due_date, cached_at=excluded.cached_at
        """, (cve_id, data.get("vendorProject",""), data.get("product",""),
              data.get("vulnerabilityName",""), data.get("dateAdded",""),
              data.get("shortDescription",""), data.get("requiredAction",""),
              data.get("dueDate",""), now))
        await self._conn.commit()

    async def is_kev(self, cve_id: str) -> bool:
        row = await self._fetchone("SELECT 1 FROM cisa_kev WHERE cve_id=?", (cve_id,))
        return row is not None

    async def list_kev(self, limit: int = 200) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM cisa_kev ORDER BY date_added DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    async def kev_count(self) -> int:
        row = await self._fetchone("SELECT COUNT(*) AS n FROM cisa_kev", ())
        return row["n"] if row else 0

    # ── EPSS scores ───────────────────────────────────────────────────────────

    async def upsert_epss(self, cve_id: str, epss: float, percentile: float, model_date: str = "") -> None:
        await self._conn.execute("""
            INSERT INTO epss_scores(cve_id,epss,percentile,model_date,cached_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                epss=excluded.epss, percentile=excluded.percentile,
                model_date=excluded.model_date, cached_at=excluded.cached_at
        """, (cve_id, epss, percentile, model_date, time.time()))
        await self._conn.commit()

    async def get_epss(self, cve_id: str) -> Optional[dict]:
        row = await self._fetchone("SELECT * FROM epss_scores WHERE cve_id=?", (cve_id,))
        return dict(row) if row else None

    async def get_epss_bulk(self, cve_ids: list[str]) -> dict[str, float]:
        if not cve_ids:
            return {}
        placeholders = ",".join("?" * len(cve_ids))
        rows = await self._fetchall(
            f"SELECT cve_id, epss FROM epss_scores WHERE cve_id IN ({placeholders})",
            tuple(cve_ids))
        return {r["cve_id"]: r["epss"] for r in rows}

    # ── Threat actors ─────────────────────────────────────────────────────────

    async def upsert_threat_actor(self, name: str, source: str, data: dict) -> None:
        now = time.time()
        await self._conn.execute("""
            INSERT INTO threat_actors
            (name,aliases,description,active,countries,ttps,source,first_seen,last_active,cached_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(name,source) DO UPDATE SET
                aliases=excluded.aliases, description=excluded.description,
                active=excluded.active, countries=excluded.countries,
                ttps=excluded.ttps, first_seen=excluded.first_seen,
                last_active=excluded.last_active, cached_at=excluded.cached_at
        """, (name, json.dumps(data.get("aliases",[])), data.get("description",""),
              1 if data.get("active", True) else 0,
              json.dumps(data.get("countries",[])), json.dumps(data.get("ttps",[])),
              source, data.get("first_seen",""), data.get("last_active",""), now))
        await self._conn.commit()

    async def get_threat_actors(self, active_only: bool = True, limit: int = 100) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM threat_actors WHERE (?=0 OR active=1) ORDER BY cached_at DESC LIMIT ?",
            (1 if active_only else 0, limit))
        return [dict(r) for r in rows]

    async def actor_count(self) -> int:
        row = await self._fetchone("SELECT COUNT(*) AS n FROM threat_actors WHERE active=1", ())
        return row["n"] if row else 0

    # ── Security news ─────────────────────────────────────────────────────────

    async def upsert_news(self, source: str, external_id: str, data: dict) -> None:
        await self._conn.execute("""
            INSERT INTO security_news
            (source,external_id,title,url,summary,keywords,cve_refs,severity,published_at,cached_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(source,external_id) DO UPDATE SET
                title=excluded.title, summary=excluded.summary,
                keywords=excluded.keywords, cve_refs=excluded.cve_refs,
                cached_at=excluded.cached_at
        """, (source, external_id, data.get("title",""), data.get("url",""),
              data.get("summary",""), json.dumps(data.get("keywords",[])),
              json.dumps(data.get("cve_refs",[])), data.get("severity","info"),
              data.get("published_at", time.time()), time.time()))
        await self._conn.commit()

    async def get_recent_news(self, hours: int = 48, limit: int = 50) -> list[dict]:
        cutoff = time.time() - hours * 3600
        rows = await self._fetchall(
            "SELECT * FROM security_news WHERE published_at>? ORDER BY published_at DESC LIMIT ?",
            (cutoff, limit))
        return [dict(r) for r in rows]

    async def search_news_by_cve(self, cve_id: str) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM security_news WHERE cve_refs LIKE ? ORDER BY published_at DESC LIMIT 10",
            (f"%{cve_id}%",))
        return [dict(r) for r in rows]

    async def news_count(self) -> int:
        cutoff = time.time() - 7 * 86400
        row = await self._fetchone("SELECT COUNT(*) AS n FROM security_news WHERE cached_at>?", (cutoff,))
        return row["n"] if row else 0

    # ── AI analysis ───────────────────────────────────────────────────────────

    async def upsert_ai_analysis(self, finding_id: int, data: dict) -> None:
        await self._conn.execute("""
            INSERT INTO ai_analysis
            (finding_id,model,analysis,threat_context,risk_factors,ioc_matches,
             news_context,actor_context,confidence,tokens_used,generated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(finding_id) DO UPDATE SET
                model=excluded.model, analysis=excluded.analysis,
                threat_context=excluded.threat_context, risk_factors=excluded.risk_factors,
                ioc_matches=excluded.ioc_matches, news_context=excluded.news_context,
                actor_context=excluded.actor_context, confidence=excluded.confidence,
                tokens_used=excluded.tokens_used, generated_at=excluded.generated_at
        """, (finding_id, data.get("model","claude-sonnet-4-6"),
              data.get("analysis",""), data.get("threat_context",""),
              json.dumps(data.get("risk_factors",[])), json.dumps(data.get("ioc_matches",[])),
              json.dumps(data.get("news_context",[])), json.dumps(data.get("actor_context",[])),
              float(data.get("confidence",0)), int(data.get("tokens_used",0)),
              time.time()))
        await self._conn.execute(
            "UPDATE findings SET ai_analysed=1 WHERE id=?", (finding_id,))
        await self._conn.commit()

    async def get_ai_analysis(self, finding_id: int) -> Optional[dict]:
        row = await self._fetchone("SELECT * FROM ai_analysis WHERE finding_id=?", (finding_id,))
        return dict(row) if row else None

    # ── Remediation plans ─────────────────────────────────────────────────────

    async def upsert_remediation_plan(self, finding_id: int, agent_id: str,
                                      os_type: str, data: dict) -> None:
        await self._conn.execute("""
            INSERT INTO remediation_plans
            (finding_id,agent_id,os_type,model,steps,summary,effort,risk_level,
             verification,long_term,generated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(finding_id,os_type) DO UPDATE SET
                model=excluded.model, steps=excluded.steps, summary=excluded.summary,
                effort=excluded.effort, risk_level=excluded.risk_level,
                verification=excluded.verification, long_term=excluded.long_term,
                generated_at=excluded.generated_at
        """, (finding_id, agent_id, os_type, data.get("model","claude-sonnet-4-6"),
              json.dumps(data.get("steps",[])), data.get("summary",""),
              data.get("effort","medium"), data.get("risk_level","low"),
              json.dumps(data.get("verification",[])), json.dumps(data.get("long_term",[])),
              time.time()))
        await self._conn.commit()

    async def get_remediation_plan(self, finding_id: int,
                                   os_type: str = "macos") -> Optional[dict]:
        row = await self._fetchone(
            "SELECT * FROM remediation_plans WHERE finding_id=? AND os_type=?",
            (finding_id, os_type))
        if not row:
            return None
        d = dict(row)
        for field in ("steps", "verification", "long_term"):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                d[field] = []
        return d

    async def list_remediation_plans(self, agent_id: str, limit: int = 50) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM remediation_plans WHERE agent_id=? ORDER BY generated_at DESC LIMIT ?",
            (agent_id, limit))
        return [dict(r) for r in rows]

    # ── Asset registry ────────────────────────────────────────────────────────

    async def upsert_asset(self, agent_id: str, data: dict) -> None:
        now = time.time()
        await self._conn.execute("""
            INSERT INTO asset_registry
            (agent_id,hostname,os,os_version,arch,asset_tier,asset_group,
             importance,owner,department,tags,first_seen,last_seen)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname=excluded.hostname, os=excluded.os,
                os_version=excluded.os_version, arch=excluded.arch,
                asset_tier=COALESCE(NULLIF(excluded.asset_tier,''), asset_tier),
                asset_group=COALESCE(NULLIF(excluded.asset_group,''), asset_group),
                importance=COALESCE(CASE WHEN excluded.importance>0 THEN excluded.importance END, importance),
                owner=COALESCE(NULLIF(excluded.owner,''), owner),
                department=COALESCE(NULLIF(excluded.department,''), department),
                tags=excluded.tags, last_seen=excluded.last_seen
        """, (agent_id, data.get("hostname",""), data.get("os",""),
              data.get("os_version",""), data.get("arch",""),
              data.get("asset_tier","standard"), data.get("asset_group",""),
              float(data.get("importance", 0.3)), data.get("owner",""),
              data.get("department",""), json.dumps(data.get("tags",[])),
              now, now))
        await self._conn.commit()

    async def get_asset(self, agent_id: str) -> Optional[dict]:
        row = await self._fetchone("SELECT * FROM asset_registry WHERE agent_id=?", (agent_id,))
        if not row:
            return None
        d = dict(row)
        try:
            d["tags"] = json.loads(d["tags"])
        except Exception:
            d["tags"] = []
        return d

    async def list_assets(self, limit: int = 500) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM asset_registry ORDER BY importance DESC, last_seen DESC LIMIT ?",
            (limit,))
        return [dict(r) for r in rows]

    async def update_asset_tier(self, agent_id: str, tier: str, importance: float,
                                group: str = "", owner: str = "") -> None:
        await self._conn.execute("""
            UPDATE asset_registry SET asset_tier=?, importance=?,
            asset_group=COALESCE(NULLIF(?,''),(SELECT asset_group FROM asset_registry WHERE agent_id=?)),
            owner=COALESCE(NULLIF(?,''),(SELECT owner FROM asset_registry WHERE agent_id=?))
            WHERE agent_id=?
        """, (tier, importance, group, agent_id, owner, agent_id, agent_id))
        await self._conn.commit()

    # ── Org groups ────────────────────────────────────────────────────────────

    async def upsert_org_group(self, name: str, data: dict) -> None:
        now = time.time()
        await self._conn.execute("""
            INSERT INTO org_groups(name,description,importance,member_agents,created_at,updated_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET
                description=excluded.description, importance=excluded.importance,
                member_agents=excluded.member_agents, updated_at=excluded.updated_at
        """, (name, data.get("description",""), float(data.get("importance",0.5)),
              json.dumps(data.get("member_agents",[])), now, now))
        await self._conn.commit()

    async def list_org_groups(self) -> list[dict]:
        rows = await self._fetchall("SELECT * FROM org_groups ORDER BY importance DESC", ())
        return [dict(r) for r in rows]

    async def get_org_group(self, name: str) -> Optional[dict]:
        row = await self._fetchone("SELECT * FROM org_groups WHERE name=?", (name,))
        return dict(row) if row else None

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _fetchone(self, sql: str, args: tuple) -> Optional[aiosqlite.Row]:
        """Concurrent read — uses a pool reader connection."""
        if self._pool is None:
            raise RuntimeError("IntelDB not initialised")
        async with self._pool.read() as conn:
            async with conn.execute(sql, args) as cur:
                return await cur.fetchone()

    async def _fetchall(self, sql: str, args: tuple) -> list[aiosqlite.Row]:
        """Concurrent read — uses a pool reader connection."""
        if self._pool is None:
            raise RuntimeError("IntelDB not initialised")
        async with self._pool.read() as conn:
            async with conn.execute(sql, args) as cur:
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


def _external_id(finding_id: int) -> str:
    return f"AL-F-{int(finding_id):08d}"


def _json_value(v: Any, default: Any) -> Any:
    if v is None or v == "":
        return default
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v)
    except Exception:
        return default


def _shape_finding(d: dict) -> dict:
    d["external_id"] = d.get("external_id") or _external_id(d["id"])
    d["display_id"] = d["external_id"]
    d["kev"] = bool(d.get("kev"))
    d["exploit_available"] = bool(d.get("exploit_available"))
    d["exploit_sources"] = _json_value(d.get("exploit_sources"), [])
    d["action_plan"] = _json_value(d.get("action_plan"), [])
    d["priority_reason"] = d.get("priority_reason") or _priority_reason(d)
    return d


def _priority_reason(f: dict) -> str:
    reasons: list[str] = []
    if f.get("kev"):
        reasons.append("CISA KEV match")
    if f.get("exploit_available"):
        reasons.append("public exploit available")
    if f.get("epss_score"):
        reasons.append(f"EPSS {float(f.get('epss_score') or 0) * 100:.0f}%")
    if f.get("asset_tier"):
        reasons.append(f"{f.get('asset_tier')} asset")
    if f.get("source", "").startswith("feed:") or f.get("source") in ("abuseipdb",):
        reasons.append("threat-intel IOC hit")
    if not reasons and f.get("cvss_score"):
        reasons.append(f"CVSS {f.get('cvss_score')}")
    if not reasons:
        reasons.append("rule and telemetry correlation")
    return ", ".join(reasons)
