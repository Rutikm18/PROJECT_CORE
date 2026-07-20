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
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from .pg_pool import PgPool
from . import finding_lifecycle as _lc

log = logging.getLogger("manager.indexer")

FindingNotificationHandler = Callable[[dict, str], Awaitable[None]]

# Reserved pseudo-agent under which fleet-wide / global-threat correlations are
# stored (correlations table is keyed UNIQUE(agent_id, rule_id)). A real agent
# can never collide with this — agent ids are hardware-derived (mac-/win-/host-).
FLEET_AGENT_ID = "__fleet__"

_SCHEMA = """
-- ── Attack Terrain lookup table ──────────────────────────────────────────
-- Defines the 5 canonical attack terrains. Used as a FK target for findings
-- so every finding is classified into one terrain at creation time.
CREATE TABLE IF NOT EXISTS terrains (
    id          TEXT PRIMARY KEY,               -- 'citadels' | 'vector' | 'origin' | 'identity' | 'posture'
    label       TEXT NOT NULL,                  -- Human-readable title
    description TEXT NOT NULL DEFAULT '',
    color       TEXT NOT NULL DEFAULT '',       -- UI hint for dashboard chips
    created_at  DOUBLE PRECISION NOT NULL
);

-- ── Findings ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id                BIGSERIAL PRIMARY KEY,
    external_id       TEXT    NOT NULL DEFAULT '',
    agent_id          TEXT    NOT NULL,
    category          TEXT    NOT NULL,
    item_key          TEXT    NOT NULL,
    fingerprint       TEXT    NOT NULL,
    severity          TEXT    NOT NULL DEFAULT 'info',
    score             DOUBLE PRECISION    NOT NULL DEFAULT 0,
    title             TEXT    NOT NULL DEFAULT '',
    description       TEXT,
    evidence          TEXT,
    recommendation    TEXT,
    source            TEXT,
    rule_id           TEXT,
    cve_ids           TEXT,
    cvss_score        DOUBLE PRECISION,
    cvss_vector       TEXT,
    composite_score   DOUBLE PRECISION    NOT NULL DEFAULT 0,
    epss_score        DOUBLE PRECISION    NOT NULL DEFAULT 0,
    kev               INTEGER NOT NULL DEFAULT 0,
    exploit_available INTEGER NOT NULL DEFAULT 0,
    exploit_sources   TEXT    NOT NULL DEFAULT '[]',
    asset_tier        TEXT    NOT NULL DEFAULT '',
    asset_importance  DOUBLE PRECISION    NOT NULL DEFAULT 0,
    exploitability_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    exploitability_band  TEXT    NOT NULL DEFAULT '',
    priority_reason   TEXT    NOT NULL DEFAULT '',
    action_plan       TEXT    NOT NULL DEFAULT '[]',
    mitre_technique   TEXT,
    mitre_tactic      TEXT,
    first_detected_at DOUBLE PRECISION    NOT NULL,
    last_detected_at  DOUBLE PRECISION    NOT NULL,
    scan_count        INTEGER NOT NULL DEFAULT 1,
    is_active         INTEGER NOT NULL DEFAULT 1,
    resolved_at       DOUBLE PRECISION,
    tags              TEXT,
    -- SOC workflow columns (were migrations; now canonical schema for fresh DBs)
    status            TEXT    NOT NULL DEFAULT 'new',
    assignee          TEXT    NOT NULL DEFAULT '',
    sla_due           DOUBLE PRECISION    NOT NULL DEFAULT 0,
    closed_at         DOUBLE PRECISION,
    priority          INTEGER NOT NULL DEFAULT 0,
    analyst_notes     TEXT    NOT NULL DEFAULT '',
    ai_analysed       INTEGER NOT NULL DEFAULT 0,
    threat_actor_match TEXT   NOT NULL DEFAULT '',
    news_refs         TEXT    NOT NULL DEFAULT '[]',
    -- Detection Confidence Engine (canonical for fresh DBs)
    signal_cluster_id INTEGER,
    confidence        DOUBLE PRECISION,
    validation_gates_passed TEXT NOT NULL DEFAULT '[]',
    layers_involved   TEXT    NOT NULL DEFAULT '[]',
    host_class        TEXT    NOT NULL DEFAULT '',
    -- AI Precision Validation (canonical for fresh DBs)
    precision_score   DOUBLE PRECISION    NOT NULL DEFAULT 0.0,
    precision_factors TEXT    NOT NULL DEFAULT '{}',
    ai_verdict        TEXT    NOT NULL DEFAULT '{}',
    ai_validation_used INTEGER NOT NULL DEFAULT 0,
    -- Terrain-aware validation (per-criterion checklist)
    terrain_validation TEXT   NOT NULL DEFAULT '{}',
    -- Unique Finding ID (UUIDv4 hex) — globally unique, non-sequential,
    -- reference-safe across systems, audit logs, and external integrations.
    finding_uid       TEXT    NOT NULL DEFAULT '',
    -- Attack Terrain FK — canonical terrain classification at creation time.
    -- References terrains(id): citadels | vector | origin | identity | posture.
    terrain_id        TEXT    NOT NULL DEFAULT '',
    -- Compact actions log (JSON array). Each entry: {action_id, action, actor,
    -- timestamp}.  A lightweight summary on the finding itself so the UI never
    -- needs to join to soc_activity just to show "who did what when".
    actions_log       TEXT    NOT NULL DEFAULT '[]',
    -- Ingest dedup tracking (promoted from _SOC_MIGRATIONS so fresh DBs have them)
    content_changed_at    DOUBLE PRECISION NOT NULL DEFAULT 0,
    consecutive_unchanged INTEGER          NOT NULL DEFAULT 0,
    UNIQUE(agent_id, category, item_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_find_external_id ON findings(external_id);
CREATE INDEX IF NOT EXISTS idx_find_agent   ON findings(agent_id, severity, is_active);
CREATE INDEX IF NOT EXISTS idx_find_ts      ON findings(last_detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_find_score   ON findings(score DESC);
CREATE INDEX IF NOT EXISTS idx_find_composite ON findings(composite_score DESC);
CREATE INDEX IF NOT EXISTS idx_find_exploitability ON findings(exploitability_score DESC);
CREATE INDEX IF NOT EXISTS idx_find_cat     ON findings(agent_id, category);
-- Every Attack Terrain page (processes/network/persistence/packages/ports)
-- queries category + is_active with NO agent_id filter (fleet-wide view) —
-- idx_find_cat can't help there (its leading column is agent_id). Confirmed
-- live against an 18k-row findings table: this turned an 839ms full-index
-- SCAN into a 2ms SEARCH. idx_find_agent's leading-agent_id limitation is the
-- same gap for severity-only fleet-wide filters, so it gets the matching index.
CREATE INDEX IF NOT EXISTS idx_find_active_cat_score ON findings(is_active, category, composite_score DESC);
CREATE INDEX IF NOT EXISTS idx_find_active_sev_score ON findings(is_active, severity, composite_score DESC);
-- get_dashboard_stats() — the very first page most users hit. Confirmed live
-- (18.4k-row findings table): top_agents' "GROUP BY agent_id" forced a full
-- temp B-TREE scan over every active row (136ms); the 7-day trend loop ran
-- 7 unindexed full-table scans on first_detected_at (22ms each, ~157ms
-- total). Together these two gaps accounted for ~290ms of the page's 305ms
-- total. With these indexes: top_agents 136ms→10ms, trend loop 157ms→1ms.
CREATE INDEX IF NOT EXISTS idx_find_active_agent     ON findings(is_active, agent_id);
CREATE INDEX IF NOT EXISTS idx_find_first_detected   ON findings(first_detected_at);
-- Unique Finding ID index — used for lookup-by-UID in API endpoints.
CREATE UNIQUE INDEX IF NOT EXISTS idx_find_finding_uid ON findings(finding_uid)
    WHERE finding_uid != '';
-- Attack Terrain index — fleet-wide filtering and dashboard grouping.
CREATE INDEX IF NOT EXISTS idx_find_terrain_id ON findings(terrain_id);

-- ── Full-text search ──────────────────────────────────────────────────────
-- SQLite's FTS5 needed a separate virtual table + 3 triggers to mirror data
-- into a shadow index on every insert/update/delete. Postgres can compute the
-- search vector AS PART OF THE ROW ITSELF via a GENERATED STORED column —
-- no shadow table, no triggers, always in sync by construction. A GIN index
-- on that column gives the same sub-millisecond search.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS search_vector tsvector
    GENERATED ALWAYS AS (
        to_tsvector('english',
            coalesce(title,'') || ' ' || coalesce(description,'') || ' ' ||
            coalesce(evidence,'') || ' ' || coalesce(tags,'') || ' ' ||
            coalesce(cve_ids,'')
        )
    ) STORED;
CREATE INDEX IF NOT EXISTS idx_findings_search ON findings USING GIN(search_vector);

-- ── IOC cache ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_cache (
    ioc_type   TEXT NOT NULL,
    ioc_value  TEXT NOT NULL,
    source     TEXT NOT NULL,
    severity   TEXT,
    confidence INTEGER DEFAULT 50,
    description TEXT,
    tags       TEXT,
    cached_at  DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY(ioc_type, ioc_value, source)
);
CREATE INDEX IF NOT EXISTS idx_ioc_val  ON ioc_cache(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_exp  ON ioc_cache(expires_at);

-- ── CVE cache ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key     TEXT PRIMARY KEY,
    data_json     TEXT NOT NULL,
    cached_at     DOUBLE PRECISION NOT NULL,
    expires_at    DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id        TEXT PRIMARY KEY,
    description   TEXT,
    cvss_score    DOUBLE PRECISION,
    cvss_vector   TEXT,
    severity      TEXT,
    cwe_ids       TEXT,
    published_at  TEXT,
    modified_at   TEXT,
    affected_cpe  TEXT,
    cached_at     DOUBLE PRECISION NOT NULL
);

-- ── Behavioral baseline ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS behavior_baseline (
    agent_id      TEXT NOT NULL,
    metric        TEXT NOT NULL,
    mean          DOUBLE PRECISION DEFAULT 0,
    m2            DOUBLE PRECISION DEFAULT 0,
    stddev        DOUBLE PRECISION DEFAULT 0,
    min_val       DOUBLE PRECISION,
    max_val       DOUBLE PRECISION,
    sample_count  INTEGER DEFAULT 0,
    updated_at    DOUBLE PRECISION NOT NULL,
    PRIMARY KEY(agent_id, metric)
);

-- ── Entity state (for change detection) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS entity_state (
    agent_id    TEXT NOT NULL,
    category    TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    seen_at     DOUBLE PRECISION NOT NULL,
    PRIMARY KEY(agent_id, category, entity_key)
);

-- ── Correlation chains ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS correlations (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT    NOT NULL,
    rule_id         TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'high',
    score           DOUBLE PRECISION    NOT NULL DEFAULT 0,
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
    first_detected  DOUBLE PRECISION    NOT NULL,
    last_detected   DOUBLE PRECISION    NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1,
    UNIQUE(agent_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_corr_agent ON correlations(agent_id, is_active, score DESC);

-- ── Change timeline ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS change_timeline (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT    NOT NULL,
    category    TEXT    NOT NULL,
    change_type TEXT    NOT NULL,
    item_key    TEXT    NOT NULL,
    title       TEXT,
    item_data   TEXT,
    prev_data   TEXT,
    detected_at DOUBLE PRECISION    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tl_agent ON change_timeline(agent_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_tl_cat   ON change_timeline(agent_id, category, detected_at DESC);

-- ── SOC workflow: analyst activity log ───────────────────────────────────
-- Records every analyst action on a finding (status change, assignment, etc.)
CREATE TABLE IF NOT EXISTS soc_activity (
    id              BIGSERIAL PRIMARY KEY,
    finding_id      INTEGER NOT NULL,
    agent_id        TEXT    NOT NULL,
    action          TEXT    NOT NULL,   -- 'created','status_change','assigned','commented','escalated','resolved','false_positive','accepted_risk'
    actor           TEXT    DEFAULT 'system',
    old_value       TEXT    DEFAULT '',
    new_value       TEXT    DEFAULT '',
    detail          TEXT    DEFAULT '',
    created_at      DOUBLE PRECISION    NOT NULL,
    -- Enhanced audit trail: canonical finding reference, network provenance
    finding_uid     TEXT    NOT NULL DEFAULT '',
    ip_address      TEXT    NOT NULL DEFAULT '',
    session_id      TEXT    NOT NULL DEFAULT '',
    -- Structured change tracking: JSON dict of {field: {old: val, new: val}}
    changed_fields  TEXT    NOT NULL DEFAULT '{}',
    -- Extensible metadata: browser, user-agent, geo, etc.
    metadata        TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_act_finding    ON soc_activity(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_act_agent      ON soc_activity(agent_id,   created_at DESC);
-- Enhanced audit indexes
CREATE INDEX IF NOT EXISTS idx_act_finding_uid ON soc_activity(finding_uid, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_act_actor       ON soc_activity(actor, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_act_action      ON soc_activity(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_act_ip          ON soc_activity(ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_act_created     ON soc_activity(created_at DESC);

-- ── SOC workflow: analyst comments ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_comments (
    id          BIGSERIAL PRIMARY KEY,
    finding_id  INTEGER NOT NULL,
    agent_id    TEXT    NOT NULL,
    analyst     TEXT    NOT NULL DEFAULT 'analyst',
    comment     TEXT    NOT NULL,
    created_at  DOUBLE PRECISION    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cmt_finding ON soc_comments(finding_id, created_at DESC);

-- ── SOC workflow: durable action / remediation plan items ─────────────────
CREATE TABLE IF NOT EXISTS soc_actions (
    id          BIGSERIAL PRIMARY KEY,
    finding_id  INTEGER NOT NULL,
    agent_id    TEXT    NOT NULL,
    action_type TEXT    NOT NULL DEFAULT 'remediate',
    title       TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'open',
    owner       TEXT    NOT NULL DEFAULT '',
    due_at      DOUBLE PRECISION    DEFAULT 0,
    detail      TEXT    DEFAULT '',
    created_by  TEXT    NOT NULL DEFAULT 'system',
    created_at  DOUBLE PRECISION    NOT NULL,
    updated_at  DOUBLE PRECISION    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_finding ON soc_actions(finding_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_agent   ON soc_actions(agent_id, status, created_at DESC);

-- ── Threat intel feed health ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS feed_health (
    source        TEXT PRIMARY KEY,
    last_attempt  DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_success  DOUBLE PRECISION NOT NULL DEFAULT 0,
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
    cvss_score    DOUBLE PRECISION,
    cvss_vector   TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'info',
    cwe_ids       TEXT NOT NULL DEFAULT '[]',
    cpe_uris      TEXT NOT NULL DEFAULT '[]',
    pkg_keywords  TEXT NOT NULL DEFAULT '',
    published_at  TEXT NOT NULL DEFAULT '',
    modified_at   TEXT NOT NULL DEFAULT '',
    synced_at     DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nvd_score ON nvd_cve_local(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_nvd_mod   ON nvd_cve_local(modified_at DESC);

-- Same GENERATED-column approach as findings.search_vector above — replaces
-- the FTS5 virtual table + 3 triggers entirely.
ALTER TABLE nvd_cve_local ADD COLUMN IF NOT EXISTS search_vector tsvector
    GENERATED ALWAYS AS (to_tsvector('english', coalesce(pkg_keywords,''))) STORED;
CREATE INDEX IF NOT EXISTS idx_nvd_search ON nvd_cve_local USING GIN(search_vector);

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
    updated_at DOUBLE PRECISION NOT NULL DEFAULT 0
);

-- ── Settings audit log ─────────────────────────────────────────────────────
-- Immutable record of every settings change: who changed what, from/to, when.
CREATE TABLE IF NOT EXISTS settings_audit (
    id         BIGSERIAL PRIMARY KEY,
    key        TEXT NOT NULL,
    old_value  TEXT NOT NULL DEFAULT '',
    new_value  TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT 'system',
    ip         TEXT NOT NULL DEFAULT '',
    changed_at DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_audit_key ON settings_audit(key, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ts  ON settings_audit(changed_at DESC);

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
    cached_at       DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kev_date ON cisa_kev(date_added DESC);

-- ── EPSS scores ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id      TEXT PRIMARY KEY,
    epss        DOUBLE PRECISION NOT NULL DEFAULT 0,
    percentile  DOUBLE PRECISION NOT NULL DEFAULT 0,
    model_date  TEXT NOT NULL DEFAULT '',
    cached_at   DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_scores(epss DESC);

-- ── Threat actors (ransomware.live, ThreatFox, etc.) ──────────────────────
CREATE TABLE IF NOT EXISTS threat_actors (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    aliases     TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    active      INTEGER NOT NULL DEFAULT 1,
    countries   TEXT NOT NULL DEFAULT '[]',
    ttps        TEXT NOT NULL DEFAULT '[]',
    source      TEXT NOT NULL DEFAULT 'ransomware.live',
    first_seen  TEXT NOT NULL DEFAULT '',
    last_active TEXT NOT NULL DEFAULT '',
    cached_at   DOUBLE PRECISION NOT NULL,
    UNIQUE(name, source)
);
CREATE INDEX IF NOT EXISTS idx_actors_active ON threat_actors(active, cached_at DESC);

-- ── Security news feed (HackerNews, security blogs) ──────────────────────
CREATE TABLE IF NOT EXISTS security_news (
    id           BIGSERIAL PRIMARY KEY,
    source       TEXT NOT NULL,
    external_id  TEXT NOT NULL DEFAULT '',
    title        TEXT NOT NULL,
    url          TEXT NOT NULL DEFAULT '',
    summary      TEXT NOT NULL DEFAULT '',
    keywords     TEXT NOT NULL DEFAULT '[]',
    cve_refs     TEXT NOT NULL DEFAULT '[]',
    severity     TEXT NOT NULL DEFAULT 'info',
    published_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    cached_at    DOUBLE PRECISION NOT NULL,
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
    confidence      DOUBLE PRECISION NOT NULL DEFAULT 0,
    tokens_used     INTEGER NOT NULL DEFAULT 0,
    generated_at    DOUBLE PRECISION NOT NULL,
    -- Provider-agnostic AI layer fields (multi-provider support)
    provider        TEXT NOT NULL DEFAULT '',
    urgency         TEXT NOT NULL DEFAULT 'scheduled',
    mitre_context   TEXT NOT NULL DEFAULT '',
    latency_ms      DOUBLE PRECISION NOT NULL DEFAULT 0
);

-- ── AI-generated remediation plans ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS remediation_plans (
    id           BIGSERIAL PRIMARY KEY,
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
    generated_at DOUBLE PRECISION NOT NULL,
    -- Provider-agnostic AI layer fields
    provider     TEXT NOT NULL DEFAULT '',
    compensating TEXT NOT NULL DEFAULT '',
    tokens_used  INTEGER NOT NULL DEFAULT 0,
    latency_ms   DOUBLE PRECISION NOT NULL DEFAULT 0,
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
    importance  DOUBLE PRECISION NOT NULL DEFAULT 0.3,
    owner       TEXT NOT NULL DEFAULT '',
    department  TEXT NOT NULL DEFAULT '',
    tags        TEXT NOT NULL DEFAULT '[]',
    first_seen  DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_seen   DOUBLE PRECISION NOT NULL DEFAULT 0
);

-- ── Org groups for priority weighting ────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_groups (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT '',
    importance    DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    member_agents TEXT NOT NULL DEFAULT '[]',
    created_at    DOUBLE PRECISION NOT NULL,
    updated_at    DOUBLE PRECISION NOT NULL
);

-- ── Detection Confidence Engine tables ───────────────────────────────────

-- Raw signals emitted by rules before clustering / validation
CREATE TABLE IF NOT EXISTS signals (
    id               BIGSERIAL PRIMARY KEY,
    rule_id          TEXT NOT NULL,
    layer            TEXT NOT NULL CHECK (layer IN ('surface','exposure','execution')),
    data_point       TEXT NOT NULL,
    entity_key       TEXT NOT NULL,
    agent_id         TEXT NOT NULL,
    severity_hint    TEXT NOT NULL DEFAULT 'medium',
    evidence         TEXT NOT NULL DEFAULT '{}',
    weight           DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    strength         DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    detected_at      DOUBLE PRECISION NOT NULL,
    created_at       DOUBLE PRECISION NOT NULL,
    cluster_id       INTEGER,          -- set after cluster is persisted
    validation_status TEXT,            -- 'promoted' | 'rejected_G<n>' | 'low_confidence'
    rejection_reason  TEXT
);
CREATE INDEX IF NOT EXISTS idx_signals_agent ON signals(agent_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_signals_rule  ON signals(rule_id);
CREATE INDEX IF NOT EXISTS idx_signals_cluster ON signals(cluster_id);

-- Persisted signal clusters (one row per cluster)
CREATE TABLE IF NOT EXISTS signal_clusters (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    entity_key      TEXT NOT NULL,
    layers_covered  TEXT NOT NULL DEFAULT '[]',   -- JSON array
    confidence      DOUBLE PRECISION,
    validation_status TEXT,
    rejection_reason  TEXT,
    finding_id      INTEGER,                       -- FK to findings (if promoted)
    created_at      DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clusters_agent ON signal_clusters(agent_id, created_at DESC);

-- Table-backed allowlist (complements static attacklens/allowlist.py lists)
CREATE TABLE IF NOT EXISTS detection_allowlist (
    id         BIGSERIAL PRIMARY KEY,
    rule_id    TEXT,        -- NULL = all rules
    entity_key TEXT,        -- NULL = all entities
    agent_id   TEXT,        -- NULL = all agents
    reason     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION          -- NULL = never expires
);
CREATE INDEX IF NOT EXISTS idx_allowlist_lookup
    ON detection_allowlist(rule_id, entity_key, agent_id);

-- FP-history per rule + host class + ISO week (drives confidence FP penalty)
CREATE TABLE IF NOT EXISTS rule_fp_stats (
    rule_id       TEXT NOT NULL,
    host_class    TEXT NOT NULL,
    window_start  TEXT NOT NULL,    -- ISO week 'YYYY-WW'
    tp_count      INTEGER DEFAULT 0,
    fp_count      INTEGER DEFAULT 0,
    accepted_risk INTEGER DEFAULT 0,
    updated_at    DOUBLE PRECISION,
    PRIMARY KEY (rule_id, host_class, window_start)
);

-- Auto-generated allowlist suggestions for engineer review
CREATE TABLE IF NOT EXISTS allowlist_suggestions (
    id           BIGSERIAL PRIMARY KEY,
    rule_id      TEXT NOT NULL,
    entity_key   TEXT NOT NULL,
    fp_count     INTEGER NOT NULL DEFAULT 0,
    last_fp_at   DOUBLE PRECISION,
    suggested_at DOUBLE PRECISION NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',    -- 'pending'|'approved'|'rejected'
    reviewed_by  TEXT,
    reviewed_at  DOUBLE PRECISION,
    UNIQUE(rule_id, entity_key)
);

-- ── Analyst-defined custom correlation rules ──────────────────────────────
CREATE TABLE IF NOT EXISTS custom_correlation_rules (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL DEFAULT '',
    description        TEXT NOT NULL DEFAULT '',
    enabled            INTEGER NOT NULL DEFAULT 1,
    action             TEXT NOT NULL DEFAULT 'alert',
    severity           TEXT NOT NULL DEFAULT 'medium',
    confidence         INTEGER NOT NULL DEFAULT 70,
    conditions         TEXT NOT NULL DEFAULT '{"operator":"AND","rules":[]}',
    required_count     INTEGER NOT NULL DEFAULT 1,
    time_window_hours  INTEGER NOT NULL DEFAULT 24,
    tags               TEXT NOT NULL DEFAULT '[]',
    attack_chain       TEXT NOT NULL DEFAULT '[]',
    recommendation     TEXT NOT NULL DEFAULT '',
    created_by         TEXT NOT NULL DEFAULT 'analyst',
    created_at         DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at         DOUBLE PRECISION NOT NULL DEFAULT 0,
    hit_count          INTEGER NOT NULL DEFAULT 0,
    last_hit_at        DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_custom_corr_enabled ON custom_correlation_rules(enabled, created_at DESC);

-- ── Per-finding case management ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS finding_cases (
    finding_id  INTEGER          PRIMARY KEY,
    status      TEXT             NOT NULL DEFAULT 'new',
    assignee    TEXT             NOT NULL DEFAULT '',
    priority    INTEGER          NOT NULL DEFAULT 3,
    due_date    TEXT             NOT NULL DEFAULT '',
    notes       TEXT             NOT NULL DEFAULT '',
    sla_due_at  TEXT             NOT NULL DEFAULT '',
    created_at  DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at  DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS finding_timeline (
    id          BIGSERIAL        PRIMARY KEY,
    finding_id  INTEGER          NOT NULL,
    actor       TEXT             NOT NULL DEFAULT 'system',
    action      TEXT             NOT NULL,
    from_status TEXT,
    to_status   TEXT,
    note        TEXT,
    created_at  DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_finding_timeline_fid ON finding_timeline(finding_id, id);
"""

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# SLA hours by severity (Critical=4h, High=24h, Medium=7d, Low=30d, Info=90d)
_SLA_HOURS = {"critical": 4, "high": 24, "medium": 168, "low": 720, "info": 2160}

# Valid SOC workflow statuses
# Canonical status vocabulary lives in finding_lifecycle (single source of truth).
_SOC_STATUSES = set(_lc.ALL_STATUSES)

# Migrations: add SOC workflow columns to existing findings table
_SOC_MIGRATIONS = [
    ("findings",     "external_id",       "TEXT    DEFAULT ''"),
    ("findings",     "status",        "TEXT    DEFAULT 'new'"),
    ("findings",     "assignee",      "TEXT    DEFAULT ''"),
    ("findings",     "sla_due",       "DOUBLE PRECISION    DEFAULT 0"),
    ("findings",     "closed_at",     "DOUBLE PRECISION    DEFAULT NULL"),
    ("findings",     "priority",      "INTEGER DEFAULT 0"),
    ("findings",     "analyst_notes", "TEXT    DEFAULT ''"),
    ("findings",     "composite_score",   "DOUBLE PRECISION    DEFAULT 0"),
    ("findings",     "epss_score",        "DOUBLE PRECISION    DEFAULT 0"),
    ("findings",     "kev",               "INTEGER DEFAULT 0"),
    ("findings",     "exploit_available", "INTEGER DEFAULT 0"),
    ("findings",     "exploit_sources",   "TEXT    DEFAULT '[]'"),
    ("findings",     "asset_tier",        "TEXT    DEFAULT ''"),
    ("findings",     "asset_importance",  "DOUBLE PRECISION    DEFAULT 0"),
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
    # Detection Confidence Engine columns (added on existing findings rows)
    ("findings", "signal_cluster_id",       "INTEGER"),
    ("findings", "confidence",              "DOUBLE PRECISION"),
    ("findings", "validation_gates_passed", "TEXT    DEFAULT '[]'"),
    ("findings", "layers_involved",         "TEXT    DEFAULT '[]'"),
    ("findings", "host_class",              "TEXT    DEFAULT ''"),
    # AI Precision Validation columns
    ("findings", "precision_score",         "DOUBLE PRECISION    DEFAULT 0.0"),
    ("findings", "precision_factors",       "TEXT    DEFAULT '{}'"),
    ("findings", "ai_verdict",              "TEXT    DEFAULT '{}'"),
    ("findings", "ai_validation_used",      "INTEGER DEFAULT 0"),
    ("findings", "terrain_validation",      "TEXT    DEFAULT '{}'"),
    # Unique Finding ID + Attack Terrain FK + Actions Log
    ("findings", "finding_uid",             "TEXT    DEFAULT ''"),
    ("findings", "terrain_id",              "TEXT    DEFAULT ''"),
    ("findings", "actions_log",             "TEXT    DEFAULT '[]'"),
    # Enhanced soc_activity columns
    ("soc_activity", "finding_uid",         "TEXT    DEFAULT ''"),
    ("soc_activity", "ip_address",          "TEXT    DEFAULT ''"),
    ("soc_activity", "session_id",          "TEXT    DEFAULT ''"),
    ("soc_activity", "changed_fields",      "TEXT    DEFAULT '{}'"),
    ("soc_activity", "metadata",            "TEXT    DEFAULT '{}'"),
    # Terrain source provenance — captures why a finding landed in its terrain
    ("findings", "terrain_source",          "TEXT    DEFAULT ''"),
    # Unified exploitability score (CVSS+EPSS+KEV+exploit+recency+asset)
    ("findings", "exploitability_score",    "DOUBLE PRECISION DEFAULT 0"),
    ("findings", "exploitability_band",     "TEXT    DEFAULT ''"),
    # Provider-agnostic AI layer — analysis cache columns
    ("ai_analysis", "provider",       "TEXT DEFAULT ''"),
    ("ai_analysis", "urgency",        "TEXT DEFAULT 'scheduled'"),
    ("ai_analysis", "mitre_context",  "TEXT DEFAULT ''"),
    ("ai_analysis", "latency_ms",     "DOUBLE PRECISION DEFAULT 0"),
    # Provider-agnostic AI layer — remediation cache columns
    ("remediation_plans", "provider",     "TEXT DEFAULT ''"),
    ("remediation_plans", "compensating", "TEXT DEFAULT ''"),
    ("remediation_plans", "tokens_used",  "INTEGER DEFAULT 0"),
    ("remediation_plans", "latency_ms",   "DOUBLE PRECISION DEFAULT 0"),
    # Ingest dedup tracking — when content last changed vs just re-seen
    ("findings", "content_changed_at",   "DOUBLE PRECISION DEFAULT 0"),
    ("findings", "consecutive_unchanged", "INTEGER DEFAULT 0"),
]


@dataclass
class _CacheEntry:
    content_hash: str
    last_seen_at: float
    consecutive_unchanged: int = 0
    pending_count: int = 0          # heartbeats accumulated since last DB flush


class IngestDeduplicator:
    """
    Write-through in-memory dedup cache for agent findings.

    For unchanged findings (same content hash as last seen), skips the DB
    SELECT entirely and accumulates a heartbeat counter. A background task
    flushes accumulated heartbeats to DB in one batch UPDATE every 30s,
    reducing DB writes by ~96% in stable environments.

    Identity key  : (agent_id, category, item_key)  — what makes a finding unique
    Content hash  : SHA-256 of mutable payload fields  — what the finding says now

    Three outcomes per upsert call:
      "miss"      → not in cache; caller does normal DB SELECT path
      "unchanged" → cached and hash matches; heartbeat counted, DB skipped
      "changed"   → cached but hash differs; caller does full DB UPDATE, cache refreshed

    Edge cases handled:
      - Manager restart: cache cold-starts; DB is always authoritative
      - Cache eviction: LRU; evicted entries re-enter on next access
      - Finding closed: explicit invalidate() call prevents stale cache reads
      - Crash mid-flush: max heartbeat lag = flush_interval (30s); last_detected_at
        may trail by one interval — acceptable for telemetry workloads
    """

    MAX_SIZE    = 200_000   # ~40 MB at ~200 bytes/entry
    FLUSH_EVERY = 30.0      # seconds between batch heartbeat flushes

    def __init__(self) -> None:
        self._cache: OrderedDict[tuple, _CacheEntry] = OrderedDict()
        self._flush_task: Optional[asyncio.Task] = None
        self._hits   = 0
        self._misses = 0
        self._changes = 0

    # ── Cache operations (synchronous, called inside _lock) ──────────────────

    def check(self, agent_id: str, category: str, item_key: str,
              content_hash: str, ts: float) -> str:
        key = (agent_id, category, item_key)
        entry = self._cache.get(key)
        if entry is None:
            self._misses += 1
            return "miss"
        self._cache.move_to_end(key)          # LRU refresh
        if entry.content_hash == content_hash:
            entry.last_seen_at = max(entry.last_seen_at, ts)
            entry.consecutive_unchanged += 1
            entry.pending_count += 1
            self._hits += 1
            return "unchanged"
        self._changes += 1
        return "changed"

    def put(self, agent_id: str, category: str, item_key: str,
            content_hash: str, ts: float, consecutive_unchanged: int = 0) -> None:
        key = (agent_id, category, item_key)
        self._evict()
        self._cache[key] = _CacheEntry(
            content_hash=content_hash,
            last_seen_at=ts,
            consecutive_unchanged=consecutive_unchanged,
        )

    def invalidate(self, agent_id: str, category: str, item_key: str) -> None:
        self._cache.pop((agent_id, category, item_key), None)

    def _evict(self) -> None:
        while len(self._cache) >= self.MAX_SIZE:
            self._cache.popitem(last=False)   # remove oldest (LRU)

    # ── Background flush ──────────────────────────────────────────────────────

    def start(self, conn) -> None:
        self._conn = conn
        self._flush_task = asyncio.get_event_loop().create_task(
            self._flush_loop(), name="ingest-dedup-flush"
        )

    async def stop(self) -> None:
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self._flush_now()

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self.FLUSH_EVERY)
            try:
                await self._flush_now()
            except Exception as exc:
                log.warning("ingest-dedup flush error: %s", exc)

    async def _flush_now(self) -> None:
        pending = [(k, e) for k, e in self._cache.items() if e.pending_count > 0]
        if not pending:
            return
        for (agent_id, category, item_key), entry in pending:
            try:
                await self._conn.execute(
                    """UPDATE findings
                       SET last_detected_at    = $1,
                           scan_count          = scan_count + $2,
                           consecutive_unchanged = $3
                       WHERE agent_id=$4 AND category=$5 AND item_key=$6""",
                    entry.last_seen_at,
                    entry.pending_count,
                    entry.consecutive_unchanged,
                    agent_id, category, item_key,
                )
            except Exception as exc:
                log.debug("dedup flush row error %s/%s/%s: %s",
                          agent_id, category, item_key, exc)
            else:
                entry.pending_count = 0
        try:
            await self._conn.commit()
        except Exception as exc:
            log.warning("dedup flush commit error: %s", exc)
        log.debug("ingest-dedup flushed %d heartbeats", len(pending))

    def stats(self) -> dict:
        total = self._hits + self._misses + self._changes
        return {
            "cache_size":   len(self._cache),
            "hits":         self._hits,
            "misses":       self._misses,
            "changes":      self._changes,
            "hit_rate":     round(self._hits / total, 4) if total else 0.0,
            "pending_flush": sum(e.pending_count for e in self._cache.values()),
        }


class IntelDB:
    """
    Async Postgres wrapper for the intel database (migrated from SQLite —
    see manager/pg_pool.py for the compatibility layer that kept query call
    sites largely unchanged).

    Postgres handles concurrent writers natively, so unlike the old
    SQLitePool there's no single-writer bottleneck here — read() and write()
    both draw from one connection pool. self._conn is aliased to a write
    checkout for backwards compatibility with all existing write methods.
    """

    def __init__(self, dsn: str) -> None:
        self._path = dsn  # kept as _path for any code/logs still reading it
        self._dsn = dsn
        self._pool: Optional[PgPool] = None
        self._conn = None
        self._lock = asyncio.Lock()  # kept for write-serialisation within Python
        self._dedup = IngestDeduplicator()
        self._finding_notification_handler: Optional[FindingNotificationHandler] = None

    def set_finding_notification_handler(
        self, handler: Optional[FindingNotificationHandler],
    ) -> None:
        """Register an async background callback for material finding events."""
        self._finding_notification_handler = handler

    def _schedule_finding_notification(self, finding: dict, event: str) -> None:
        handler = self._finding_notification_handler
        if handler is None:
            return
        payload = dict(finding)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(handler(payload, event))

        def _done(t) -> None:
            try:
                t.result()
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                log.debug("finding notification handler failed: %s", exc)

        task.add_done_callback(_done)

    async def init(self) -> None:
        self._pool = PgPool(self._dsn, readers=3)
        await self._pool.init()
        # Alias a long-lived write connection for all existing write code
        # (zero call-site changes needed). Postgres can hold one connection
        # open indefinitely without blocking other writers, unlike SQLite's
        # single-writer model this used to compensate for.
        self._conn_ctx = self._pool.write()
        self._conn = await self._conn_ctx.__aenter__()

        # 1. Migrations first: add columns that exist in _SOC_MIGRATIONS but may
        #    be absent on old databases.  Must run before executescript because
        #    _SCHEMA creates indexes that reference these migrated columns
        #    (e.g. idx_find_composite on composite_score).  Errors are silently
        #    ignored — the column already exists, or the table doesn't exist yet
        #    (fresh DB) and will be created by executescript below.
        #
        #    Postgres-specific: unlike SQLite, ANY failed statement poisons the
        #    rest of the current transaction (InFailedSQLTransactionError) until
        #    a rollback — so swallowing the Python exception alone isn't enough;
        #    the transaction itself must be rolled back too, or every subsequent
        #    statement (the remaining migrations, then executescript) fails.
        for table, col, defn in _SOC_MIGRATIONS:
            try:
                await self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col} {defn}"
                )
                await self._conn.commit()
            except Exception:
                await self._conn.rollback()  # reset the poisoned transaction

        # 2. Backfill external_id before creating the UNIQUE INDEX on it.
        #    On existing DBs all rows may have external_id=''; giving each a
        #    distinct value here prevents the CREATE UNIQUE INDEX in step 3
        #    from failing with a UNIQUE constraint violation.
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
            await self._conn.rollback()  # findings table doesn't exist yet on a fresh DB

        # 3. Create all tables + indexes (idempotent CREATE IF NOT EXISTS).
        #    Migrations and backfill above ensure existing data is clean before
        #    the UNIQUE INDEX on external_id is (re-)created.
        async with self._conn.executescript(_SCHEMA):
            pass
        await self._conn.commit()

        # 4. Seed terrain lookup data (idempotent — ON CONFLICT DO NOTHING).
        try:
            now = time.time()
            terrain_seed = [
                ('citadels','Citadels','Execution, persistence, and malware signals','#ef4444',now),
                ('vector','Vector','Network connections, ports, ARP, lateral movement','#f97316',now),
                ('origin','Origin','Vulnerabilities, packages, SBOM, config drift','#eab308',now),
                ('identity','Identity','User accounts, credentials, identity anomalies','#3b82f6',now),
                ('posture','Posture','Security posture, SIP, Gatekeeper, FileVault, firewall','#8b5cf6',now),
            ]
            for row in terrain_seed:
                await self._conn.execute(
                    "INSERT INTO terrains(id,label,description,color,created_at) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
                    row,
                )
            await self._conn.commit()
        except Exception as _terr_exc:
            await self._conn.rollback()
            log.warning("Terrain seeding skipped (table may not exist): %s", _terr_exc)

        # 5. Backfill finding_uid for existing findings that don't have one yet.
        #    Uses uuid.uuid4().hex for each row without a UID.
        try:
            async with self._conn.execute(
                "SELECT id FROM findings WHERE finding_uid IS NULL OR finding_uid = ''"
            ) as cur:
                uid_rows = await cur.fetchall()
            for row in uid_rows:
                await self._conn.execute(
                    "UPDATE findings SET finding_uid=? WHERE id=?",
                    (uuid.uuid4().hex, row[0]),
                )
            if uid_rows:
                await self._conn.commit()
                log.info("Backfilled finding_uid for %d existing findings", len(uid_rows))
        except Exception:
            await self._conn.rollback()

        # 6. Backfill terrain_id for existing findings based on category → terrain mapping.
        try:
            from .attacklens.terrain_validators import CATEGORY_TO_TERRAIN
            for category, terrain_id in CATEGORY_TO_TERRAIN.items():
                await self._conn.execute(
                    "UPDATE findings SET terrain_id=? "
                    "WHERE (terrain_id IS NULL OR terrain_id = '') AND category=?",
                    (terrain_id, category),
                )
            await self._conn.commit()
        except Exception:
            await self._conn.rollback()

        # 7. Backfill terrain_source for existing findings from their category.
        try:
            async with self._conn.execute(
                "SELECT id, category FROM findings WHERE terrain_source IS NULL OR terrain_source = ''"
            ) as cur:
                ts_rows = await cur.fetchall()
            for row in ts_rows:
                await self._conn.execute(
                    "UPDATE findings SET terrain_source=? WHERE id=?",
                    (row["category"], row["id"]),
                )
            if ts_rows:
                await self._conn.commit()
                log.info("Backfilled terrain_source for %d existing findings", len(ts_rows))
        except Exception:
            await self._conn.rollback()

        log.info("IntelDB initialised at %s (pool readers=3)", self._path)
        self._dedup.start(self._conn)

    async def close(self) -> None:
        await self._dedup.stop()
        if self._pool:
            # Release the long-held write checkout BEFORE closing the pool —
            # asyncpg.Pool.close() waits for all checked-out connections to be
            # released first, so skipping this would hang forever.
            if getattr(self, "_conn_ctx", None) is not None:
                await self._conn_ctx.__aexit__(None, None, None)
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

        # ── Unified exploitability score ─────────────────────────────────────
        # Computed at the single write chokepoint so every emit path gets a
        # consistent score. Recency uses cve_published_ts when the caller
        # supplies it (NVD worker does), else neutral.
        try:
            from .threat.exploitability import exploitability_scorer
            _exp = exploitability_scorer.compute(
                f, cve_published_ts=f.get("cve_published_ts"),
            )
            exploitability_score = _exp.score
            exploitability_band  = _exp.band
        except Exception:
            exploitability_score = 0.0
            exploitability_band  = ""

        # ── Unique Finding ID (UUIDv4 hex) ──────────────────────────────────
        # Use existing finding_uid from the caller if provided (e.g. on re-insert),
        # otherwise generate a fresh one.  Stored in findings.finding_uid.
        finding_uid = f.get("finding_uid") or uuid.uuid4().hex
        f["finding_uid"] = finding_uid

        # ── Attack Terrain classification ────────────────────────────────────
        # Resolve the canonical terrain from the finding's category.  Callers
        # (e.g. the detection engine) may pre-set terrain_id; if absent we
        # derive it here via terrain_validators, which is the single source of
        # truth for category→terrain mapping.
        terrain_id = f.get("terrain_id") or ""
        if not terrain_id:
            try:
                from .attacklens.terrain_validators import terrain_for
                terrain_id = terrain_for(f)
            except Exception:
                terrain_id = "origin"  # safest fallback
        f["terrain_id"] = terrain_id

        # ── Terrain source provenance ────────────────────────────────────────
        # Captures the detection source (rule_id | source | category) that drove
        # the terrain classification — visible in the UI as "via <source>".
        terrain_source = f.get("terrain_source") or ""
        if not terrain_source:
            terrain_source = f.get("source") or f.get("rule_id") or category
        f["terrain_source"] = terrain_source

        # ── Actions log ──────────────────────────────────────────────────────
        # Lightweight summary embedded on the finding itself.  The full detail
        # (ip_address, session_id, changed_fields) lives in soc_activity.
        # On first insert, seed with a "system.created" entry.
        actions_log = f.get("actions_log") or []
        if not actions_log:
            actions_log = [{
                "action_id": uuid.uuid4().hex[:12],
                "action": "system.created",
                "actor": "system",
                "timestamp": ts,
            }]
        actions_log_j = json.dumps(actions_log, default=str)

        # AI precision validation fields
        precision_score   = float(f.get("precision_score") or 0.0)
        precision_factors_j = json.dumps(f.get("precision_factors") or {}, default=str)
        ai_verdict_j      = json.dumps(f.get("ai_verdict") or {}, default=str)
        # `ai_validation_used` = LLM verdict actually ran (not just deterministic
        # scoring).  Respect an explicit 0 from the engine's legacy-precision
        # path; only auto-detect when the caller didn't set it.
        if "ai_validation_used" in f:
            ai_validation_used = 1 if f.get("ai_validation_used") else 0
        else:
            av = f.get("ai_verdict") or {}
            # A non-empty ai_verdict dict with a real label means the LLM ran.
            llm_actually_ran = isinstance(av, dict) and bool(av.get("label"))
            ai_validation_used = 1 if llm_actually_ran else 0

        # Terrain validation (per-criterion checklist) — see terrain_validators.py
        terrain_validation_j = json.dumps(f.get("terrain_validation") or {}, default=str)

        async with self._lock:
            # ── Cache-first dedup ────────────────────────────────────────────
            # Check in-memory cache before touching the DB. For stable findings
            # (same content hash) this eliminates both the SELECT and the UPDATE,
            # reducing DB ops by ~96% for unchanged agent environments.
            cache_result = self._dedup.check(agent_id, category, item_key, fp, ts)
            if cache_result == "unchanged":
                return "unchanged"

            row = await self._fetchone(
                "SELECT id, external_id, fingerprint, first_detected_at, "
                "severity, exploitability_band, exploitability_score, consecutive_unchanged "
                "FROM findings WHERE agent_id=? AND category=? AND item_key=?",
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
                     exploitability_score,exploitability_band,
                     priority_reason,action_plan,mitre_technique,mitre_tactic,
                     first_detected_at,last_detected_at,scan_count,is_active,tags,
                     status,assignee,sla_due,priority,analyst_notes,
                     precision_score,precision_factors,ai_verdict,ai_validation_used,
                     terrain_validation,finding_uid,terrain_id,actions_log,
                     content_changed_at,consecutive_unchanged)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,?,
                           'new','',?,0,'',?,?,?,?,?,?,?,?,?,0)
                """, (agent_id, category, item_key, fp,
                      sev, f.get("score",0),
                      f.get("title",""), f.get("description",""),
                      evidence_j, f.get("source",""), f.get("rule_id",""),
                      cve_j, f.get("cvss_score"), f.get("cvss_vector",""),
                      composite, epss, kev, exploit, exploit_j, asset_tier,
                      asset_imp, exploitability_score, exploitability_band,
                      priority_reason, action_j,
                      f.get("mitre_technique",""), f.get("mitre_tactic",""),
                      ts, ts, tags_j, sla_due,
                      precision_score, precision_factors_j, ai_verdict_j,
                      ai_validation_used, terrain_validation_j,
                      finding_uid, terrain_id, actions_log_j, ts))
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
                        finding_uid=finding_uid,
                    )
                    notify_payload = {
                        **f,
                        "id": new_row["id"],
                        "external_id": external_id,
                        "exploitability_score": exploitability_score,
                        "exploitability_band": exploitability_band,
                    }
                    if _finding_is_alertable(notify_payload):
                        self._schedule_finding_notification(notify_payload, "created")
                await self._append_timeline(agent_id, category, "added",
                                            item_key, f.get("title",""),
                                            evidence_j, None, ts)
                self._dedup.put(agent_id, category, item_key, fp, ts,
                                consecutive_unchanged=0)
                return "new"

            elif row["fingerprint"] != fp:
                await self._conn.execute("""
                    UPDATE findings SET
                        fingerprint=?, severity=?, score=?, title=?,
                        description=?, evidence=?, source=?, rule_id=?,
                        cve_ids=?, cvss_score=?, cvss_vector=?,
                        composite_score=?, epss_score=?, kev=?,
                        exploit_available=?, exploit_sources=?, asset_tier=?,
                        asset_importance=?, exploitability_score=?,
                        exploitability_band=?, priority_reason=?, action_plan=?,
                        mitre_technique=?, mitre_tactic=?,
                        last_detected_at=?, scan_count=scan_count+1,
                        is_active=1, tags=?,
                        precision_score=?, precision_factors=?,
                        ai_verdict=?, ai_validation_used=?,
                        terrain_validation=?, terrain_id=?,
                        actions_log=?,
                        content_changed_at=?, consecutive_unchanged=0
                    WHERE agent_id=? AND category=? AND item_key=?
                """, (fp, f.get("severity","info"), f.get("score",0),
                      f.get("title",""), f.get("description",""),
                      evidence_j, f.get("source",""), f.get("rule_id",""),
                      cve_j, f.get("cvss_score"), f.get("cvss_vector",""),
                      composite, epss, kev, exploit, exploit_j, asset_tier,
                      asset_imp, exploitability_score, exploitability_band,
                      priority_reason, action_j,
                      f.get("mitre_technique",""), f.get("mitre_tactic",""),
                      ts, tags_j,
                      precision_score, precision_factors_j, ai_verdict_j,
                      ai_validation_used, terrain_validation_j,
                      terrain_id, actions_log_j, ts,
                      agent_id, category, item_key))
                await self._conn.commit()
                await self._append_timeline(agent_id, category, "modified",
                                            item_key, f.get("title",""),
                                            evidence_j, row["fingerprint"], ts)
                previous_alertable = _finding_is_alertable(row)
                current_alertable = _finding_is_alertable({
                    **f,
                    "exploitability_score": exploitability_score,
                    "exploitability_band": exploitability_band,
                })
                if current_alertable and not previous_alertable:
                    notify_payload = {
                        **f,
                        "id": row["id"],
                        "external_id": row["external_id"],
                        "exploitability_score": exploitability_score,
                        "exploitability_band": exploitability_band,
                    }
                    self._schedule_finding_notification(notify_payload, "escalated")
                self._dedup.put(agent_id, category, item_key, fp, ts,
                                consecutive_unchanged=0)
                return "updated"

            else:
                # DB path for heartbeat on cache miss — populate cache and defer
                # future heartbeats. The SELECT already happened so we know the
                # DB state; use it to seed consecutive_unchanged from the DB row.
                db_consec = row["consecutive_unchanged"] or 0
                self._dedup.put(agent_id, category, item_key, fp, ts,
                                consecutive_unchanged=db_consec)
                # Also do the immediate heartbeat so last_detected_at is never
                # stale by more than one flush interval.
                entry = self._dedup._cache.get((agent_id, category, item_key))
                if entry:
                    entry.pending_count += 1
                    entry.consecutive_unchanged += 1
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

    async def get_active_findings_global(
        self,
        *,
        categories: list[str] | None = None,
        since: float | None = None,
        limit: int = 5000,
        live_agent_ids: list[str] | None = None,
    ) -> list[dict]:
        """Active findings across ALL agents — the input to fleet-wide / global
        correlation. The per-agent get_findings() can never see a campaign that
        spans hosts (distributed C2, worm propagation, supply-chain outbreak);
        this is the cross-host read that makes that visible.

        Bounded by LIMIT and (optionally) a recency cutoff + category filter so a
        large fleet doesn't pull the whole table. Excludes the synthetic
        __fleet__ pseudo-agent so fleet correlations never recurse on themselves.

        `live_agent_ids`: when given, also excludes findings whose source agent
        has gone stale — a campaign rule with min_hosts=3 should mean 3
        CURRENTLY-reporting hosts, not 2 live ones plus a third that went dark
        weeks ago. Without this, a stale agent's lingering findings can be the
        deciding vote in a fleet-wide false positive.
        """
        parts = ["is_active=1", "agent_id != ?"]
        args: list = [FLEET_AGENT_ID]
        if categories:
            placeholders = ",".join("?" for _ in categories)
            parts.append(f"category IN ({placeholders})")
            args.extend(categories)
        if since is not None:
            parts.append("last_detected_at >= ?")
            args.append(since)
        if live_agent_ids is not None:
            if not live_agent_ids:
                return []
            placeholders = ",".join("?" * len(live_agent_ids))
            parts.append(f"agent_id IN ({placeholders})")
            args.extend(live_agent_ids)
        where = " AND ".join(parts)
        rows = await self._fetchall(
            f"SELECT * FROM findings WHERE {where} "
            f"ORDER BY last_detected_at DESC LIMIT ?",
            (*args, limit),
        )
        return [dict(r) for r in rows]

    async def search_by_external_id(
        self,
        id_term: str,
        *,
        active_only: bool = False,
        agent_id: str | None = None,
        terrain_id: str | None = None,
        limit: int = 20,
    ) -> list[dict]:
        """Direct indexed lookup by external_id prefix or exact match.  Uses the
        UNIQUE index idx_find_external_id — O(log n), not a full scan.  Accepts
        partial prefixes like 'AL-F-000' so the analyst can type incrementally."""
        parts = ["f.external_id LIKE ?"]
        args: list = [id_term.replace("*", "%") + "%"]
        if active_only:
            parts.append("f.is_active=1")
        if agent_id:
            parts.append("f.agent_id=?")
            args.append(agent_id)
        if terrain_id:
            parts.append("f.terrain_id=?")
            args.append(terrain_id)
        rows = await self._fetchall(
            "SELECT f.*, "
            "       ar.os         AS agent_os, "
            "       ar.hostname   AS agent_hostname, "
            "       ar.os_version AS agent_os_version "
            "FROM findings f "
            "LEFT JOIN asset_registry ar ON ar.agent_id = f.agent_id "
            f"WHERE {' AND '.join(parts)} "
            "ORDER BY f.external_id "
            "LIMIT ?",
            (*args, limit),
        )
        return [_shape_finding(dict(r)) for r in rows]

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

    async def auto_resolve_absent(
        self,
        agent_id: str,
        categories: list[str],
        cutoff_ts: float,
        reason: str = "evidence_cleared",
    ) -> int:
        """Auto-resolve active findings whose evidence vanished from a fresh snapshot.

        A finding is resolved when `last_detected_at < cutoff_ts` — i.e. the agent
        re-collected the section AFTER cutoff_ts and the entity was NOT in it, so it
        was never re-confirmed. This is how a closed port / removed package / exited
        process turns its incident from active → resolved instead of lingering as a
        false positive.

        Returns the count resolved. The caller MUST only pass categories from a
        fresh, non-empty snapshot — never resolve on an empty/errored section
        (that's "data missed", not "evidence gone").
        """
        if not categories:
            return 0
        ts = time.time()
        cat_ph = ",".join("?" * len(categories))
        async with self._lock:
            rows = await self._fetchall(
                f"SELECT id, category, item_key, title FROM findings "
                f"WHERE agent_id=? AND is_active=1 "
                f"AND category IN ({cat_ph}) AND last_detected_at < ?",
                (agent_id, *categories, cutoff_ts),
            )
            if not rows:
                return 0
            id_ph = ",".join("?" * len(rows))
            ids = [r["id"] for r in rows]
            await self._conn.execute(
                f"UPDATE findings SET is_active=0, resolved_at=?, status='auto_resolved' "
                f"WHERE agent_id=? AND id IN ({id_ph})",
                (ts, agent_id, *ids),
            )
            for r in rows:
                # reason carried in the timeline note (item_data) field
                await self._append_timeline(
                    agent_id, r["category"], "auto_resolved",
                    r["item_key"], r["title"], reason, None, ts,
                )
                self._dedup.invalidate(agent_id, r["category"], r["item_key"])
            await self._conn.commit()
        return len(rows)

    async def prune_inactive(self, cutoff_ts: float) -> dict:
        """Bound intel.db to a retention window (Settings → Data Retention,
        same cutoff as raw telemetry — see server.py's _cleanup_store).

        Only removes the HISTORICAL backlog: resolved findings, closed
        correlations, and timeline events older than cutoff. Never touches a
        currently-active finding/correlation regardless of age — "active"
        means it represents real, currently-true state, and deleting it
        because it's old would be the exact data-loss-to-correlations
        regression this engine is built to avoid. change_timeline is pure
        audit history with no active/inactive concept, so it prunes
        unconditionally by age.
        """
        deleted = {"findings": 0, "correlations": 0, "change_timeline": 0}
        async with self._lock:
            cur = await self._conn.execute(
                "DELETE FROM findings WHERE is_active=0 AND last_detected_at < ?",
                (cutoff_ts,),
            )
            deleted["findings"] = cur.rowcount or 0
            cur = await self._conn.execute(
                "DELETE FROM correlations WHERE is_active=0 AND last_detected < ?",
                (cutoff_ts,),
            )
            deleted["correlations"] = cur.rowcount or 0
            cur = await self._conn.execute(
                "DELETE FROM change_timeline WHERE detected_at < ?",
                (cutoff_ts,),
            )
            deleted["change_timeline"] = cur.rowcount or 0
            await self._conn.commit()
        return deleted

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
            if row:
                await self._append_timeline(
                    agent_id, row["category"], "resolved",
                    row["item_key"], row["title"], None, None, ts,
                )
                self._dedup.invalidate(agent_id, row["category"], row["item_key"])
            # Single commit covers both the UPDATE and the timeline INSERT.
            await self._conn.commit()

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
        async with self._lock:
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

    async def is_malicious_hash(self, sha256: str) -> bool:
        """True iff sha256 is present in ioc_cache as a non-expired malicious hash."""
        if not sha256:
            return False
        row = await self._fetchone(
            "SELECT 1 FROM ioc_cache "
            "WHERE ioc_type='hash' AND ioc_value=? AND expires_at>? LIMIT 1",
            (sha256.lower(), time.time()),
        )
        return row is not None

    # ── CVE cache ─────────────────────────────────────────────────────────────

    async def get_cve_cache(self, cache_key: str) -> Optional[list]:
        row = await self._fetchone(
            "SELECT data_json FROM cve_cache WHERE cache_key=? AND expires_at>?",
            (cache_key, time.time()),
        )
        return json.loads(row["data_json"]) if row else None

    async def set_cve_cache(self, cache_key: str, data: list, ttl: int) -> None:
        async with self._lock:
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
        async with self._lock:
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

    async def get_cve_published_ts(self, cve_id: str) -> float:
        """
        Best-effort CVE publication epoch for vulnerability-recency scoring.
        Checks cve_entries then nvd_cve_local. Returns 0.0 when unknown.
        """
        published = ""
        for table in ("cve_entries", "nvd_cve_local"):
            try:
                row = await self._fetchone(
                    f"SELECT published_at FROM {table} WHERE cve_id=?", (cve_id,))
                if row and row["published_at"]:
                    published = str(row["published_at"])
                    break
            except Exception:
                continue
        if not published:
            return 0.0
        s = published.strip().replace("Z", "+00:00")
        from datetime import datetime
        for fmt in (None, "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                if fmt is None:
                    return datetime.fromisoformat(s).timestamp()
                return datetime.strptime(s.split("+")[0], fmt).timestamp()
            except (ValueError, TypeError):
                continue
        return 0.0

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
        async with self._lock:
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
        async with self._lock:
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
        terrain_id: str | None = None,
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
        min_precision: float | None = None,
        live_agent_ids: list[str] | None = None,
    ) -> list[dict]:
        """Global findings list with full SOC filters.

        `min_precision` filters by the AI Precision Validator composite score
        (precision_score in [0,1]).  The Validated Findings page uses 0.9 to
        only show high-confidence findings.

        `live_agent_ids`: when given AND no explicit `agent_id` was requested
        AND `active_only` is True, restrict to these agent_ids — excludes
        findings whose source agent has gone stale (hasn't reported within
        config.py's stale_agent_sec) from fleet-wide views. An explicit
        single-agent query is NEVER filtered this way — an analyst
        investigating one agent should see its findings regardless of how
        long it's been offline. None (the default) disables this entirely —
        callers that haven't computed agent liveness get the old behavior.

        Each row is left-joined to asset_registry so the response carries the
        agent's OS as `agent_os` — the UI uses this to lock the remediation
        panel to the right command set per finding.
        """
        parts: list[str] = []
        args: list = []
        if agent_id:
            parts.append("f.agent_id=?"); args.append(agent_id)
        elif live_agent_ids is not None and active_only:
            if not live_agent_ids:
                return []   # no live agents at all — nothing to show
            placeholders = ",".join("?" * len(live_agent_ids))
            parts.append(f"f.agent_id IN ({placeholders})")
            args.extend(live_agent_ids)
        if severity:
            parts.append("f.severity=?"); args.append(severity)
        if min_precision is not None:
            parts.append("COALESCE(f.precision_score, 0) >= ?"); args.append(float(min_precision))
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
        if terrain_id:
            parts.append("f.terrain_id=?"); args.append(terrain_id)
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
            # Full-text search path, via Postgres tsvector/tsquery (was SQLite
            # FTS5 MATCH against a separate virtual table + JOIN; now a direct
            # predicate against findings.search_vector — see _SCHEMA). Also:
            # previously also LEFT JOINed a subquery selecting `name FROM
            # agents` — agents lives in manager.db, a SEPARATE database from
            # this one (intel.db); there is no `agents` table here. That made
            # every search query throw "no such table: agents" — confirmed by
            # reproducing it directly against the live database. The resulting
            # agent_name column was never read anywhere (not in _enrich, not in
            # the frontend), so the fix is to drop it, matching the non-search
            # branch below.
            rows = await self._fetchall(
                f"SELECT f.*, "
                f"       ar.os         AS agent_os, "
                f"       ar.hostname   AS agent_hostname, "
                f"       ar.os_version AS agent_os_version "
                f"FROM findings f "
                f"LEFT JOIN asset_registry ar ON ar.agent_id = f.agent_id "
                f"{where} {'AND' if where else 'WHERE'} "
                f"f.search_vector @@ websearch_to_tsquery('english', ?) "
                f"ORDER BY ts_rank(f.search_vector, websearch_to_tsquery('english', ?)) DESC "
                f"LIMIT ? OFFSET ?",
                (*args, search, search, limit, offset),
            )
        else:
            rows = await self._fetchall(
                f"SELECT f.*, "
                f"       ar.os         AS agent_os, "
                f"       ar.hostname   AS agent_hostname, "
                f"       ar.os_version AS agent_os_version "
                f"FROM findings f "
                f"LEFT JOIN asset_registry ar ON ar.agent_id = f.agent_id "
                f"{where} "
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
            "SELECT f.*, "
            "       ar.os         AS agent_os, "
            "       ar.hostname   AS agent_hostname, "
            "       ar.os_version AS agent_os_version "
            "FROM findings f "
            "LEFT JOIN asset_registry ar ON ar.agent_id = f.agent_id "
            "WHERE f.id = ?",
            (finding_id,),
        )
        return _shape_finding(dict(row)) if row else None

    async def get_agent_os(self, agent_id: str) -> str:
        """
        Best-effort agent OS lookup, normalised to {macos, linux, windows, unknown}.
        Used by the remediation recipe endpoint to filter commands per host.
        """
        try:
            row = await self._fetchone(
                "SELECT os, os_version FROM asset_registry WHERE agent_id=?",
                (agent_id,),
            )
        except Exception:
            row = None
        if not row:
            return "unknown"
        raw = (row["os"] or "").strip().lower()
        if not raw:
            return "unknown"
        # Many possible spellings — normalise.
        if any(k in raw for k in ("darwin", "macos", "mac os", "osx")):
            return "macos"
        if "win" in raw:
            return "windows"
        if any(k in raw for k in ("linux", "ubuntu", "debian", "rhel", "centos",
                                   "fedora", "arch", "alpine", "suse")):
            return "linux"
        return "unknown"

    async def update_finding(
        self, finding_id: int, *,
        status: str | None = None,
        assignee: str | None = None,
        analyst_notes: str | None = None,
        priority: int | None = None,
        actor: str = "analyst",
        ip_address: str = "",
        session_id: str = "",
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
            if _lc.is_terminal(status):
                # Terminal (closed/FP/accepted/verified/remediated/duplicate):
                # resolve the finding — drop it off the active board, stamp closed_at.
                sets.append("closed_at=?"); vals.append(ts)
                sets.append("is_active=0")
            elif _lc.is_terminal(old.get("status")):
                # Re-opening a previously-resolved finding.
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

            # Build changed_fields for structured audit trail.
            # Captures every field that changed in this update and its
            # before/after values — so the audit log is self-describing
            # without needing to diff the entire finding record.
            changed_fields: dict[str, dict[str, Any]] = {}
            if status is not None and status != old.get("status"):
                changed_fields["status"] = {"old": old.get("status",""), "new": status}
            if assignee is not None and assignee != old.get("assignee",""):
                changed_fields["assignee"] = {"old": old.get("assignee",""), "new": assignee}
            if analyst_notes is not None:
                changed_fields["analyst_notes"] = {"old": old.get("analyst_notes",""), "new": analyst_notes}
            if priority is not None:
                changed_fields["priority"] = {"old": old.get("priority",0), "new": priority}

            # Log activities. These INSERTs need their OWN commit — the commit
            # above only persisted the UPDATE. Without it the activity row hangs
            # uncommitted until some later write flushes it, and a failure in the
            # (best-effort) timeline append would roll the activity back with it —
            # which is exactly how status-change history went silently missing.
            finding_uid = old.get("finding_uid") or ""
            if status is not None and status != old.get("status"):
                await self._log_activity(
                    finding_id, old["agent_id"], "status_change", actor,
                    old.get("status",""), status, "", ts,
                    finding_uid=finding_uid,
                    changed_fields=changed_fields,
                    ip_address=ip_address,
                    session_id=session_id,
                )
            if assignee is not None and assignee != old.get("assignee",""):
                await self._log_activity(
                    finding_id, old["agent_id"], "assigned", actor,
                    old.get("assignee",""), assignee, "", ts,
                    finding_uid=finding_uid,
                    changed_fields=changed_fields,
                    ip_address=ip_address,
                    session_id=session_id,
                )
            # Append a summary entry to the finding's actions_log so the UI
            # can show recent actions without hitting soc_activity.
            if changed_fields:
                action_entry = {
                    "action_id": uuid.uuid4().hex[:12],
                    "action": list(changed_fields.keys())[0],  # 'status' | 'assignee' | etc.
                    "actor": actor,
                    "timestamp": ts,
                    "fields": list(changed_fields.keys()),
                }
                try:
                    cur = await self._conn.execute(
                        "SELECT actions_log FROM findings WHERE id=?", (finding_id,)
                    )
                    cur_r = await cur.fetchone()
                    current = _json_value(cur_r["actions_log"] if cur_r else None, [])
                    if not isinstance(current, list):
                        current = []
                    current.append(action_entry)
                    await self._conn.execute(
                        "UPDATE findings SET actions_log=? WHERE id=?",
                        (json.dumps(current, default=str), finding_id),
                    )
                except Exception as act_exc:
                    log.debug("actions_log append failed for finding %s: %s", finding_id, act_exc)

            # Commit the activity log NOW, before the best-effort timeline write,
            # so the audit trail is durable regardless of what follows.
            await self._conn.commit()

            # Timeline append is best-effort (a secondary view); never let it
            # abort the transaction that carries the authoritative activity log.
            if status is not None and status != old.get("status") \
                    and _lc.is_terminal(status):
                try:
                    await self._append_timeline(
                        old["agent_id"], old["category"], "resolved",
                        old["item_key"], old["title"], None, None, ts,
                    )
                    await self._conn.commit()
                except Exception as exc:
                    log.debug("timeline append failed for finding %s: %s", finding_id, exc)
                    try:
                        await self._conn.rollback()
                    except Exception:
                        pass

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
        # Fetch the finding_uid for the audit log
        finding_uid = ""
        try:
            row = await self._fetchone(
                "SELECT finding_uid FROM findings WHERE id=?", (finding_id,)
            )
            if row and row.get("finding_uid"):
                finding_uid = row["finding_uid"]
        except Exception:
            pass
        async with self._lock:
            await self._conn.execute(
                "INSERT INTO soc_comments(finding_id,agent_id,analyst,comment,created_at) "
                "VALUES(?,?,?,?,?)",
                (finding_id, agent_id, analyst, comment, ts),
            )
            await self._conn.commit()
            await self._log_activity(
                finding_id, agent_id, "commented", analyst, "", "", comment[:100], ts,
                finding_uid=finding_uid,
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
        out = []
        for r in rows:
            d = dict(r)
            _parse_activity_row(d)
            out.append(d)
        return out

    async def get_actions(self, finding_id: int) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM soc_actions WHERE finding_id=? ORDER BY status ASC, created_at ASC",
            (finding_id,),
        )
        return [dict(r) for r in rows]

    async def get_finding_timeline(self, finding_id: int) -> list[dict]:
        """
        Unified per-finding analyst timeline.

        `finding_timeline` stores case-specific notes/workflow events. The
        authoritative SOC audit stream is `soc_activity`; merge both so the
        case tab, All Incidents, and Attack Terrain detail panels show every
        analyst action on the finding without depending on one table only.
        """
        case_rows = await self._fetchall(
            """SELECT id, finding_id, actor, action, from_status, to_status,
                      note, created_at
               FROM finding_timeline
               WHERE finding_id=?
               ORDER BY created_at ASC, id ASC""",
            (finding_id,),
        )
        activity_rows = await self._fetchall(
            """SELECT id, finding_id, agent_id, action, actor, old_value,
                      new_value, detail, created_at, finding_uid,
                      changed_fields, metadata
               FROM soc_activity
               WHERE finding_id=?
               ORDER BY created_at ASC, id ASC""",
            (finding_id,),
        )

        events: list[dict] = []
        for r in case_rows:
            d = dict(r)
            created = float(d.get("created_at") or 0)
            events.append({
                "id": d.get("id"),
                "source": "case",
                "finding_id": d.get("finding_id"),
                "actor": d.get("actor") or "system",
                "action": d.get("action") or "",
                "from_status": d.get("from_status"),
                "to_status": d.get("to_status"),
                "note": d.get("note") or "",
                "created_at": created,
                "elapsed": _elapsed_label(created),
            })

        for r in activity_rows:
            d = dict(r)
            _parse_activity_row(d)
            created = float(d.get("created_at") or 0)
            action = str(d.get("action") or "")
            if action in {"case_opened", "case_status_change", "case_note"}:
                continue
            old_value = d.get("old_value") or ""
            new_value = d.get("new_value") or ""
            from_status = old_value if action in ("status_change", "case_status_change") else None
            to_status = new_value if action in ("status_change", "case_status_change") else None

            detail = d.get("detail") or ""
            if action in ("assigned", "case_assigned") and (old_value or new_value):
                prev = old_value or "unassigned"
                nxt = new_value or "unassigned"
                detail = detail or f"{prev} -> {nxt}"

            events.append({
                "id": 1_000_000_000 + int(d.get("id") or 0),
                "source": "soc_activity",
                "finding_id": d.get("finding_id"),
                "agent_id": d.get("agent_id"),
                "finding_uid": d.get("finding_uid") or "",
                "actor": d.get("actor") or "system",
                "action": action.replace("_", " "),
                "raw_action": action,
                "from_status": from_status,
                "to_status": to_status,
                "note": detail,
                "changed_fields": d.get("changed_fields") or {},
                "metadata": d.get("metadata") or {},
                "created_at": created,
                "elapsed": _elapsed_label(created),
            })

        events.sort(key=lambda e: (e.get("created_at") or 0, e.get("id") or 0))
        return events

    async def _log_activity(
        self, finding_id: int, agent_id: str, action: str,
        actor: str, old_val: str, new_val: str, detail: str, ts: float,
        *,
        finding_uid: str = "",
        ip_address: str = "",
        session_id: str = "",
        changed_fields: Optional[dict] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        await self._conn.execute(
            "INSERT INTO soc_activity(finding_id,agent_id,action,actor,old_value,new_value,detail,"
            "created_at,finding_uid,ip_address,session_id,changed_fields,metadata) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (finding_id, agent_id, action, actor, old_val, new_val, detail, ts,
             finding_uid, ip_address, session_id,
             json.dumps(changed_fields or {}, default=str),
             json.dumps(metadata or {}, default=str)),
        )

    # ── Terrains ────────────────────────────────────────────────────────────────

    async def get_terrains(self) -> list[dict]:
        """Return the canonical list of all attack terrains."""
        rows = await self._fetchall(
            "SELECT * FROM terrains ORDER BY id",
            (),
        )
        return [dict(r) for r in rows]

    async def get_finding_by_uid(self, finding_uid: str) -> dict | None:
        """Look up a finding by its UUIDv4 hex identifier."""
        row = await self._fetchone(
            "SELECT f.*, "
            "       ar.os         AS agent_os, "
            "       ar.hostname   AS agent_hostname, "
            "       ar.os_version AS agent_os_version "
            "FROM findings f "
            "LEFT JOIN asset_registry ar ON ar.agent_id = f.agent_id "
            "WHERE f.finding_uid=?",
            (finding_uid,),
        )
        return _shape_finding(dict(row)) if row else None

    async def get_finding_audit(self, finding_uid: str, limit: int = 100, offset: int = 0) -> list[dict]:
        """Return the full audit trail for a specific finding by its UUID.
        Returns soc_activity rows (the unbounded detail log), NOT the summary
        actions_log embedded on the finding — use that for fast display and
        this for the full immutable trail."""
        rows = await self._fetchall(
            "SELECT * FROM soc_activity "
            "WHERE finding_uid=? "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (finding_uid, limit, offset),
        )
        out = []
        for r in rows:
            d = dict(r)
            _parse_activity_row(d)
            out.append(d)
        return out

    async def get_audit_log(
        self,
        actor: str | None = None,
        action_type: str | None = None,
        finding_uid: str | None = None,
        agent_id: str | None = None,
        ip_address: str | None = None,
        date_from: float | None = None,
        date_to: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Global audit log with flexible filters. Every filter is optional;
        when none are provided the entire log is returned (most recent first)."""
        clauses: list[str] = ["1=1"]
        params: list = []
        if actor:
            clauses.append("actor=?")
            params.append(actor)
        if action_type:
            clauses.append("action=?")
            params.append(action_type)
        if finding_uid:
            clauses.append("finding_uid=?")
            params.append(finding_uid)
        if agent_id:
            clauses.append("agent_id=?")
            params.append(agent_id)
        if ip_address:
            clauses.append("ip_address=?")
            params.append(ip_address)
        if date_from is not None:
            clauses.append("created_at>=?")
            params.append(date_from)
        if date_to is not None:
            clauses.append("created_at<=?")
            params.append(date_to)
        rows = await self._fetchall(
            f"SELECT * FROM soc_activity WHERE {' AND '.join(clauses)} "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        out = []
        for r in rows:
            d = dict(r)
            _parse_activity_row(d)
            out.append(d)
        return out

    async def smart_search_findings(
        self,
        query: str,
        *,
        agent_id: str | None = None,
        terrain_id: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """
        Full-text search across ALL findings using the Postgres tsvector index.

        Searches across title, description, evidence, tags, and cve_ids.
        Supports websearch syntax: \"quoted phrase\", -exclude, OR.
        Results ranked by ts_rank (relevance) descending.
        """
        if not query or not query.strip():
            return []

        parts: list[str] = ["f.search_vector @@ websearch_to_tsquery('english', ?)"]
        args: list = [query]

        if agent_id:
            parts.append("f.agent_id=?")
            args.append(agent_id)
        if terrain_id:
            parts.append("f.terrain_id=?")
            args.append(terrain_id)
        if severity:
            parts.append("f.severity=?")
            args.append(severity)
        if category:
            parts.append("f.category=?")
            args.append(category)

        where = " AND ".join(parts)
        rows = await self._fetchall(f"""
            SELECT f.*,
                   ts_rank(f.search_vector, websearch_to_tsquery('english', ?)) AS relevance,
                   ar.os         AS agent_os,
                   ar.hostname   AS agent_hostname,
                   ar.os_version AS agent_os_version
            FROM findings f
            LEFT JOIN asset_registry ar ON ar.agent_id = f.agent_id
            WHERE {where}
            ORDER BY relevance DESC, f.composite_score DESC
            LIMIT ? OFFSET ?
        """, (query, *args, limit, offset))

        result = []
        for r in rows:
            d = dict(r)
            d["relevance"] = round(float(d.get("relevance", 0)), 4)
            result.append(_shape_finding(d))
        return result

    async def search_findings(
        self,
        agent_id: str,
        query: str,
        *,
        limit: int = 50,
    ) -> list[dict]:
        """Compatibility wrapper for legacy AttackLens/threat search routes."""
        return await self.smart_search_findings(query, agent_id=agent_id, limit=limit)

    async def smart_search_count(
        self,
        query: str,
        *,
        agent_id: str | None = None,
        terrain_id: str | None = None,
        severity: str | None = None,
        category: str | None = None,
    ) -> int:
        """Count of findings matching the smart search query (for pagination)."""
        if not query or not query.strip():
            return 0
        parts: list[str] = ["search_vector @@ websearch_to_tsquery('english', ?)"]
        args: list = [query]
        if agent_id:
            parts.append("agent_id=?")
            args.append(agent_id)
        if terrain_id:
            parts.append("terrain_id=?")
            args.append(terrain_id)
        if severity:
            parts.append("severity=?")
            args.append(severity)
        if category:
            parts.append("category=?")
            args.append(category)
        row = await self._fetchone(
            f"SELECT COUNT(*) AS n FROM findings WHERE {' AND '.join(parts)}",
            args,
        )
        return row["n"] if row else 0

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

    def dedup_stats(self) -> dict:
        """Return ingest dedup cache stats — hit rate, pending flushes, size."""
        return self._dedup.stats()

    # ── Dashboard & SLA analytics ─────────────────────────────────────────────

    async def get_dashboard_stats(self, live_agent_ids: list[str] | None = None) -> dict:
        """Comprehensive stats for the SOC dashboard — the first page most
        users hit, so its latency sets the tone for "the whole app feels slow".

        `live_agent_ids`: same contract as get_soc_findings — when given,
        excludes findings from agents that have gone stale (see config.py's
        stale_agent_sec) from every count here. Without this, a dead agent's
        lingering findings inflate total_active/critical/top_agents/etc. with
        numbers that don't correspond to any currently-reporting machine —
        confirmed live: a 16-day-silent agent contributed 794 of ~18.4k
        "active" findings straight into these headline KPIs.
        """
        now = time.time()
        today_start = now - (now % 86400)  # approximate

        if live_agent_ids is not None and not live_agent_ids:
            return {
                "kpi": {}, "severity_dist": [], "status_dist": [], "category_dist": [],
                "top_agents": [], "daily_trend": [], "sla_compliance": {},
            }
        agent_clause = ""
        agent_args: tuple = ()
        if live_agent_ids is not None:
            placeholders = ",".join("?" * len(live_agent_ids))
            agent_clause = f" AND agent_id IN ({placeholders})"
            agent_args = tuple(live_agent_ids)

        # KPI row
        kpi_row = await self._fetchone(f"""
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
            FROM findings WHERE 1=1{agent_clause}
        """, (now, today_start, *agent_args))

        # Severity distribution (all active)
        sev_rows = await self._fetchall(
            f"SELECT severity, COUNT(*) AS cnt FROM findings WHERE is_active=1{agent_clause} "
            "GROUP BY severity", agent_args
        )

        # Status distribution (all active)
        status_rows = await self._fetchall(
            f"SELECT status, COUNT(*) AS cnt FROM findings WHERE is_active=1{agent_clause} "
            "GROUP BY status", agent_args
        )

        # Category distribution
        cat_rows = await self._fetchall(
            f"SELECT category, COUNT(*) AS cnt FROM findings WHERE is_active=1{agent_clause} "
            "GROUP BY category ORDER BY cnt DESC LIMIT 10", agent_args
        )

        # Top 5 agents by active finding count
        agent_rows = await self._fetchall(f"""
            SELECT f.agent_id,
                   COUNT(*) AS total,
                   SUM(CASE WHEN f.severity='critical' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN f.severity='high'     THEN 1 ELSE 0 END) AS high
            FROM findings f WHERE f.is_active=1{agent_clause}
            GROUP BY f.agent_id ORDER BY total DESC LIMIT 5
        """, agent_args)

        # 7-day trend (approximate using last_detected_at)
        trend = []
        for i in range(6, -1, -1):
            day_start = now - (i + 1) * 86400
            day_end   = now - i * 86400
            day_row = await self._fetchone(f"""
                SELECT
                    SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN severity='high'     THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN severity='medium'   THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN severity='low'      THEN 1 ELSE 0 END) AS low
                FROM findings WHERE first_detected_at >= ? AND first_detected_at < ?{agent_clause}
            """, (day_start, day_end, *agent_args))
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
            row = await self._fetchone(f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN sla_due=0 OR sla_due >= ? THEN 1 ELSE 0 END) AS on_time,
                    SUM(CASE WHEN sla_due > 0 AND sla_due < ?  THEN 1 ELSE 0 END) AS breached
                FROM findings WHERE severity=? AND is_active=1{agent_clause}
            """, (now, now, sev, *agent_args))
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
                to_char(to_timestamp(first_detected_at), 'YYYY-MM') AS month,
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
        """Batch upsert CVEs into local NVD mirror. Returns count written.

        Was SQLite named-parameter binding (`:cve_id` + executemany(sql, dicts))
        — sqlite3/aiosqlite support binding directly from a list of dicts.
        asyncpg's executemany requires POSITIONAL ($1,$2,... here written as ?,
        translated by PgPool) placeholders and a list of tuples, so each dict is
        converted to a tuple in the exact column order below before binding.
        """
        async with self._lock:
            rows = [
                (
                    c.get("cve_id", ""), c.get("description", ""), c.get("cvss_score"),
                    c.get("cvss_vector", ""), c.get("severity", "info"),
                    c.get("cwe_ids", "[]"), c.get("cpe_uris", "[]"),
                    c.get("pkg_keywords", ""), c.get("published_at", ""),
                    c.get("modified_at", ""), c.get("synced_at", 0),
                )
                for c in cves
            ]
            await self._conn.executemany("""
                INSERT INTO nvd_cve_local
                (cve_id, description, cvss_score, cvss_vector, severity,
                 cwe_ids, cpe_uris, pkg_keywords, published_at, modified_at, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            """, rows)
            await self._conn.commit()
        return len(cves)

    async def search_nvd_local(self, keyword: str, limit: int = 20) -> list[dict]:
        """Prefix search on local NVD mirror, ordered by CVSS score. Postgres
        to_tsquery's `:*` prefix operator replaces SQLite FTS5's `term*`
        syntax (was a JOIN against a separate nvd_cve_fts virtual table; now a
        direct predicate against nvd_cve_local.search_vector — see _SCHEMA)."""
        # to_tsquery is strict about its input grammar (unlike
        # websearch_to_tsquery) — reduce to a single safe lexeme before
        # appending the prefix operator, to avoid a syntax error on punctuation.
        safe_term = re.sub(r"[^\w]", "", keyword.strip())
        if not safe_term:
            return []
        fts_term = safe_term + ":*"
        try:
            rows = await self._fetchall("""
                SELECT cve_id, description, cvss_score, cvss_vector,
                       severity, cwe_ids, cpe_uris, published_at, modified_at
                FROM nvd_cve_local
                WHERE search_vector @@ to_tsquery('english', ?)
                ORDER BY COALESCE(cvss_score, 0) DESC
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
        async with self._lock:
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
        async with self._lock:
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
        async with self._lock:
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
        async with self._lock:
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
        async with self._lock:
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
        async with self._lock:
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
        async with self._lock:
            await self._conn.execute("""
                INSERT INTO ai_analysis
                (finding_id,model,analysis,threat_context,risk_factors,ioc_matches,
                 news_context,actor_context,confidence,tokens_used,generated_at,
                 provider,urgency,mitre_context,latency_ms)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    model=excluded.model, analysis=excluded.analysis,
                    threat_context=excluded.threat_context, risk_factors=excluded.risk_factors,
                    ioc_matches=excluded.ioc_matches, news_context=excluded.news_context,
                    actor_context=excluded.actor_context, confidence=excluded.confidence,
                    tokens_used=excluded.tokens_used, generated_at=excluded.generated_at,
                    provider=excluded.provider, urgency=excluded.urgency,
                    mitre_context=excluded.mitre_context, latency_ms=excluded.latency_ms
            """, (finding_id, data.get("model","claude-sonnet-4-6"),
                  data.get("analysis",""), data.get("threat_context",""),
                  json.dumps(data.get("risk_factors",[])), json.dumps(data.get("ioc_matches",[])),
                  json.dumps(data.get("news_context",[])), json.dumps(data.get("actor_context",[])),
                  float(data.get("confidence",0)), int(data.get("tokens_used",0)),
                  time.time(),
                  data.get("provider",""), data.get("urgency","scheduled"),
                  data.get("mitre_context",""), float(data.get("latency_ms",0))))
            await self._conn.execute(
                "UPDATE findings SET ai_analysed=1 WHERE id=?", (finding_id,))
            await self._conn.commit()

    async def get_ai_analysis(self, finding_id: int) -> Optional[dict]:
        row = await self._fetchone("SELECT * FROM ai_analysis WHERE finding_id=?", (finding_id,))
        if not row:
            return None
        d = dict(row)
        # Parse JSON-encoded list columns so callers get real lists, not strings.
        for field in ("risk_factors", "ioc_matches", "news_context", "actor_context"):
            v = d.get(field)
            if isinstance(v, str):
                try:
                    d[field] = json.loads(v) if v else []
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        return d

    # ── Remediation plans ─────────────────────────────────────────────────────

    async def upsert_remediation_plan(self, finding_id: int, agent_id: str,
                                      os_type: str, data: dict) -> None:
        async with self._lock:
            await self._conn.execute("""
                INSERT INTO remediation_plans
                (finding_id,agent_id,os_type,model,steps,summary,effort,risk_level,
                 verification,long_term,generated_at,provider,compensating,
                 tokens_used,latency_ms)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id,os_type) DO UPDATE SET
                    model=excluded.model, steps=excluded.steps, summary=excluded.summary,
                    effort=excluded.effort, risk_level=excluded.risk_level,
                    verification=excluded.verification, long_term=excluded.long_term,
                    generated_at=excluded.generated_at, provider=excluded.provider,
                    compensating=excluded.compensating, tokens_used=excluded.tokens_used,
                    latency_ms=excluded.latency_ms
            """, (finding_id, agent_id, os_type, data.get("model","claude-sonnet-4-6"),
                  json.dumps(data.get("steps",[])), data.get("summary",""),
                  data.get("effort","medium"), data.get("risk_level","low"),
                  json.dumps(data.get("verification",[])), json.dumps(data.get("long_term",[])),
                  time.time(), data.get("provider",""), data.get("compensating",""),
                  int(data.get("tokens_used",0)), float(data.get("latency_ms",0))))
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
            v = d.get(field)
            if isinstance(v, str):
                try:
                    d[field] = json.loads(v) if v else []
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        return d

    async def list_remediation_plans(self, agent_id: str, limit: int = 50) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM remediation_plans WHERE agent_id=? ORDER BY generated_at DESC LIMIT ?",
            (agent_id, limit))
        return [dict(r) for r in rows]

    # ── Asset registry ────────────────────────────────────────────────────────

    async def upsert_asset(self, agent_id: str, data: dict) -> None:
        async with self._lock:
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
        async with self._lock:
            await self._conn.execute("""
                UPDATE asset_registry SET asset_tier=?, importance=?,
                asset_group=COALESCE(NULLIF(?,''),(SELECT asset_group FROM asset_registry WHERE agent_id=?)),
                owner=COALESCE(NULLIF(?,''),(SELECT owner FROM asset_registry WHERE agent_id=?))
                WHERE agent_id=?
            """, (tier, importance, group, agent_id, owner, agent_id, agent_id))
            await self._conn.commit()

    # ── Org groups ────────────────────────────────────────────────────────────

    async def upsert_org_group(self, name: str, data: dict) -> None:
        async with self._lock:
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

    # ── Detection Confidence Engine methods ───────────────────────────────────

    async def execute(self, sql: str, args: tuple = ()) -> None:
        """Generic write — used by feedback.py and validation tests."""
        async with self._lock:
            await self._conn.execute(sql, args)
            await self._conn.commit()

    async def upsert_signal(self, sig) -> int:
        """Persist a Signal to the signals table; return its new id.

        cur.lastrowid was an aiosqlite/sqlite3-only Cursor attribute — Postgres
        has no equivalent concept (no per-connection "last generated id"), so
        the idiomatic fix is INSERT ... RETURNING id, read directly from the
        result row instead.
        """
        async with self._lock:
            cur = await self._conn.execute(
                "INSERT INTO signals "
                "(rule_id, layer, data_point, entity_key, agent_id, severity_hint, "
                "evidence, weight, strength, detected_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
                sig.to_db_row(),
            )
            row = await cur.fetchone()
            await self._conn.commit()
            return row["id"]

    async def get_recent_signals(self, agent_id: str, since: float) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM signals WHERE agent_id=? AND detected_at>=? ORDER BY detected_at DESC",
            (agent_id, since),
        )
        return [dict(r) for r in rows]

    async def persist_cluster(self, cluster) -> int:
        """Insert a SignalCluster row; return its id.  Updates cluster.id in place."""
        async with self._lock:
            cur = await self._conn.execute(
                "INSERT INTO signal_clusters "
                "(agent_id, entity_key, layers_covered, confidence, created_at) "
                "VALUES (?, ?, ?, ?, ?) RETURNING id",
                (
                    cluster.agent_id,
                    cluster.entity_key,
                    json.dumps(sorted(cluster.layers_covered)),
                    cluster.confidence,
                    time.time(),
                ),
            )
            row = await cur.fetchone()
            cluster_id = row["id"]
            # Link all signals to this cluster
            for sig in cluster.signals:
                if sig.id:
                    await self._conn.execute(
                        "UPDATE signals SET cluster_id=? WHERE id=?", (cluster_id, sig.id)
                    )
            await self._conn.commit()
        cluster.id = cluster_id
        return cluster_id

    async def mark_cluster_rejected(self, cluster, gate: str, detail: str) -> None:
        async with self._lock:
            if cluster.id:
                await self._conn.execute(
                    "UPDATE signal_clusters SET validation_status=?, rejection_reason=? WHERE id=?",
                    (f"rejected_{gate}", detail, cluster.id),
                )
                for sig in cluster.signals:
                    if sig.id:
                        await self._conn.execute(
                            "UPDATE signals SET validation_status=?, rejection_reason=? WHERE id=?",
                            (f"rejected_{gate}", detail, sig.id),
                        )
            await self._conn.commit()

    async def mark_cluster_promoted(self, cluster_id: int, finding_id: int) -> None:
        async with self._lock:
            await self._conn.execute(
                "UPDATE signal_clusters SET validation_status='promoted', finding_id=? WHERE id=?",
                (finding_id, cluster_id),
            )
            await self._conn.execute(
                "UPDATE signals SET validation_status='promoted' WHERE cluster_id=?",
                (cluster_id,),
            )
            await self._conn.commit()

    async def get_signals_for_cluster(self, cluster_id: int) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM signals WHERE cluster_id=?", (cluster_id,)
        )
        return [dict(r) for r in rows]

    async def record_cluster_rejection(self, cluster, reason: str) -> None:
        if cluster.id:
            await self.mark_cluster_rejected(cluster, reason, reason)

    async def is_allowlisted(self, rule_id: str, entity_key: str, agent_id: str) -> bool:
        row = await self._fetchone(
            "SELECT 1 FROM detection_allowlist WHERE "
            "(rule_id IS NULL OR rule_id=?) AND "
            "(entity_key IS NULL OR entity_key=?) AND "
            "(agent_id IS NULL OR agent_id=?) AND "
            "(expires_at IS NULL OR expires_at>?) LIMIT 1",
            (rule_id, entity_key, agent_id, time.time()),
        )
        return row is not None

    async def get_fp_rate_for_rules(
        self, rule_ids: list[str], host_class: str, window_days: int = 7
    ) -> float:
        """FP rate = fp / (tp + fp) across all rules in the list over recent weeks."""
        if not rule_ids:
            return 0.0
        try:
            from datetime import date, timedelta
            cutoff_week = (date.today() - timedelta(days=window_days)).strftime("%G-%V")
            placeholders = ",".join("?" * len(rule_ids))
            rows = await self._fetchall(
                f"SELECT SUM(tp_count) AS tp, SUM(fp_count) AS fp FROM rule_fp_stats "
                f"WHERE rule_id IN ({placeholders}) AND host_class=? AND window_start>=?",
                (*rule_ids, host_class, cutoff_week),
            )
            if rows and rows[0]:
                tp = rows[0]["tp"] or 0
                fp = rows[0]["fp"] or 0
                total = tp + fp
                return fp / total if total > 0 else 0.0
        except Exception:
            pass
        return 0.0

    async def rules_with_recent_fp(
        self,
        rule_ids: list[str],
        host_class: str,
        window_days: int = 7,
        threshold: float = 0.5,
    ) -> list[str]:
        """Return rule_ids whose recent FP rate exceeds threshold."""
        if not rule_ids:
            return []
        result: list[str] = []
        for rid in rule_ids:
            rate = await self.get_fp_rate_for_rules([rid], host_class, window_days)
            if rate > threshold:
                result.append(rid)
        return result

    async def has_active_finding_for_cluster(self, cluster, since: float) -> bool:
        """Check if an active finding exists for the cluster's entity_key in the last N hours."""
        row = await self._fetchone(
            "SELECT 1 FROM findings WHERE agent_id=? AND is_active=1 "
            "AND last_detected_at>=? "
            "AND (item_key=? OR item_key LIKE ?) LIMIT 1",
            (cluster.agent_id, since, cluster.entity_key, f"%{cluster.entity_key}%"),
        )
        return row is not None

    async def get_agent_last_seen(self, agent_id: str) -> Optional[float]:
        try:
            row = await self._fetchone(
                "SELECT last_seen FROM asset_registry WHERE agent_id=?", (agent_id,)
            )
            return float(row["last_seen"]) if row else None
        except Exception:
            return None

    async def get_asset_tier(self, agent_id: str) -> str:
        try:
            row = await self._fetchone(
                "SELECT asset_tier FROM asset_registry WHERE agent_id=?", (agent_id,)
            )
            return str(row["asset_tier"]) if row else "endpoint"
        except Exception:
            return "endpoint"

    async def get_host_class(self, agent_id: str) -> str:
        return await self.get_asset_tier(agent_id)

    async def get_compensating_controls(self, agent_id: str) -> list[str]:
        """Return names of active compensating controls for the agent (empty list if none)."""
        try:
            row = await self._fetchone(
                "SELECT * FROM asset_registry WHERE agent_id=?", (agent_id,)
            )
            if not row:
                return []
            tags: list = json.loads(row["tags"] or "[]")
            return [t for t in tags if str(t).startswith("ctrl:")]
        except Exception:
            return []

    async def recent_fp_count(self, rule_id: str, entity_key: str, days: int = 30) -> int:
        """Count FPs for a (rule_id, entity_key) pair in the last N days."""
        try:
            from datetime import date, timedelta
            cutoff = (date.today() - timedelta(days=days)).strftime("%G-%V")
            row = await self._fetchone(
                "SELECT SUM(fp_count) AS total FROM rule_fp_stats "
                "WHERE rule_id=? AND window_start>=?",
                (rule_id, cutoff),
            )
            return int(row["total"] or 0) if row else 0
        except Exception:
            return 0

    async def upsert_allowlist_suggestion(
        self, rule_id: str, entity_key: str, fp_count: int
    ) -> None:
        async with self._lock:
            await self._conn.execute(
                "INSERT INTO allowlist_suggestions "
                "(rule_id, entity_key, fp_count, last_fp_at, suggested_at, status) "
                "VALUES (?, ?, ?, ?, ?, 'pending') "
                "ON CONFLICT(rule_id, entity_key) DO UPDATE SET "
                "fp_count=excluded.fp_count, last_fp_at=excluded.last_fp_at, "
                "suggested_at=excluded.suggested_at",
                (rule_id, entity_key, fp_count, time.time(), time.time()),
            )
            await self._conn.commit()

    async def list_allowlist_suggestions(self, status: str = "pending") -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM allowlist_suggestions WHERE status=? ORDER BY fp_count DESC, suggested_at DESC",
            (status,),
        )
        return [dict(r) for r in rows]

    async def get_allowlist_suggestion(self, sid: int) -> Optional[dict]:
        row = await self._fetchone(
            "SELECT * FROM allowlist_suggestions WHERE id=?", (sid,)
        )
        return dict(row) if row else None

    async def update_suggestion_status(
        self, sid: int, status: str, reviewed_by: str = "system"
    ) -> None:
        async with self._lock:
            await self._conn.execute(
                "UPDATE allowlist_suggestions SET status=?, reviewed_by=?, reviewed_at=? WHERE id=?",
                (status, reviewed_by, time.time(), sid),
            )
            await self._conn.commit()

    async def upsert_allowlist_entry(
        self,
        rule_id: Optional[str],
        entity_key: Optional[str],
        reason: str,
        created_by: str = "system",
        agent_id: Optional[str] = None,
        expires_at: Optional[float] = None,
    ) -> None:
        async with self._lock:
            await self._conn.execute(
                "INSERT INTO detection_allowlist "
                "(rule_id, entity_key, agent_id, reason, created_by, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rule_id, entity_key, agent_id, reason, created_by, time.time(), expires_at),
            )
            await self._conn.commit()

    async def list_allowlist_entries(self) -> list[dict]:
        rows = await self._fetchall(
            "SELECT * FROM detection_allowlist ORDER BY created_at DESC", ()
        )
        return [dict(r) for r in rows]

    async def compute_confidence_metrics(self) -> dict:
        """Compute per-rule and engine-wide precision from rule_fp_stats."""
        try:
            rows = await self._fetchall(
                "SELECT rule_id, SUM(tp_count) AS tp, SUM(fp_count) AS fp "
                "FROM rule_fp_stats GROUP BY rule_id ORDER BY fp DESC",
                (),
            )
            per_rule = []
            total_tp = total_fp = 0
            for r in rows:
                tp, fp = (r["tp"] or 0), (r["fp"] or 0)
                tot = tp + fp
                prec = tp / tot if tot > 0 else None
                per_rule.append({
                    "rule_id": r["rule_id"],
                    "tp": tp, "fp": fp,
                    "precision": round(prec, 3) if prec is not None else None,
                })
                total_tp += tp
                total_fp += fp
            grand_total = total_tp + total_fp
            overall = round(total_tp / grand_total, 3) if grand_total > 0 else None

            # Gate rejection breakdown
            gate_rows = await self._fetchall(
                "SELECT validation_status, COUNT(*) AS n FROM signal_clusters "
                "WHERE validation_status IS NOT NULL GROUP BY validation_status",
                (),
            )
            gates = {r["validation_status"]: r["n"] for r in gate_rows}

            return {
                "precision_overall": overall,
                "precision_by_rule": per_rule,
                "rejected_by_gate": gates,
                "total_tp": total_tp,
                "total_fp": total_fp,
            }
        except Exception as exc:
            log.warning("compute_confidence_metrics: %s", exc)
            return {"error": str(exc)}

    async def get_finding_by_id(self, finding_id: int) -> Optional[dict]:
        """
        Single finding fetch with asset_registry JOIN so the response carries
        the agent's actual OS (used by the remediation recipe endpoint and the
        OS-aware UI panel).  This intentionally shadows the earlier definition
        above to keep the asset context attached to every single-row lookup.
        """
        row = await self._fetchone(
            "SELECT f.*, "
            "       ar.os         AS agent_os, "
            "       ar.hostname   AS agent_hostname, "
            "       ar.os_version AS agent_os_version "
            "FROM findings f "
            "LEFT JOIN asset_registry ar ON ar.agent_id = f.agent_id "
            "WHERE f.id = ?",
            (finding_id,),
        )
        return _shape_finding(dict(row)) if row else None

    async def recompute_terrain_validation_all(
        self, *, only_unscored: bool = False, limit: int = 5000,
    ) -> dict:
        """
        Re-evaluate every active finding against the terrain validator and
        persist the new `terrain_validation` + `precision_score`.

        Why this exists: when validation was added, findings already in the DB
        have `precision_score = 0` and an empty `terrain_validation` blob,
        so they never pass the Validated Findings threshold filter even when
        they obviously should.  Calling this once after configuration brings
        historical findings up to date.

        only_unscored=True skips findings that already have a non-zero score.
        """
        try:
            from .attacklens.terrain_validators import evaluate_finding
        except ImportError:
            from manager.attacklens.terrain_validators import evaluate_finding
        rows = await self._fetchall(
            "SELECT id, agent_id, category, item_key, severity, score, "
            "       evidence, source, rule_id, cve_ids, cvss_score, kev, "
            "       epss_score, asset_tier, host_class, ai_verdict, "
            "       precision_score, terrain_validation "
            "FROM findings WHERE is_active=1 LIMIT ?",
            (limit,),
        )
        updated = 0
        scanned = 0
        score_hist = {"00-49": 0, "50-69": 0, "70-84": 0, "85-89": 0, "90-100": 0}
        async with self._lock:
            for r in rows:
                scanned += 1
                f = dict(r)
                if only_unscored and float(f.get("precision_score") or 0) > 0:
                    continue

                # Parse JSON columns so the evaluator sees structured input
                for k, default in [("evidence", {}), ("cve_ids", []),
                                    ("ai_verdict", {})]:
                    v = f.get(k)
                    if isinstance(v, str):
                        try:
                            f[k] = json.loads(v) if v else default
                        except json.JSONDecodeError:
                            f[k] = default

                # Build the same enriched context the engine's legacy path uses
                ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
                kev = bool(f.get("kev") or ev.get("kev")
                           or (isinstance(ev.get("cve"), dict) and ev["cve"].get("kev")))
                agent_id = f.get("agent_id", "")

                # Cross-finding peek for package_running / port_open / paired-persistence
                sibs = await self._fetchall(
                    "SELECT category, evidence FROM findings "
                    "WHERE agent_id=? AND is_active=1 AND id != ? LIMIT 100",
                    (agent_id, f["id"]),
                )
                package_running = False
                port_open       = False
                paired_persist  = False
                controls_off    = 0
                pkg_name = str(ev.get("name") or "").lower() if isinstance(ev, dict) else ""
                for s in sibs:
                    cat = s["category"]
                    if cat == "port":
                        port_open = True
                    if cat in ("service", "task"):
                        paired_persist = True
                    if cat == "security":
                        controls_off += 1
                    if cat == "process" and pkg_name:
                        try:
                            sev_ev = json.loads(s["evidence"] or "{}")
                        except Exception:
                            sev_ev = {}
                        if pkg_name in str(sev_ev.get("process") or "").lower() \
                           or pkg_name in str(sev_ev.get("path") or "").lower():
                            package_running = True

                enriched = {
                    "kev_hit":                kev,
                    "malicious_ip_hit":       bool(str(f.get("source", "")).startswith("feed:") or f.get("source") == "abuseipdb"),
                    "malicious_hash_hit":     bool(ev.get("malware_hash_hit") if isinstance(ev, dict) else False),
                    "epss_scores":            [float(f.get("epss_score") or 0)] if (f.get("epss_score") or 0) > 0 else [],
                    "asset_tier":             f.get("asset_tier") or "endpoint",
                    "host_class":             f.get("host_class") or "unknown",
                    "compensating_controls":  [],
                    "package_running":        package_running,
                    "port_open":              port_open,
                    "paired_with_persistence": paired_persist,
                    "cross_layer_match":      paired_persist,
                    "controls_disabled_count": controls_off,
                    "threat_intel_source_count": (1 if str(f.get("source","")).startswith("feed:") or f.get("source") == "abuseipdb" else 0) + (1 if kev else 0),
                }
                ai_dict = f.get("ai_verdict") if isinstance(f.get("ai_verdict"), dict) else None

                tv = evaluate_finding(f, enriched, ai_dict)
                new_score = float(tv["score"])

                await self._conn.execute(
                    "UPDATE findings SET "
                    "   precision_score=?, "
                    "   terrain_validation=? "
                    "WHERE id=?",
                    (new_score, json.dumps(tv, default=str), f["id"]),
                )
                updated += 1

                # Histogram for the UI
                p = int(new_score * 100)
                if   p >= 90: score_hist["90-100"] += 1
                elif p >= 85: score_hist["85-89"]  += 1
                elif p >= 70: score_hist["70-84"]  += 1
                elif p >= 50: score_hist["50-69"]  += 1
                else:         score_hist["00-49"]  += 1

            await self._conn.commit()
        return {
            "scanned":   scanned,
            "updated":   updated,
            "histogram": score_hist,
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _fetchone(self, sql: str, args: tuple) -> Optional[Any]:
        """Concurrent read — uses a pool reader connection. Returns an
        asyncpg.Record (positional + key access, like the old aiosqlite.Row)."""
        if self._pool is None:
            raise RuntimeError("IntelDB not initialised")
        async with self._pool.read() as conn:
            async with conn.execute(sql, args) as cur:
                return await cur.fetchone()

    async def _fetchall(self, sql: str, args: tuple) -> list[Any]:
        """Concurrent read — uses a pool reader connection."""
        if self._pool is None:
            raise RuntimeError("IntelDB not initialised")
        async with self._pool.read() as conn:
            async with conn.execute(sql, args) as cur:
                return await cur.fetchall()


def _sla_status(sla_due: float, status: str) -> str:
    """Return 'ok' | 'warning' | 'breached' | 'closed' based on SLA due time."""
    if _lc.is_terminal(status):
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


def _elapsed_label(ts: float) -> str:
    sec = max(0, int(time.time() - float(ts or 0)))
    if sec < 60:
        return f"{sec}s ago"
    if sec < 3600:
        return f"{sec // 60}m ago"
    if sec < 86400:
        return f"{sec // 3600}h ago"
    return f"{sec // 86400}d ago"


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


def _finding_is_alertable(f: Any) -> bool:
    def _field(key: str, default: Any = None) -> Any:
        if hasattr(f, "get"):
            return f.get(key, default)
        try:
            return f[key]
        except Exception:
            return default

    severity = str(_field("severity") or "").lower()
    band = str(_field("exploitability_band") or "").lower()
    try:
        exploitability = float(_field("exploitability_score") or 0.0)
    except (TypeError, ValueError):
        exploitability = 0.0
    return severity == "critical" or band == "critical" or exploitability >= 90.0


def _json_value(v: Any, default: Any) -> Any:
    if v is None or v == "":
        return default
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v)
    except Exception:
        return default


def _parse_activity_row(d: dict) -> None:
    """Parse JSON string columns in a soc_activity row into Python objects."""
    for fld in ("changed_fields", "metadata"):
        v = d.get(fld)
        if isinstance(v, str):
            try:
                d[fld] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                d[fld] = {}


def _shape_finding(d: dict) -> dict:
    # search_vector is a Postgres GENERATED column (replaces SQLite's FTS5
    # shadow table) — internal-only, never part of the API response shape.
    d.pop("search_vector", None)
    d["external_id"] = d.get("external_id") or _external_id(d["id"])
    d["display_id"] = d["external_id"]
    d["finding_uid"] = d.get("finding_uid") or ""
    d["terrain_id"] = d.get("terrain_id") or ""
    d["terrain_source"] = d.get("terrain_source") or d.get("category", "")
    d["kev"] = bool(d.get("kev"))
    d["exploit_available"] = bool(d.get("exploit_available"))
    d["exploit_sources"] = _json_value(d.get("exploit_sources"), [])
    d["action_plan"] = _json_value(d.get("action_plan"), [])
    d["actions_log"] = _json_value(d.get("actions_log"), [])
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
