"""
manager/api/raw.py — Deep Analysis (raw telemetry explorer) endpoints.

GET /api/v1/raw/agents     — list all known agents with live status
GET /api/v1/raw/sections   — distinct payload sections (optionally by agent)
GET /api/v1/raw/query      — paginated payload query with all filter combinations
GET /api/v1/raw/count      — total row count for current filter (pagination support)

Search algorithm:
  - Time + agent + section: covered index scan on idx_payloads_agent_section_ts
  - Free-text search: LIKE '%term%' scan within the already-filtered result set
  - Count query reuses same WHERE clause to avoid double full-scan
  All queries are bounded by LIMIT/OFFSET so no result set is unbounded.
"""
from __future__ import annotations

import time
import logging
from typing import Optional, TYPE_CHECKING

from fastapi import APIRouter, Query

if TYPE_CHECKING:
    from ..db import Database

log = logging.getLogger("manager.api.raw")

# Preset time windows in seconds
_TIME_WINDOWS = {
    "5m":  5 * 60,
    "1h":  3600,
    "6h":  6 * 3600,
    "24h": 24 * 3600,
    "7d":  7 * 24 * 3600,
}


def make_raw_router(db: "Database") -> APIRouter:
    router = APIRouter()

    @router.get("/agents")
    async def list_agents():
        """All enrolled agents with last-seen timestamp and online status."""
        agents = await db.get_all_agents()
        now = int(time.time())
        result = []
        for a in agents:
            last_seen = int(a.get("last_seen") or 0)
            elapsed = now - last_seen
            if elapsed < 60:
                status = "online"
            elif elapsed < 300:
                status = "stale"
            else:
                status = "offline"
            result.append({
                "agent_id":  a["agent_id"],
                "name":      a.get("name") or a["agent_id"],
                "last_seen": last_seen,
                "last_ip":   a.get("last_ip", ""),
                "status":    status,
                "elapsed_s": elapsed,
            })
        return result

    @router.get("/sections")
    async def list_sections(agent_id: Optional[str] = Query(None)):
        """Distinct telemetry sections, optionally scoped to one agent."""
        sections = await db.get_distinct_sections(agent_id)
        return {"sections": sections}

    @router.get("/count")
    async def count_payloads(
        agent_id: Optional[str] = Query(None),
        section:  Optional[str] = Query(None),
        window:   Optional[str] = Query(None, description="5m|1h|6h|24h|7d"),
        start:    Optional[int] = Query(None, description="Unix timestamp"),
        end:      Optional[int] = Query(None, description="Unix timestamp"),
        search:   Optional[str] = Query(None),
    ):
        """Row count matching the current filter set (for pagination UI)."""
        now = int(time.time())
        resolved_start, resolved_end = _resolve_window(window, start, end, now)
        # Use an efficient COUNT(*) query rather than loading all rows.
        count = await db.count_payloads(
            agent_id=agent_id,
            section=section,
            start=resolved_start,
            end=resolved_end,
            search=search,
        )
        return {"count": count}

    @router.get("/query")
    async def query_payloads(
        agent_id: Optional[str] = Query(None),
        section:  Optional[str] = Query(None),
        window:   Optional[str] = Query(None, description="5m|1h|6h|24h|7d"),
        start:    Optional[int] = Query(None, description="Unix timestamp"),
        end:      Optional[int] = Query(None, description="Unix timestamp"),
        search:   Optional[str] = Query(None),
        limit:    int = Query(200, ge=1, le=1000),
        offset:   int = Query(0, ge=0),
    ):
        """
        Paginated raw payload query.

        Returns rows ordered by collected_at DESC.
        Each row contains the full payload JSON + metadata.

        Filter combinations:
          - No filters        → most recent N rows across all agents/sections
          - agent_id only     → all sections for that agent
          - agent_id+section  → section-specific data for that agent
          - window            → resolves to (start, end) timestamp range
          - search            → substring match against payload JSON
        """
        now = int(time.time())
        resolved_start, resolved_end = _resolve_window(window, start, end, now)

        rows = await db.query_payloads(
            agent_id=agent_id,
            section=section,
            start=resolved_start,
            end=resolved_end,
            search=search,
            limit=limit,
            offset=offset,
        )

        # Enrich each row with a compact preview string
        result = []
        for r in rows:
            data = r.get("data", {})
            preview = _data_preview(data)
            result.append({
                "id":           r["id"],
                "agent_id":     r["agent_id"],
                "section":      r["section"],
                "collected_at": r["collected_at"],
                "received_at":  r["received_at"],
                "record_count": _record_count(data),
                "preview":      preview,
                "data":         data,
            })

        return {
            "rows":    result,
            "limit":   limit,
            "offset":  offset,
            "filters": {
                "agent_id": agent_id,
                "section":  section,
                "start":    resolved_start,
                "end":      resolved_end,
                "search":   search,
            },
        }

    # ── First-layer data checkpoint ─────────────────────────────────────────
    # Every section a macOS agent is expected to report, and whether it feeds
    # executable detection logic (inline analyzers, rich modules, or rule-pack
    # evaluators). Battery is kept non-feeding until its rule-pack conditions
    # have the required historical/CMDB inputs.
    _EXPECTED_SECTIONS: dict[str, bool] = {
        # section: feeds_detection?
        "metrics": True,  "connections": True, "processes": True, "ports": True,
        "network": True,  "arp": True,         "mounts": True,    "battery": False,
        "openfiles": True, "services": True,   "users": True,     "hardware": True,
        "containers": True, "storage": True,   "tasks": True,     "security": True,
        "sysctl": True,   "configs": True,     "apps": True,      "packages": True,
        "binaries": True, "sbom": True,
    }

    def _has_real_data(data) -> bool:
        """True only if the section's latest payload carries actual telemetry —
        not empty and not a collector-error ({"error": ...}) payload."""
        if not data:
            return False
        if isinstance(data, dict):
            if set(data.keys()) == {"error"}:
                return False
            return any(v not in (None, "", [], {}) for v in data.values())
        if isinstance(data, (list, tuple)):
            return len(data) > 0
        return False

    @router.get("/coverage")
    async def coverage(
        agent_id:  Optional[str] = Query(None, description="Agent to check; default = most recently active"),
        stale_sec: int           = Query(7200, ge=1, description="A section older than this is 'stale'"),
    ):
        """First-layer checkpoint: for ONE agent, verify every expected section is
        PRESENT, FRESH, and carrying REAL data (not empty / not an {error}
        payload). `ok` is True only when every detection-feeding section passes —
        i.e. the agent is actually delivering the data the 14 detection modules
        need. Per-section `status` ∈ ok | stale | empty | missing pinpoints gaps.
        """
        if not agent_id:
            agents = await db.get_all_agents()
            if not agents:
                return {"ok": False, "error": "no agents have reported yet",
                        "agent_id": None, "sections": []}
            agent_id = agents[0]["agent_id"]    # ordered by last_seen DESC

        last_times = await db.get_section_last_times(agent_id)
        now = int(time.time())

        sections, missing, stale, empty = [], [], [], []
        for sec, feeds in sorted(_EXPECTED_SECTIONS.items()):
            last    = last_times.get(sec)
            present = last is not None
            age     = (now - int(last)) if present else None
            has_data = None
            status   = "missing"
            if present:
                try:
                    rows = await db.query_section(agent_id, sec, limit=1)
                    has_data = _has_real_data(rows[0]["data"]) if rows else False
                except Exception:
                    has_data = None
                fresh = age is not None and age <= stale_sec
                if not fresh:
                    status = "stale"
                elif has_data is False:
                    status = "empty"
                else:
                    status = "ok"
            if status == "missing":
                missing.append(sec)
            elif status == "stale":
                stale.append(sec)
            elif status == "empty":
                empty.append(sec)
            sections.append({
                "section": sec, "feeds_detection": feeds, "present": present,
                "last_collected_at": last, "age_sec": age,
                "has_real_data": has_data, "status": status,
            })

        det_ok = all(s["status"] == "ok" for s in sections if s["feeds_detection"])
        return {
            "agent_id":       agent_id,
            "checked_at":     now,
            "stale_sec":      stale_sec,
            "ok":             det_ok,                 # all detection-feeding sections good
            "detection_ready": det_ok,
            "expected":       len(_EXPECTED_SECTIONS),
            "present":        sum(1 for s in sections if s["present"]),
            "missing":        missing,
            "stale":          stale,
            "empty":          empty,
            "sections":       sections,
        }

    return router


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_window(
    window: Optional[str],
    start:  Optional[int],
    end:    Optional[int],
    now:    int,
) -> tuple[int, int]:
    """Convert window preset OR explicit start/end into (start, end) epoch ints."""
    if window and window in _TIME_WINDOWS:
        return now - _TIME_WINDOWS[window], now
    return (start or 0), (end or now)


def _record_count(data: object) -> int:
    """Number of records in this payload — list = len(list), dict = 1."""
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        # Some sections wrap a list under a key
        for v in data.values():
            if isinstance(v, list):
                return len(v)
        return 1
    return 0


def _data_preview(data: object, max_chars: int = 140) -> str:
    """Short human-readable preview of payload data."""
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            # Show key=value pairs from first record
            parts = [f"{k}={v}" for k, v in list(first.items())[:4]]
            preview = "  ·  ".join(str(p) for p in parts)
        else:
            preview = str(first)
    elif isinstance(data, dict):
        parts = [f"{k}={v}" for k, v in list(data.items())[:4]]
        preview = "  ·  ".join(str(p) for p in parts)
    else:
        preview = str(data)
    return preview[:max_chars] + ("…" if len(preview) > max_chars else "")
