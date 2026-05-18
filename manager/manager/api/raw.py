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
        rows = await db.query_payloads(
            agent_id=agent_id,
            section=section,
            start=resolved_start,
            end=resolved_end,
            search=search,
            limit=1_000_000,  # large enough to get the real count
            offset=0,
        )
        return {"count": len(rows)}

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
