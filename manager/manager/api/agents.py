"""
manager/manager/api/agents.py — GET /api/v1/agents/* router.

Endpoints:
  GET /api/v1/agents                              list all agents + online status
  GET /api/v1/agents/{id}                         agent detail + section timestamps
  GET /api/v1/agents/{id}/sections                per-section summary (freshness)
  GET /api/v1/agents/{id}/{section}               time-series data

Query parameters for section data:
  window  : 5m | 15m | 1h | 8h | 1d | 7d | 30d | 90d (default: 1h)
  limit   : max records returned (default: 100, max: 1000)
  start   : Unix epoch start (overrides window)
  end     : Unix epoch end   (overrides window)
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Query

from ..models import AgentSummary, AgentDetail, SectionRow
from shared.sections import VALID_SECTION_NAMES
from shared.wire     import WINDOW_SECONDS

if TYPE_CHECKING:
    from ..db    import Database
    from ..store import TelemetryStore

log = logging.getLogger("manager.api.agents")
ONLINE_WINDOW_SECONDS = 300


def _agent_live_fields(agent: dict, now: float, session_count: int = 0) -> dict:
    last_seen = int(agent.get("last_seen", 0) or 0)
    online = bool(last_seen and (now - last_seen) < ONLINE_WINDOW_SECONDS)
    delta = max(0, int(now - last_seen)) if last_seen else 0
    return {
        **agent,
        "online": online,
        "live_status": "connected" if online else "disconnected",
        "last_seen_label": "live now" if online else ("never seen" if not last_seen else f"last seen {_human_delta(delta)} ago"),
        "online_for": delta if online else 0,
        "offline_for": 0 if online else delta,
        "session_count": session_count,
    }


def _human_delta(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def make_agents_router(db: "Database", store: "TelemetryStore") -> APIRouter:
    router = APIRouter()

    # ── List agents ───────────────────────────────────────────────────────────
    @router.get("", response_model=list[AgentSummary])
    async def list_agents():
        agents = await db.get_all_agents()
        now = time.time()
        counts = await db.get_agent_session_counts()
        return [_agent_live_fields(a, now, counts.get(a["agent_id"], 0)) for a in agents]

    # ── Agent detail ──────────────────────────────────────────────────────────
    @router.get("/{agent_id}", response_model=AgentDetail)
    async def get_agent(agent_id: str):
        agent = await db.get_agent(agent_id)
        if not agent:
            raise HTTPException(404, "Agent not found")
        sections = await db.get_section_last_times(agent_id)
        sessions = await db.get_agent_sessions(agent_id, limit=5)
        shaped_sessions = []
        for session in sessions:
            duration_end = session.get("disconnected_at") or int(time.time())
            shaped_sessions.append({
                **session,
                "duration": max(0, int(duration_end - session.get("connected_at", 0))),
            })
        return {
            **_agent_live_fields(agent, time.time(), len(sessions)),
            "sections": sections,
            "sessions": shaped_sessions,
        }

    # ── Section summary (freshness for timeline) ──────────────────────────────
    @router.get("/{agent_id}/sections")
    async def get_sections(agent_id: str):
        """Return per-section summary: latest timestamp, row count, file count."""
        # Try file-store index first (richer data)
        try:
            summary = await store.index.get_section_summary(agent_id)
            if summary:
                return {s["section"]: s for s in summary}
        except Exception:
            pass
        # Fallback: SQLite section last times
        return await db.get_section_last_times(agent_id)

    # ── Section time-series ───────────────────────────────────────────────────
    @router.get("/{agent_id}/{section}")
    async def get_section_data(
        agent_id: str,
        section:  str,
        window:   str = Query(default="1h"),
        limit:    int = Query(default=100, ge=1, le=1000),
        start:    int = Query(default=0),
        end:      int = Query(default=0),
    ):
        if section not in VALID_SECTION_NAMES:
            raise HTTPException(400, f"Invalid section: {section!r}")

        now = int(time.time())

        # Resolve start/end from window shortcut
        if start <= 0:
            secs  = WINDOW_SECONDS.get(window, 3600)
            start = now - secs
        if end <= 0:
            end = now

        # Try file store first (richer, multi-tier)
        try:
            rows = await store.query(
                agent_id=agent_id,
                section=section,
                window=window,
                limit=limit,
                start=float(start),
                end=float(end),
            )
            if rows:
                # Normalise to {collected_at, data} shape the dashboard expects
                return [
                    {
                        "collected_at": int(r.get("ts", r.get("collected_at", 0))),
                        "data":         r.get("data", {}),
                        "os":           r.get("os", ""),
                        "hostname":     r.get("hostname", ""),
                    }
                    for r in rows
                ]
        except Exception as exc:
            log.debug("Store query failed, falling back to db: %s", exc)

        # Fallback: SQLite payloads table
        rows = await db.query_section(
            agent_id, section,
            limit=limit,
            start=start,
            end=end,
        )
        return rows

    return router
