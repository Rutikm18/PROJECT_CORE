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


def make_agents_router(db: "Database", store: "TelemetryStore") -> APIRouter:
    router = APIRouter()

    # ── List agents ───────────────────────────────────────────────────────────
    @router.get("", response_model=list[AgentSummary])
    async def list_agents():
        agents = await db.get_all_agents()
        now = time.time()
        return [
            {**a, "online": (now - a.get("last_seen", 0)) < 300}
            for a in agents
        ]

    # ── Agent detail ──────────────────────────────────────────────────────────
    @router.get("/{agent_id}", response_model=AgentDetail)
    async def get_agent(agent_id: str):
        agent = await db.get_agent(agent_id)
        if not agent:
            raise HTTPException(404, "Agent not found")
        sections = await db.get_section_last_times(agent_id)
        online   = (time.time() - agent.get("last_seen", 0)) < 300
        return {**agent, "sections": sections, "online": online}

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
