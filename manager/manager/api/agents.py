"""
manager/manager/api/agents.py — GET /api/v1/agents/* router.

Read-only endpoints for querying stored agent data.
Section names are validated against shared/sections.py so the valid set
is maintained in one place.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException

from ..models import AgentSummary, AgentDetail, SectionRow

if TYPE_CHECKING:
    from ..db import Database

log = logging.getLogger("manager.api.agents")

# Import valid section names from the shared canonical list
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
try:
    from shared.sections import VALID_SECTION_NAMES
except ImportError:
    # Fallback: inline set so the manager still works without shared/ on PYTHONPATH
    VALID_SECTION_NAMES = frozenset(
        "metrics connections processes ports network battery openfiles "
        "services users hardware containers arp mounts storage tasks "
        "security sysctl configs apps packages binaries sbom".split()
    )


def make_agents_router(db: "Database") -> APIRouter:
    """Router factory — inject db at startup."""
    router = APIRouter()

    @router.get("", response_model=list[AgentSummary])
    async def list_agents() -> list[AgentSummary]:
        agents = await db.get_all_agents()
        now = time.time()
        return [
            AgentSummary(**a, online=(now - a.get("last_seen", 0)) < 300)
            for a in agents
        ]

    @router.get("/{agent_id}", response_model=AgentDetail)
    async def get_agent(agent_id: str) -> AgentDetail:
        agent = await db.get_agent(agent_id)
        if not agent:
            raise HTTPException(404, "Agent not found")
        sections = await db.get_section_last_times(agent_id)
        online = (time.time() - agent.get("last_seen", 0)) < 300
        return AgentDetail(**agent, sections=sections, online=online)

    @router.get("/{agent_id}/{section}", response_model=list[SectionRow])
    async def get_section(
        agent_id: str,
        section: str,
        limit: int = 100,
        start: int = 0,
        end: int = 0,
    ) -> list[SectionRow]:
        if section not in VALID_SECTION_NAMES:
            raise HTTPException(400, f"Unknown section: {section!r}")
        rows = await db.query_section(
            agent_id, section,
            limit=min(limit, 1000),
            start=start or 0,
            end=end or int(time.time()),
        )
        return [SectionRow(**r) for r in rows]

    return router
