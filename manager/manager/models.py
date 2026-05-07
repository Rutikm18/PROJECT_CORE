"""
manager/manager/models.py — Pydantic response models for the REST API.

Typed responses provide:
  - Consistent field names across all endpoints
  - Automatic OpenAPI / Swagger schema generation
  - Clear contract for the dashboard frontend and API consumers

Keep models in sync with manager/manager/db.py return shapes.
"""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class AgentSummary(BaseModel):
    agent_id:   str
    name:       str
    last_seen:  int
    last_ip:    str
    created_at: int
    online:     bool
    live_status: str = "offline"
    last_seen_label: str = ""
    online_for: int = 0
    offline_for: int = 0
    session_count: int = 0


class AgentDetail(AgentSummary):
    sections: dict[str, int]   # section_name → last collected_at (Unix epoch)
    sessions: list[dict] = []


class SectionRow(BaseModel):
    collected_at: int
    received_at:  int
    data:         Any


class IngestResponse(BaseModel):
    status: str  = "ok"
    queued: bool = False   # True when payload was published to RabbitMQ queue


class HealthResponse(BaseModel):
    status: str
    db:     str
