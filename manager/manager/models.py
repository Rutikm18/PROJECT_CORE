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


class AgentDetail(AgentSummary):
    sections: dict[str, int]   # section_name → last collected_at (Unix epoch)


class SectionRow(BaseModel):
    collected_at: int
    received_at:  int
    data:         Any


class IngestResponse(BaseModel):
    status: str = "ok"


class HealthResponse(BaseModel):
    status: str
    db:     str
