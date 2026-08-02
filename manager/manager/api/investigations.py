"""API for durable, analyst-gated post-finding investigations."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


class InvestigationDecision(BaseModel):
    decision: Literal["approve", "reject", "request_more"]
    actor: str = Field(default="analyst", min_length=1, max_length=100)
    feedback: str = Field(default="", max_length=1000)


def make_investigations_router(service) -> APIRouter:
    router = APIRouter(tags=["ai-investigations"])

    @router.post("/investigations/{finding_id}")
    async def start_investigation(finding_id: int, force: bool = False) -> dict:
        try:
            return await service.start_investigation(finding_id, force=force)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.get("/investigations/run/{run_id}")
    async def get_investigation(run_id: str) -> dict:
        run = await service.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Investigation run not found")
        return run

    @router.get("/investigations/{finding_id}")
    async def latest_investigation(finding_id: int) -> dict:
        run = await service.get_latest_run(finding_id)
        if not run:
            raise HTTPException(status_code=404, detail="No investigation exists for this finding")
        return run

    @router.post("/investigations/run/{run_id}/decision")
    async def decide_investigation(run_id: str, body: InvestigationDecision) -> dict:
        try:
            return await service.resume_investigation(
                run_id,
                decision=body.decision,
                actor=body.actor,
                feedback=body.feedback,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    return router
