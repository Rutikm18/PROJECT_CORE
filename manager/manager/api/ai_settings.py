"""
manager/manager/api/ai_settings.py — Customer-managed AI provider configuration.

Endpoints:
  GET    /api/v1/ai/provider      — current config (key masked)
  POST   /api/v1/ai/provider      — set/update provider + API key + model
  DELETE /api/v1/ai/provider      — remove config
  POST   /api/v1/ai/test          — test connection with current config
  GET    /api/v1/ai/models        — available models per provider
  POST   /api/v1/ai/analyze/{id}  — analyze a finding with AI
  POST   /api/v1/ai/remediate/{id}— generate remediation plan with AI
  POST   /api/v1/ai/prioritize    — AI-prioritize a batch of findings

Design:
  • API key is encrypted at rest (AES-256-GCM) in data/ai_provider.enc
  • Key preview (first 6 + last 4 chars) is the only key data sent to the UI
  • Provider test validates key + model availability before saving
  • Finding analysis is cached in intel_db; use force=true to regenerate
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..ai.base import PROVIDER_MODELS, DEFAULT_MODELS
from ..ai.key_store import load_config, save_config, delete_config, config_summary
from ..ai.providers import build_provider
from ..ai.finding_analyzer import FindingAnalyzer

log = logging.getLogger("manager.api.ai_settings")

router = APIRouter(prefix="/api/v1/ai", tags=["ai-provider"])

_VALID_PROVIDERS = list(PROVIDER_MODELS.keys())


# ── Dependencies ──────────────────────────────────────────────────────────────

def _idb(req: Request):
    idb = getattr(req.app.state, "intel_db", None)
    if idb is None:
        raise HTTPException(503, "IntelDB not available")
    return idb


# ── Request models ────────────────────────────────────────────────────────────

class ProviderSetRequest(BaseModel):
    provider: str  = Field(..., description="anthropic | openai | gemini | ollama")
    api_key:  str  = Field(default="", description="API key (empty for ollama)")
    model:    str  = Field(default="", description="Model name; defaults to cheapest for provider")
    base_url: str  = Field(default="", description="Custom endpoint (ollama, Azure, proxies)")
    test_first: bool = Field(default=True, description="Validate connection before saving")


class AnalyzeRequest(BaseModel):
    force: bool = Field(default=False, description="Regenerate even if cached")
    os_type: str = Field(default="macos", description="macos|windows|linux (for remediation)")


class PrioritizeRequest(BaseModel):
    finding_ids: list[int] = Field(..., min_length=1, max_length=50)


# ── Provider config endpoints ─────────────────────────────────────────────────

@router.get("/provider")
async def get_provider_config() -> dict:
    """Return current AI provider config (key masked)."""
    summary = config_summary()
    if summary is None:
        return {
            "configured":  False,
            "provider":    None,
            "model":       None,
            "key_set":     False,
            "key_preview": None,
            "base_url":    "",
            "updated_at":  None,
            "available_providers": _VALID_PROVIDERS,
        }
    return {
        "configured": True,
        **summary,
        "available_providers": _VALID_PROVIDERS,
    }


@router.post("/provider")
async def set_provider_config(body: ProviderSetRequest) -> dict:
    """
    Configure AI provider + API key.
    Tests the connection first (unless test_first=false) before persisting.
    """
    if body.provider not in _VALID_PROVIDERS:
        raise HTTPException(
            422,
            detail=f"Invalid provider '{body.provider}'. Valid: {_VALID_PROVIDERS}",
        )

    model    = body.model or DEFAULT_MODELS[body.provider]
    api_key  = body.api_key.strip()

    # Ollama doesn't need a key
    if body.provider != "ollama" and not api_key and body.test_first:
        raise HTTPException(422, "api_key is required for non-Ollama providers")

    if body.test_first:
        from ..ai.base import ProviderConfig
        test_cfg = ProviderConfig(
            provider = body.provider,
            api_key  = api_key,
            model    = model,
            base_url = body.base_url,
        )
        provider = build_provider(test_cfg)
        ok, msg  = await provider.health_check()
        if not ok:
            raise HTTPException(400, detail=f"Provider test failed: {msg}")

    cfg = save_config(
        provider = body.provider,
        api_key  = api_key,
        model    = model,
        base_url = body.base_url,
    )

    return {
        "ok":       True,
        "provider": cfg.provider,
        "model":    cfg.model,
        "message":  f"Provider '{cfg.provider}' configured with model '{cfg.model}'",
    }


@router.delete("/provider")
async def delete_provider_config() -> dict:
    """Remove stored AI provider config."""
    delete_config()
    return {"ok": True, "message": "AI provider configuration removed"}


@router.post("/test")
async def test_provider_connection() -> dict:
    """
    Test the currently-configured provider.
    Returns latency, model, and a status message.
    """
    cfg = load_config()
    if cfg is None:
        raise HTTPException(404, "No AI provider configured. POST /api/v1/ai/provider first.")

    provider = build_provider(cfg)
    t0       = time.monotonic()
    ok, msg  = await provider.health_check()
    latency  = round((time.monotonic() - t0) * 1000, 1)

    return {
        "ok":        ok,
        "provider":  cfg.provider,
        "model":     cfg.model,
        "message":   msg,
        "latency_ms": latency,
    }


@router.get("/models")
async def list_models() -> dict:
    """Return available models per provider with cost notes."""
    cost_notes = {
        "anthropic": {
            "claude-haiku-4-5-20251001": "Fastest · cheapest — ideal for finding validation",
            "claude-sonnet-4-6":         "Balanced — recommended for remediation plans",
            "claude-opus-4-8":           "Most capable — use for complex analysis",
        },
        "openai": {
            "gpt-4o-mini": "Cheapest · fast — ideal for finding validation",
            "gpt-4o":      "Balanced — recommended for remediation plans",
            "gpt-4-turbo": "Most capable — use for complex analysis",
        },
        "gemini": {
            "gemini-1.5-flash":  "Fastest · cheapest — ideal for validation",
            "gemini-1.5-pro":    "Balanced — recommended for remediation",
            "gemini-2.0-flash":  "Fast + capable",
        },
        "ollama": {
            "llama3.2:3b":   "Fastest local — 2GB RAM, good for simple analysis",
            "llama3.2:8b":   "Balanced local — 5GB RAM",
            "llama3.1:70b":  "Best local quality — requires 40GB+ RAM",
            "mistral:7b":    "Good reasoning — 4GB RAM",
            "qwen2.5:7b":    "Strong JSON output — 4GB RAM",
        },
    }
    return {
        "providers": {
            p: {
                "models":  [
                    {
                        "id":      m,
                        "note":    cost_notes.get(p, {}).get(m, ""),
                        "default": m == DEFAULT_MODELS.get(p),
                    }
                    for m in models
                ],
                "requires_key": p != "ollama",
            }
            for p, models in PROVIDER_MODELS.items()
        }
    }


# ── Finding analysis endpoints ─────────────────────────────────────────────────

@router.get("/analysis/{finding_id}")
async def get_cached_analysis(finding_id: int, idb=Depends(_idb)) -> dict:
    """
    Return the cached AI analysis for a finding WITHOUT triggering generation.
    Returns 404 if never analyzed. Used by the UI to peek on drawer open so
    it never spends an API call unless the user explicitly clicks Analyze.
    """
    try:
        cached = await idb.get_ai_analysis(finding_id)
    except Exception as exc:
        raise HTTPException(503, f"DB error: {exc}")
    if not cached or not cached.get("analysis"):
        raise HTTPException(404, "No cached analysis. POST /analyze/{id} to generate.")
    return cached


@router.get("/remediation/{finding_id}")
async def get_cached_remediation(
    finding_id: int,
    os_type: str = Query("macos"),
    idb=Depends(_idb),
) -> dict:
    """
    Return the cached remediation plan WITHOUT triggering generation.
    Returns 404 if none exists for this finding+OS.
    """
    try:
        cached = await idb.get_remediation_plan(finding_id, os_type)
    except Exception as exc:
        raise HTTPException(503, f"DB error: {exc}")
    if not cached or not cached.get("summary"):
        raise HTTPException(404, "No cached remediation plan. POST /remediate/{id} to generate.")
    return cached


@router.post("/analyze/{finding_id}")
async def analyze_finding(
    finding_id: int,
    force:      bool = Query(False, description="Regenerate even if cached"),
    idb = Depends(_idb),
) -> dict:
    """
    Analyze a finding with AI — returns threat context, risk narrative, urgency.
    Result is cached; use force=true to regenerate.
    """
    finding = await _get_finding(finding_id, idb)
    analyzer = FindingAnalyzer()
    try:
        result = await analyzer.analyze(
            finding_id, finding, force=force, intel_db=idb
        )
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except Exception as exc:
        log.warning("AI analysis failed for finding %d: %s", finding_id, exc)
        raise HTTPException(500, f"AI analysis failed: {exc}")
    return result.to_dict()


@router.post("/remediate/{finding_id}")
async def remediate_finding(
    finding_id: int,
    os_type:    str  = Query("macos",  description="macos|windows|linux"),
    force:      bool = Query(False,    description="Regenerate even if cached"),
    idb = Depends(_idb),
) -> dict:
    """
    Generate an AI-powered OS-specific remediation plan for a finding.
    Result is cached; use force=true to regenerate.
    """
    if os_type not in ("macos", "windows", "linux"):
        raise HTTPException(422, f"Invalid os_type '{os_type}'. Use: macos|windows|linux")

    finding  = await _get_finding(finding_id, idb)
    analyzer = FindingAnalyzer()
    try:
        result = await analyzer.remediate(
            finding_id, finding, os_type=os_type, force=force, intel_db=idb
        )
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except Exception as exc:
        log.warning("AI remediation failed for finding %d: %s", finding_id, exc)
        raise HTTPException(500, f"AI remediation failed: {exc}")
    return result.to_dict()


@router.post("/prioritize")
async def prioritize_findings(body: PrioritizeRequest, idb=Depends(_idb)) -> dict:
    """AI-assisted finding prioritization — ranks by true business risk."""
    findings = []
    for fid in body.finding_ids:
        try:
            f = await _get_finding(fid, idb)
            f["item_key"] = str(fid)
            findings.append(f)
        except HTTPException:
            pass

    if not findings:
        raise HTTPException(404, "No findings found for the supplied IDs")

    analyzer = FindingAnalyzer()
    try:
        prioritized = await analyzer.prioritize(findings)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Prioritization failed: {exc}")

    cfg = load_config()
    return {
        "findings":   prioritized,
        "count":      len(prioritized),
        "provider":   cfg.provider if cfg else "unknown",
        "model":      cfg.model    if cfg else "unknown",
        "ranked_at":  time.time(),
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_finding(finding_id: int, idb) -> dict:
    try:
        f = await idb.get_finding_by_id(finding_id)
    except Exception as exc:
        raise HTTPException(503, f"DB error: {exc}")
    if f is None:
        raise HTTPException(404, f"Finding {finding_id} not found")

    # Deserialize JSON columns
    for col, default in [("evidence", {}), ("cve_ids", []), ("tags", []),
                         ("exploit_sources", []), ("action_plan", [])]:
        v = f.get(col)
        if isinstance(v, str):
            try:
                f[col] = json.loads(v) if v else default
            except Exception:
                f[col] = default
    return f
