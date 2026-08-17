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
from ..ai import catalog
from ..ai.finding_analyzer import FindingAnalyzer
from .authz import require_admin, require_session

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
    provider: str  = Field(..., description="anthropic | openai | gemini | ollama | openrouter")
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
async def get_provider_config(
    _user: dict = Depends(require_session),
) -> dict:
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
async def set_provider_config(
    body: ProviderSetRequest,
    _admin: dict = Depends(require_admin),
) -> dict:
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
async def delete_provider_config(
    _admin: dict = Depends(require_admin),
) -> dict:
    """Remove stored AI provider config."""
    delete_config()
    return {"ok": True, "message": "AI provider configuration removed"}


@router.post("/test")
async def test_provider_connection(
    _admin: dict = Depends(require_admin),
) -> dict:
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
async def list_models(
    _user: dict = Depends(require_session),
) -> dict:
    """Return available models per provider with cost notes."""
    cost_notes = {
        "anthropic": {
            "claude-haiku-4-5-20251001": "Fastest · cheapest — ideal for finding validation",
            "claude-sonnet-4-6":         "Balanced — recommended for remediation plans",
            "claude-opus-4-8":           "Most capable — use for complex analysis",
        },
        "openai": {
            "gpt-4o-mini":        "Cheapest · fast — ideal for finding validation",
            "gpt-4o":             "Balanced — recommended for remediation plans",
            "gpt-4-turbo":        "Most capable — use for complex analysis",
            "codex-mini-latest":  "Codex — optimised for code & structured output",
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
        # Verified against the live catalog 2026-08-17; the live overlay below
        # is authoritative when reachable.
        "openrouter": {
            "openai/gpt-oss-20b:free":                "FREE · 131k ctx — best free structured output",
            "google/gemma-4-31b-it:free":             "FREE · 262k ctx — Google Gemma 4",
            "google/gemma-4-26b-a4b-it:free":         "FREE · 262k ctx — MoE, fast",
            "nvidia/nemotron-3-super-120b-a12b:free": "FREE · 262k ctx — largest free model",
            "nvidia/nemotron-nano-9b-v2:free":        "FREE · 128k ctx — fastest free",
            "inclusionai/ling-2.6-flash":             "~$0.01/M in — cheapest paid, structured",
            "mistralai/mistral-nemo":                 "~$0.02/M in — cheap and reliable",
            "qwen/qwen3.7-flash":                     "~$0.03/M in · 1M ctx",
            "openai/gpt-oss-120b":                    "~$0.03/M in — strong for the price",
            "openai/gpt-4o-mini":                     "Cheap, excellent structured output",
            "google/gemini-2.5-flash":                "Balanced — good for remediation plans",
            "anthropic/claude-haiku-4.5":             "Claude Haiku 4.5 via OpenRouter",
            "anthropic/claude-sonnet-4.5":            "Claude Sonnet 4.5 — deep thinking, one credential",
            "anthropic/claude-opus-4.1":              "Claude Opus 4.1 — most capable",
            "deepseek/deepseek-r1":                   "DeepSeek R1 — deep reasoning",
            "google/gemini-2.5-pro":                  "Gemini 2.5 Pro — most capable Google model",
            "openai/gpt-5.1-codex-mini":              "Codex Mini — code-optimised",
        },
    }
    providers = {
        p: {
            "models": [
                {
                    "id":      m,
                    "note":    cost_notes.get(p, {}).get(m, ""),
                    "default": m == DEFAULT_MODELS.get(p),
                }
                for m in models
            ],
            "requires_key": p != "ollama",
            "source": "static",
        }
        for p, models in PROVIDER_MODELS.items()
    }

    # Overlay the live OpenRouter catalog when we can reach it. The static list
    # above is only a cold-start fallback — OpenRouter's roster changes weekly,
    # so a pinned list goes stale and starts hiding models that exist.
    try:
        live = await catalog.refresh()
    except Exception as exc:                       # never fail the settings page
        log.warning("Live model catalog unavailable: %s", exc)
        live = {}

    if live:
        seeded = set(PROVIDER_MODELS.get("openrouter", []))
        entries = []
        for model_id, info in live.items():
            entry = info.to_dict()
            entry["note"] = cost_notes["openrouter"].get(model_id) or entry["note"]
            entry["default"] = model_id == DEFAULT_MODELS.get("openrouter")
            entry["recommended"] = model_id in seeded
            entries.append(entry)
        # Free first, then cheapest — the order an operator picking a model wants.
        entries.sort(key=lambda e: (not e["is_free"], not e["recommended"], e["id"]))
        providers["openrouter"] = {
            "models": entries,
            "requires_key": True,
            "source": "live",
            "cache_age_seconds": catalog.cache_age_seconds(),
        }

    return {"providers": providers}


# ── Per-task model selection ───────────────────────────────────────────────────
# Stored as JSON in data/ai_task_models.json alongside the main provider config.
# Tasks: "validation" (AI finding validation) | "remediation" (fix plans)

import json as _json
import pathlib as _pathlib

_TASK_MODELS_PATH = _pathlib.Path("data/ai_task_models.json")

# validation  — high volume, cheapest capable model
# remediation — balanced; writes the fix plan an analyst will follow
# deep        — low volume, highest quality (e.g. a Claude or R1 reasoning model
#               reached through the same OpenRouter credential)
_VALID_TASKS = {"validation", "remediation", "deep"}


def _load_task_models() -> dict:
    try:
        return _json.loads(_TASK_MODELS_PATH.read_text())
    except Exception:
        return {}


def _save_task_models(models: dict) -> None:
    _TASK_MODELS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _TASK_MODELS_PATH.write_text(_json.dumps(models, indent=2))


def _validate_model_for_provider(provider: str, model: str) -> None:
    """Reject a model the provider cannot serve — without pinning a stale list.

    The old check required the model to appear in the hardcoded
    PROVIDER_MODELS list, which rejected every OpenRouter model added since
    that list was written (including every current Claude model, leaving only a
    March-2024 Haiku). For OpenRouter the live catalog is authoritative and the
    static list is just a seed; when the catalog is cold we accept the value
    rather than block on a list we know is incomplete.
    """
    model = (model or "").strip()
    if not model:
        raise HTTPException(422, detail="model is required")

    if provider == "openrouter":
        live = catalog.cached_models()
        if live and model not in live:
            raise HTTPException(
                422,
                detail=(
                    f"Model '{model}' is not in the OpenRouter catalog. "
                    "Check the ID at https://openrouter.ai/models, or call "
                    "GET /api/v1/ai/models to refresh the list."
                ),
            )
        return

    # Non-OpenRouter providers expose a small, stable set we can enumerate.
    valid_models = PROVIDER_MODELS.get(provider, [])
    if valid_models and model not in valid_models:
        raise HTTPException(
            422,
            detail=f"Model '{model}' not in provider '{provider}' model list. "
                   f"Valid: {valid_models}",
        )


class TaskModelRequest(BaseModel):
    task:     str = Field(..., description="validation | remediation")
    provider: str = Field(..., description="Provider name (anthropic, openrouter, ...)")
    model:    str = Field(..., description="Model ID for this task")


@router.get("/task-models")
async def get_task_models(
    _user: dict = Depends(require_session),
) -> dict:
    """Return per-task model overrides (validation vs remediation)."""
    task_models = _load_task_models()
    summary = config_summary()
    default_provider = summary["provider"] if summary else None
    default_model = summary["model"] if summary else None
    return {
        "task_models": task_models,
        "default_provider": default_provider,
        "default_model": default_model,
        "valid_tasks": list(_VALID_TASKS),
    }


@router.post("/task-models")
async def set_task_model(
    body: TaskModelRequest,
    _admin: dict = Depends(require_admin),
) -> dict:
    """Set the AI model to use for a specific task (validation or remediation)."""
    if body.task not in _VALID_TASKS:
        raise HTTPException(422, detail=f"Invalid task '{body.task}'. Valid: {sorted(_VALID_TASKS)}")
    if body.provider not in _VALID_PROVIDERS:
        raise HTTPException(422, detail=f"Invalid provider '{body.provider}'. Valid: {_VALID_PROVIDERS}")
    saved_config = load_config()
    if saved_config is None:
        raise HTTPException(
            422,
            detail="Configure and test a provider credential before assigning a task model",
        )
    if body.provider != saved_config.provider:
        raise HTTPException(
            422,
            detail=(
                f"The saved credential belongs to '{saved_config.provider}', not "
                f"'{body.provider}'. Configure that provider credential first."
            ),
        )
    _validate_model_for_provider(body.provider, body.model)
    task_models = _load_task_models()
    task_models[body.task] = {"provider": body.provider, "model": body.model}
    _save_task_models(task_models)
    return {"task": body.task, "provider": body.provider, "model": body.model, "saved": True}


@router.delete("/task-models/{task}")
async def reset_task_model(
    task: str,
    _admin: dict = Depends(require_admin),
) -> dict:
    """Reset a task to use the default provider model."""
    if task not in _VALID_TASKS:
        raise HTTPException(422, detail=f"Invalid task '{task}'. Valid: {sorted(_VALID_TASKS)}")
    task_models = _load_task_models()
    task_models.pop(task, None)
    _save_task_models(task_models)
    return {"task": task, "reset": True}


# ── Finding analysis endpoints ─────────────────────────────────────────────────

@router.get("/analysis/{finding_id}")
async def get_cached_analysis(
    finding_id: int,
    idb=Depends(_idb),
    _user: dict = Depends(require_session),
) -> dict:
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
    _user: dict = Depends(require_session),
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
    _user: dict = Depends(require_session),
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
    _user: dict = Depends(require_session),
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
async def prioritize_findings(
    body: PrioritizeRequest,
    idb=Depends(_idb),
    _user: dict = Depends(require_session),
) -> dict:
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
