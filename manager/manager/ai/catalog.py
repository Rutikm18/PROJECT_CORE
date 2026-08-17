"""
manager/manager/ai/catalog.py — Live OpenRouter model catalog.

OpenRouter's roster changes constantly: models are added, pulled, re-priced, and
free tiers come and go. A hardcoded list goes stale within weeks and then
silently blocks model IDs that exist (the old `PROVIDER_MODELS` allow-list
rejected every Claude model except a March-2024 Haiku).

So the catalog is fetched from the provider and cached on disk:

    GET https://openrouter.ai/api/v1/models   (public — no API key required)

Two facts are derived per model and used elsewhere:

  • ``is_free``  — pricing is exactly zero. Free tiers generally train on
    prompts, which matters because we send endpoint telemetry.
  • ``supports_structured_output`` — whether the model accepts a strict
    ``json_schema`` response format. Sending one to a model that does not
    support it makes OpenRouter find zero eligible providers and fail the call.

Every lookup degrades to a heuristic when the catalog is unavailable, so an
offline manager keeps working.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("manager.ai.catalog")

_CATALOG_URL = "https://openrouter.ai/api/v1/models"
_CACHE_PATH = Path(os.environ.get("AI_MODEL_CACHE", "data/ai_models_cache.json"))
_CACHE_TTL_S = int(os.environ.get("AI_MODEL_CACHE_TTL_SECONDS", str(6 * 3600)))
_FETCH_TIMEOUT_S = 15

# Parameter names OpenRouter reports for models that accept a strict schema.
_STRUCTURED_PARAMS = {"structured_outputs", "response_format"}

# In-process memo so repeated lookups in one request do not re-read the file.
_memo: dict[str, object] = {"loaded_at": 0.0, "models": {}}


@dataclass
class ModelInfo:
    id: str
    name: str = ""
    context_length: int = 0
    prompt_price: float = 0.0        # USD per token
    completion_price: float = 0.0
    supported_parameters: list[str] = field(default_factory=list)

    @property
    def is_free(self) -> bool:
        return self.prompt_price == 0.0 and self.completion_price == 0.0

    @property
    def supports_structured_output(self) -> bool:
        return bool(_STRUCTURED_PARAMS.intersection(self.supported_parameters))

    def price_note(self) -> str:
        if self.is_free:
            return "FREE (rate-limited)"
        # Providers quote per-million-token prices; convert for readability.
        return (
            f"${self.prompt_price * 1_000_000:.2f}/M in · "
            f"${self.completion_price * 1_000_000:.2f}/M out"
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "context_length": self.context_length,
            "is_free": self.is_free,
            "structured_output": self.supports_structured_output,
            "note": self.price_note(),
        }


def _price(raw: object) -> float:
    """OpenRouter quotes prices as strings ('0', '0.00000015'). Be forgiving."""
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _parse(payload: dict) -> dict[str, ModelInfo]:
    models: dict[str, ModelInfo] = {}
    for item in payload.get("data", []):
        if not isinstance(item, dict):
            continue
        model_id = str(item.get("id") or "").strip()
        if not model_id:
            continue
        pricing = item.get("pricing") or {}
        params = item.get("supported_parameters") or []
        models[model_id] = ModelInfo(
            id=model_id,
            name=str(item.get("name") or model_id),
            context_length=int(item.get("context_length") or 0),
            prompt_price=_price(pricing.get("prompt")),
            completion_price=_price(pricing.get("completion")),
            supported_parameters=[str(p) for p in params if isinstance(p, str)],
        )
    return models


# ── Disk cache ────────────────────────────────────────────────────────────────

def _read_cache() -> tuple[dict[str, ModelInfo], float]:
    if not _CACHE_PATH.exists():
        return {}, 0.0
    try:
        raw = json.loads(_CACHE_PATH.read_text())
        return _parse(raw), float(raw.get("fetched_at") or 0.0)
    except Exception as exc:
        log.warning("Model catalog cache unreadable: %s", exc)
        return {}, 0.0


def _write_cache(payload: dict) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(payload)
        payload["fetched_at"] = time.time()
        _CACHE_PATH.write_text(json.dumps(payload))
    except Exception as exc:
        log.warning("Could not write model catalog cache: %s", exc)


def cached_models() -> dict[str, ModelInfo]:
    """Models from the in-process memo or the disk cache. Never fetches."""
    now = time.time()
    if _memo["models"] and now - float(_memo["loaded_at"]) < 60:
        return _memo["models"]  # type: ignore[return-value]
    models, _fetched_at = _read_cache()
    _memo["models"] = models
    _memo["loaded_at"] = now
    return models


def cache_age_seconds() -> Optional[float]:
    _models, fetched_at = _read_cache()
    return (time.time() - fetched_at) if fetched_at else None


def invalidate_memo() -> None:
    """Drop the in-process memo — used by tests and right after a refresh."""
    _memo["models"] = {}
    _memo["loaded_at"] = 0.0


# ── Fetch ─────────────────────────────────────────────────────────────────────

async def refresh(force: bool = False) -> dict[str, ModelInfo]:
    """Fetch the catalog if the cache is stale. Returns whatever is usable.

    Never raises: a provider outage must not take AI features down, it just
    means lookups fall back to heuristics.
    """
    models, fetched_at = _read_cache()
    if models and not force and (time.time() - fetched_at) < _CACHE_TTL_S:
        return models

    try:
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=_FETCH_TIMEOUT_S)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(_CATALOG_URL) as resp:
                if resp.status != 200:
                    log.warning("Model catalog fetch returned HTTP %s", resp.status)
                    return models
                payload = await resp.json()
    except Exception as exc:
        log.warning("Model catalog fetch failed (%s) — using cached/heuristic data", exc)
        return models

    parsed = _parse(payload)
    if not parsed:
        log.warning("Model catalog fetch returned no usable models")
        return models

    _write_cache(payload)
    invalidate_memo()
    log.info("Model catalog refreshed — %d models", len(parsed))
    return parsed


# ── Lookups (cache-only, safe to call from a hot path) ────────────────────────

def get(model_id: str) -> Optional[ModelInfo]:
    return cached_models().get(model_id)


def is_free_model(model_id: str) -> bool:
    """True when the model costs nothing.

    Falls back to OpenRouter's ':free' naming convention when the catalog is
    unavailable. The fallback errs toward *treating a model as free*, which is
    the conservative direction: free implies the stricter privacy handling.
    """
    info = get(model_id)
    if info is not None:
        return info.is_free
    return model_id.strip().endswith(":free")


def supports_structured_output(model_id: str) -> Optional[bool]:
    """True/False from the catalog, or None when genuinely unknown.

    None is a distinct answer, not a synonym for False — the caller decides
    whether to risk a strict schema or downgrade. Collapsing unknown into False
    would permanently disable structured output whenever the catalog is cold.
    """
    info = get(model_id)
    if info is None:
        return None
    return info.supports_structured_output
