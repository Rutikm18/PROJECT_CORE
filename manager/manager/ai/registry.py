"""Provider registry used by runtime AI tasks.

The encrypted provider config owns credentials. Per-task configuration may
select a different model for that same provider, but it may never silently
reuse one provider's key with another provider.
"""
from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Optional

from .base import AIProvider, ProviderConfig
from .key_store import load_config
from .providers import build_provider

_TASK_MODELS_PATH = Path(
    os.environ.get("AI_TASK_MODELS_STORE", "data/ai_task_models.json")
)


class ProviderConfigurationError(RuntimeError):
    """Saved task/provider settings cannot form a safe runtime provider."""


def _load_task_models(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def resolve_task_provider_config(
    task: str,
    *,
    provider_config: Optional[ProviderConfig] = None,
    task_models_path: Path = _TASK_MODELS_PATH,
) -> Optional[ProviderConfig]:
    config = provider_config if provider_config is not None else load_config()
    if config is None:
        return None
    override = _load_task_models(task_models_path).get(task)
    if not isinstance(override, dict):
        return config
    provider = str(override.get("provider") or config.provider)
    if provider != config.provider:
        raise ProviderConfigurationError(
            f"Task '{task}' selects provider '{provider}', but the stored "
            f"credential belongs to '{config.provider}'"
        )
    model = str(override.get("model") or config.model)
    return replace(config, model=model)


def build_task_provider(task: str) -> Optional[AIProvider]:
    config = resolve_task_provider_config(task)
    return build_provider(config) if config is not None else None
