from __future__ import annotations

from types import SimpleNamespace

import pytest

from manager.manager.attacklens.ai_validator import invalidate_validation_settings_cache
from manager.manager.attacklens.validation import _g7_quality_floor


class _SettingsDB:
    def __init__(self, floor: float) -> None:
        self.floor = floor

    async def _fetchall(self, _query: str, _args: tuple) -> list[dict]:
        return [{"key": "validation_min_strength", "value": str(self.floor)}]


@pytest.mark.asyncio
async def test_g7_uses_runtime_validation_min_strength() -> None:
    cluster = SimpleNamespace(signals=[SimpleNamespace(strength=0.80)])

    invalidate_validation_settings_cache()
    rejected = await _g7_quality_floor(cluster, {}, _SettingsDB(0.90), None, None)
    invalidate_validation_settings_cache()
    accepted = await _g7_quality_floor(cluster, {}, _SettingsDB(0.70), None, None)

    assert rejected.passed is False
    assert "0.9" in (rejected.detail or "")
    assert accepted.passed is True
