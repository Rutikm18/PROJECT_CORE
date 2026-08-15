from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest

from manager.manager.integrations.client import ResilientHTTPClient, _parse_retry_after
from manager.manager.integrations.resilience import (
    RetryPolicy,
    TransientError,
    registry,
)


def test_retry_after_accepts_delta_seconds() -> None:
    assert _parse_retry_after("12.5") == 12.5


def test_retry_after_accepts_http_date() -> None:
    value = format_datetime(datetime.now(UTC) + timedelta(seconds=20), usegmt=True)

    parsed = _parse_retry_after(value)

    assert parsed is not None
    assert parsed == pytest.approx(20, abs=2)


def test_retry_after_rejects_invalid_and_clamps_past_values() -> None:
    assert _parse_retry_after("not-a-date") is None
    assert _parse_retry_after("-4") == 0.0


@pytest.mark.asyncio
async def test_ai_transport_retries_transient_failure_then_records_success() -> None:
    registry.reset()
    client = ResilientHTTPClient(
        "ai:test-retry",
        retry=RetryPolicy(max_attempts=3, base_delay=0, max_delay=0, jitter=False),
    )
    attempts = 0

    async def flaky_call() -> dict:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise TransientError("ai:test-retry", "temporary provider failure")
        return {"status": "ok"}

    try:
        assert await client.call(flaky_call) == {"status": "ok"}
        metrics = registry.metrics("ai:test-retry")
        assert attempts == 3
        assert metrics.calls == 1
        assert metrics.retries == 2
        assert metrics.successes == 1
        assert metrics.failures == 0
    finally:
        registry.reset()


@pytest.mark.asyncio
async def test_ai_transport_uses_fallback_after_retry_exhaustion() -> None:
    registry.reset()
    client = ResilientHTTPClient(
        "ai:test-fallback",
        retry=RetryPolicy(max_attempts=2, base_delay=0, max_delay=0, jitter=False),
    )
    attempts = 0

    async def unavailable() -> dict:
        nonlocal attempts
        attempts += 1
        raise TransientError("ai:test-fallback", "provider unavailable")

    async def deterministic_fallback() -> dict:
        return {"verdict": "inconclusive", "source": "deterministic"}

    try:
        result = await client.call(unavailable, fallback=deterministic_fallback)
        assert result == {"verdict": "inconclusive", "source": "deterministic"}
        assert attempts == 2
        metrics = registry.metrics("ai:test-fallback")
        assert metrics.retries == 1
        assert metrics.failures == 1
    finally:
        registry.reset()
