from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest

from manager.manager.integrations.client import _parse_retry_after


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
