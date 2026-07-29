from __future__ import annotations

import time
from unittest.mock import AsyncMock

import pytest

from manager.manager.attacklens.feeds import FeedManager, FeedRefreshError
from manager.manager.threat.nvd_sync import (
    NVDSyncWorker,
    _STATE_DELTA,
    _STATE_FULL,
    _parse_vuln,
)


class _FakeIntelDB:
    def __init__(self, delta_state: str = "0") -> None:
        self.delta_state = delta_state
        self.states: dict[str, str] = {}
        self.feed_attempts: list[tuple[str, bool, int, str]] = []
        self.batches: list[list[dict]] = []

    async def get_nvd_state(self, key):
        return self.states.get(key, self.delta_state if key == _STATE_DELTA else "0")

    async def set_nvd_state(self, key, value):
        self.states[key] = value

    async def upsert_nvd_bulk(self, batch):
        self.batches.append(batch)
        return len(batch)

    async def record_feed_attempt(
        self, source, *, success, entry_count=0, error=""
    ):
        self.feed_attempts.append((source, success, entry_count, error))


def _nvd_page(cve_id: str = "CVE-2026-1234", *, status: str = "Analyzed"):
    return {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "vulnStatus": status,
                "descriptions": [{"lang": "en", "value": "Acme widget vulnerability"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
            }
        }],
    }


@pytest.mark.asyncio
async def test_full_sync_does_not_advance_checkpoint_after_failed_page():
    db = _FakeIntelDB()
    worker = NVDSyncWorker(db)
    worker._fetch_page = AsyncMock(return_value=None)

    await worker._run_full_sync()

    assert _STATE_FULL not in db.states
    assert _STATE_DELTA not in db.states
    assert db.feed_attempts[-1][0:2] == ("nvd:full_sync", False)


@pytest.mark.asyncio
async def test_full_sync_sets_delta_baseline_to_sync_start():
    db = _FakeIntelDB()
    worker = NVDSyncWorker(db)
    worker._fetch_page = AsyncMock(return_value=_nvd_page())
    started_before = time.time()

    await worker._run_full_sync()

    assert float(db.states[_STATE_FULL]) >= started_before
    assert started_before <= float(db.states[_STATE_DELTA]) <= float(db.states[_STATE_FULL])
    assert db.feed_attempts[-1][0:3] == ("nvd:full_sync", True, 1)


@pytest.mark.asyncio
async def test_delta_sync_keeps_checkpoint_after_failed_page():
    original = str(time.time() - 600)
    db = _FakeIntelDB(delta_state=original)
    worker = NVDSyncWorker(db)
    worker._fetch_page = AsyncMock(return_value=None)

    await worker._run_delta_sync()

    assert _STATE_DELTA not in db.states
    assert db.feed_attempts[-1][0:2] == ("nvd:delta_sync", False)


def test_nvd_parser_preserves_rejected_status():
    parsed = _parse_vuln(_nvd_page(status="Rejected")["vulnerabilities"][0])
    assert parsed is not None
    assert parsed["vuln_status"] == "Rejected"


class _HttpErrorResponse:
    status = 503

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _HttpErrorSession:
    def __init__(self, *_args, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def get(self, *_args, **_kwargs):
        return _HttpErrorResponse()


@pytest.mark.asyncio
async def test_feed_http_failure_is_not_reported_as_zero_entry_success(monkeypatch):
    from manager.manager.attacklens import feeds as feeds_module

    monkeypatch.setattr(feeds_module.aiohttp, "ClientSession", _HttpErrorSession)
    manager = FeedManager(db=object())

    with pytest.raises(FeedRefreshError):
        await manager.refresh_feodo()
