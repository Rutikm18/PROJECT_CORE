"""
manager/tests/unit/test_data_retention_settings.py — configurable data
retention: period (1/3/6/12/24 months) + action (delete | archive).

Covers:
  - retention_period_days() conversion + safe fallback on bad input
  - SettingsUpdate validators reject invalid period/action values
  - TelemetryStore.cleanup(prune_cold=False) preserves the cold tier (the
    "archive") while still pruning hot/warm on their normal schedule
  - TelemetryStore.archive_stats() reports real on-disk size (filesystem walk,
    not the known-lagging index)
  - GET/PUT /api/v1/settings round-trips retention_period_months/action
  - GET /api/v1/settings/retention returns config + live stats, with
    slow_fetch_warning true only for 12/24-month windows
  - default settings (no PUT yet) are period=1 day (0-sentinel), action=delete
"""
from __future__ import annotations

import asyncio
import gzip
import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from manager.manager.api.settings import (
    RETENTION_ACTIONS, RETENTION_PERIODS_MONTHS, RETENTION_SLOW_FETCH_MONTHS,
    SettingsUpdate, retention_period_days,
)
from manager.manager.store import TelemetryStore

# Note: TelemetryStore tests below are intentionally unchanged — that's the
# file-based (NDJSON+gzip) hot/warm/cold archive, out of scope for the
# manager.db/intel.db → Postgres migration, and still uses tempfile.mkdtemp()
# correctly (no SQL database involved at all).


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


# ── retention_period_days() ───────────────────────────────────────────────────

@pytest.mark.parametrize("months,days", [("0", 1), ("1", 30), ("3", 90),
                                         ("6", 180), ("12", 360), ("24", 720)])
def test_retention_period_days_conversion(months, days):
    assert retention_period_days(months) == days


def test_retention_period_days_bad_input_falls_back_to_default():
    # Default is the 0-sentinel (1 day) — bad input must degrade to it, not crash
    assert retention_period_days("not-a-number") == 1
    assert retention_period_days(None) == 1
    assert retention_period_days("999") == 24 * 30, \
        "an out-of-range month count must clamp to the nearest valid period, not crash"


def test_slow_fetch_months_are_exactly_twelve_and_twentyfour():
    assert RETENTION_SLOW_FETCH_MONTHS == frozenset({12, 24})
    assert 1 not in RETENTION_SLOW_FETCH_MONTHS
    assert 6 not in RETENTION_SLOW_FETCH_MONTHS


# ── SettingsUpdate validators ─────────────────────────────────────────────────

@pytest.mark.parametrize("months", ["1", "3", "6", "12", "24"])
def test_settings_update_accepts_valid_period(months):
    u = SettingsUpdate(retention_period_months=months)
    assert u.retention_period_months == months


def test_settings_update_rejects_invalid_period():
    with pytest.raises(ValidationError):
        SettingsUpdate(retention_period_months="5")


@pytest.mark.parametrize("action", ["delete", "archive"])
def test_settings_update_accepts_valid_action(action):
    u = SettingsUpdate(retention_action=action)
    assert u.retention_action == action


def test_settings_update_rejects_invalid_action():
    with pytest.raises(ValidationError):
        SettingsUpdate(retention_action="wipe")


def test_settings_update_action_case_insensitive():
    assert SettingsUpdate(retention_action="ARCHIVE").retention_action == "archive"


# ── TelemetryStore.cleanup(prune_cold=False) / archive_stats() ──────────────

def _gz_write(path: Path, line: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "at") as f:
        f.write(json.dumps(line) + "\n")


def test_cleanup_archive_mode_preserves_cold_tier():
    async def body():
        d = tempfile.mkdtemp()
        store = TelemetryStore(d)
        await store.init()
        try:
            now = datetime.now(tz=timezone.utc)
            old = now - timedelta(days=400)   # well past any retention window

            # Old cold-tier file (per-day bucket, %Y-%m dir naming per store.py)
            cold_path = store.cold / "agent-1" / "metrics" / old.strftime("%Y-%m") / f"{old.strftime('%d')}.ndjson.gz"
            _gz_write(cold_path, {"ts": old.timestamp(), "data": {}})
            os.utime(cold_path, (old.timestamp(), old.timestamp()))

            # Old hot/warm files too — these must STILL be pruned in archive mode.
            hot_path = store.hot / "agent-1" / "metrics" / old.strftime("%Y-%m-%d") / "00-00.ndjson.gz"
            _gz_write(hot_path, {"ts": old.timestamp(), "data": {}})
            os.utime(hot_path, (old.timestamp(), old.timestamp()))

            stats = await store.cleanup(prune_cold=False)

            assert cold_path.exists(), "archive mode must NOT delete the cold tier"
            assert stats["cold"] == 0
            assert not hot_path.exists(), "hot tier must still prune on its normal schedule"
        finally:
            await store.close()
    _run(body())


def test_cleanup_delete_mode_with_custom_retention_prunes_cold():
    async def body():
        d = tempfile.mkdtemp()
        store = TelemetryStore(d)
        await store.init()
        try:
            now = datetime.now(tz=timezone.utc)
            old = now - timedelta(days=100)   # beyond a 90-day (3-month) retention

            cold_path = store.cold / "agent-1" / "metrics" / old.strftime("%Y-%m") / f"{old.strftime('%d')}.ndjson.gz"
            _gz_write(cold_path, {"ts": old.timestamp(), "data": {}})
            os.utime(cold_path, (old.timestamp(), old.timestamp()))

            stats = await store.cleanup(cold_retention_sec=90 * 86400, prune_cold=True)

            assert not cold_path.exists(), "delete mode must prune cold beyond the configured retention"
            assert stats["cold"] == 1
        finally:
            await store.close()
    _run(body())


def test_archive_stats_reports_real_files_on_disk():
    async def body():
        d = tempfile.mkdtemp()
        store = TelemetryStore(d)
        await store.init()
        try:
            now = datetime.now(tz=timezone.utc)
            for i in range(3):
                p = store.cold / "agent-1" / "metrics" / now.strftime("%Y-%m") / f"{i:02d}.ndjson.gz"
                _gz_write(p, {"ts": now.timestamp(), "data": {"i": i}})

            stats = await store.archive_stats()
            assert stats["file_count"] == 3
            assert stats["total_bytes"] > 0
            assert stats["path"] == str(store.cold)
        finally:
            await store.close()
    _run(body())


def test_archive_stats_empty_when_no_cold_files():
    async def body():
        d = tempfile.mkdtemp()
        store = TelemetryStore(d)
        await store.init()
        try:
            stats = await store.archive_stats()
            assert stats["file_count"] == 0
            assert stats["total_bytes"] == 0
        finally:
            await store.close()
    _run(body())


# ── HTTP integration: GET/PUT /api/v1/settings, GET /api/v1/settings/retention ──
#
# create_app() builds Database/IntelDB from MANAGER_DATABASE_URL/
# INTEL_DATABASE_URL (server.py) — without setting these, every test here
# would silently share the same default postgresql://.../manager + /intel
# databases with no isolation or cleanup.
#
# app/client are MODULE-scoped (one app instance shared across this file's
# HTTP tests), matching the established, proven-stable pattern in
# test_attacklens_pipeline.py — NOT function-scoped. A function-scoped app
# here recreates create_app()'s full background-worker set (NVD sync, threat
# feeds, enrichment) once per test; cycling 29 of those in rapid succession
# produced genuine, non-deterministic test flakiness (a different test failed
# each run) from worker shutdown/startup overlap on the shared connection —
# confirmed by the fact this same test always passes standalone. One
# long-lived app for the whole file avoids the cycling entirely.
from manager.tests.conftest import _create_test_db, _drop_test_db


@pytest.fixture(scope="module")
def _module_pg_manager_dsn():
    dsn, name = _run(_create_test_db())
    try:
        yield dsn
    finally:
        _run(_drop_test_db(name))


@pytest.fixture(scope="module")
def _module_pg_intel_dsn():
    dsn, name = _run(_create_test_db())
    try:
        yield dsn
    finally:
        _run(_drop_test_db(name))


@pytest.fixture(scope="module")
def app(tmp_path_factory, _module_pg_manager_dsn, _module_pg_intel_dsn):
    mp = pytest.MonkeyPatch()  # module-scoped — monkeypatch fixture itself is function-scoped
    mp.setenv("DATA_DIR", str(tmp_path_factory.mktemp("retention_settings_data")))
    mp.setenv("MANAGER_DATABASE_URL", _module_pg_manager_dsn)
    mp.setenv("INTEL_DATABASE_URL", _module_pg_intel_dsn)
    mp.delenv("MACOS_INTEL_DEV_BOOTSTRAP", raising=False)
    from manager.manager.server import create_app
    try:
        yield create_app()
    finally:
        mp.undo()


@pytest.fixture(scope="module")
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c


def test_default_retention_settings_are_one_day_delete(client):
    r = client.get("/api/v1/settings")
    assert r.status_code == 200
    settings = r.json()["settings"]
    assert settings["retention_period_months"] == "0"   # 0-sentinel = 1 day
    assert settings["retention_action"] == "delete"


def test_put_retention_settings_round_trips(client):
    r = client.put("/api/v1/settings", json={
        "retention_period_months": "6", "retention_action": "archive",
    })
    assert r.status_code == 200
    settings = r.json()["settings"]
    assert settings["retention_period_months"] == "6"
    assert settings["retention_action"] == "archive"

    # Persisted, not just echoed — a fresh GET must see the same values.
    r2 = client.get("/api/v1/settings")
    assert r2.json()["settings"]["retention_period_months"] == "6"


def test_put_rejects_invalid_retention_period(client):
    r = client.put("/api/v1/settings", json={"retention_period_months": "9"})
    assert r.status_code == 422


def test_put_rejects_invalid_retention_action(client):
    r = client.put("/api/v1/settings", json={"retention_action": "shred"})
    assert r.status_code == 422


def test_get_retention_endpoint_reflects_config(client):
    client.put("/api/v1/settings", json={
        "retention_period_months": "12", "retention_action": "delete",
    })
    r = client.get("/api/v1/settings/retention")
    assert r.status_code == 200
    body = r.json()
    assert body["config"]["period_months"] == 12
    assert body["config"]["period_days"] == 360
    assert body["config"]["action"] == "delete"
    assert body["config"]["slow_fetch_warning"] is True, \
        "12-month window must carry the slow-fetch warning"
    assert body["config"]["available_periods"] == list(RETENTION_PERIODS_MONTHS)
    assert body["config"]["available_actions"] == list(RETENTION_ACTIONS)


def test_get_retention_no_slow_warning_for_short_periods(client):
    client.put("/api/v1/settings", json={"retention_period_months": "3"})
    r = client.get("/api/v1/settings/retention")
    assert r.json()["config"]["slow_fetch_warning"] is False


def test_get_retention_includes_live_payload_stats(client):
    r = client.get("/api/v1/settings/retention")
    stats = r.json()["stats"]
    assert stats["live_payloads"] is not None
    assert "row_count" in stats["live_payloads"]
    assert "approx_bytes" in stats["live_payloads"]


def test_get_retention_archive_stats_only_present_in_archive_mode(client):
    client.put("/api/v1/settings", json={"retention_action": "delete"})
    r = client.get("/api/v1/settings/retention")
    assert r.json()["stats"]["archive"] is None, \
        "archive stats must be absent (not just empty) when action=delete"

    client.put("/api/v1/settings", json={"retention_action": "archive"})
    r2 = client.get("/api/v1/settings/retention")
    assert r2.json()["stats"]["archive"] is not None
    assert "path" in r2.json()["stats"]["archive"]
