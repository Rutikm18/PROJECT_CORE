"""
manager/tests/integration/test_org_name_lock.py — the organization name is set
once from the dashboard and then locked: further dashboard PUTs cannot change it,
GET advertises the lock, and only the server-side set_org_name command can change
it afterwards.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.settings import make_settings_router
from manager.manager.indexer import IntelDB
from manager.manager.scripts import set_org_name


@pytest.fixture()
async def client_and_db(pg_intel_dsn):
    # httpx + ASGITransport runs the app in THIS event loop, so the IntelDB pool
    # (created here) and the request handlers share a loop — TestClient would run
    # them in a separate loop and asyncpg connections are loop-bound.
    intel = IntelDB(pg_intel_dsn)
    await intel.init()
    app = FastAPI()
    app.include_router(make_settings_router(intel), prefix="/settings")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        yield client, intel
    await intel.close()


async def _get(client) -> dict:
    return (await client.get("/settings")).json()


async def test_org_name_sets_once_then_locks(client_and_db):
    client, _intel = client_and_db

    # Unset → not locked, editable.
    assert (await _get(client))["org_name_locked"] is False

    # First set from the dashboard succeeds and locks.
    r = await client.put("/settings", json={"org_name": "Acme Security"})
    assert r.status_code == 200
    body = r.json()
    assert body["org_name_locked"] is True
    assert body["settings"]["org_name"] == "Acme Security"
    assert body["locked"] == []

    # A different value from the dashboard is refused and reported, not applied.
    r = await client.put("/settings", json={"org_name": "Evil Corp"})
    assert r.status_code == 200
    body = r.json()
    assert body["locked"] == ["org_name"]
    assert body["settings"]["org_name"] == "Acme Security"

    # GET still shows the locked original.
    got = await _get(client)
    assert got["org_name_locked"] is True
    assert got["settings"]["org_name"] == "Acme Security"


async def test_other_fields_still_save_when_org_name_is_locked(client_and_db):
    client, _intel = client_and_db
    await client.put("/settings", json={"org_name": "Acme Security"})

    # A locked org_name alongside an editable field: the field saves, org_name doesn't.
    r = await client.put("/settings", json={"org_name": "Nope", "org_location": "Berlin"})
    assert r.status_code == 200
    body = r.json()
    assert body["locked"] == ["org_name"]
    assert body["settings"]["org_location"] == "Berlin"
    assert body["settings"]["org_name"] == "Acme Security"


async def test_server_command_can_change_the_locked_name(client_and_db):
    client, intel = client_and_db
    await client.put("/settings", json={"org_name": "Acme Security"})

    old = await set_org_name.apply_org_name(intel, "Renamed Corp")
    assert old == "Acme Security"

    got = await _get(client)
    assert got["settings"]["org_name"] == "Renamed Corp"
    assert got["org_name_locked"] is True   # still locked to the dashboard
