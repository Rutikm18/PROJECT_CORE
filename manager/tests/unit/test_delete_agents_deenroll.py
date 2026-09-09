import argparse

import pytest

from manager.manager.scripts import delete_agents as da


class FakeDB:
    def __init__(self, events):
        self.events = events

    async def init(self):
        pass

    async def close(self):
        pass

    async def agent_exists(self, aid):
        return True

    async def revoke_key(self, aid):
        self.events.append(("revoke", aid))
        return True

    async def delete_agent(self, aid):
        self.events.append(("delete", aid))
        return {"agents": 1}

    async def count_agent_rows(self, aid):
        return {}


class FakeIntel:
    def __init__(self, events):
        self.events = events

    async def init(self):
        pass

    async def close(self):
        pass

    async def delete_agent(self, aid):
        self.events.append(("intel_delete", aid))
        return {}

    async def count_agent_rows(self, aid):
        return {}


@pytest.mark.asyncio
async def test_deenroll_precedes_delete(monkeypatch):
    events: list[tuple[str, str]] = []
    monkeypatch.setattr(da, "_resolve_dsns", lambda: ("db", "intel"))
    monkeypatch.setattr(da, "Database", lambda *_a, **_k: FakeDB(events))
    monkeypatch.setattr(da, "IntelDB", lambda *_a, **_k: FakeIntel(events))
    monkeypatch.setattr(da, "DRAIN_SECONDS", 0)

    args = argparse.Namespace(
        list=False, all=False, agents=["ag1"], older_than=None, dry_run=False, yes=True,
    )
    rc = await da._run(args)

    assert rc == 0
    # The agent is revoked (de-enrolled) before it is deleted.
    assert events.index(("revoke", "ag1")) < events.index(("delete", "ag1"))


@pytest.mark.asyncio
async def test_dry_run_does_not_revoke(monkeypatch):
    events: list[tuple[str, str]] = []
    monkeypatch.setattr(da, "_resolve_dsns", lambda: ("db", "intel"))
    monkeypatch.setattr(da, "Database", lambda *_a, **_k: FakeDB(events))
    monkeypatch.setattr(da, "IntelDB", lambda *_a, **_k: FakeIntel(events))
    monkeypatch.setattr(da, "DRAIN_SECONDS", 0)

    args = argparse.Namespace(
        list=False, all=False, agents=["ag1"], older_than=None, dry_run=True, yes=True,
    )
    rc = await da._run(args)

    assert rc == 0
    assert not any(e[0] == "revoke" for e in events)  # dry-run never de-enrolls
    assert not any(e[0] == "delete" for e in events)
