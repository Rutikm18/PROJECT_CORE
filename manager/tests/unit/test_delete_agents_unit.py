"""
manager/tests/unit/test_delete_agents_unit.py — no-database tests for the
delete-agents command: the cascade table lists stay complete as the schema
grows, the CLI argument parsing is correct, and the orchestration deletes the
right agents (and nothing on --dry-run).
"""
from __future__ import annotations

import argparse
import asyncio
import re

import pytest

from manager.manager import db as db_mod
from manager.manager import indexer as indexer_mod
from manager.manager.scripts import delete_agents as da

# ── The cascade lists must cover every agent_id table ────────────────────────

def _agent_id_tables(path: str) -> set[str]:
    """Every table in a source file with its own agent_id COLUMN (not just an FK
    reference to one)."""
    text = open(path).read()
    found: set[str] = set()
    for name, body in re.findall(
        r"CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\((.*?)\n\s*\)\s*[;\"]", text, re.S
    ):
        for line in body.splitlines():
            if re.match(r"agent_id\s+\w", line.strip()):   # a column def, not FOREIGN KEY(agent_id)
                found.add(name)
                break
    return found


def test_manager_db_cascade_list_matches_schema():
    schema = _agent_id_tables("manager/manager/db.py")
    # detection_event_chunks FK-cascades from detection_events; nonce_cache has no
    # agent_id — so the schema set is exactly AGENT_SCOPED_TABLES.
    assert schema == set(db_mod.AGENT_SCOPED_TABLES)


def test_intel_db_cascade_list_matches_schema():
    schema = _agent_id_tables("manager/manager/indexer.py")
    assert schema == set(indexer_mod.INTEL_AGENT_SCOPED_TABLES)


def test_agents_table_is_deleted_last():
    # agents is the parent of payloads (RESTRICT FK), so it must be removed last.
    assert db_mod.AGENT_SCOPED_TABLES[-1] == "agents"


# ── CLI parsing ──────────────────────────────────────────────────────────────

def test_parse_ids_splits_and_dedupes_in_order():
    assert da._parse_ids(["a,b", "c d", " a "]) == ["a", "b", "c", "d"]


@pytest.mark.parametrize("spec,seconds", [
    ("30d", 30 * 86400),
    ("12h", 12 * 3600),
    ("45m", 45 * 60),
    ("90s", 90),
    ("7",   7 * 86400),      # bare number means days
    ("0",   0),
])
def test_parse_age_seconds(spec, seconds):
    assert da._parse_age_seconds(spec) == seconds


@pytest.mark.parametrize("bad", ["", "-5d", "xd", "  "])
def test_parse_age_seconds_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        da._parse_age_seconds(bad)


def test_resolve_dsns_from_base_url(monkeypatch):
    monkeypatch.delenv("MANAGER_DATABASE_URL", raising=False)
    monkeypatch.delenv("INTEL_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h:5432/")
    assert da._resolve_dsns() == (
        "postgresql://u:p@h:5432/manager",
        "postgresql://u:p@h:5432/intel",
    )


def test_resolve_dsns_honours_explicit_overrides(monkeypatch):
    monkeypatch.setenv("MANAGER_DATABASE_URL", "postgresql://x/mgr")
    monkeypatch.setenv("INTEL_DATABASE_URL", "postgresql://x/int")
    assert da._resolve_dsns() == ("postgresql://x/mgr", "postgresql://x/int")


# ── Orchestration (fake databases) ───────────────────────────────────────────

class _FakeDB:
    instances: list[_FakeDB] = []

    def __init__(self, _dsn):
        self.deleted: list[str] = []
        _FakeDB.instances.append(self)

    async def init(self): ...
    async def close(self): ...
    async def agent_exists(self, agent_id):
        return agent_id in {"a", "b", "old-1"}
    async def agent_ids_seen_before(self, _cutoff):
        return ["old-1"]
    async def delete_agent(self, agent_id):
        self.deleted.append(agent_id)
        return {"agents": 1, "payloads": 3}


class _FakeIntel:
    instances: list[_FakeIntel] = []

    def __init__(self, _dsn):
        self.deleted: list[str] = []
        _FakeIntel.instances.append(self)

    async def init(self): ...
    async def close(self): ...
    async def delete_agent(self, agent_id):
        self.deleted.append(agent_id)
        return {"findings": 2}


@pytest.fixture()
def fakes(monkeypatch):
    _FakeDB.instances.clear()
    _FakeIntel.instances.clear()
    monkeypatch.setattr(da, "Database", _FakeDB)
    monkeypatch.setattr(da, "IntelDB", _FakeIntel)
    monkeypatch.setattr(da, "_resolve_dsns", lambda: ("m", "i"))
    return _FakeDB, _FakeIntel


def _run(**kw):
    args = argparse.Namespace(
        agents=kw.get("agents"), older_than=kw.get("older_than"),
        dry_run=kw.get("dry_run", False), yes=kw.get("yes", True),
    )
    return asyncio.run(da._run(args))


def test_deletes_explicit_ids(fakes):
    FakeDB, FakeIntel = fakes
    rc = _run(agents=["a b"])
    assert rc == 0
    assert FakeDB.instances[0].deleted == ["a", "b"]
    assert FakeIntel.instances[0].deleted == ["a", "b"]


def test_age_selection_adds_old_agents(fakes):
    FakeDB, _ = fakes
    _run(older_than="30d")
    assert FakeDB.instances[0].deleted == ["old-1"]


def test_dry_run_deletes_nothing(fakes):
    FakeDB, FakeIntel = fakes
    rc = _run(agents=["a"], dry_run=True)
    assert rc == 0
    assert FakeDB.instances[0].deleted == []
    assert FakeIntel.instances[0].deleted == []


def test_unknown_agent_is_skipped_not_deleted(fakes):
    FakeDB, _ = fakes
    _run(agents=["a ghost"])
    assert FakeDB.instances[0].deleted == ["a"]   # ghost fails agent_exists


def test_no_selectors_is_an_error(fakes):
    assert _run(agents=None, older_than=None) == 2
