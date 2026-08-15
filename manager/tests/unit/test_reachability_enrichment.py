"""
Tests for payload-backed reachability enrichment (attacklens/reachability.py)
and its wiring into the legacy terrain-validation path.

These pin the accuracy fix: Origin `package_running` / `service_reachable` must
resolve from the raw processes/ports *inventory*, not the findings table, and
must degrade to a no-op (never raise) when the manager DB handle is absent.
"""
from __future__ import annotations

import pytest

from manager.manager.attacklens import reachability as rb
from manager.manager.attacklens.engine import AttackLensEngine


class _FakeManagerDB:
    """Minimal manager-DB stub exposing query_section over canned payloads."""

    def __init__(self, processes=None, ports=None):
        self._sections = {"processes": processes or [], "ports": ports or []}
        self.calls = 0

    async def query_section(self, agent_id, section, limit=1):
        self.calls += 1
        data = self._sections.get(section)
        if not data:
            return []
        return [{"collected_at": 1, "received_at": 1, "data": data}]


@pytest.fixture(autouse=True)
def _clear_cache():
    rb._reset_cache_for_tests()
    yield
    rb._reset_cache_for_tests()


# ── Context building + matching ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_package_running_matches_process_inventory():
    db = _FakeManagerDB(processes=[{"name": "nginx", "pid": 10},
                                    {"name": "python3.11", "pid": 20}])
    ctx = await rb.load_reachability(db, "agent-a")
    assert ctx.loaded is True
    assert ctx.package_running("nginx") is True
    assert ctx.package_running("python@3.11") is True   # version-suffix normalised
    assert ctx.package_running("redis") is False


@pytest.mark.asyncio
async def test_port_open_is_scoped_to_owning_process_and_external():
    db = _FakeManagerDB(
        processes=[{"name": "nginx"}],
        ports=[
            {"port": 443, "bind_addr": "0.0.0.0", "process": "nginx"},
            {"port": 5432, "bind_addr": "127.0.0.1", "process": "postgres"},
        ],
    )
    ctx = await rb.load_reachability(db, "agent-a")
    # nginx listens on a public bind → reachable
    assert ctx.package_port_open("nginx") is True
    # postgres only listens on loopback → not externally reachable
    assert ctx.package_port_open("postgres") is False
    # a package with no listener of its own → not reachable
    assert ctx.package_port_open("openssl") is False
    assert ctx.any_external_listener() is True


@pytest.mark.asyncio
async def test_scoped_npm_and_lib_prefix_normalisation():
    db = _FakeManagerDB(processes=[{"name": "esbuild"}, {"path": "/usr/lib/libssl.so"}])
    ctx = await rb.load_reachability(db, "agent-a")
    assert ctx.package_running("@scope/esbuild") is True
    assert ctx.package_running("libssl") is True          # lib-prefix + basename


@pytest.mark.asyncio
async def test_short_token_does_not_overmatch():
    # 'go' is below the min-token floor → must not match 'mongod'.
    db = _FakeManagerDB(processes=[{"name": "mongod"}])
    ctx = await rb.load_reachability(db, "agent-a")
    assert ctx.package_running("go") is False


def test_external_bind_detection():
    assert rb._external_bind("0.0.0.0") is True
    assert rb._external_bind("::") is True
    assert rb._external_bind("127.0.0.1") is False
    assert rb._external_bind("::1") is False
    assert rb._external_bind("") is True                  # unknown → fail-open


# ── Graceful degradation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_absent_manager_db_returns_empty_context():
    ctx = await rb.load_reachability(None, "agent-a")
    assert ctx.loaded is False
    assert ctx.package_running("nginx") is False


@pytest.mark.asyncio
async def test_handle_without_query_section_is_safe():
    ctx = await rb.load_reachability(object(), "agent-a")
    assert ctx.loaded is False


@pytest.mark.asyncio
async def test_ttl_cache_avoids_repeat_queries():
    db = _FakeManagerDB(processes=[{"name": "nginx"}])
    await rb.load_reachability(db, "agent-a")
    await rb.load_reachability(db, "agent-a")
    # Two sections on the first call only; the second is served from cache.
    assert db.calls == 2


# ── Wiring: legacy terrain path consumes payload reachability ────────────────

class _CaptureIDB:
    async def upsert_finding(self, finding, _ts):
        return "unchanged"

    async def _fetchall(self, _query, _args):
        return []                                          # no sibling findings

    async def get_asset_tier(self, _agent_id):
        return "endpoint"


class _NoFeeds:
    @staticmethod
    def is_kev_cve(_cve_id):
        return False


@pytest.mark.asyncio
async def test_legacy_precision_uses_payload_reachability(monkeypatch):
    async def _threshold(_idb, _agent_id, _category):
        return 0.75

    monkeypatch.setattr(
        "manager.manager.attacklens.engine.resolve_threshold", _threshold,
    )

    engine = object.__new__(AttackLensEngine)
    engine._idb = _CaptureIDB()
    engine._feeds = _NoFeeds()
    engine._db = _FakeManagerDB(
        processes=[{"name": "nginx"}],
        ports=[{"port": 443, "bind_addr": "0.0.0.0", "process": "nginx"}],
    )

    finding = {
        "agent_id": "agent-a",
        "category": "package",
        "source": "S-PKG-001",
        "rule_id": "S-PKG-001",
        "severity": "high",
        "score": 7.0,
        "cve_ids": ["CVE-2024-0001"],
        "evidence": {"name": "nginx", "cve_id": "CVE-2024-0001"},
    }

    await engine._attach_legacy_precision(finding)

    crit = {c["name"]: c for c in finding["terrain_validation"]["criteria"]}
    assert crit["package_running"]["status"] == "met"
    assert crit["service_reachable"]["status"] == "met"


@pytest.mark.asyncio
async def test_legacy_precision_no_manager_db_is_safe(monkeypatch):
    async def _threshold(_idb, _agent_id, _category):
        return 0.75

    monkeypatch.setattr(
        "manager.manager.attacklens.engine.resolve_threshold", _threshold,
    )
    engine = object.__new__(AttackLensEngine)
    engine._idb = _CaptureIDB()
    engine._feeds = _NoFeeds()
    # No engine._db attribute at all — must not raise.
    finding = {
        "agent_id": "agent-a",
        "category": "package",
        "source": "S-PKG-001",
        "rule_id": "S-PKG-001",
        "severity": "high",
        "score": 7.0,
        "evidence": {"name": "nginx"},
    }
    await engine._attach_legacy_precision(finding)
    crit = {c["name"]: c for c in finding["terrain_validation"]["criteria"]}
    assert crit["package_running"]["status"] == "not_met"
