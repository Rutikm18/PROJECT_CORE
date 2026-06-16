"""
agent/tests/unit/test_config_engine.py — ConfigEngine substrate behaviour.

Covers: merge (policy wins over baseline), the fail-closed `response_enabled`
matrix (every non-ideal condition ⇒ False), tighten-only env overrides (can
disable/shrink, never enable/add), downgrade rejection + high-water persistence
across a restart, offline-start-from-cache then refresh-on-reconnect, atomic
hot-reload under concurrent readers (no torn snapshot), and clock-skew forcing
fail-closed.

All hermetic: a fake transport serves wire objects from the signing fixture; a
fake clock drives skew tests. The real pinned key is never used.
"""
from __future__ import annotations

import threading

import pytest

from agent.agent.config_engine import (
    ConfigEngine,
    PathProvider,
    RuntimeConfig,
    SystemClock,
    TransportUnreachable,
)
from agent.tests.fixtures.signing import make_policy, make_trust

AGENT_ID = "mac-engine-001"
GROUPS = ["canary"]


# ── Test doubles ─────────────────────────────────────────────────────────────

class FakeTransport:
    """Serves a wire object per policy type; can simulate unreachability."""

    def __init__(self):
        self.policies: dict[str, dict] = {}
        self.unreachable = False
        self.fetches = 0

    def set(self, typ: str, wire: dict | None):
        if wire is None:
            self.policies.pop(typ, None)
        else:
            self.policies[typ] = wire

    def fetch(self, policy_type: str):
        self.fetches += 1
        if self.unreachable:
            raise TransportUnreachable("offline")
        return self.policies.get(policy_type)


class FakeClock:
    def __init__(self, wall=None, mono=10_000.0):
        import time as _t
        self._wall = _t.time() if wall is None else wall
        self._mono = mono

    def wall(self):
        return self._wall

    def monotonic(self):
        return self._mono

    def advance(self, *, wall=0.0, mono=0.0):
        self._wall += wall
        self._mono += mono


def _engine(tmp_path, transport, *, clock=None, trust=None,
            agent_id=AGENT_ID, group_ids=GROUPS, base=None):
    base = base or PathProvider(base=str(tmp_path))
    return ConfigEngine(
        paths=base,
        trust=trust or make_trust(),
        transport=transport,
        agent_id=agent_id,
        group_ids=group_ids,
        clock=clock or SystemClock(),
        refresh_interval_sec=21600,
    )


def _baseline(tmp_path, toml_text: str):
    (tmp_path / "agent.toml").write_text(toml_text)


# ── Merge ─────────────────────────────────────────────────────────────────────

def test_first_run_no_cache_baseline_only(tmp_path):
    _baseline(tmp_path, '[security]\nthreshold = 10\n')
    eng = _engine(tmp_path, FakeTransport())
    cfg = eng.load()
    assert isinstance(cfg, RuntimeConfig)
    assert cfg.section("security")["threshold"] == 10
    assert cfg.response_enabled is False           # no response policy
    assert dict(cfg.policy_versions) == {}


def test_policy_content_merges_over_baseline(tmp_path):
    _baseline(tmp_path, '[security]\nthreshold = 10\nkeep = "me"\n')
    tr = FakeTransport()
    tr.set("security", make_policy("security", 1, {"threshold": 99}))
    eng = _engine(tmp_path, tr)
    eng.load()
    eng.refresh()
    cfg = eng.current()
    assert cfg.section("security")["threshold"] == 99   # policy wins
    assert cfg.section("security")["keep"] == "me"       # baseline preserved
    assert cfg.policy_versions["security"] == 1


def test_runtime_config_maps_are_immutable(tmp_path):
    tr = FakeTransport()
    tr.set("security", make_policy("security", 1, {"a": {"b": 1}}))
    eng = _engine(tmp_path, tr)
    eng.load()
    eng.refresh()
    cfg = eng.current()
    with pytest.raises(TypeError):
        cfg.sections["security"]["a"]["b"] = 2          # nested frozen


# ── Fail-closed response matrix ───────────────────────────────────────────────

def _resp(version=1, **content):
    return make_policy("response", version, {"allowed_actions": ["isolate"],
                                             **content})


def test_response_enabled_true_only_with_valid_policy(tmp_path):
    tr = FakeTransport()
    tr.set("response", _resp())
    eng = _engine(tmp_path, tr)
    eng.load()
    eng.refresh()
    assert eng.current().response_enabled is True


@pytest.mark.parametrize("mutate", [
    "missing",       # no response policy at all
    "expired",
    "unverifiable",
    "wrong_audience",
    "key_absent",
])
def test_response_fails_closed_under_every_bad_condition(tmp_path, mutate):
    tr = FakeTransport()
    trust = make_trust()
    if mutate == "missing":
        pass
    elif mutate == "expired":
        import time
        tr.set("response", make_policy(
            "response", 1, {"allowed_actions": ["isolate"]},
            issued_at=int(time.time()) - 10_000, ttl=100))
    elif mutate == "unverifiable":
        tr.set("response", make_policy(
            "response", 1, {"allowed_actions": ["isolate"]}, tamper="signature"))
    elif mutate == "wrong_audience":
        tr.set("response", make_policy(
            "response", 1, {"allowed_actions": ["isolate"]}, audience="prod"))
    elif mutate == "key_absent":
        tr.set("response", make_policy(
            "response", 1, {"allowed_actions": ["isolate"]}, key_id="ghost"))
    eng = _engine(tmp_path, tr, trust=trust)
    eng.load()
    eng.refresh()
    assert eng.current().response_enabled is False


def test_baseline_cannot_enable_response(tmp_path):
    # Even if baseline screams response_enabled=true, it is ignored.
    _baseline(tmp_path, '[response]\nresponse_enabled = true\nenabled = true\n')
    eng = _engine(tmp_path, FakeTransport())
    eng.load()
    assert eng.current().response_enabled is False


# ── Tighten-only env overrides ────────────────────────────────────────────────

def test_env_can_disable_but_not_enable_response(tmp_path, monkeypatch):
    tr = FakeTransport()
    tr.set("response", _resp())
    eng = _engine(tmp_path, tr)
    eng.load(); eng.refresh()
    assert eng.current().response_enabled is True

    monkeypatch.setenv("ATTACKLENS_RESPONSE_ENABLED", "false")
    eng.refresh()
    assert eng.current().response_enabled is False      # tighten honoured


def test_env_true_cannot_enable_without_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKLENS_RESPONSE_ENABLED", "true")
    eng = _engine(tmp_path, FakeTransport())   # no response policy
    eng.load()
    assert eng.current().response_enabled is False      # loosening ignored


def test_env_can_shrink_but_not_add_actions(tmp_path, monkeypatch):
    tr = FakeTransport()
    tr.set("response", make_policy("response", 1,
                                   {"allowed_actions": ["isolate", "kill", "quarantine"]}))
    monkeypatch.setenv("ATTACKLENS_RESPONSE_ALLOWED_ACTIONS", "isolate,reboot")
    eng = _engine(tmp_path, tr)
    eng.load(); eng.refresh()
    actions = list(eng.current().section("response")["allowed_actions"])
    assert actions == ["isolate"]            # only the intersection survives; "reboot" not added


# ── Downgrade + high-water persistence across restart ────────────────────────

def test_downgrade_rejected_and_high_water_persists(tmp_path):
    tr = FakeTransport()
    tr.set("security", make_policy("security", 5, {"threshold": 5}))
    eng = _engine(tmp_path, tr)
    eng.load()
    r = eng.refresh()
    assert r["security"] == "accepted"
    assert eng.current().policy_versions["security"] == 5

    # Manager replays an older validly-signed version → downgrade.
    tr.set("security", make_policy("security", 3, {"threshold": 999}))
    r2 = eng.refresh()
    assert r2["security"] == "rejected:downgrade"
    assert eng.current().section("security")["threshold"] == 5   # kept v5

    # Simulate a process restart: new engine, same dirs. High-water persisted,
    # cache replayed, and the same downgrade is still rejected.
    eng2 = _engine(tmp_path, tr)
    eng2.load()
    assert eng2.current().policy_versions["security"] == 5
    r3 = eng2.refresh()
    assert r3["security"] == "rejected:downgrade"


# ── Offline start + reconnect ─────────────────────────────────────────────────

def test_offline_start_from_cache_then_refresh_on_reconnect(tmp_path):
    # Prime a cache with a good policy via a first online engine.
    tr = FakeTransport()
    tr.set("security", make_policy("security", 2, {"threshold": 7}))
    primer = _engine(tmp_path, tr)
    primer.load(); primer.refresh()
    assert primer.current().policy_versions["security"] == 2

    # New engine, manager offline at startup: load() is cache-first + non-blocking.
    tr.unreachable = True
    eng = _engine(tmp_path, tr)
    cfg = eng.load()
    assert cfg.section("security")["threshold"] == 7      # served from cache
    assert cfg.policy_versions["security"] == 2

    # Refresh while offline is non-fatal — last good kept.
    r = eng.refresh()
    assert r["security"] == "unreachable"
    assert eng.current().section("security")["threshold"] == 7

    # Reconnect with a newer policy → accepted.
    tr.unreachable = False
    tr.set("security", make_policy("security", 3, {"threshold": 8}))
    eng.on_reconnect()
    assert eng.current().policy_versions["security"] == 3
    assert eng.current().section("security")["threshold"] == 8


def test_corrupt_cache_treated_as_absent(tmp_path):
    # Write garbage into the cache file; load() must not crash and must fall back.
    pol_dir = tmp_path / "policies"
    pol_dir.mkdir(exist_ok=True)
    (pol_dir / "security.policy").write_bytes(b"{not json")
    eng = _engine(tmp_path, FakeTransport())
    cfg = eng.load()
    assert cfg.policy_versions == {} or "security" not in cfg.policy_versions


# ── Clock skew ────────────────────────────────────────────────────────────────

def test_clock_skew_forces_fail_closed(tmp_path):
    clock = FakeClock()
    tr = FakeTransport()
    tr.set("response", _resp())
    eng = _engine(tmp_path, tr, clock=clock)
    eng.load(); eng.refresh()
    assert eng.current().response_enabled is True

    # Wall jumps backward far beyond skew while monotonic advances normally.
    clock.advance(mono=100.0, wall=-10_000.0)
    eng.refresh()
    assert eng.current().response_enabled is False


# ── Atomic hot-reload under concurrent readers ───────────────────────────────

def test_hot_reload_no_torn_snapshot(tmp_path):
    tr = FakeTransport()
    tr.set("security", make_policy("security", 1, {"threshold": 1}))
    eng = _engine(tmp_path, tr)
    eng.load(); eng.refresh()

    stop = threading.Event()
    seen_bad = []

    def reader():
        import time as _t
        while not stop.is_set():
            cfg = eng.current()
            v = cfg.policy_versions.get("security")
            t = cfg.section("security").get("threshold")
            # Invariant: version N always pairs with threshold N (written together).
            if v is not None and v != t:
                seen_bad.append((v, t))
            _t.sleep(0)   # yield so the writer thread isn't GIL-starved

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for th in threads:
        th.start()

    for version in range(2, 60):
        tr.set("security", make_policy("security", version, {"threshold": version}))
        eng.refresh()

    stop.set()
    for th in threads:
        th.join()

    assert not seen_bad, f"torn snapshot(s) observed: {seen_bad[:5]}"
