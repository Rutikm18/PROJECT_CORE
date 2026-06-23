"""
manager/tests/unit/test_user_account_fp.py — user_account FP tuning.

Two false-positive fixes are pinned here:
  1. First-run seeding — on the first snapshot every pre-existing account is
     recorded as baseline and NOT alerted (no enrollment "new account" storm).
  2. Risk-tiered severity — a new account's severity tracks real risk:
     service/daemon → info, interactive → high, root/privileged login → critical
     (was blanket CRITICAL for everything).
"""
from __future__ import annotations

import asyncio

from manager.manager.attacklens.detections import user_account as ua


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


class _FakeDB:
    def __init__(self):
        self._state: dict = {}

    async def get_entity_state(self, agent_id, module, key):
        return self._state.get((agent_id, module, key))

    async def set_entity_state(self, agent_id, module, key, value, ts):
        self._state[(agent_id, module, key)] = value


def _user(name, uid, shell, groups=None, home="/home/x"):
    return {"username": name, "uid": uid, "gid": uid, "shell": shell,
            "home": home, "groups": groups or [], "raw": {"u": name}}


def setup_function(_):
    # Module-level dedup/rate caches must not leak across tests.
    ua._dedup_cache.clear()
    ua._rate_counter.clear()


# ── First-run seeding ────────────────────────────────────────────────────────

def test_first_run_seeds_baseline_without_alerting():
    db = _FakeDB()
    existing = [
        _user("root", 0, "/bin/bash", ["wheel"]),
        _user("_spotlight", 89, "/usr/bin/false"),
        _user("alice", 501, "/bin/zsh"),
    ]
    findings = _run(ua.detect_new_account("a1", existing, db))
    assert findings == [], "first observation must not alert on pre-existing accounts"


def test_genuinely_new_interactive_account_is_high():
    db = _FakeDB()
    base = [_user("root", 0, "/bin/bash", ["wheel"]), _user("alice", 501, "/bin/zsh")]
    _run(ua.detect_new_account("a1", base, db))            # seed
    # Next snapshot adds a new login user.
    findings = _run(ua.detect_new_account("a1", base + [_user("bob", 1002, "/bin/bash")], db))
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["username"] == "bob"


def test_new_service_account_is_info_not_critical():
    db = _FakeDB()
    base = [_user("alice", 501, "/bin/zsh")]
    _run(ua.detect_new_account("a1", base, db))            # seed
    findings = _run(ua.detect_new_account(
        "a1", base + [_user("_helperd", 250, "/usr/bin/false")], db))
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"   # installer noise, not an incident


def test_new_uid0_clone_is_critical():
    db = _FakeDB()
    base = [_user("root", 0, "/bin/bash", ["wheel"]), _user("alice", 501, "/bin/zsh")]
    _run(ua.detect_new_account("a1", base, db))            # seed
    findings = _run(ua.detect_new_account(
        "a1", base + [_user("backdoor", 0, "/bin/bash")], db))
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


# ── Pure severity tiering ─────────────────────────────────────────────────────

def test_severity_tiers():
    assert ua._new_account_severity(_user("x", 0, "/bin/bash")) == "critical"
    assert ua._new_account_severity(_user("adm", 1500, "/bin/bash", ["sudo"])) == "critical"
    assert ua._new_account_severity(_user("u", 1500, "/bin/zsh")) == "high"
    assert ua._new_account_severity(_user("_d", 200, "/usr/bin/false")) == "info"
    # nologin → service account regardless of UID → info (correct)
    assert ua._new_account_severity(_user("svc", 1500, "/sbin/nologin")) == "info"
    # non-system UID with a blank/non-interactive shell → medium (edge)
    assert ua._new_account_severity(_user("weird", 1500, "")) == "medium"


def test_is_system_account():
    assert ua._is_system_account(_user("_mdns", 65, "/usr/bin/false")) is True
    assert ua._is_system_account(_user("daemon", 1, "/usr/sbin/nologin")) is True
    assert ua._is_system_account(_user("alice", 501, "/bin/zsh")) is False
