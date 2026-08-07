"""
agent/tests/unit/test_section_merge.py — orchestrator merges default sections.

Regression test for the "newly-shipped section never collected" bug.

`Orchestrator._sections()` used to be all-or-nothing: if the operator's
agent.toml had ANY [collection.sections] block, the built-in _DEFAULT_SECTIONS
were ignored entirely. A section added to a newer agent build (e.g.
developer_security) was therefore never scheduled on any agent whose config
predated it — the config had to be hand-edited or the pkg reinstalled.

The fix merges defaults with config: the operator's explicit blocks stay
authoritative (including `enabled = false` to opt out), and any default section
with a registered collector on THIS platform that the config doesn't mention is
added so it rolls out on a binary update alone.
"""
from __future__ import annotations

import queue

from agent.agent.core import Orchestrator, _DEFAULT_SECTIONS, COLLECTORS


def _orch(sections: dict) -> Orchestrator:
    cfg = {
        "agent": {"id": "mac-001", "name": "t"},
        "manager": {"url": "http://127.0.0.1:8080", "max_queue_size": 100},
        "collection": {"tick_sec": 5, "sections": sections},
    }
    return Orchestrator(cfg, b"0" * 32, b"0" * 32, queue.Queue())


def test_empty_config_uses_builtin_defaults():
    cfg = {
        "agent": {"id": "mac-001", "name": "t"},
        "manager": {"url": "http://127.0.0.1:8080", "max_queue_size": 100},
        "collection": {"tick_sec": 5},   # no [collection.sections] at all
    }
    orch = Orchestrator(cfg, b"0" * 32, b"0" * 32, queue.Queue())
    assert orch._sections() == _DEFAULT_SECTIONS


def test_missing_default_section_is_merged_in():
    # A config that lists only `metrics` must still schedule the other default
    # sections whose collector is registered — otherwise a newly-shipped section
    # never rolls out to agents with a pre-existing config.
    orch = _orch({"metrics": {"interval_sec": 30, "enabled": True}})
    sections = orch._sections()

    # Explicit operator block wins over the default (30s, not the 60s default).
    assert sections["metrics"]["interval_sec"] == 30

    # Every default section with a collector on this platform is present even
    # though the config omitted it.
    expected_added = [n for n in _DEFAULT_SECTIONS if n in COLLECTORS and n != "metrics"]
    assert expected_added, "test precondition: some default sections have collectors"
    for name in expected_added:
        assert name in sections, f"{name} should be merged in from defaults"


def test_explicit_disable_is_respected_over_default():
    # An operator who disables a section the default enables must stay disabled.
    orch = _orch({
        "metrics":   {"interval_sec": 60, "enabled": True},
        "processes": {"interval_sec": 60, "enabled": False},
    })
    sections = orch._sections()
    assert sections["processes"]["enabled"] is False


def test_only_sections_with_registered_collectors_are_added():
    # Merged-in defaults must have a runnable collector; nothing is scheduled for
    # a section this platform's registry can't collect.
    orch = _orch({"metrics": {"interval_sec": 60, "enabled": True}})
    for name in orch._sections():
        # config-supplied names are allowed through untouched; merged defaults
        # must be backed by a collector.
        if name in _DEFAULT_SECTIONS and name != "metrics":
            assert name in COLLECTORS
