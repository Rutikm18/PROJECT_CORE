"""
manager/tests/unit/test_detection_coverage.py — every telemetry category is
analyzed, the previously-dormant modules are wired, and new-mount detection fires.

Runs WITHOUT Postgres: the section→detector coverage is a pure-map assertion, and
mount_monitor is exercised against an in-memory FakeDB (the entity_state API it
uses). The rich modules' deep behavior is covered by their own suites +
test_engine_module_routing (Postgres); here we lock down wiring + coverage.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest

from manager.manager.attacklens.engine import _DETECTION_MODULE_ROUTES
from manager.manager.attacklens.detections import mount_monitor


# The 24 telemetry categories the agent ships (23 sections + agent_health).
ALL_SECTIONS = {
    "metrics", "connections", "processes", "ports", "network", "arp", "mounts",
    "battery", "openfiles", "services", "users", "hardware", "containers",
    "storage", "tasks", "security", "sysctl", "configs", "sca", "apps",
    "packages", "binaries", "sbom", "agent_health",
}

# Sections intentionally covered ONLY by the universal rulepack + behavioral
# (low security-signal inventory/health telemetry — no dedicated module needed):
#   battery, hardware, sca, agent_health, metrics, openfiles.
# They still pass through _dispatch + rulepack; they just don't require a rich
# module route the way the high-signal sections below do.


def _routed_modules() -> set[str]:
    # Each module exports `analyze` (aliased on import), so __name__ is always
    # "analyze"; identify the source module via __module__ instead.
    return {fn.__module__.rsplit(".", 1)[-1]
            for fns in _DETECTION_MODULE_ROUTES.values() for fn in fns}


def test_previously_dormant_modules_are_now_routed():
    """The 11 modules that had 0 references must now be wired into a route."""
    routed = _routed_modules()
    for mod in [
        "lateral_movement", "exfiltration", "covert_channel", "persistence",
        "service_monitor", "scheduled_task", "privilege_escalation",
        "binary_integrity", "defense_evasion", "app_vulnerability",
        "package_vulnerability", "mount_monitor",
    ]:
        assert mod in routed, f"{mod} is imported but never routed (dead code)"


def test_key_security_sections_have_a_rich_module():
    """The high-signal sections must route to at least one detection module."""
    must_route = {
        "connections", "network", "processes", "services", "tasks", "configs",
        "binaries", "security", "sysctl", "apps", "packages", "users", "ports",
        "arp", "containers", "sbom", "mounts", "storage",
    }
    for s in must_route:
        assert _DETECTION_MODULE_ROUTES.get(s), f"section '{s}' has no rich detector route"


def test_new_connection_and_new_binary_have_dedicated_detectors():
    """The user-named examples: a new connection and a new binary must be analyzed."""
    conn = {fn.__module__.rsplit(".", 1)[-1] for fn in _DETECTION_MODULE_ROUTES["connections"]}
    assert "lateral_movement" in conn and "exfiltration" in conn
    bins = {fn.__module__.rsplit(".", 1)[-1] for fn in _DETECTION_MODULE_ROUTES["binaries"]}
    assert "binary_integrity" in bins


def test_all_routed_targets_are_coroutines():
    for section, fns in _DETECTION_MODULE_ROUTES.items():
        for fn in fns:
            assert inspect.iscoroutinefunction(fn), f"{section}:{fn.__name__} not async"


# ── FakeDB for the entity_state first-seen API ────────────────────────────────

class FakeDB:
    def __init__(self):
        self._st: dict = {}

    async def get_entity_state(self, agent_id, category, entity_key):
        return self._st.get((agent_id, category, entity_key))

    async def set_entity_state(self, agent_id, category, entity_key, fingerprint, ts):
        self._st[(agent_id, category, entity_key)] = {"fingerprint": fingerprint, "seen_at": ts}


def _run(coro):
    return asyncio.run(coro)


class TestMountMonitor:
    def test_first_run_seeds_silently(self):
        db = FakeDB()
        mounts = [{"device": "/dev/disk1s1", "mountpoint": "/", "fstype": "apfs"}]
        out = _run(mount_monitor.analyze("mac-1", "mounts", mounts, db))
        assert out == []                      # baseline capture, no alert
        # sentinel + the mount are now remembered
        assert db._st

    def test_new_removable_media_fires_after_baseline(self):
        db = FakeDB()
        base = [{"device": "/dev/disk1s1", "mountpoint": "/", "fstype": "apfs"}]
        _run(mount_monitor.analyze("mac-1", "mounts", base, db))      # baseline
        # A USB stick appears
        usb = base + [{"device": "/dev/disk4s1", "mountpoint": "/Volumes/USB", "fstype": "msdos"}]
        out = _run(mount_monitor.analyze("mac-1", "mounts", usb, db))
        assert len(out) == 1
        f = out[0]
        assert f["category"] == "mount"
        assert f["rule_id"] == "mount:new_removable_media"
        assert f["mitre_technique"] == "T1091"
        assert "USB" in f["item_key"]

    def test_network_share_classified_high(self):
        db = FakeDB()
        _run(mount_monitor.analyze("mac-1", "mounts", [{"device": "/dev/disk1s1",
             "mountpoint": "/", "fstype": "apfs"}], db))
        share = [{"device": "//user@server/share", "mountpoint": "/Volumes/share",
                  "fstype": "smbfs"}]
        # include baseline root so only the share is new
        out = _run(mount_monitor.analyze("mac-1", "mounts",
                   [{"device": "/dev/disk1s1", "mountpoint": "/", "fstype": "apfs"}] + share, db))
        assert len(out) == 1
        assert out[0]["severity"] == "high"
        assert out[0]["mitre_technique"] == "T1021.002"

    def test_known_mount_does_not_refire(self):
        db = FakeDB()
        base = [{"device": "/dev/disk1s1", "mountpoint": "/", "fstype": "apfs"}]
        _run(mount_monitor.analyze("mac-1", "mounts", base, db))     # baseline
        out = _run(mount_monitor.analyze("mac-1", "mounts", base, db))  # same set again
        assert out == []                      # baseline-known mount never re-fires

    def test_ignores_unrelated_section(self):
        db = FakeDB()
        assert _run(mount_monitor.analyze("mac-1", "battery", {"pct": 50}, db)) == []

    def test_storage_section_also_handled(self):
        db = FakeDB()
        _run(mount_monitor.analyze("mac-1", "storage", [{"device": "/dev/disk1s1",
             "mountpoint": "/", "fstype": "apfs"}], db))
        out = _run(mount_monitor.analyze("mac-1", "storage",
                   [{"device": "/dev/disk1s1", "mountpoint": "/", "fstype": "apfs"},
                    {"device": "/dev/disk9s1", "mountpoint": "/Volumes/EXT", "fstype": "exfat"}], db))
        assert any(f["rule_id"] == "mount:new_removable_media" for f in out)
