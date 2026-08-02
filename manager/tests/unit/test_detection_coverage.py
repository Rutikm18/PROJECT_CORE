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

from manager.manager.attacklens.engine import (
    _DETECTION_MODULE_ROUTES,
    detection_source_coverage,
)
from manager.manager.attacklens.rulepack import RulePackDetector
from manager.manager.attacklens.detections import battery_health, mount_monitor, sca_compliance
from shared.sections import VALID_SECTION_NAMES


# Use the same canonical source registry as ingest and the agent. A hand-written
# test set can silently omit a newly-added source and still pass.
ALL_SECTIONS = set(VALID_SECTION_NAMES)


def test_every_canonical_source_has_an_executable_detection_path():
    coverage = detection_source_coverage(RulePackDetector.load())
    assert set(coverage) == ALL_SECTIONS
    assert not {section: paths for section, paths in coverage.items() if not paths}


def test_sca_and_battery_are_dedicated_routes_not_metadata_only():
    assert _DETECTION_MODULE_ROUTES["sca"]
    assert _DETECTION_MODULE_ROUTES["battery"]


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


class TestBatteryHealth:
    def test_explicit_bad_condition_and_severe_degradation_fire(self):
        out = _run(battery_health.analyze("mac-1", "battery", {
            "present": True,
            "condition": "Service Recommended",
            "charge_pct": 75,
            "capacity_mah": 2500,
            "design_mah": 5000,
            "cycle_count": 400,
        }, FakeDB()))
        assert {finding["rule_id"] for finding in out} == {
            "BATTERY-HEALTH-001", "BATTERY-HEALTH-002",
        }

    def test_cycle_counter_decrease_fires_only_after_durable_baseline(self):
        db = FakeDB()
        assert _run(battery_health.analyze(
            "mac-1", "battery", {"present": True, "cycle_count": 120}, db,
        )) == []
        out = _run(battery_health.analyze(
            "mac-1", "battery", {"present": True, "cycle_count": 3}, db,
        ))
        assert [finding["rule_id"] for finding in out] == ["BATTERY-002"]
        assert out[0]["evidence"]["previous_cycle_count"] == 120

    def test_absent_battery_is_not_an_alert(self):
        assert _run(battery_health.analyze(
            "desktop-1", "battery", {"present": False}, FakeDB(),
        )) == []


class TestScaCompliance:
    def test_only_failed_applicable_checks_become_findings(self):
        payload = {
            "policies": [{
                "policy": {"id": "cis-macos", "name": "CIS macOS"},
                "applicable": True,
                "checks": [
                    {"id": "1.1", "title": "Enable updates", "result": "passed"},
                    {"id": "2.1", "title": "Enable firewall", "result": "failed",
                     "reason": "firewall disabled", "remediation": "Enable the firewall",
                     "mitre": ["T1562.004"]},
                    {"id": "3.1", "title": "Unknown probe", "result": "not_applicable"},
                ],
            }],
        }
        out = _run(sca_compliance.analyze("mac-1", "sca", payload, FakeDB()))
        assert len(out) == 1
        assert out[0]["item_key"] == "sca:cis-macos:2.1"
        assert out[0]["category"] == "compliance"
        assert out[0]["evidence"]["reason"] == "firewall disabled"

    def test_unrelated_section_is_ignored(self):
        assert _run(sca_compliance.analyze(
            "mac-1", "security", {"policies": []}, FakeDB(),
        )) == []


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
