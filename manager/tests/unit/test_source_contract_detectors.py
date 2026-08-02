"""Detectors consume the actual health/hardware shapes emitted by the agent."""
from __future__ import annotations

import asyncio

from manager.manager.attacklens.detections.agent_health import analyze as health_analyze
from manager.manager.attacklens.detections.hardware_integrity import analyze as hardware_analyze
from manager.manager.attacklens.engine import (
    AttackLensEngine,
    InvalidDetectionSourceData,
    _normalize_legacy_detection_shape,
)
from shared.schema import (
    DICT_SECTIONS,
    FLEX_SECTIONS,
    LIST_SECTIONS,
    SCHEMAS,
    validate_section,
)
from shared.sections import VALID_SECTION_NAMES


class _StateDB:
    def __init__(self):
        self.values = {}

    async def get_entity_state(self, agent_id, category, key):
        value = self.values.get((agent_id, category, key))
        return {"fingerprint": value, "seen_at": 0} if value is not None else None

    async def set_entity_state(self, agent_id, category, key, value, _ts):
        self.values[(agent_id, category, key)] = value


def test_every_canonical_source_has_a_registered_shape():
    assert set(SCHEMAS) == set(VALID_SECTION_NAMES)
    shape_sections = set(DICT_SECTIONS) | set(LIST_SECTIONS) | set(FLEX_SECTIONS)
    assert shape_sections == set(VALID_SECTION_NAMES)
    assert not (set(DICT_SECTIONS) & set(LIST_SECTIONS))
    assert not (set(FLEX_SECTIONS) & (set(DICT_SECTIONS) | set(LIST_SECTIONS)))


def test_agent_health_schema_and_real_failure_detection():
    data = {
        "agent_id": "agent-1", "hostname": "mac-1", "os": "macos", "arch": "arm64",
        "uptime_sec": 100, "queue_depth": 4, "skipped_overlap": 0,
        "generated_at": 1_700_000_000,
        "sections": {
            "ports": {"state": "OPEN", "failures": 3, "last_result": "timeout"},
        },
        "link": {
            "spool_dropped_trim": 2, "spool_dropped_corrupt": 0,
            "spool_dropped_auth": 0, "spool_bytes": 1024, "auth_failures": 4,
            "delivery_rejected_4xx": 4,
        },
    }
    assert validate_section("agent_health", data) == []
    findings = asyncio.run(health_analyze("agent-1", "agent_health", data, None, "mac-1"))
    assert {f["rule_id"] for f in findings} == {
        "AGENT-HEALTH-COLLECTOR-OPEN",
        "AGENT-HEALTH-SPOOL-LOSS",
        "AGENT-HEALTH-AUTH-FAILURES",
    }


def test_hardware_first_snapshot_seeds_then_change_alerts():
    db = _StateDB()
    first = [{
        "bus": "usb", "name": "External Disk", "vendor": "Acme",
        "vendor_id": "0x1", "product_id": "0x2", "serial": "A", "revision": "1",
    }]
    assert asyncio.run(hardware_analyze("agent-1", "hardware", first, db)) == []

    changed = [{**first[0], "serial": "B"}]
    findings = asyncio.run(hardware_analyze("agent-1", "hardware", changed, db))
    assert [f["rule_id"] for f in findings] == ["HARDWARE-COMPONENT-CHANGED"]


def test_sca_has_canonical_dict_schema():
    data = {
        "policies": [],
        "summary": {"passed": 0, "failed": 0, "not_applicable": 0},
        "engine": {"yaml": True, "platform": "darwin"},
    }
    assert validate_section("sca", data) == []


def test_legacy_sysctl_and_config_maps_are_normalized_before_detection():
    sysctl = _normalize_legacy_detection_shape(
        "sysctl", {"vm.cs_enforcement_disable": 1},
    )
    configs = _normalize_legacy_detection_shape(
        "configs", {"/tmp/test.conf": "curl example.invalid"},
    )
    assert sysctl == [{
        "key": "vm.cs_enforcement_disable",
        "value": "1",
        "security_relevant": True,
    }]
    assert configs == [{
        "path": "/tmp/test.conf",
        "content": "curl example.invalid",
        "suspicious": False,
    }]


def test_rich_arp_wrapper_is_a_valid_detection_shape():
    data = {"entries": [{
        "ip_address": "10.0.0.4", "mac_address": "aa:bb:cc:dd:ee:ff",
    }], "gateway_info": [], "arp_stats": []}
    assert validate_section("arp", data) == []


def test_detection_never_marks_wrong_top_level_shape_as_processed():
    engine = object.__new__(AttackLensEngine)
    engine._source_coverage = {"ports": ("inline",), "metrics": ("inline",)}
    engine._ready = True
    try:
        asyncio.run(engine.process("agent-1", "ports", {"port": 22}))
    except InvalidDetectionSourceData:
        pass
    else:
        raise AssertionError("list source with object data was silently accepted")
