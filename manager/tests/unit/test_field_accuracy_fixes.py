"""
manager/tests/unit/test_field_accuracy_fixes.py — detection field-correctness audit.

Each test pins a confirmed mismatch between what the detection layer checked
and what the real agent collector/normalizer actually emits (verified against
agent/os/macos/collectors/*.py, os/windows/collectors/*.py, and
agent/os/macos/normalizer.py — both macOS and Windows confirmed identical):

  1. engine._security() checked a key that never exists ("sip_enabled" — the
     real key is "sip") and compared sip/gatekeeper/filevault/firewall (all
     STRINGS: "enabled"/"disabled"/"on"/"off") against the Python literal
     False. A str is never == a bool, so is_bad was unconditionally False for
     every agent, on every platform — the entire posture-disabled check never
     fired, ever, regardless of actual SIP/Gatekeeper/FileVault/Firewall state.

  2. port_listener.ingest_listeners()'s bind-address fallback chain never
     included "bind_addr" — the actual field BOTH macOS and Windows
     PortsCollector emit. Every real listener silently defaulted to "0.0.0.0",
     so detect_wildcard_bind() flagged EVERY listener as world-accessible,
     including ones bound to 127.0.0.1 only (fleet-wide false positives).

  3. fleet_correlator's malware-propagation-by-path rule checked `signed` on
     "binary"-category evidence, but BinariesCollector never emits a `signed`
     field at all (it only scans fixed system PATH dirs and never inspects
     code-signing) — the rule could never fire. Repurposed to "app" category,
     which genuinely has `signed: bool`.

DB-backed tests use the pg_manager_dsn/pg_intel_dsn fixtures (conftest.py) —
each a freshly CREATEd, then DROPped, real Postgres database. Pure-function
tests (ingest_listeners, _ix_app_path_unsigned) need no DB and are unchanged.
"""
from __future__ import annotations

import time

from manager.manager.attacklens.engine import AttackLensEngine
from manager.manager.attacklens.detections.port_listener import ingest_listeners
from manager.manager.attacklens.fleet_correlator import FleetCorrelator, _ix_app_path_unsigned
from manager.manager.db import Database
from manager.manager.indexer import IntelDB


# ── 1. engine._security() field names + value types ──────────────────────────

async def test_security_fires_on_real_field_names_and_string_values(pg_manager_dsn, pg_intel_dsn):
    """The exact shape agent/os/macos/normalizer.py._norm_security produces."""
    dbm = Database(pg_manager_dsn); await dbm.init()
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        eng = AttackLensEngine(dbm, idb)
        findings = await eng._security("agent-1", {
            "sip": "disabled", "gatekeeper": "enabled",
            "filevault": "off", "firewall": "on",
        })
        by_key = {f["item_key"]: f for f in findings}
        assert "sec:sip" in by_key, "sip=disabled must fire — was dead code before this fix"
        assert by_key["sec:sip"]["severity"] == "critical"
        assert "sec:filevault" in by_key, "filevault=off must fire"
        assert "sec:gatekeeper" not in by_key, "gatekeeper=enabled is healthy — must NOT fire"
        assert "sec:firewall" not in by_key, "firewall=on is healthy — must NOT fire"
    finally:
        await dbm.close(); await idb.close()


async def test_security_old_broken_keys_no_longer_referenced(pg_manager_dsn, pg_intel_dsn):
    """Regression guard: the old nonexistent key must not silently come back."""
    dbm = Database(pg_manager_dsn); await dbm.init()
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        eng = AttackLensEngine(dbm, idb)
        # "sip_enabled" (the old, wrong key) present but "sip" absent —
        # must produce ZERO findings: there's nothing real to check.
        findings = await eng._security("agent-1", {"sip_enabled": False})
        assert findings == []
    finally:
        await dbm.close(); await idb.close()


async def test_lockdown_mode_is_info_only_never_escalates(pg_manager_dsn, pg_intel_dsn):
    dbm = Database(pg_manager_dsn); await dbm.init()
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        eng = AttackLensEngine(dbm, idb)
        findings = await eng._security("agent-1", {"lockdown_mode": True})
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
    finally:
        await dbm.close(); await idb.close()


# ── 2. port_listener bind_addr field ──────────────────────────────────────────

def test_ingest_listeners_reads_real_agent_bind_addr_field():
    """Exact shape from agent/os/macos/collectors/network.py PortsCollector and
    os/windows/collectors/network.py (both confirmed identical: "bind_addr")."""
    raw = [{
        "proto": "tcp", "port": 8443, "bind_addr": "127.0.0.1",
        "state": "LISTEN", "pid": 42, "process": "myservice",
    }]
    listeners = ingest_listeners("ports", raw)
    assert len(listeners) == 1
    assert listeners[0]["bind_ip"] == "127.0.0.1", \
        "must read the real 'bind_addr' field, not silently default to 0.0.0.0"


def test_ingest_listeners_wildcard_still_detected_correctly():
    raw = [{
        "proto": "tcp", "port": 9999, "bind_addr": "0.0.0.0",
        "pid": 42, "process": "nc",
    }]
    listeners = ingest_listeners("ports", raw)
    assert listeners[0]["bind_ip"] == "0.0.0.0"


def test_ingest_listeners_legacy_field_names_still_supported():
    """Backward-compat: a payload already using bind_ip/bind_address must still
    work — the fix only ADDS bind_addr, doesn't remove the existing fallbacks."""
    raw = [{"proto": "tcp", "port": 1, "bind_ip": "10.0.0.5", "pid": 1, "process": "x"}]
    assert ingest_listeners("ports", raw)[0]["bind_ip"] == "10.0.0.5"
    raw2 = [{"proto": "tcp", "port": 1, "bind_address": "10.0.0.6", "pid": 1, "process": "x"}]
    assert ingest_listeners("ports", raw2)[0]["bind_ip"] == "10.0.0.6"


# ── 3. fleet_correlator app-path indicator (was binary-path, dead code) ─────

def test_ix_app_path_unsigned_matches_real_apps_collector_shape():
    """Exact shape from agent/os/macos/collectors/inventory.py AppsCollector."""
    finding = {"evidence": {
        "name": "FreeVPN", "version": "1.0", "bundle_id": "com.example.freevpn",
        "path": "/Applications/FreeVPN.app", "vendor": None,
        "signed": False, "notarized": False, "installed_at": 0,
    }}
    assert _ix_app_path_unsigned(finding) == "/Applications/FreeVPN.app"


def test_ix_app_path_unsigned_skips_signed_apps():
    finding = {"evidence": {"path": "/Applications/Safari.app", "signed": True}}
    assert _ix_app_path_unsigned(finding) is None


async def test_fleet_malware_propagation_path_fires_on_app_category(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        for host in ("mac-1", "mac-2", "mac-3"):
            await idb.upsert_finding({
                "agent_id": host, "category": "app", "item_key": f"app:{host}",
                "severity": "medium", "score": 5.0, "title": "Unsigned app",
                "source": "rule:unsigned_app", "rule_id": "rule:unsigned_app",
                "evidence": {"path": "/Applications/Updater.app", "signed": False},
            }, time.time())
        campaigns = await FleetCorrelator(idb).correlate()
        hit = [c for c in campaigns if c["rule_id"].startswith("fleet:malware_propagation_path")]
        assert len(hit) == 1
        assert set(hit[0]["affected_assets"]) == {"mac-1", "mac-2", "mac-3"}
    finally:
        await idb.close()
