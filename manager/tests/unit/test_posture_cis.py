"""
manager/tests/unit/test_posture_cis.py — CIS posture scorer.

Two things are pinned here:

  1. The historical pipeline bug is FIXED: canonical agent fields
     (sip="enabled", filevault="on", gatekeeper="enabled", firewall="on",
     xprotect_version, dev_tools) now score PASS. Previously the agent shipped
     raw CLI strings that never matched, so every Mac scored F.

  2. The 7 CIS-expansion checks (audit, password policy, guest account,
     auto-login, automatic update install, network time, file/printer sharing)
     evaluate pass/fail/unknown correctly.
"""
from __future__ import annotations

import pytest

from manager.manager.api.posture import (
    _run_checks, _compute_score, _CHECKS, _CIS_GROUPS,
    _audit_enabled, _password_policy, _guest_account, _auto_login,
    _auto_update_install, _network_time, _sharing_services,
)


def _by_id(checks):
    return {c["id"]: c for c in checks}


# ── Regression: canonical fields score PASS (the foundation fix) ──────────────

def test_canonical_core_controls_pass():
    """A fully-hardened Mac (canonical schema) must score these as PASS — this is
    the exact case that used to report FAIL because the agent shipped raw CLI
    strings like 'FileVault is On.' instead of 'on'."""
    sec = {
        "sip": "enabled", "filevault": "on", "gatekeeper": "enabled",
        "firewall": "on", "xprotect_version": "5347",
        "dev_tools": "Developer mode is currently disabled.",
    }
    checks = _by_id(_run_checks(sec, [], []))
    for cid in ("SIP", "FV2", "GK", "FW", "XP", "DT"):
        assert checks[cid]["status"] == "pass", f"{cid} should pass, got {checks[cid]}"


def test_raw_uncanonical_strings_would_not_pass():
    """Guard against regressing to the old behaviour: the legacy raw strings must
    NOT score pass (they are not the canonical values)."""
    sec = {"sip": "System Integrity Protection status: enabled.",
           "filevault": "FileVault is On."}
    checks = _by_id(_run_checks(sec, [], []))
    assert checks["SIP"]["status"] != "pass"
    assert checks["FV2"]["status"] != "pass"


# ── New checks present & wired ────────────────────────────────────────────────

def test_expansion_checks_registered():
    ids = {c[0] for c in _CHECKS}
    for cid in ("AUD", "PWP", "GST", "ALI", "AUI", "NTP", "SHR"):
        assert cid in ids, f"expansion check {cid} missing from registry"
    assert 8 in _CIS_GROUPS and _CIS_GROUPS[8] == "Audit Log Management"


# ── Audit subsystem ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("sec,expected", [
    ({"audit_enabled": True, "audit_flags": "lo,aa"}, "pass"),
    ({"audit_enabled": False}, "fail"),
    ({"audit_enabled": None}, "unknown"),
    ({}, "unknown"),
])
def test_audit_enabled(sec, expected):
    assert _audit_enabled(sec, [], [])[0] == expected


# ── Password policy ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("sec,expected", [
    ({"pw_policy_configured": True, "pw_min_length": 12}, "pass"),
    ({"pw_policy_configured": True, "pw_min_length": 8},  "pass"),
    ({"pw_policy_configured": True, "pw_min_length": 4},  "fail"),
    ({"pw_policy_configured": True, "pw_min_length": None}, "warn"),
    ({"pw_policy_configured": False}, "fail"),
    ({"pw_policy_configured": None}, "unknown"),
])
def test_password_policy(sec, expected):
    assert _password_policy(sec, [], [])[0] == expected


# ── Guest / auto-login ────────────────────────────────────────────────────────

@pytest.mark.parametrize("sec,expected", [
    ({"guest_account": False}, "pass"),
    ({"guest_account": True},  "fail"),
    ({"guest_account": None},  "unknown"),
])
def test_guest_account(sec, expected):
    assert _guest_account(sec, [], [])[0] == expected


@pytest.mark.parametrize("sec,expected", [
    ({"auto_login_user": ""},      "pass"),   # "" = disabled (good)
    ({"auto_login_user": "admin"}, "fail"),
    ({"auto_login_user": None},    "unknown"),
])
def test_auto_login(sec, expected):
    assert _auto_login(sec, [], [])[0] == expected


# ── Software-update install ───────────────────────────────────────────────────

@pytest.mark.parametrize("sec,expected", [
    ({"auto_update_install": True, "critical_update_install": True}, "pass"),
    ({"auto_update_install": False}, "fail"),
    ({"auto_update_install": None}, "unknown"),
])
def test_auto_update_install(sec, expected):
    assert _auto_update_install(sec, [], [])[0] == expected


# ── Network time ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sec,expected", [
    ({"network_time": True, "time_server": "time.apple.com"}, "pass"),
    ({"network_time": False}, "fail"),
    ({"network_time": None}, "unknown"),
])
def test_network_time(sec, expected):
    assert _network_time(sec, [], [])[0] == expected


# ── Sharing services ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("sec,expected", [
    ({"file_sharing": False, "printer_sharing": False}, "pass"),
    ({"file_sharing": True,  "printer_sharing": False}, "fail"),
    ({"file_sharing": False, "printer_sharing": True},  "fail"),
    ({"file_sharing": None,  "printer_sharing": None},  "unknown"),
])
def test_sharing_services(sec, expected):
    assert _sharing_services(sec, [], [])[0] == expected


# ── Unknown data degrades gracefully (no false FAIL) ──────────────────────────

def test_missing_fields_are_unknown_not_fail():
    """An agent that hasn't collected a field (None) must score 'unknown', never
    'fail' — a missing probe must not masquerade as a security failure."""
    checks = _run_checks({}, [], [])
    assert all(c["status"] == "unknown" for c in checks), \
        "empty security dict should be entirely unknown"
    # And unknowns are excluded from the score denominator.
    assert _compute_score(checks)["score"] == 0
