"""
agent/tests/unit/test_posture_collector_cis.py
— macOS SecurityCollector CIS-expansion parsing + normalizer passthrough.

Producer side of the CIS pipeline. The manager-side scorer is covered by
manager/tests/unit/test_posture_cis.py; here we pin that the collector parses
each source command/file into the canonical field the scorer consumes, and that
the macOS normalizer forwards those fields (and fixes the historical
xprotect/xprotect_version + dev_tools key mismatches).
"""
from __future__ import annotations

from unittest.mock import patch, mock_open

import pytest

from agent.os.macos.collectors.posture import SecurityCollector
from agent.os.macos.normalizer import normalize

POSTURE = "agent.os.macos.collectors.posture"


def _sc():
    return SecurityCollector()


# ── launchd service detection (file/printer/audit sharing) ────────────────────

def test_svc_loaded_true_when_label_present():
    with patch(f"{POSTURE}._run", return_value='\t"Label" = "com.apple.smbd";'):
        assert _sc()._svc_loaded("com.apple.smbd") is True


def test_svc_loaded_false_when_not_found():
    def fake(cmd, *a, **k):
        return "" if not k.get("stderr") else "Could not find service com.apple.smbd"
    with patch(f"{POSTURE}._run", side_effect=fake):
        assert _sc()._svc_loaded("com.apple.smbd") is False


def test_svc_loaded_none_when_ambiguous():
    with patch(f"{POSTURE}._run", return_value=""):
        # Empty stdout AND empty stderr → can't tell → None (never guesses off)
        assert _sc()._svc_loaded("com.apple.smbd") is None


# ── Printer sharing (cupsctl) ─────────────────────────────────────────────────

@pytest.mark.parametrize("cups,expected", [
    ("_share_printers=1\nWebInterface=No", True),
    ("_share_printers=0\nWebInterface=No", False),
    ("WebInterface=No", None),
])
def test_printer_sharing(cups, expected):
    with patch(f"{POSTURE}._run", return_value=cups):
        assert _sc()._printer_sharing() is expected


# ── Time sync requires root: must not leak the privilege-error string ─────────

def test_time_server_admin_error_returns_none():
    msg = "You need administrator access to run this tool... exiting!"
    with patch(f"{POSTURE}._run", return_value=msg):
        assert _sc()._time_server() is None
        assert _sc()._network_time() is None


def test_time_server_parses_value():
    with patch(f"{POSTURE}._run", return_value="Network Time Server: time.apple.com"):
        assert _sc()._time_server() == "time.apple.com"


# ── Auto-login: "" (disabled) vs configured user vs missing ───────────────────

@pytest.mark.parametrize("out,expected", [
    ("admin", "admin"),
    ("The domain/default pair ... does not exist", ""),
    ("", ""),
])
def test_auto_login_user(out, expected):
    with patch(f"{POSTURE}._run", return_value=out):
        assert _sc()._auto_login_user() == expected


# ── Password policy min length parsing ────────────────────────────────────────

@pytest.mark.parametrize("out,expected", [
    ("<key>minimumLength</key>\n<integer>15</integer>", 15),
    ("policyContent = 'matches .{8,}'", 8),
    ("Getting global account policies", None),
])
def test_pw_min_length(out, expected):
    with patch(f"{POSTURE}._run", return_value=out):
        assert _sc()._pw_min_length() == expected


@pytest.mark.parametrize("out,expected", [
    ("<key>policyContent</key><string>...</string>", True),
    ("No accountPolicies set for global.", False),
    ("", None),
])
def test_pw_policy_configured(out, expected):
    with patch(f"{POSTURE}._run", return_value=out):
        assert _sc()._pw_policy_configured() is expected


# ── Audit flags read from /etc/security/audit_control ─────────────────────────

def test_audit_flags_parsed_from_file():
    content = "# comment\ndir:/var/audit\nflags:lo,aa\nminfree:5\n"
    with patch("builtins.open", mock_open(read_data=content)):
        assert _sc()._audit_flags() == "lo,aa"


def test_audit_flags_missing_file_returns_none():
    with patch("builtins.open", side_effect=OSError):
        assert _sc()._audit_flags() is None


# ── Normalizer passthrough + key fixes ────────────────────────────────────────

def test_norm_security_forwards_canonical_and_new_fields():
    raw = {
        "sip": "enabled", "filevault": "on", "gatekeeper": "enabled",
        "firewall": "on", "xprotect_version": "5347",
        "dev_tools": "Developer mode is currently disabled.",
        "remote_login": False, "ssh_password_auth": "no",
        "screensaver_lock": True, "screensaver_idle_sec": 300,
        # expansion fields
        "audit_enabled": True, "audit_flags": "lo,aa",
        "pw_policy_configured": True, "pw_min_length": 12,
        "guest_account": False, "auto_login_user": "",
        "auto_update_install": True, "critical_update_install": True,
        "network_time": True, "time_server": "time.apple.com",
        "file_sharing": False, "printer_sharing": False,
    }
    out = normalize("security", raw)

    # canonical core preserved
    assert out["sip"] == "enabled"
    assert out["filevault"] == "on"
    assert out["xprotect_version"] == "5347"      # not the legacy "xprotect"
    assert out["dev_tools"].startswith("Developer mode")
    # rich access fields forwarded
    assert out["remote_login"] is False
    assert out["screensaver_idle_sec"] == 300
    # expansion fields forwarded with correct types
    assert out["audit_enabled"] is True
    assert out["pw_min_length"] == 12
    assert out["auto_login_user"] == ""           # "" preserved, NOT collapsed to None
    assert out["network_time"] is True
    assert out["file_sharing"] is False


def test_norm_security_maps_legacy_keys():
    """Old collector keys (xprotect, dev_tools_security) still map onto the
    canonical names so a mixed-version agent doesn't silently drop them."""
    out = normalize("security", {"xprotect": "5347",
                                 "dev_tools_security": "Developer mode is currently disabled."})
    assert out["xprotect_version"] == "5347"
    assert out["dev_tools"].startswith("Developer mode")
