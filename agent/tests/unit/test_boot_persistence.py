"""
agent/tests/unit/test_boot_persistence.py — macOS boot-persistence + reboot
detection.

Covers the parts that are pure logic (no root, no launchctl, no real plist):
  - _analyze_plist():   drift detection on a LaunchDaemon body.
  - _parse_disabled():  both launchctl print-disabled output formats.
  - detect_boot_transition(): first-run / reboot / no-reboot state machine,
    downtime estimate, and clean vs unexpected shutdown classification.
  - mark_clean_stop() / touch_heartbeat(): marker semantics.

The verify/repair launchctl+filesystem plumbing is integration-tested on a real
Mac (it needs root); here we lock down the decision logic that governs it.
"""
from __future__ import annotations

import json

import pytest

from agent.os.macos import boot_persistence as bp
from agent.os.macos.launchd import _AGENT_LABEL, _AGENT_BIN, _agent_plist_xml


# ── _analyze_plist ─────────────────────────────────────────────────────────────

def test_analyze_plist_clean_on_real_template():
    """The plist our own installer writes must have zero drift issues."""
    body = _agent_plist_xml()
    issues = bp._analyze_plist(body, _AGENT_BIN, _AGENT_LABEL)
    assert issues == []


def test_analyze_plist_flags_missing_run_at_load():
    body = _agent_plist_xml().replace("<key>RunAtLoad</key>\n    <true/>", "")
    issues = bp._analyze_plist(body, _AGENT_BIN, _AGENT_LABEL)
    assert "no_run_at_load" in issues


def test_analyze_plist_flags_wrong_binary_and_label():
    body = _agent_plist_xml()
    issues = bp._analyze_plist(body, "/opt/other/binary", "com.evil.other")
    assert "wrong_binary" in issues
    assert "wrong_label" in issues


def test_analyze_plist_accepts_keepalive_dict_form():
    body = _agent_plist_xml().replace(
        "<key>KeepAlive</key>\n    <true/>",
        "<key>KeepAlive</key>\n    <dict><key>SuccessfulExit</key><false/></dict>",
    )
    issues = bp._analyze_plist(body, _AGENT_BIN, _AGENT_LABEL)
    assert "no_keep_alive" not in issues


# ── _parse_disabled ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ('"com.attacklens.agent" => true', True),      # legacy: true == disabled
    ('"com.attacklens.agent" => disabled', True),  # newer worded form
    ('"com.attacklens.agent" => false', False),    # explicitly enabled
    ('"com.other.thing" => true', False),          # our label absent → enabled
    ('', False),                                    # empty → enabled
])
def test_parse_disabled(text, expected):
    assert bp._parse_disabled(text, _AGENT_LABEL) is expected


# ── detect_boot_transition ─────────────────────────────────────────────────────

@pytest.fixture
def marker(tmp_path, monkeypatch):
    """Redirect the boot-state marker to a temp file and let us control the
    'current' kernel boot time."""
    path = tmp_path / "boot_state.json"
    monkeypatch.setattr(bp, "_STATE_FILE", str(path))

    def set_boot(ts):
        monkeypatch.setattr(bp, "_current_boot_time", lambda: ts)

    return path, set_boot


def _read(path) -> dict:
    return json.loads(path.read_text())


def test_first_run_initializes_marker_no_reboot(marker):
    path, set_boot = marker
    set_boot(1000)
    res = bp.detect_boot_transition()
    assert res["first_run"] is True
    assert res["rebooted"] is False
    # Marker is now seeded with the current boot time and running state.
    saved = _read(path)
    assert saved["boot_time"] == 1000
    assert saved["clean_stop"] is False


def test_same_boot_time_is_not_a_reboot(marker):
    path, set_boot = marker
    set_boot(1000)
    bp.detect_boot_transition()          # seed
    res = bp.detect_boot_transition()    # same boot time → agent just restarted
    assert res["rebooted"] is False
    assert res["first_run"] is False


def test_reboot_after_clean_shutdown_reports_clean(marker):
    path, set_boot = marker
    set_boot(1000)
    bp.detect_boot_transition()          # seed at boot=1000
    bp.mark_clean_stop()                 # graceful SIGTERM recorded

    set_boot(5000)                       # machine rebooted (new kernel boot time)
    res = bp.detect_boot_transition()
    assert res["rebooted"] is True
    assert res["clean_shutdown"] is True
    assert res["previous_boot"] == 1000
    assert res["current_boot"] == 5000
    assert res["downtime_sec"] is not None and res["downtime_sec"] >= 0


def test_reboot_without_clean_stop_reports_unexpected(marker):
    path, set_boot = marker
    set_boot(1000)
    bp.detect_boot_transition()          # seed, clean_stop defaults to False

    set_boot(5000)                       # rebooted with no graceful stop = power loss/panic
    res = bp.detect_boot_transition()
    assert res["rebooted"] is True
    assert res["clean_shutdown"] is False


def test_downtime_measured_from_last_heartbeat(marker):
    path, set_boot = marker
    set_boot(1000)
    bp.detect_boot_transition()          # seed
    # Simulate the heartbeat thread advancing last_seen to t=4000.
    state = _read(path)
    state["last_seen"] = 4000
    path.write_text(json.dumps(state))

    set_boot(4600)                       # new boot 600s after last heartbeat
    res = bp.detect_boot_transition()
    assert res["downtime_sec"] == 600


def test_mark_clean_stop_preserves_boot_time(marker):
    path, set_boot = marker
    set_boot(1000)
    bp.detect_boot_transition()
    bp.mark_clean_stop()
    saved = _read(path)
    assert saved["clean_stop"] is True
    assert saved["boot_time"] == 1000    # marker not corrupted by clean-stop


def test_touch_heartbeat_does_not_reset_clean_stop(marker):
    path, set_boot = marker
    set_boot(1000)
    bp.detect_boot_transition()
    bp.mark_clean_stop()
    bp.touch_heartbeat()
    saved = _read(path)
    # Heartbeat updates last_seen but must leave clean_stop intact.
    assert saved["clean_stop"] is True
