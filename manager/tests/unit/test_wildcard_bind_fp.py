"""
manager/tests/unit/test_wildcard_bind_fp.py — wildcard-bind false-positive lock.

Against the live deployment data, detect_wildcard_bind was the single largest
false-positive source in the entire system: 16,616 of 16,632 findings (99.9%)
were CRITICAL wildcard-bind alerts on signed, stock-macOS / dev processes —
netbiosd (137/138), com.docker.backend, "code helper" subprocesses, and Apple
daemons. Two compounding bugs:

  1. Allowlist used exact-name matching → missed com.docker.* and "<App> Helper".
  2. Allowlist entries were mixed-case ("mDNSResponder", "ControlCenter") but the
     agent emits process names LOWERCASED → those entries never matched.

After fixing both, replaying 200 real `ports` payloads collapsed wildcard_bind
from 16,616 stored findings to 1 (a genuine `openssl s_server` exposure).

An EARLIER version of this fix also blanket-exempted the whole ephemeral port
range (>=49152), reasoning that high ports are mostly transient IPC churn.
That was REMOVED: it created exactly the port-based blind spot a real backdoor
could exploit on purpose by choosing a high port. Replaying real data with the
exemption removed surfaced only a handful of legitimate macOS daemons
(airportd, syslogd, wifip2pd, ...) doing normal OS work on high ports — now
named explicitly in the allowlist — not a return of the false-positive volume.
Detection now covers every port; the only exemption left is port 0 (not a
real, connectable network surface — a data-validity case, not a coverage
decision).
"""
from __future__ import annotations

from manager.manager.attacklens.detections.port_listener import (
    detect_wildcard_bind, _is_approved_wildcard, _is_invalid_port,
)


def _listener(**kw) -> dict:
    base = {
        "port": 8080, "proto": "tcp", "bind_ip": "0.0.0.0", "pid": 1234,
        "process_name": "mystery", "process_path": "/x", "parent_pid": 1,
        "cmdline": "", "interface": "", "process_signature_valid": True,
    }
    base.update(kw)
    return base


def _reset():
    # Clear module dedup so each case is judged on its own merits.
    from manager.manager.attacklens.detections import port_listener as pl
    pl._dedup_cache.clear(); pl._rate_counter.clear()
    pl._listener_identity.clear(); pl._rate_counter.clear()


# ── Casing fix (bug #2): lowercased agent names match the allowlist ──────────

def test_macos_daemons_lowercased_are_approved():
    for proc in ("mdnsresponder", "controlcenter", "netbiosd", "rapportd",
                 "sharingd", "airplayxpchelper", "airportd", "replicatord",
                 "symptomsd", "syslogd", "wifip2pd", "wifivelocityd"):
        assert _is_approved_wildcard(proc), f"{proc} must be allowlisted"


def test_vendor_prefix_matching():
    assert _is_approved_wildcard("com.docker.backend")
    assert _is_approved_wildcard("com.apple.webkit.networking")


def test_app_helper_convention_matching():
    assert _is_approved_wildcard("code helper (plugin)")
    assert _is_approved_wildcard("google chrome helper")


def test_unknown_process_is_not_approved():
    assert not _is_approved_wildcard("totally_unknown_daemon")
    assert not _is_approved_wildcard("")


# ── Port coverage: no port-based blind spot ──────────────────────────────────

def test_invalid_port_classification():
    """Only port 0 (no real port resolved) is exempt — everything else,
    INCLUDING the high/ephemeral range, is a real network surface that must
    be covered."""
    assert _is_invalid_port(0)
    assert not _is_invalid_port(49152)
    assert not _is_invalid_port(53782)
    assert not _is_invalid_port(65535)
    assert not _is_invalid_port(8080)
    assert not _is_invalid_port(443)
    assert not _is_invalid_port(137)


def test_unapproved_process_on_high_port_still_fires():
    """The high/ephemeral range is NOT a blind spot — an unapproved process
    choosing a high port is exactly what a backdoor evading naive port-range
    filtering would do, so it must still be flagged."""
    _reset()
    f = detect_wildcard_bind("a", [_listener(process_name="unknown", port=53782)])
    assert len(f) == 1, "unapproved process on a high port must still fire"
    assert f[0]["evidence"]["port"] == 53782


def test_port_zero_is_suppressed():
    """Port 0 is the one narrow exemption — not a real connectable surface,
    a data-validity case distinct from port-range coverage."""
    _reset()
    f = detect_wildcard_bind("a", [_listener(process_name="unknown", port=0)])
    assert f == [], "port 0 has no real exposure to report"


# ── End-to-end FP regression on the exact real-world offenders ───────────────

def test_real_world_false_positives_all_suppressed():
    """The exact (process, port) pairs that produced ~16k FPs on live data,
    including ones on high/ephemeral ports — suppression here must come from
    the allowlist (the process IS legitimate), never from the port number."""
    cases = [
        ("netbiosd", 137), ("netbiosd", 138),
        ("com.docker.backend", 6443), ("com.docker.backend", 8080),
        ("com.docker.backend", 0),
        ("code helper (plugin)", 18620), ("code helper (plugin)", 53782),
        ("mdnsresponder", 5353), ("controlcenter", 7000),
        ("com.apple.webkit.networking", 443),
        # Found by removing the ephemeral-port exemption and replaying real
        # data — legitimate macOS daemons doing normal OS work on high ports.
        ("airportd", 0), ("replicatord", 59995), ("symptomsd", 52138),
        ("syslogd", 50194), ("wifip2pd", 0), ("wifivelocityd", 0),
    ]
    for proc, port in cases:
        _reset()
        f = detect_wildcard_bind("a", [_listener(process_name=proc, port=port)])
        assert f == [], f"{proc}:{port} must be suppressed (was a real FP)"


# ── True positives still fire, at the corrected severity ─────────────────────

def test_genuine_service_exposure_still_fires_medium():
    _reset()
    f = detect_wildcard_bind("a", [_listener(process_name="openssl", port=8443)])
    assert len(f) == 1
    assert f[0]["severity"] == "medium", "wildcard exposure is MEDIUM, not CRITICAL"
    assert f[0]["rule_id"] == "wildcard_bind"


def test_genuine_exposure_on_ephemeral_port_still_fires():
    """An unapproved process exposing a wildcard listener on a high port is a
    real finding, not noise — this is the whole point of removing the
    port-range exemption."""
    _reset()
    f = detect_wildcard_bind("a", [_listener(process_name="suspicious_tool", port=54321)])
    assert len(f) == 1
    assert f[0]["severity"] == "medium"


def test_stable_item_key_does_not_churn_on_pid():
    """Same process+port across scans with different pids → identical evidence
    key material (pid excluded), so the engine dedups instead of accumulating."""
    _reset()
    f1 = detect_wildcard_bind("a", [_listener(process_name="openssl", port=8443, pid=100)])
    _reset()
    f2 = detect_wildcard_bind("a", [_listener(process_name="openssl", port=8443, pid=999)])
    assert len(f1) == 1 and len(f2) == 1
    # The engine derives its dedup key from evidence (process_name, port) — both
    # identical here regardless of pid.
    assert f1[0]["evidence"]["process_name"] == f2[0]["evidence"]["process_name"]
    assert f1[0]["evidence"]["port"] == f2[0]["evidence"]["port"]
