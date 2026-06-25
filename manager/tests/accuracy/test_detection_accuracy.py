"""
manager/tests/accuracy/test_detection_accuracy.py — per-module accuracy/calibration.

Phase-1 accuracy harness: each case is a labelled true-positive (must fire, at the
right severity) or false-positive (must stay silent), run through the real module
`analyze()`. This locks calibration so accuracy can't silently regress, and
measures detection latency against a speed budget.

Snapshots run in order on a shared baseline store, so first-run seeding (a new
listener/account/etc. is only an incident when it appears in a LATER snapshot,
not at enrollment) is verified exactly as it behaves in production.

Extend by adding Case(...) entries — keep ≥1 TP and ≥1 FP per module.
"""
from __future__ import annotations

import pytest

from manager.manager.attacklens import detections as D
from manager.tests.accuracy.harness import Case, evaluate, sev_rank


# ── Reusable sample fragments ────────────────────────────────────────────────

def _listener(port, proc="svc", bind="0.0.0.0", pid=100, path="/usr/bin/svc"):
    return {"port": port, "proto": "tcp", "bind_ip": bind, "pid": pid,
            "process_name": proc, "process_path": path}

def _user(name, uid, shell="/bin/zsh", groups=None):
    return {"username": name, "uid": uid, "gid": uid, "shell": shell,
            "home": f"/Users/{name}", "groups": groups or [], "raw": {"u": name}}


# Genuinely-benign baseline: loopback-bound local services on non-high-risk
# ports. These must NOT trip any detector (no external exposure, no wildcard,
# no C2 port) — so they isolate the first-run/new-listener behaviour under test.
# (Externally-exposed SSH/HTTP are legitimate exposure findings, not FPs, so we
# deliberately don't use them as the "should stay silent" baseline.)
_SAFE_PORTS  = [_listener(5432, "postgres", bind="127.0.0.1", path="/usr/local/bin/postgres"),
                _listener(6379, "redis",    bind="127.0.0.1", path="/usr/local/bin/redis-server")]
_BASE_USERS  = [_user("root", 0, "/bin/bash", ["wheel"]), _user("alice", 501)]

# ── Fragments for the modules wired live this session (sysctl/arp/containers/
# sbom). Input shapes mirror what each analyze() receives — taken from the
# modules' own self-tests and the integration TP fixtures so these accuracy
# cases exercise the same detection paths production does. Each module had
# zero measured TP/FP coverage before this; the per-module __main__ self-tests
# are not part of the precision harness.

# A pinned, non-privileged, bridge-networked container with no sensitive env or
# exposed mgmt port — must trip none of container_security's rules. The @sha256
# digest is what makes the image "pinned" (a bare tag like :latest is HIGH).
_BENIGN_CTR  = [{"container_id": "cafef00d0001", "container_name": "web",
                 "image": "nginx:1.25@sha256:" + "a" * 64,
                 "privileged": False, "network_mode": "bridge",
                 "ports": [], "env": []}]
_PRIV_CTR    = [{"container_id": "deadbeef0001", "container_name": "sketchy-ctr",
                 "image": "alpine:1.0@sha256:" + "b" * 64,
                 "privileged": True, "network_mode": "host"}]

# ARP: one IP resolving to two distinct MACs within a single snapshot is a
# stateless, definitive poisoning signal; a clean unique-mapping table is silent.
_DUP_ARP     = {"entries": [
    {"ip_address": "10.50.50.50", "mac_address": "aa:bb:cc:dd:ee:f1"},
    {"ip_address": "10.50.50.50", "mac_address": "aa:bb:cc:dd:ee:f2"}]}
_CLEAN_ARP   = {"entries": [
    {"ip_address": "10.50.50.1",  "mac_address": "aa:bb:cc:dd:ee:01"},
    {"ip_address": "10.50.50.50", "mac_address": "aa:bb:cc:dd:ee:f1"}]}


CASES: list[Case] = [
    # ── port_listener ────────────────────────────────────────────────────────
    Case(  # TP: a NEW C2 listener appears after the baseline is established
        name="port_listener/new_c2_listener",
        analyze_fn=D.analyze_port_listener, section="ports",
        snapshots=[_SAFE_PORTS, _SAFE_PORTS + [_listener(4444, "nc", path="/tmp/nc", pid=9)]],
        expect_fire=True, min_severity="high", label="tp",
    ),
    Case(  # FP: first observation must NOT alert on pre-existing safe listeners
        name="port_listener/first_run_no_storm",
        analyze_fn=D.analyze_port_listener, section="ports",
        snapshots=[_SAFE_PORTS],
        expect_fire=False, label="fp",
    ),
    Case(  # FP: an unchanged baseline (re-report) must stay silent
        name="port_listener/unchanged_silent",
        analyze_fn=D.analyze_port_listener, section="ports",
        snapshots=[_SAFE_PORTS, _SAFE_PORTS],
        expect_fire=False, label="fp",
    ),

    # ── user_account ──────────────────────────────────────────────────────────
    Case(  # TP: a NEW root-equivalent (UID 0) account appears
        name="user_account/new_uid0_clone",
        analyze_fn=D.analyze_user_account, section="users",
        snapshots=[_BASE_USERS, _BASE_USERS + [_user("backdoor", 0, "/bin/bash")]],
        expect_fire=True, min_severity="critical", label="tp",
    ),
    Case(  # FP: first observation must NOT alert on pre-existing accounts
        name="user_account/first_run_no_storm",
        analyze_fn=D.analyze_user_account, section="users",
        snapshots=[_BASE_USERS + [_user("_spotlight", 89, "/usr/bin/false")]],
        expect_fire=False, label="fp",
    ),
    Case(  # FP: a new SERVICE/daemon account is info-tier, not a high-sev incident
        name="user_account/new_service_acct_low_noise",
        analyze_fn=D.analyze_user_account, section="users",
        snapshots=[_BASE_USERS, _BASE_USERS + [_user("_helperd", 250, "/usr/bin/false")]],
        expect_fire=True, min_severity="info", label="tp",
    ),
    Case(  # TP: a usable account hidden behind the macOS `_` convention — a real
        # UID + interactive shell. Regression-locks the hidden_user FN where
        # _is_system_account() suppressed EVERY underscore name, making the
        # detector's own reason-for-existing dead code.
        name="user_account/underscore_hidden_usable_account",
        analyze_fn=D.analyze_user_account, section="users",
        snapshots=[_BASE_USERS, _BASE_USERS + [_user("_evil_daemon", 500, "/bin/bash")]],
        expect_fire=True, min_severity="high", label="tp",
    ),
    Case(  # FP: a genuine Apple daemon (_spotlight: system UID + nologin) already
        # in the baseline must produce nothing — not a new-account info finding
        # and, critically, not a hidden_user HIGH. (A brand-NEW account would
        # legitimately fire an info-tier new_account, so it must be pre-existing
        # to isolate the hidden_user precision check.)
        name="user_account/apple_daemon_silent",
        analyze_fn=D.analyze_user_account, section="users",
        snapshots=[_BASE_USERS + [_user("_spotlight", 89, "/usr/bin/false")],
                   _BASE_USERS + [_user("_spotlight", 89, "/usr/bin/false")]],
        expect_fire=False, label="fp",
    ),

    # ── sysctl_monitor (wired this session) ───────────────────────────────────
    Case(  # TP: a critical kernel-security param disabled
        name="sysctl_monitor/secure_kernel_disabled",
        analyze_fn=D.analyze_sysctl_monitor, section="sysctl",
        snapshots=[{"kern.secure_kernel": "0"}],
        expect_fire=True, min_severity="critical", rule_id="sysctl_critical", label="tp",
    ),
    Case(  # FP: the same param at its secure value must stay silent
        name="sysctl_monitor/secure_kernel_ok",
        analyze_fn=D.analyze_sysctl_monitor, section="sysctl",
        snapshots=[{"kern.secure_kernel": "1"}],
        expect_fire=False, label="fp",
    ),

    # ── arp_spoofing (wired this session) ─────────────────────────────────────
    Case(  # TP: one IP → two MACs = poisoning (stateless, single snapshot)
        name="arp_spoofing/duplicate_ip_mapping",
        analyze_fn=D.analyze_arp_spoofing, section="arp",
        snapshots=[_DUP_ARP],
        expect_fire=True, min_severity="high",
        rule_id="arp:duplicate_ip_mapping", label="tp",
    ),
    Case(  # FP: a clean unique-mapping ARP table must stay silent
        name="arp_spoofing/clean_table_silent",
        analyze_fn=D.analyze_arp_spoofing, section="arp",
        snapshots=[_CLEAN_ARP],
        expect_fire=False, label="fp",
    ),

    # ── container_security (wired this session) ───────────────────────────────
    Case(  # TP: privileged + host-network container = critical escape risk
        name="container_security/privileged_host_network",
        analyze_fn=D.analyze_container_security, section="containers",
        snapshots=[_PRIV_CTR],
        expect_fire=True, min_severity="critical",
        rule_id="cs:privileged_host_network", label="tp",
    ),
    Case(  # FP: a pinned, unprivileged, bridge-networked container is silent
        name="container_security/benign_container_silent",
        analyze_fn=D.analyze_container_security, section="containers",
        snapshots=[_BENIGN_CTR],
        expect_fire=False, label="fp",
    ),

    # ── sbom_posture (wired this session) ─────────────────────────────────────
    Case(  # TP: a strong-copyleft (GPL-3.0) component in the SBOM
        name="sbom_posture/copyleft_license_conflict",
        analyze_fn=D.analyze_sbom_posture, section="sbom",
        snapshots=[[{"name": "copyleft-pkg", "version": "2.0", "license": "GPL-3.0"}]],
        expect_fire=True, label="tp",
    ),
    Case(  # FP: a permissive (MIT) component must stay silent
        name="sbom_posture/permissive_license_silent",
        analyze_fn=D.analyze_sbom_posture, section="sbom",
        snapshots=[[{"name": "permissive-pkg", "version": "1.0", "license": "MIT"}]],
        expect_fire=False, label="fp",
    ),
]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_detection_accuracy(case: Case):
    # Worst-case latency across the snapshots in this case.
    res = evaluate(case.analyze_fn, case.section, case.snapshots)

    if case.expect_fire:
        assert res.fired, f"{case.name}: TP did NOT fire (expected a finding)"
        if case.min_severity:
            assert sev_rank(res.top_severity) >= sev_rank(case.min_severity), (
                f"{case.name}: severity {res.top_severity!r} < expected "
                f"{case.min_severity!r}")
        if case.rule_id:
            rules = {f.get("rule_id") for f in res.findings}
            assert case.rule_id in rules, f"{case.name}: rule {case.rule_id} not in {rules}"
    else:
        assert not res.fired, (
            f"{case.name}: FALSE POSITIVE — expected silence, got "
            f"{[(f.get('severity'), f.get('rule_id')) for f in res.findings]}")

    # Speed budget (Phase-1: validate detection speed per module).
    assert res.latency_ms <= case.max_latency_ms, (
        f"{case.name}: detection took {res.latency_ms:.1f}ms > "
        f"budget {case.max_latency_ms}ms")


def test_precision_summary(capsys):
    """Aggregate precision across all cases — the headline calibration metric."""
    tp_fired = fp_silent = tp_total = fp_total = 0
    for c in CASES:
        res = evaluate(c.analyze_fn, c.section, c.snapshots)
        if c.expect_fire:
            tp_total += 1; tp_fired += int(res.fired)
        else:
            fp_total += 1; fp_silent += int(not res.fired)
    # Every TP must fire and every FP must stay silent for the suite to pass.
    assert tp_fired == tp_total, f"recall gap: {tp_fired}/{tp_total} TPs fired"
    assert fp_silent == fp_total, f"precision gap: {fp_silent}/{fp_total} FPs silent"
