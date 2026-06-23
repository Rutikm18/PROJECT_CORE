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
