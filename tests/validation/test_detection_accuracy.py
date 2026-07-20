"""
tests/validation/test_detection_accuracy.py — Detection & prioritization accuracy.

Validates the risk-prioritization logic across a diverse, labeled corpus of
attack scenarios. Each scenario carries an expected exploitability band and an
expected relative priority; the harness asserts:

  1. Band accuracy         — computed band matches the analyst-expected band
  2. Ranking correctness   — active-exploitation cases outrank theoretical ones
  3. Escalation firing     — KEV / weaponized / high-EPSS floors trigger correctly
  4. No inversion          — no benign finding outranks a critical one

Run:  python3 -m pytest tests/validation/test_detection_accuracy.py -v
   or standalone:  PYTHONPATH=. python3 tests/validation/test_detection_accuracy.py
"""
from __future__ import annotations

import time

from manager.manager.threat.exploitability import exploitability_scorer as S

NOW = time.time()
DAY = 86400


# ── Labeled attack-scenario corpus ─────────────────────────────────────────────
# Each: (name, finding, cve_age_days, expected_band, expected_tier)
# expected_tier is a coarse priority class for ranking checks (higher = act first)
SCENARIOS = [
    # ---- Actively exploited (must be top tier) ----
    ("Log4Shell on prod server (KEV+exploit+EPSS)",
     {"cvss_score": 10.0, "epss_score": 0.97, "kev": True, "exploit_available": True,
      "exploit_sources": ["ExploitDB:50592", "Metasploit", "PoC"], "asset_tier": "server"},
     45, "critical", 5),

    ("ProxyShell on exec laptop (KEV, crown jewel)",
     {"cvss_score": 9.8, "epss_score": 0.90, "kev": True, "exploit_available": True,
      "exploit_sources": ["Metasploit"], "asset_tier": "crown_jewel"},
     120, "critical", 5),

    ("Older KEV, low EPSS, endpoint (KEV floor still applies)",
     {"cvss_score": 7.5, "epss_score": 0.05, "kev": True, "exploit_available": False,
      "asset_tier": "endpoint"},
     900, "critical", 5),

    ("MOVEit Transfer SQLi mass exploitation (KEV+EPSS)",
     {"cvss_score": 9.8, "epss_score": 0.94, "kev": True, "exploit_available": True,
      "exploit_sources": ["CISA KEV", "Metasploit", "VulnCheck exploited"],
      "asset_tier": "server"},
     30, "critical", 5),

    ("Citrix Bleed internet gateway (KEV, crown jewel)",
     {"cvss_score": 9.4, "epss_score": 0.86, "kev": True, "exploit_available": True,
      "exploit_sources": ["CISA KEV", "Nuclei template"], "asset_tier": "crown_jewel"},
     90, "critical", 5),

    # ---- Weaponized but not yet KEV (high tier) ----
    ("Public exploit, CVSS 8.1, server, moderate EPSS",
     {"cvss_score": 8.1, "epss_score": 0.35, "kev": False, "exploit_available": True,
      "exploit_sources": ["ExploitDB:51234"], "asset_tier": "server"},
     60, "high", 4),

    ("Atlassian Confluence OGNL RCE, verified exploit",
     {"cvss_score": 9.8, "epss_score": 0.75, "kev": False, "exploit_available": True,
      "exploit_sources": ["Metasploit", "ExploitDB:verified"], "asset_tier": "server"},
     15, "high", 4),

    ("High EPSS (0.72), no public exploit yet, workstation",
     {"cvss_score": 6.5, "epss_score": 0.72, "kev": False, "exploit_available": False,
      "asset_tier": "workstation"},
     30, "high", 4),

    ("High EPSS, no exploit yet, crown-jewel identity system",
     {"cvss_score": 7.2, "epss_score": 0.66, "kev": False, "exploit_available": False,
      "asset_tier": "crown_jewel"},
     10, "high", 4),

    # ---- Moderate ----
    ("Single public exploit, low CVSS 5.0, endpoint",
     {"cvss_score": 5.0, "epss_score": 0.10, "kev": False, "exploit_available": True,
      "exploit_sources": ["PoC reference"], "asset_tier": "endpoint"},
     200, "moderate", 3),

    ("Weak blog PoC, high CVSS, low EPSS endpoint",
     {"cvss_score": 8.8, "epss_score": 0.08, "kev": False, "exploit_available": True,
      "exploit_sources": ["blog PoC reference"], "asset_tier": "endpoint"},
     20, "moderate", 3),

    # ---- Low / theoretical (must NOT outrank exploited) ----
    ("High CVSS 9.8 but NO exploit / NO KEV / negligible EPSS",
     {"cvss_score": 9.8, "epss_score": 0.02, "kev": False, "exploit_available": False,
      "asset_tier": "endpoint"},
     800, "low", 2),

    ("Crown-jewel high CVSS but no exploitation signal",
     {"cvss_score": 9.6, "epss_score": 0.04, "kev": False, "exploit_available": False,
      "asset_tier": "crown_jewel"},
     15, "low", 2),

    ("Medium CVSS 5.5, no exploit signals, laptop",
     {"cvss_score": 5.5, "epss_score": 0.03, "kev": False, "exploit_available": False,
      "asset_tier": "laptop"},
     400, "low", 2),

    # ---- Minimal ----
    ("Low-severity config finding, no CVE signals",
     {"cvss_score": 3.1, "epss_score": 0.01, "kev": False, "exploit_available": False,
      "asset_tier": "endpoint"},
     1000, "minimal", 1),

    ("Informational, no exploitability signals at all",
     {"cvss_score": 0.0, "epss_score": 0.0, "kev": False, "exploit_available": False,
      "asset_tier": "unknown"},
     0, "minimal", 1),
]


def _score(scn):
    _, finding, age_days, _, _ = scn
    pub = NOW - age_days * DAY if age_days else None
    return S.compute(finding, cve_published_ts=pub, now=NOW)


# ── Pytest test cases ──────────────────────────────────────────────────────────

def test_band_accuracy():
    """Computed band matches analyst-expected band for every scenario."""
    mismatches = []
    for scn in SCENARIOS:
        name, _, _, expected_band, _ = scn
        r = _score(scn)
        if r.band != expected_band:
            mismatches.append(f"{name}: got {r.band} ({r.score}), expected {expected_band}")
    assert not mismatches, "Band mismatches:\n" + "\n".join(mismatches)


def test_active_exploitation_outranks_theoretical():
    """Every KEV/exploited case must outrank every no-signal high-CVSS case."""
    exploited = [_score(s).score for s in SCENARIOS if s[1].get("kev") or s[1].get("exploit_available")]
    theoretical = [_score(s).score for s in SCENARIOS
                   if not s[1].get("kev") and not s[1].get("exploit_available")
                   and s[1].get("epss_score", 0) < 0.50
                   and s[1].get("cvss_score", 0) >= 7.0]
    assert exploited and theoretical
    assert min(exploited) > max(theoretical), (
        f"active-exploitation floor min={min(exploited)} must exceed "
        f"theoretical max={max(theoretical)}"
    )


def test_kev_floor_always_critical():
    """KEV-listed findings must always land in the critical band regardless of CVSS."""
    for scn in SCENARIOS:
        if scn[1].get("kev"):
            r = _score(scn)
            assert r.band == "critical" and r.score >= 90, f"{scn[0]}: {r.score}/{r.band}"


def test_expected_tier_ranking_monotonic():
    """Higher expected-tier scenarios must score >= lower-tier scenarios (by tier mean)."""
    from statistics import mean
    by_tier: dict[int, list[float]] = {}
    for scn in SCENARIOS:
        by_tier.setdefault(scn[4], []).append(_score(scn).score)
    tier_means = {t: mean(v) for t, v in by_tier.items()}
    ordered = [tier_means[t] for t in sorted(tier_means)]
    assert ordered == sorted(ordered), f"tier means not monotonic: {tier_means}"


def test_no_benign_outranks_critical():
    """No 'minimal'/'low' scenario may score above any 'critical' scenario."""
    crit = [_score(s).score for s in SCENARIOS if s[3] == "critical"]
    benign = [_score(s).score for s in SCENARIOS if s[3] in ("minimal", "low")]
    assert min(crit) > max(benign)


def test_exploit_source_quality_calibration():
    """Verified/weaponized sources must outrank a weak PoC-only reference."""
    base = {
        "cvss_score": 8.8,
        "epss_score": 0.08,
        "kev": False,
        "exploit_available": True,
        "asset_tier": "endpoint",
    }
    weak = S.compute({**base, "exploit_sources": ["blog PoC reference"]}, now=NOW)
    strong = S.compute({**base, "exploit_sources": ["Metasploit"]}, now=NOW)

    weak_factor = next(f for f in weak.factors if f.factor == "exploit_available")
    strong_factor = next(f for f in strong.factors if f.factor == "exploit_available")

    assert strong_factor.value > weak_factor.value
    assert strong.score > weak.score
    assert "Weaponized + CVSS" not in weak.escalations
    assert "Weaponized + CVSS≥7 floor (78)" in strong.escalations


# ── Standalone accuracy report ─────────────────────────────────────────────────

def run_report() -> int:
    print("=" * 78)
    print("DETECTION / PRIORITIZATION ACCURACY REPORT")
    print("=" * 78)
    correct = 0
    rows = []
    for scn in SCENARIOS:
        name, _, _, expected, _ = scn
        r = _score(scn)
        ok = r.band == expected
        correct += ok
        rows.append((ok, r.score, r.band, expected, name, r.escalations))

    # Sort by score desc to show the prioritized queue
    rows.sort(key=lambda x: -x[1])
    print(f"\n{'✓/✗':>3}  {'score':>5}  {'band':>9}  {'expected':>9}   scenario")
    print("-" * 78)
    for ok, score, band, expected, name, esc in rows:
        mark = "✓" if ok else "✗"
        print(f"{mark:>3}  {score:>5.1f}  {band:>9}  {expected:>9}   {name[:40]}")
        if esc:
            print(f"{'':>32}↳ {', '.join(esc)}")

    acc = correct / len(SCENARIOS) * 100
    print("-" * 78)
    print(f"Band accuracy: {correct}/{len(SCENARIOS)} = {acc:.0f}%")

    # Ranking integrity checks
    checks = [
        ("active-exploitation outranks theoretical", _check(test_active_exploitation_outranks_theoretical)),
        ("KEV always critical",                      _check(test_kev_floor_always_critical)),
        ("tier ranking monotonic",                   _check(test_expected_tier_ranking_monotonic)),
        ("no benign outranks critical",              _check(test_no_benign_outranks_critical)),
        ("exploit source quality calibrated",         _check(test_exploit_source_quality_calibration)),
    ]
    print("\nRanking-integrity checks:")
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")

    all_ok = acc == 100 and all(p for _, p in checks)
    print("\nRESULT:", "ALL CHECKS PASS" if all_ok else "FAILURES DETECTED")
    return 0 if all_ok else 1


def _check(fn) -> bool:
    try:
        fn(); return True
    except AssertionError:
        return False


if __name__ == "__main__":
    import sys
    sys.exit(run_report())
