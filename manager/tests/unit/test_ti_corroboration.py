"""
manager/tests/unit/test_ti_corroboration.py — TI corroboration scoring.

Pins the deterministic threat-intel corroboration factor used by the precision
validator, with focus on the newly-wired `exploit_available` source: a CVE with
public exploit code (ExploitDB / Metasploit / PoC) must now earn corroboration
credit instead of being ignored. KEV stays the strongest single source.
"""
from __future__ import annotations

from manager.manager.attacklens.ai_validator import _ti_corroboration_score


def test_no_intel_scores_zero():
    assert _ti_corroboration_score({}) == 0.0


def test_exploit_available_is_credited():
    # Previously this scored 0.0 (exploit availability was never consumed).
    score = _ti_corroboration_score({"exploit_available": True})
    assert score == 0.30


def test_exploit_ranks_below_kev_above_ip():
    kev = _ti_corroboration_score({"kev_hit": True})
    expl = _ti_corroboration_score({"exploit_available": True})
    ip = _ti_corroboration_score({"malicious_ip_hit": True})
    assert kev > expl > ip


def test_two_sources_get_corroboration_bonus():
    # KEV (0.45) + exploit (0.30) = 0.75, plus +0.10 ≥2-source bonus = 0.85.
    score = _ti_corroboration_score({"kev_hit": True, "exploit_available": True})
    assert abs(score - 0.85) < 1e-9


def test_score_is_capped_at_one():
    score = _ti_corroboration_score({
        "kev_hit": True,
        "malicious_hash_hit": True,
        "exploit_available": True,
        "malicious_ip_hit": True,
        "epss_scores": [0.9],
    })
    assert score == 1.0
