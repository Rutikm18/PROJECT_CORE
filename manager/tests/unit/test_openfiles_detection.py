from __future__ import annotations

import asyncio

from manager.manager.attacklens.engine import AttackLensEngine
from manager.manager.attacklens.rulepack import RulePackDetector


def _run(coro):
    return asyncio.run(coro)


def _engine() -> AttackLensEngine:
    return AttackLensEngine.__new__(AttackLensEngine)


def test_live_openfiles_fd_anomaly_emits_open_file_finding() -> None:
    eng = _engine()

    findings = _run(eng._openfiles("agent-1", [{
        "pid": 4242,
        "process": "python3",
        "fd_count": 1250,
        "user": "alice",
    }]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "open_file"
    assert finding["source"] == "rule:openfiles_fd_anomaly"
    assert finding["severity"] == "medium"
    assert finding["confidence"] >= 0.70
    assert finding["evidence"]["live_schema_limitation"]


def test_live_openfiles_common_desktop_process_is_not_flagged() -> None:
    eng = _engine()

    findings = _run(eng._openfiles("agent-1", [{
        "pid": 100,
        "process": "Google Chrome Helper",
        "fd_count": 1800,
        "user": "alice",
    }]))

    assert findings == []


def test_dispatch_runs_openfiles_analyzer_for_agent_section() -> None:
    eng = _engine()
    eng._rulepack = RulePackDetector.load()
    eng._feeds = None

    findings = _run(eng._dispatch("agent-1", "openfiles", [{
        "pid": 4242,
        "process": "python3",
        "fd_count": 1250,
        "user": "alice",
    }]))

    assert any(f["source"] == "rule:openfiles_fd_anomaly" for f in findings)
    assert any(f["category"] == "open_file" for f in findings)
