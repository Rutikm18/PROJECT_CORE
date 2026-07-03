"""
manager/tests/unit/test_finding_lifecycle.py — finding triage state machine.

Pins the single source of truth for finding lifecycle: terminal vs active
statuses, the action→target map, transition validity, and the available_actions
the UI renders. Pure logic, no DB.
"""
from __future__ import annotations

from manager.manager import finding_lifecycle as lc


def test_terminal_vs_active_partition():
    # Every status is exactly one of active/terminal, and they cover ALL.
    assert lc.ACTIVE_STATUSES.isdisjoint(lc.TERMINAL_STATUSES)
    assert lc.ACTIVE_STATUSES | lc.TERMINAL_STATUSES == lc.ALL_STATUSES
    assert lc.is_terminal("closed") and lc.is_terminal("false_positive")
    assert not lc.is_terminal("new") and not lc.is_terminal("triaging")


def test_normalize_unknown_to_new():
    assert lc.normalize(None) == "new"
    assert lc.normalize("bogus") == "new"
    assert lc.normalize("investigating") == "investigating"


def test_available_actions_for_open_finding():
    acts = [a["action"] for a in lc.available_actions("new")]
    assert "close" in acts and "false_positive" in acts and "accept_risk" in acts
    assert "reopen" not in acts            # can't reopen an already-open finding


def test_available_actions_for_terminal_finding():
    acts = [a["action"] for a in lc.available_actions("closed")]
    assert acts == ["reopen"]              # the only thing you can do to a closed finding


def test_can_transition_enforces_state():
    assert lc.can_transition("new", "close")
    assert not lc.can_transition("closed", "close")      # already closed
    assert lc.can_transition("accepted_risk", "reopen")
    assert not lc.can_transition("new", "reopen")        # nothing to reopen


def test_action_aliases_resolve():
    assert lc.canonical_action("false-positive") == "false_positive"
    assert lc.canonical_action("accept-risk") == "accept_risk"
    assert lc.canonical_action("FP") == "false_positive"
    assert lc.canonical_action("garbage") is None


def test_target_status_mapping():
    assert lc.target_status("close") == "closed"
    assert lc.target_status("false_positive") == "false_positive"
    assert lc.target_status("accept_risk") == "accepted_risk"
    assert lc.target_status("reopen") == "triaging"


def test_accept_risk_needs_reason_flag():
    spec = {a["action"]: a for a in lc.available_actions("new")}
    assert spec["accept_risk"]["needs_reason"] is True
    assert spec["close"]["needs_reason"] is False


def test_available_actions_button_order_is_stable():
    # Buttons render in a fixed, sensible order regardless of dict iteration.
    order = [a["action"] for a in lc.available_actions("new")]
    assert order == ["open", "investigate", "close", "accept_risk", "false_positive"]
