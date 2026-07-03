"""
manager/manager/attacklens/finding_lifecycle.py — the single source of truth for
finding triage state.

Every detected finding has a stable unique id (numeric `id` + human `external_id`
like AL-F-00000042) and a lifecycle status. Analysts move a finding through that
lifecycle with ACTIONS (open / close / accept-risk / false-positive / reopen…).
Before this module, the state machine was duplicated in ~11 places — the
terminal-status set, the "what closes a finding" rules, and the implicit
allowed-transitions — each able to drift from the others. This centralizes:

  • the canonical status vocabulary,
  • which statuses are TERMINAL (resolved → is_active=0) vs ACTIVE (open),
  • the action → target-status map and which states each action is valid FROM,
  • `available_actions(status)` so EVERY page (All Incidents, Attack Terrain
    Origin/Vector/Citadels, Validated Findings) renders the SAME, correct set
    of action buttons for a finding given its current state.

Keep all triage-state logic here; callers import, never re-hardcode.
"""
from __future__ import annotations

# ── Canonical statuses ────────────────────────────────────────────────────────
NEW            = "new"
TRIAGING       = "triaging"
INVESTIGATING  = "investigating"
IN_REMEDIATION = "in_remediation"
REMEDIATED     = "remediated"
VERIFIED       = "verified"
CLOSED         = "closed"
FALSE_POSITIVE = "false_positive"
ACCEPTED_RISK  = "accepted_risk"
DUPLICATE      = "duplicate"

ALL_STATUSES: frozenset[str] = frozenset({
    NEW, TRIAGING, INVESTIGATING, IN_REMEDIATION, REMEDIATED,
    VERIFIED, CLOSED, FALSE_POSITIVE, ACCEPTED_RISK, DUPLICATE,
})

# Terminal = the finding is resolved and drops off the active board (is_active=0,
# closed_at set, SLA stops). Everything else is an ACTIVE/open state.
TERMINAL_STATUSES: frozenset[str] = frozenset({
    CLOSED, FALSE_POSITIVE, ACCEPTED_RISK, VERIFIED, REMEDIATED, DUPLICATE,
})
ACTIVE_STATUSES: frozenset[str] = ALL_STATUSES - TERMINAL_STATUSES

# Statuses that represent an analyst-confirmed resolution (feed the FP/TP
# feedback loop and "resolved" timeline events).
RESOLUTION_STATUSES: frozenset[str] = frozenset({
    CLOSED, FALSE_POSITIVE, ACCEPTED_RISK, VERIFIED,
})


def is_terminal(status: str | None) -> bool:
    return (status or NEW) in TERMINAL_STATUSES


def normalize(status: str | None) -> str:
    """Map a missing/unknown status to the canonical default (new)."""
    return status if status in ALL_STATUSES else NEW


# ── Actions (what an analyst can DO to a finding) ─────────────────────────────
# Each action declares: the target status it moves the finding INTO, the set of
# current statuses it is valid FROM, a UI label, an intent kind (the UI uses
# this to colour/group buttons), and whether it requires a justification note.
ACTIONS: dict[str, dict] = {
    "open": {
        "target": TRIAGING,
        "from":   frozenset({NEW}),
        "label":  "Open",
        "kind":   "primary",
        "needs_reason": False,
    },
    "investigate": {
        "target": INVESTIGATING,
        "from":   frozenset({NEW, TRIAGING}),
        "label":  "Investigate",
        "kind":   "primary",
        "needs_reason": False,
    },
    "close": {
        "target": CLOSED,
        "from":   ACTIVE_STATUSES,
        "label":  "Close",
        "kind":   "resolve",
        "needs_reason": False,
    },
    "accept_risk": {
        "target": ACCEPTED_RISK,
        "from":   ACTIVE_STATUSES,
        "label":  "Accept Risk",
        "kind":   "resolve",
        "needs_reason": True,
    },
    "false_positive": {
        "target": FALSE_POSITIVE,
        "from":   ACTIVE_STATUSES,
        "label":  "False Positive",
        "kind":   "dismiss",
        "needs_reason": False,
    },
    "reopen": {
        "target": TRIAGING,
        "from":   TERMINAL_STATUSES,
        "label":  "Reopen",
        "kind":   "primary",
        "needs_reason": False,
    },
}

# Alias map: the action keys the HTTP layer / UI may use → canonical action.
ACTION_ALIASES: dict[str, str] = {
    "accept-risk":    "accept_risk",
    "acceptrisk":     "accept_risk",
    "false-positive": "false_positive",
    "fp":             "false_positive",
    "triage":         "open",
}


def canonical_action(action: str) -> str | None:
    """Resolve an action key (with aliases) to a canonical action, or None."""
    if not action:
        return None
    a = action.strip().lower()
    a = ACTION_ALIASES.get(a, a)
    return a if a in ACTIONS else None


def can_transition(current_status: str | None, action: str) -> bool:
    """True if `action` is valid from `current_status`."""
    a = canonical_action(action)
    if a is None:
        return False
    return normalize(current_status) in ACTIONS[a]["from"]


def target_status(action: str) -> str | None:
    """The status an action moves a finding into (or None if unknown action)."""
    a = canonical_action(action)
    return ACTIONS[a]["target"] if a else None


def available_actions(status: str | None) -> list[dict]:
    """The actions an analyst may take on a finding in `status`, ready for the
    UI to render as buttons. Returned in a stable, sensible button order.

    Each entry: {action, label, kind, needs_reason, target_status}.
    """
    cur = normalize(status)
    order = ["open", "investigate", "close", "accept_risk", "false_positive", "reopen"]
    out: list[dict] = []
    for key in order:
        spec = ACTIONS[key]
        if cur in spec["from"]:
            out.append({
                "action":        key,
                "label":         spec["label"],
                "kind":          spec["kind"],
                "needs_reason":  spec["needs_reason"],
                "target_status": spec["target"],
            })
    return out
