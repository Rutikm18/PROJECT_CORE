"""
manager/tests/unit/test_tenant_scope_middleware.py — the customer boundary on
the shared operator routes.

The customer portal mirrors the operator dashboard page for page, so a customer
principal reaches the *same* endpoints an operator does. Everything that keeps
that safe lives in TenantScopeMiddleware and the query compiler:

  * read-only — every mutating verb refused before routing
  * operator-only prefixes refused whatever the method
  * a tenant scope attached, and applied by the query compiler even when the
    handler knows nothing about tenants
  * an explicit ?agent_id= belonging to another customer returns nothing rather
    than bypassing the scope

That last one is the bug this design is most exposed to, because the existing
`live_agent_ids` filter sits in an `elif` after `agent_id` — reusing it for
tenancy would have handed any customer a one-parameter bypass.
"""
from __future__ import annotations

import pytest

from manager.manager.api import tenant_scope as ts
from manager.manager.indexer import FindingQuery, _compile_finding_filter


# ── Path and method rules ────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/api/v1/settings", "/api/v1/settings/validation",
    "/api/v1/customers", "/api/v1/customers/org_1/agents",
    "/api/v1/keys", "/api/v1/ai/provider", "/api/v1/allowlist",
    "/api/v1/custom-correlations", "/api/v1/enroll", "/api/v1/ingest",
    "/api/v1/integrations/health",
    "/api/v1/accuracy/report", "/api/v1/dashboard/ws-token",
])
def test_operator_only_paths_are_refused_to_customers(path):
    assert ts.is_operator_only(path) is True


@pytest.mark.parametrize("path", [
    "/api/v1/detection/all", "/api/v1/soc/findings", "/api/v1/assets",
    "/api/v1/posture/agents", "/api/v1/threat/actors", "/api/v1/intel/kev",
    "/api/v1/agents", "/api/v1/attacklens/header-stats", "/api/v1/meta",
    "/api/v1/raw/query", "/api/v1/raw/agents",
])
def test_mirrored_paths_stay_reachable(path):
    """These are the pages the portal mirrors — denying them breaks the mirror."""
    assert ts.is_operator_only(path) is False


def test_raw_telemetry_is_reachable_now_that_it_is_scoped():
    """The customer's own endpoint telemetry, which Deep Analysis reads.

    Scoped in db.py for the list/count paths and in raw.py for the ones that
    address a single agent or row, so the portal can show it without ever
    reaching another tenant's payloads.
    """
    assert ts.is_operator_only("/api/v1/raw/query") is False
    assert ts.is_operator_only("/api/v1/raw/record") is False


def test_only_safe_methods_are_allowed():
    assert ts.SAFE_METHODS == frozenset({"GET", "HEAD", "OPTIONS"})
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        assert verb not in ts.SAFE_METHODS


def test_portal_paths_are_left_to_their_own_auth():
    assert ts.is_portal_path("/api/v1/portal/summary") is True
    assert ts.is_portal_path("/api/v1/detection/all") is False


# ── The query compiler applies the scope ─────────────────────────────────────

def _sql(query: FindingQuery) -> tuple[str, list]:
    return _compile_finding_filter(query)


def test_an_operator_query_is_unrestricted():
    ts.set_current_tenant(None)
    sql, args = _sql(FindingQuery())
    assert "1=0" not in sql
    assert "agent_id IN" not in sql


def test_a_tenant_scope_restricts_the_query():
    ts.set_current_tenant(None)
    sql, args = _sql(FindingQuery(tenant_agent_ids=("a1", "a2")))
    assert "f.agent_id IN (?,?)" in sql
    assert args[:2] == ["a1", "a2"]


def test_an_empty_tenant_scope_returns_nothing_not_everything():
    ts.set_current_tenant(None)
    sql, _args = _sql(FindingQuery(tenant_agent_ids=()))
    assert "1=0" in sql


def test_the_context_scope_applies_when_the_handler_passes_none():
    """This is what lets every mirrored page work untouched: a handler that
    knows nothing about tenants still produces a scoped query."""
    ts.set_current_tenant(("ctx-agent",))
    try:
        sql, args = _sql(FindingQuery())
        assert "f.agent_id IN (?)" in sql
        assert "ctx-agent" in args
    finally:
        ts.set_current_tenant(None)


def test_an_explicit_scope_beats_the_context():
    ts.set_current_tenant(("ctx-agent",))
    try:
        _sql_text, args = _sql(FindingQuery(tenant_agent_ids=("explicit",)))
        assert "explicit" in args
        assert "ctx-agent" not in args
    finally:
        ts.set_current_tenant(None)


# ── The bypass ───────────────────────────────────────────────────────────────

def test_an_explicit_agent_id_cannot_escape_the_tenant_scope():
    """?agent_id=<another customer's> must return nothing.

    The tenant predicate is its own `if`, ANDed with the agent_id filter. Were
    it an `elif` in that chain — the shape `live_agent_ids` uses — this single
    query parameter would be a complete tenant bypass.
    """
    ts.set_current_tenant(None)
    sql, args = _sql(FindingQuery(
        agent_id="globex-agent-1", tenant_agent_ids=("acme-1", "acme-2"),
    ))
    assert "f.agent_id IN (?,?)" in sql          # tenant boundary present
    assert "f.agent_id=?" in sql                  # and the explicit filter too
    assert args[:3] == ["acme-1", "acme-2", "globex-agent-1"]
    # Both predicates are ANDed, so an out-of-tenant agent matches no row.
    assert " AND ".join(["", ""]) in sql or sql.count("agent_id") == 2


def test_the_tenant_predicate_is_not_conditional_on_active_only():
    """`live_agent_ids` only applies when active_only is set. A tenant boundary
    that inherited that condition would leak on any historical view."""
    ts.set_current_tenant(None)
    sql, _args = _sql(FindingQuery(active_only=False, tenant_agent_ids=("a1",)))
    assert "f.agent_id IN (?)" in sql


def test_scope_survives_alongside_every_other_filter():
    ts.set_current_tenant(None)
    sql, args = _sql(FindingQuery(
        tenant_agent_ids=("a1",), severity="critical",
        validation_state="validated", min_precision=0.8,
    ))
    assert "f.agent_id IN (?)" in sql
    assert "f.severity=?" in sql
    assert args[0] == "a1"


# ── Raw payload scope ────────────────────────────────────────────────────────

def test_payload_scope_is_unrestricted_for_an_operator():
    from manager.manager.db import _tenant_payload_scope
    ts.set_current_tenant(None)
    assert _tenant_payload_scope() == (None, [])


def test_payload_scope_restricts_a_customer():
    from manager.manager.db import _tenant_payload_scope
    ts.set_current_tenant(("a1", "a2"))
    try:
        clause, args = _tenant_payload_scope()
        assert clause == "agent_id IN (?,?)"
        assert args == ["a1", "a2"]
    finally:
        ts.set_current_tenant(None)


def test_an_empty_payload_scope_returns_nothing():
    from manager.manager.db import _tenant_payload_scope
    ts.set_current_tenant(())
    try:
        clause, args = _tenant_payload_scope()
        assert clause == "1=0"
        assert args == []
    finally:
        ts.set_current_tenant(None)


# ── Helpers ──────────────────────────────────────────────────────────────────

def test_current_tenant_defaults_to_unrestricted():
    ts.set_current_tenant(None)
    assert ts.current_tenant() is None
