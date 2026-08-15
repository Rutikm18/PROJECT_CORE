"""
manager/tests/unit/test_devsec_composite_schema.py — first-class validation for
the developer_security (Deep Mesh) composite section.

Historically `validate_section("developer_security", …)` only checked the seven
top-level envelope fields and that `capabilities` was *a dict* — the 17 named
capabilities inside it (each a record list under a capability-specific key, or an
{"error": …} collector stub) were never structurally validated, so a malformed
capability (e.g. a string where a list belongs) was stored as a silent blank and
counted wrong by the Deep Mesh nav. These tests pin the composite contract:

  • each capability is either an {"error": …} stub or a dict,
  • the capability's declared record key (items/servers/users/… per
    DEVSEC_CAPABILITY_ITEMS) is a list when present,
  • homebrew's formulae/casks are lists when present,
  • unknown capabilities are allowed (forward-compat) but must be dict-shaped,
  • the items-key map is a single source of truth shared with raw.py (no drift).

Deep per-record field validation is intentionally NOT asserted — records are
heterogeneous, capped, and redacted at the agent; the contract that matters
downstream is the structural shape.
"""
from __future__ import annotations

from shared.schema import DEVSEC_CAPABILITY_ITEMS, validate_section


def _snapshot(capabilities: dict, **collection_overrides) -> dict:
    """A structurally-complete developer_security envelope wrapping the given
    capability map, so tests exercise the composite validator, not the envelope."""
    collection = {
        "state": "complete",
        "partial": False,
        "errors": [],
        "issues": [],
        "capability_states": {},
        "duration_ms": 12,
    }
    collection.update(collection_overrides)
    return {
        "schema_version": 1,
        "collector_version": "macos-developer-security/2",
        "platform": "macos",
        "scope": {"users": ["u1"], "system_context": False},
        "privacy": {"secret_contents_collected": False},
        "capabilities": capabilities,
        "collection": collection,
    }


# ── Happy path ────────────────────────────────────────────────────────────

def test_realistic_snapshot_is_valid():
    caps = {
        "editor_extensions":   {"count": 1, "items": [{"id": "ms-python.python"}]},
        "mcp_servers":         {"count": 1, "servers": [{"name": "filesystem"}]},
        "homebrew":            {"formulae": [{"name": "git"}], "casks": []},
        "cron":                {"users": [{"user": "u1", "entries": []}]},
        "credential_locations": {"locations": [{"path": "~/.aws/credentials"}]},
        "docker":              {"containers": []},
        "shell_startup":       {"files": [{"path": "~/.zshrc"}]},
        # a capability whose collector raised — valid, expected shape
        "listening_ports":     {"error": "TimeoutError"},
    }
    assert validate_section("developer_security", _snapshot(caps)) == []


def test_empty_capabilities_map_is_valid():
    # A collector that reports no capabilities yet is still structurally valid.
    assert validate_section("developer_security", _snapshot({})) == []


def test_capability_with_count_but_no_items_key_is_valid():
    # count-only (no record list shipped) must not be forced to carry the key.
    caps = {"processes": {"count": 0}}
    assert validate_section("developer_security", _snapshot(caps)) == []


# ── Capability structural failures ──────────────────────────────────────────

def test_non_dict_capability_is_flagged():
    caps = {"mcp_servers": ["not", "a", "dict"]}
    errors = validate_section("developer_security", _snapshot(caps))
    assert any("capabilities.mcp_servers" in e and "expected object" in e for e in errors), errors


def test_wrong_items_key_type_is_flagged():
    caps = {"editor_extensions": {"items": "should-be-a-list"}}
    errors = validate_section("developer_security", _snapshot(caps))
    assert any(
        "capabilities.editor_extensions.items" in e and "expected list" in e
        for e in errors
    ), errors


def test_capability_specific_key_is_respected():
    # mcp_servers stores its list under "servers", not "items".
    caps = {"mcp_servers": {"servers": "should-be-a-list"}}
    errors = validate_section("developer_security", _snapshot(caps))
    assert any(
        "capabilities.mcp_servers.servers" in e and "expected list" in e
        for e in errors
    ), errors


def test_homebrew_formulae_and_casks_must_be_lists():
    caps = {"homebrew": {"formulae": "git", "casks": []}}
    errors = validate_section("developer_security", _snapshot(caps))
    assert any(
        "capabilities.homebrew.formulae" in e and "expected list" in e
        for e in errors
    ), errors


def test_error_stub_capability_is_accepted():
    caps = {"docker": {"error": "insufficient_privilege"}}
    assert validate_section("developer_security", _snapshot(caps)) == []


# ── Forward-compatibility ───────────────────────────────────────────────────

def test_unknown_capability_is_allowed_when_dict_shaped():
    # A capability the manager doesn't know about yet must not fail ingest.
    caps = {"future_capability": {"count": 3, "items": [{"x": 1}]}}
    assert validate_section("developer_security", _snapshot(caps)) == []


def test_unknown_capability_still_must_be_a_dict():
    caps = {"future_capability": 42}
    errors = validate_section("developer_security", _snapshot(caps))
    assert any("capabilities.future_capability" in e for e in errors), errors


# ── Envelope contract preserved ─────────────────────────────────────────────

def test_missing_capabilities_still_flagged_by_envelope():
    snap = _snapshot({})
    del snap["capabilities"]
    errors = validate_section("developer_security", snap)
    assert any("capabilities" in e and "required" in e for e in errors), errors


def test_capabilities_not_a_dict_flagged_by_envelope():
    snap = _snapshot({})
    snap["capabilities"] = ["nope"]
    errors = validate_section("developer_security", snap)
    assert any("capabilities" in e for e in errors), errors


# ── Single source of truth (no drift with raw.py) ───────────────────────────

def test_items_key_map_is_shared_with_raw_module():
    # raw.py must consume the same canonical map, not its own copy — otherwise
    # the Deep Mesh counts and this validator can silently disagree.
    from manager.manager.api import raw
    assert raw._DEVSEC_CAP_ITEMS is DEVSEC_CAPABILITY_ITEMS


def test_map_covers_all_seventeen_collector_capabilities():
    expected = {
        "editor_extensions", "mcp_servers", "node_packages", "python_packages",
        "homebrew", "ai_applications", "agent_cli_tools", "shell_startup",
        "launchd", "cron", "processes", "listening_ports", "browser_extensions",
        "native_messaging", "git", "credential_locations", "docker",
    }
    assert set(DEVSEC_CAPABILITY_ITEMS) == expected
