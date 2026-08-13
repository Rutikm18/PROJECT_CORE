"""Executable positive/negative/boundary contracts for AL-DEV-001…009."""
from __future__ import annotations

import json

import pytest

from manager.manager.attacklens.detections.developer_security import RULE_SPECS, analyze


def _payload(capability: str, value: dict) -> dict:
    return {"capabilities": {capability: value}}


CASES = [
    # rule, positive, negative, boundary, boundary fires?
    ("AL-DEV-001",
     _payload("editor_extensions", {"items": [{"id": "x", "auto_activates": True, "unknown_publisher": True, "entrypoint_indicators": ["child_process"]}]}),
     _payload("editor_extensions", {"items": [{"id": "x", "auto_activates": True, "unknown_publisher": False, "entrypoint_indicators": ["child_process"]}]}),
     _payload("editor_extensions", {"items": [{"id": "x", "auto_activates": True, "installed_from_vsix": True, "entrypoint_indicators": []}]}), False),
    ("AL-DEV-002",
     _payload("mcp_servers", {"servers": [{"name": "x", "uses_latest": True, "env_keys": ["API_TOKEN"]}]}),
     _payload("mcp_servers", {"servers": [{"name": "x", "command": "server@1.2.3", "env_keys": []}]}),
     _payload("mcp_servers", {"servers": [{"name": "x", "uses_unpinned_ephemeral_runner": True, "env_keys": [], "capability_indicators": []}]}), False),
    ("AL-DEV-003",
     _payload("agent_cli_tools", {"path": [{"path": "/tmp/bin", "world_writable": True}]}),
     _payload("agent_cli_tools", {"path": [{"path": "/opt/bin", "world_writable": False}]}),
     _payload("agent_cli_tools", {"path": [{"path": "/unknown", "world_writable": None}]}), False),
    ("AL-DEV-004",
     _payload("browser_extensions", {"items": [{"id": "x", "native_messaging": True, "dangerous_permissions": ["cookies"]}]}),
     _payload("browser_extensions", {"items": [{"id": "x", "native_messaging": False, "dangerous_permissions": ["cookies"]}]}),
     _payload("browser_extensions", {"items": [{"id": "x", "native_messaging": True, "dangerous_permissions": []}]}), False),
    ("AL-DEV-005",
     _payload("native_messaging", {"items": [{"name": "x", "executable": "/tmp/host", "executable_meta": {"mode": "-rwxr-xr-x"}}]}),
     _payload("native_messaging", {"items": [{"name": "x", "executable": "/opt/host", "executable_meta": {"mode": "-rwxr-xr-x"}}]}),
     _payload("native_messaging", {"items": [{"name": "x", "executable": "/opt/host", "executable_meta": {"mode": "-rwxrwxr-x"}}]}), True),
    ("AL-DEV-006",
     _payload("git", {"users": [{"settings": [{"key": "core.hooksPath", "value": "/hooks"}]}]}),
     _payload("git", {"users": [{"settings": [{"key": "user.name", "value": "Alice"}]}]}),
     _payload("git", {"local": {"settings": [{"key": "core.sshCommand", "value": "wrapper"}]}}), True),
    ("AL-DEV-007",
     _payload("credential_locations", {"locations": [{"path": "/a/.env", "mode": "-rw-r--r--"}]}),
     _payload("credential_locations", {"locations": [{"path": "/a/.env", "mode": "-rw-------"}]}),
     _payload("credential_locations", {"locations": [{"path": "/a/.aws", "mode": "drwxr-xr-x"}]}), False),
    ("AL-DEV-008",
     _payload("listening_ports", {"items": [{"process": "ollama", "endpoint": "*:11434", "wildcard": True, "interesting": True}]}),
     _payload("listening_ports", {"items": [{"process": "ollama", "endpoint": "127.0.0.1:11434", "wildcard": False, "interesting": True}]}),
     _payload("listening_ports", {"items": [{"process": "unrelated", "endpoint": "*:9999", "wildcard": True, "interesting": False}]}), False),
    ("AL-DEV-009",
     _payload("docker", {"risk_posture": [{"id": "x", "privileged": True, "high_risk": True}]}),
     _payload("docker", {"risk_posture": [{"id": "x", "privileged": False, "network_mode": "bridge", "high_risk": False}]}),
     _payload("docker", {"risk_posture": [{"id": "x", "cap_add": ["SYS_ADMIN"], "high_risk": True}]}), True),
]


@pytest.mark.parametrize("rule_id,positive,negative,boundary,boundary_fires", CASES)
@pytest.mark.asyncio
async def test_rule_positive_negative_and_boundary(
    rule_id, positive, negative, boundary, boundary_fires,
):
    positive_hits = await analyze("agent", "developer_security", positive, object())
    negative_hits = await analyze("agent", "developer_security", negative, object())
    boundary_hits = await analyze("agent", "developer_security", boundary, object())

    assert rule_id in {hit["rule_id"] for hit in positive_hits}
    assert rule_id not in {hit["rule_id"] for hit in negative_hits}
    assert (rule_id in {hit["rule_id"] for hit in boundary_hits}) is boundary_fires


def test_rule_registry_is_complete_and_documents_boundaries():
    assert set(RULE_SPECS) == {f"AL-DEV-{index:03d}" for index in range(1, 10)}
    assert all(spec["condition"] and spec["boundary"] for spec in RULE_SPECS.values())


@pytest.mark.asyncio
async def test_detection_evidence_keeps_key_names_but_not_values():
    secret = "never-persist-this-value"
    payload = _payload("mcp_servers", {"servers": [{
        "name": "x", "uses_latest": True,
        "env_keys": ["OPENAI_API_KEY"],
        "env_value_presence": {"OPENAI_API_KEY": bool(secret)},
        "args": ["--api-key", "[REDACTED]"],
    }]})
    hits = await analyze("agent", "developer_security", payload, object())

    encoded = json.dumps(hits)
    assert secret not in encoded
    assert "OPENAI_API_KEY" in encoded
    assert "env_value_presence" not in encoded


@pytest.mark.asyncio
async def test_repeated_snapshot_deduplicates_and_material_evidence_updates(pg_intel_dsn):
    from manager.manager.indexer import IntelDB

    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        base = _payload("editor_extensions", {"items": [{
            "id": "x", "user": "alice", "editor": "vscode",
            "auto_activates": True, "unknown_publisher": True,
            "entrypoint_indicators": ["child_process"],
        }]})
        first = (await analyze("agent", "developer_security", base, object()))[0]
        first["agent_id"] = "agent"
        assert await idb.upsert_finding(first, 1_000.0) == "new"

        repeated = (await analyze("agent", "developer_security", base, object()))[0]
        repeated["agent_id"] = "agent"
        assert repeated["detection_fingerprint"] == first["detection_fingerprint"]
        assert await idb.upsert_finding(repeated, 1_100.0) == "unchanged"

        changed_payload = _payload("editor_extensions", {"items": [{
            "id": "x", "user": "alice", "editor": "vscode",
            "auto_activates": True, "unknown_publisher": True,
            "entrypoint_indicators": ["child_process", "spawn"],
        }]})
        changed = (await analyze("agent", "developer_security", changed_payload, object()))[0]
        changed["agent_id"] = "agent"
        assert changed["detection_fingerprint"] != first["detection_fingerprint"]
        assert await idb.upsert_finding(changed, 1_200.0) == "updated"

        rows = await idb.get_soc_findings(agent_id="agent", terrain_id="mesh")
        assert len(rows) == 1
        evidence = rows[0]["evidence"]
        if isinstance(evidence, str):
            evidence = json.loads(evidence)
        assert evidence["indicators"] == ["child_process", "spawn"]
    finally:
        await idb.close()
