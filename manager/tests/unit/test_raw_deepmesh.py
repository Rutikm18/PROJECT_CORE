"""DeepMesh backend contract — section-aware preview/summary + lazy record fetch.

Covers the raw-API improvements that back the DeepMesh page:
  • developer_security gets a capability-count preview + structured summary
    (the generic dict preview would only show schema_version/platform).
  • _record_count sums capability records instead of returning 1 for a dict.
  • get_payload_by_id returns one full payload (lazy expand after a
    metadata-only list) and None for a missing id.
"""
from __future__ import annotations

import time

from manager.manager.db import Database
from manager.manager.api.raw import (
    _data_preview, _record_count, _section_summary,
)


_DEVSEC = {
    "schema_version": 1,
    "platform": "macos",
    "capabilities": {
        "editor_extensions": {"items": [{"id": "a"}, {"id": "b"}], "count": 2},
        "mcp_servers": {"servers": [{"name": "m"}], "count": 1},
        "browser_extensions": {"items": [{"id": "x"}]},
        "agent_cli_tools": {"items": [{"command": "claude", "found": True}]},
        "listening_ports": {"items": []},
        "native_messaging": {"items": []},
        "docker": {"error": "FileNotFoundError"},
    },
    "collection": {"partial": True, "errors": [{"capability": "docker", "error": "x"}],
                   "duration_ms": 1234},
}


def test_devsec_preview_shows_capability_counts():
    preview = _data_preview(_DEVSEC, "developer_security")
    assert "ext=2" in preview and "mcp=1" in preview and "browser=1" in preview
    assert "partial" in preview
    # The useless generic preview must NOT be what we return.
    assert "schema_version" not in preview


def test_devsec_summary_structure():
    s = _section_summary(_DEVSEC, "developer_security")
    assert s is not None
    # Counts are keyed by capability name and cover every capability.
    assert s["counts"]["editor_extensions"] == 2
    assert s["counts"]["mcp_servers"] == 1
    assert s["counts"]["browser_extensions"] == 1
    assert s["counts"]["agent_cli_tools"] == 1
    assert s["counts"]["listening_ports"] == 0
    assert s["counts"]["docker"] == 0        # errored capability → 0 records
    assert s["partial"] is True
    assert s["error_count"] == 1
    # docker errored → not counted among present capabilities
    assert s["capabilities_present"] == 6


def test_record_count_sums_devsec_capabilities():
    # 2 ext + 1 mcp + 1 browser + 1 cli = 5
    assert _record_count(_DEVSEC, "developer_security") == 5
    # non-devsec sections keep list/dict semantics
    assert _record_count([1, 2, 3], "processes") == 3


def test_non_devsec_sections_unaffected():
    assert _section_summary([{"pid": 1}], "processes") is None
    assert "pid=1" in _data_preview([{"pid": 1}], "processes")


async def test_get_payload_by_id_roundtrip(pg_manager_dsn):
    db = Database(pg_manager_dsn)
    await db.init()
    try:
        now = int(time.time())
        await db.upsert_agent("mac-dm", "DM", "127.0.0.1")
        await db.insert_payload("mac-dm", "developer_security", now, _DEVSEC)
        rows = await db.query_payloads(section="developer_security")
        assert len(rows) == 1
        pid = rows[0]["id"]

        full = await db.get_payload_by_id(pid)
        assert full is not None
        assert full["section"] == "developer_security"
        assert full["agent_id"] == "mac-dm"
        assert full["data"]["capabilities"]["mcp_servers"]["count"] == 1

        assert await db.get_payload_by_id(999_999) is None
    finally:
        await db.close()
