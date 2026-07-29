"""Deep Analysis raw telemetry search contract."""
from __future__ import annotations

import time

from manager.manager.db import Database


async def _seed(dsn: str) -> Database:
    db = Database(dsn)
    await db.init()
    now = int(time.time())
    await db.upsert_agent("MAC-ALPHA", "Alpha", "127.0.0.1")
    await db.upsert_agent("mac-beta", "Beta", "127.0.0.2")
    await db.insert_payload(
        "MAC-ALPHA",
        "processes",
        now,
        [{"name": "OsqueryD", "path": "/opt/osquery/bin/osqueryd", "cpu_pct": 1.2}],
    )
    await db.insert_payload(
        "MAC-ALPHA",
        "connections",
        now + 1,
        [{"remote_address": "198.51.100.42", "process": "curl_100%"}],
    )
    await db.insert_payload(
        "mac-beta",
        "packages",
        now + 2,
        [{"name": "openssl", "version": "3.0.0"}],
    )
    return db


async def test_search_is_case_insensitive_across_all_sections(pg_manager_dsn):
    db = await _seed(pg_manager_dsn)
    try:
        rows = await db.query_payloads(search="OSQUERY")
        assert [(row["agent_id"], row["section"]) for row in rows] == [
            ("MAC-ALPHA", "processes")
        ]
        assert await db.count_payloads(search="osquery") == 1
    finally:
        await db.close()


async def test_search_respects_section_scope_and_count(pg_manager_dsn):
    db = await _seed(pg_manager_dsn)
    try:
        assert await db.count_payloads(search="MAC-ALPHA") == 2
        assert await db.count_payloads(section="processes", search="MAC-ALPHA") == 1
        assert await db.query_payloads(section="packages", search="MAC-ALPHA") == []
    finally:
        await db.close()


async def test_search_matches_section_and_agent_metadata(pg_manager_dsn):
    db = await _seed(pg_manager_dsn)
    try:
        section_rows = await db.query_payloads(search="CONNECTIONS")
        agent_rows = await db.query_payloads(search="mac-beta")
        assert [row["section"] for row in section_rows] == ["connections"]
        assert [row["section"] for row in agent_rows] == ["packages"]
    finally:
        await db.close()


async def test_search_treats_sql_wildcards_as_literal_text(pg_manager_dsn):
    db = await _seed(pg_manager_dsn)
    try:
        rows = await db.query_payloads(search="curl_100%")
        assert [row["section"] for row in rows] == ["connections"]
        assert await db.count_payloads(search="%") == 1
        assert await db.count_payloads(search="_") == 2
    finally:
        await db.close()
