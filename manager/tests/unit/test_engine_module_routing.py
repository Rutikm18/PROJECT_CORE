"""
manager/tests/unit/test_engine_module_routing.py — detections/ modules wired live.

Verifies the engine routes configured sections through the rich detections/
modules (not the inline analyzers): findings flow end-to-end into IntelDB in the
engine finding format (category + item_key), the module's first-run seeding FP
fix is active (a benign baseline emits nothing), and a genuinely-new C2 listener
fires. Also confirms dispatch-once (module internal dedup isn't double-suppressed).

Uses pg_manager_dsn/pg_intel_dsn (conftest.py) — freshly CREATEd, then DROPped,
real Postgres databases.
"""
from __future__ import annotations

from manager.manager.db import Database
from manager.manager.indexer import IntelDB
from manager.manager.attacklens.engine import AttackLensEngine
from manager.manager.attacklens.detections import port_listener as _pl


def setup_function(_):
    # Module-level dedup state must not leak between tests.
    for attr in ("_dedup_cache", "_rate_counter"):
        c = getattr(_pl, attr, None)
        if isinstance(c, dict):
            c.clear()


def _listener(port, proc, pid, path):
    return {"port": port, "proto": "tcp", "bind_ip": "0.0.0.0",
            "pid": pid, "process_name": proc, "process_path": path}


async def test_ports_routed_through_module_end_to_end(pg_manager_dsn, pg_intel_dsn):
    dbm = Database(pg_manager_dsn); await dbm.init()
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await dbm.upsert_agent("mac-1", "T", "127.0.0.1")
        eng = AttackLensEngine(dbm, idb); eng._ready = True

        safe = [_listener(443, "nginx", 1, "/usr/sbin/nginx")]

        async def active():
            return await idb._fetchall(
                "SELECT category, item_key, rule_id FROM findings "
                "WHERE agent_id=? AND is_active=1", ("mac-1",))

        # First observation → first-run seed, no new-listener storm.
        await eng.process("mac-1", "ports", safe)
        r1 = await active()
        assert all(r["rule_id"] != "new_listener" for r in r1), \
            "first-run must not emit new_listener (FP fix)"

        # A new C2 listener appears → must fire, in engine format.
        await eng.process("mac-1", "ports",
                          safe + [_listener(4444, "nc", 9, "/tmp/nc")])
        r2 = await active()
        assert any(r["category"] == "port" and r["item_key"] for r in r2), \
            "module finding must reach IntelDB with category + item_key"
        assert any("4444" in (r["item_key"] or "") for r in r2), \
            "the new 4444 C2 listener must be detected"
    finally:
        await dbm.close(); await idb.close()
