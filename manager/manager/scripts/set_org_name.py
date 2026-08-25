"""
set_org_name.py — set the organization name from the server.

The org name is set once from the dashboard and then locked; the dashboard can no
longer change it. This command is the only way to change it afterwards. It writes
straight to the settings store (bypassing the lock) and records an audit row.

Run inside the manager container:

    python -m manager.manager.scripts.set_org_name --name "Acme Corp"

The Makefile wraps this: `make set-org-name NAME="Acme Corp"`.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

from ..indexer import IntelDB

_MAX_LEN = 200


def _resolve_intel_dsn() -> str:
    database_url = os.environ.get(
        "DATABASE_URL", "postgresql://attacklens:attacklens@localhost:5432"
    ).rstrip("/")
    return os.environ.get("INTEL_DATABASE_URL", f"{database_url}/intel")


async def apply_org_name(intel: IntelDB, name: str, *, actor: str = "server-cli") -> str:
    """Write org_name to org_settings + audit, in one transaction. Returns the
    previous value it replaced."""
    ts = time.time()
    async with intel._lock:
        async with intel.write_txn():
            old_row = await intel._fetchone(
                "SELECT value FROM org_settings WHERE key=?", ("org_name",)
            )
            old = old_row["value"] if old_row else ""
            await intel._conn.execute(
                "INSERT INTO org_settings(key,value,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET "
                "value=excluded.value, updated_at=excluded.updated_at",
                ("org_name", name, ts),
            )
            if old != name:
                await intel._conn.execute(
                    "INSERT INTO settings_audit(key,old_value,new_value,actor,ip,changed_at) "
                    "VALUES(?,?,?,?,?,?)",
                    ("org_name", old, name, actor, "cli", ts),
                )
    return old


async def _run(name: str) -> int:
    name = name.strip()
    if not name:
        print("error: NAME must not be empty", file=sys.stderr)
        return 2
    if len(name) > _MAX_LEN:
        print(f"error: NAME must be at most {_MAX_LEN} characters", file=sys.stderr)
        return 2

    intel = IntelDB(_resolve_intel_dsn())
    await intel.init()
    try:
        old = await apply_org_name(intel, name)
    finally:
        await intel.close()
    if old and old != name:
        print(f'Organization name changed: "{old}" -> "{name}"')
    else:
        print(f'Organization name set to "{name}"')
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="set_org_name",
        description="Set the (dashboard-locked) organization name from the server.",
    )
    parser.add_argument("--name", required=True, help="the organization name to set")
    args = parser.parse_args(argv)
    return asyncio.run(_run(args.name))


if __name__ == "__main__":
    raise SystemExit(main())
