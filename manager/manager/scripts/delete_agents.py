"""
delete_agents.py — remove one or more agents and ALL of their data.

A single command that deletes agents by explicit id and/or by age, cascading
across both databases so nothing the agent produced survives in the dashboard:
its telemetry (payloads, detection events), findings, detections, correlations,
SOC activity, assets and signals.

Run inside the manager container (it has the DATABASE_URL the manager uses):

    # check what is enrolled first (no deletion)
    python -m manager.manager.scripts.delete_agents --list

    # by id (space- or comma-separated)
    python -m manager.manager.scripts.delete_agents --agents "agent-a agent-b"

    # by age — every agent not seen in the last 30 days
    python -m manager.manager.scripts.delete_agents --older-than 30d

    # EVERY agent (careful — wipes them all)
    python -m manager.manager.scripts.delete_agents --all --yes

    # preview without deleting
    python -m manager.manager.scripts.delete_agents --older-than 30d --dry-run

    # skip the confirmation prompt (required when there is no TTY)
    python -m manager.manager.scripts.delete_agents --agents agent-a --yes

The Makefile wraps this: `make delete-agents AGENTS="a b" OLDER_THAN=30d`.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

from ..db import Database
from ..indexer import IntelDB

_SUFFIX_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}


def _resolve_dsns() -> tuple[str, str]:
    """The two logical DBs, resolved exactly as server.py does."""
    database_url = os.environ.get(
        "DATABASE_URL", "postgresql://attacklens:attacklens@localhost:5432"
    ).rstrip("/")
    db_path    = os.environ.get("MANAGER_DATABASE_URL", f"{database_url}/manager")
    intel_path = os.environ.get("INTEL_DATABASE_URL",   f"{database_url}/intel")
    return db_path, intel_path


def _parse_ids(values: list[str]) -> list[str]:
    """Flatten --agents args split on commas or whitespace, de-duplicated in order."""
    seen: dict[str, None] = {}
    for chunk in values:
        for token in chunk.replace(",", " ").split():
            token = token.strip()
            if token:
                seen.setdefault(token, None)
    return list(seen)


def _parse_age_seconds(spec: str) -> int:
    """'30d' / '12h' / '45m' / '90s' / '30' (days) → seconds."""
    spec = spec.strip().lower()
    if not spec:
        raise ValueError("empty --older-than")
    unit = spec[-1]
    if unit in _SUFFIX_SECONDS:
        number, mult = spec[:-1], _SUFFIX_SECONDS[unit]
    else:
        number, mult = spec, _SUFFIX_SECONDS["d"]   # bare number means days
    value = int(number)
    if value < 0:
        raise ValueError("--older-than must not be negative")
    return value * mult


async def _resolve_targets(db: Database, ids: list[str], age_seconds: int | None) -> list[str]:
    targets: dict[str, None] = {}
    for agent_id in ids:
        if await db.agent_exists(agent_id):
            targets.setdefault(agent_id, None)
        else:
            print(f"  ! no such agent, skipping: {agent_id}", file=sys.stderr)
    if age_seconds is not None:
        cutoff = int(time.time()) - age_seconds
        for agent_id in await db.agent_ids_seen_before(cutoff):
            targets.setdefault(agent_id, None)
    return list(targets)


def _confirm(count: int, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    prompt = f"Delete {count} agent(s) and ALL their data? This cannot be undone. [y/N] "
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        print("  ! no TTY to confirm on — re-run with --yes", file=sys.stderr)
        return False


def _fmt_ts(ts: object) -> str:
    epoch = int(ts or 0)
    if epoch <= 0:
        return "never seen"
    age_days = (time.time() - epoch) / 86400
    return f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(epoch))} ({age_days:.0f}d ago)"


async def _list_agents(db: Database) -> int:
    agents = await db.list_agents()
    if not agents:
        print("No agents enrolled.")
        return 0
    print(f"{len(agents)} agent(s):\n")
    for a in agents:
        name = (a.get("name") or "").strip()
        line = f"  {a['agent_id']:<34}  {_fmt_ts(a.get('last_seen'))}"
        print(line + (f"  {name}" if name else ""))
    print('\nCheck one:   make delete-agents AGENTS="<id>" DRY_RUN=1   (preview, deletes nothing)')
    print('Delete one:  make delete-agents AGENTS="<id>" YES=1       (deletes it)')
    return 0


async def _run(args: argparse.Namespace) -> int:
    age_seconds = _parse_age_seconds(args.older_than) if args.older_than else None
    ids = _parse_ids(args.agents or [])
    if not args.list and not args.all and not ids and age_seconds is None:
        print("Nothing to do: pass --list, --all, --agents and/or --older-than.", file=sys.stderr)
        return 2

    db_dsn, intel_dsn = _resolve_dsns()
    db, intel_db = Database(db_dsn), IntelDB(intel_dsn)
    await db.init()
    await intel_db.init()
    try:
        if args.list:
            return await _list_agents(db)

        if args.all:
            targets = [a["agent_id"] for a in await db.list_agents()]
        else:
            targets = await _resolve_targets(db, ids, age_seconds)
        if not targets:
            print("No matching agents. Nothing deleted.")
            return 0

        print(f"Matched {len(targets)} agent(s): " + ", ".join(targets))

        if args.dry_run:
            for agent_id in targets:
                counts = {**await db.count_agent_rows(agent_id),
                          **await intel_db.count_agent_rows(agent_id)}
                total = sum(counts.values())
                print(f"\n[dry-run] {agent_id} — would delete {total} row(s):")
                for table, n in counts.items():
                    if n:
                        print(f"    {table:<26} {n}")
            print("\n[dry-run] Nothing was deleted.")
            return 0

        if not _confirm(len(targets), args.yes):
            print("Aborted. Nothing deleted.")
            return 1

        totals: dict[str, int] = {}
        for agent_id in targets:
            counts = {**await db.delete_agent(agent_id), **await intel_db.delete_agent(agent_id)}
            removed = sum(counts.values())
            print(f"\nDeleted agent {agent_id} — {removed} row(s):")
            for table, n in counts.items():
                if n:
                    print(f"    {table:<26} {n}")
                totals[table] = totals.get(table, 0) + n

        print(f"\nDone. Removed {sum(totals.values())} row(s) across "
              f"{len(targets)} agent(s).")
        return 0
    finally:
        await intel_db.close()
        await db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="delete_agents",
        description="Delete agents and all their data from the manager.",
    )
    parser.add_argument("--list", action="store_true",
                        help="list all agents (id, last-seen) and exit — no deletion")
    parser.add_argument("--all", action="store_true",
                        help="select EVERY agent (still confirms unless --yes)")
    parser.add_argument("--agents", action="append", metavar="IDS",
                        help="agent id(s), comma- or space-separated (repeatable)")
    parser.add_argument("--older-than", metavar="AGE",
                        help="also delete agents not seen within AGE (e.g. 30d, 12h, 90)")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would be deleted, delete nothing")
    parser.add_argument("--yes", action="store_true",
                        help="skip the confirmation prompt")
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
