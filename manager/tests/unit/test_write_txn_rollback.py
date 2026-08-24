"""
manager/tests/unit/test_write_txn_rollback.py — Shared-connection poisoning.

IntelDB._conn is one long-lived Postgres write connection shared by every
writer in the process. Postgres aborts the whole transaction on the first
failed statement, so a handler that catches the error *without* rolling back
leaves that shared connection permanently broken — and every later write, in
completely unrelated endpoints, fails with:

    cannot commit; the transaction is in error state

That is one defect presenting as several: settings would not save, case
transitions returned 500, and accept-risk stopped working, all at once, until
the manager was restarted.
"""
from __future__ import annotations

import pytest

from manager.manager.indexer import IntelDB


class _FakeConn:
    """Models Postgres transaction semantics: a failure poisons until rollback."""

    def __init__(self):
        self.poisoned = False
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, sql, args=()):
        if self.poisoned:
            raise RuntimeError("current transaction is aborted")
        if "BOOM" in sql:
            self.poisoned = True
            raise RuntimeError("relation does not exist")
        return None

    async def commit(self):
        if self.poisoned:
            raise RuntimeError("cannot commit; the transaction is in error state")
        self.commits += 1

    async def rollback(self):
        self.poisoned = False
        self.rollbacks += 1


@pytest.fixture
def db():
    idb = IntelDB("postgresql://unused/db")
    idb._conn = _FakeConn()
    return idb


@pytest.mark.asyncio
async def test_successful_write_commits_once(db):
    async with db.write_txn() as conn:
        await conn.execute("UPDATE findings SET x=1")
    assert db._conn.commits == 1
    assert db._conn.rollbacks == 0


@pytest.mark.asyncio
async def test_failed_write_rolls_back_and_reraises(db):
    with pytest.raises(RuntimeError, match="relation does not exist"):
        async with db.write_txn() as conn:
            await conn.execute("INSERT INTO BOOM VALUES(1)")
    assert db._conn.rollbacks == 1
    assert db._conn.commits == 0


@pytest.mark.asyncio
async def test_the_next_write_still_works_after_a_failure(db):
    """The regression itself: one bad write used to break every later one."""
    with pytest.raises(RuntimeError):
        async with db.write_txn() as conn:
            await conn.execute("INSERT INTO BOOM VALUES(1)")

    # Unrelated endpoint, same shared connection — must succeed.
    async with db.write_txn() as conn:
        await conn.execute("UPDATE org_settings SET value='x'")

    assert db._conn.commits == 1
    assert not db._conn.poisoned


@pytest.mark.asyncio
async def test_without_rollback_the_connection_stays_broken(db):
    """Pins why the fix is needed, by reproducing the old behaviour."""
    conn = db._conn
    try:
        await conn.execute("INSERT INTO BOOM VALUES(1)")
    except RuntimeError:
        pass                       # swallowed, as the old handlers did

    with pytest.raises(RuntimeError, match="transaction is in error state"):
        await conn.commit()


@pytest.mark.asyncio
async def test_rollback_failure_does_not_mask_the_original_error(db):
    class _BadRollback(_FakeConn):
        async def rollback(self):
            raise RuntimeError("connection lost")

    db._conn = _BadRollback()
    with pytest.raises(RuntimeError, match="relation does not exist"):
        async with db.write_txn() as conn:
            await conn.execute("INSERT INTO BOOM VALUES(1)")


# ── Call-site coverage ────────────────────────────────────────────────────────

@pytest.mark.parametrize("module", [
    "manager/manager/api/settings.py",
    "manager/manager/api/cases.py",
    "manager/manager/api/finding_validation.py",
])
def test_request_handlers_do_not_commit_the_shared_connection_directly(module):
    """A bare _conn.commit() in a handler has no rollback partner.

    These three modules own settings, case management and validation — the
    three surfaces that failed together.
    """
    from pathlib import Path

    src = Path(module).read_text()
    assert "_conn.commit()" not in src, (
        f"{module} commits the shared connection directly; use write_txn() so a "
        "failure cannot poison it for every other endpoint"
    )


# ── Repo-wide invariant ───────────────────────────────────────────────────────

def test_no_module_commits_the_shared_connection_without_a_rollback_path():
    """Every writer must either use write_txn() or roll back explicitly.

    This is the invariant, not the individual call sites: the defect was an
    *omission*, and omissions come back. indexer.py is exempt because it owns
    the connection and already rolls back inline during migrations.
    """
    from pathlib import Path

    offenders = []
    for path in sorted(Path("manager/manager").rglob("*.py")):
        if path.name == "indexer.py":
            continue
        src = path.read_text(errors="ignore")
        if "_conn.commit()" in src and "rollback" not in src:
            offenders.append(str(path))

    assert offenders == [], (
        "these modules commit the shared write connection with no rollback "
        f"path, so one failed statement poisons it for every endpoint: {offenders}"
    )
