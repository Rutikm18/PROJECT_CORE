"""
manager/tests/unit/test_feed_health_honesty.py — Feed health must not lie.

The CISA KEV catalog was empty (0 rows) while feed_health reported
status='ok', error_count=0. Every KEV-based score was therefore silently
inert, and the health page said the feed was fine — so nobody looked.

A fetch that raised nothing but imported nothing is not "ok". It is a third
state, and naming it is the difference between a visible gap and a silent one.
"""
from __future__ import annotations

import pytest

from manager.manager.indexer import IntelDB


class _Capture:
    def __init__(self):
        self.rows = []
        self.commits = 0
        self.rollbacks = 0
        self.fail = False

    async def execute(self, sql, args=()):
        if self.fail:
            raise RuntimeError("write failed")
        self.rows.append((sql, args))

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


@pytest.fixture
def db():
    idb = IntelDB("postgresql://unused/db")
    idb._conn = _Capture()
    return idb


def _status_of(conn) -> str:
    """The status value bound into the most recent health write."""
    _sql, args = conn.rows[-1]
    return args[-1]


@pytest.mark.asyncio
async def test_successful_fetch_with_entries_is_ok(db):
    await db.record_feed_attempt("cisa_kev", success=True, entry_count=1200)
    assert _status_of(db._conn) == "ok"


@pytest.mark.asyncio
async def test_successful_fetch_that_imported_nothing_is_not_ok(db):
    """The exact CISA KEV situation: no error raised, no data imported."""
    await db.record_feed_attempt("cisa_kev", success=True, entry_count=0)
    assert _status_of(db._conn) == "empty"


@pytest.mark.asyncio
async def test_empty_result_records_why(db):
    await db.record_feed_attempt("cisa_kev", success=True, entry_count=0)
    _sql, args = db._conn.rows[-1]
    assert any("imported 0 entries" in str(a) for a in args)


@pytest.mark.asyncio
async def test_failed_fetch_still_records_an_error(db):
    await db.record_feed_attempt("feodo", success=False, error="TLS verify failed")
    sql, args = db._conn.rows[-1]
    assert "error" in sql
    assert any("TLS verify failed" in str(a) for a in args)


@pytest.mark.asyncio
async def test_health_write_commits_once(db):
    await db.record_feed_attempt("cisa_kev", success=True, entry_count=5)
    assert db._conn.commits == 1
    assert db._conn.rollbacks == 0


@pytest.mark.asyncio
async def test_a_failed_health_write_rolls_back(db):
    """This runs on a timer for every feed. Without rollback, one failure here
    poisons the shared connection and breaks settings, cases and validation."""
    db._conn.fail = True
    with pytest.raises(RuntimeError):
        await db.record_feed_attempt("cisa_kev", success=True, entry_count=5)
    assert db._conn.rollbacks == 1
    assert db._conn.commits == 0
