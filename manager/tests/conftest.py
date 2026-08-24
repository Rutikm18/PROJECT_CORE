"""
manager/tests/conftest.py — Shared pytest fixtures for manager tests.
"""
from __future__ import annotations

import os
import secrets
import sys
import uuid

import pytest

# Make packages importable from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# ── Postgres per-test isolation ──────────────────────────────────────────────
# Replaces the old pattern (tempfile.mkdtemp() + a fresh SQLite file per test —
# zero shared state, free to create). Postgres has no equivalent of "just point
# at a new file path", so each test gets a freshly CREATEd, then DROPped,
# real database — same isolation guarantee, via the admin ("postgres") database
# on the same test instance docker-compose.postgres.yml brings up.
_ADMIN_DSN = os.environ.get(
    "TEST_POSTGRES_ADMIN_DSN", "postgresql://attacklens:attacklens@localhost:5432/postgres"
)


async def _create_test_db() -> tuple[str, str]:
    import asyncpg
    name = f"test_{uuid.uuid4().hex[:16]}"
    conn = await asyncpg.connect(_ADMIN_DSN)
    try:
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()
    base = _ADMIN_DSN.rsplit("/", 1)[0]
    return f"{base}/{name}", name


async def _drop_test_db(name: str) -> None:
    import asyncpg
    conn = await asyncpg.connect(_ADMIN_DSN)
    try:
        # Terminate any lingering backends (a test that left a connection open
        # would otherwise make DROP DATABASE hang/fail).
        await conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname=$1 AND pid <> pg_backend_pid()",
            name,
        )
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
    finally:
        await conn.close()


@pytest.fixture
async def pg_manager_dsn():
    """A freshly created, empty Postgres database for one test — pass directly
    to Database(dsn). Dropped automatically when the test ends."""
    dsn, name = await _create_test_db()
    try:
        yield dsn
    finally:
        await _drop_test_db(name)


@pytest.fixture
async def pg_intel_dsn():
    """Same as pg_manager_dsn, for IntelDB(dsn). A separate fixture (not the
    same one reused) so a test needing both gets two genuinely independent
    databases, mirroring the real manager.db / intel.db separation."""
    dsn, name = await _create_test_db()
    try:
        yield dsn
    finally:
        await _drop_test_db(name)


@pytest.fixture
def api_key() -> str:
    """Fresh 256-bit API key for each test."""
    return secrets.token_hex(32)


@pytest.fixture
def derived_keys(api_key: str) -> tuple[bytes, bytes]:
    """(enc_key, mac_key) pair derived from the test API key."""
    from agent.agent.crypto import derive_keys
    return derive_keys(api_key)


@pytest.fixture
def enc_key(derived_keys: tuple[bytes, bytes]) -> bytes:
    return derived_keys[0]


@pytest.fixture
def mac_key(derived_keys: tuple[bytes, bytes]) -> bytes:
    return derived_keys[1]


# ── Orphaned test-database sweep ─────────────────────────────────────────────
# The per-test fixtures above drop their database in a `finally`, which cannot
# run when a session is killed — Ctrl-C, a CI step timeout, an OOM. Each of
# those leaves a `test_<hex>` database behind on the shared instance forever.
#
# Only databases older than this are swept, so a concurrent session's live
# databases are never dropped out from under it. A run that legitimately lasts
# longer than the cutoff is still safe: its databases were *created* at the
# start, but the sweep only runs at session start, before any of its own exist.
_ORPHAN_DB_MIN_AGE_SECONDS = 2 * 3600


async def _drop_orphaned_test_dbs() -> int:
    import asyncpg
    conn = await asyncpg.connect(_ADMIN_DSN)
    try:
        # Postgres does not record database creation time; the PG_VERSION file
        # in the database's directory is written once at CREATE and not touched
        # again, so its mtime is the closest available proxy.
        rows = await conn.fetch(
            "SELECT datname FROM pg_database"
            " WHERE datname LIKE 'test\\_%'"
            "   AND (pg_stat_file('base/' || oid || '/PG_VERSION')).modification"
            "       < now() - ($1 || ' seconds')::interval",
            str(_ORPHAN_DB_MIN_AGE_SECONDS),
        )
        dropped = 0
        for row in rows:
            name = row["datname"]
            try:
                await conn.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname=$1 AND pid <> pg_backend_pid()",
                    name,
                )
                await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
                dropped += 1
            except Exception:
                # Another session may have dropped it first, or hold it open.
                # Leaking one stale database is not worth failing the run over.
                pass
        return dropped
    finally:
        await conn.close()


@pytest.fixture(scope="session", autouse=True)
def _sweep_orphaned_test_dbs():
    """Best-effort cleanup of databases abandoned by previously killed runs."""
    import asyncio
    try:
        dropped = asyncio.run(_drop_orphaned_test_dbs())
        if dropped:
            print(f"\nconftest: dropped {dropped} orphaned test database(s)")
    except Exception:
        # No Postgres reachable yet, or no permission. The tests that need it
        # will fail with a far clearer message than this fixture could give.
        pass
    yield


# ── Dashboard session helper ─────────────────────────────────────────────────
# Every /api/v1/* data route now requires a dashboard session (see the auth
# boundary in manager/manager/server.py and the coverage test in
# manager/tests/unit/test_api_auth_coverage.py). Tests that drive those routes
# are exercising the *authenticated* path, so they sign in rather than the
# endpoints being reopened to keep the suite green.


def dashboard_session_token(
    email: str = "admin@attacklens.ai", role: str = "admin",
) -> str:
    """Mint a valid dashboard JWT.

    Minted through auth_ui itself, so it is signed with whatever secret that
    module resolved at import time — signer and verifier can never drift, even
    when JWT_SECRET is unset and an ephemeral key is generated per process.
    """
    from manager.manager.api import auth_ui

    token, _jti, _exp = auth_ui._make_token(email, role)
    return token


def authenticate(client, *, email: str = "admin@attacklens.ai", role: str = "admin"):
    """Attach a dashboard session cookie to a TestClient. Returns the client."""
    client.cookies.set("al_session", dashboard_session_token(email, role))
    return client
