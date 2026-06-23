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
