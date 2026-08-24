"""
manager/tests/unit/test_tenancy_model.py — orgs, portal users, and the
agent binding that will become the tenant boundary.

`org_agents` is the table that decides what a customer can see. Phase 3 feeds
`agent_ids_for_org` into the query choke point, so anything that widens the set
it returns widens the blast radius of a leak. These tests are written against
that reading: the interesting cases are the ones that would over-grant.
"""
from __future__ import annotations

import time

import pytest

from manager.manager import licensing as L
from manager.manager.indexer import IntelDB


@pytest.fixture
def signing_key(monkeypatch):
    monkeypatch.setenv("LICENSE_SIGNING_KEY", L.generate_signing_key())
    monkeypatch.setenv("LICENSE_KID", "k1")


async def _db(dsn) -> IntelDB:
    idb = IntelDB(dsn)
    await idb.init()
    return idb


async def _org(idb, slug="acme", *, max_agents=10, valid_days=365) -> dict:
    key, ent = L.issue(
        org_id="pending", org_slug=slug,
        valid_days=valid_days, max_agents=max_agents,
    )
    return await idb.create_org(
        slug=slug, name=slug.title(), contact_email=f"ops@{slug}.io",
        license_key_hash=L.key_fingerprint(key),
        entitlements=ent.to_dict(), actor="admin@attacklens.ai",
        status="active",
    )


# ── Orgs ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_and_read_back_an_org(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb, "acme", max_agents=25)
        assert org["slug"] == "acme"
        assert org["status"] == "active"
        assert org["max_agents"] == 25
        assert org["license_days_remaining"] == 364
        assert org["license_expired"] is False
        assert await idb.get_org_by_slug("ACME") == org   # slug is normalised
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_the_licence_hash_is_never_returned(pg_intel_dsn, signing_key):
    """The stored hash is not a secret, but it has no business on an API
    response, and leaving it in makes it easy to start comparing against it."""
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        assert "license_key_hash" not in org
        assert "license_key_hash" not in (await idb.list_orgs())[0]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_slugs_are_unique(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        await _org(idb, "acme")
        with pytest.raises(Exception):
            await _org(idb, "acme")
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_status_transitions_are_validated(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        assert await idb.set_org_status(org["org_id"], "suspended") is True
        assert (await idb.get_org(org["org_id"]))["status"] == "suspended"
        with pytest.raises(ValueError):
            await idb.set_org_status(org["org_id"], "deleted")
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_list_orgs_reports_agent_and_user_counts(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        await idb.assign_agents_to_org(org["org_id"], ["a1", "a2"])
        await idb.create_portal_user(org_id=org["org_id"], email="u@acme.io")
        listed = (await idb.list_orgs())[0]
        assert listed["agent_count"] == 2
        assert listed["user_count"] == 1
    finally:
        await idb.close()


# ── Agent binding: the tenant boundary ───────────────────────────────────────

@pytest.mark.asyncio
async def test_agents_bind_to_an_org(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        result = await idb.assign_agents_to_org(
            org["org_id"], ["mac-1", "mac-2"], actor="admin",
        )
        assert result["assigned"] == ["mac-1", "mac-2"]
        assert await idb.agent_ids_for_org(org["org_id"]) == ["mac-1", "mac-2"]
        assert await idb.org_for_agent("mac-1") == org["org_id"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_agent_cannot_belong_to_two_orgs(pg_intel_dsn, signing_key):
    """The leak this prevents: one customer's endpoint appearing in another
    customer's dashboard."""
    idb = await _db(pg_intel_dsn)
    try:
        acme = await _org(idb, "acme")
        globex = await _org(idb, "globex")
        await idb.assign_agents_to_org(acme["org_id"], ["shared-agent"])

        with pytest.raises(ValueError, match="already assigned"):
            await idb.assign_agents_to_org(globex["org_id"], ["shared-agent"])

        assert await idb.agent_ids_for_org(globex["org_id"]) == []
        assert await idb.org_for_agent("shared-agent") == acme["org_id"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_seat_cap_is_enforced_and_the_batch_is_all_or_nothing(
    pg_intel_dsn, signing_key,
):
    """Partially applying would leave the operator believing all were assigned."""
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb, "acme", max_agents=2)
        with pytest.raises(ValueError, match="allows 2 agents"):
            await idb.assign_agents_to_org(org["org_id"], ["a", "b", "c"])
        assert await idb.agent_ids_for_org(org["org_id"]) == []

        await idb.assign_agents_to_org(org["org_id"], ["a", "b"])
        with pytest.raises(ValueError):
            await idb.assign_agents_to_org(org["org_id"], ["c"])
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_reassigning_an_existing_agent_is_a_no_op_not_an_error(
    pg_intel_dsn, signing_key,
):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb, "acme", max_agents=2)
        await idb.assign_agents_to_org(org["org_id"], ["a"])
        result = await idb.assign_agents_to_org(org["org_id"], ["a", "b"])
        assert result["assigned"] == ["b"]
        assert result["skipped"] == ["a"]
        assert await idb.agent_ids_for_org(org["org_id"]) == ["a", "b"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_unassigning_frees_the_agent_and_the_seat(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        acme = await _org(idb, "acme", max_agents=1)
        globex = await _org(idb, "globex", max_agents=1)
        await idb.assign_agents_to_org(acme["org_id"], ["mac-1"])

        assert await idb.unassign_agent("mac-1") is True
        assert await idb.agent_ids_for_org(acme["org_id"]) == []
        # Now reassignable elsewhere — a deliberate move, not a silent one.
        await idb.assign_agents_to_org(globex["org_id"], ["mac-1"])
        assert await idb.org_for_agent("mac-1") == globex["org_id"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_unknown_org_cannot_be_assigned_agents(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        with pytest.raises(ValueError, match="unknown org"):
            await idb.assign_agents_to_org("org_nope", ["a"])
    finally:
        await idb.close()


# ── Portal users and invites ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_new_user_has_no_password(pg_intel_dsn, signing_key):
    """Credentials come from the invite flow, so no plaintext ever exists."""
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        user = await idb.create_portal_user(org_id=org["org_id"], email="Ops@Acme.IO")
        assert user["email"] == "ops@acme.io"          # normalised
        assert user["status"] == "invited"
        assert user["password_hash"] == ""
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_email_is_globally_unique(pg_intel_dsn, signing_key):
    """Login takes an email with no org selector, so it must be unambiguous —
    and it must not reveal which org an address belongs to."""
    idb = await _db(pg_intel_dsn)
    try:
        acme = await _org(idb, "acme")
        globex = await _org(idb, "globex")
        await idb.create_portal_user(org_id=acme["org_id"], email="dup@x.io")
        with pytest.raises(Exception):
            await idb.create_portal_user(org_id=globex["org_id"], email="dup@x.io")
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_a_malformed_email_is_rejected(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        with pytest.raises(ValueError):
            await idb.create_portal_user(org_id=org["org_id"], email="not-an-email")
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_invite_activates_the_user_exactly_once(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        user = await idb.create_portal_user(org_id=org["org_id"], email="u@acme.io")
        await idb.create_invite(
            user_id=user["user_id"], org_id=org["org_id"], token_hash="hash-1",
        )

        activated = await idb.consume_invite("hash-1", "pbkdf2:fake-hash")
        assert activated["status"] == "active"
        assert activated["password_hash"] == "pbkdf2:fake-hash"

        # Replaying the same link must not work.
        assert await idb.consume_invite("hash-1", "attacker-hash") is None
        assert (await idb.get_portal_user(user["user_id"]))["password_hash"] == "pbkdf2:fake-hash"
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_expired_invite_is_refused(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        user = await idb.create_portal_user(org_id=org["org_id"], email="u@acme.io")
        await idb.create_invite(
            user_id=user["user_id"], org_id=org["org_id"],
            token_hash="hash-old", ttl_seconds=60,
        )
        async with idb._lock:
            await idb._conn.execute(
                "UPDATE portal_invites SET expires_at=? WHERE token_hash=?",
                (time.time() - 1, "hash-old"),
            )
            await idb._conn.commit()

        assert await idb.consume_invite("hash-old", "h") is None
        assert (await idb.get_portal_user(user["user_id"]))["status"] == "invited"
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_unknown_invite_token_is_refused(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        assert await idb.consume_invite("never-issued", "h") is None
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_a_resent_invite_supersedes_the_previous_link(pg_intel_dsn, signing_key):
    """Two live setup links for one account is two chances to intercept one."""
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        user = await idb.create_portal_user(org_id=org["org_id"], email="u@acme.io")
        await idb.create_invite(
            user_id=user["user_id"], org_id=org["org_id"], token_hash="first",
        )
        await idb.create_invite(
            user_id=user["user_id"], org_id=org["org_id"], token_hash="second",
        )
        assert await idb.consume_invite("first", "h") is None
        assert (await idb.consume_invite("second", "h"))["status"] == "active"
    finally:
        await idb.close()


# ── Audit ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_provisioning_actions_are_audited(pg_intel_dsn, signing_key):
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)
        await idb.assign_agents_to_org(org["org_id"], ["a1"], actor="admin@x.io")
        await idb.set_org_status(org["org_id"], "suspended", actor="admin@x.io")

        actions = [r["action"] for r in await idb.portal_audit_for_org(org["org_id"])]
        assert "org.agents.assigned" in actions
        assert "org.status.suspended" in actions
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_audit_failure_never_breaks_the_action(pg_intel_dsn, signing_key):
    """The trail matters, but losing a row must not fail a suspension."""
    idb = await _db(pg_intel_dsn)
    try:
        org = await _org(idb)

        async def boom(*a, **k):
            raise RuntimeError("audit table unavailable")

        original = idb._conn.execute
        try:
            await idb.record_portal_audit(org_id=org["org_id"], action="x")
            idb._conn.execute = boom
            await idb.record_portal_audit(org_id=org["org_id"], action="y")
        finally:
            idb._conn.execute = original
    finally:
        await idb.close()
