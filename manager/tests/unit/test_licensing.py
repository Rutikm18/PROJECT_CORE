"""
manager/tests/unit/test_licensing.py — entitlement-bearing licence keys.

The key carries its own entitlements so a deployment can verify a customer's
rights with no callback. That makes the signature the only thing standing
between a customer and arbitrary self-granted entitlements, so the negative
cases matter more than the happy path.
"""
from __future__ import annotations

import time

import pytest

from manager.manager import licensing as L


@pytest.fixture
def signing_key(monkeypatch):
    key = L.generate_signing_key()
    monkeypatch.setenv("LICENSE_SIGNING_KEY", key)
    monkeypatch.delenv("LICENSE_PUBLIC_KEYS", raising=False)
    monkeypatch.setenv("LICENSE_KID", "k1")
    return key


def _issue(**over):
    params = dict(
        org_id="org_abc", org_slug="acme", valid_days=365,
        max_agents=50, tier="enterprise", features=("ai_validation",),
    )
    params.update(over)
    return L.issue(**params)


# ── Round trip ───────────────────────────────────────────────────────────────

def test_issue_and_verify_round_trip(signing_key):
    key, issued = _issue()
    assert L.verify(key) == issued


def test_issue_returns_exactly_what_it_signed(signing_key):
    """The caller persists these entitlements next to the key, so a drifting
    sub-second timestamp would make the stored record disagree with the key."""
    key, issued = _issue(issued_at=time.time() + 0.7654321)
    assert L.verify(key) == issued
    assert float(issued.issued_at).is_integer()


def test_entitlements_survive_the_round_trip(signing_key):
    key, _ = _issue(max_agents=7, tier="starter", features=("a", "b"))
    ent = L.verify(key)
    assert (ent.org_id, ent.org_slug) == ("org_abc", "acme")
    assert ent.max_agents == 7
    assert ent.tier == "starter"
    assert ent.features == ("a", "b")


def test_a_grouped_key_verifies_identically(signing_key):
    """Keys are displayed hyphenated for readability; both forms are one key."""
    key, issued = _issue()
    grouped = L.format_grouped(key)
    assert "-" in grouped
    assert L.verify(grouped) == issued


def test_verification_needs_no_network(signing_key, monkeypatch):
    """The whole point of embedding entitlements. Any socket use fails here."""
    import socket

    key, _ = _issue()

    def no_network(*a, **k):
        raise AssertionError("licence verification attempted a network call")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    assert L.verify(key).org_slug == "acme"


# ── Rejection ────────────────────────────────────────────────────────────────

def test_a_tampered_payload_is_rejected(signing_key):
    """Raising max_agents by editing the key must not work."""
    key, _ = _issue()
    prefix, payload, sig = key.split(".")
    flipped = payload[:-1] + ("0" if payload[-1] != "0" else "1")
    with pytest.raises((L.LicenseSignatureError, L.LicenseFormatError)):
        L.verify(f"{prefix}.{flipped}.{sig}")


def test_a_tampered_signature_is_rejected(signing_key):
    key, _ = _issue()
    prefix, payload, sig = key.split(".")
    flipped = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    with pytest.raises(L.LicenseSignatureError):
        L.verify(f"{prefix}.{payload}.{flipped}")


def test_a_key_from_another_signing_key_is_rejected(signing_key, monkeypatch):
    """Someone else's valid key is not valid here."""
    key, _ = _issue()
    monkeypatch.setenv("LICENSE_SIGNING_KEY", L.generate_signing_key())
    with pytest.raises(L.LicenseSignatureError):
        L.verify(key)


def test_an_expired_key_is_rejected(signing_key):
    key, ent = _issue(valid_days=1, issued_at=time.time() - 10 * 86400)
    with pytest.raises(L.LicenseExpiredError):
        L.verify(key)
    # Still verifiable as of a time inside its window — expiry, not forgery.
    assert L.verify(key, at=ent.issued_at + 3600).org_slug == "acme"


def test_expiry_is_checked_after_the_signature(signing_key, monkeypatch):
    """A forged key must read as forged, never as merely expired — otherwise
    the error tells an attacker their signature was fine."""
    key, _ = _issue(valid_days=1, issued_at=time.time() - 10 * 86400)
    monkeypatch.setenv("LICENSE_SIGNING_KEY", L.generate_signing_key())
    with pytest.raises(L.LicenseSignatureError):
        L.verify(key)


def test_a_perpetual_key_never_expires(signing_key):
    key, ent = _issue(valid_days=0)
    assert ent.expires_at == 0
    assert L.verify(key, at=time.time() + 100 * 365 * 86400).days_remaining is None


@pytest.mark.parametrize("bad", [
    "", "not-a-key", "AL1.only-two-parts",
    "AL2.AAAA.BBBB",                      # wrong version prefix
    "AL1..BBBB", "AL1.AAAA.",             # empty segments
])
def test_malformed_keys_are_rejected(signing_key, bad):
    with pytest.raises(L.LicenseFormatError):
        L.verify(bad)


def test_an_unknown_signing_key_id_is_named_in_the_error(signing_key, monkeypatch):
    """After a rotation, a key signed by a retired kid must fail with a message
    that says how to fix it, not a generic signature error."""
    monkeypatch.setenv("LICENSE_KID", "old")
    key, _ = _issue()
    monkeypatch.setenv("LICENSE_KID", "new")
    monkeypatch.setenv("LICENSE_SIGNING_KEY", L.generate_signing_key())
    with pytest.raises(L.UnknownSigningKeyError) as exc:
        L.verify(key)
    assert "LICENSE_PUBLIC_KEYS" in str(exc.value)


def test_a_retired_key_keeps_verifying_when_its_public_key_is_kept(monkeypatch):
    """Rotation must not invalidate keys already in customers' hands."""
    old_private = L.generate_signing_key()
    monkeypatch.setenv("LICENSE_SIGNING_KEY", old_private)
    monkeypatch.setenv("LICENSE_KID", "k1")
    key, issued = _issue()
    old_public = L.public_key_b32()

    monkeypatch.setenv("LICENSE_SIGNING_KEY", L.generate_signing_key())
    monkeypatch.setenv("LICENSE_KID", "k2")
    monkeypatch.setenv("LICENSE_PUBLIC_KEYS", f"k1:{old_public}")
    assert L.verify(key) == issued


def test_a_missing_signing_key_is_a_hard_error(monkeypatch):
    """Auto-generating one would silently invalidate every issued licence."""
    monkeypatch.delenv("LICENSE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("LICENSE_PUBLIC_KEYS", raising=False)
    with pytest.raises(L.LicenseError) as exc:
        L.issue(org_id="o", org_slug="s")
    assert "LICENSE_SIGNING_KEY" in str(exc.value)


# ── Encoding ─────────────────────────────────────────────────────────────────

def test_the_alphabet_excludes_ambiguous_characters():
    """Crockford Base32: no I, L, O or U, so a transcribed key survives."""
    assert set("ILOU").isdisjoint(set(L._ALPHABET))
    assert len(L._ALPHABET) == 32


def test_ambiguous_characters_decode_to_their_intended_digit():
    """A human who writes O for 0 or l for 1 should still get a working key."""
    assert L.b32decode("O", 1) == L.b32decode("0", 1)
    assert L.b32decode("I", 1) == L.b32decode("1", 1)
    assert L.b32decode("L", 1) == L.b32decode("1", 1)


def test_a_key_is_case_insensitive(signing_key):
    key, issued = _issue()
    prefix, payload, sig = key.split(".")
    assert L.verify(f"{prefix}.{payload.lower()}.{sig.lower()}") == issued


def test_base32_round_trips_arbitrary_bytes():
    import os
    for length in (1, 16, 32, 64):
        raw = os.urandom(length)
        assert L.b32decode(L.b32encode(raw), length) == raw


def test_fingerprint_is_stable_and_not_the_key(signing_key):
    key, _ = _issue()
    assert L.key_fingerprint(key) == L.key_fingerprint(key)
    assert key not in L.key_fingerprint(key)
    assert len(L.key_fingerprint(key)) == 64
