"""
tests/unit/test_crypto.py — Unit tests for the crypto module.

Coverage:
  - Key derivation is deterministic and domain-separated
  - Encrypt → Decrypt round-trip preserves payload exactly
  - HMAC tamper detection (corrupt hmac, corrupt ciphertext, wrong key)
  - Envelope version check
  - Missing field detection
"""
from __future__ import annotations

import base64
import secrets
import time

import pytest

from agent.agent.crypto import derive_keys, encrypt, decrypt


# ── Key derivation ────────────────────────────────────────────────────────────

def test_derive_keys_is_deterministic():
    key = secrets.token_hex(32)
    enc1, mac1 = derive_keys(key)
    enc2, mac2 = derive_keys(key)
    assert enc1 == enc2
    assert mac1 == mac2


def test_derive_keys_are_distinct():
    """enc_key and mac_key must be different (domain-separated)."""
    enc_key, mac_key = derive_keys(secrets.token_hex(32))
    assert enc_key != mac_key


def test_different_api_keys_produce_different_enc_keys():
    enc1, _ = derive_keys("a" * 64)
    enc2, _ = derive_keys("b" * 64)
    assert enc1 != enc2


# ── Round-trip ────────────────────────────────────────────────────────────────

def test_roundtrip_preserves_payload(enc_key, mac_key):
    payload = {"section": "metrics", "data": {"cpu": "5% idle"}, "nested": [1, 2, 3]}
    ts = int(time.time())
    envelope = encrypt(payload, enc_key, mac_key, "agent-1", ts)
    assert decrypt(envelope, enc_key, mac_key) == payload


def test_encrypt_produces_all_required_fields(enc_key, mac_key):
    envelope = encrypt({"x": 1}, enc_key, mac_key, "agent-1", int(time.time()))
    for field in ("v", "agent_id", "timestamp", "nonce", "ct", "hmac"):
        assert field in envelope, f"Missing field: {field}"


def test_envelope_version_is_1(enc_key, mac_key):
    envelope = encrypt({}, enc_key, mac_key, "a", int(time.time()))
    assert envelope["v"] == 1


# ── Tamper detection ──────────────────────────────────────────────────────────

def test_corrupt_hmac_raises(enc_key, mac_key):
    env = encrypt({"x": 1}, enc_key, mac_key, "agent-1", int(time.time()))
    env["hmac"] = "00" * 32
    with pytest.raises(ValueError, match="HMAC"):
        decrypt(env, enc_key, mac_key)


def test_corrupt_ciphertext_raises(enc_key, mac_key):
    env = encrypt({"x": 1}, enc_key, mac_key, "agent-1", int(time.time()))
    ct_bytes = bytearray(base64.b64decode(env["ct"]))
    ct_bytes[0] ^= 0xFF   # flip a byte
    env["ct"] = base64.b64encode(bytes(ct_bytes)).decode()
    with pytest.raises(ValueError):
        decrypt(env, enc_key, mac_key)


def test_wrong_key_pair_raises(enc_key, mac_key):
    env = encrypt({"x": 1}, enc_key, mac_key, "agent-1", int(time.time()))
    wrong_enc, wrong_mac = derive_keys(secrets.token_hex(32))
    with pytest.raises(ValueError):
        decrypt(env, wrong_enc, wrong_mac)


def test_missing_field_raises(enc_key, mac_key):
    env = encrypt({"x": 1}, enc_key, mac_key, "agent-1", int(time.time()))
    del env["hmac"]
    with pytest.raises(ValueError, match="missing"):
        decrypt(env, enc_key, mac_key)


def test_unsupported_version_raises(enc_key, mac_key):
    env = encrypt({"x": 1}, enc_key, mac_key, "agent-1", int(time.time()))
    env["v"] = 99
    with pytest.raises(ValueError, match="version"):
        decrypt(env, enc_key, mac_key)
