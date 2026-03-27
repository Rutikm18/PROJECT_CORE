"""
tests/unit/test_auth.py — Unit tests for the manager auth / verify pipeline.

Coverage:
  - Valid envelope passes all checks
  - Each failure mode returns the correct error message
  - Nonce deduplication (replay prevention)
  - Timestamp window (past and future)
  - HMAC tamper detection
"""
from __future__ import annotations

import secrets
import time

import pytest

from agent.agent.crypto import derive_keys, encrypt
from manager.manager.auth import verify_envelope


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def good_envelope(enc_key: bytes, mac_key: bytes) -> dict:
    payload = {"section": "metrics", "data": {"cpu": "2%"}}
    return encrypt(payload, enc_key, mac_key, "agent-1", int(time.time()))


# ── Happy path ────────────────────────────────────────────────────────────────

def test_valid_envelope_passes(good_envelope: dict, enc_key: bytes, mac_key: bytes):
    result = verify_envelope(good_envelope, enc_key, mac_key, {})
    assert result["section"] == "metrics"


# ── Schema validation ─────────────────────────────────────────────────────────

def test_missing_field_raises(good_envelope: dict, enc_key: bytes, mac_key: bytes):
    del good_envelope["hmac"]
    with pytest.raises(ValueError, match="Missing field"):
        verify_envelope(good_envelope, enc_key, mac_key, {})


# ── Timestamp window ──────────────────────────────────────────────────────────

def test_stale_timestamp_rejected(enc_key: bytes, mac_key: bytes):
    stale_ts = int(time.time()) - 400   # > 5-minute window
    env = encrypt({"x": 1}, enc_key, mac_key, "agent-1", stale_ts)
    with pytest.raises(ValueError, match="Timestamp"):
        verify_envelope(env, enc_key, mac_key, {})


def test_future_timestamp_rejected(enc_key: bytes, mac_key: bytes):
    future_ts = int(time.time()) + 400
    env = encrypt({"x": 1}, enc_key, mac_key, "agent-1", future_ts)
    with pytest.raises(ValueError, match="Timestamp"):
        verify_envelope(env, enc_key, mac_key, {})


# ── Replay prevention ─────────────────────────────────────────────────────────

def test_first_nonce_accepted(good_envelope: dict, enc_key: bytes, mac_key: bytes):
    cache: dict = {}
    verify_envelope(good_envelope, enc_key, mac_key, cache)
    assert good_envelope["nonce"] in cache


def test_duplicate_nonce_rejected(good_envelope: dict, enc_key: bytes, mac_key: bytes):
    cache: dict = {}
    verify_envelope(good_envelope, enc_key, mac_key, cache)        # first → OK
    with pytest.raises(ValueError, match="replay"):
        verify_envelope(good_envelope, enc_key, mac_key, cache)    # second → replay


# ── HMAC verification ─────────────────────────────────────────────────────────

def test_tampered_hmac_rejected(good_envelope: dict, enc_key: bytes, mac_key: bytes):
    good_envelope["hmac"] = "00" * 32
    with pytest.raises(ValueError):
        verify_envelope(good_envelope, enc_key, mac_key, {})
