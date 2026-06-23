"""
agent/tests/unit/test_restamp.py — store-and-forward transport freshness.

The manager rejects any envelope whose transport `timestamp` is outside its
±5-minute replay window. An envelope sealed at enqueue time and then spooled
during an outage goes stale → rejected on reconnect → data loss.

restamp_envelope() refreshes ONLY the transport timestamp + HMAC at send time,
so buffered data delivers after any outage, while the event's own collected_at
(inside the ciphertext) stays accurate. These tests pin that contract.
"""
from __future__ import annotations

import time

from agent.agent.crypto import (
    decrypt, derive_keys, encrypt, restamp_envelope, _compute_hmac,
)

REPLAY_WINDOW = 300  # mirrors manager shared.wire.REPLAY_WINDOW_SECONDS


def _keys():
    return derive_keys("a" * 64)


def test_restamp_brings_stale_envelope_into_replay_window():
    enc, mac = _keys()
    stale_ts = int(time.time()) - 3600          # sealed an hour ago (offline)
    env = encrypt({"section": "ports", "collected_at": stale_ts, "data": {"p": 4444}},
                  enc, mac, "mac-1", stale_ts)

    # Before: would be rejected (skew > window).
    assert abs(time.time() - env["timestamp"]) > REPLAY_WINDOW

    fresh = restamp_envelope(env, mac)

    # After: transport timestamp is fresh → passes the manager's replay check.
    assert abs(time.time() - fresh["timestamp"]) <= REPLAY_WINDOW


def test_restamp_keeps_payload_and_collected_at_intact():
    enc, mac = _keys()
    event_ts = int(time.time()) - 7200
    env = encrypt({"section": "ports", "collected_at": event_ts, "data": {"p": 22}},
                  enc, mac, "mac-1", event_ts)
    fresh = restamp_envelope(env, mac)

    # Ciphertext unchanged → decrypts, and the EVENT time is preserved.
    payload = decrypt(fresh, enc, mac)
    assert payload["collected_at"] == event_ts
    assert payload["data"] == {"p": 22}


def test_restamp_hmac_is_valid_for_new_timestamp():
    enc, mac = _keys()
    env = encrypt({"data": {"x": 1}}, enc, mac, "mac-1", int(time.time()) - 1000)
    fresh = restamp_envelope(env, mac)
    expected = _compute_hmac(mac, fresh["agent_id"], fresh["timestamp"],
                             fresh["nonce"], fresh["ct"])
    assert fresh["hmac"] == expected          # HMAC covers the new timestamp


def test_restamp_does_not_mutate_original():
    enc, mac = _keys()
    env = encrypt({"data": {"x": 1}}, enc, mac, "mac-1", 1000)
    original_ts = env["timestamp"]
    restamp_envelope(env, mac)
    assert env["timestamp"] == original_ts     # spooled copy untouched
