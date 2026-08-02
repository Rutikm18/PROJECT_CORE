"""Resource limits for authenticated encrypted telemetry."""
from __future__ import annotations

import pytest

from agent.agent.crypto import encrypt
from manager.manager import crypto as manager_crypto


def test_decompression_bomb_is_rejected(monkeypatch):
    key = "a" * 64
    enc_key, mac_key = manager_crypto.derive_keys(key)
    payload = {"data": "A" * 10_000}
    envelope = encrypt(payload, enc_key, mac_key, "agent-1", 1)
    monkeypatch.setattr(manager_crypto, "MAX_DECOMPRESSED_BYTES", 100)

    with pytest.raises(ValueError, match="Decompressed payload exceeds"):
        manager_crypto.decrypt(envelope, enc_key, mac_key)
