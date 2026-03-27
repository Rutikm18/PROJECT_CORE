"""manager/auth.py — Envelope verification pipeline."""

import time
from .crypto import decrypt

REPLAY_WINDOW = 300  # seconds


def verify_envelope(envelope: dict, enc_key: bytes, mac_key: bytes,
                    nonce_cache: dict) -> dict:
    """
    Full verification pipeline. Raises ValueError with a safe message.
    Order: schema → timestamp → nonce → HMAC+decrypt
    (cheap checks before expensive crypto)
    """
    for field in ("v", "agent_id", "timestamp", "nonce", "ct", "hmac"):
        if field not in envelope:
            raise ValueError(f"Missing field: {field}")

    skew = abs(time.time() - envelope["timestamp"])
    if skew > REPLAY_WINDOW:
        raise ValueError("Timestamp out of window")

    nonce = envelope["nonce"]
    if nonce in nonce_cache:
        raise ValueError("Duplicate nonce (replay)")

    payload = decrypt(envelope, enc_key, mac_key)   # raises on HMAC failure
    nonce_cache[nonce] = time.time() + REPLAY_WINDOW
    return payload
