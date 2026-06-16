"""
agent/tests/fixtures/signing.py — hermetic policy-signing helpers for tests.

Generates a throwaway ed25519 keypair (the real pinned key is NEVER used in
tests) and a `make_policy(...)` helper that emits the exact `GET
/api/v1/policies/<type>` wire object. `tamper=` mutates the transmitted bytes
*after* signing so the test can assert each rejection path.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.agent.policy import TrustStore

TEST_KEY_ID = "test-ed25519-1"

# One module-level keypair shared across a test session. Tests that need a
# *wrong* key call new_keypair() and pass key=.
_DEFAULT_KEY = Ed25519PrivateKey.generate()


def new_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_of(key: Optional[Ed25519PrivateKey] = None):
    return (key or _DEFAULT_KEY).public_key()


def make_trust(*, key_id: str = TEST_KEY_ID,
               key: Optional[Ed25519PrivateKey] = None) -> TrustStore:
    """A TrustStore pinning the (test) signing key under `key_id`."""
    return TrustStore({key_id: public_key_of(key)})


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _flip_byte(b: bytes, idx: int = 0) -> bytes:
    if not b:
        return b"\x00"
    ba = bytearray(b)
    ba[idx % len(ba)] ^= 0x01
    return bytes(ba)


def make_policy(
    policy_type: str,
    version: int,
    content: dict,
    *,
    audience: str = "fleet",
    ttl: int = 86400,
    issued_at: Optional[int] = None,
    schema: int = 1,
    key: Optional[Ed25519PrivateKey] = None,
    key_id: str = TEST_KEY_ID,
    sig_alg: str = "ed25519",
    tamper: Optional[str] = None,
) -> dict:
    """Build a signed wire object.

    tamper ∈ {version, issued_at, expires_at, audience, content_byte, signature}:
      • field tampers re-encode the payload with the field changed but keep the
        signature over the *original* bytes → verification fails (SignatureInvalid).
      • content_byte flips a payload byte; signature flips a signature byte.
    """
    now = int(time.time())
    issued = now if issued_at is None else issued_at
    payload_obj = {
        "schema": schema,
        "type": policy_type,
        "version": version,
        "issued_at": issued,
        "expires_at": issued + ttl,
        "audience": audience,
        "content": content,
    }
    raw = json.dumps(payload_obj, separators=(",", ":")).encode()
    signer = key or _DEFAULT_KEY
    signature = signer.sign(raw)

    payload_bytes = raw  # what we transmit as payload_b64

    if tamper in ("version", "issued_at", "expires_at", "audience"):
        tampered = dict(payload_obj)
        if tamper == "version":
            tampered["version"] = version + 1000
        elif tamper == "issued_at":
            tampered["issued_at"] = issued + 1
        elif tamper == "expires_at":
            tampered["expires_at"] = issued + ttl + 1
        elif tamper == "audience":
            tampered["audience"] = audience + "-evil"
        payload_bytes = json.dumps(tampered, separators=(",", ":")).encode()
    elif tamper == "content_byte":
        payload_bytes = _flip_byte(raw, idx=len(raw) // 2)
    elif tamper == "signature":
        signature = _flip_byte(signature)
    elif tamper is not None:
        raise ValueError(f"unknown tamper mode: {tamper!r}")

    return {
        "payload_b64": _b64(payload_bytes),
        "signature_b64": _b64(signature),
        "sig_alg": sig_alg,
        "key_id": key_id,
    }
