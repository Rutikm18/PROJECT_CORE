"""
manager/manager/licensing.py — Customer licence keys that carry their own
entitlements.

A key is a signed, self-describing token:

    AL1.<crockford-base32(payload)>.<crockford-base32(ed25519 signature)>

The payload holds the entitlements — org, expiry, agent cap, tier, features —
so a deployment can verify a customer's rights with **no callback to us**. That
was the explicit requirement, and it drives every other decision here:

  * **Ed25519, not HMAC.** A shared secret would have to ship to anywhere that
    verifies, which makes every verifier able to mint keys. With a signature
    scheme the private key stays on the issuing manager and the public key is
    safe to embed in an agent, an installer, or a customer's own deployment.
  * **`kid` in the payload.** Signing keys have to be rotatable without
    invalidating every key already issued, so the payload names which key
    signed it and verification looks the key up.
  * **Crockford Base32.** No I, L, O or U, so the alphabet cannot produce a
    character a human misreads when a key is read aloud or retyped.

WHAT THIS DESIGN CANNOT DO
    A key that verifies offline cannot be revoked offline. Anyone holding a
    valid signed key can prove entitlement until `exp` passes, whatever you do
    server-side. That is inherent, not an implementation gap. Mitigate with
    short expiry, and treat the signature as proof of purchase — the online
    org-status check is what actually gates access.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

PREFIX = "AL1"
DEFAULT_KID = "k1"
DEFAULT_TIER = "standard"

# Crockford Base32: RFC 4648's alphabet with I, L, O and U removed so no
# character can be confused with 1, 0 or another letter when transcribed.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {c: i for i, c in enumerate(_ALPHABET)}
# Crockford's documented substitutions for the characters he removed.
_DECODE.update({"I": 1, "L": 1, "O": 0, "U": 0, "i": 1, "l": 1, "o": 0, "u": 0})
for _i, _c in enumerate(_ALPHABET):
    _DECODE[_c.lower()] = _i


class LicenseError(Exception):
    """Base class so callers can catch every licence failure in one place."""


class LicenseFormatError(LicenseError):
    """The key is not a well-formed AL1 token."""


class LicenseSignatureError(LicenseError):
    """The signature does not verify — forged, tampered, or wrong key."""


class LicenseExpiredError(LicenseError):
    """The key verified but its entitlement period has passed."""


class UnknownSigningKeyError(LicenseError):
    """The key names a `kid` this deployment has no public key for."""


# ── Crockford Base32 ─────────────────────────────────────────────────────────

def b32encode(data: bytes) -> str:
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    bits = len(data) * 8
    out = []
    for shift in range(((bits + 4) // 5 - 1) * 5, -1, -5):
        out.append(_ALPHABET[(num >> shift) & 0x1F])
    return "".join(out)


def b32decode(text: str, length: int) -> bytes:
    """Decode to exactly `length` bytes. Hyphens are stripped so a grouped,
    human-readable rendering of a key decodes the same as a bare one."""
    cleaned = text.replace("-", "").replace(" ", "").strip()
    if not cleaned:
        raise LicenseFormatError("empty encoded segment")
    num = 0
    for char in cleaned:
        value = _DECODE.get(char)
        if value is None:
            raise LicenseFormatError(f"invalid character {char!r} in licence key")
        num = (num << 5) | value
    return num.to_bytes(length, "big")


# ── Entitlements ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Entitlements:
    org_id: str
    org_slug: str
    issued_at: float
    expires_at: float
    max_agents: int
    tier: str = DEFAULT_TIER
    features: tuple[str, ...] = ()
    kid: str = DEFAULT_KID
    version: int = 1

    @property
    def expired(self) -> bool:
        return self.expires_at > 0 and time.time() >= self.expires_at

    @property
    def days_remaining(self) -> Optional[int]:
        if self.expires_at <= 0:
            return None
        return max(0, int((self.expires_at - time.time()) // 86400))

    def to_payload(self) -> dict:
        # Short keys keep the encoded key shorter; sort_keys at dump time makes
        # the signed bytes deterministic.
        return {
            "v": self.version, "kid": self.kid,
            "org": self.org_id, "slug": self.org_slug,
            "iat": int(self.issued_at), "exp": int(self.expires_at),
            "max": int(self.max_agents), "tier": self.tier,
            "feat": list(self.features),
        }

    @classmethod
    def from_payload(cls, payload: dict) -> "Entitlements":
        try:
            return cls(
                org_id=str(payload["org"]),
                org_slug=str(payload.get("slug") or ""),
                issued_at=float(payload.get("iat") or 0),
                expires_at=float(payload.get("exp") or 0),
                max_agents=int(payload.get("max") or 0),
                tier=str(payload.get("tier") or DEFAULT_TIER),
                features=tuple(str(f) for f in (payload.get("feat") or [])),
                kid=str(payload.get("kid") or DEFAULT_KID),
                version=int(payload.get("v") or 1),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise LicenseFormatError(f"malformed licence payload: {exc}") from exc

    def to_dict(self) -> dict:
        """Display shape for the API — never includes the key itself."""
        return {
            "org_id": self.org_id, "org_slug": self.org_slug,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
            "max_agents": self.max_agents, "tier": self.tier,
            "features": list(self.features), "kid": self.kid,
            "expired": self.expired, "days_remaining": self.days_remaining,
        }


def _canonical(payload: dict) -> bytes:
    """Bytes that get signed. Deterministic, so the same payload always
    produces the same signature and verification is not whitespace-sensitive."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# ── Key material ─────────────────────────────────────────────────────────────

def _load_private_key() -> Ed25519PrivateKey:
    """Private key from LICENSE_SIGNING_KEY (base32 or hex of the 32 raw bytes).

    Deliberately no auto-generation: silently minting a fresh key would make
    every previously issued licence unverifiable, and the failure would only
    surface at a customer's site. Missing key is a hard error.
    """
    raw = os.environ.get("LICENSE_SIGNING_KEY", "").strip()
    if not raw:
        raise LicenseError(
            "LICENSE_SIGNING_KEY is not set. Generate one with "
            "`python -m manager.manager.licensing --generate-key` and store it "
            "in your secret manager — not in .env for production."
        )
    try:
        seed = bytes.fromhex(raw) if len(raw) == 64 and all(
            c in "0123456789abcdefABCDEF" for c in raw
        ) else b32decode(raw, 32)
    except Exception as exc:
        raise LicenseError(f"LICENSE_SIGNING_KEY is not decodable: {exc}") from exc
    if len(seed) != 32:
        raise LicenseError("LICENSE_SIGNING_KEY must decode to exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_keys() -> dict[str, Ed25519PublicKey]:
    """kid -> public key.

    The active signing key is always present. `LICENSE_PUBLIC_KEYS` adds
    retired keys as `kid:base32` pairs so licences signed before a rotation
    keep verifying.
    """
    keys: dict[str, Ed25519PublicKey] = {}
    for entry in os.environ.get("LICENSE_PUBLIC_KEYS", "").split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        kid, _, encoded = entry.partition(":")
        try:
            keys[kid.strip()] = Ed25519PublicKey.from_public_bytes(
                b32decode(encoded.strip(), 32)
            )
        except Exception:
            continue
    try:
        keys[active_kid()] = _load_private_key().public_key()
    except LicenseError:
        pass
    return keys


def active_kid() -> str:
    return os.environ.get("LICENSE_KID", DEFAULT_KID).strip() or DEFAULT_KID


def public_key_b32() -> str:
    """The active public key, for embedding in an offline verifier."""
    return b32encode(_load_private_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


def generate_signing_key() -> str:
    """A new private key as base32, for the operator to store as a secret."""
    return b32encode(Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))


# ── Issue and verify ─────────────────────────────────────────────────────────

def issue(
    *,
    org_id: str,
    org_slug: str,
    valid_days: int = 365,
    max_agents: int = 25,
    tier: str = DEFAULT_TIER,
    features: tuple[str, ...] = (),
    issued_at: Optional[float] = None,
) -> tuple[str, Entitlements]:
    """Mint a licence key. Returns (key, entitlements).

    The key is shown to the operator once and never stored in full — callers
    persist `key_fingerprint(key)` and the entitlements.
    """
    now = float(issued_at if issued_at is not None else time.time())
    draft = Entitlements(
        org_id=org_id, org_slug=org_slug,
        issued_at=now,
        expires_at=now + valid_days * 86400 if valid_days > 0 else 0,
        max_agents=max_agents, tier=tier, features=tuple(features),
        kid=active_kid(),
    )
    payload_dict = draft.to_payload()
    payload = _canonical(payload_dict)
    signature = _load_private_key().sign(payload)
    # Return the entitlements *as encoded*, not as drafted. `to_payload` casts
    # timestamps to int, so the draft carries sub-second precision the key does
    # not — and the caller persists this object alongside the key. Round-tripping
    # through from_payload guarantees the stored record and the key agree.
    ent = Entitlements.from_payload(payload_dict)
    return f"{PREFIX}.{b32encode(payload)}.{b32encode(signature)}", ent


def verify(key: str, *, at: Optional[float] = None) -> Entitlements:
    """Verify a licence key and return its entitlements.

    Order matters: format, then signature, then expiry. Checking expiry before
    the signature would let a forged key produce a different error and leak
    whether its dates were plausible.
    """
    parts = (key or "").strip().split(".")
    if len(parts) != 3 or parts[0].upper() != PREFIX:
        raise LicenseFormatError(
            f"licence key must look like {PREFIX}.<payload>.<signature>"
        )
    _, payload_b32, sig_b32 = parts

    encoded = payload_b32.replace("-", "").replace(" ", "")
    payload_len = (len(encoded) * 5) // 8
    try:
        payload_bytes = b32decode(payload_b32, payload_len)
        signature = b32decode(sig_b32, 64)
    except LicenseFormatError:
        raise
    except Exception as exc:
        raise LicenseFormatError(f"licence key is not decodable: {exc}") from exc

    # The leading zero byte that base32 padding can introduce is not part of
    # the JSON, so trim to the first '{'.
    start = payload_bytes.find(b"{")
    if start < 0:
        raise LicenseFormatError("licence payload is not a JSON object")
    payload_bytes = payload_bytes[start:]

    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError as exc:
        raise LicenseFormatError(f"licence payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise LicenseFormatError("licence payload is not a JSON object")

    kid = str(payload.get("kid") or DEFAULT_KID)
    key_for_kid = public_keys().get(kid)
    if key_for_kid is None:
        raise UnknownSigningKeyError(
            f"licence was signed with key {kid!r}, which this deployment does "
            "not know. Add it to LICENSE_PUBLIC_KEYS to keep honouring keys "
            "issued before a rotation."
        )

    try:
        key_for_kid.verify(signature, _canonical(payload))
    except InvalidSignature as exc:
        raise LicenseSignatureError(
            "licence signature does not verify — the key was altered or was "
            "not issued by this platform"
        ) from exc

    ent = Entitlements.from_payload(payload)
    now = float(at if at is not None else time.time())
    if ent.expires_at > 0 and now >= ent.expires_at:
        raise LicenseExpiredError(
            f"licence for {ent.org_slug or ent.org_id} expired at "
            f"{int(ent.expires_at)}"
        )
    return ent


def key_fingerprint(key: str) -> str:
    """SHA-256 of the key. Stored instead of the key itself."""
    return hashlib.sha256((key or "").strip().encode()).hexdigest()


def format_grouped(key: str, group: int = 8) -> str:
    """Hyphenate the payload/signature for display. `verify` strips hyphens,
    so a grouped key and a bare one are the same key."""
    parts = key.split(".")
    if len(parts) != 3:
        return key
    def chunk(segment: str) -> str:
        return "-".join(segment[i:i + group] for i in range(0, len(segment), group))
    return f"{parts[0]}.{chunk(parts[1])}.{chunk(parts[2])}"


if __name__ == "__main__":                                   # pragma: no cover
    import sys
    if "--generate-key" in sys.argv:
        print(generate_signing_key())
    elif "--public-key" in sys.argv:
        print(public_key_b32())
    else:
        print(__doc__)
