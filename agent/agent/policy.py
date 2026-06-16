"""
agent/agent/policy.py — Signed-policy envelope: model, decode, verify-then-parse.

A *policy* is a signed configuration document the manager pushes to the agent
(`GET /api/v1/policies/<type>`). It lets the control plane tighten or relax the
agent's behaviour (security thresholds, response actions, telemetry cadence,
compliance baselines) WITHOUT shipping new code — but only when the document is
cryptographically trustworthy.

Security contract (byte-exact, no canonicalisation):
  • The manager signs the *exact bytes* it base64-encodes into `payload_b64`.
  • The agent verifies the signature over those raw decoded bytes and parses the
    JSON **only after** verification succeeds. The agent never re-serialises the
    payload, so there is no canonical-JSON negotiation to get wrong.
  • `sig_alg` selects the verify routine; `key_id` selects the pinned public key.

Trust + signature primitives reuse the `cryptography` library already pulled in
by `agent/crypto.py` (AES-GCM/HKDF) — this is NOT a parallel crypto stack, it is
the asymmetric-verify half of the same dependency. Pinned-key handling lives in
`TrustStore` (keys loaded from `paths.keystore_dir`).

This module builds NO detection/response logic — only the trusted substrate.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

log = logging.getLogger("agent.policy")

# Max wall-clock skew tolerated for future-dated `issued_at` (seconds).
MAX_SKEW_SEC = 300

# Policy document schema version this agent understands.
SCHEMA_VERSION = 1

# The policy types the control plane may push. `response` is special: it is the
# only one that can grant active-response capability, and it always fails closed.
VALID_TYPES = ("security", "response", "telemetry", "compliance")

_SUPPORTED_ALGS = ("ed25519", "rsa-pss-sha256")


# ── Error taxonomy ──────────────────────────────────────────────────────────
# Every rejection carries a stable `.reason` code (logged, never the secret
# content). Subclasses fix the reason; an optional detail aids debugging.

class PolicyError(Exception):
    """Base for every policy rejection. `.reason` is a stable machine code."""
    reason = "policy_error"

    def __init__(self, detail: str = ""):
        self._detail = detail
        super().__init__(f"{self.reason}: {detail}" if detail else self.reason)


class SignatureInvalid(PolicyError):
    reason = "signature_invalid"


class PolicyExpired(PolicyError):
    reason = "expired"


class PolicyDowngrade(PolicyError):
    reason = "downgrade"


class AudienceMismatch(PolicyError):
    reason = "audience_mismatch"


class PolicyCorrupt(PolicyError):
    reason = "corrupt"


class KeyUnavailable(PolicyError):
    reason = "key_unavailable"


class SchemaInvalid(PolicyError):
    reason = "schema_invalid"


# ── Verified policy model ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class SignedPolicy:
    """A policy whose signature, audience, expiry and version all checked out.

    `raw_payload` is the exact verified bytes — kept so callers can re-persist or
    re-verify without ever re-serialising (which would break the signature).
    """
    type: str
    version: int
    issued_at: int
    expires_at: int
    audience: str
    content: Mapping[str, Any]
    raw_payload: bytes


# ── Pinned-key trust store ─────────────────────────────────────────────────────

class TrustStore:
    """Maps `key_id` → pinned public key.

    Keys may be injected directly (tests) or loaded lazily from a directory of
    PEM files named `<key_id>.pub` (production, under `paths.keystore_dir`). The
    real pinned key is never used in tests; the test fixture injects its own.
    """

    def __init__(self, keys: Optional[Mapping[str, Any]] = None,
                 keystore_dir: Optional[str] = None):
        self._keys: dict[str, Any] = dict(keys or {})
        self._keystore_dir = keystore_dir

    def add(self, key_id: str, public_key: Any) -> None:
        self._keys[key_id] = public_key

    def key_for(self, key_id: str) -> Optional[Any]:
        """Return the pinned public key for `key_id`, or None if not trusted."""
        if key_id in self._keys:
            return self._keys[key_id]
        if self._keystore_dir:
            loaded = self._load_pinned(key_id)
            if loaded is not None:
                self._keys[key_id] = loaded
                return loaded
        return None

    def _load_pinned(self, key_id: str) -> Optional[Any]:
        # Reject path-traversal in key_id before touching the filesystem.
        if os.sep in key_id or "/" in key_id or "\\" in key_id or ".." in key_id:
            log.warning("Rejecting key_id with path separators: %r", key_id)
            return None
        path = os.path.join(self._keystore_dir, f"{key_id}.pub")
        try:
            with open(path, "rb") as f:
                return serialization.load_pem_public_key(f.read())
        except FileNotFoundError:
            return None
        except Exception as exc:
            log.warning("Pinned key %s unreadable: %s", path, exc)
            return None


# ── Signature verification (asymmetric half of the crypto dependency) ──────────

def _verify_signature(sig_alg: str, public_key: Any,
                      signature: bytes, payload: bytes) -> bool:
    """Verify `signature` over the raw `payload` bytes. Never raises."""
    try:
        if sig_alg == "ed25519":
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            public_key.verify(signature, payload)
            return True
        if sig_alg == "rsa-pss-sha256":
            if not isinstance(public_key, RSAPublicKey):
                return False
            public_key.verify(
                signature,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size,  # salt = digest length
                ),
                hashes.SHA256(),
            )
            return True
        return False  # unknown sig_alg
    except InvalidSignature:
        return False
    except Exception as exc:  # malformed key/signature material
        log.debug("verify error (%s): %s", sig_alg, exc)
        return False


# ── Per-type content schema validation ─────────────────────────────────────────

def schema_validate(policy_type: str, content: Any) -> None:
    """Light per-type validation of `content`. Raises SchemaInvalid on bad shape.

    Deliberately permissive on *unknown* keys (forward compatibility) but strict
    on the typed fields later phases consume.
    """
    if policy_type not in VALID_TYPES:
        raise SchemaInvalid(f"unknown policy type {policy_type!r}")
    if not isinstance(content, Mapping):
        raise SchemaInvalid("content must be an object")

    if policy_type == "response":
        actions = content.get("allowed_actions")
        if actions is not None:
            if not isinstance(actions, (list, tuple)) or not all(
                isinstance(a, str) for a in actions
            ):
                raise SchemaInvalid("response.allowed_actions must be a list of str")
        if "enabled" in content and not isinstance(content["enabled"], bool):
            raise SchemaInvalid("response.enabled must be a bool")


# ── Verify-then-parse ──────────────────────────────────────────────────────────

def load_verified(
    raw_obj: Mapping[str, Any],
    *,
    agent_id: str,
    group_ids: Iterable[str],
    trust: TrustStore,
    now_wall: float,
    high_water: Mapping[str, int],
) -> SignedPolicy:
    """Decode → verify signature → (only then) parse → validate → return.

    Order is security-critical and matches the manifest contract exactly:
      b64-decode · key lookup · verify · parse · schema==1 · audience ·
      future-dated · expiry · monotonic version · per-type schema.
    The JSON parser NEVER runs on unverified bytes.
    """
    # 1. base64-decode the transmitted (== signed) bytes.
    try:
        payload = base64.b64decode(raw_obj["payload_b64"], validate=True)
        signature = base64.b64decode(raw_obj["signature_b64"], validate=True)
        sig_alg = raw_obj["sig_alg"]
        key_id = raw_obj["key_id"]
    except (KeyError, TypeError, ValueError, base64.binascii.Error) as exc:
        raise PolicyCorrupt(f"bad wire object: {exc}") from exc

    if sig_alg not in _SUPPORTED_ALGS:
        # Unknown algorithm cannot be trusted — treat as an invalid signature.
        raise SignatureInvalid(f"unsupported sig_alg {sig_alg!r}")

    # 2. resolve the pinned public key.
    public_key = trust.key_for(key_id)
    if public_key is None:
        raise KeyUnavailable(key_id)

    # 3. verify BEFORE any parsing.
    if not _verify_signature(sig_alg, public_key, signature, payload):
        raise SignatureInvalid(f"key_id={key_id}")

    # 4. parse only after verification succeeds.
    try:
        p = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PolicyCorrupt(f"payload not JSON: {exc}") from exc
    if not isinstance(p, dict):
        raise PolicyCorrupt("payload is not an object")

    # 5. schema version.
    if p.get("schema") != SCHEMA_VERSION:
        raise SchemaInvalid(f"schema={p.get('schema')!r}")

    typ = p.get("type")

    # 6. audience binding.
    audience = p.get("audience")
    allowed_audiences = {agent_id, "fleet"} | set(group_ids)
    if audience not in allowed_audiences:
        raise AudienceMismatch(f"audience={audience!r}")

    # 7. timing fields must be sane integers.
    try:
        issued_at = int(p["issued_at"])
        expires_at = int(p["expires_at"])
        version = int(p["version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyCorrupt(f"bad timing/version field: {exc}") from exc

    # 8. future-dated beyond skew → corrupt/forged clock.
    if issued_at > now_wall + MAX_SKEW_SEC:
        raise PolicyCorrupt(f"future-dated issued_at={issued_at}")

    # 9. expiry (fail closed on stale policies).
    if expires_at <= now_wall:
        raise PolicyExpired(f"expires_at={expires_at}")

    # 10. monotonic version (replay / rollback protection).
    if version <= high_water.get(typ, 0):
        raise PolicyDowngrade(f"version={version} <= high_water")

    # 11. per-type content schema.
    content = p.get("content", {})
    schema_validate(typ, content)

    return SignedPolicy(
        type=typ,
        version=version,
        issued_at=issued_at,
        expires_at=expires_at,
        audience=audience,
        content=MappingProxyType(dict(content)),
        raw_payload=payload,
    )
