"""
agent/tests/unit/test_policy.py — verify-then-parse contract for policy.py.

Pins down: a valid policy verifies; every tampered signed field is caught as
SignatureInvalid (we sign raw bytes, so any flip breaks the signature); the
non-signature rejections (expiry/audience/downgrade/key/schema/corrupt) each
fire with the right `.reason`; and the JSON parser NEVER runs on unverified
bytes (asserted by spying on call order).
"""
from __future__ import annotations

import time

import pytest

from agent.agent import policy as policy_mod
from agent.agent.policy import (
    AudienceMismatch,
    KeyUnavailable,
    PolicyCorrupt,
    PolicyDowngrade,
    PolicyError,
    PolicyExpired,
    SchemaInvalid,
    SignatureInvalid,
    load_verified,
)
from agent.tests.fixtures.signing import (
    TEST_KEY_ID,
    make_policy,
    make_trust,
    new_keypair,
    public_key_of,
)

AGENT_ID = "mac-unit-001"
GROUPS = ["canary"]


def _load(wire, *, trust=None, now=None, high_water=None,
          agent_id=AGENT_ID, group_ids=GROUPS):
    return load_verified(
        wire,
        agent_id=agent_id,
        group_ids=group_ids,
        trust=trust or make_trust(),
        now_wall=now if now is not None else time.time(),
        high_water=high_water or {},
    )


# ── Happy path ─────────────────────────────────────────────────────────────

def test_valid_policy_verifies_and_parses():
    wire = make_policy("security", 5, {"threshold": 80})
    pol = _load(wire)
    assert pol.type == "security"
    assert pol.version == 5
    assert pol.content["threshold"] == 80
    assert isinstance(pol.raw_payload, bytes)


def test_audience_agent_id_and_group_accepted():
    _load(make_policy("telemetry", 1, {}, audience=AGENT_ID))
    _load(make_policy("telemetry", 2, {}, audience="canary"))
    _load(make_policy("telemetry", 3, {}, audience="fleet"))


# ── Tampering every signed field → SignatureInvalid ──────────────────────────

@pytest.mark.parametrize(
    "field", ["version", "issued_at", "expires_at", "audience",
              "content_byte", "signature"],
)
def test_tampered_field_is_signature_invalid(field):
    wire = make_policy("security", 7, {"threshold": 50}, tamper=field)
    with pytest.raises(SignatureInvalid) as ei:
        _load(wire)
    assert ei.value.reason == "signature_invalid"


# ── Non-signature rejections ─────────────────────────────────────────────────

def test_expired_policy():
    # issued well in the past, already expired
    wire = make_policy("security", 1, {}, issued_at=int(time.time()) - 10_000,
                       ttl=100)
    with pytest.raises(PolicyExpired) as ei:
        _load(wire)
    assert ei.value.reason == "expired"


def test_downgrade_rejected():
    wire = make_policy("security", 3, {})
    with pytest.raises(PolicyDowngrade) as ei:
        _load(wire, high_water={"security": 3})
    assert ei.value.reason == "downgrade"
    # equal version is also a downgrade (monotonic, strictly-greater required)
    with pytest.raises(PolicyDowngrade):
        _load(make_policy("security", 3, {}), high_water={"security": 5})


def test_wrong_audience():
    wire = make_policy("response", 1, {}, audience="prod")
    with pytest.raises(AudienceMismatch) as ei:
        _load(wire)
    assert ei.value.reason == "audience_mismatch"


def test_future_dated_is_corrupt():
    wire = make_policy("security", 1, {}, issued_at=int(time.time()) + 10_000)
    with pytest.raises(PolicyCorrupt) as ei:
        _load(wire)
    assert ei.value.reason == "corrupt"


def test_key_unavailable():
    wire = make_policy("security", 1, {}, key_id="no-such-key")
    with pytest.raises(KeyUnavailable) as ei:
        _load(wire)
    assert ei.value.reason == "key_unavailable"


def test_wrong_key_is_signature_invalid():
    other = new_keypair()
    # signed by `other`, but trust still pins the default key under TEST_KEY_ID
    wire = make_policy("security", 1, {}, key=other, key_id=TEST_KEY_ID)
    with pytest.raises(SignatureInvalid):
        _load(wire)


def test_bad_base64_is_corrupt():
    wire = make_policy("security", 1, {})
    wire["payload_b64"] = "!!!not base64!!!"
    with pytest.raises(PolicyCorrupt) as ei:
        _load(wire)
    assert ei.value.reason == "corrupt"


def test_bad_json_after_valid_signature_is_corrupt():
    # Sign raw non-JSON bytes so the signature verifies but json.loads fails.
    import base64 as _b64

    from agent.tests.fixtures import signing
    raw = b"this is not json"
    sig = signing._DEFAULT_KEY.sign(raw)
    wire = {
        "payload_b64": _b64.b64encode(raw).decode(),
        "signature_b64": _b64.b64encode(sig).decode(),
        "sig_alg": "ed25519",
        "key_id": TEST_KEY_ID,
    }
    with pytest.raises(PolicyCorrupt) as ei:
        _load(wire)
    assert ei.value.reason == "corrupt"


def test_unsupported_sig_alg_is_signature_invalid():
    wire = make_policy("security", 1, {})
    wire["sig_alg"] = "hmac-sha1"
    with pytest.raises(SignatureInvalid):
        _load(wire)


def test_bad_schema_version():
    wire = make_policy("security", 1, {}, schema=2)
    with pytest.raises(SchemaInvalid):
        _load(wire)


def test_response_content_schema_enforced():
    wire = make_policy("response", 1, {"allowed_actions": "isolate"})  # not a list
    with pytest.raises(SchemaInvalid):
        _load(wire)


# ── The parser must never run on unverified bytes ─────────────────────────────

def test_json_parse_never_runs_before_verify(monkeypatch):
    order: list[str] = []

    real_verify = policy_mod._verify_signature
    real_loads = policy_mod.json.loads

    def spy_verify(*a, **k):
        order.append("verify")
        return real_verify(*a, **k)

    def spy_loads(*a, **k):
        order.append("parse")
        return real_loads(*a, **k)

    monkeypatch.setattr(policy_mod, "_verify_signature", spy_verify)
    monkeypatch.setattr(policy_mod.json, "loads", spy_loads)

    _load(make_policy("security", 1, {}))
    assert order and order[0] == "verify"
    assert order.index("verify") < order.index("parse")


def test_json_parse_skipped_when_signature_invalid(monkeypatch):
    parsed = {"hit": False}
    real_loads = policy_mod.json.loads

    def spy_loads(*a, **k):
        parsed["hit"] = True
        return real_loads(*a, **k)

    # Force verification to fail; the parser must not be reached.
    monkeypatch.setattr(policy_mod, "_verify_signature", lambda *a, **k: False)
    monkeypatch.setattr(policy_mod.json, "loads", spy_loads)

    with pytest.raises(SignatureInvalid):
        _load(make_policy("security", 1, {}))
    assert parsed["hit"] is False


def test_all_errors_subclass_policy_error():
    for cls in (SignatureInvalid, PolicyExpired, PolicyDowngrade,
                AudienceMismatch, PolicyCorrupt, KeyUnavailable, SchemaInvalid):
        assert issubclass(cls, PolicyError)
