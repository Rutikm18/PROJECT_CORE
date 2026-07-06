"""
shared/wire.py — Wire protocol constants and envelope schema.

Envelope v1 structure (JSON over HTTPS / TLS 1.3):

    {
      "v":         int,     # protocol version — currently 1
      "agent_id":  str,     # unique agent identifier
      "timestamp": float,   # Unix epoch (seconds, float)
      "nonce":     str,     # base64-encoded 96-bit random nonce
      "ct":        str,     # base64-encoded AES-256-GCM ciphertext + GCM tag
      "hmac":      str,     # HMAC-SHA256 hex over agent_id:timestamp:nonce:ct
      "section":   str,     # plaintext routing hint (NOT trusted — verified after decrypt)
    }

Decrypted payload (gzip-compressed JSON inside "ct"):

    {
      "section":      str,  # authoritative section name (inside the envelope)
      "agent_id":     str,
      "agent_name":   str,
      "os":           str,  # "macos" | "windows" | "linux"
      "os_version":   str,
      "arch":         str,
      "hostname":     str,
      "collected_at": int,  # Unix epoch
      "data":         any,  # section-specific payload
    }

Payload-schema validation (`validate_payload`) lives here so both the ingest
endpoint and any future stream consumer (e.g. a Kafka storage-writer) enforce
the SAME contract. Historically only the *envelope* was validated; the inner
payload was read with silent defaults, so missing/empty fields were stored as
blanks with no signal. `validate_payload` turns that into an explicit report.
"""
from typing import Any, Mapping

# ── Envelope fields ───────────────────────────────────────────────────────────
F_VERSION   = "v"
F_AGENT_ID  = "agent_id"
F_TIMESTAMP = "timestamp"
F_NONCE     = "nonce"
F_CT        = "ct"
F_HMAC      = "hmac"
F_SECTION   = "section"   # plaintext routing hint

REQUIRED_ENVELOPE_FIELDS: frozenset[str] = frozenset({
    F_VERSION, F_AGENT_ID, F_TIMESTAMP, F_NONCE, F_CT, F_HMAC,
})

# ── Payload fields (inside the decrypted ct blob) ────────────────────────────
P_SECTION      = "section"
P_AGENT_ID     = "agent_id"
P_AGENT_NAME   = "agent_name"
P_OS           = "os"
P_OS_VERSION   = "os_version"
P_ARCH         = "arch"
P_HOSTNAME     = "hostname"
P_COLLECTED_AT = "collected_at"
P_DATA         = "data"

# Must be present AND non-empty for the record to be routable/scoreable.
# (`data` must be present; "present-but-empty" is reported separately so an
# empty collection is distinguishable from a structurally-broken payload.)
REQUIRED_PAYLOAD_FIELDS: frozenset[str] = frozenset({
    P_AGENT_ID, P_SECTION, P_COLLECTED_AT, P_DATA,
})

# Should be present; their absence degrades the asset record (host attribution,
# OS-specific scoring) but does not make the payload unroutable.
RECOMMENDED_PAYLOAD_FIELDS: frozenset[str] = frozenset({
    P_AGENT_NAME, P_OS, P_OS_VERSION, P_ARCH, P_HOSTNAME,
})


def _is_blank(v: Any) -> bool:
    """True for None / empty string / empty list / empty dict."""
    return v is None or v == "" or v == [] or v == {}


def validate_payload(payload: Mapping[str, Any]) -> dict:
    """Validate the decrypted payload against the canonical contract.

    Pure and side-effect-free so both the ingest endpoint and stream consumers
    can call it. Returns a report; the caller decides whether to flag or reject.

      ok                  → routable AND carries real telemetry
      missing             → required keys absent entirely
      empty               → required keys present but blank (excl. `data`)
      data_empty          → `data` present but empty ({}/[]/""/None)
      data_error          → `data` is just a collector error ({"error": "..."})
      recommended_missing → recommended keys absent or blank
    """
    if not isinstance(payload, Mapping):
        return {
            "ok": False, "missing": sorted(REQUIRED_PAYLOAD_FIELDS), "empty": [],
            "data_empty": True, "data_error": False,
            "recommended_missing": sorted(RECOMMENDED_PAYLOAD_FIELDS),
        }

    missing = sorted(f for f in REQUIRED_PAYLOAD_FIELDS if f not in payload)
    empty = sorted(
        f for f in (REQUIRED_PAYLOAD_FIELDS - {P_DATA})
        if f in payload and _is_blank(payload[f])
    )

    data = payload.get(P_DATA)
    data_empty = _is_blank(data)
    # A failed collector ships {"error": "..."} (agent core.py) — a section that
    # arrived but carries no real fields.
    data_error = isinstance(data, dict) and set(data.keys()) == {"error"}

    recommended_missing = sorted(
        f for f in RECOMMENDED_PAYLOAD_FIELDS
        if f not in payload or _is_blank(payload.get(f))
    )

    ok = not missing and not empty and not data_empty and not data_error
    return {
        "ok": ok,
        "missing": missing,
        "empty": empty,
        "data_empty": data_empty,
        "data_error": data_error,
        "recommended_missing": recommended_missing,
    }

# ── Protocol constants ────────────────────────────────────────────────────────
WIRE_VERSION          = 1
REPLAY_WINDOW_SECONDS = 300   # ±5 minutes
NONCE_BYTES           = 12    # 96-bit GCM nonce (NIST SP 800-38D)
KEY_BYTES             = 32    # AES-256

# ── Time window → seconds mapping (used by both agent and manager) ────────────
WINDOW_SECONDS: dict[str, int] = {
    "5m":  300,
    "15m": 900,
    "1h":  3600,
    "8h":  28800,
    "1d":  86400,
    "7d":  604800,
    "30d": 2592000,
    "90d": 7776000,
}
