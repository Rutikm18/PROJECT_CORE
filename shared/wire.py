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
      "collected_at": int,  # Unix epoch
      "data":         any,  # section-specific payload
    }
"""

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
P_COLLECTED_AT = "collected_at"
P_DATA         = "data"

# ── Protocol constants ────────────────────────────────────────────────────────
WIRE_VERSION          = 1
REPLAY_WINDOW_SECONDS = 300   # ±5 minutes
NONCE_BYTES           = 12    # 96-bit GCM nonce (NIST SP 800-38D)
KEY_BYTES             = 32    # AES-256
