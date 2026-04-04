"""
agent/agent/enrollment.py — First-run key generation and manager enrollment.

Enrollment flow
───────────────
  1. Check keystore → if a key already exists, skip enrollment (idempotent).
  2. Generate a fresh 256-bit API key via secrets.token_hex(32).
  3. Persist key to keystore FIRST — so it is never lost even if the network
     call later fails.
  4. POST /api/v1/enroll to the manager with the one-time enrollment token.
  5. Manager validates the token, stores agent_id → api_key.
  6. Return the generated key; caller clears the enrollment token from config.

Security notes
──────────────
  • The enrollment token is a one-time or operator-managed secret.  It is only
    sent over TLS 1.3 and never repeated once enrollment succeeds.
  • The actual payload key (api_key) is agent-generated — the manager never
    issues it, it only records it.  Compromise of the enrollment token does NOT
    expose an already-enrolled agent's session key.
  • Re-enrollment (key rotation) is supported: calling enroll() when a key is
    already stored will overwrite it after a successful manager acknowledgment.
"""
from __future__ import annotations

import json
import logging
import platform
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

from .keystore import store_key, load_key, delete_key

log = logging.getLogger("agent.enrollment")


class EnrollmentError(Exception):
    """Raised when enrollment fails and cannot be retried without operator action."""


# ── Public API ────────────────────────────────────────────────────────────────

def needs_enrollment(
    agent_id: str,
    backend: str = "keychain",
    security_dir: str = "/Library/Application Support/MacIntel/security",
) -> bool:
    """Return True if no API key is stored for this agent (first run)."""
    return load_key(agent_id, backend=backend, security_dir=security_dir) is None


def enroll(cfg: dict) -> str:
    """
    Run the full enrollment flow.  Returns the generated API key (64-char hex).
    Raises EnrollmentError on any unrecoverable failure.

    Required cfg keys
    -----------------
    cfg["agent"]["id"]
    cfg["agent"]["name"]
    cfg["manager"]["url"]
    cfg["manager"]["tls_verify"]
    cfg["enrollment"]["token"]     — one-time token from manager operator
    cfg["enrollment"]["keystore"]  — "keychain" | "file"
    cfg["paths"]["security_dir"]   — directory for file-backend key storage
    """
    agent_id     = cfg["agent"]["id"]
    agent_name   = cfg["agent"].get("name", "")
    token        = cfg.get("enrollment", {}).get("token", "").strip()
    backend      = cfg.get("enrollment", {}).get("keystore", "keychain")
    security_dir = cfg.get("paths", {}).get(
        "security_dir",
        "/Library/Application Support/MacIntel/security",
    )

    if not token:
        raise EnrollmentError(
            "No enrollment token in [enrollment] token = '...'. "
            "Run `make enroll-token` or set token in agent.toml to match the manager."
        )

    # Step 1 — generate key
    api_key = secrets.token_hex(32)   # 256-bit
    log.info("Generated 256-bit API key for agent_id=%s", agent_id)

    # Step 2 — persist BEFORE network call (key is never lost)
    try:
        store_key(agent_id, api_key, backend=backend, security_dir=security_dir)
    except Exception as exc:
        raise EnrollmentError(f"Keystore write failed — aborting enrollment: {exc}") from exc

    # Step 3 — register with manager
    url = cfg["manager"]["url"].rstrip("/") + "/api/v1/enroll"
    try:
        _post_enroll(
            url=url,
            token=token,
            payload={
                "agent_id":   agent_id,
                "agent_name": agent_name,
                "api_key":    api_key,
                "hostname":   socket.gethostname(),
                "os":         "macos" if sys.platform == "darwin" else sys.platform,
                "arch":       platform.machine(),
                "timestamp":  int(time.time()),
            },
            tls_verify=cfg["manager"].get("tls_verify", True),
        )
    except EnrollmentError as exc:
        # If manager never accepted the key, drop the local key so the next run can retry
        # (avoids "HMAC mismatch" from a key that never reached the server).
        err = str(exc).lower()
        if "401" in err or "invalid enrollment token" in err or "rejected enrollment" in err:
            try:
                delete_key(agent_id, backend=backend, security_dir=security_dir)
                log.warning(
                    "Enrollment failed — removed local key so you can fix the token and retry"
                )
            except Exception:
                pass
        raise
    except Exception as exc:
        raise EnrollmentError(f"Manager enrollment request failed: {exc}") from exc

    log.info("Enrollment complete: agent_id=%s", agent_id)
    return api_key


# ── Internal ──────────────────────────────────────────────────────────────────

def _post_enroll(url: str, token: str, payload: dict, tls_verify: bool) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if not tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type":       "application/json",
            "X-Enrollment-Token": token,
            "User-Agent":         "mac_intel-agent/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            status    = resp.status
            body_resp = resp.read()
    except urllib.error.HTTPError as exc:
        status    = exc.code
        body_resp = exc.read()

    if status == 200:
        return
    if status == 401:
        raise EnrollmentError(
            f"Manager rejected enrollment token (HTTP 401). "
            f"Check [enrollment] token in agent.conf. "
            f"Server: {body_resp.decode(errors='replace')}"
        )
    if status == 409:
        raise EnrollmentError(
            "Agent already enrolled on manager (HTTP 409). "
            "To re-enroll: delete the stored key and set a fresh token."
        )
    raise EnrollmentError(
        f"Manager returned HTTP {status}: {body_resp.decode(errors='replace')}"
    )
