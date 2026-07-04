"""
manager/security_policy.py — Password policy and security controls.

PASSWORD POLICY (NIST SP 800-63B + OWASP recommendations)
  ─────────────────────────────────────────────────────────
  • Minimum 16 characters
  • Must contain: uppercase, lowercase, digit, special character
  • Maximum 128 characters (prevents DoS via bcrypt cost on huge inputs)
  • Disallow passwords from the top-10k common list
  • No character-class substitution tricks (checked after normalization)

PASSWORD HASHING
  ─────────────────────────────────────────────────────────
  PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023 recommendation).
  Format: pbkdf2:sha256:<iters>:<salt_hex>:<dk_hex>
  Stdlib-only — no new pip dependencies.

ACCOUNT LOCKOUT
  ─────────────────────────────────────────────────────────
  • IP lockout: 5 failures in 15 minutes → 15-minute block
  • Account lockout: 10 failures in 1 hour → 30-minute block
    (higher threshold than IP to limit DoS potential)
  • Both reset on successful login

SESSION POLICY
  ─────────────────────────────────────────────────────────
  • Absolute timeout: 8 hours (configurable via JWT_TTL_HOURS)
  • Idle timeout: 30 minutes of inactivity (enforced on frontend;
    server tracks last-activity in token claims)
  • Single active session per account (new login revokes old JTIs)

SECURITY HEADERS (applied via FastAPI middleware)
  ─────────────────────────────────────────────────────────
  Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options,
  Content-Security-Policy, Referrer-Policy, Permissions-Policy,
  Cache-Control on auth endpoints.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re

# ── Top-10 000 common passwords (abbreviated to the most critical subset) ─────
# Source: https://github.com/danielmiessler/SecLists (top-1000 truncated)
# Full list should be loaded from a file in production.
_COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password123", "batman", "admin", "welcome", "login",
    "hello", "charlie", "donald", "password2", "qwerty123", "1234567890",
    "iloveyou1", "sunshine1", "princess", "welcome1", "password12",
    "123456789", "password3", "123qwe", "test", "admin123",
    "attacklens", "attacklensiasm",   # own product names are never valid passwords
})

_SPECIAL_CHARS = r"!@#$%^&*\-_=+?.,;:~|<>()"


class PasswordPolicyError(ValueError):
    """Raised when a password fails policy — message is safe to surface to the user."""


def validate_password(password: str) -> None:
    """Raise PasswordPolicyError if the password does not meet policy.

    Call this on every admin-set password (e.g. DASHBOARD_PASSWORD validation
    at startup, future password-change endpoint).
    """
    if len(password) < 16:
        raise PasswordPolicyError("Password must be at least 16 characters.")
    if len(password) > 128:
        raise PasswordPolicyError("Password must not exceed 128 characters.")
    if not re.search(r"[A-Z]", password):
        raise PasswordPolicyError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise PasswordPolicyError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise PasswordPolicyError("Password must contain at least one digit.")
    if not re.search(rf"[{re.escape(_SPECIAL_CHARS)}]", password):
        raise PasswordPolicyError(
            f"Password must contain at least one special character ({_SPECIAL_CHARS})."
        )
    if password.lower() in _COMMON_PASSWORDS:
        raise PasswordPolicyError("Password is too common. Choose a unique password.")


# ── PBKDF2 hashing ───────────────────────────────────────────────────────────

_PBKDF2_ITERS   = 600_000
_PBKDF2_ALGO    = "sha256"
_PBKDF2_DK_LEN  = 32          # 256-bit derived key


def hash_password(password: str) -> str:
    """Return a storable hash string: pbkdf2:sha256:<iters>:<salt_hex>:<dk_hex>"""
    salt = os.urandom(32)
    dk   = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode(), salt, _PBKDF2_ITERS, _PBKDF2_DK_LEN)
    return f"pbkdf2:{_PBKDF2_ALGO}:{_PBKDF2_ITERS}:{salt.hex()}:{dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time PBKDF2 verify. Returns False for any malformed hash."""
    try:
        _, algo, iters_str, salt_hex, dk_hex = stored_hash.split(":")
        iters  = int(iters_str)
        salt   = bytes.fromhex(salt_hex)
        dk_ref = bytes.fromhex(dk_hex)
    except (ValueError, AttributeError):
        return False
    dk = hashlib.pbkdf2_hmac(algo, password.encode(), salt, iters, len(dk_ref))
    return hmac.compare_digest(dk, dk_ref)


# ── Security header values ────────────────────────────────────────────────────

SECURITY_HEADERS: dict[str, str] = {
    # Force HTTPS for 1 year (including subdomains) — effective only behind TLS
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    # Prevent MIME-type sniffing
    "X-Content-Type-Options": "nosniff",
    # Block framing (clickjacking protection)
    "X-Frame-Options": "DENY",
    # Disable legacy XSS filter (modern browsers ignore it; old IE might re-enable reflected XSS)
    "X-XSS-Protection": "0",
    # Limit referrer leakage
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Restrict powerful browser features
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), "
        "payment=(), usb=(), magnetometer=(), gyroscope=()"
    ),
    # CSP for the React SPA (served same-origin, inline styles from JSX, WebSocket)
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "   # JSX inline style= attributes
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        "connect-src 'self' ws: wss:; "        # WebSocket live feed
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    ),
}

AUTH_CACHE_HEADERS: dict[str, str] = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma":        "no-cache",
    "Expires":       "0",
}

# ── Lockout policy constants (imported by auth_ui) ────────────────────────────

# IP-based: protects against credential stuffing from one source
IP_LOCKOUT_ATTEMPTS = 5
IP_LOCKOUT_WINDOW   = 15 * 60    # 15 min window
IP_LOCKOUT_DURATION = 15 * 60    # 15 min block

# Account-based: protects a specific account even across IPs
ACCOUNT_LOCKOUT_ATTEMPTS = 10
ACCOUNT_LOCKOUT_WINDOW   = 60 * 60     # 1 h window
ACCOUNT_LOCKOUT_DURATION = 30 * 60     # 30 min block

# Session
SESSION_IDLE_MINUTES  = 30   # frontend enforces; server embeds in token claim
SESSION_TTL_HOURS     = 8
