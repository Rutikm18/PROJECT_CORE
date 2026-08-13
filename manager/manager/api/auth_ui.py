"""
manager/api/auth_ui.py — Dashboard authentication endpoints.

  POST /api/v1/auth/login    — validate credentials, issue JWT
  POST /api/v1/auth/logout   — invalidate session (revoke JTI)
  GET  /api/v1/auth/me       — return current user from live token
  GET  /api/v1/auth/policy   — return password/session policy for the UI

CREDENTIAL CONFIGURATION
  Set DASHBOARD_EMAIL and DASHBOARD_PASSWORD_HASH in the environment.
  Generate a hash with:
      python3 -c "from manager.security_policy import hash_password; print(hash_password('yourpassword'))"

  Falls back to plaintext DASHBOARD_PASSWORD (hashed at startup) for
  development convenience — do not use plaintext in production.

  Default (change before deploying):
    Email:    admin@attacklens.ai
    Password: !HLwS=f73fHo$?p!#M77XA*M   (option 1 from generated list)
    Hash:     pbkdf2:sha256:600000:c7b9...

SECURITY CONTROLS
  ─────────────────────────────────────────────────────────
  • Password hashing: PBKDF2-HMAC-SHA256, 600 000 iterations
  • IP lockout: 5 failures / 15 min → 15-min block
  • Account lockout: 10 failures / 1 h → 30-min block (DoS-resistant threshold)
  • No user enumeration: identical 401 for wrong email OR wrong password
  • Constant-time comparison on every code path — no short-circuit
  • Fake PBKDF2 work on unknown email to prevent timing oracle
  • JWT: HMAC-SHA256, 8 h absolute TTL, 30 min idle TTL embedded in claim
  • Single active session: new login revokes all previous JTIs for that account
  • httpOnly + SameSite=Strict cookie AND Authorization bearer (SPA dual delivery)
  • Token revocation list (JTI blacklist) with auto-pruning on expiry
  • Full audit log: every success / failure / lockout / logout with IP + UA
  • MFA hook: MFA_ENABLED=true when TOTP is wired in
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Cookie, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..security_policy import (
    verify_password, hash_password,
    IP_LOCKOUT_ATTEMPTS, IP_LOCKOUT_WINDOW, IP_LOCKOUT_DURATION,
    ACCOUNT_LOCKOUT_ATTEMPTS, ACCOUNT_LOCKOUT_WINDOW, ACCOUNT_LOCKOUT_DURATION,
    SESSION_IDLE_MINUTES, SESSION_TTL_HOURS,
    AUTH_CACHE_HEADERS,
)

log = logging.getLogger(__name__)
audit = logging.getLogger("manager.audit")   # separate audit logger

router = APIRouter(tags=["auth"])

# ── Credential setup ──────────────────────────────────────────────────────────
_ADMIN_EMAIL = os.environ.get("DASHBOARD_EMAIL", "admin@attacklens.ai").strip().lower()

# Prefer a pre-hashed password from env; fall back to plaintext (hashed once at import)
_stored_hash: str

_DEFAULT_PASSWORD = "!HLwS=f73fHo$?p!#M77XA*M"

_env_hash      = os.environ.get("DASHBOARD_PASSWORD_HASH", "").strip()
_env_plaintext = os.environ.get("DASHBOARD_PASSWORD", _DEFAULT_PASSWORD).strip()

if _env_hash:
    _stored_hash = _env_hash
else:
    # Hash the plaintext password at startup (600k PBKDF2 rounds — ~0.5s once)
    _stored_hash = hash_password(_env_plaintext)
    if _env_plaintext not in (_DEFAULT_PASSWORD,):
        log.warning(
            "auth: DASHBOARD_PASSWORD_HASH not set — password hashed at startup. "
            "Set DASHBOARD_PASSWORD_HASH in production to avoid recomputing on every restart."
        )

# The built-in default credential is "active" (safe to surface on the login
# screen for first-run convenience) ONLY when the operator has NOT overridden it
# via DASHBOARD_PASSWORD_HASH or a custom DASHBOARD_PASSWORD. We never expose an
# operator-set password (we only hold its hash) — only this known default.
_USING_DEFAULT_CREDENTIALS = (not _env_hash) and (_env_plaintext == _DEFAULT_PASSWORD)
if _USING_DEFAULT_CREDENTIALS:
    log.warning(
        "auth: using built-in DEFAULT dashboard password — surfaced on the login "
        "screen for first-run setup. Set DASHBOARD_PASSWORD_HASH before deploying."
    )

# Dummy hash used when the email is wrong: we still run PBKDF2 so the response
# time is identical whether the email exists or not (timing oracle prevention).
_DUMMY_HASH = hash_password(secrets.token_hex(32))

# ── JWT config ────────────────────────────────────────────────────────────────
_JWT_SECRET_B64 = os.environ.get("JWT_SECRET", "").strip()
if _JWT_SECRET_B64:
    try:
        _JWT_SECRET = base64.b64decode(_JWT_SECRET_B64)
    except Exception:
        _JWT_SECRET = _JWT_SECRET_B64.encode()
else:
    _JWT_SECRET = secrets.token_bytes(32)
    log.warning("auth: JWT_SECRET not set — using ephemeral key (sessions lost on restart)")

_JWT_TTL_HOURS    = int(os.environ.get("JWT_TTL_HOURS", str(SESSION_TTL_HOURS)))
_IDLE_TTL_MINUTES = int(os.environ.get("SESSION_IDLE_MINUTES", str(SESSION_IDLE_MINUTES)))
_COOKIE_NAME      = "al_session"

# ── Token stores ──────────────────────────────────────────────────────────────
# Revoked JTIs: {jti: expiry_epoch}. Pruned on logout and on /me calls.
_revoked: dict[str, float] = {}

# Active JTIs per account: {email: [jti, ...]} — new login revokes previous.
_active_sessions: dict[str, list[str]] = defaultdict(list)

# ── Rate limiting / lockout ───────────────────────────────────────────────────
# IP log: {ip: [timestamp_of_failure, ...]}
_ip_fail_log:      dict[str, list[float]] = defaultdict(list)
# Account log: {email: [timestamp_of_failure, ...]}
_acct_fail_log:    dict[str, list[float]] = defaultdict(list)

# MFA hook
_MFA_ENABLED = os.environ.get("MFA_ENABLED", "false").lower() in ("1", "true", "yes")


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


def _make_token(
    email: str, role: str, tenant_id: str = "default",
) -> tuple[str, str, float]:
    """Return (token, jti, exp_epoch)."""
    now  = time.time()
    exp  = now + _JWT_TTL_HOURS * 3600
    jti  = secrets.token_urlsafe(20)
    hdr  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pay  = _b64url(json.dumps({
        "sub":  email,
        "role": role,
        "tenant_id": str(tenant_id or "default")[:120],
        "jti":  jti,
        "iat":  int(now),
        "exp":  int(exp),
        "idle": _IDLE_TTL_MINUTES,   # frontend reads this for idle-timeout config
    }).encode())
    sig_input = f"{hdr}.{pay}".encode()
    sig = _b64url(hmac.new(_JWT_SECRET, sig_input, hashlib.sha256).digest())
    return f"{hdr}.{pay}.{sig}", jti, exp


def _verify_token(token: str) -> Optional[dict]:
    """Constant-time verify. Returns decoded payload or None."""
    try:
        hdr, pay_b64, sig = token.split(".")
    except ValueError:
        return None
    expected = _b64url(hmac.new(_JWT_SECRET, f"{hdr}.{pay_b64}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig.encode(), expected.encode()):
        return None
    try:
        payload = json.loads(_b64url_decode(pay_b64))
    except Exception:
        return None
    if payload.get("exp", 0) < time.time():
        return None
    if payload.get("jti") in _revoked:
        return None
    return payload


# ── Lockout helpers ───────────────────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For", "").split(",")
    candidate = fwd[0].strip()
    return candidate if candidate else (request.client.host if request.client else "unknown")


def _user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "")[:200]


def _ip_allowed(ip: str) -> bool:
    now = time.time()
    _ip_fail_log[ip] = [t for t in _ip_fail_log[ip] if t > now - IP_LOCKOUT_WINDOW]
    return len(_ip_fail_log[ip]) < IP_LOCKOUT_ATTEMPTS


def _account_allowed(email: str) -> bool:
    now = time.time()
    _acct_fail_log[email] = [t for t in _acct_fail_log[email] if t > now - ACCOUNT_LOCKOUT_WINDOW]
    return len(_acct_fail_log[email]) < ACCOUNT_LOCKOUT_ATTEMPTS


def _record_failure(ip: str, email: str) -> tuple[int, int]:
    """Record failure for both IP and account; return (ip_count, acct_count)."""
    _ip_fail_log[ip].append(time.time())
    _acct_fail_log[email].append(time.time())
    return len(_ip_fail_log[ip]), len(_acct_fail_log[email])


def _reset_counters(ip: str, email: str) -> None:
    _ip_fail_log.pop(ip, None)
    _acct_fail_log.pop(email, None)


def _lockout_minutes(ip: str, email: str) -> int:
    """Return remaining lockout minutes (max of IP vs account)."""
    now = time.time()
    ip_fails   = [t for t in _ip_fail_log.get(ip, [])    if t > now - IP_LOCKOUT_WINDOW]
    acct_fails = [t for t in _acct_fail_log.get(email, []) if t > now - ACCOUNT_LOCKOUT_WINDOW]
    ip_locked  = len(ip_fails)   >= IP_LOCKOUT_ATTEMPTS
    acct_locked = len(acct_fails) >= ACCOUNT_LOCKOUT_ATTEMPTS
    if not ip_locked and not acct_locked:
        return 0
    # Time until the oldest failure in the blocking window drops out
    oldest_ip   = min(ip_fails)   if ip_locked   else now
    oldest_acct = min(acct_fails) if acct_locked else now
    duration = IP_LOCKOUT_DURATION if ip_locked else ACCOUNT_LOCKOUT_DURATION
    remaining = int((min(oldest_ip, oldest_acct) + duration - now) / 60) + 1
    return max(1, remaining)


def _prune_revoked() -> None:
    now = time.time()
    for jti in [j for j, e in _revoked.items() if e < now]:
        _revoked.pop(jti, None)


def _revoke_all_sessions(email: str) -> None:
    """Revoke every active JTI for this account (single-session enforcement)."""
    for jti in _active_sessions.pop(email, []):
        _revoked[jti] = time.time() + _JWT_TTL_HOURS * 3600


# ── Error responses — no user enumeration ─────────────────────────────────────

def _auth_error(locked_minutes: int = 0) -> JSONResponse:
    if locked_minutes:
        return JSONResponse(
            {"error": f"Too many failed attempts. Try again in {locked_minutes} minute(s)."},
            status_code=429,
            headers=AUTH_CACHE_HEADERS,
        )
    return JSONResponse(
        {"error": "Invalid credentials."},
        status_code=401,
        headers=AUTH_CACHE_HEADERS,
    )


# ── Schemas ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email:    str
    password: str
    # mfa_code: str | None = None   # wire in when MFA_ENABLED


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/api/v1/auth/login")
async def login(body: LoginRequest, request: Request, response: Response):
    ip = _client_ip(request)
    ua = _user_agent(request)

    email    = (body.email    or "").strip().lower()
    password = (body.password or "").strip()

    # Missing fields → same error as wrong creds (no field enumeration)
    if not email or not password:
        audit.warning("login.empty_fields ip=%s ua=%s", ip, ua)
        return _auth_error()

    # ── Lockout check (IP + account, before any crypto) ──────────────────────
    ip_ok    = _ip_allowed(ip)
    acct_ok  = _account_allowed(email)
    if not ip_ok or not acct_ok:
        mins = _lockout_minutes(ip, email)
        audit.warning("login.locked ip=%s email=%s remaining_min=%d ua=%s", ip, email, mins, ua)
        return _auth_error(locked_minutes=mins)

    # ── Credential check ──────────────────────────────────────────────────────
    # Always run PBKDF2 regardless of whether the email matches — prevents
    # timing attacks that distinguish "unknown email" from "wrong password".
    email_matches = hmac.compare_digest(email.encode(), _ADMIN_EMAIL.encode())
    hash_to_check = _stored_hash if email_matches else _DUMMY_HASH
    password_ok   = verify_password(password, hash_to_check)

    if not (email_matches and password_ok):
        ip_count, acct_count = _record_failure(ip, email)
        ip_remaining   = max(0, IP_LOCKOUT_ATTEMPTS   - ip_count)
        acct_remaining = max(0, ACCOUNT_LOCKOUT_ATTEMPTS - acct_count)
        audit.warning(
            "login.failure ip=%s email=%s ip_count=%d acct_count=%d ua=%s",
            ip, email, ip_count, acct_count, ua,
        )
        mins = _lockout_minutes(ip, email)
        if mins:
            return _auth_error(locked_minutes=mins)
        return _auth_error()

    # ── MFA hook ──────────────────────────────────────────────────────────────
    if _MFA_ENABLED:
        # Extend: mfa_code = body.mfa_code; if not _verify_totp(email, mfa_code): return _auth_error()
        pass

    # ── Issue token ───────────────────────────────────────────────────────────
    # Revoke all previous sessions for this account (single active session)
    _revoke_all_sessions(email)
    _prune_revoked()

    token, jti, exp = _make_token(email, "admin")
    _active_sessions[email].append(jti)

    _reset_counters(ip, email)

    audit.info("login.success ip=%s email=%s jti=%s ua=%s", ip, email, jti[:8], ua)

    response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="strict",
        secure=os.environ.get("HTTPS_ONLY", "false").lower() in ("1", "true", "yes"),
        max_age=_JWT_TTL_HOURS * 3600,
        path="/",
    )
    # Cache-control: auth responses must never be cached
    for k, v in AUTH_CACHE_HEADERS.items():
        response.headers[k] = v

    return {
        "token":      token,
        "expires_at": int(exp),
        "idle_minutes": _IDLE_TTL_MINUTES,
        "user": {
            "email":    email,
            "role":     "admin",
            "name":     "Admin",
            "initials": "A",
        },
    }


@router.post("/api/v1/auth/logout")
async def logout(
    request:    Request,
    response:   Response,
    al_session: str = Cookie(default=""),
):
    ip = _client_ip(request)
    bearer = request.headers.get("Authorization", "")
    token  = al_session or (bearer.removeprefix("Bearer ").strip() if bearer.startswith("Bearer ") else "")

    if token:
        payload = _verify_token(token)
        if payload:
            jti   = payload.get("jti", "")
            exp   = payload.get("exp", 0.0)
            email = payload.get("sub", "")
            if jti:
                _revoked[jti] = exp
                if email in _active_sessions:
                    _active_sessions[email] = [j for j in _active_sessions[email] if j != jti]
                _prune_revoked()
            audit.info("logout.success ip=%s email=%s jti=%s", ip, email, jti[:8] if jti else "")

    response.delete_cookie(_COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/api/v1/auth/me")
async def me(
    request:    Request,
    response:   Response,
    al_session: str = Cookie(default=""),
):
    bearer = request.headers.get("Authorization", "")
    token  = al_session or (bearer.removeprefix("Bearer ").strip() if bearer.startswith("Bearer ") else "")

    for k, v in AUTH_CACHE_HEADERS.items():
        response.headers[k] = v

    if not token:
        return JSONResponse({"error": "Not authenticated."}, status_code=401, headers=AUTH_CACHE_HEADERS)

    payload = _verify_token(token)
    if not payload:
        return JSONResponse({"error": "Session expired or invalid."}, status_code=401, headers=AUTH_CACHE_HEADERS)

    return {
        "email":        payload.get("sub"),
        "role":         payload.get("role", "admin"),
        "name":         "Admin",
        "initials":     "A",
        "expires_at":   payload.get("exp"),
        "idle_minutes": payload.get("idle", _IDLE_TTL_MINUTES),
    }


@router.get("/api/v1/auth/policy")
async def auth_policy():
    """Return session and password policy parameters for the UI to enforce."""
    return {
        "session": {
            "ttl_hours":    _JWT_TTL_HOURS,
            "idle_minutes": _IDLE_TTL_MINUTES,
        },
        "password": {
            "min_length":    16,
            "max_length":    128,
            "require_upper": True,
            "require_lower": True,
            "require_digit": True,
            "require_special": True,
        },
        "lockout": {
            "ip_attempts":       IP_LOCKOUT_ATTEMPTS,
            "ip_window_minutes": IP_LOCKOUT_WINDOW // 60,
            "ip_duration_minutes": IP_LOCKOUT_DURATION // 60,
            "account_attempts":       ACCOUNT_LOCKOUT_ATTEMPTS,
            "account_window_minutes": ACCOUNT_LOCKOUT_WINDOW // 60,
            "account_duration_minutes": ACCOUNT_LOCKOUT_DURATION // 60,
        },
        "mfa_enabled": _MFA_ENABLED,
        # First-run convenience: expose the built-in default credential so the
        # login screen can offer click-to-autofill — but ONLY while that default
        # is actually in use. Once an operator sets a custom password, `active`
        # is false and no password is returned.
        "default_credentials": {
            "active":   _USING_DEFAULT_CREDENTIALS,
            "email":    _ADMIN_EMAIL if _USING_DEFAULT_CREDENTIALS else None,
            "password": _DEFAULT_PASSWORD if _USING_DEFAULT_CREDENTIALS else None,
        },
    }
