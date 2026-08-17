"""
manager/manager/ai/key_store.py — Encrypted AI provider config storage.

Stores the customer-managed API key + provider config in a JSON file at
data/ai_provider.enc.  The API key is encrypted with AES-256-GCM using a
derived key from the manager's own JWT_SECRET (or a local random fallback).

Format on disk:
  {
    "provider":  "anthropic",
    "model":     "claude-haiku-4-5-20251001",
    "base_url":  "",
    "key_enc":   "<base64-encoded nonce+ciphertext+tag>",
    "key_source": "jwt_secret" | "local_file",
    "master_fp": "<16 hex chars — fingerprint of the derivation master>",
    "updated_at": 1234567890
  }

The plaintext API key never touches disk. Both the store and the fallback key
file are written 0600.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .base import ProviderConfig, DEFAULT_MODELS

log = logging.getLogger("manager.ai.key_store")

_STORE_PATH = Path(os.environ.get("AI_PROVIDER_STORE", "data/ai_provider.enc"))
_HKDF_SALT  = b"attacklens_ai_provider_v1"
_HKDF_INFO  = b"ai_key_enc_v1"
_NONCE_LEN  = 12  # 96-bit GCM nonce


class MasterKeyMismatch(RuntimeError):
    """The stored key was encrypted under a different JWT_SECRET."""


def _write_private(path: Path, data: bytes) -> None:
    """Write owner-only (0600), never leaving the file world-readable.

    os.open with mode 0o600 sets the permissions at creation, so the content is
    never briefly visible at the umask default the way Path.write_text leaves it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)   # existing files keep their old mode otherwise
    except OSError as exc:
        log.warning("Could not chmod 0600 %s: %s", path, exc)


def _master_fingerprint(master: bytes) -> str:
    """Non-reversible tag identifying which master derived a stored key.

    Stored in cleartext next to the ciphertext so a JWT_SECRET change is
    reported as exactly that, instead of a generic decrypt failure. Safe to
    persist: the master carries 32 bytes of entropy, so the digest is not
    searchable.
    """
    return hashlib.sha256(_HKDF_SALT + b"|fingerprint|" + master).hexdigest()[:16]


def _derive_master() -> tuple[bytes, str]:
    """Return (master_secret, source_label)."""
    master = os.environ.get("JWT_SECRET", "").encode()
    if master:
        return master, "jwt_secret"

    # No JWT_SECRET: fall back to a persistent random key. This lives in the
    # same directory as the ciphertext it protects, so it only defends against
    # someone reading the store alone — set JWT_SECRET in production.
    fallback_path = _STORE_PATH.parent / ".ai_enc_key"
    fallback_path.parent.mkdir(parents=True, exist_ok=True)
    if fallback_path.exists():
        master = fallback_path.read_bytes()
        try:
            os.chmod(fallback_path, 0o600)
        except OSError:
            pass
    else:
        master = os.urandom(32)
        _write_private(fallback_path, master)
        log.warning(
            "JWT_SECRET is not set — the AI provider key is encrypted with a "
            "random key stored at %s, beside the ciphertext it protects. "
            "Set JWT_SECRET for production.", fallback_path,
        )
    return master, "local_file"


def _derive_enc_key() -> bytes:
    """Derive a 256-bit AES key from JWT_SECRET or a random fallback file."""
    master, _ = _derive_master()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(master)


def _encrypt(plaintext: str) -> str:
    """Encrypt plaintext API key → base64(nonce + ciphertext + tag)."""
    key   = _derive_enc_key()
    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def _decrypt(encoded: str) -> str:
    """Decrypt base64(nonce+ct+tag) → plaintext API key."""
    key  = _derive_enc_key()
    raw  = base64.b64decode(encoded)
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None).decode()


# ── Public interface ──────────────────────────────────────────────────────────

def load_config() -> Optional[ProviderConfig]:
    """
    Load and decrypt the stored provider config.
    Returns None if not configured or the file is corrupted.
    """
    if not _STORE_PATH.exists():
        return None
    try:
        data = json.loads(_STORE_PATH.read_text())
        _check_master(data)
        api_key = _decrypt(data["key_enc"]) if data.get("key_enc") else ""
        return ProviderConfig(
            provider = data["provider"],
            model    = data.get("model") or DEFAULT_MODELS.get(data["provider"], ""),
            api_key  = api_key,
            base_url = data.get("base_url", ""),
        )
    except MasterKeyMismatch as exc:
        log.error("%s", exc)
        return None
    except Exception as exc:
        log.warning("Failed to load AI provider config: %s", exc)
        return None


def _check_master(data: dict) -> None:
    """Raise MasterKeyMismatch when the stored key predates a JWT_SECRET change.

    Without this the decrypt just fails and the manager reports the generic
    "AI provider not configured", which sends you looking in the wrong place.
    Configs written before this field existed have no fingerprint, so they are
    left to the decrypt path.
    """
    stored_fp = data.get("master_fp")
    if not stored_fp:
        return
    master, source = _derive_master()
    if stored_fp != _master_fingerprint(master):
        raise MasterKeyMismatch(
            "The stored AI provider key was encrypted with a different "
            f"JWT_SECRET (stored fingerprint {stored_fp}, current master from "
            f"{source}). It cannot be decrypted. Either restore the previous "
            "JWT_SECRET, or re-enter the API key in Settings -> AI Provider."
        )


def save_config(
    provider: str,
    api_key:  str,
    model:    str,
    base_url: str = "",
) -> ProviderConfig:
    """
    Encrypt and persist the provider config.
    Returns the ProviderConfig that was saved.
    """
    master, source = _derive_master()
    data = {
        "provider":   provider,
        "model":      model or DEFAULT_MODELS.get(provider, ""),
        "base_url":   base_url,
        "key_enc":    _encrypt(api_key) if api_key else "",
        "key_source": source,
        "master_fp":  _master_fingerprint(master),
        "updated_at": int(time.time()),
    }
    _write_private(_STORE_PATH, json.dumps(data, indent=2).encode())
    log.info("AI provider config saved (provider=%s, model=%s)", provider, model)
    return ProviderConfig(
        provider = provider,
        model    = data["model"],
        api_key  = api_key,
        base_url = base_url,
    )


def bootstrap_from_env() -> Optional[ProviderConfig]:
    """Seed the store from AI_PROVIDER / AI_MODEL / AI_API_KEY on first boot.

    Lets a deployment ship its provider config declaratively in .env instead of
    requiring someone to click through the dashboard before AI features work.

    Deliberately a one-time seed: an already-configured store always wins, so a
    stale key left in .env can never silently override a key rotated through the
    API. Performs no network I/O — startup stays fast and cannot be blocked by a
    provider outage. Use POST /api/v1/ai/test to verify the key afterwards.
    """
    if _STORE_PATH.exists():
        return None

    provider = os.environ.get("AI_PROVIDER", "").strip().lower()
    api_key  = os.environ.get("AI_API_KEY", "").strip()
    model    = os.environ.get("AI_MODEL", "").strip()
    base_url = os.environ.get("AI_BASE_URL", "").strip()

    if not provider:
        return None

    # Ollama runs locally and needs no credential; everything else does.
    if provider != "ollama" and not api_key:
        return None

    if provider not in DEFAULT_MODELS:
        log.warning(
            "AI_PROVIDER=%r is not a known provider (%s) — skipping bootstrap",
            provider, ", ".join(sorted(DEFAULT_MODELS)),
        )
        return None

    cfg = save_config(
        provider = provider,
        api_key  = api_key,
        model    = model or DEFAULT_MODELS[provider],
        base_url = base_url,
    )
    log.info(
        "AI provider bootstrapped from environment (provider=%s, model=%s). "
        "Verify with POST /api/v1/ai/test.", cfg.provider, cfg.model,
    )
    return cfg


def delete_config() -> None:
    """Remove the stored config."""
    if _STORE_PATH.exists():
        _STORE_PATH.unlink()
        log.info("AI provider config deleted")


def config_summary() -> Optional[dict]:
    """
    Return a safe display dict (key masked) for the API response.
    Returns None if not configured.
    """
    if not _STORE_PATH.exists():
        return None
    try:
        data = json.loads(_STORE_PATH.read_text())
        cfg  = ProviderConfig(
            provider = data["provider"],
            model    = data.get("model", ""),
            api_key  = "••••",          # never expose
            base_url = data.get("base_url", ""),
        )
        # Surface a JWT_SECRET change as its own state so the UI can tell the
        # user to re-enter the key rather than showing a healthy-looking config
        # whose key silently fails on the next call.
        key_usable = True
        try:
            _check_master(data)
        except MasterKeyMismatch:
            key_usable = False

        return {
            "provider":    cfg.provider,
            "model":       cfg.model,
            "base_url":    cfg.base_url,
            "key_set":     bool(data.get("key_enc")),
            "key_preview": _preview_key(data) if key_usable else "(unreadable)",
            "key_source":  data.get("key_source", "unknown"),
            "key_usable":  key_usable,
            "updated_at":  data.get("updated_at"),
        }
    except Exception as exc:
        log.warning("Config summary failed: %s", exc)
        return None


def _preview_key(data: dict) -> str:
    if not data.get("key_enc"):
        return "(none)"
    try:
        k = _decrypt(data["key_enc"])
        return f"{k[:6]}…{k[-4:]}" if len(k) > 12 else "••••••••"
    except Exception:
        return "(encrypted)"
