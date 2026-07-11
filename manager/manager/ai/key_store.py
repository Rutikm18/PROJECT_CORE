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
    "updated_at": 1234567890
  }

The plaintext API key never touches disk.
"""
from __future__ import annotations

import base64
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


def _derive_enc_key() -> bytes:
    """Derive a 256-bit AES key from JWT_SECRET or a random fallback file."""
    master = os.environ.get("JWT_SECRET", "").encode()
    if not master:
        # Persistent random key stored alongside the config
        fallback_path = _STORE_PATH.parent / ".ai_enc_key"
        fallback_path.parent.mkdir(parents=True, exist_ok=True)
        if fallback_path.exists():
            master = fallback_path.read_bytes()
        else:
            master = os.urandom(32)
            fallback_path.write_bytes(master)

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
        data    = json.loads(_STORE_PATH.read_text())
        api_key = _decrypt(data["key_enc"]) if data.get("key_enc") else ""
        return ProviderConfig(
            provider = data["provider"],
            model    = data.get("model") or DEFAULT_MODELS.get(data["provider"], ""),
            api_key  = api_key,
            base_url = data.get("base_url", ""),
        )
    except Exception as exc:
        log.warning("Failed to load AI provider config: %s", exc)
        return None


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
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "provider":   provider,
        "model":      model or DEFAULT_MODELS.get(provider, ""),
        "base_url":   base_url,
        "key_enc":    _encrypt(api_key) if api_key else "",
        "updated_at": int(time.time()),
    }
    _STORE_PATH.write_text(json.dumps(data, indent=2))
    log.info("AI provider config saved (provider=%s, model=%s)", provider, model)
    return ProviderConfig(
        provider = provider,
        model    = data["model"],
        api_key  = api_key,
        base_url = base_url,
    )


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
        return {
            "provider":    cfg.provider,
            "model":       cfg.model,
            "base_url":    cfg.base_url,
            "key_set":     bool(data.get("key_enc")),
            "key_preview": _preview_key(data),
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
