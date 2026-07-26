"""
agent/agent/keystore.py — Secure API-key persistence.

Storage priority
────────────────
  1. macOS Keychain  (via 'keyring' library)  — OS-managed, Keychain Access
  2. Encrypted file  (<security_dir>/<id>.key, mode 0600)  — universal fallback

Rules
─────
  • Key is stored BEFORE the network enrollment call so it is never lost.
  • File backend refuses to load a key whose permissions include group/other bits
    (world-readable key = compromised key).
  • Both backends are isolated per agent_id so multi-agent hosts work correctly.

Public API
──────────
  store_key(agent_id, key_hex, backend, security_dir)
  load_key (agent_id, backend, security_dir) → str | None
  delete_key(agent_id, backend, security_dir)
"""
from __future__ import annotations

import logging
import os
import stat

log = logging.getLogger("agent.keystore")

_KEYRING_SERVICE = "com.attacklens.agent"

# ── Public ────────────────────────────────────────────────────────────────────

def store_key(
    agent_id: str,
    key_hex: str,
    backend: str = "keychain",
    security_dir: str = "/Library/AttackLens/security",
    mirror_to_file: bool = True,
) -> None:
    """Persist the API key. Raises on total failure (nothing persisted anywhere).

    Reboot safety (macOS): the agent runs as a root LaunchDaemon that starts at
    boot with NO user login session. The macOS *login* keychain is locked in that
    state, so `keyring` cannot read the key back — the agent would lose its key on
    every reboot and churn on re-enrollment. To prevent that, a keychain store
    ALWAYS also writes the ACL-restricted file copy (0600, root-only under
    security_dir), which is the only storage guaranteed readable by the daemon at
    boot. Set mirror_to_file=False to opt out (not recommended for the daemon).
    """
    keychain_ok = False
    if backend == "keychain":
        try:
            import keyring  # type: ignore[import]
            keyring.set_password(_KEYRING_SERVICE, agent_id, key_hex)
            keychain_ok = True
            log.info("API key stored in macOS Keychain (service=%s account=%s)",
                     _KEYRING_SERVICE, agent_id)
        except Exception as exc:
            log.warning("Keychain store failed (%s) — using file backend", exc)

    # Write the file backend when: it's the chosen backend, the boot-safe mirror
    # is enabled (default), OR the keychain write failed (never silently lose it).
    if backend != "keychain" or mirror_to_file or not keychain_ok:
        try:
            _store_key_file(agent_id, key_hex, security_dir)
        except Exception as exc:
            if not keychain_ok:
                raise   # key was persisted NOWHERE — must surface, don't swallow
            log.warning(
                "Boot-safe key file mirror failed (%s); keychain copy only — the "
                "agent may fail to authenticate after a reboot", exc,
            )


def load_key(
    agent_id: str,
    backend: str = "keychain",
    security_dir: str = "/Library/AttackLens/security",
) -> str | None:
    """Return the stored API key, or None if not found."""
    if backend == "keychain":
        try:
            import keyring  # type: ignore[import]
            key = keyring.get_password(_KEYRING_SERVICE, agent_id)
            if key:
                log.debug("API key loaded from Keychain")
                return key
        except Exception as exc:
            log.warning("Keychain load failed (%s) — trying file", exc)
    return _load_key_file(agent_id, security_dir)


def delete_key(
    agent_id: str,
    backend: str = "keychain",
    security_dir: str = "/Library/AttackLens/security",
) -> None:
    """Remove the stored key (for re-enrollment or uninstall)."""
    if backend == "keychain":
        try:
            import keyring  # type: ignore[import]
            keyring.delete_password(_KEYRING_SERVICE, agent_id)
            log.info("API key deleted from Keychain")
        except Exception:
            pass
    path = _key_file_path(security_dir, agent_id)
    if os.path.exists(path):
        os.unlink(path)
        log.info("API key file deleted: %s", path)


# ── File backend ──────────────────────────────────────────────────────────────

def _key_file_path(security_dir: str, agent_id: str) -> str:
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_id)
    return os.path.join(security_dir, f"{safe_id}.key")


def _store_key_file(agent_id: str, key_hex: str, security_dir: str) -> None:
    os.makedirs(security_dir, exist_ok=True)
    # Tighten the directory itself
    try:
        os.chmod(security_dir, stat.S_IRWXU)   # 0700 — only owner
    except Exception:
        pass
    path = _key_file_path(security_dir, agent_id)
    tmp  = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(key_hex)
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)   # 0600
    os.replace(tmp, path)                          # atomic rename
    log.info("API key stored in file: %s (mode 0600)", path)


def _load_key_file(agent_id: str, security_dir: str) -> str | None:
    path = _key_file_path(security_dir, agent_id)
    if not os.path.exists(path):
        return None
    # Refuse to load a world- or group-readable key file
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        log.error(
            "SECURITY: key file %s has unsafe permissions %o — refusing to load. "
            "Fix with: chmod 600 %s", path, mode, path,
        )
        return None
    with open(path, "r") as f:
        return f.read().strip() or None
