"""
agent/agent/manifest.py — immutable install manifest + checksum validation (matrix R1).

The watchdog/agent must not launch a binary that has been replaced, truncated, or
corrupted — and must not retry-loop on a missing target every 30 s. The installer
writes a manifest recording each managed binary's path, version, size, and
SHA-256. At startup the watchdog (and the agent) validate the target against the
manifest and, on any mismatch, enter a **degraded/stopped** state (a structured
alert, no tight retry loop) instead of blindly re-exec'ing a bad file.

All functions are best-effort and pure-ish (filesystem in, typed result out) so
they unit-test without root: no launchd, no real install.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

MANIFEST_PATH = "/Library/AttackLens/manifest.json"

# Read in 1 MiB chunks so hashing a ~20 MB PyInstaller binary is bounded memory.
_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class VerifyResult:
    status: str      # ok | manifest_absent | component_absent | file_missing |
                     # size_mismatch | checksum_mismatch | unreadable
    ok: bool
    detail: str = ""

    @property
    def should_degrade(self) -> bool:
        """True when the agent should refuse to (re)launch the component and enter
        a degraded/stopped state rather than retry. `manifest_absent` is NOT a
        degrade during the rollout window (older installs have no manifest)."""
        return self.status in {
            "component_absent", "file_missing", "size_mismatch",
            "checksum_mismatch", "unreadable",
        }


def sha256_file(path: str) -> str | None:
    """Streaming SHA-256 hex digest, or None if the file can't be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def load_manifest(path: str = MANIFEST_PATH) -> dict | None:
    """Parse the manifest JSON, or None if absent/unreadable/malformed."""
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


def build_component(path: str, version: str = "") -> dict | None:
    """Compute the manifest record for a binary at `path` (for the installer)."""
    digest = sha256_file(path)
    if digest is None:
        return None
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    return {"path": path, "version": version, "size": size, "sha256": digest}


def write_manifest(components: dict, path: str = MANIFEST_PATH, version: str = "") -> bool:
    """Atomically write the manifest. `components` maps name -> record. Best-effort."""
    doc = {"version": version, "components": components}
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def verify_component(
    name: str,
    manifest: dict | None = None,
    *,
    manifest_path: str = MANIFEST_PATH,
) -> VerifyResult:
    """Validate the on-disk binary for `name` against the manifest. Never raises.

    Order (fail fast, cheapest first): manifest present → component present →
    file present → size matches (cheap) → checksum matches (expensive). Size is
    checked before hashing so a truncated/replaced file short-circuits.
    """
    if manifest is None:
        manifest = load_manifest(manifest_path)
    if manifest is None:
        return VerifyResult("manifest_absent", False, f"no manifest at {manifest_path}")

    comp = (manifest.get("components") or {}).get(name)
    if not isinstance(comp, dict):
        return VerifyResult("component_absent", False, f"{name} not in manifest")

    path = comp.get("path")
    if not path or not os.path.isfile(path):
        return VerifyResult("file_missing", False, f"{name} binary missing: {path}")

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return VerifyResult("unreadable", False, f"{name}: {exc}")

    expected_size = comp.get("size")
    if isinstance(expected_size, int) and size != expected_size:
        return VerifyResult(
            "size_mismatch", False,
            f"{name}: size {size} != manifest {expected_size}",
        )

    expected_hash = comp.get("sha256")
    if expected_hash:
        digest = sha256_file(path)
        if digest is None:
            return VerifyResult("unreadable", False, f"{name}: cannot hash {path}")
        if digest != expected_hash:
            return VerifyResult(
                "checksum_mismatch", False,
                f"{name}: sha256 mismatch (expected {expected_hash[:12]}…, got {digest[:12]}…)",
            )

    return VerifyResult("ok", True, "")
