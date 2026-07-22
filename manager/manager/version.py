"""
manager/manager/version.py — Application version resolution.

Version scheme: 1.1.x  (major.minor.patch)
  Patch is bumped automatically on every push to GitHub by the deploy workflow.
  Major / minor are bumped manually by editing the VERSION file at the repo root.

Resolution order (first hit wins):
  1. APP_VERSION env var  — baked into the Docker image at build time by deploy.yml
  2. VERSION file at repo root — picked up by local / dev runs automatically
  3. "1.1.0-dev"              — absolute last resort (no env, no file)

Commit SHA and build timestamp come from APP_COMMIT / APP_BUILT_AT env vars
(also baked in at build time).  The git fallback for SHA requires .git to be
present — not the case inside the stripped-source production image, hence the env.
"""
from __future__ import annotations

import functools
import os
import subprocess


def _git(*args: str) -> str | None:
    try:
        root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        out = subprocess.run(
            ["git", "-C", root, *args],
            capture_output=True, text=True, timeout=3,
        )
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def _read_version_file() -> str | None:
    """Read the VERSION file from the repo root (sibling of manager/)."""
    try:
        root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        path = os.path.join(root, "VERSION")
        with open(path) as f:
            v = f.read().strip()
        return v or None
    except OSError:
        return None


@functools.lru_cache(maxsize=1)
def get_version_info() -> dict:
    """Return {version, commit, built_at} for the running build (cached once)."""
    version  = os.environ.get("APP_VERSION") or None
    commit   = os.environ.get("APP_COMMIT")  or None
    built_at = os.environ.get("APP_BUILT_AT") or None

    # Resolve version
    if not version:
        version = _read_version_file() or "1.1.0-dev"

    # Resolve commit SHA for local runs (not available in prod image — no .git)
    if not commit:
        commit = _git("rev-parse", "--short", "HEAD")

    return {
        "version":  version,
        "commit":   commit,
        "built_at": built_at,
    }


def get_version() -> str:
    return get_version_info()["version"]
