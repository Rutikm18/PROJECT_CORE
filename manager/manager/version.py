"""
manager/manager/version.py — Application version resolution.

Version scheme: 1.0.x  (major.minor.patch)
  Patch is derived from `git rev-list --count HEAD`, so it advances as the
  repository advances. Major / minor come from the VERSION file at the repo root.

Resolution order:
  1. APP_VERSION env var       — baked into Docker images by deploy.yml
  2. Git-derived 1.0.<count>   — local/dev runs from a checked-out repo
  3. VERSION file at repo root — fallback when Git metadata is unavailable
  4. "1.0.0-dev"              — absolute last resort

Commit SHA and build timestamp come from APP_COMMIT / APP_BUILT_AT env vars
(also baked in at build time).  The git fallback for SHA requires .git to be
present — not the case inside the stripped-source production image, hence the env.
"""
from __future__ import annotations

import functools
import os
import subprocess

DEFAULT_VERSION = "1.0.0-dev"
DEFAULT_SERIES = "1.0"


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


def _clean_env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else None


def _version_series() -> str:
    """Return major.minor from VERSION, defaulting to 1.0."""
    raw = _read_version_file() or ""
    parts = raw.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return f"{parts[0]}.{parts[1]}"
    return DEFAULT_SERIES


def _git_version() -> str | None:
    count = _git("rev-list", "--count", "HEAD")
    if not count or not count.isdigit():
        return None
    return f"{_version_series()}.{count}"


@functools.lru_cache(maxsize=1)
def get_version_info() -> dict:
    """Return {version, commit, built_at} for the running build (cached once)."""
    version  = _clean_env("APP_VERSION")
    commit   = _clean_env("APP_COMMIT")
    built_at = _clean_env("APP_BUILT_AT")

    # Resolve version
    if not version or version == DEFAULT_VERSION:
        version = _git_version() or _read_version_file() or version or DEFAULT_VERSION

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
