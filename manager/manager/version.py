"""
manager/manager/version.py — Application version resolution.

Single source of truth for the running build's version, surfaced on the
dashboard main page and the /health and /api/v1/meta endpoints.

Version scheme: ``1.0.<commit-count>``.
  The patch component is the number of commits on the branch, so every push
  to GitHub advances the version automatically — no manual bump, no bot commit,
  no version file to keep in sync.

Resolution order (first hit wins):
  1. APP_VERSION env var       — baked into the Docker image at build time
                                  (deploy.yml computes it from git and passes it
                                  as a build-arg; see Dockerfile / docker-compose).
  2. git rev-list --count HEAD — for local/dev runs from a checkout.
  3. "1.0.0-dev"               — last-resort fallback (no env, no git).

The result is computed once and cached — version does not change while the
process is running.
"""
from __future__ import annotations

import functools
import os
import subprocess


def _git(*args: str) -> str | None:
    """Run a git command from the repo root; return stripped stdout or None."""
    try:
        root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        out = subprocess.run(
            ["git", "-C", root, *args],
            capture_output=True, text=True, timeout=3,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except Exception:
        pass
    return None


@functools.lru_cache(maxsize=1)
def get_version_info() -> dict:
    """Return {version, commit, built_at} for the running build (cached)."""
    version = os.environ.get("APP_VERSION")
    commit = os.environ.get("APP_COMMIT")
    built_at = os.environ.get("APP_BUILT_AT") or None

    if not version:
        # Dev / local run — derive from the working tree if git is available.
        count = _git("rev-list", "--count", "HEAD")
        version = f"1.0.{count}" if count else "1.0.0-dev"

    if not commit:
        commit = _git("rev-parse", "--short", "HEAD")

    return {
        "version":  version,
        "commit":   commit,
        "built_at": built_at,
    }


def get_version() -> str:
    """Return just the version string, e.g. '1.0.46'."""
    return get_version_info()["version"]
