"""
agent/os/macos/collectors/sca.py — Security Configuration Assessment (12 hr).

Thin macOS wrapper around the OS-agnostic SCA engine (agent.agent.sca): runs
every applicable CIS policy (built-in under agent/agent/sca/policies/, plus
operator drop-ins in /Library/AttackLens/sca) and returns per-check results.

The engine's `c:` rule commands are executed through a budget-aware runner so
a slow command degrades that one check to not_applicable instead of blowing
the section timeout — same contract every other posture collector honours.
"""
from __future__ import annotations

import logging
import subprocess

from .base import BaseCollector, _get_env, run_budget_remaining, _MIN_RUN_SLICE_SEC

log = logging.getLogger(__name__)


def _budgeted_runner(cmd: str, timeout: float = 10.0):
    """(rc, stdout) runner for SCA `c:` rules, capped by the section budget."""
    remaining = run_budget_remaining()
    if remaining is not None:
        if remaining < _MIN_RUN_SLICE_SEC:
            log.debug("SCA check skipped (section budget spent): %s", cmd)
            return None, ""          # engine maps this to not_applicable
        timeout = min(timeout, remaining)
    try:
        p = subprocess.run(
            ["/bin/sh", "-c", cmd],
            capture_output=True, text=True, errors="replace",
            timeout=timeout, env=_get_env(),
        )
        # systemsetup & friends print this instead of an answer when the caller
        # isn't root (dev/test runs) — that's "couldn't evaluate", not "failed".
        if "administrator access" in (p.stdout + p.stderr).lower():
            return None, ""
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        log.warning("SCA command timed out after %.1fs: %s", timeout, cmd)
        return None, ""
    except Exception as exc:
        log.debug("SCA command failed [%s]: %s", cmd, exc)
        return None, ""


class ScaCollector(BaseCollector):
    name = "sca"

    def collect(self) -> dict:
        from agent.agent.sca import ScaEngine
        return ScaEngine(runner=_budgeted_runner).scan()
