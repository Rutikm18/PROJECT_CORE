"""
agent/os/macos/collectors/base.py — macOS ARM64 base collector.

Extends the core BaseCollector with macOS-specific helpers:
  _run_json(cmd)       — subprocess returning parsed JSON dict/list or None
  _sp_json(data_type)  — system_profiler -json <DataType>
  _plist(path)         — read a .plist file as a Python dict (via plutil -convert json)
  _codesign(path)      — codesign -dvvv output for a binary
  _mdutil(vol)         — mdutil -s <volume> (spotlight / FileVault indicator)
"""
from __future__ import annotations

import json
import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Union

log = logging.getLogger(__name__)

CollectorResult = Union[dict, list]


_EXTENDED_ENV: dict | None = None

def _get_env() -> dict:
    """Return os.environ with extra PATH entries for LaunchDaemon context.

    LaunchDaemons start with PATH=/usr/bin:/bin:/usr/sbin:/sbin — missing
    /usr/local/bin (brew, pip3, docker) and /opt/homebrew/bin (Apple Silicon).
    """
    global _EXTENDED_ENV
    if _EXTENDED_ENV is None:
        import os as _os
        env = dict(_os.environ)
        extra = "/usr/local/bin:/opt/homebrew/bin:/opt/homebrew/sbin"
        current = env.get("PATH", "")
        parts = [p for p in extra.split(":") if p not in current.split(":")]
        env["PATH"] = ":".join(parts) + (":" + current if current else "")
        # Suppress "MallocStackLogging: can't turn off..." spam in subprocess stderr.
        # macOS injects this when the parent process has malloc debug flags set;
        # setting it to 0 prevents child processes from inheriting the flag.
        env["MallocStackLogging"] = "0"
        _EXTENDED_ENV = env
    return _EXTENDED_ENV


def _run(cmd: list[str], timeout: int = 15, stderr: bool = False) -> str:
    """Run a command, return stdout (or stderr when stderr=True) as str. Returns '' on any error."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            env=_get_env(),
        )
        return r.stderr if stderr else r.stdout
    except FileNotFoundError:
        log.debug("Command not found: %s", cmd[0])
        return ""
    except subprocess.TimeoutExpired:
        log.warning("Timed out after %ds: %s", timeout, " ".join(cmd))
        return ""
    except Exception as exc:
        log.debug("Command failed [%s]: %s", " ".join(cmd), exc)
        return ""


def _run_json(cmd: list[str], timeout: int = 20) -> dict | list | None:
    """Run a command that outputs JSON. Returns parsed object or None."""
    out = _run(cmd, timeout=timeout)
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _sp_json(data_type: str, timeout: int = 30) -> dict | None:
    """
    Run system_profiler -json <data_type>.
    Returns the parsed top-level dict (keys = DataType names) or None.
    """
    result = _run_json(["system_profiler", "-json", data_type], timeout=timeout)
    if isinstance(result, dict):
        return result
    return None


def _plist_to_dict(path: str) -> dict | None:
    """
    Convert a .plist file to a Python dict via `plutil -convert json -o -`.
    Returns None if the file doesn't exist or can't be parsed.
    """
    result = _run_json(["plutil", "-convert", "json", "-o", "-", path])
    if isinstance(result, dict):
        return result
    return None


def _codesign_info(path: str) -> dict:
    """
    Return codesign metadata for a binary:
      identifier, authority (list), team_id, flags, signed (bool)
    codesign writes its verbose output to stderr, so we capture stderr.
    """
    out = _run(["codesign", "-dvvv", "--", path], timeout=10, stderr=True)
    info: dict = {"path": path, "signed": False, "identifier": None,
                  "authority": [], "team_id": None, "flags": None}
    if not out:
        return info
    for line in out.splitlines():
        if line.startswith("Identifier="):
            info["identifier"] = line.split("=", 1)[1].strip()
            info["signed"] = True
        elif line.startswith("Authority="):
            info["authority"].append(line.split("=", 1)[1].strip())
        elif line.startswith("TeamIdentifier="):
            info["team_id"] = line.split("=", 1)[1].strip()
        elif line.startswith("Flags="):
            info["flags"] = line.split("=", 1)[1].strip()
    return info


def codesign_trust(path: str) -> bool | None:
    """Security-grade signing verdict for a Mach-O binary at `path`.

      True  → validly signed with a real authority chain (Apple / Developer ID
              / Mac App Store)
      False → unsigned, OR only ad-hoc signed (no authority)
      None  → cannot be determined (path missing, codesign unavailable, error)

    Why this is stricter than `"Identifier=" in output`: an ad-hoc signature
    (`Signature=adhoc`) produces an Identifier but carries NO authority — and
    ad-hoc / unsigned is exactly the shape most macOS malware ships in. Treating
    "has an Identifier" as "trusted" would wave through precisely the binaries a
    security agent exists to flag. Trust here requires a non-ad-hoc signature
    AND at least one Authority in the chain.
    """
    out = _run(["codesign", "-dvvv", "--", path], timeout=8, stderr=True)
    if not out:
        return None
    low = out.lower()
    if "not signed at all" in low or "code object is not signed" in low:
        return False
    if "signature=adhoc" in low:
        return False          # ad-hoc: identifier present, but no real authority
    if any(line.startswith("Authority=") for line in out.splitlines()):
        return True
    if "identifier=" in low:
        return False          # signed shell but no authority chain → untrusted
    return None


class BaseCollector(ABC):
    """
    Abstract base for all macOS ARM64 collectors.

    Subclass, declare `name`, implement `collect()`.
    Instances are callable: c = MetricsCollector(); data = c()
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def collect(self) -> CollectorResult: ...

    def __call__(self) -> CollectorResult:
        return self.collect()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} section={self.name!r}>"
