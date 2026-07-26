"""
agent/agent/single_instance.py — cross-process single-instance guard.

Why this exists
───────────────
The agent can be launched down TWO independent paths on macOS: the
`com.attacklens.agent` LaunchDaemon runs the agent binary directly, while the
`com.attacklens.watchdog` LaunchDaemon runs the watchdog, which itself spawns the
agent as a child. If both are active, two agent processes run at once and RACE on
the same on-disk spool (`unsent.ndjson`): concurrent read-then-remove in
`DiskSpool.drain()` across processes loses or double-sends telemetry, both
processes enroll, and both emit duplicate sections. A short-lived overlap is also
normal during a launchd restart (old process not yet reaped when the new one
starts).

An advisory file lock (`flock`) makes exactly one agent the live one:
  • The first process acquires an exclusive lock and runs.
  • A later process waits briefly (covers restart overlap) and, if the lock is
    still held, exits cleanly instead of corrupting shared state.

POSIX-only; on other platforms acquire() is a no-op (returns None) so the agent
still runs — Windows has its own service-level single-instance guarantee.
"""
from __future__ import annotations

import logging
import os
import time

log = logging.getLogger("agent.single_instance")


class AlreadyRunning(Exception):
    """Raised by acquire() when another live instance holds the lock."""


def acquire(lock_path: str, wait_sec: float = 5.0):
    """Acquire an exclusive advisory lock at `lock_path`.

    Returns an OPEN file object that MUST be kept referenced for the process
    lifetime — closing it (or letting it be garbage-collected) releases the lock.
    Raises AlreadyRunning if another process still holds the lock after wait_sec.

    On non-POSIX platforms returns None (no-op): the caller runs unguarded.
    """
    if os.name != "posix":
        return None

    import fcntl

    try:
        os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
    except Exception as exc:  # noqa: BLE001 - dir may already exist / be unwritable
        log.debug("single_instance: could not ensure lock dir: %s", exc)

    # a+ so the file is created if absent and we can also read the holder PID.
    fd = open(lock_path, "a+")
    deadline = time.monotonic() + max(0.0, wait_sec)
    while True:
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Record our PID for diagnostics (best-effort).
            try:
                fd.seek(0)
                fd.truncate()
                fd.write(str(os.getpid()))
                fd.flush()
            except Exception:  # noqa: BLE001
                pass
            log.debug("single_instance: acquired %s (pid=%d)", lock_path, os.getpid())
            return fd
        except OSError:
            if time.monotonic() >= deadline:
                holder = _read_holder(fd)
                try:
                    fd.close()
                except Exception:  # noqa: BLE001
                    pass
                raise AlreadyRunning(
                    f"another agent instance holds {lock_path} "
                    f"(holder pid={holder})"
                )
            time.sleep(0.2)


def _read_holder(fd) -> str:
    try:
        fd.seek(0)
        return fd.read().strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"
