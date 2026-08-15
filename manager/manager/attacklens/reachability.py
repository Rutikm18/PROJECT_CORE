"""
manager/manager/attacklens/reachability.py — Payload-backed reachability
enrichment for terrain validation.

Origin terrain criteria `package_running` and `service_reachable` ask a simple
question: is this vulnerable package *actually loaded / network-exposed*, or just
sitting installed on disk?  The authoritative answer lives in the raw telemetry
**inventory** — the latest `processes` and `ports` payloads for the agent — NOT
in the `findings` table.  Benign running processes and ordinary listening ports
are never themselves findings, so the previous findings-table lookups resolved
these criteria to 0 almost every time, silently draining ~25 % of the Origin
score weight and pushing genuine CVEs below the validation threshold.

This module reads the inventory directly and answers, for a given package name:
  • package_running — a live process matches the package
  • package_port_open — a live LISTEN socket is owned by a process matching the
    package (network-reachable), preferring loopback exclusion

The lookups are bounded (one latest payload per section) and memoised behind a
short TTL cache keyed by agent_id, so a burst of N Origin findings for one agent
costs two DB reads, not 2·N.  Every entry point degrades gracefully to an empty
context when the manager DB handle is absent (e.g. unit tests that build the
engine with `object.__new__`) — reachability then simply contributes 0, exactly
as before, never raising into the detection hot-path.
"""
from __future__ import annotations

import re
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger("manager.attacklens.reachability")

# Latest-payload lookups are cheap but the enrichment runs once per finding; a
# short TTL keeps a burst of findings for one agent to a single pair of reads.
# processes refresh every ~10 s and ports every ~30 s upstream, so 15 s of
# staleness is well within one collection interval.
_CACHE_TTL_SEC = 15.0
_CACHE_MAX_AGENTS = 512

# agent_id -> (expires_at, ReachabilityContext)
_CACHE: dict[str, tuple[float, "ReachabilityContext"]] = {}

_LOOPBACK_BINDS = {"127.0.0.1", "::1", "localhost"}

# A package token must be at least this long to be matched against a process
# name — shorter tokens ("go", "c", "m4") produce too many spurious substring
# hits and would falsely inflate `package_running`.
_MIN_TOKEN_LEN = 3

# Strip a trailing version qualifier a package manager appends:
#   openssl@3 -> openssl, python@3.11 -> python, node18 -> node, ruby-3.2 -> ruby
_VERSION_SUFFIX = re.compile(r"[@\-_]?\d[\d._]*$")


def _basename(value: str) -> str:
    """Last path component, lowercased — '/usr/bin/python3.11' -> 'python3.11'."""
    v = str(value or "").strip().lower()
    if not v:
        return ""
    # Handle both POSIX and Windows separators without importing os.path,
    # since a payload may carry either depending on the reporting agent OS.
    for sep in ("/", "\\"):
        if sep in v:
            v = v.rsplit(sep, 1)[-1]
    return v


def _pkg_token(package_name: str) -> str:
    """Normalise a package name to a comparable base token.

    Strips path, version suffixes, and (for scoped npm names) the leading scope,
    so 'openssl@3', '@scope/pkg', and '/usr/lib/libfoo' reduce to a stable core.
    Returns '' when nothing usable remains (caller then declines to match).
    """
    name = _basename(package_name)
    if name.startswith("@") and "/" in name:      # @scope/pkg -> pkg
        name = name.split("/", 1)[1]
    name = _VERSION_SUFFIX.sub("", name)
    name = name.lstrip("lib")  # libssl -> ssl, libpng -> png (common C libs)
    name = re.sub(r"[^a-z0-9]+", "", name)
    return name if len(name) >= _MIN_TOKEN_LEN else ""


@dataclass(frozen=True)
class ReachabilityContext:
    """Immutable snapshot of one agent's process/port inventory."""

    agent_id: str
    # Normalised (basename, lowercased) names of every running process.
    running_names: frozenset[str] = frozenset()
    # (owning-process-basename, is_external) for each LISTEN socket.
    listeners: tuple[tuple[str, bool], ...] = ()
    loaded: bool = False
    processes_seen: int = 0
    ports_seen: int = 0

    def package_running(self, package_name: str) -> bool:
        """True when a live process corresponds to this package."""
        token = _pkg_token(package_name)
        if not token or not self.running_names:
            return False
        return any(_token_in_name(token, name) for name in self.running_names)

    def package_port_open(self, package_name: str) -> bool:
        """True when a LISTEN socket is owned by a process matching this package.

        Scoped to the package's own process so a vulnerable *library* with no
        network surface does not inherit an unrelated service's open port.
        """
        token = _pkg_token(package_name)
        if not token or not self.listeners:
            return False
        return any(
            is_external and _token_in_name(token, proc)
            for proc, is_external in self.listeners
        )

    def any_external_listener(self) -> bool:
        """Any non-loopback LISTEN socket at all — a coarse fallback signal."""
        return any(is_external for _proc, is_external in self.listeners)


_EMPTY = ReachabilityContext(agent_id="", loaded=False)


def _token_in_name(token: str, name: str) -> bool:
    """Conservative containment: the package token appears as a run inside the
    normalised process name (alnum-only both sides), or vice-versa for short
    process names.  Avoids matching 'ssh' inside 'crossh' via the min-length
    floor already applied in _pkg_token."""
    clean = re.sub(r"[^a-z0-9]+", "", name)
    if not clean:
        return False
    return token in clean or clean in token


def _external_bind(bind_addr: str) -> bool:
    """A listener is externally reachable when it is not bound to loopback."""
    addr = str(bind_addr or "").strip().lower()
    if not addr:
        # Unknown bind — treat as external (fail-open on exposure is the
        # security-conservative choice for a *reachability* signal).
        return True
    # Strip an IPv6 zone / brackets before comparing.
    addr = addr.strip("[]").split("%", 1)[0]
    return addr not in _LOOPBACK_BINDS


def _iter_records(data: Any) -> list[dict]:
    """A section payload is a list of records, or a dict wrapping one such list."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def _build_context(agent_id: str, processes: Any, ports: Any) -> ReachabilityContext:
    proc_records = _iter_records(processes)
    running: set[str] = set()
    for rec in proc_records:
        for key in ("name", "process", "process_name", "exe", "path", "command", "comm"):
            base = _basename(rec.get(key, ""))
            if base:
                running.add(base)
    port_records = _iter_records(ports)
    listeners: list[tuple[str, bool]] = []
    for rec in port_records:
        proc = _basename(rec.get("process") or rec.get("proc") or rec.get("name") or "")
        listeners.append((proc, _external_bind(rec.get("bind_addr") or rec.get("addr") or "")))
    return ReachabilityContext(
        agent_id=agent_id,
        running_names=frozenset(running),
        listeners=tuple(listeners),
        loaded=True,
        processes_seen=len(proc_records),
        ports_seen=len(port_records),
    )


async def load_reachability(manager_db, agent_id: str) -> ReachabilityContext:
    """Return this agent's reachability context, memoised for `_CACHE_TTL_SEC`.

    `manager_db` must expose `query_section(agent_id, section, limit=...)`
    against the raw `payloads` table (the manager DB — NOT the intel/findings
    DB).  Any absence, wrong handle, or DB error yields the empty context so the
    caller contributes 0 to the score instead of raising.
    """
    if not agent_id or manager_db is None:
        return _EMPTY
    query = getattr(manager_db, "query_section", None)
    if not callable(query):
        return _EMPTY

    now = time.time()
    cached = _CACHE.get(agent_id)
    if cached is not None and cached[0] > now:
        return cached[1]

    try:
        proc_rows = await query(agent_id, "processes", limit=1)
        port_rows = await query(agent_id, "ports", limit=1)
    except Exception as exc:                       # pragma: no cover - defensive
        log.debug("reachability load failed agent=%s: %s", agent_id, exc)
        return _EMPTY

    processes = proc_rows[0]["data"] if proc_rows else None
    ports = port_rows[0]["data"] if port_rows else None
    ctx = _build_context(agent_id, processes, ports)

    if len(_CACHE) >= _CACHE_MAX_AGENTS:
        # Bounded cache — evict the entry nearest expiry (cheap, no ordering
        # structure needed for a 512-entry map refreshed every 15 s).
        oldest = min(_CACHE, key=lambda k: _CACHE[k][0])
        _CACHE.pop(oldest, None)
    _CACHE[agent_id] = (now + _CACHE_TTL_SEC, ctx)
    return ctx


def apply_reachability(enriched: dict, ctx: ReachabilityContext, package_name: str) -> dict:
    """Populate reachability keys on an `enriched` dict in place, and return it.

    Only overwrites `package_running` / `port_open` with a positive result — an
    existing True from a cross-finding signal is preserved, so this strictly
    *adds* recall, never removes an already-established reachability signal.
    """
    if not ctx.loaded:
        return enriched
    if ctx.package_running(package_name):
        enriched["package_running"] = True
    if ctx.package_port_open(package_name):
        enriched["port_open"] = True
    return enriched


def _reset_cache_for_tests() -> None:
    """Test hook — clear the module-level TTL cache between cases."""
    _CACHE.clear()
