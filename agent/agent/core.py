"""
agent/agent.py — Main orchestrator
Reads agent.toml, schedules collectors, encrypts, sends to manager.

Usage:
    python3 agent/agent.py [--config path/to/agent.toml]

Signal handling:
    SIGTERM / SIGINT  → graceful shutdown
    SIGHUP            → reload config (change intervals without restart)
"""

import argparse
import json
import logging
import logging.handlers
import os
import queue
import signal
import sys
import threading
import time

# ── Config ────────────────────────────────────────────────────────────────────
try:
    import tomllib                          # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib             # backport: pip install tomli
    except ImportError:
        print("ERROR: Python 3.11+ required, or: pip install tomli", file=sys.stderr)
        sys.exit(1)

import platform
import socket

from .crypto          import derive_keys, encrypt
from .enrollment      import enroll, EnrollmentError
from .keystore        import load_key, store_key
from .circuit_breaker import CircuitBreakerRegistry

# ── OS-aware path defaults ────────────────────────────────────────────────────
if sys.platform == "darwin":
    _DEFAULT_LOG_FILE    = "/Library/AttackLens/logs/agent.log"
    _DEFAULT_SPOOL_DIR   = "/Library/AttackLens/spool"
    _DEFAULT_SECURITY    = "/Library/AttackLens/security"
    _DEFAULT_CONFIG      = "/Library/AttackLens/agent.toml"
    _DEFAULT_STATUS_FILE = "/Library/AttackLens/health.json"
elif sys.platform == "win32":
    _DEFAULT_LOG_FILE    = r"C:\Program Files (x86)\AttackLens\logs\agent.log"
    _DEFAULT_SPOOL_DIR   = r"C:\Program Files (x86)\AttackLens\spool"
    _DEFAULT_SECURITY    = r"C:\Program Files (x86)\AttackLens\security"
    _DEFAULT_CONFIG      = r"C:\Program Files (x86)\AttackLens\config\agent.toml"
    _DEFAULT_STATUS_FILE = r"C:\Program Files (x86)\AttackLens\health.json"
else:
    _DEFAULT_LOG_FILE    = "/var/log/attacklens/agent.log"
    _DEFAULT_SPOOL_DIR   = "/var/lib/attacklens/spool"
    _DEFAULT_SECURITY    = "/var/lib/attacklens/security"
    _DEFAULT_CONFIG      = "/etc/attacklens/agent.toml"
    _DEFAULT_STATUS_FILE = "/var/lib/attacklens/health.json"

# ── Built-in default collection schedule (used when [collection.sections] absent) ──
_DEFAULT_SECTIONS: dict = {
    "metrics":     {"enabled": True,  "interval_sec": 60,    "send": True},
    "connections": {"enabled": True,  "interval_sec": 60,    "send": True},
    "processes":   {"enabled": True,  "interval_sec": 60,    "send": True},
    "ports":       {"enabled": True,  "interval_sec": 30,    "send": True},
    "network":     {"enabled": True,  "interval_sec": 120,   "send": True},
    "arp":         {"enabled": True,  "interval_sec": 120,   "send": True},
    "mounts":      {"enabled": True,  "interval_sec": 120,   "send": True},
    "battery":     {"enabled": True,  "interval_sec": 120,   "send": True},
    "openfiles":   {"enabled": True,  "interval_sec": 120,   "send": True},
    "services":    {"enabled": True,  "interval_sec": 120,   "send": True},
    "users":       {"enabled": True,  "interval_sec": 120,   "send": True},
    "hardware":    {"enabled": True,  "interval_sec": 120,   "send": True},
    "containers":  {"enabled": True,  "interval_sec": 120,   "send": True},
    "storage":     {"enabled": True,  "interval_sec": 600,   "send": True},
    "tasks":       {"enabled": True,  "interval_sec": 600,   "send": True},
    "security":    {"enabled": True,  "interval_sec": 3600,  "send": True},
# CIS compliance scan: many short shell probes; 60 s ceiling instead of the
# 25 s default so a cold first run (systemsetup/pwpolicy are ~1 s each) never
# degrades checks to not_applicable via the section budget.
"sca":         {"enabled": True,  "interval_sec": 43200, "send": True, "timeout_sec": 60},
    "sysctl":      {"enabled": True,  "interval_sec": 3600,  "send": True},
    "configs":     {"enabled": True,  "interval_sec": 3600,  "send": True},
    "developer_security": {
        "enabled": True, "interval_sec": 3600, "send": True, "timeout_sec": 120,
    },
    "apps":        {"enabled": True,  "interval_sec": 86400, "send": True},
    "packages":    {"enabled": True,  "interval_sec": 86400, "send": True},
    "binaries":    {"enabled": False, "interval_sec": 86400, "send": False},
    "sbom":        {"enabled": True,  "interval_sec": 86400, "send": True},
}

# ── OS-aware collector + normalizer loading ───────────────────────────────────
if sys.platform == "win32":
    try:
        from agent.os.windows.collectors import COLLECTORS
        from agent.os.windows.normalizer import normalize as _normalize
        _HAS_NORMALIZER = True
    except Exception as _e:
        log_init = logging.getLogger("agent")
        log_init.warning("Windows collectors unavailable (%s) — using empty registry", _e)
        COLLECTORS: dict = {}
        _HAS_NORMALIZER = False
elif sys.platform == "darwin":
    try:
        from agent.os.macos.collectors import COLLECTORS
        from agent.os.macos.normalizer import normalize as _normalize
        _HAS_NORMALIZER = True
    except Exception as _e:
        log_init = logging.getLogger("agent")
        log_init.warning("macOS collectors unavailable (%s) — falling back to generic", _e)
        from .collectors import COLLECTORS
        try:
            from .normalizer import normalize as _normalize
            _HAS_NORMALIZER = True
        except Exception:
            _HAS_NORMALIZER = False
else:
    from .collectors import COLLECTORS   # Linux / generic collector registry
    try:
        from .normalizer import normalize as _normalize
        _HAS_NORMALIZER = True
    except Exception:
        _HAS_NORMALIZER = False

# Optional per-section subprocess budget (macOS collectors only). When present,
# the orchestrator arms it on each collector's worker thread so a section that
# fans out into many slow shell-outs (security, packages, …) degrades to
# partial data within its timeout instead of hanging the whole section. No-op
# on platforms whose collectors don't shell out through the budgeted _run().
try:
    from agent.os.macos.collectors.base import (
        set_run_budget as _set_run_budget,
        clear_run_budget as _clear_run_budget,
    )
except Exception:
    _set_run_budget = _clear_run_budget = None

# Headroom between the collector's self-imposed budget and the orchestrator's
# hard section timeout, so partial data is gathered and returned BEFORE the
# hard timeout would fire and discard it.
_SECTION_BUDGET_MARGIN_SEC = 3.0

# Cached at startup — never changes during the process lifetime
_OS_NAME   = "macos" if sys.platform == "darwin" else ("linux" if sys.platform.startswith("linux") else "windows")
_OS_VER    = platform.mac_ver()[0] if sys.platform == "darwin" else platform.version()
_ARCH      = platform.machine()
_HOSTNAME  = socket.gethostname()

# How often to push a synthetic agent_health section (circuit-breaker snapshot)
_HEALTH_INTERVAL_SEC = 60
_START_TIME          = time.time()

# A backward wall-clock jump larger than this (seconds) is treated as real clock
# skew — an NTP correction after boot, a VM snapshot restore, or a manual date
# change — rather than scheduler jitter. The scheduler runs on time.time(), so a
# backward jump would push every section's next-fire time into the future and
# stall ALL collection until the clock caught up; when detected we re-seed.
_CLOCK_SKEW_BACKWARD_SEC = 60

# Hard wall-clock deadline for a single collector call. Without this, a
# hung subprocess (a stuck system_profiler/mdfind call, a stalled read on a
# slow disk) blocks its ThreadPoolExecutor worker FOREVER — the circuit
# breaker never sees a failure (it only records when fn() returns, success or
# exception; a hang returns neither), so the section's data freezes
# permanently with zero operator visibility, and the worker pool slowly loses
# a slot per hang until everything stops. Overridable per-section via
# cfg["timeout_sec"], or globally via [collection] section_timeout_sec.
_DEFAULT_SECTION_TIMEOUT_SEC = 25


def _call_with_timeout(fn, timeout_sec: float):
    """Run fn() with a hard deadline; raise TimeoutError if it's exceeded.

    A plain function call can't be interrupted from the outside in Python, so
    a genuinely hung fn() keeps running in a throwaway daemon thread past the
    deadline — but THIS call returns to the caller immediately regardless.
    A hang now costs one leaked daemon thread, never a permanently-stuck pool
    worker: the orchestrator's bounded ThreadPoolExecutor slot is freed every
    time, so one slow/hanging collector can no longer starve the others.
    """
    result: queue.Queue = queue.Queue(maxsize=1)

    def _worker():
        # Arm the subprocess budget on THIS worker thread (thread-local), so the
        # collector's many _run() calls collectively stay under the section
        # timeout and return partial data instead of overrunning it. Margin
        # keeps the collector finishing before the hard timeout below fires.
        if _set_run_budget is not None:
            _set_run_budget(max(1.0, timeout_sec - _SECTION_BUDGET_MARGIN_SEC))
        try:
            result.put(("ok", fn()))
        except Exception as exc:
            result.put(("error", exc))
        finally:
            if _clear_run_budget is not None:
                _clear_run_budget()

    threading.Thread(target=_worker, daemon=True, name="collector-call").start()
    try:
        kind, value = result.get(timeout=timeout_sec)
    except queue.Empty:
        raise TimeoutError(f"did not complete within {timeout_sec}s — possible hang")
    if kind == "error":
        raise value
    return value


# ─────────────────────────────────────────────────────────────────────────────
#  Orchestrator  (with circuit breakers + health heartbeat)
# ─────────────────────────────────────────────────────────────────────────────

class Orchestrator:
    """
    Schedules all collection sections, encrypts payloads, enqueues for sender.

    Features
    ────────
    • Per-section circuit breakers: CLOSED → OPEN → HALF-OPEN state machine.
      Failing sections are skipped and probed again after cooldown (60 s default).
    • Health heartbeat: synthetic agent_health payload every 60 s containing
      circuit-breaker snapshot, queue depth, and uptime.
    • Thread-pool execution: collectors run concurrently (one slot each).
    • Per-collector timeout (25 s default): a hung collector can't hold its
      pool slot forever or freeze that section's data permanently — it's
      converted into a circuit-breaker failure and retried on schedule.
    • Graceful shutdown via _stop event.
    """

    def __init__(self, config: dict, enc_key: bytes, mac_key: bytes,
                 send_queue: "queue.Queue", link_state=None, policy_state=None,
                 overflow_sink=None, heartbeat=None):
        self.config     = config
        self.enc_key    = enc_key
        self.mac_key    = mac_key
        self.send_queue = send_queue
        self.agent_id   = config["agent"]["id"]
        self.tick       = config.get("collection", {}).get("tick_sec", 5)
        self._stop      = threading.Event()
        self._last_run: dict[str, float] = {}
        self._last_health = 0.0
        self._last_wall   = 0.0     # clock-skew detector baseline (wall clock)
        self._executor  = None
        self._cbr       = CircuitBreakerRegistry(fail_threshold=3, cooldown_sec=60)
        # Per-collector overlap guard (matrix R9): a section whose run takes
        # LONGER than its interval must not be submitted again while the prior
        # run is still executing (it would double-run, duplicate work, and burn a
        # pool slot). Names in _inflight are skipped until they complete.
        self._inflight: set[str] = set()
        self._inflight_lock = threading.Lock()
        self._skipped_overlap = 0
        # Optional callable(success: bool=False) -> None: liveness heartbeat for
        # the Supervisor (matrix R6). Called each tick (alive) and on a successful
        # collection (success), so a wedged orchestrator is detectable.
        self.heartbeat = heartbeat
        # Optional callable -> dict: manager connectivity snapshot from the
        # Sender, surfaced in the agent_health heartbeat for dashboard link
        # status. Kept as an attribute so it survives SIGHUP __init__ re-runs.
        self.link_state = link_state
        # Optional callable -> dict: ConfigEngine snapshot (accepted policy
        # versions + response gate), surfaced in the heartbeat so the manager
        # can see which signed policies each agent is actually running.
        self.policy_state = policy_state
        # Optional callable(envelope) -> None: where an evicted envelope goes
        # when the in-memory queue is full. Wired to the Sender's disk spool so
        # backpressure overflow is PERSISTED, never silently dropped. Survives
        # SIGHUP re-init like the other providers above.
        self.overflow_sink = overflow_sink

    def start(self):
        import concurrent.futures
        self._stop.clear()
        self._last_run    = {}
        self._last_health = 0.0
        self._last_wall   = 0.0
        self._seed_phase()
        self._executor    = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(4, len(COLLECTORS)),
            thread_name_prefix="collector",
        )
        t = threading.Thread(target=self._tick_loop, daemon=True,
                             name="orchestrator")
        t.start()
        log.info("Orchestrator started — %d sections, circuit breakers active",
                 len(self._sections()))
        return t

    # Spread first fires over a SMALL fixed window (seconds), not the section's
    # full interval — otherwise a daily collector wouldn't fire for ~24h after
    # startup. This de-bursts the startup stampede while keeping every section
    # prompt (all fire within _STARTUP_STAGGER_SEC of boot).
    _STARTUP_STAGGER_SEC = 30

    def _seed_phase(self) -> None:
        """Stagger each section's FIRST fire across a small startup window so
        collectors don't all stampede on the same tick (CPU spike + manager
        429s), while still firing every section promptly after boot. Phase is a
        deterministic hash of the name (stable across restarts) but capped at
        _STARTUP_STAGGER_SEC — never the full interval.
        """
        import hashlib
        now = time.time()
        for name, cfg in self._sections().items():
            interval = max(1, cfg.get("interval_sec", 60))
            stagger  = min(interval, self._STARTUP_STAGGER_SEC)
            h = int(hashlib.sha256(name.encode()).hexdigest(), 16)
            phase = h % stagger             # 0 .. stagger-1 seconds (≤ 30s)
            # First fire lands at now+phase (prompt), then natural cadence.
            self._last_run[name] = now - interval + phase

    def stop(self):
        self._stop.set()
        if self._executor:
            self._executor.shutdown(wait=False)

    def _sections(self) -> dict:
        cfg_sections = self.config.get("collection", {}).get("sections", {})
        # No [collection.sections] in config — use built-in defaults verbatim.
        if not cfg_sections:
            return _DEFAULT_SECTIONS
        # Merge defaults with the operator's config. The old behaviour was
        # all-or-nothing: any [collection.sections] block made _DEFAULT_SECTIONS
        # ignored entirely, so a section shipped in a newer agent build (e.g.
        # developer_security) was NEVER scheduled on an agent whose agent.toml
        # predated it — it silently required a config edit or pkg reinstall.
        #
        # Now the operator's explicit blocks stay authoritative (including
        # `enabled = false` to opt out), and any default section that (a) the
        # config doesn't mention and (b) has a registered collector on THIS
        # platform is added — so new sections roll out on a binary update alone.
        # Gating on COLLECTORS keeps a generic-registry (fallback) agent from
        # being scheduled for a macOS-only section it cannot collect.
        merged = dict(cfg_sections)
        for name, default in _DEFAULT_SECTIONS.items():
            if name not in merged and name in COLLECTORS:
                merged[name] = dict(default)
        return merged

    def _maybe_reseed_on_skew(self, now: float) -> bool:
        """Re-seed the schedule when the wall clock jumps BACKWARD past the skew
        threshold, so collection doesn't stall until the clock catches up.

        A backward jump (NTP correction after boot, VM snapshot restore, manual
        date change) leaves every section's _last_run in the future; without this
        no section would fire for the duration of the jump. Returns True if a
        re-seed happened. (Forward jumps are harmless — they just fire sections
        promptly — so they're ignored.) Extracted for unit testing.
        """
        reseeded = False
        if self._last_wall and now < self._last_wall - _CLOCK_SKEW_BACKWARD_SEC:
            log.warning(
                "Wall clock jumped backward %.0fs (was %.0f, now %.0f) — "
                "re-seeding collection schedule to avoid a stall",
                self._last_wall - now, self._last_wall, now,
            )
            self._seed_phase()
            self._last_health = 0.0   # let the heartbeat fire promptly too
            reseeded = True
        self._last_wall = now
        return reseeded

    def _tick_loop(self):
        # The orchestrator thread MUST NOT die — if it does, all collection
        # stops silently. Every iteration is guarded so one unexpected error
        # (bad config, executor hiccup) is logged and the loop continues.
        while not self._stop.is_set():
            try:
                now = time.time()

                # Liveness heartbeat (matrix R6): prove the tick loop is running.
                if self.heartbeat is not None:
                    try:
                        self.heartbeat()
                    except Exception:
                        pass

                # ── Clock-skew guard ──────────────────────────────────────────
                self._maybe_reseed_on_skew(now)

                # ── Health heartbeat ──────────────────────────────────────────
                if now - self._last_health >= _HEALTH_INTERVAL_SEC:
                    self._last_health = now
                    self._executor.submit(self._emit_health)  # type: ignore

                # ── Section scheduling ────────────────────────────────────────
                for name, cfg in self._sections().items():
                    try:
                        if not cfg.get("enabled", True):
                            continue
                        interval = cfg.get("interval_sec", 60)
                        # While a breaker is open, re-check on ITS cooldown
                        # (60s default), not the section's own interval — a
                        # 1-hour section that just failed must not be silently
                        # held to a 1-hour retry cadence; the breaker's own
                        # cooldown promise (probed again after 60s) wins.
                        if self._cbr.state(name) != "CLOSED":
                            interval = min(interval, self._cbr.cooldown_for(name))
                        if now - self._last_run.get(name, 0) >= interval:
                            # Overlap guard (R9): skip if the prior run of this
                            # section is still in flight (slower than its interval).
                            if not self._try_mark_inflight(name):
                                self._skipped_overlap += 1
                                log.debug("[%s] previous run still in flight — "
                                          "skipping this tick (overlap)", name)
                                continue
                            self._last_run[name] = now
                            if self._cbr.allow(name):
                                self._executor.submit(self._run_section, name, cfg)  # type: ignore
                            else:
                                self._clear_inflight(name)   # not submitted
                                log.debug("[%s] circuit open — skipping", name)
                    except Exception as exc:
                        log.error("tick scheduling error for section %s: %s", name, exc)
            except Exception as exc:
                log.error("orchestrator tick loop error (continuing): %s", exc)

            self._stop.wait(timeout=self.tick)

    def _try_mark_inflight(self, name: str) -> bool:
        """Atomically claim a section slot. Returns False if already running."""
        with self._inflight_lock:
            if name in self._inflight:
                return False
            self._inflight.add(name)
            return True

    def _clear_inflight(self, name: str) -> None:
        with self._inflight_lock:
            self._inflight.discard(name)

    def _run_section(self, name: str, cfg: dict):
        # try/finally guarantees the overlap slot (R9) is released on EVERY path
        # (success, timeout, error, early-return) — a leaked slot would freeze the
        # section forever.
        try:
            fn = COLLECTORS.get(name)
            if not fn:
                return
            timeout = cfg.get("timeout_sec") or self.config.get("collection", {}).get(
                "section_timeout_sec", _DEFAULT_SECTION_TIMEOUT_SEC)
            try:
                raw = _call_with_timeout(fn, timeout)
                # Normalize raw output to canonical schema
                data = raw
                if _HAS_NORMALIZER:
                    try:
                        data = _normalize(name, raw)
                    except Exception as exc:
                        log.debug("Normalizer skipped for %s: %s", name, exc)
                self._cbr.success(name)
                # Successful collection → orchestrator is making progress (R6).
                if self.heartbeat is not None:
                    try:
                        self.heartbeat(success=True)
                    except Exception:
                        pass
                log.debug("Collected %s: %s items", name,
                          len(data) if isinstance(data, (list, dict)) else "—")
            except TimeoutError as exc:
                self._cbr.failure(name, str(exc))
                log.error("Collector %s timed out (limit=%ss) — %s", name, timeout, exc)
                # Do NOT enqueue an {"error": …} blob: it would overwrite the last
                # good snapshot for this section in the manager's store with an
                # error placeholder (and pollute detection). The failure is already
                # recorded on the circuit breaker and surfaced per-section in the
                # agent_health heartbeat — that is the failure channel. Skip the
                # send; the previous good data stays until a later cycle succeeds.
                return
            except Exception as exc:
                self._cbr.failure(name, str(exc))
                log.warning("Collector %s failed: %s", name, exc)
                return

            if not cfg.get("send", True):
                return

            self._enqueue(name, data)
        finally:
            self._clear_inflight(name)

    def _enqueue(self, section: str, data) -> None:
        payload = {
            "section":      section,
            "agent_id":     self.agent_id,
            "agent_name":   self.config["agent"].get("name", ""),
            "os":           _OS_NAME,
            "os_version":   _OS_VER,
            "arch":         _ARCH,
            "hostname":     _HOSTNAME,
            "collected_at": int(time.time()),
            "data":         data,
        }
        try:
            envelope = encrypt(payload, self.enc_key, self.mac_key,
                               self.agent_id, int(time.time()))
            envelope["section"] = section   # plaintext routing hint for manager
        except Exception as exc:
            log.error("Encrypt failed for %s — payload dropped: %s", section, exc)
            return

        maxq = self.config["manager"].get("max_queue_size", 500)
        if self.send_queue.qsize() >= maxq:
            # Queue is full — evict the oldest item to make room. Instead of
            # DROPPING it (the historical silent-data-loss path), spill it to the
            # Sender's disk spool so it is replayed once the backlog clears.
            try:
                evicted = self.send_queue.get_nowait()
                if self.overflow_sink is not None:
                    try:
                        self.overflow_sink(evicted)
                        log.warning(
                            "Send queue full (max=%d) — spilled oldest section=%s "
                            "to disk spool (backpressure). Check sender/network.",
                            maxq, evicted.get("section", "unknown"),
                        )
                    except Exception as exc:
                        log.error("Overflow spill failed section=%s: %s — dropped",
                                  evicted.get("section", "unknown"), exc)
                else:
                    log.warning(
                        "Send queue full (max=%d) — no overflow sink; dropped "
                        "oldest section=%s.", maxq, evicted.get("section", "unknown"),
                    )
            except queue.Empty:
                pass

        try:
            self.send_queue.put_nowait(envelope)
        except queue.Full:
            # Highly unlikely (we just evicted above) — spill rather than drop.
            if self.overflow_sink is not None:
                try:
                    self.overflow_sink(envelope)
                except Exception:
                    log.error("Send queue full after eviction section=%s — dropped",
                              section)
            else:
                log.error(
                    "Send queue still full after eviction for section=%s — dropping",
                    section,
                )

    def emit_event(self, section: str, data: dict) -> None:
        """Emit a single ad-hoc event (e.g. a macOS `system_boot` record) through
        the same encrypt → enqueue → spool path as scheduled sections. Public and
        guarded so a one-shot emit can never crash the caller."""
        try:
            self._enqueue(section, data)
        except Exception as exc:
            log.error("emit_event(%s) failed: %s", section, exc)

    def _emit_health(self) -> None:
        """Emit a synthetic agent_health section with diagnostics."""
        health_data = {
            "agent_id":     self.agent_id,
            "hostname":     _HOSTNAME,
            "os":           _OS_NAME,
            "arch":         _ARCH,
            "uptime_sec":   int(time.time() - _START_TIME),
            "queue_depth":  self.send_queue.qsize(),
            "sections":     self._cbr.snapshot(),
            "skipped_overlap": self._skipped_overlap,   # R9 visibility
            "generated_at": int(time.time()),
        }
        # Manager link health (probe state / spool backlog / auth failures).
        if self.link_state is not None:
            try:
                health_data["link"] = self.link_state()
            except Exception as exc:
                log.debug("link_state() failed: %s", exc)
        # Signed-policy state: which verified policy versions are active and
        # whether the active-response gate is open. Lets the manager confirm
        # fleet-wide policy convergence and spot agents stuck on a stale policy.
        if self.policy_state is not None:
            try:
                ps = self.policy_state()
                health_data["policy_versions"] = ps.get("policy_versions", {})
                health_data["response_enabled"] = ps.get("response_enabled", False)
            except Exception as exc:
                log.debug("policy_state() failed: %s", exc)
        self._enqueue("agent_health", health_data)
        self._write_status_file(health_data)

    def _write_status_file(self, health_data: dict) -> None:
        """Mirror the heartbeat to a local JSON file for offline diagnosis.

        The manager-bound heartbeat is useless for troubleshooting the exact
        outage it would otherwise report (manager unreachable). This file lets
        an operator run `attacklens-agent --status` (or just `cat` it) on the
        box itself with no network round-trip. Skipped when no [paths] table
        is configured (e.g. ad-hoc Orchestrator construction in tests) — only
        a real agent run (which always sets `paths.security_dir`) writes here.
        """
        paths = self.config.get("paths")
        if not paths:
            return
        path = paths.get("status_file", _DEFAULT_STATUS_FILE)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(health_data, f, indent=2)
            os.replace(tmp, path)
        except Exception as exc:
            log.debug("status file write failed (%s): %s", path, exc)


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

log = logging.getLogger("agent")


def setup_logging(cfg: dict):
    lcfg    = cfg.get("logging", {})
    level   = getattr(logging, lcfg.get("level", "INFO").upper(), logging.INFO)
    logfile = lcfg.get("file", _DEFAULT_LOG_FILE)
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        logfile,
        maxBytes=lcfg.get("max_mb", 10) * 1024 * 1024,
        backupCount=lcfg.get("backups", 3),
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[handler, logging.StreamHandler()],
    )


def _auto_agent_id() -> str:
    """
    Derive a stable hardware-bound agent ID.
    macOS  → Hardware UUID from system_profiler  → mac-<uuid>
    Windows→ MachineGuid from registry           → win-<guid>
    Linux  → /etc/machine-id                     → linux-<id>
    Fallback → hostname-based deterministic ID
    """
    try:
        if sys.platform == "darwin":
            import subprocess
            out = subprocess.check_output(
                ["system_profiler", "SPHardwareDataType"],
                text=True, timeout=10,
            )
            for line in out.splitlines():
                if "Hardware UUID" in line:
                    uuid = line.split(":")[-1].strip().lower()
                    return f"mac-{uuid}"
        elif sys.platform == "win32":
            import subprocess
            out = subprocess.check_output(
                ["reg", "query",
                 r"HKLM\SOFTWARE\Microsoft\Cryptography",
                 "/v", "MachineGuid"],
                text=True, timeout=10,
            )
            for line in out.splitlines():
                if "MachineGuid" in line:
                    guid = line.split()[-1].strip().lower()
                    return f"win-{guid}"
        else:
            try:
                with open("/etc/machine-id") as f:
                    mid = f.read().strip()
                if mid:
                    return f"linux-{mid[:32]}"
            except OSError:
                pass
    except Exception:
        pass
    # Fallback: hostname-based
    h = socket.gethostname().lower()
    import re
    h = re.sub(r"[^a-z0-9-]", "-", h)[:48]
    return f"host-{h}"


class ConfigError(Exception):
    """Raised when agent.toml is missing, malformed, or lacks required keys.
    Carries an operator-actionable message (printed once, no stack-trace loop)."""


def load_config(path: str) -> dict:
    """Load + minimally validate agent.toml.

    Turns the three config failure modes a boot daemon actually hits — file
    missing, malformed TOML, missing required keys — into a single clear
    ConfigError instead of a cryptic traceback that launchd would restart-loop
    on every 10 s forever. Fail-fast is correct (we can't invent a manager URL),
    but the operator gets a message that names the file and the exact problem.
    """
    try:
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(
            f"config file not found: {path}\n"
            f"  The installer generates it; regenerate with: "
            f"sudo attacklens-service repair"
        )
    except IsADirectoryError:
        raise ConfigError(f"config path is a directory, not a file: {path}")
    except PermissionError as exc:
        raise ConfigError(f"config file not readable ({exc}): {path}")
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(
            f"config file is not valid TOML ({exc}): {path}\n"
            f"  A partial write or hand-edit likely corrupted it; restore from "
            f"backup or run: sudo attacklens-service repair"
        )

    if not isinstance(cfg, dict):
        raise ConfigError(f"config file did not parse to a table: {path}")

    # Minimal structural validation of the keys the agent dereferences at startup.
    mgr = cfg.get("manager")
    if not isinstance(mgr, dict) or not str(mgr.get("url", "")).strip():
        raise ConfigError(
            f"[manager] url is missing or empty in {path}\n"
            f"  Set it to your manager, e.g.  url = \"http://MANAGER_IP:8080\""
        )
    url = str(mgr["url"]).strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ConfigError(
            f"[manager] url must start with http:// or https:// (got {url!r}) in {path}"
        )
    if not isinstance(cfg.get("agent"), dict):
        # Not fatal — id is auto-derived later — but normalise so callers can
        # setdefault safely without a TypeError on a non-dict.
        cfg["agent"] = {} if cfg.get("agent") is None else cfg["agent"]
        if not isinstance(cfg["agent"], dict):
            raise ConfigError(f"[agent] section must be a table in {path}")
    return cfg


def _resolve_security_dir(cfg: dict, config_path: str) -> str:
    """Absolute path as-is; relative paths resolve next to the config file."""
    raw = cfg.get("paths", {}).get("security_dir", _DEFAULT_SECURITY)
    if os.path.isabs(raw):
        return raw
    base = os.path.dirname(os.path.abspath(config_path))
    return os.path.normpath(os.path.join(base, raw))


def _hex64(s: str) -> bool:
    s = s.strip().lower()
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _obtain_api_key(cfg: dict, config_path: str) -> str:
    """
    Resolution order:
      1) [manager] api_key in agent.toml if set to a valid 64-hex key (dev / explicit)
         — wins over keystore so bootstrap + make keygen stay in sync with manager
      2) Keystore (keychain or file under security_dir)
      3) enroll() using [enrollment] token
    """
    agent_id     = cfg["agent"]["id"]
    backend      = cfg.get("enrollment", {}).get("keystore", "keychain")
    security_dir = _resolve_security_dir(cfg, config_path)
    cfg.setdefault("paths", {})["security_dir"] = security_dir

    raw = (cfg.get("manager") or {}).get("api_key")
    if isinstance(raw, str):
        k = raw.strip()
        if k and k != "REPLACE_ME" and _hex64(k):
            try:
                store_key(agent_id, k, backend=backend, security_dir=security_dir)
                log.info(
                    "Using [manager] api_key from %s; synced to keystore (%s)",
                    os.path.basename(config_path),
                    backend,
                )
            except Exception as exc:
                log.warning(
                    "Could not persist key to keystore (%s); using config key this run",
                    exc,
                )
            return k

    k = load_key(agent_id, backend=backend, security_dir=security_dir)
    if k:
        # Reboot-safety migration: a key that came from the Keychain (older
        # installs stored keychain-only) must ALSO exist as the ACL-restricted
        # file, because a root LaunchDaemon at boot has no login session and
        # can't read the login keychain. Ensure the boot-safe file mirror exists.
        # Idempotent + best-effort — never block startup on it.
        if backend == "keychain":
            try:
                store_key(agent_id, k, backend="file", security_dir=security_dir)
            except Exception as exc:
                log.debug("Boot-safe key mirror refresh failed: %s", exc)
        return k

    if isinstance(raw, str):
        k = raw.strip()
        if k and k != "REPLACE_ME":
            try:
                store_key(agent_id, k, backend=backend, security_dir=security_dir)
                log.info(
                    "Loaded API key from [manager] api_key in %s; saved to keystore (%s)",
                    os.path.basename(config_path),
                    backend,
                )
            except Exception as exc:
                log.warning(
                    "Could not persist key to keystore (%s); using [manager] api_key this run",
                    exc,
                )
            return k

    log.info("No API key in keystore or config — starting first-run enrollment...")
    return enroll(cfg)


def _print_status(config_path: str) -> None:
    """Print the last-written health snapshot and exit. No agent startup,
    no network call — reads whatever the running agent last wrote to disk.
    """
    status_file = _DEFAULT_STATUS_FILE
    # Use a RAW parse here, not the validating load_config(): --status is a
    # read-only diagnostic that must work even when the config is incomplete or
    # invalid (that's often exactly when an operator runs it). We only need the
    # status_file path; a bad [manager] url must not send us to the default.
    try:
        with open(config_path, "rb") as f:
            cfg = tomllib.load(f)
        status_file = (cfg.get("paths") or {}).get("status_file", _DEFAULT_STATUS_FILE)
    except Exception:
        pass   # fall back to the default path; config may not exist yet

    try:
        with open(status_file, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(json.dumps({
            "error": "no status file yet — agent may not be running, or "
                     "hasn't completed its first heartbeat (60s after start)",
            "path": status_file,
        }, indent=2))
        sys.exit(1)
    except Exception as exc:
        print(json.dumps({"error": str(exc), "path": status_file}, indent=2))
        sys.exit(1)

    age = int(time.time()) - data.get("generated_at", 0)
    data["_status_file_age_sec"] = age
    if age > 180:
        data["_warning"] = "stale — last heartbeat over 3 minutes ago, agent may be down"
    print(json.dumps(data, indent=2))


def main():
    parser = argparse.ArgumentParser(description="mac_intel agent")
    parser.add_argument("--config", default=_DEFAULT_CONFIG)
    parser.add_argument("--status", action="store_true",
                        help="Print the agent's last health snapshot as JSON and exit "
                             "(no network call, reads the on-disk heartbeat mirror)")
    args = parser.parse_args()

    if args.status:
        _print_status(args.config)
        return

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        # One clear line to stderr (launchd captures it) then exit non-zero.
        # Better than a raw traceback restart-looping every ThrottleInterval.
        print(f"FATAL: {exc}", file=sys.stderr)
        sys.exit(78)   # EX_CONFIG — signals a configuration problem to launchd
    setup_logging(cfg)

    # ── Single-instance guard ────────────────────────────────────────────────
    # Prevent two agent processes (e.g. the agent LaunchDaemon AND the
    # watchdog-spawned child) from racing on the shared disk spool, which would
    # duplicate telemetry and corrupt unsent.ndjson. A brief wait covers the
    # normal old→new overlap during a launchd restart; a persistent duplicate
    # exits cleanly. POSIX-only (no-op elsewhere) and never fatal to construct.
    _instance_lock = None
    try:
        from .single_instance import acquire as _acquire_lock, AlreadyRunning
        _lock_path = cfg.get("paths", {}).get("lock_file") or os.path.join(
            os.path.dirname(_DEFAULT_SPOOL_DIR), "attacklens-agent.lock")
        try:
            _instance_lock = _acquire_lock(_lock_path)
        except AlreadyRunning as exc:
            print(f"Another agent instance is already running ({exc}); exiting to "
                  f"avoid duplicate telemetry / spool corruption.", file=sys.stderr)
            sys.exit(0)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - lock is best-effort, never block startup
        log.warning("single-instance guard unavailable (%s) — continuing", exc)

    # ── Auto-populate agent ID from hardware if not set in config ─────────────
    cfg.setdefault("agent", {})
    if not cfg["agent"].get("id"):
        cfg["agent"]["id"] = _auto_agent_id()
        log.info("Agent ID auto-derived: %s", cfg["agent"]["id"])

    log.info("mac_intel agent starting — id=%s name=%r",
             cfg["agent"]["id"], cfg["agent"].get("name", ""))

    agent_id = cfg["agent"]["id"]
    backend  = cfg.get("enrollment", {}).get("keystore", "keychain")

    try:
        api_key = _obtain_api_key(cfg, args.config)
    except EnrollmentError as exc:
        log.warning("Enrollment failed (manager unreachable?): %s", exc)
        log.warning("Starting with temporary key — will retry enrollment every 60s in background")
        import secrets as _secrets
        api_key = _secrets.token_hex(32)
        # Persist to file backend so restarts find it before enrollment succeeds
        try:
            from .keystore import store_key as _store
            _store(agent_id, api_key, backend="file",
                   security_dir=_resolve_security_dir(cfg, args.config))
        except Exception as _ke:
            log.debug("Could not persist temp key: %s", _ke)
        # Background thread: keep retrying enrollment until manager is reachable
        def _retry_enrollment(cfg=cfg, config_path=args.config):
            import time as _time
            while True:
                _time.sleep(60)
                try:
                    real_key = enroll(cfg)
                    log.info("Enrollment succeeded on retry — restart agent to apply new key")
                    break
                except Exception as _re:
                    log.debug("Enrollment retry: %s", _re)
        threading.Thread(target=_retry_enrollment, daemon=True,
                         name="enrollment-retry").start()

    if not api_key:
        log.critical("No API key for agent_id=%s", agent_id)
        sys.exit(1)

    log.info("API key ready (keystore backend=%s, agent_id=%s)", backend, agent_id)

    enc_key, mac_key = derive_keys(api_key)
    log.info("Crypto keys derived (tail=...%s)", api_key[-4:])

    send_queue: queue.Queue = queue.Queue()

    # ── Supervision tree (matrix R6) ──────────────────────────────────────────
    # Workers publish liveness heartbeats; a supervisor thread escalates a dead/
    # wedged worker to a clean process exit so launchd (the single lifecycle
    # owner) restarts the whole agent deterministically — never a competing
    # in-process supervisor. Best-effort: if supervision is unavailable, the
    # agent still runs (KeepAlive remains the crash-recovery backstop).
    _hb = None
    try:
        from .supervision import HeartbeatRegistry
        _hb = HeartbeatRegistry()
        _hb.register("sender")
        _hb.register("orchestrator")
    except Exception as exc:  # noqa: BLE001
        log.warning("supervision unavailable (%s) — continuing without it", exc)

    def _sender_beat(success: bool = False):
        if _hb is not None:
            _hb.beat("sender", success)

    def _orch_beat(success: bool = False):
        if _hb is not None:
            _hb.beat("orchestrator", success)

    # Import sender here (avoids circular import)
    from .sender import Sender
    # Pass mac_key so the sender re-stamps transport freshness at send time —
    # spooled data survives outages > the manager's replay window (no loss).
    sender = Sender(cfg, send_queue, mac_key=mac_key, heartbeat=_sender_beat)
    sender_thread = sender.start()

    # ── Signed-policy control plane ───────────────────────────────────────────
    # Replaces the static agent.toml-only posture for the policy-controlled
    # sections (security/response/telemetry/compliance): the ConfigEngine merges
    # baseline ◅ verified manager policies ◅ tighten-only overrides into one
    # immutable RuntimeConfig, fails closed on the response gate, and refreshes
    # cache-first/non-blocking. Construction must never abort agent startup.
    config_engine = None
    try:
        from .config_engine import (ConfigEngine, HttpPolicyTransport,
                                     PathProvider)
        from .policy import TrustStore

        _base = os.path.dirname(os.path.abspath(args.config))
        _paths = PathProvider(base=_base)
        _trust = TrustStore(keystore_dir=_paths.keystore_dir)
        _transport = HttpPolicyTransport(
            cfg["manager"]["url"],
            agent_id=agent_id,
            tls_verify=cfg["manager"].get("tls_verify", True),
            timeout_sec=cfg["manager"].get("timeout_sec", 10),
        )
        _group_ids = cfg.get("agent", {}).get("group_ids", []) \
            or cfg.get("policy", {}).get("group_ids", [])
        config_engine = ConfigEngine(
            paths=_paths, trust=_trust, transport=_transport,
            agent_id=agent_id, group_ids=_group_ids,
        )
        config_engine.load()                 # cache-first, non-blocking
        config_engine.start_background()     # refresh on a monotonic cadence + reconnect
        rc = config_engine.current()
        log.info("ConfigEngine ready — policy_versions=%s response_enabled=%s",
                 dict(rc.policy_versions), rc.response_enabled)
    except Exception as exc:
        log.error("ConfigEngine init failed (%s) — running on baseline only", exc)

    def _policy_state():
        if config_engine is None:
            return {"policy_versions": {}, "response_enabled": False}
        rc = config_engine.current()
        return {"policy_versions": dict(rc.policy_versions),
                "response_enabled": rc.response_enabled}

    orch = Orchestrator(cfg, enc_key, mac_key, send_queue,
                        link_state=sender.link_state,
                        policy_state=_policy_state,
                        overflow_sink=sender.spool_envelope,
                        heartbeat=_orch_beat)
    orch_thread  = orch.start()

    # ── Supervisor loop (matrix R6) ───────────────────────────────────────────
    # Periodically evaluate worker liveness. A worker that is ALIVE but not
    # succeeding (e.g. manager unreachable) only ESCALATEs (logged, throttled) —
    # never a restart. A worker that stops ticking (dead/hung thread) is escalated
    # to a clean process exit so launchd restarts the whole agent; the restart
    # budget bounds the rate (launchd's ThrottleInterval provides the floor).
    if _hb is not None:
        def _supervise():
            import time as _t
            from .supervision import Supervisor, RESTART, TERMINATE, ESCALATE
            from .obs import log_throttled
            # alive_stale generously exceeds the worst-case send cycle
            # (max_retry × timeout + backoff ≈ 105 s) so a busy-but-alive sender
            # is never falsely killed; a truly wedged thread is caught in ≤5 min.
            sup = Supervisor(_hb, alive_stale=300.0, success_stale=900.0,
                             grace=120.0, max_restarts=3, window_sec=600.0)
            while not orch._stop.is_set():          # noqa: SLF001 - shared stop
                orch._stop.wait(timeout=30.0)
                if orch._stop.is_set():
                    break
                try:
                    for name, verdict in sup.check():
                        if verdict == ESCALATE:
                            log_throttled(
                                log, f"supervise:{name}", logging.WARNING,
                                "component alive but not succeeding",
                                interval=300.0, component=name,
                                snapshot=_hb.snapshot(),
                                recovery_action="monitoring",
                            )
                        elif verdict in (RESTART, TERMINATE):
                            log.error(
                                "SUPERVISOR: component %s is unresponsive (%s) — "
                                "exiting for a clean launchd restart. snapshot=%s",
                                name, verdict, _hb.snapshot(),
                            )
                            try:
                                orch.stop(); sender.stop()
                            except Exception:
                                pass
                            os._exit(70)   # EX_SOFTWARE — launchd KeepAlive restarts
                except Exception as exc:      # noqa: BLE001 - supervisor must not die
                    log.debug("supervisor cycle error: %s", exc)
        threading.Thread(target=_supervise, daemon=True, name="supervisor").start()

    # ── Boot persistence + reboot detection (macOS) ──────────────────────────
    # Guarantees the LaunchDaemon still auto-starts after the next shutdown even
    # if the plist was deleted/disabled/tampered, and emits a `system_boot` event
    # when the box rebooted since the agent last ran. Best-effort — a failure
    # here must never abort startup, so it is fully guarded.
    if sys.platform == "darwin":
        try:
            from agent.os.macos.boot_persistence import on_agent_startup
            on_agent_startup(orch, args.config)
        except Exception as exc:
            log.debug("boot-persistence/reboot-detect skipped: %s", exc)

    # Re-enrollment callback: called by sender when persistent 401 detected.
    # Obtains a new key, derives new crypto keys, updates the orchestrator in-place.
    _security_dir = _resolve_security_dir(cfg, args.config)
    _ks_backend   = cfg.get("enrollment", {}).get("keystore", "keychain")

    def _on_auth_error():
        log.info("Re-enrollment triggered — obtaining new key from manager...")
        try:
            new_key = enroll(cfg)
            if not new_key:
                # 409 case: existing key still valid, nothing to do
                log.info("Re-enrollment: existing key still valid")
                return
            store_key(agent_id, new_key, backend=_ks_backend,
                      security_dir=_security_dir)
            new_enc, new_mac = derive_keys(new_key)
            orch.enc_key = new_enc
            orch.mac_key = new_mac
            # Keep the sender's re-stamp key in sync with the rotated key.
            sender.set_mac_key(new_mac)
            # Drain in-memory queue: items encrypted with old key cannot be
            # decrypted by the manager after key rotation — drop them so the
            # sender doesn't loop on 401s from stale-key ciphertext.
            drained = 0
            while not send_queue.empty():
                try:
                    send_queue.get_nowait()
                    drained += 1
                except Exception:
                    break
            if drained:
                log.info("Dropped %d stale-key items from send queue after re-enrollment",
                         drained)
            log.info("Re-enrollment complete — new crypto keys active (tail=...%s)",
                     new_key[-4:])
        except EnrollmentError as exc:
            log.error("Re-enrollment failed (will retry on next auth failure): %s", exc)
        except Exception as exc:
            log.error("Re-enrollment unexpected error: %s", exc)

    sender.on_auth_error = _on_auth_error

    def _shutdown(signum, frame):
        log.info("Shutting down (signal %d)", signum)
        # Record a GRACEFUL stop so the next boot classifies this shutdown as
        # clean. If the box instead loses power / panics / is SIGKILLed, this
        # never runs and the marker stays "unclean" → reported as unexpected.
        if sys.platform == "darwin":
            try:
                from agent.os.macos.boot_persistence import mark_clean_stop
                mark_clean_stop()
            except Exception as exc:
                log.debug("clean-stop marker failed: %s", exc)
        orch.stop()
        sender.stop()
        if config_engine is not None:
            config_engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    # SIGHUP — POSIX only (reload config); not available on Windows
    if sys.platform != "win32":
        def _reload(signum, frame):
            nonlocal cfg
            try:
                cfg = load_config(args.config)
                log.info("Config reloaded on SIGHUP")
                # Re-pull verified policies on reload too (SIGHUP == reload_config).
                if config_engine is not None:
                    try:
                        result = config_engine.refresh()
                        log.info("Policy refresh on SIGHUP: %s", result.outcomes)
                    except Exception as exc:
                        log.error("Policy refresh on SIGHUP failed: %s", exc)
                orch.stop()
                # Use orch.enc_key/mac_key — not startup enc_key/mac_key — so
                # any keys updated via re-enrollment are preserved across reloads.
                # Preserve link_state + policy_state providers across the re-init.
                orch.__init__(cfg, orch.enc_key, orch.mac_key, send_queue,
                              link_state=orch.link_state,
                              policy_state=orch.policy_state,
                              overflow_sink=orch.overflow_sink,
                              heartbeat=orch.heartbeat)
                orch.start()
            except Exception as exc:
                log.error("Config reload failed: %s", exc)
        signal.signal(signal.SIGHUP, _reload)

    log.info("Agent running. tick=%ss. SIGHUP to reload, SIGTERM to stop.",
             cfg.get("collection", {}).get("tick_sec", 5))
    orch_thread.join()


if __name__ == "__main__":
    main()
