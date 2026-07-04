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
                 overflow_sink=None):
        self.config     = config
        self.enc_key    = enc_key
        self.mac_key    = mac_key
        self.send_queue = send_queue
        self.agent_id   = config["agent"]["id"]
        self.tick       = config.get("collection", {}).get("tick_sec", 5)
        self._stop      = threading.Event()
        self._last_run: dict[str, float] = {}
        self._last_health = 0.0
        self._executor  = None
        self._cbr       = CircuitBreakerRegistry(fail_threshold=3, cooldown_sec=60)
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
        if cfg_sections:
            return cfg_sections
        # No [collection.sections] in config — use built-in defaults
        return _DEFAULT_SECTIONS

    def _tick_loop(self):
        # The orchestrator thread MUST NOT die — if it does, all collection
        # stops silently. Every iteration is guarded so one unexpected error
        # (bad config, executor hiccup) is logged and the loop continues.
        while not self._stop.is_set():
            try:
                now = time.time()

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
                            self._last_run[name] = now
                            if self._cbr.allow(name):
                                self._executor.submit(self._run_section, name, cfg)  # type: ignore
                            else:
                                log.debug("[%s] circuit open — skipping", name)
                    except Exception as exc:
                        log.error("tick scheduling error for section %s: %s", name, exc)
            except Exception as exc:
                log.error("orchestrator tick loop error (continuing): %s", exc)

            self._stop.wait(timeout=self.tick)

    def _run_section(self, name: str, cfg: dict):
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


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


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
    try:
        cfg = load_config(config_path)
        status_file = cfg.get("paths", {}).get("status_file", _DEFAULT_STATUS_FILE)
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

    cfg = load_config(args.config)
    setup_logging(cfg)

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

    # Import sender here (avoids circular import)
    from .sender import Sender
    # Pass mac_key so the sender re-stamps transport freshness at send time —
    # spooled data survives outages > the manager's replay window (no loss).
    sender = Sender(cfg, send_queue, mac_key=mac_key)
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
                        overflow_sink=sender.spool_envelope)
    orch_thread  = orch.start()

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
                              overflow_sink=orch.overflow_sink)
                orch.start()
            except Exception as exc:
                log.error("Config reload failed: %s", exc)
        signal.signal(signal.SIGHUP, _reload)

    log.info("Agent running. tick=%ss. SIGHUP to reload, SIGTERM to stop.",
             cfg.get("collection", {}).get("tick_sec", 5))
    orch_thread.join()


if __name__ == "__main__":
    main()
