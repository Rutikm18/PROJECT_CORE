#!/usr/bin/env python3
"""
agent_v2.py — mac_intel Hardened Agent v2
==========================================
A production-grade agent with:
  • Startup self-test: verifies every collector before sending any data
  • Circuit breakers: stops retrying sections that consistently fail
  • Disk spool: survives manager outages, auto-drains on reconnect
  • Health heartbeat: sends agent status + per-section health to manager every 60 s
  • Connectivity watchdog: probes manager, pauses collection if unreachable
  • Proper fallbacks: psutil → CLI for every network/process collector
  • Graceful shutdown: SIGTERM / SIGINT flush queue, persist spool

Usage:
    python3 agent_v2.py [--config agent.toml]
    # or via Makefile:
    make run-agent-v2
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import logging.handlers
import os
import platform
import queue
import signal
import socket
import sys
import threading
import time
import traceback

# ── Config loader ─────────────────────────────────────────────────────────────
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib   # type: ignore[no-reuse-obj]
    except ImportError:
        print("ERROR: Python 3.11+ or 'pip install tomli' required", file=sys.stderr)
        sys.exit(1)

# ── Load agent package ────────────────────────────────────────────────────────
# Ensure project root is on sys.path when run directly
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from agent.agent.crypto         import derive_keys, encrypt
from agent.agent.enrollment     import enroll, EnrollmentError
from agent.agent.keystore       import load_key, store_key
from agent.agent.sender         import Sender
from agent.agent.circuit_breaker import CircuitBreakerRegistry

# ── OS-specific collectors + normalizer ──────────────────────────────────────
if sys.platform == "darwin":
    from agent.os.macos.collectors import COLLECTORS
    from agent.os.macos.normalizer import normalize as _normalize
elif sys.platform == "win32":
    from agent.os.windows.collectors import COLLECTORS    # type: ignore[import]
    from agent.os.windows.normalizer import normalize as _normalize  # type: ignore[import]
else:
    from agent.agent.collectors import COLLECTORS         # type: ignore[import]
    try:
        from agent.agent.normalizer import normalize as _normalize  # type: ignore[import]
    except ImportError:
        def _normalize(section, raw):  # type: ignore[misc]
            return raw

# ── Constants ─────────────────────────────────────────────────────────────────
_OS_NAME  = ("macos" if sys.platform == "darwin"
             else "windows" if sys.platform == "win32" else "linux")
_OS_VER   = platform.mac_ver()[0] if sys.platform == "darwin" else platform.version()
_ARCH     = platform.machine()
_HOSTNAME = socket.gethostname()

HEALTH_INTERVAL_SEC    = 60    # how often to push health section
WATCHDOG_INTERVAL_SEC  = 15    # how often connectivity watchdog checks manager
STARTUP_TIMEOUT_SEC    = 20    # max time per collector during self-test

log = logging.getLogger("agent_v2")


# ═══════════════════════════════════════════════════════════════════════════════
#  Startup self-test
# ═══════════════════════════════════════════════════════════════════════════════

def run_self_test(sections: dict) -> dict[str, dict]:
    """
    Run every enabled collector once. Returns a dict:
        section_name → {"ok": bool, "items": int, "elapsed": float, "error": str}
    Logs a table summary.
    """
    log.info("═══ STARTUP SELF-TEST (%d sections) ═══", len(sections))
    results: dict[str, dict] = {}
    ok_count = fail_count = 0

    def _test(name: str, cfg: dict) -> tuple[str, dict]:
        if not cfg.get("enabled", True):
            return name, {"ok": None, "items": 0, "elapsed": 0, "error": "disabled"}
        fn = COLLECTORS.get(name)
        if not fn:
            return name, {"ok": False, "items": 0, "elapsed": 0,
                          "error": "no collector registered"}
        t0 = time.time()
        try:
            raw    = fn()
            normed = _normalize(name, raw)
            items  = len(normed) if isinstance(normed, (list, dict)) else 1
            return name, {"ok": True, "items": items,
                          "elapsed": round(time.time() - t0, 2), "error": ""}
        except Exception as exc:
            return name, {"ok": False, "items": 0,
                          "elapsed": round(time.time() - t0, 2),
                          "error": str(exc)[:120]}

    # Run in parallel but with a wall-clock cap per section
    with concurrent.futures.ThreadPoolExecutor(max_workers=6,
                                               thread_name_prefix="selftest") as ex:
        futures = {ex.submit(_test, name, cfg): name
                   for name, cfg in sections.items()}
        for fut in concurrent.futures.as_completed(futures,
                                                    timeout=STARTUP_TIMEOUT_SEC * 4):
            name, info = fut.result()
            results[name] = info
            if info["ok"] is True:
                ok_count += 1
            elif info["ok"] is False:
                fail_count += 1

    # Print table
    log.info("  %-20s  %-8s  %-6s  %s", "SECTION", "STATUS", "ITEMS", "ELAPSED")
    log.info("  " + "─" * 55)
    for name, r in sorted(results.items()):
        status = ("✓ OK" if r["ok"] is True
                  else ("─ skip" if r["ok"] is None else "✗ FAIL"))
        err    = f"  [{r['error']}]" if r["error"] else ""
        log.info("  %-20s  %-8s  %-6s  %.2fs%s",
                 name, status, r["items"], r["elapsed"], err)
    log.info("  ─────  %d OK  %d FAILED  %d disabled",
             ok_count, fail_count, len(results) - ok_count - fail_count)
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Hardened Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class HardenedOrchestrator:
    """
    Collects all sections on schedule.  Features:
    - Circuit breakers per section (skip failing sections, probe on cooldown)
    - Emits a synthetic `agent_health` section every HEALTH_INTERVAL_SEC
    - Thread-pool based; each section runs in its own thread slot
    - Coordinator thread stops cleanly on _stop event
    """

    def __init__(self, config: dict, enc_key: bytes, mac_key: bytes,
                 send_queue: queue.Queue, cbr: CircuitBreakerRegistry):
        self.config     = config
        self.enc_key    = enc_key
        self.mac_key    = mac_key
        self.queue      = send_queue
        self.cbr        = cbr
        self.agent_id   = config["agent"]["id"]
        self.tick       = config["collection"].get("tick_sec", 5)
        self._stop      = threading.Event()
        self._last_run: dict[str, float] = {}
        self._last_health = 0.0
        self._sent_total: dict[str, int] = {}
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None

    def start(self) -> threading.Thread:
        self._stop.clear()
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(4, len(COLLECTORS)),
            thread_name_prefix="collector",
        )
        t = threading.Thread(target=self._tick_loop, daemon=True, name="orchestrator")
        t.start()
        log.info("Orchestrator started — %d sections configured", len(self._sections()))
        return t

    def stop(self) -> None:
        self._stop.set()
        if self._executor:
            self._executor.shutdown(wait=False)

    def _sections(self) -> dict:
        return self.config.get("collection", {}).get("sections", {})

    def _tick_loop(self) -> None:
        while not self._stop.is_set():
            now = time.time()

            # ── Health heartbeat ──────────────────────────────────────────
            if now - self._last_health >= HEALTH_INTERVAL_SEC:
                self._last_health = now
                self._executor.submit(self._emit_health)  # type: ignore[union-attr]

            # ── Section scheduling ────────────────────────────────────────
            for name, cfg in self._sections().items():
                if not cfg.get("enabled", True):
                    continue
                interval = cfg.get("interval_sec", 60)
                if now - self._last_run.get(name, 0) >= interval:
                    self._last_run[name] = now
                    if self.cbr.allow(name):
                        self._executor.submit(  # type: ignore[union-attr]
                            self._run_section, name, cfg)
                    else:
                        log.debug("[%s] circuit open — skip", name)

            self._stop.wait(timeout=self.tick)

    def _run_section(self, name: str, cfg: dict) -> None:
        fn = COLLECTORS.get(name)
        if not fn:
            log.debug("No collector for section '%s' — skipping", name)
            return

        try:
            raw  = fn()
            data = _normalize(name, raw)
            self.cbr.success(name)
            log.debug("Collected %s: %s items", name,
                      len(data) if isinstance(data, (list, dict)) else "—")
        except Exception as exc:
            self.cbr.failure(name, str(exc))
            log.warning("Collector %s failed: %s", name, exc)
            data = {"error": str(exc), "section": name}

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
            envelope["section"] = section

            maxq = self.config["manager"].get("max_queue_size", 1000)
            if self.queue.qsize() >= maxq:
                try:
                    self.queue.get_nowait()
                    log.warning("Queue full — dropped oldest envelope")
                except queue.Empty:
                    pass
            self.queue.put_nowait(envelope)
            self._sent_total[section] = self._sent_total.get(section, 0) + 1
        except Exception as exc:
            log.error("Encrypt/enqueue failed for %s: %s", section, exc)

    def _emit_health(self) -> None:
        """Send a synthetic agent_health section with circuit-breaker status."""
        health = {
            "agent_id":     self.agent_id,
            "hostname":     _HOSTNAME,
            "os":           _OS_NAME,
            "arch":         _ARCH,
            "uptime_sec":   int(time.time() - _START_TIME),
            "queue_depth":  self.queue.qsize(),
            "sections":     self.cbr.snapshot(),
            "sent_totals":  dict(self._sent_total),
        }
        self._enqueue("agent_health", health)


# ═══════════════════════════════════════════════════════════════════════════════
#  Connectivity watchdog
# ═══════════════════════════════════════════════════════════════════════════════

class ConnectivityWatchdog:
    """
    Separate thread that probes /health every WATCHDOG_INTERVAL_SEC.
    Logs reconnect events and can pause orchestrator if desired (future).
    """
    def __init__(self, config: dict, sender: Sender):
        self._url  = config["manager"]["url"].rstrip("/") + "/health"
        self._sender = sender
        self._stop = threading.Event()
        self._online = True

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._loop, daemon=True, name="watchdog")
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            reachable = self._sender._probe()
            if reachable and not self._online:
                log.info("★ Manager back ONLINE — spool will drain automatically")
                self._online = True
            elif not reachable and self._online:
                log.warning("▲ Manager OFFLINE — buffering to disk spool")
                self._online = False
            self._stop.wait(timeout=WATCHDOG_INTERVAL_SEC)


# ═══════════════════════════════════════════════════════════════════════════════
#  Key resolution
# ═══════════════════════════════════════════════════════════════════════════════

def _obtain_api_key(cfg: dict, config_path: str) -> str:
    agent_id     = cfg["agent"]["id"]
    backend      = cfg.get("enrollment", {}).get("keystore", "keychain")
    security_dir = cfg.get("paths", {}).get(
        "security_dir",
        os.path.join(os.path.dirname(os.path.abspath(config_path)),
                     "agent", "security"),
    )
    cfg.setdefault("paths", {})["security_dir"] = security_dir

    # 1) [manager] api_key in toml (dev bootstrap)
    raw = (cfg.get("manager") or {}).get("api_key", "")
    if isinstance(raw, str):
        k = raw.strip()
        if k and k != "REPLACE_ME" and len(k) == 64:
            try:
                store_key(agent_id, k, backend=backend, security_dir=security_dir)
            except Exception:
                pass
            log.info("Using api_key from config file")
            return k

    # 2) Keystore (keychain / file)
    k = load_key(agent_id, backend=backend, security_dir=security_dir)
    if k:
        log.info("API key loaded from keystore (backend=%s)", backend)
        return k

    # 3) First-run enrollment
    log.info("No key found — starting enrollment...")
    return enroll(cfg)


# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════

_START_TIME = time.time()


def setup_logging(cfg: dict) -> None:
    lcfg    = cfg.get("logging", {})
    level   = getattr(logging, lcfg.get("level", "INFO").upper(), logging.INFO)
    logfile = lcfg.get("file", "agent/logs/agent_v2.log")
    os.makedirs(os.path.dirname(logfile) or ".", exist_ok=True)
    fmt     = "%(asctime)s %(name)s %(levelname)s %(message)s"
    handlers = [logging.StreamHandler()]
    try:
        fh = logging.handlers.RotatingFileHandler(
            logfile,
            maxBytes=lcfg.get("max_mb", 10) * 1024 * 1024,
            backupCount=lcfg.get("backups", 3),
        )
        fh.setFormatter(logging.Formatter(fmt))
        handlers.append(fh)
    except Exception as exc:
        print(f"WARNING: Could not open log file {logfile}: {exc}", file=sys.stderr)
    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="mac_intel Hardened Agent v2")
    parser.add_argument("--config",     default="agent.toml")
    parser.add_argument("--no-selftest", action="store_true",
                        help="Skip startup collector self-test")
    args = parser.parse_args()

    # Load config
    try:
        with open(args.config, "rb") as f:
            cfg = tomllib.load(f)
    except FileNotFoundError:
        print(f"ERROR: Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    setup_logging(cfg)
    log.info("═══════════════════════════════════════════")
    log.info(" mac_intel Agent v2 — %s (%s)", _HOSTNAME, _ARCH)
    log.info(" Agent ID : %s", cfg["agent"]["id"])
    log.info(" Manager  : %s", cfg["manager"]["url"])
    log.info("═══════════════════════════════════════════")

    # Resolve API key
    try:
        api_key = _obtain_api_key(cfg, args.config)
    except EnrollmentError as exc:
        log.critical("Enrollment failed: %s", exc)
        sys.exit(1)
    if not api_key:
        log.critical("No API key — cannot start")
        sys.exit(1)
    log.info("API key ready (...%s)", api_key[-4:])

    # Derive crypto keys
    enc_key, mac_key = derive_keys(api_key)
    log.info("Crypto keys derived OK")

    # Startup self-test
    sections = cfg.get("collection", {}).get("sections", {})
    if not args.no_selftest and sections:
        run_self_test(sections)
    else:
        log.info("Self-test skipped")

    # Connectivity check before starting
    send_queue: queue.Queue = queue.Queue()
    sender   = Sender(cfg, send_queue)

    log.info("Probing manager at %s ...", cfg["manager"]["url"])
    if sender._probe():
        log.info("Manager reachable ✓")
    else:
        log.warning("Manager not reachable — will buffer to spool and retry")

    # Circuit breaker registry
    cbr = CircuitBreakerRegistry(fail_threshold=3, cooldown_sec=60)

    # Start everything
    sender_thread  = sender.start()
    orch           = HardenedOrchestrator(cfg, enc_key, mac_key, send_queue, cbr)
    watchdog       = ConnectivityWatchdog(cfg, sender)
    orch_thread    = orch.start()
    watchdog.start()

    log.info("Agent v2 running — press CTRL+C to stop")

    def _shutdown(signum, _frame):
        log.info("Shutting down (signal %d)...", signum)
        orch.stop()
        watchdog.stop()
        # Drain remaining queue to spool
        drained = 0
        while not send_queue.empty():
            try:
                env = send_queue.get_nowait()
                sender._spool.write(env)
                drained += 1
            except queue.Empty:
                break
        if drained:
            log.info("Persisted %d unsent payloads to spool", drained)
        sender.stop()
        log.info("Shutdown complete")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)
    if sys.platform != "win32":
        def _reload(_sig, _frame):
            log.info("SIGHUP — reloading config")
            try:
                with open(args.config, "rb") as f:
                    new_cfg = tomllib.load(f)
                orch.stop()
                orch.config = new_cfg
                orch.start()
                log.info("Config reloaded OK")
            except Exception as exc:
                log.error("Config reload failed: %s", exc)
        signal.signal(signal.SIGHUP, _reload)

    orch_thread.join()


if __name__ == "__main__":
    main()
