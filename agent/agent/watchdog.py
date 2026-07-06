"""
agent/agent/watchdog.py — Standalone process watchdog binary.

Reads [watchdog], [binaries], and [paths] from agent.conf.
Starts the main agent binary and restarts it on crash.
Rate-limits restarts: if the agent crashes more than max_restarts times
in restart_window_sec, the watchdog backs off and logs a critical alert
instead of looping endlessly.

Managed by the com.attacklens.watchdog LaunchDaemon plist.
The LaunchDaemon launches *this process*, which in turn manages the agent:

  launchd
    └── attacklens-watchdog (KeepAlive=true — launchd restarts watchdog if it dies)
          └── attacklens-agent  (watchdog restarts agent if it crashes)

Usage
─────
  /Library/AttackLens/bin/attacklens-watchdog \\
      --config "/Library/AttackLens/agent.toml"
"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        print("ERROR: Python 3.11+ required, or: pip install tomli", file=sys.stderr)
        sys.exit(1)

log = logging.getLogger("watchdog")


class Watchdog:
    """
    Monitors and auto-restarts the agent binary.

    Rate-limiting: > max_restarts crashes within restart_window_sec → back-off.
    The back-off is intentional: a crash loop likely means a bug or config
    problem that requires operator attention, not an infinite restart spiral.
    """

    def __init__(self, cfg: dict) -> None:
        wdcfg  = cfg.get("watchdog", {})
        bins   = cfg.get("binaries", {})
        paths  = cfg.get("paths",    {})

        self.agent_bin       = bins.get("agent", "/Library/AttackLens/bin/attacklens-agent")
        # The agent target may be a native PyInstaller binary OR a .py entry
        # script (the current macOS deployment ships `run_agent.py`, which is not
        # executable). For a .py target we launch it via a Python interpreter
        # instead of exec'ing it directly — exec'ing a non-executable .py was the
        # historical bug that made the watchdog FATAL-loop and never start the
        # agent. The interpreter defaults to the one running the watchdog
        # (`sys.executable`, the framework python3.13 in deployment) and can be
        # overridden with [binaries] python = "...".
        self.python_bin      = bins.get("python") or sys.executable or "python3"
        self._use_interpreter = self.agent_bin.endswith(".py")
        # Whether to pass the 'run' subcommand. Default True (current CLI).
        # Toggled automatically if the agent exits 2 (argparse rejection) —
        # covers mismatched agent/watchdog builds without operator action.
        self._use_run_subcommand = True
        self._consecutive_exit2  = 0
        self.config_path     = cfg.get("_config_path", "")
        self.pid_file        = paths.get("pid_file", "/Library/AttackLens/attacklens-agent.pid")
        self.check_interval  = int(wdcfg.get("check_interval_sec", 30))
        self.max_restarts    = int(wdcfg.get("max_restarts", 5))
        self.restart_window  = int(wdcfg.get("restart_window_sec", 300))

        self._proc: subprocess.Popen | None = None
        self._restart_times: list[float]    = []
        self._stop = threading.Event()

    # ── Public ────────────────────────────────────────────────────────────────

    def run(self) -> None:
        log.info("Watchdog started. agent_bin=%s check_interval=%ds",
                 self.agent_bin, self.check_interval)
        self._verify_binary()
        self._start_agent()

        while not self._stop.is_set():
            self._stop.wait(timeout=self.check_interval)
            if self._stop.is_set():
                break
            self._check_and_maybe_restart()

        log.info("Watchdog main loop exited.")

    def stop(self) -> None:
        self._stop.set()
        proc = self._proc
        if proc and proc.poll() is None:
            log.info("Watchdog: sending SIGTERM to agent PID=%d", proc.pid)
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                log.warning("Agent did not exit cleanly — sending SIGKILL")
                proc.kill()
        self._clear_pid()

    # ── Binary verification ───────────────────────────────────────────────────

    def _interpreter_path(self) -> str | None:
        """Resolve the configured Python interpreter to a runnable path, or None."""
        p = self.python_bin
        if os.path.isabs(p):
            return p if (os.path.isfile(p) and os.access(p, os.X_OK)) else None
        return shutil.which(p)

    # Fallback agent targets tried (in order) when the configured path is
    # missing — covers stale configs pointing at removed .py entry scripts.
    _FALLBACK_AGENT_TARGETS = (
        "/Library/AttackLens/bin/attacklens-agent",
        "/Library/AttackLens/bin/run_agent.sh",
        "/Library/AttackLens/bin/run_agent.py",
    )

    def _resolve_fallback(self) -> str | None:
        """Find a launchable agent target when the configured one is missing."""
        for cand in self._FALLBACK_AGENT_TARGETS:
            if cand == self.agent_bin or not os.path.isfile(cand):
                continue
            if cand.endswith(".py"):
                if os.access(cand, os.R_OK) and self._interpreter_path():
                    return cand
            elif os.access(cand, os.X_OK):
                return cand
        return None

    def _verify_binary(self) -> bool:
        """Check the agent target exists and is launchable, and warn on tampering.

        Two launch modes:
          • native binary  → the target itself must be executable (X_OK)
          • .py entry script → the target must be readable AND a usable Python
            interpreter must exist (the script need not be executable)

        Self-healing: if the configured target is missing (stale agent.toml
        from an older install), fall back to known-good candidate paths
        instead of FATAL-looping until an operator edits the config.
        """
        if not os.path.isfile(self.agent_bin):
            fallback = self._resolve_fallback()
            if fallback:
                log.warning(
                    "Configured agent target %s not found — auto-switching to %s "
                    "(update [binaries] agent = ... in agent.toml to silence this).",
                    self.agent_bin, fallback,
                )
                self.agent_bin = fallback
                self._use_interpreter = fallback.endswith(".py")
            else:
                log.critical(
                    "FATAL: agent target not found at %s (no fallback candidate "
                    "exists either). Re-install or update [binaries] agent = ... "
                    "in agent.toml.",
                    self.agent_bin,
                )
                return False

        if self._use_interpreter:
            if not os.access(self.agent_bin, os.R_OK):
                log.critical("FATAL: agent script %s is not readable.", self.agent_bin)
                return False
            if not self._interpreter_path():
                log.critical(
                    "FATAL: Python interpreter %r not found for launching %s — "
                    "set [binaries] python = \"/path/to/python3\" in agent.toml.",
                    self.python_bin, self.agent_bin,
                )
                return False
        else:
            if not os.access(self.agent_bin, os.X_OK):
                log.critical(
                    "FATAL: agent binary %s is not executable. If this is a Python "
                    "entry script, give it a .py suffix so the watchdog launches it "
                    "via the interpreter.",
                    self.agent_bin,
                )
                return False

        # Warn if the launched file is world-writable (tampering risk)
        mode = os.stat(self.agent_bin).st_mode & 0o777
        if mode & 0o002:
            log.error(
                "SECURITY WARNING: agent target %s is world-writable (%o). "
                "This is a tampering risk. Fix: chmod 755 %s",
                self.agent_bin, mode, self.agent_bin,
            )
        return True

    # ── Process management ────────────────────────────────────────────────────

    def _build_cmd(self) -> list[str]:
        """Build the agent launch command (interpreter-prefixed for .py targets)."""
        if self._use_interpreter:
            cmd = [self._interpreter_path() or self.python_bin, self.agent_bin]
            if self._use_run_subcommand:
                cmd.append("run")
        else:
            # Native PyInstaller binary uses subcommand-based argparse;
            # 'run' is required — bare '--config' without a subcommand exits 2.
            cmd = [self.agent_bin]
            if self._use_run_subcommand:
                cmd.append("run")
        if self.config_path:
            cmd += ["--config", self.config_path]
        return cmd

    def _start_agent(self) -> None:
        if not self._verify_binary():
            return

        cmd = self._build_cmd()

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                # stdout/stderr inherit from this process → captured by launchd
            )
            self._write_pid(self._proc.pid)
            log.info("Agent started: PID=%d  cmd=%s", self._proc.pid, " ".join(cmd))
        except Exception as exc:
            log.error("Failed to start agent: %s", exc)
            self._proc = None

    def _check_and_maybe_restart(self) -> None:
        if self._proc is None:
            log.warning("Agent is not running — attempting start")
            self._rate_limited_restart()
            return

        rc = self._proc.poll()
        if rc is None:
            return   # still running — all good

        log.warning("Agent exited with code %d (PID=%d)", rc, self._proc.pid)

        # Exit 2 = argparse rejected the command line. If it happens twice in
        # a row, flip the 'run' subcommand form — the agent build we're
        # launching expects the other CLI shape. This self-heals mixed-version
        # installs (old binary + new watchdog, or vice versa).
        if rc == 2:
            self._consecutive_exit2 += 1
            if self._consecutive_exit2 >= 2:
                self._use_run_subcommand = not self._use_run_subcommand
                self._consecutive_exit2 = 0
                log.warning(
                    "Agent rejected its command line twice (exit 2) — "
                    "retrying with%s the 'run' subcommand.",
                    "" if self._use_run_subcommand else "out",
                )
        else:
            self._consecutive_exit2 = 0

        self._proc = None
        self._clear_pid()
        self._rate_limited_restart()

    def _rate_limited_restart(self) -> None:
        now = time.monotonic()
        # Remove timestamps that have aged out of the window
        self._restart_times = [
            t for t in self._restart_times if now - t < self.restart_window
        ]

        if len(self._restart_times) >= self.max_restarts:
            log.critical(
                "Agent crashed %d times in %ds (limit=%d). "
                "Watchdog is backing off — manual intervention required. "
                "Check logs at agent.log for root cause.",
                len(self._restart_times), self.restart_window, self.max_restarts,
            )
            return

        self._restart_times.append(now)
        log.info("Restarting agent (crash #%d / %d allowed in %ds window)",
                 len(self._restart_times), self.max_restarts, self.restart_window)
        self._start_agent()

    # ── PID file ──────────────────────────────────────────────────────────────

    def _write_pid(self, pid: int) -> None:
        try:
            pid_dir = os.path.dirname(self.pid_file)
            if pid_dir:
                os.makedirs(pid_dir, exist_ok=True)
            with open(self.pid_file, "w") as f:
                f.write(str(pid))
        except Exception as exc:
            log.warning("Could not write PID file %s: %s", self.pid_file, exc)

    def _clear_pid(self) -> None:
        try:
            if os.path.exists(self.pid_file):
                os.unlink(self.pid_file)
        except Exception:
            pass


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(cfg: dict) -> None:
    lcfg    = cfg.get("logging", {})
    level   = getattr(logging, lcfg.get("level", "INFO").upper(), logging.INFO)
    log_dir = cfg.get("paths", {}).get("log_dir", "/Library/AttackLens/logs")
    logfile = os.path.join(log_dir, "watchdog.log")
    os.makedirs(log_dir, exist_ok=True)
    fmt     = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")

    fh = logging.handlers.RotatingFileHandler(
        logfile,
        maxBytes=lcfg.get("max_mb", 10) * 1024 * 1024,
        backupCount=lcfg.get("backups", 3),
    )
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(fh)
    root.addHandler(sh)


# ── Service-control subcommands ───────────────────────────────────────────────
#
# The LaunchDaemon plist invokes this binary with just --config (foreground
# run).  When a human runs `attacklens-watchdog status|start|stop|restart|logs`
# from a terminal, delegate to launchctl instead of erroring out.

WATCHDOG_LABEL = "com.attacklens.watchdog"
WATCHDOG_PLIST = "/Library/LaunchDaemons/com.attacklens.watchdog.plist"
WATCHDOG_LOG   = "/Library/AttackLens/logs/watchdog.log"


def _launchctl(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["launchctl", *argv], capture_output=True, text=True, timeout=30
    )


def _require_root(cmd: str) -> None:
    if os.geteuid() != 0:
        print(f"ERROR: '{cmd}' requires root. Re-run with: sudo attacklens-watchdog {cmd}",
              file=sys.stderr)
        sys.exit(1)


def _service_command(cmd: str, log_lines: int) -> None:
    if cmd == "status":
        out = _launchctl("print", f"system/{WATCHDOG_LABEL}")
        if out.returncode != 0:
            print(f"○ {WATCHDOG_LABEL} is NOT loaded")
            print(f"  start it with: sudo attacklens-watchdog start")
            sys.exit(3)
        pid = ""
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("pid ="):
                pid = line.split("=", 1)[1].strip()
        if pid:
            print(f"● {WATCHDOG_LABEL} running  PID {pid}")
        else:
            print(f"◐ {WATCHDOG_LABEL} loaded but not running (launchd will restart it)")
        sys.exit(0)

    if cmd == "start":
        _require_root(cmd)
        if not os.path.exists(WATCHDOG_PLIST):
            print(f"ERROR: {WATCHDOG_PLIST} not found — reinstall the agent PKG.",
                  file=sys.stderr)
            sys.exit(1)
        # Already loaded? bootstrap would fail with error 5 — kickstart instead.
        if _launchctl("print", f"system/{WATCHDOG_LABEL}").returncode == 0:
            _launchctl("kickstart", "-k", f"system/{WATCHDOG_LABEL}")
            print(f"● {WATCHDOG_LABEL} restarted (was already loaded)")
        else:
            _launchctl("enable", f"system/{WATCHDOG_LABEL}")
            res = _launchctl("bootstrap", "system", WATCHDOG_PLIST)
            if res.returncode != 0:
                print(f"ERROR: bootstrap failed: {res.stderr.strip()}", file=sys.stderr)
                sys.exit(1)
            print(f"● {WATCHDOG_LABEL} started")
        sys.exit(0)

    if cmd == "stop":
        _require_root(cmd)
        _launchctl("bootout", f"system/{WATCHDOG_LABEL}")
        print(f"○ {WATCHDOG_LABEL} stopped")
        sys.exit(0)

    if cmd == "restart":
        _require_root(cmd)
        if _launchctl("print", f"system/{WATCHDOG_LABEL}").returncode == 0:
            _launchctl("kickstart", "-k", f"system/{WATCHDOG_LABEL}")
        else:
            _launchctl("enable", f"system/{WATCHDOG_LABEL}")
            _launchctl("bootstrap", "system", WATCHDOG_PLIST)
        print(f"● {WATCHDOG_LABEL} restarted")
        sys.exit(0)

    if cmd == "logs":
        if not os.path.exists(WATCHDOG_LOG):
            print(f"No log file yet at {WATCHDOG_LOG}")
            sys.exit(0)
        subprocess.run(["tail", "-n", str(log_lines), WATCHDOG_LOG])
        sys.exit(0)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="mac_intel process watchdog",
        epilog="With no COMMAND, runs the watchdog loop in the foreground "
               "(this is how the LaunchDaemon invokes it).",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["run", "status", "start", "stop", "restart", "logs"],
        default="run",
        help="service control command (default: run in foreground)",
    )
    parser.add_argument(
        "--config",
        default="/Library/AttackLens/agent.toml",
        help="Path to agent.toml",
    )
    parser.add_argument(
        "--lines", type=int, default=50,
        help="number of log lines for 'logs' (default 50)",
    )
    args = parser.parse_args()

    if args.command != "run":
        _service_command(args.command, args.lines)
        return

    try:
        with open(args.config, "rb") as f:
            cfg = tomllib.load(f)
    except FileNotFoundError:
        print(f"ERROR: Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Failed to parse config: {exc}", file=sys.stderr)
        sys.exit(1)

    cfg["_config_path"] = args.config
    setup_logging(cfg)
    log.info("mac_intel watchdog initialising. config=%s", args.config)

    watchdog = Watchdog(cfg)

    def _shutdown(signum, frame):
        log.info("Received signal %d — initiating graceful shutdown", signum)
        watchdog.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    watchdog.run()


if __name__ == "__main__":
    main()
