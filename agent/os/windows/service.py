"""
agent/os/windows/service.py — Windows Service wrapper for mac_intel agent.

The agent binary is built as a console application by PyInstaller. This module
wraps the agent core inside a Windows Service so it starts at boot, runs as
NETWORK SERVICE (or a dedicated service account), and integrates with the
Windows Service Control Manager (SCM).

Architecture
────────────
  SCM
   └─ MacIntelAgent service  (this module)
       └─ agent.agent.core   (runs in a daemon thread)

Service lifecycle
─────────────────
  install   → sc create / win32serviceutil.InstallService
  start     → SvcDoRun → _run_agent_thread
  stop      → SvcStop → sets _stop_event → thread exits → service stops
  remove    → sc delete / win32serviceutil.RemoveService

CLI (when run as a PyInstaller binary)
──────────────────────────────────────
  macintel-agent.exe install   — register service
  macintel-agent.exe start     — start service
  macintel-agent.exe stop      — stop service
  macintel-agent.exe remove    — unregister service
  macintel-agent.exe debug     — run in foreground (no service; useful for testing)
  macintel-agent.exe           — (no args) hand control to SCM (used when SCM starts it)

Dependencies (Windows only)
───────────────────────────
  pip install pywin32
  python Scripts/pywin32_postinstall.py -install  (only needed once after pip install)

Default config path: C:\\ProgramData\\MacIntel\\agent.toml
Override:            set MACINTEL_CONFIG env var before starting the service.
"""
from __future__ import annotations

import logging
import os
import queue
import sys
import threading

log = logging.getLogger("agent.windows.service")

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = r"C:\ProgramData\MacIntel\agent.toml"


# ── pywin32 availability guard ────────────────────────────────────────────────
try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False


# ── Service class ─────────────────────────────────────────────────────────────

if _HAS_WIN32:
    class MacIntelAgentService(win32serviceutil.ServiceFramework):
        _svc_name_         = "MacIntelAgent"
        _svc_display_name_ = "mac_intel Agent"
        _svc_description_  = (
            "Endpoint telemetry agent — collects system metrics, security posture, "
            "and software inventory. Sends encrypted data to the mac_intel manager."
        )
        # Ensure network stack is ready before agent tries to enroll/send
        _svc_deps_         = ["Tcpip", "Dnscache"]
        # Service account: LocalSystem gives full access; NetworkService is
        # more restrictive (recommended for production).
        # Set via sc config MacIntelAgent obj= "NT AUTHORITY\NetworkService" password= ""
        _exe_name_         = sys.executable   # PyInstaller sets this to the .exe path

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event    = win32event.CreateEvent(None, 0, 0, None)
            self._agent_thread: threading.Thread | None = None
            self._orch          = None
            self._sender        = None

        # ── SCM callbacks ─────────────────────────────────────────────────────

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            log.info("Service stop requested")
            win32event.SetEvent(self._stop_event)
            if self._orch:
                try:
                    self._orch.stop()
                except Exception:
                    pass
            if self._sender:
                try:
                    self._sender.stop()
                except Exception:
                    pass

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self._run_agent()
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, ""),
            )

        # ── Agent bootstrap ───────────────────────────────────────────────────

        def _run_agent(self):
            config_path = os.environ.get("MACINTEL_CONFIG", DEFAULT_CONFIG)
            if not os.path.isfile(config_path):
                msg = f"Config not found: {config_path}"
                servicemanager.LogErrorMsg(msg)
                log.critical(msg)
                return

            # Ensure project root is importable (PyInstaller already handles this,
            # but also works when running from source)
            _add_root_to_path()

            try:
                from agent.agent.core import load_config, setup_logging, _obtain_api_key
                from agent.agent.core import Orchestrator
                from agent.agent.crypto import derive_keys
                from agent.agent.enrollment import EnrollmentError
                from agent.agent.sender import Sender

                cfg = load_config(config_path)
                setup_logging(cfg)

                try:
                    api_key = _obtain_api_key(cfg, config_path)
                except EnrollmentError as exc:
                    servicemanager.LogErrorMsg(f"Enrollment failed: {exc}")
                    log.critical("Enrollment failed: %s", exc)
                    return

                enc_key, mac_key = derive_keys(api_key)
                send_q           = queue.Queue()

                self._sender = Sender(cfg, send_q)
                self._orch   = Orchestrator(cfg, enc_key, mac_key, send_q)

                self._sender.start()
                self._orch.start()

                log.info("mac_intel Agent service running (agent_id=%s)",
                         cfg["agent"]["id"])

                # Block until SvcStop signals
                win32event.WaitForSingleObject(self._stop_event,
                                               win32event.INFINITE)
                log.info("mac_intel Agent service stopping")

            except Exception as exc:
                servicemanager.LogErrorMsg(f"Agent service fatal error: {exc}")
                log.exception("Agent service fatal error")


# ── Foreground debug mode (no SCM) ───────────────────────────────────────────

def _run_debug() -> None:
    """Run agent in foreground — useful for testing the service logic without SCM."""
    import signal
    config_path = os.environ.get("MACINTEL_CONFIG", DEFAULT_CONFIG)
    if not os.path.isfile(config_path):
        print(f"ERROR: config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    _add_root_to_path()
    from agent.agent.core import main as agent_main
    # Patch sys.argv to point at the config
    sys.argv = ["agent", "--config", config_path]
    agent_main()


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main() -> None:
    if not _HAS_WIN32:
        print(
            "ERROR: pywin32 is required for Windows service mode.\n"
            "  pip install pywin32\n"
            "  python Scripts/pywin32_postinstall.py -install",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(sys.argv) == 1:
        # No arguments → SCM is starting us as a service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(MacIntelAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    elif len(sys.argv) >= 2 and sys.argv[1].lower() == "debug":
        _run_debug()
    else:
        win32serviceutil.HandleCommandLine(MacIntelAgentService)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _add_root_to_path() -> None:
    """Ensure project root (grandparent of this file's package) is on sys.path."""
    root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    if root not in sys.path:
        sys.path.insert(0, root)


if __name__ == "__main__":
    main()
