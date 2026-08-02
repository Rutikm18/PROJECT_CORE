"""
agent/selfinstall.py — Cross-platform self-install / service management.

Pure Python. No shell scripts required.

Platforms
─────────
  macOS   — LaunchDaemon via launchctl
  Linux   — systemd via systemctl
  Windows — Windows Service via sc.exe

Public API
──────────
    install(manager_url, install_dir, agent_name, agent_id, enroll_token)
    uninstall(install_dir)
    start(install_dir)
    stop(install_dir)
    status(install_dir)  → (running: bool, detail: str)
    reload(install_dir)
    show_logs(install_dir, lines)
    write_config(config_path, install_dir, manager_url, agent_id, agent_name, ...)
"""

from __future__ import annotations

import os
import platform
import signal
import socket
import stat
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

# ── Platform ───────────────────────────────────────────────────────────────────

def _sys() -> str:
    return platform.system()   # "Darwin" | "Linux" | "Windows"


def default_install_dir() -> Path:
    p = _sys()
    if p == "Darwin":  return Path("/Library/AttackLens")
    if p == "Windows": return Path(r"C:\Program Files (x86)\AttackLens")
    return Path("/opt/attacklens")


# ── Path helpers ───────────────────────────────────────────────────────────────

def _bin_dir(d: Path)       -> Path: return d / "bin"
def _log_dir(d: Path)       -> Path: return d / "logs"
def _security_dir(d: Path)  -> Path: return d / "security"
def _spool_dir(d: Path)     -> Path: return d / "spool"
def _data_dir(d: Path)      -> Path: return d / "data"
def _config_path(d: Path)   -> Path: return d / "agent.toml"
def _pid_path(d: Path)      -> Path: return d / "attacklens-agent.pid"
def _log_path(d: Path)      -> Path: return _log_dir(d) / "agent.log"


def _installed_binary(d: Path) -> Path:
    if _sys() == "Windows":
        return _bin_dir(d) / "attacklens-agent.exe"
    return _bin_dir(d) / "attacklens-agent"


# macOS / Linux service identifiers
_MACOS_AGENT_LABEL  = "com.attacklens.agent"
_MACOS_WD_LABEL     = "com.attacklens.watchdog"
_LAUNCHDAEMON_DIR   = Path("/Library/LaunchDaemons")
_SYSTEMD_DIR        = Path("/etc/systemd/system")
_LINUX_UNIT         = "attacklens-agent.service"
_WINDOWS_SVC_NAME   = "AttackLensAgent"
_WINDOWS_SVC_DISP   = "AttackLens Agent"


# ── Machine identity ───────────────────────────────────────────────────────────

def derive_agent_id() -> str:
    p = _sys()
    if p == "Darwin":
        try:
            out = subprocess.check_output(
                ["system_profiler", "SPHardwareDataType"],
                text=True, stderr=subprocess.DEVNULL, timeout=10,
            )
            for line in out.splitlines():
                if "Hardware UUID" in line:
                    hw = line.split(":")[-1].strip().lower()
                    if hw:
                        return f"mac-{hw}"
        except Exception:
            pass
        return f"mac-{socket.gethostname().lower()}"

    if p == "Windows":
        try:
            out = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"],
                text=True, stderr=subprocess.DEVNULL, timeout=10,
            )
            lines = [l.strip() for l in out.splitlines()
                     if l.strip() and l.strip().upper() != "UUID"]
            if lines:
                return f"win-{lines[0].lower()}"
        except Exception:
            pass
        return f"win-{socket.gethostname().lower()}"

    # Linux
    try:
        mid = Path("/etc/machine-id").read_text().strip()
        if mid:
            return f"linux-{mid}"
    except Exception:
        pass
    return f"linux-{socket.gethostname().lower()}"


def derive_agent_name() -> str:
    if _sys() == "Darwin":
        try:
            name = subprocess.check_output(
                ["scutil", "--get", "ComputerName"],
                text=True, stderr=subprocess.DEVNULL, timeout=5,
            ).strip()
            if name:
                return name
        except Exception:
            pass
    return socket.gethostname()


# ── Config generation ──────────────────────────────────────────────────────────

def write_config(
    config_path: Path,
    install_dir: Path,
    manager_url: str,
    agent_id: str,
    agent_name: str,
    enroll_token: str = "",
    tls_verify: bool | None = None,
) -> None:
    if tls_verify is None:
        tls_verify = not manager_url.startswith("http://")

    log_dir      = _log_dir(install_dir)
    security_dir = _security_dir(install_dir)
    spool_dir    = _spool_dir(install_dir)
    data_dir     = _data_dir(install_dir)
    pid_file     = _pid_path(install_dir)
    log_file     = log_dir / "agent.log"
    tls_str      = "true" if tls_verify else "false"
    ts           = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if enroll_token:
        enroll_block = f'\n[enrollment]\ntoken    = "{enroll_token}"\nkeystore = "keychain"\n'
    else:
        enroll_block = "\n[enrollment]\nkeystore = \"keychain\"\n"

    # Use forward slashes even on Windows for TOML readability
    def p(x: Path) -> str:
        return str(x).replace("\\", "/")

    content = textwrap.dedent(f"""\
        # AttackLens Agent Configuration — {ts}
        # Manage: attacklens-agent status | start | stop | uninstall

        [agent]
        id          = "{agent_id}"
        name        = "{agent_name}"

        [manager]
        url             = "{manager_url}"
        tls_verify      = {tls_str}
        timeout_sec     = 30
        retry_attempts  = 3
        retry_delay_sec = 5
        max_queue_size  = 1000
        {enroll_block}
        [watchdog]
        enabled            = true
        check_interval_sec = 30
        max_restarts       = 5
        restart_window_sec = 300

        [paths]
        install_dir  = "{p(install_dir)}"
        config_dir   = "{p(install_dir)}"
        log_dir      = "{p(log_dir)}"
        data_dir     = "{p(data_dir)}"
        security_dir = "{p(security_dir)}"
        spool_dir    = "{p(spool_dir)}"
        pid_file     = "{p(pid_file)}"

        [logging]
        level   = "INFO"
        file    = "{p(log_file)}"
        max_mb  = 10
        backups = 5

        [collection]
        enabled  = true
        tick_sec = 5

        [collection.sections.metrics]
        enabled      = true
        interval_sec = 10
        send         = true

        [collection.sections.connections]
        enabled      = true
        interval_sec = 10
        send         = true

        [collection.sections.processes]
        enabled      = true
        interval_sec = 10
        send         = true

        [collection.sections.ports]
        enabled      = true
        interval_sec = 30
        send         = true

        [collection.sections.network]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.arp]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.mounts]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.battery]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.openfiles]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.services]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.users]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.hardware]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.containers]
        enabled      = true
        interval_sec = 120
        send         = true

        [collection.sections.storage]
        enabled      = true
        interval_sec = 600
        send         = true

        [collection.sections.tasks]
        enabled      = true
        interval_sec = 600
        send         = true

        [collection.sections.security]
        enabled      = true
        interval_sec = 3600
        send         = true

        [collection.sections.sysctl]
        enabled      = true
        interval_sec = 3600
        send         = true

        [collection.sections.configs]
        enabled      = true
        interval_sec = 3600
        send         = true

        [collection.sections.developer_security]
        enabled      = true
        interval_sec = 3600
        send         = true
        timeout_sec  = 120

        [collection.sections.sca]
        enabled      = true
        interval_sec = 43200
        send         = true
        timeout_sec  = 60

        [collection.sections.apps]
        enabled      = true
        interval_sec = 86400
        send         = true

        [collection.sections.packages]
        enabled      = true
        interval_sec = 86400
        send         = true

        [collection.sections.binaries]
        enabled      = true
        interval_sec = 86400
        send         = true

        [collection.sections.sbom]
        enabled      = true
        interval_sec = 86400
        send         = true
    """)

    config_path.write_text(content, encoding="utf-8")
    if _sys() != "Windows":
        config_path.chmod(0o640)
    print(f"  Config  → {config_path}")


# ── Directory setup ────────────────────────────────────────────────────────────

def _make_dirs(install_dir: Path) -> None:
    for d in [
        _bin_dir(install_dir),
        _log_dir(install_dir),
        _security_dir(install_dir),
        _spool_dir(install_dir),
        _data_dir(install_dir),
    ]:
        d.mkdir(parents=True, exist_ok=True)

    if _sys() != "Windows":
        _security_dir(install_dir).chmod(0o700)
        for d in [_log_dir(install_dir), _spool_dir(install_dir), _data_dir(install_dir)]:
            d.chmod(0o750)


# ── Binary placement ───────────────────────────────────────────────────────────

def _place_binary(install_dir: Path) -> Path:
    """Copy this executable to install_dir/bin/ and symlink to /usr/local/bin."""
    src = Path(sys.executable)
    dst = _installed_binary(install_dir)
    import shutil
    shutil.copy2(src, dst)
    if _sys() != "Windows":
        dst.chmod(0o755)

    # Symlink into PATH
    if _sys() in ("Darwin", "Linux"):
        link = Path("/usr/local/bin/attacklens-agent")
        link.unlink(missing_ok=True)
        link.symlink_to(dst)
        print(f"  Binary  → {dst}")
        print(f"  Symlink → {link}")
    else:
        print(f"  Binary  → {dst}")

    return dst


# ── macOS LaunchDaemon ─────────────────────────────────────────────────────────

def _macos_agent_plist(install_dir: Path, binary: Path, config: Path) -> str:
    log_dir = _log_dir(install_dir)
    return textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key><string>{_MACOS_AGENT_LABEL}</string>
            <key>ProgramArguments</key>
            <array>
                <string>{binary}</string>
                <string>run</string>
                <string>--config</string>
                <string>{config}</string>
            </array>
            <key>EnvironmentVariables</key>
            <dict>
                <key>PYTHONUNBUFFERED</key><string>1</string>
            </dict>
            <key>WorkingDirectory</key><string>{install_dir}</string>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>UserName</key><string>root</string>
            <key>StandardOutPath</key><string>{log_dir}/agent-stdout.log</string>
            <key>StandardErrorPath</key><string>{log_dir}/agent-stderr.log</string>
            <key>ThrottleInterval</key><integer>10</integer>
            <key>ProcessType</key><string>Background</string>
            <key>LowPriorityIO</key><true/>
        </dict>
        </plist>
    """)


def _macos_load(label: str, plist: Path) -> None:
    subprocess.run(["launchctl", "enable", f"system/{label}"],
                   check=False, capture_output=True)
    ret = subprocess.run(
        ["launchctl", "bootstrap", "system", str(plist)],
        capture_output=True,
    )
    if ret.returncode != 0:
        subprocess.run(["launchctl", "load", "-w", str(plist)],
                       check=False, capture_output=True)


def _macos_unload(label: str, plist: Path) -> None:
    subprocess.run(["launchctl", "bootout", f"system/{label}"],
                   check=False, capture_output=True)
    subprocess.run(["launchctl", "unload", "-w", str(plist)],
                   check=False, capture_output=True)


def _register_macos(install_dir: Path, binary: Path) -> None:
    config = _config_path(install_dir)
    plist  = _LAUNCHDAEMON_DIR / f"{_MACOS_AGENT_LABEL}.plist"

    # Stop existing instance
    _macos_unload(_MACOS_AGENT_LABEL, plist)

    plist.write_text(_macos_agent_plist(install_dir, binary, config), encoding="utf-8")
    plist.chmod(0o644)
    print(f"  Plist   → {plist}")

    _macos_load(_MACOS_AGENT_LABEL, plist)
    print(f"  Service → {_MACOS_AGENT_LABEL} loaded")


# ── Linux systemd ──────────────────────────────────────────────────────────────

def _linux_unit(install_dir: Path, binary: Path, config: Path) -> str:
    return textwrap.dedent(f"""\
        [Unit]
        Description=AttackLens Agent
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        ExecStart={binary} run --config {config}
        Restart=always
        RestartSec=10
        WorkingDirectory={install_dir}
        Environment=PYTHONUNBUFFERED=1
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
    """)


def _register_linux(install_dir: Path, binary: Path) -> None:
    config = _config_path(install_dir)
    unit   = _SYSTEMD_DIR / _LINUX_UNIT

    subprocess.run(["systemctl", "stop", _LINUX_UNIT],
                   check=False, capture_output=True)

    unit.write_text(_linux_unit(install_dir, binary, config), encoding="utf-8")
    unit.chmod(0o644)
    print(f"  Unit    → {unit}")

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", _LINUX_UNIT], check=True)
    subprocess.run(["systemctl", "start",  _LINUX_UNIT], check=True)
    print(f"  Service → {_LINUX_UNIT} started")


# ── Windows Service ────────────────────────────────────────────────────────────

def _register_windows(install_dir: Path, binary: Path) -> None:
    config = _config_path(install_dir)

    # Remove existing service if present
    subprocess.run(["sc", "stop",   _WINDOWS_SVC_NAME], check=False, capture_output=True)
    subprocess.run(["sc", "delete", _WINDOWS_SVC_NAME], check=False, capture_output=True)
    import time; time.sleep(2)

    cmd = [
        "sc", "create", _WINDOWS_SVC_NAME,
        f"binPath= {binary} run --config {config}",
        "start= auto",
        f"DisplayName= {_WINDOWS_SVC_DISP}",
    ]
    subprocess.run(cmd, check=True)
    subprocess.run(["sc", "description", _WINDOWS_SVC_NAME,
                    "AttackLens endpoint telemetry agent"], check=True)
    subprocess.run(["sc", "start", _WINDOWS_SVC_NAME], check=True)
    print(f"  Service → {_WINDOWS_SVC_NAME} registered and started")


# ── Public: install ────────────────────────────────────────────────────────────

def install(
    manager_url:   str,
    install_dir:   Path | None = None,
    agent_name:    str | None  = None,
    agent_id:      str | None  = None,
    enroll_token:  str         = "",
) -> None:
    install_dir  = Path(install_dir) if install_dir else default_install_dir()
    agent_id     = agent_id   or derive_agent_id()
    agent_name   = agent_name or derive_agent_name()

    if _sys() != "Windows" and os.geteuid() != 0:
        print("ERROR: install requires root (sudo attacklens-agent install ...)",
              file=sys.stderr)
        sys.exit(1)

    print(f"\n  AttackLens Agent — Install")
    print(f"  Manager : {manager_url}")
    print(f"  Agent   : {agent_name}  ({agent_id})")
    print(f"  Dir     : {install_dir}")
    print()

    _make_dirs(install_dir)
    binary = _place_binary(install_dir)
    write_config(_config_path(install_dir), install_dir, manager_url,
                 agent_id, agent_name, enroll_token)

    p = _sys()
    if p == "Darwin":
        _register_macos(install_dir, binary)
    elif p == "Linux":
        _register_linux(install_dir, binary)
    elif p == "Windows":
        _register_windows(install_dir, binary)
    else:
        print(f"WARNING: unsupported platform '{p}' — config written but service not registered")

    print(f"\n  Install complete.")
    print(f"  attacklens-agent status   — check service state")
    print(f"  attacklens-agent logs     — tail agent log\n")


# ── Public: uninstall ──────────────────────────────────────────────────────────

def uninstall(install_dir: Path | None = None) -> None:
    install_dir = Path(install_dir) if install_dir else default_install_dir()

    if _sys() != "Windows" and os.geteuid() != 0:
        print("ERROR: uninstall requires root", file=sys.stderr)
        sys.exit(1)

    p = _sys()
    if p == "Darwin":
        for label, fname in [
            (_MACOS_AGENT_LABEL, f"{_MACOS_AGENT_LABEL}.plist"),
            (_MACOS_WD_LABEL,    f"{_MACOS_WD_LABEL}.plist"),
        ]:
            plist = _LAUNCHDAEMON_DIR / fname
            _macos_unload(label, plist)
            plist.unlink(missing_ok=True)
        link = Path("/usr/local/bin/attacklens-agent")
        link.unlink(missing_ok=True)

    elif p == "Linux":
        subprocess.run(["systemctl", "stop",    _LINUX_UNIT], check=False, capture_output=True)
        subprocess.run(["systemctl", "disable", _LINUX_UNIT], check=False, capture_output=True)
        (_SYSTEMD_DIR / _LINUX_UNIT).unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)
        Path("/usr/local/bin/attacklens-agent").unlink(missing_ok=True)

    elif p == "Windows":
        subprocess.run(["sc", "stop",   _WINDOWS_SVC_NAME], check=False, capture_output=True)
        subprocess.run(["sc", "delete", _WINDOWS_SVC_NAME], check=False, capture_output=True)

    import shutil
    if install_dir.exists():
        shutil.rmtree(install_dir)
        print(f"  Removed {install_dir}")

    print("  Uninstall complete.")


# ── Public: start / stop / reload / status ────────────────────────────────────

def start(install_dir: Path | None = None) -> None:
    install_dir = Path(install_dir) if install_dir else default_install_dir()
    p = _sys()
    if p == "Darwin":
        plist = _LAUNCHDAEMON_DIR / f"{_MACOS_AGENT_LABEL}.plist"
        _macos_load(_MACOS_AGENT_LABEL, plist)
    elif p == "Linux":
        subprocess.run(["systemctl", "start", _LINUX_UNIT], check=True)
    elif p == "Windows":
        subprocess.run(["sc", "start", _WINDOWS_SVC_NAME], check=True)


def stop(install_dir: Path | None = None) -> None:
    install_dir = Path(install_dir) if install_dir else default_install_dir()
    p = _sys()
    if p == "Darwin":
        plist = _LAUNCHDAEMON_DIR / f"{_MACOS_AGENT_LABEL}.plist"
        _macos_unload(_MACOS_AGENT_LABEL, plist)
    elif p == "Linux":
        subprocess.run(["systemctl", "stop", _LINUX_UNIT], check=True)
    elif p == "Windows":
        subprocess.run(["sc", "stop", _WINDOWS_SVC_NAME], check=True)


def reload(install_dir: Path | None = None) -> None:
    install_dir = Path(install_dir) if install_dir else default_install_dir()
    pid_file = _pid_path(install_dir)

    p = _sys()
    if p in ("Darwin", "Linux"):
        # Try PID file first, fall back to pkill
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, signal.SIGHUP)
            print(f"  SIGHUP sent to PID {pid}")
            return
        except Exception:
            pass
        ret = subprocess.run(
            ["pkill", "-HUP", "-f", "attacklens-agent run"],
            capture_output=True,
        )
        if ret.returncode == 0:
            print("  SIGHUP sent (config reloaded)")
        else:
            print("  Agent process not found — is it running?")
    elif p == "Windows":
        subprocess.run(["sc", "stop",  _WINDOWS_SVC_NAME], check=False)
        import time; time.sleep(2)
        subprocess.run(["sc", "start", _WINDOWS_SVC_NAME], check=False)
        print("  Service restarted (Windows)")


def status(install_dir: Path | None = None) -> Tuple[bool, str]:
    install_dir = Path(install_dir) if install_dir else default_install_dir()
    p = _sys()

    if p == "Darwin":
        out = subprocess.run(
            ["launchctl", "list", _MACOS_AGENT_LABEL],
            capture_output=True, text=True,
        )
        running = '"PID"' in out.stdout
        pid_part = ""
        for line in out.stdout.splitlines():
            if '"PID"' in line:
                import re
                m = re.search(r'"PID"\s*=\s*(\d+)', line)
                if m:
                    pid_part = f"  PID {m.group(1)}"
        detail = f"running{pid_part}" if running else "stopped"
        return running, detail

    elif p == "Linux":
        out = subprocess.run(
            ["systemctl", "is-active", _LINUX_UNIT],
            capture_output=True, text=True,
        )
        running = out.stdout.strip() == "active"
        detail  = out.stdout.strip()
        return running, detail

    elif p == "Windows":
        out = subprocess.run(
            ["sc", "query", _WINDOWS_SVC_NAME],
            capture_output=True, text=True,
        )
        running = "RUNNING" in out.stdout
        detail  = "running" if running else "stopped"
        return running, detail

    return False, "unknown platform"


def show_logs(install_dir: Path | None = None, lines: int = 50) -> None:
    install_dir = Path(install_dir) if install_dir else default_install_dir()
    log_file = _log_path(install_dir)
    if not log_file.exists():
        print(f"Log file not found: {log_file}")
        return
    try:
        with open(log_file, encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        for l in all_lines[-lines:]:
            print(l, end="")
    except Exception as exc:
        print(f"Error reading log: {exc}", file=sys.stderr)
