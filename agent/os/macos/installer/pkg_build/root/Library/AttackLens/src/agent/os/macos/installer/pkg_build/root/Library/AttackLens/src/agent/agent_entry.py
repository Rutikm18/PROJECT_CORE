"""
agent/agent_entry.py — Unified CLI entry point for attacklens-agent binary.

Subcommands
───────────
  install   --manager URL [--name NAME] [--id ID] [--token TOKEN] [--dir DIR]
  run       [--config PATH]          ← called by service daemons
  start                              ← start registered service
  stop                               ← stop running service
  status                             ← check service state
  reload                             ← live config reload (SIGHUP on Unix)
  uninstall [--dir DIR]              ← stop + remove all files
  logs      [--lines N] [--dir DIR]  ← tail agent log

PyInstaller runs this as __main__ — absolute imports throughout so the
bundler can resolve the full package tree.
"""

from __future__ import annotations

import argparse
import sys


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attacklens-agent",
        description="AttackLens endpoint agent — install, run, and manage.",
    )
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    # install
    inst = sub.add_parser("install", help="install and register as a system service")
    inst.add_argument("--manager", required=True,
                      help="manager URL, e.g. http://1.2.3.4:8080")
    inst.add_argument("--name",  default=None, help="agent display name")
    inst.add_argument("--id",    default=None, help="agent ID (auto-derived if omitted)")
    inst.add_argument("--token", default="",   help="enrollment token")
    inst.add_argument("--dir",   default=None, help="install directory override")

    # run (called by service daemon)
    run = sub.add_parser("run", help="run agent in foreground (used by service)")
    run.add_argument("--config", default=None, help="path to agent.toml")

    # start / stop / reload / status / uninstall / logs
    sub.add_parser("start",     help="start registered service")
    sub.add_parser("stop",      help="stop running service")
    sub.add_parser("reload",    help="reload config without restart (SIGHUP)")

    st = sub.add_parser("status",   help="show service state")
    st.add_argument("--dir", default=None)

    un = sub.add_parser("uninstall", help="stop service and remove all agent files")
    un.add_argument("--dir", default=None)

    lg = sub.add_parser("logs",     help="tail agent log")
    lg.add_argument("--lines", type=int, default=50, help="number of lines (default 50)")
    lg.add_argument("--dir",   default=None)

    return p


def main() -> None:
    # When called by a LaunchDaemon/systemd with no args, default to "run"
    if len(sys.argv) == 1:
        _cmd_run(config=None)
        return

    args = _parser().parse_args()

    if args.cmd == "install":
        from agent.selfinstall import install
        from pathlib import Path
        install(
            manager_url  = args.manager,
            install_dir  = args.dir,
            agent_name   = args.name,
            agent_id     = args.id,
            enroll_token = args.token,
        )

    elif args.cmd == "run":
        _cmd_run(config=getattr(args, "config", None))

    elif args.cmd == "start":
        from agent.selfinstall import start
        start()

    elif args.cmd == "stop":
        from agent.selfinstall import stop
        stop()

    elif args.cmd == "reload":
        from agent.selfinstall import reload
        reload()

    elif args.cmd == "status":
        from agent.selfinstall import status
        from pathlib import Path
        running, detail = status(install_dir=getattr(args, "dir", None))
        icon = "●" if running else "○"
        print(f"  {icon} attacklens-agent  {detail}")
        sys.exit(0 if running else 1)

    elif args.cmd == "uninstall":
        from agent.selfinstall import uninstall
        from pathlib import Path
        uninstall(install_dir=getattr(args, "dir", None))

    elif args.cmd == "logs":
        from agent.selfinstall import show_logs
        show_logs(
            install_dir = getattr(args, "dir", None),
            lines       = args.lines,
        )

    else:
        _parser().print_help()
        sys.exit(1)


def _cmd_run(config: str | None) -> None:
    """Start the agent core (foreground). Called by 'run' subcommand and service daemons."""
    import os
    from pathlib import Path

    # Resolve config path: CLI arg → env var → default install location → dev default
    if config:
        cfg_path = config
    else:
        cfg_path = os.environ.get("ATTACKLENS_CONFIG")

    if not cfg_path:
        from agent.selfinstall import default_install_dir, _config_path
        candidate = _config_path(default_install_dir())
        if candidate.exists():
            cfg_path = str(candidate)
        else:
            # Dev fallback: agent.toml in cwd
            dev = Path("agent.toml")
            if dev.exists():
                cfg_path = str(dev)

    if not cfg_path:
        print(
            "ERROR: no config found. Pass --config PATH or run 'attacklens-agent install' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Patch sys.argv so agent.agent.core.main() sees --config
    sys.argv = ["attacklens-agent", "--config", cfg_path]

    from agent.agent.core import main as agent_main
    agent_main()


if __name__ == "__main__":
    main()
