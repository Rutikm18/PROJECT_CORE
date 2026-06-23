"""
agent/tests/unit/test_launchd_plist.py — generated LaunchDaemon plist contract.

Regression for a confirmed boot-reconnect bug: the agent plist's
ProgramArguments invoked the binary as `attacklens-agent --config <path>`,
with no subcommand. The binary is built from agent_entry.py, whose CLI is
subcommand-based (run/start/stop/status/...). Reproduced directly:

    sys.argv = ["attacklens-agent", "--config", "/x.toml"]
    agent_entry._parser().parse_args()
    # SystemExit(2): "error: argument COMMAND: invalid choice: '/x.toml'"

argparse treats "--config" as having no matching subcommand and tries to
parse "/x.toml" as the subcommand itself — exit 2, every single launch.
Under launchd's KeepAlive=true that's an infinite crash loop that NEVER
actually starts the agent — exactly the "reboot and it never reconnects"
failure mode. The fix: pass "run" before "--config". watchdog.py has no
subcommands (plain argparse), so its plist must NOT get this treatment.
"""
from __future__ import annotations

from agent.os.macos.launchd import _agent_plist_xml, _watchdog_plist_xml


def test_agent_plist_invokes_run_subcommand():
    xml = _agent_plist_xml()
    args = _program_arguments(xml)
    assert args[1] == "run", (
        "agent_entry.py's CLI is subcommand-based — invoking the binary with "
        "bare --config (no subcommand) makes argparse exit 2 on every launch"
    )
    assert "--config" in args


def test_watchdog_plist_has_no_subcommand():
    """watchdog.main() takes plain --config via its own argparse — no
    subcommands exist, so inserting "run" here would be the new bug."""
    xml = _watchdog_plist_xml()
    args = _program_arguments(xml)
    assert "run" not in args
    assert args[1] == "--config"


def test_agent_plist_config_path_survives_the_inserted_subcommand():
    xml = _agent_plist_xml(config_path="/custom/agent.toml")
    args = _program_arguments(xml)
    assert args == [args[0], "run", "--config", "/custom/agent.toml"]


def _program_arguments(plist_xml: str) -> list[str]:
    """Minimal extraction of the ProgramArguments <string> list — avoids a
    plistlib dependency on the exact same XML this test is verifying."""
    import re
    block = re.search(r"<key>ProgramArguments</key>\s*<array>(.*?)</array>",
                      plist_xml, re.DOTALL)
    assert block, "ProgramArguments array not found in generated plist"
    return re.findall(r"<string>(.*?)</string>", block.group(1))
