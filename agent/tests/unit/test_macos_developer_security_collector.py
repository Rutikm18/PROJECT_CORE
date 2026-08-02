"""Privacy, bounding, and schema tests for the macOS developer-security snapshot."""
from __future__ import annotations

import json
import os
import pwd
import subprocess
from pathlib import Path

from agent.os.macos.collectors import COLLECTORS
from agent.os.macos.collectors.developer_security import (
    DeveloperSecurityCollector,
    _redact,
    _run_command,
)
from shared.sections import VALID_SECTION_NAMES
from shared.schema import validate_section


def test_section_is_registered_end_to_end():
    collector = COLLECTORS["developer_security"]
    assert isinstance(collector, DeveloperSecurityCollector)
    assert "developer_security" in VALID_SECTION_NAMES


def test_redact_removes_common_secret_forms():
    source = (
        "AWS_SECRET_ACCESS_KEY=topsecret --api-key sk-abcdefghijklmnopqrst "
        "https://user:password@example.test Authorization: Bearer eyJabc.def.ghi"
    )
    redacted = _redact(source)
    assert "topsecret" not in redacted
    assert "sk-abcdefghijklmnopqrst" not in redacted
    assert "user:password" not in redacted
    assert "eyJabc.def.ghi" not in redacted
    assert redacted.count("[REDACTED]") >= 4


def test_command_output_and_runtime_are_bounded():
    output = _run_command(
        ["python3", "-c", "print('x' * 10000)"], max_output=100, timeout=2
    )
    assert output["ok"] is True
    assert output["truncated"] is True
    assert len(output["stdout"].encode()) <= 100

    timed_out = _run_command(
        ["python3", "-c", "import time; time.sleep(2)"], timeout=0.1
    )
    assert timed_out["ok"] is False
    assert timed_out["error"] == "timeout"


def test_extension_inventory_reports_activation_and_execution_indicators(tmp_path):
    home = tmp_path / "alice"
    extension = home / ".vscode/extensions/unknown.agent-1.2.3"
    extension.mkdir(parents=True)
    (extension / "package.json").write_text(json.dumps({
        "name": "agent", "publisher": "unknown", "version": "1.2.3",
        "activationEvents": ["onStartupFinished"],
        "main": "index.js", "contributes": {"terminal": {}},
    }))
    (extension / "index.js").write_text("require('child_process').exec('id')")

    result = DeveloperSecurityCollector()._extensions([("alice", home)])

    assert result["count"] == 1
    item = result["items"][0]
    assert item["id"] == "unknown.agent"
    assert item["auto_activates"] is True
    assert "child_process" in item["entrypoint_indicators"]
    assert "terminal" in item["contributes"]


def test_mcp_inventory_never_transmits_environment_values(tmp_path):
    home = tmp_path / "alice"
    config = home / "Library/Application Support/Claude/claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({
        "mcpServers": {
            "risky": {
                "command": "npx",
                "args": ["-y", "unknown-mcp-server@latest", "--api-key", "arg-secret"],
                "env": {"OPENAI_API_KEY": "env-secret", "MODE": "read-only"},
            }
        }
    }))

    result = DeveloperSecurityCollector()._mcp([("alice", home)])
    serialized = json.dumps(result)

    assert result["servers"][0]["uses_latest"] is True
    assert result["servers"][0]["uses_unpinned_ephemeral_runner"] is True
    assert result["servers"][0]["env_keys"] == ["MODE", "OPENAI_API_KEY"]
    assert result["servers"][0]["args"][-1] == "[REDACTED]"
    assert "env-secret" not in serialized
    assert "arg-secret" not in serialized


def test_mcp_inventory_parses_toml_and_yaml_variants(tmp_path):
    home = tmp_path / "alice"
    codex = home / ".codex/config.toml"
    codex.parent.mkdir(parents=True)
    codex.write_text(
        '[mcp_servers.toml_server]\ncommand = "npx"\n'
        'args = ["-y", "toml-server@latest"]\n'
        '[mcp_servers.toml_server.env]\nAPI_TOKEN = "toml-secret"\n'
    )
    yaml_path = home / ".config/tool/mcp.yaml"
    yaml_path.parent.mkdir(parents=True)
    yaml_path.write_text(
        "mcpServers:\n  yaml_server:\n    command: uvx\n"
        "    args: [yaml-server]\n    env:\n      API_KEY: yaml-secret\n"
    )

    result = DeveloperSecurityCollector()._mcp([("alice", home)])
    by_name = {server["name"]: server for server in result["servers"]}
    assert "toml_server" in by_name
    assert by_name["toml_server"]["uses_latest"] is True
    assert by_name["toml_server"]["env_keys"] == ["API_TOKEN"]
    # PyYAML is optional in source-only environments; when packaged (where SCA
    # already includes it), YAML MCP definitions receive the same treatment.
    if "yaml_server" in by_name:
        assert by_name["yaml_server"]["env_keys"] == ["API_KEY"]
    serialized = json.dumps(result)
    assert "toml-secret" not in serialized
    assert "yaml-secret" not in serialized


def test_snapshot_declares_all_requested_capabilities(monkeypatch):
    monkeypatch.setattr(
        "agent.os.macos.collectors.developer_security._user_homes", lambda: []
    )
    collector = DeveloperSecurityCollector()
    method_names = (
        "_extensions", "_mcp", "_node", "_python", "_homebrew", "_applications",
        "_cli_tools", "_shell_startup", "_launchd", "_cron", "_processes",
        "_listeners", "_browser_extensions", "_native_messaging", "_git",
        "_credentials", "_docker",
    )
    for name in method_names:
        monkeypatch.setattr(collector, name, lambda *args, **kwargs: {"items": []})

    snapshot = collector.collect()

    assert snapshot["schema_version"] == 1
    assert snapshot["privacy"]["secret_contents_collected"] is False
    assert set(snapshot["capabilities"]) == {
        "editor_extensions", "mcp_servers", "node_packages", "python_packages",
        "homebrew", "ai_applications", "agent_cli_tools", "shell_startup",
        "launchd", "cron", "processes", "listening_ports", "browser_extensions",
        "native_messaging", "git", "credential_locations", "docker",
    }
    assert validate_section("developer_security", snapshot) == []


def test_user_scoped_command_never_impersonates_without_privilege(monkeypatch):
    current = pwd.getpwuid(os.geteuid())
    result = _run_command(
        ["python3", "-c", "import os; print(os.geteuid())"],
        home=Path(current.pw_dir),
        run_as_user=current.pw_name,
    )
    assert result["ok"] is True
    assert result["stdout"].strip() == str(current.pw_uid)

    class Other:
        pw_name = "another-user"
        pw_uid = current.pw_uid + 1000
        pw_gid = current.pw_gid
        pw_dir = "/Users/another-user"

    monkeypatch.setattr(pwd, "getpwnam", lambda _name: Other())
    refused = _run_command(
        ["python3", "-c", "print('must-not-run')"],
        run_as_user="another-user",
    )
    assert refused["error"] == "insufficient_privilege"
    assert refused["stdout"] == ""


def test_root_agent_drops_to_target_uid_for_user_command(monkeypatch):
    captured = {}

    class Account:
        pw_name = "alice"
        pw_uid = 501
        pw_gid = 20
        pw_dir = "/Users/alice"

    class FakeProcess:
        def __init__(self, _args, **kwargs):
            captured.update(kwargs)
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"501\n")
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(
        "agent.os.macos.collectors.developer_security._command_path",
        lambda _name, _home=None: "/usr/bin/id",
    )
    monkeypatch.setattr(pwd, "getpwnam", lambda _name: Account())
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgrouplist", lambda _name, _gid: [20, 12])
    monkeypatch.setattr(subprocess, "Popen", FakeProcess)

    result = _run_command(["id", "-u"], home=Path("/Users/alice"), run_as_user="alice")
    assert result["ok"] is True
    assert result["identity_switched"] is True
    assert captured["user"] == 501
    assert captured["group"] == 20
    assert captured["extra_groups"] == [20, 12]
    assert captured["env"]["HOME"] == "/Users/alice"
    assert captured["env"]["USER"] == "alice"


def test_snapshot_size_is_hard_bounded_and_visible(monkeypatch):
    import agent.os.macos.collectors.developer_security as module

    monkeypatch.setattr(module, "_MAX_SNAPSHOT_BYTES", 8_000)
    monkeypatch.setattr(module, "_user_homes", lambda: [])
    collector = DeveloperSecurityCollector()
    huge = {"items": [{"value": "x" * 1000, "n": i} for i in range(100)]}
    for name in (
        "_extensions", "_mcp", "_node", "_python", "_applications",
        "_shell_startup", "_cron", "_browser_extensions", "_native_messaging",
        "_git", "_credentials",
    ):
        monkeypatch.setattr(collector, name, lambda *args, **kwargs: json.loads(json.dumps(huge)))
    for name in (
        "_homebrew", "_cli_tools", "_launchd", "_processes", "_listeners", "_docker",
    ):
        monkeypatch.setattr(collector, name, lambda *args, **kwargs: json.loads(json.dumps(huge)))

    snapshot = collector.collect()
    encoded = json.dumps(snapshot, separators=(",", ":")).encode()
    assert len(encoded) <= 8_000
    assert snapshot["collection"]["partial"] is True
    assert snapshot["collection"]["payload_truncated"] is True
    assert snapshot["collection"]["payload_truncations"]


def test_timeout_status_marks_snapshot_partial(monkeypatch):
    monkeypatch.setattr(
        "agent.os.macos.collectors.developer_security._user_homes", lambda: []
    )
    collector = DeveloperSecurityCollector()
    for name in (
        "_extensions", "_mcp", "_node", "_python", "_applications",
        "_shell_startup", "_cron", "_browser_extensions", "_native_messaging",
        "_git", "_credentials",
    ):
        monkeypatch.setattr(collector, name, lambda *args, **kwargs: {"items": []})
    for name in ("_homebrew", "_cli_tools", "_launchd", "_processes", "_listeners", "_docker"):
        monkeypatch.setattr(collector, name, lambda *args, **kwargs: {"items": []})
    monkeypatch.setattr(
        collector, "_docker",
        lambda: {"status": {"available": True, "ok": False, "error": "timeout"}},
    )

    snapshot = collector.collect()
    assert snapshot["collection"]["partial"] is True
    assert any(i["error"] == "timeout" for i in snapshot["collection"]["issues"])
