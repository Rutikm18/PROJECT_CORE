"""Detections for the privacy-safe macOS developer security inventory."""
from __future__ import annotations

import re
import uuid
import hashlib
import json
from datetime import datetime, timezone
from typing import Any


_SENSITIVE_ENV = re.compile(
    r"(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)",
    re.I,
)
_TEMP_PATH = re.compile(r"^/(?:tmp|private/tmp|var/tmp)(?:/|$)", re.I)
_SHELL_EXEC = {"child_process", "exec", "spawn", "shell", "eval"}

RULE_SPECS: dict[str, dict[str, str]] = {
    "AL-DEV-001": {"asset": "editor extension", "condition": "auto activation AND command execution AND side-loaded/unverified publisher", "boundary": "all three anchors are required"},
    "AL-DEV-002": {"asset": "MCP server", "condition": "mutable @latest reference OR unpinned ephemeral runner with sensitive/capability access", "boundary": "an ephemeral runner alone is not sufficient"},
    "AL-DEV-003": {"asset": "PATH directory", "condition": "world-writable executable search path entry", "boundary": "unknown or non-world-writable modes are silent"},
    "AL-DEV-004": {"asset": "browser extension", "condition": "native messaging AND at least one dangerous browser/host permission", "boundary": "both anchors are required"},
    "AL-DEV-005": {"asset": "native messaging host", "condition": "temporary executable path OR group/world-writable executable", "boundary": "ordinary 0755 read/execute access is safe"},
    "AL-DEV-006": {"asset": "Git configuration", "condition": "core.hooksPath or core.sshCommand execution override", "boundary": "unrelated Git settings are silent"},
    "AL-DEV-007": {"asset": "credential location", "condition": "group/other read or write permission on a credential-related file", "boundary": "owner-only 0600 and directories are silent"},
    "AL-DEV-008": {"asset": "developer listener", "condition": "interesting developer/AI process AND wildcard bind", "boundary": "loopback or unrelated wildcard listeners are silent"},
    "AL-DEV-009": {"asset": "developer container", "condition": "privileged, host network, Docker socket/root bind, or SYS_ADMIN posture", "boundary": "ordinary bridge containers are silent"},
}


def _items(capabilities: dict[str, Any], name: str, key: str = "items") -> list[dict[str, Any]]:
    value = capabilities.get(name)
    if not isinstance(value, dict):
        return []
    rows = value.get(key)
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _mode_exposes_secret(mode: Any) -> bool:
    text = str(mode or "")
    if len(text) < 10 or text[0] == "d":
        return False
    return any(text[index] != "-" for index in (4, 5, 7, 8))


def _mode_is_group_or_world_writable(mode: Any) -> bool:
    text = str(mode or "")
    return len(text) >= 10 and text[0] != "d" and any(text[index] == "w" for index in (5, 8))


def _hit(
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    evidence: dict[str, Any],
    *,
    technique: str,
    tactic: str,
    action: str,
    item_key: str,
) -> dict[str, Any]:
    score = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}[severity]
    fingerprint_payload = json.dumps(
        {"rule_id": rule_id, "item_key": item_key, "evidence": evidence},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return {
        "alert_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "severity": severity,
        "score": score,
        "title": title,
        "description": description,
        "affected_asset": "",
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "evidence": evidence,
        "raw_telemetry": [],
        "compliance_controls": {
            "NIST CSF": ["PR.DS-6", "DE.CM-7"],
            "ISO 27001": ["A.8.8", "A.8.19"],
        },
        "recommended_action": action,
        "false_positive_notes": "Confirm the component and execution path against the approved developer tooling baseline.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "category": "developer_security",
        "item_key": item_key,
        "source": "rule:developer_security",
        "tags": ["developer_security", technique],
        "cve_ids": [],
        "cvss_score": None,
        "cvss_vector": None,
        "detection_fingerprint": hashlib.sha256(fingerprint_payload.encode()).hexdigest(),
    }


def _extension_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "editor_extensions"):
        extension_id = str(row.get("id") or row.get("directory") or "unknown")
        indicators = {
            str(value).lower()
            for value in [*(row.get("manifest_indicators") or []), *(row.get("entrypoint_indicators") or [])]
        }
        code_exec = bool(indicators & _SHELL_EXEC)
        side_loaded = bool(row.get("installed_from_vsix") or row.get("unknown_publisher"))
        if not (row.get("auto_activates") and code_exec and side_loaded):
            continue
        hits.append(_hit(
            "AL-DEV-001", "high", "Untrusted editor extension can auto-execute commands",
            "A side-loaded or unverified editor extension automatically activates and contains command-execution indicators.",
            {"id": extension_id, "editor": row.get("editor"), "user": row.get("user"),
             "auto_activates": True, "indicators": sorted(indicators),
             "installed_from_vsix": bool(row.get("installed_from_vsix")),
             "unknown_publisher": bool(row.get("unknown_publisher")),
             "side_loaded": side_loaded},
            technique="T1204.002", tactic="Execution",
            action="Disable the extension, verify its publisher and source, and review its entrypoint before re-enabling it.",
            item_key=f"extension:{row.get('user')}:{row.get('editor')}:{extension_id}",
        ))
    return hits


def _mcp_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "mcp_servers", "servers"):
        name = str(row.get("name") or "unknown")
        env_keys = [str(key) for key in (row.get("env_keys") or [])]
        sensitive_env = sorted(key for key in env_keys if _SENSITIVE_ENV.search(key))
        indicators = [str(value) for value in (row.get("capability_indicators") or [])]
        uses_latest = bool(row.get("uses_latest"))
        ephemeral = bool(row.get("uses_unpinned_ephemeral_runner"))
        if not (uses_latest or (ephemeral and (sensitive_env or indicators))):
            continue
        severity = "high" if uses_latest and sensitive_env else "medium"
        hits.append(_hit(
            "AL-DEV-002", severity, "Unpinned MCP server executes with sensitive capabilities",
            "An MCP server is launched from a mutable package reference or ephemeral runner and may receive sensitive environment variables.",
            {"name": name, "config_path": row.get("config_path"), "command": row.get("command"),
             "uses_latest": uses_latest, "uses_unpinned_ephemeral_runner": ephemeral,
             "sensitive_env_keys": sensitive_env, "capability_indicators": indicators},
            technique="T1195.002", tactic="Initial Access",
            action="Pin the MCP package to a reviewed version and digest, minimize exposed environment keys, and restrict filesystem access.",
            item_key=f"mcp:{row.get('config_path')}:{name}",
        ))
    return hits


def _path_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    cli = capabilities.get("agent_cli_tools")
    if not isinstance(cli, dict):
        return hits
    writable = [str(row.get("path")) for row in (cli.get("path") or [])
                if isinstance(row, dict) and row.get("world_writable")]
    if not writable:
        return hits
    hits.append(_hit(
        "AL-DEV-003", "high", "World-writable directory is present in executable search path",
        "A world-writable PATH entry can let another local user replace or shadow developer and agent commands.",
        {"paths": writable[:20]}, technique="T1574.007", tactic="Persistence",
        action="Remove the directory from PATH or change ownership and permissions so untrusted users cannot write to it.",
        item_key=f"path:{writable[0]}",
    ))
    return hits


def _browser_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "browser_extensions"):
        permissions = [str(value) for value in (row.get("dangerous_permissions") or [])]
        if not (row.get("native_messaging") and permissions):
            continue
        extension_id = str(row.get("id") or row.get("path") or "unknown")
        hits.append(_hit(
            "AL-DEV-004", "high", "Browser extension combines native messaging with broad permissions",
            "The extension can access native applications and has sensitive browser or host permissions.",
            {"id": extension_id, "browser": row.get("browser"), "user": row.get("user"),
             "native_messaging": True, "dangerous_permissions": permissions},
            technique="T1176", tactic="Persistence",
            action="Verify the extension ID and native host pairing, then remove permissions that are not required.",
            item_key=f"browser_extension:{row.get('user')}:{row.get('browser')}:{extension_id}",
        ))
    for row in _items(capabilities, "native_messaging"):
        executable = str(row.get("executable") or "")
        meta = row.get("executable_meta") if isinstance(row.get("executable_meta"), dict) else {}
        if not executable or (
            not row.get("executable_temporary")
            and not _TEMP_PATH.search(executable)
            and not _mode_is_group_or_world_writable(meta.get("mode"))
        ):
            continue
        hits.append(_hit(
            "AL-DEV-005", "high", "Native messaging host uses an unsafe executable",
            "A browser native messaging manifest points to a temporary or group/world-modifiable executable.",
            {"name": row.get("name"), "manifest": row.get("path"), "executable": executable,
             "mode": meta.get("mode")},
            technique="T1176", tactic="Persistence",
            action="Move the executable to a root- or administrator-controlled location and restrict write permissions.",
            item_key=f"native_host:{row.get('name')}:{executable}",
        ))
    return hits


def _git_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    git = capabilities.get("git")
    if not isinstance(git, dict):
        return []
    settings: list[dict[str, Any]] = []
    for user in git.get("users") or []:
        if isinstance(user, dict):
            settings.extend(row for row in (user.get("settings") or []) if isinstance(row, dict))
    for scope in (git.get("system"), git.get("local")):
        if isinstance(scope, dict):
            settings.extend(row for row in (scope.get("settings") or []) if isinstance(row, dict))
    risky = [row for row in settings if str(row.get("key") or "").lower() in {
        "core.hookspath", "core.sshcommand"
    }]
    if not risky:
        return []
    keys = sorted({str(row.get("key")) for row in risky})
    return [_hit(
        "AL-DEV-006", "medium", "Git execution override is configured",
        "Git is configured to execute a custom hooks directory or SSH command, which can alter code and credential flows.",
        {"settings": risky[:20], "keys": keys}, technique="T1059", tactic="Execution",
        action="Confirm the setting is managed and expected; remove repository or user-level overrides that are not required.",
        item_key=f"git_override:{','.join(keys)}",
    )]


def _credential_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "credential_locations", "locations"):
        if not _mode_exposes_secret(row.get("mode")):
            continue
        path = str(row.get("path") or "unknown")
        hits.append(_hit(
            "AL-DEV-007", "high", "Credential file permissions expose secrets",
            "A discovered credential-related file is readable or writable by its group or other users.",
            {"path": path, "mode": row.get("mode"), "user": row.get("user"), "kind": row.get("kind")},
            technique="T1552.001", tactic="Credential Access",
            action="Restrict the file to its owner and rotate credentials if unauthorized access may have occurred.",
            item_key=f"credential_mode:{path}",
        ))
    return hits


def _runtime_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "listening_ports"):
        if not (row.get("wildcard") and row.get("interesting")):
            continue
        endpoint = str(row.get("endpoint") or row.get("port") or "unknown")
        hits.append(_hit(
            "AL-DEV-008", "medium", "Developer or AI service listens on all interfaces",
            "A developer or AI-related process is reachable through a wildcard network bind.",
            {"process": row.get("process"), "pid": row.get("pid"), "user": row.get("user"),
             "endpoint": endpoint, "port": row.get("port")},
            technique="T1133", tactic="Persistence",
            action="Bind the service to loopback or a controlled interface and require authentication before remote access.",
            item_key=f"developer_listener:{row.get('process')}:{endpoint}",
        ))
    for row in _items(capabilities, "docker", "risk_posture"):
        if not row.get("high_risk"):
            continue
        container_id = str(row.get("id") or row.get("name") or "unknown")
        hits.append(_hit(
            "AL-DEV-009", "critical", "Developer container has host-control capabilities",
            "A developer container is privileged, uses host networking, mounts the Docker socket or host root, or adds SYS_ADMIN.",
            {"id": container_id, "name": row.get("name"), "privileged": row.get("privileged"),
             "network_mode": row.get("network_mode"), "binds": row.get("binds"),
             "cap_add": row.get("cap_add"), "high_risk": True},
            technique="T1611", tactic="Privilege Escalation",
            action="Recreate the container without privileged mode, host networking, sensitive binds, or SYS_ADMIN.",
            item_key=f"developer_container:{container_id}",
        ))
    return hits


async def analyze(
    agent_id: str,
    section: str,
    data: Any,
    db: Any,
    hostname: str = "",
) -> list[dict[str, Any]]:
    del db
    if section != "developer_security" or not isinstance(data, dict):
        return []
    capabilities = data.get("capabilities")
    if not isinstance(capabilities, dict):
        return []
    hits = [
        *_extension_hits(capabilities),
        *_mcp_hits(capabilities),
        *_path_hits(capabilities),
        *_browser_hits(capabilities),
        *_git_hits(capabilities),
        *_credential_hits(capabilities),
        *_runtime_hits(capabilities),
    ]
    asset = hostname or agent_id
    for hit in hits:
        hit["affected_asset"] = asset
    return hits


__all__ = ["RULE_SPECS", "analyze"]
