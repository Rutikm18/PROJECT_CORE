"""Hourly macOS developer-tool and AI-agent security inventory.

This collector is intentionally read-only and privacy bounded.  It inventories
the control-plane surfaces commonly used by coding agents (editor extensions,
MCP servers, package managers, persistence, listeners, browser integrations,
Git, credential *locations*, and Docker) without shipping credential contents.

The returned document is a snapshot designed for manager-side detections added
later.  Every list is capped, command output is capped, and every external
command has a short timeout so a large developer workstation cannot wedge the
agent or create an unbounded telemetry payload.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import pwd
import re
import selectors
import shlex
import shutil
import stat
import subprocess
import time
import tomllib
from pathlib import Path
from typing import Any, Callable, Iterable

from .base import BaseCollector, _get_env, run_budget_remaining


_SCHEMA_VERSION = 1
_MAX_ITEMS = 500
_MAX_FILES = 400
_MAX_TEXT = 512 * 1024
_MAX_FIELD = 2_048
_COMMAND_TIMEOUT = 6.0
# Raw JSON ceiling. The encrypted wire envelope base64-expands incompressible
# data by ~4/3, so 6 MiB stays below the manager's 10 MiB ingest ceiling even
# in the pessimistic case while leaving room for envelope metadata.
_MAX_SNAPSHOT_BYTES = 6 * 1024 * 1024

_INTERESTING = re.compile(
    r"copilot|cline|roo|continue|claude|gemini|codex|openai|codeium|windsurf|"
    r"tabnine|mcp|remote|ssh|docker|kubernetes|rest|database|ollama|llama|"
    r"langchain|crewai|autogen|aider|goose|opencode|fabric|sgpt",
    re.I,
)
_SENSITIVE_NAME = re.compile(
    r"pass(word)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"authorization|credential|client[_-]?secret|session|cookie",
    re.I,
)
_SHELL_INDICATOR = re.compile(
    r"\bcurl\b|\bwget\b|\beval\b|\bsource\b|\bnpm\b|\bnpx\b|\bpython\b|"
    r"\bpip\b|\buvx\b|\bmcp\b|\bagent\b|\bollama\b|\bclaude\b|\bcursor\b",
    re.I,
)
_EXEC_INDICATOR = re.compile(
    r"child_process|spawn\s*\(|exec(File|Sync)?\s*\(|shell|terminal|"
    r"createServer|listen\s*\(|https?://|WebSocket|net\.createServer",
    re.I,
)
_DANGEROUS_BROWSER_PERMS = {
    "<all_urls>", "cookies", "history", "clipboardread", "clipboardwrite",
    "nativemessaging", "debugger", "management", "webrequest", "downloads",
}
_SECRET_FILE = re.compile(r"^\.env($|\.)|credential|token|secret|config\.json$", re.I)


def _clip(value: Any, limit: int = _MAX_FIELD) -> str:
    text = str(value or "").replace("\x00", "")
    return text if len(text) <= limit else text[:limit] + "…"


def _redact(value: Any) -> str:
    """Redact common inline-secret forms while preserving detection context."""
    text = _clip(value)
    text = re.sub(r"(?i)(https?://)([^/@\s]+)@", r"\1[REDACTED]@", text)
    text = re.sub(
        r"(?i)(\b[A-Za-z_][A-Za-z0-9_]*(?:password|passwd|secret|token|api[_-]?key|"
        r"access[_-]?key|private[_-]?key|credential|client[_-]?secret)"
        r"[A-Za-z0-9_]*\s*=\s*)([^\s,;]+)",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|"
        r"client[_-]?secret)(\s*[:=]\s*)([^\s,;]+)",
        r"\1\2[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+",
                  r"\1[REDACTED]", text)
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|"
                  r"AKIA[A-Z0-9]{16})\b", "[REDACTED]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
                  "[REDACTED]", text)
    try:
        parts = shlex.split(text)
    except ValueError:
        return text
    out: list[str] = []
    redact_next = False
    for part in parts:
        if redact_next:
            out.append("[REDACTED]")
            redact_next = False
            continue
        if part.startswith("-") and _SENSITIVE_NAME.search(part):
            if "=" in part:
                out.append(part.split("=", 1)[0] + "=[REDACTED]")
            else:
                out.append(part)
                redact_next = True
            continue
        out.append(part)
    return " ".join(out)


def _hash_line(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _file_meta(path: Path) -> dict[str, Any] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return {
        "path": str(path),
        "mode": stat.filemode(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size_bytes": st.st_size,
        "modified_at": int(st.st_mtime),
        "symlink": path.is_symlink(),
    }


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _read_text(path: Path, limit: int = _MAX_TEXT) -> tuple[str, bool]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError:
        return "", False
    return raw[:limit].decode("utf-8", "replace"), len(raw) > limit


def _read_json(path: Path) -> dict[str, Any] | list[Any] | None:
    text, _ = _read_text(path)
    if not text:
        return None
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _read_structured(path: Path) -> dict[str, Any] | list[Any] | None:
    """Read bounded JSON, TOML, or YAML without making YAML a hard dependency."""
    text, _ = _read_text(path)
    if not text:
        return None
    try:
        suffix = path.suffix.lower()
        if suffix == ".toml":
            value = tomllib.loads(text)
        elif suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError:
                return None
            value = yaml.safe_load(text)
        else:
            value = json.loads(text)
    except Exception:
        return None
    return value if isinstance(value, (dict, list)) else None


def _user_homes() -> list[tuple[str, Path]]:
    """Return real local user homes even when the LaunchDaemon runs as root."""
    homes: dict[str, Path] = {}
    try:
        for entry in pwd.getpwall():
            home = Path(entry.pw_dir)
            if entry.pw_uid >= 500 and str(home).startswith("/Users/") and home.is_dir():
                homes[entry.pw_name] = home
    except Exception:
        pass
    users_root = Path("/Users")
    try:
        for home in users_root.iterdir():
            if home.is_dir() and home.name not in {"Shared", "Guest", ".localized"}:
                homes.setdefault(home.name, home)
    except OSError:
        pass
    return sorted(homes.items(), key=lambda item: item[0])[:50]


def _command_path(name: str, home: Path | None = None) -> str | None:
    path_parts: list[str] = []
    if home is not None:
        path_parts.extend(str(home / rel) for rel in (
            ".local/bin", ".npm-global/bin", ".bun/bin", ".cargo/bin",
            ".volta/bin", "Library/Python/3.13/bin", "Library/Python/3.12/bin",
            "Library/Python/3.11/bin",
        ))
        # Version managers normally initialise via shell startup files, which a
        # LaunchDaemon does not source. Discover their bounded user-local shims
        # and installed runtimes explicitly.
        version_roots = (
            home / ".nvm/versions/node", home / ".fnm/node-versions",
        )
        for root in version_roots:
            try:
                for child in sorted(root.iterdir(), reverse=True)[:20]:
                    path_parts.extend((str(child / "bin"), str(child / "installation/bin")))
            except OSError:
                pass
        path_parts.extend((str(home / ".asdf/shims"), str(home / ".pyenv/shims")))
    path_parts.append(_get_env().get("PATH", ""))
    path = os.pathsep.join(path_parts)
    resolved = shutil.which(name, path=path)
    if resolved:
        return resolved
    app_candidates: dict[str, tuple[str, ...]] = {
        "code": (
            "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
            str(home / "Applications/Visual Studio Code.app/Contents/Resources/app/bin/code") if home else "",
        ),
        "cursor": (
            "/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
            str(home / "Applications/Cursor.app/Contents/Resources/app/bin/cursor") if home else "",
        ),
    }
    return next((candidate for candidate in app_candidates.get(name, ())
                 if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK)), None)


def _run_command(
    args: list[str], *, home: Path | None = None, timeout: float = _COMMAND_TIMEOUT,
    max_output: int = _MAX_TEXT, run_as_user: str | None = None,
) -> dict[str, Any]:
    """Run one argv-only read command and return bounded output plus status."""
    executable = _command_path(args[0], home)
    if not executable:
        return {"available": False, "ok": False, "stdout": "", "error": "not_found"}
    remaining = run_budget_remaining()
    if remaining is not None:
        if remaining < 0.5:
            return {"available": True, "ok": False, "stdout": "", "error": "budget_exhausted"}
        timeout = min(timeout, remaining)
    env = dict(_get_env())
    if home is not None:
        env["HOME"] = str(home)
    popen_identity: dict[str, Any] = {}
    identity_switched = False
    if run_as_user:
        try:
            account = pwd.getpwnam(run_as_user)
        except KeyError:
            return {"available": True, "ok": False, "stdout": "", "error": "user_not_found"}
        env.update({"USER": account.pw_name, "LOGNAME": account.pw_name,
                    "HOME": str(home or account.pw_dir)})
        current_uid = os.geteuid()
        if current_uid == 0 and account.pw_uid != 0:
            try:
                groups = os.getgrouplist(account.pw_name, account.pw_gid)
            except (AttributeError, OSError):
                groups = [account.pw_gid]
            popen_identity = {
                "user": account.pw_uid,
                "group": account.pw_gid,
                "extra_groups": groups,
            }
            identity_switched = True
        elif current_uid != account.pw_uid:
            # A non-root source-mode agent cannot safely impersonate another
            # local user. Do not run against their HOME with the wrong identity.
            return {"available": True, "ok": False, "stdout": "",
                    "error": "insufficient_privilege"}
    env.update({
        "HOMEBREW_NO_AUTO_UPDATE": "1",
        "HOMEBREW_NO_ANALYTICS": "1",
        "NO_UPDATE_NOTIFIER": "1",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
    })
    started = time.monotonic()
    output = bytearray()
    total_output = 0
    timed_out = False
    try:
        proc = subprocess.Popen(
            [executable, *args[1:]], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, env=env, **popen_identity,
        )
        assert proc.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                timed_out = True
                proc.kill()
                break
            events = selector.select(timeout=min(0.1, remaining_time))
            if events:
                chunk = os.read(proc.stdout.fileno(), 64 * 1024)
                if not chunk:
                    break
                total_output += len(chunk)
                if len(output) < max_output:
                    output.extend(chunk[:max_output - len(output)])
            elif proc.poll() is not None:
                break
        selector.close()
        proc.wait(timeout=1)
    except Exception as exc:
        return {"available": True, "ok": False, "stdout": "", "error": type(exc).__name__}
    if timed_out:
        return {"available": True, "ok": False,
                "stdout": output.decode("utf-8", "replace"),
                "truncated": total_output > max_output, "error": "timeout"}
    return {
        "available": True,
        "ok": proc.returncode == 0,
        "stdout": output.decode("utf-8", "replace"),
        "truncated": total_output > max_output,
        "exit_code": proc.returncode,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "run_as_user": run_as_user,
        "identity_switched": identity_switched,
        "error": None if proc.returncode == 0 else "nonzero_exit",
    }


def _json_command(
    args: list[str], *, home: Path | None = None, run_as_user: str | None = None,
    max_output: int = _MAX_TEXT,
) -> tuple[Any, dict[str, Any]]:
    result = _run_command(
        args, home=home, run_as_user=run_as_user, max_output=max_output,
    )
    try:
        parsed = json.loads(result["stdout"]) if result.get("stdout") else None
    except ValueError:
        parsed = None
    status = {k: v for k, v in result.items() if k != "stdout"}
    if result.get("ok") and parsed is None:
        status.update(ok=False, error="invalid_json")
    return parsed, status


def _walk(
    roots: Iterable[Path], predicate: Callable[[Path], bool], *,
    max_depth: int = 5, max_files: int = _MAX_FILES,
) -> tuple[list[Path], bool]:
    found: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        root_depth = len(root.parts)
        for current, dirs, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            depth = len(current_path.parts) - root_depth
            dirs[:] = [d for d in dirs if not d.startswith(".") or d in {".config", ".cursor", ".vscode"}]
            if depth >= max_depth:
                dirs[:] = []
            for name in files:
                path = current_path / name
                if predicate(path):
                    found.append(path)
                    if len(found) >= max_files:
                        return found, True
    return found, False


def _risk_indicators(text: str, pattern: re.Pattern[str] = _EXEC_INDICATOR) -> list[str]:
    return sorted({m.group(0).lower() for m in pattern.finditer(text)})[:30]


def _walk_status(value: Any, path: str = "") -> tuple[list[dict[str, str]], bool]:
    """Summarise operational failures and any nested truncation signal."""
    issues: list[dict[str, str]] = []
    truncated = False
    if isinstance(value, dict):
        truncated = value.get("truncated") is True
        error = value.get("error")
        if value.get("available") is True and value.get("ok") is False and error in {
            "timeout", "budget_exhausted", "invalid_json", "PermissionError",
            "OSError", "insufficient_privilege", "user_not_found",
        }:
            issues.append({"path": path or "$", "error": str(error)})
        for key, child in value.items():
            child_issues, child_truncated = _walk_status(
                child, f"{path}.{key}" if path else str(key)
            )
            issues.extend(child_issues)
            truncated = truncated or child_truncated
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_issues, child_truncated = _walk_status(child, f"{path}[{index}]")
            issues.extend(child_issues)
            truncated = truncated or child_truncated
    return issues[:100], truncated


def _json_bytes(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), default=str).encode("utf-8"))


def _bounded_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Deterministically trim largest lists until the raw snapshot is wire-safe."""
    original = _json_bytes(snapshot)
    collection = snapshot["collection"]
    collection.update({
        "payload_limit_bytes": _MAX_SNAPSHOT_BYTES,
        "payload_original_bytes": original,
        "payload_truncated": False,
    })
    # Reserve space for compaction metadata itself.
    target = max(512, _MAX_SNAPSHOT_BYTES - min(32 * 1024, _MAX_SNAPSHOT_BYTES // 3))
    truncations: dict[str, dict[str, int]] = {}

    def lists(value: Any, path: str = "") -> list[tuple[str, list[Any]]]:
        found: list[tuple[str, list[Any]]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                # Never trim the visibility metadata that explains truncation.
                if child_path.startswith("collection"):
                    continue
                found.extend(lists(child, child_path))
        elif isinstance(value, list):
            found.append((path, value))
            for index, child in enumerate(value):
                found.extend(lists(child, f"{path}[{index}]"))
        return found

    while _json_bytes(snapshot) > target:
        candidates = [(path, values) for path, values in lists(snapshot) if values]
        if not candidates:
            break
        path, values = max(candidates, key=lambda item: _json_bytes(item[1]))
        before = len(values)
        remove = max(1, before // 2)
        del values[before - remove:]
        record = truncations.setdefault(path, {"original_count": before, "retained_count": 0})
        record["original_count"] = max(record["original_count"], before)
        record["retained_count"] = len(values)

    final = _json_bytes(snapshot)
    if final > _MAX_SNAPSHOT_BYTES:
        # This should be unreachable with bounded strings/dicts, but report it
        # explicitly rather than claiming a healthy bounded snapshot.
        collection["payload_limit_unmet"] = True
    if truncations:
        collection["partial"] = True
        collection["payload_truncated"] = True
        collection["payload_truncation_path_count"] = len(truncations)
        collection["payload_truncations"] = [
            {"path": path, **counts} for path, counts in sorted(truncations.items())
        ][:25]
    collection["payload_bytes"] = 0
    # A few fixed-point passes make the reported number include its own digits.
    for _ in range(3):
        collection["payload_bytes"] = _json_bytes(snapshot)
    return snapshot


class DeveloperSecurityCollector(BaseCollector):
    """Collect a privacy-safe developer/AI attack-surface snapshot."""

    name = "developer_security"

    def collect(self) -> dict[str, Any]:
        started = time.monotonic()
        homes = _user_homes()
        errors: list[dict[str, str]] = []

        def part(name: str, fn: Callable[[], Any]) -> Any:
            try:
                return fn()
            except Exception as exc:
                errors.append({"capability": name, "error": type(exc).__name__})
                return {"error": type(exc).__name__}

        capabilities = {
            "editor_extensions": part("editor_extensions", lambda: self._extensions(homes)),
            "mcp_servers": part("mcp_servers", lambda: self._mcp(homes)),
            "node_packages": part("node_packages", lambda: self._node(homes)),
            "python_packages": part("python_packages", lambda: self._python(homes)),
            "homebrew": part("homebrew", lambda: self._homebrew(homes)),
            "ai_applications": part("ai_applications", lambda: self._applications(homes)),
            "agent_cli_tools": part("agent_cli_tools", self._cli_tools),
            "shell_startup": part("shell_startup", lambda: self._shell_startup(homes)),
            "launchd": part("launchd", self._launchd),
            "cron": part("cron", lambda: self._cron(homes)),
            "processes": part("processes", self._processes),
            "listening_ports": part("listening_ports", self._listeners),
            "browser_extensions": part("browser_extensions", lambda: self._browser_extensions(homes)),
            "native_messaging": part("native_messaging", lambda: self._native_messaging(homes)),
            "git": part("git", lambda: self._git(homes)),
            "credential_locations": part("credential_locations", lambda: self._credentials(homes)),
            "docker": part("docker", self._docker),
        }
        issues, nested_truncated = _walk_status(capabilities)
        snapshot = {
            "schema_version": _SCHEMA_VERSION,
            "platform": "macos",
            "scope": {"users": [user for user, _ in homes], "system_context": os.geteuid() == 0},
            "privacy": {
                "secret_contents_collected": False,
                "credential_values_collected": False,
                "sensitive_values_redacted": True,
                "collection_bounded": True,
            },
            "capabilities": capabilities,
            "collection": {
                "partial": bool(errors) or bool(issues) or nested_truncated,
                "errors": errors,
                "issues": issues,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
        }
        return _bounded_snapshot(snapshot)

    def _extensions(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        cli_inventory: list[dict[str, Any]] = []
        truncated = False
        for user, home in homes:
            for editor, command, root in (
                ("vscode", "code", home / ".vscode/extensions"),
                ("cursor", "cursor", home / ".cursor/extensions"),
            ):
                cli = _run_command([command, "--list-extensions", "--show-versions"],
                                   home=home, max_output=128 * 1024,
                                   run_as_user=user)
                cli_inventory.append({
                    "user": user, "editor": editor,
                    "extensions": [_clip(line.strip(), 512)
                                   for line in cli.get("stdout", "").splitlines()
                                   if line.strip()][:_MAX_ITEMS],
                    "status": {k: v for k, v in cli.items() if k != "stdout"},
                })
                install_meta: dict[str, dict[str, Any]] = {}
                metadata_doc = _read_json(root / "extensions.json")
                if isinstance(metadata_doc, list):
                    for entry in metadata_doc:
                        if not isinstance(entry, dict):
                            continue
                        identifier = entry.get("identifier") or {}
                        extension_id = str(identifier.get("id") or "").lower()
                        metadata = entry.get("metadata") or {}
                        if extension_id and isinstance(metadata, dict):
                            install_meta[extension_id] = metadata
                try:
                    directories = sorted(p for p in root.iterdir() if p.is_dir())
                except OSError:
                    continue
                for directory in directories:
                    if len(rows) >= _MAX_ITEMS:
                        truncated = True
                        break
                    manifest_path = directory / "package.json"
                    manifest = _read_json(manifest_path)
                    if not isinstance(manifest, dict):
                        rows.append({"user": user, "editor": editor, "directory": directory.name,
                                     "manifest_valid": False})
                        continue
                    publisher = str(manifest.get("publisher") or "")
                    name = str(manifest.get("name") or directory.name)
                    activation = manifest.get("activationEvents") or []
                    contributes = manifest.get("contributes") or {}
                    manifest_text = json.dumps(manifest, default=str)
                    entry_indicators: list[str] = []
                    for key in ("main", "browser"):
                        rel = manifest.get(key)
                        if isinstance(rel, str):
                            candidate = (directory / rel).resolve()
                            try:
                                candidate.relative_to(directory.resolve())
                            except ValueError:
                                continue
                            source, _ = _read_text(candidate, 256 * 1024)
                            entry_indicators.extend(_risk_indicators(source))
                    extension_id = f"{publisher}.{name}" if publisher else name
                    metadata = install_meta.get(extension_id.lower(), {})
                    source = str(metadata.get("source") or "")
                    rows.append({
                        "user": user, "editor": editor, "id": extension_id,
                        "version": manifest.get("version"), "publisher": publisher or None,
                        "directory": directory.name,
                        "interesting": bool(_INTERESTING.search(extension_id)),
                        "activation_events": activation[:100] if isinstance(activation, list) else [],
                        "auto_activates": any(
                            str(v) in {"*", "onStartupFinished"} or str(v).startswith("workspaceContains")
                            for v in activation if isinstance(activation, list)
                        ),
                        "entrypoints": {k: manifest.get(k) for k in ("main", "browser") if manifest.get(k)},
                        "contributes": sorted(contributes.keys()) if isinstance(contributes, dict) else [],
                        "manifest_indicators": _risk_indicators(manifest_text),
                        "entrypoint_indicators": sorted(set(entry_indicators))[:30],
                        "extension_kind": manifest.get("extensionKind"),
                        "installed_at": metadata.get("installedTimestamp"),
                        "install_source": _clip(source, 256) or None,
                        "installed_from_vsix": source.lower() == "vsix",
                        "publisher_id": metadata.get("publisherId"),
                        "publisher_metadata_present": bool(metadata.get("publisherId")),
                        "unknown_publisher": not bool(publisher and metadata.get("publisherId")),
                        "target_platform": metadata.get("targetPlatform"),
                        "manifest_valid": True,
                    })
        return {"items": rows, "cli_inventory": cli_inventory,
                "count": len(rows), "truncated": truncated}

    def _mcp(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        roots: list[Path] = []
        direct_files: list[Path] = []
        for _, home in homes:
            roots.extend([
                home / "Library/Application Support/Claude",
                home / ".cursor", home / ".vscode", home / ".config",
                home / ".claude", home / ".codex", home / ".windsurf",
                home / ".continue",
            ])
            direct_files.extend([
                home / ".claude.json",
                home / "Library/Application Support/Claude/claude_desktop_config.json",
                home / ".cursor/mcp.json",
                home / ".codex/config.toml",
            ])
        walked, truncated = _walk(
            roots,
            lambda p: (
                ("mcp" in p.name.lower() and p.suffix.lower() in {".json", ".yaml", ".yml", ".toml"})
                or p.name.lower() in {"claude_desktop_config.json"}
                or (p.name.lower().startswith("config")
                    and p.suffix.lower() in {".json", ".yaml", ".yml", ".toml"})
            ),
            max_depth=5,
        )
        files = sorted({p for p in [*walked, *direct_files] if p.is_file()})[:_MAX_FILES]
        truncated = truncated or len(walked) + len(direct_files) > _MAX_FILES
        configs: list[dict[str, Any]] = []
        servers: list[dict[str, Any]] = []
        for path in files:
            meta = _file_meta(path) or {"path": str(path)}
            text, text_truncated = _read_text(path)
            doc = _read_structured(path)
            discovered = self._extract_mcp_servers(doc)
            if not discovered and not re.search(
                r"mcpServers|mcp-server|mcp_server|model.?context.?protocol", text, re.I
            ):
                continue
            configs.append({**meta, "format": path.suffix.lower().lstrip("."),
                            "parsed": doc is not None, "server_count": len(discovered),
                            "content_truncated": text_truncated})
            for server_name, spec in discovered:
                command = _redact(spec.get("command", ""))
                raw_args = spec.get("args") if isinstance(spec.get("args"), list) else []
                args = self._sanitize_args(raw_args)
                env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
                combined = " ".join([command, *args])
                servers.append({
                    "config_path": str(path), "name": _clip(server_name, 256),
                    "command": command or None, "args": args[:100],
                    "env_keys": sorted(_clip(k, 256) for k in env)[:100],
                    "env_value_presence": {str(k)[:256]: bool(v) for k, v in list(env.items())[:100]},
                    "uses_latest": bool(re.search(r"@latest(?:\s|$)", combined, re.I)),
                    "uses_unpinned_ephemeral_runner": bool(
                        re.search(r"\bnpx\b.*(?:\s-y\b|--yes\b)", combined, re.I)
                        or re.search(r"\buvx\b", combined, re.I)
                    ),
                    "filesystem_paths": sorted({a for a in args if a.startswith(("/", "~/"))})[:50],
                    "capability_indicators": _risk_indicators(combined),
                })
        return {"configs": configs, "servers": servers[:_MAX_ITEMS],
                "count": len(servers), "truncated": truncated or len(servers) > _MAX_ITEMS}

    @staticmethod
    def _extract_mcp_servers(doc: Any) -> list[tuple[str, dict[str, Any]]]:
        found: list[tuple[str, dict[str, Any]]] = []

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                for key in ("mcpServers", "mcp_servers", "mcp-servers"):
                    servers = value.get(key)
                    if isinstance(servers, dict):
                        for name, spec in servers.items():
                            if isinstance(spec, dict):
                                found.append((str(name), spec))
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(doc)
        return found[:_MAX_ITEMS]

    @staticmethod
    def _sanitize_args(args: list[Any]) -> list[str]:
        result: list[str] = []
        redact_next = False
        for value in args:
            arg = _clip(value)
            if redact_next:
                result.append("[REDACTED]")
                redact_next = False
            elif arg.startswith("-") and _SENSITIVE_NAME.search(arg):
                if "=" in arg:
                    result.append(arg.split("=", 1)[0] + "=[REDACTED]")
                else:
                    result.append(arg)
                    redact_next = True
            else:
                result.append(_redact(arg))
        return result

    def _node(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for user, home in homes or [("system", Path("/var/empty"))]:
            inventory, status = _json_command(
                ["npm", "list", "-g", "--json", "--depth=0"],
                home=home, run_as_user=None if user == "system" else user,
            )
            deps = inventory.get("dependencies", {}) if isinstance(inventory, dict) else {}
            packages = [
                {"name": _clip(name, 256), "version": _clip(info.get("version"), 128),
                 "interesting": bool(_INTERESTING.search(str(name)))}
                for name, info in list(deps.items())[:_MAX_ITEMS] if isinstance(info, dict)
            ]
            cfg: dict[str, Any] = {}
            for key in ("registry", "proxy", "https-proxy", "ignore-scripts", "prefix"):
                value = _run_command(
                    ["npm", "config", "get", key], home=home, max_output=4096,
                    run_as_user=None if user == "system" else user,
                )
                if value.get("ok"):
                    cfg[key] = _redact(value.get("stdout", "").strip())
            root = _run_command(
                ["npm", "root", "-g"], home=home, max_output=4096,
                run_as_user=None if user == "system" else user,
            )
            managers = {
                "npm": {"status": status, "packages": packages,
                        "package_count": len(deps),
                        "root": _clip(root.get("stdout", "").strip(), 1024) or None},
                "pnpm": self._pnpm(home, None if user == "system" else user),
                "yarn": self._yarn(home, None if user == "system" else user),
                "bun": self._bun(home, None if user == "system" else user),
            }
            results.append({"user": user, "managers": managers, "config": cfg})
        return {"users": results, "truncated": any(
            manager.get("package_count", 0) > _MAX_ITEMS
            for result in results for manager in result["managers"].values()
        )}

    @staticmethod
    def _package_rows(deps: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"name": _clip(name, 256),
             "version": _clip(info.get("version") if isinstance(info, dict) else info, 128),
             "interesting": bool(_INTERESTING.search(str(name)))}
            for name, info in list(deps.items())[:_MAX_ITEMS]
        ]

    def _pnpm(self, home: Path, user: str | None) -> dict[str, Any]:
        doc, status = _json_command(
            ["pnpm", "list", "-g", "--depth=0", "--json"],
            home=home, run_as_user=user,
        )
        root = doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else doc
        deps = root.get("dependencies", {}) if isinstance(root, dict) else {}
        return {"status": status, "packages": self._package_rows(deps), "package_count": len(deps)}

    def _yarn(self, home: Path, user: str | None) -> dict[str, Any]:
        result = _run_command(
            ["yarn", "global", "list", "--json"], home=home, run_as_user=user,
        )
        rows: list[dict[str, Any]] = []
        for line in result.get("stdout", "").splitlines():
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            trees = (doc.get("data") or {}).get("trees", []) if isinstance(doc, dict) else []
            for tree in trees:
                name_version = str(tree.get("name") or "") if isinstance(tree, dict) else ""
                name, _, version = name_version.rpartition("@")
                rows.append({"name": _clip(name or name_version, 256), "version": _clip(version, 128),
                             "interesting": bool(_INTERESTING.search(name_version))})
        return {"status": {k: v for k, v in result.items() if k != "stdout"},
                "packages": rows[:_MAX_ITEMS], "package_count": len(rows)}

    def _bun(self, home: Path, user: str | None) -> dict[str, Any]:
        result = _run_command(
            ["bun", "pm", "ls", "-g"], home=home, run_as_user=user,
        )
        rows = []
        for line in result.get("stdout", "").splitlines():
            match = re.search(r"([^\s@]+(?:/[^\s@]+)?)@([^\s]+)", line.strip())
            if match:
                rows.append({"name": _clip(match.group(1), 256), "version": _clip(match.group(2), 128),
                             "interesting": bool(_INTERESTING.search(match.group(1)))})
        return {"status": {k: v for k, v in result.items() if k != "stdout"},
                "packages": rows[:_MAX_ITEMS], "package_count": len(rows)}

    def _python(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for user, home in homes or [("system", Path("/var/empty"))]:
            command_user = None if user == "system" else user
            packages, status = _json_command(
                ["python3", "-m", "pip", "list", "--format=json"],
                home=home, run_as_user=command_user,
            )
            editable, editable_status = _json_command(
                ["python3", "-m", "pip", "list", "--editable", "--format=json"],
                home=home, run_as_user=command_user,
            )
            config_result = _run_command(
                ["python3", "-m", "pip", "config", "list"],
                home=home, run_as_user=command_user,
            )
            inspect, inspect_status = _json_command(
                ["python3", "-m", "pip", "inspect", "--local"],
                home=home, run_as_user=command_user, max_output=4 * 1024 * 1024,
            )
            config: list[dict[str, str]] = []
            for line in config_result.get("stdout", "").splitlines()[:100]:
                key, sep, value = line.partition("=")
                if sep:
                    config.append({"key": _clip(key.strip("' \""), 256), "value": _redact(value.strip())})
            package_rows = packages if isinstance(packages, list) else []
            editable_rows = editable if isinstance(editable, list) else []
            editable_names = {
                str(item.get("name", "")).lower() for item in editable_rows if isinstance(item, dict)
            }
            provenance: list[dict[str, Any]] = []
            installed = inspect.get("installed", []) if isinstance(inspect, dict) else []
            for item in installed[:_MAX_ITEMS] if isinstance(installed, list) else []:
                if not isinstance(item, dict):
                    continue
                metadata = item.get("metadata") or {}
                direct = item.get("direct_url") or {}
                provenance.append({
                    "name": _clip(metadata.get("name"), 256),
                    "version": _clip(metadata.get("version"), 128),
                    "installer": _clip(item.get("installer"), 128) or None,
                    "requested": item.get("requested"),
                    "direct_url": _redact(direct.get("url")) if isinstance(direct, dict) and direct.get("url") else None,
                    "vcs": (direct.get("vcs_info") or {}).get("vcs") if isinstance(direct, dict) else None,
                    "editable": bool((direct.get("dir_info") or {}).get("editable")) if isinstance(direct, dict) else False,
                })
            rows = [
                {"name": _clip(item.get("name"), 256), "version": _clip(item.get("version"), 128),
                 "editable": str(item.get("name", "")).lower() in editable_names,
                 "interesting": bool(_INTERESTING.search(str(item.get("name", ""))))}
                for item in package_rows[:_MAX_ITEMS] if isinstance(item, dict)
            ]
            results.append({"user": user, "status": status, "editable_status": editable_status,
                            "inspect_status": inspect_status, "packages": rows,
                            "package_count": len(package_rows), "provenance": provenance,
                            "config": config})
        return {"users": results, "truncated": any(r["package_count"] > _MAX_ITEMS for r in results)}

    def _homebrew(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        brew_path = _command_path("brew")
        run_user: str | None = None
        run_home: Path | None = None
        if brew_path and os.geteuid() == 0:
            try:
                owner = pwd.getpwuid(os.stat(brew_path).st_uid)
                if owner.pw_uid >= 500:
                    run_user, run_home = owner.pw_name, Path(owner.pw_dir)
            except (KeyError, OSError):
                pass
        if run_user is None and homes:
            run_user, run_home = homes[0]
        formulae = _run_command(
            ["brew", "list", "--formula"], home=run_home, run_as_user=run_user,
        )
        casks = _run_command(
            ["brew", "list", "--cask"], home=run_home, run_as_user=run_user,
        )
        services = _run_command(
            ["brew", "services", "list"], home=run_home, run_as_user=run_user,
        )
        def lines(result: dict[str, Any]) -> list[str]:
            return [_clip(v.strip(), 256) for v in result.get("stdout", "").splitlines() if v.strip()][:_MAX_ITEMS]
        return {
            "run_as_user": run_user,
            "available": formulae.get("available", False),
            "formulae": lines(formulae), "casks": lines(casks),
            "services": [_redact(v) for v in lines(services)],
            "interesting": sorted({v for v in lines(formulae) + lines(casks) if _INTERESTING.search(v)}),
            "status": {"formulae": {k: v for k, v in formulae.items() if k != "stdout"},
                       "casks": {k: v for k, v in casks.items() if k != "stdout"},
                       "services": {k: v for k, v in services.items() if k != "stdout"}},
        }

    def _applications(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        roots = [("system", Path("/Applications"))] + [
            (user, home / "Applications") for user, home in homes
        ]
        rows: list[dict[str, Any]] = []
        for owner, root in roots:
            try:
                apps = sorted(root.glob("*.app"))
            except OSError:
                continue
            for app in apps[:_MAX_ITEMS - len(rows)]:
                if _INTERESTING.search(app.name):
                    rows.append({"owner": owner, **(_file_meta(app) or {"path": str(app)}),
                                 "name": app.stem})
        return {"items": rows, "count": len(rows), "filtered": True}

    def _cli_tools(self) -> dict[str, Any]:
        commands = (
            "claude", "codex", "gemini", "aider", "ollama", "cursor", "code",
            "continue", "cline", "goose", "opencode", "fabric", "sgpt",
            "mcp-inspector", "uv", "uvx", "npx", "docker", "python3", "node", "npm",
        )
        path_entries = [p for p in _get_env().get("PATH", "").split(":") if p]
        items: list[dict[str, Any]] = []
        for command in commands:
            resolved: list[str] = []
            for directory in path_entries:
                candidate = Path(directory) / command
                try:
                    if candidate.exists() and os.access(candidate, os.X_OK):
                        resolved.append(str(candidate))
                except OSError:
                    continue
            items.append({"command": command, "found": bool(resolved),
                          "resolved": resolved[0] if resolved else None,
                          "all_resolutions": resolved[:20], "shadowed": len(resolved) > 1})
        return {"items": items, "path": [
            {"position": i, "path": p, "exists": _is_dir(Path(p)),
             "world_writable": self._world_writable(Path(p))}
            for i, p in enumerate(path_entries[:100])
        ]}

    @staticmethod
    def _world_writable(path: Path) -> bool | None:
        try:
            return bool(path.stat().st_mode & stat.S_IWOTH)
        except OSError:
            return None

    def _shell_startup(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        names = (".zshrc", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile")
        for user, home in homes:
            paths = [home / name for name in names] + [home / ".config/fish/config.fish"]
            for path in paths:
                text, truncated = _read_text(path)
                if not text and not path.exists():
                    continue
                matches = []
                for number, line in enumerate(text.splitlines(), 1):
                    indicators = _risk_indicators(line, _SHELL_INDICATOR)
                    if indicators:
                        matches.append({"line": number, "sha256": _hash_line(line),
                                        "indicators": indicators})
                rows.append({"user": user, **(_file_meta(path) or {"path": str(path)}),
                             "matches": matches[:100], "truncated": truncated or len(matches) > 100})
        return {"files": rows, "count": len(rows), "contents_transmitted": False}

    def _launchd(self) -> dict[str, Any]:
        roots = [Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
        roots.extend(home / "Library/LaunchAgents" for _, home in _user_homes())
        files, truncated = _walk(roots, lambda p: p.suffix.lower() == ".plist", max_depth=1)
        rows: list[dict[str, Any]] = []
        for path in files:
            try:
                with path.open("rb") as handle:
                    doc = plistlib.load(handle)
            except Exception:
                doc = {}
            args = doc.get("ProgramArguments") if isinstance(doc, dict) else []
            args = args if isinstance(args, list) else []
            program = doc.get("Program") if isinstance(doc, dict) else None
            command = " ".join([str(program or ""), *[str(v) for v in args]])
            rows.append({
                **(_file_meta(path) or {"path": str(path)}),
                "label": _clip(doc.get("Label"), 256) if isinstance(doc, dict) else None,
                "program": _redact(program) if program else None,
                "arguments": self._sanitize_args(args)[:100],
                "run_at_load": doc.get("RunAtLoad") if isinstance(doc, dict) else None,
                "keep_alive": bool(doc.get("KeepAlive")) if isinstance(doc, dict) else False,
                "interesting": bool(_INTERESTING.search(command)),
                "command_indicators": _risk_indicators(command, _SHELL_INDICATOR),
            })
        loaded = _run_command(["launchctl", "list"])
        relevant_loaded = [
            _redact(line) for line in loaded.get("stdout", "").splitlines()
            if _INTERESTING.search(line)
        ][:_MAX_ITEMS]
        return {"items": rows, "loaded_relevant": relevant_loaded, "count": len(rows),
                "truncated": truncated, "loaded_status": {k: v for k, v in loaded.items() if k != "stdout"}}

    def _cron(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        users = ["root", *[user for user, _ in homes]]
        for user in users[:50]:
            result = _run_command(["crontab", "-u", user, "-l"], max_output=128 * 1024)
            entries = []
            for number, line in enumerate(result.get("stdout", "").splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                entries.append({"line": number, "text": _redact(stripped),
                                "sha256": _hash_line(stripped),
                                "indicators": _risk_indicators(stripped, _SHELL_INDICATOR)})
            if result.get("available"):
                rows.append({"user": user, "entries": entries[:100],
                             "status": {k: v for k, v in result.items() if k != "stdout"}})
        cron_files, truncated = _walk(
            [Path("/etc")], lambda p: p.name.startswith("cron") or "periodic" in p.parts,
            max_depth=3, max_files=200,
        )
        return {"users": rows, "system_files": [m for p in cron_files if (m := _file_meta(p))],
                "truncated": truncated}

    def _processes(self) -> dict[str, Any]:
        result = _run_command(["ps", "-axo", "pid=,ppid=,user=,command="], max_output=2 * _MAX_TEXT)
        rows = []
        for line in result.get("stdout", "").splitlines():
            match = re.match(r"\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)", line)
            if not match:
                continue
            command = match.group(4)
            if _INTERESTING.search(command) or re.search(r"\b(node|python(?:3)?|npx|uvx)\b", command, re.I):
                rows.append({"pid": int(match.group(1)), "ppid": int(match.group(2)),
                             "user": match.group(3), "command": _redact(command),
                             "interesting": bool(_INTERESTING.search(command))})
                if len(rows) >= _MAX_ITEMS:
                    break
        return {"items": rows, "count": len(rows), "filtered": True,
                "status": {k: v for k, v in result.items() if k != "stdout"}}

    def _listeners(self) -> dict[str, Any]:
        result = _run_command(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], max_output=2 * _MAX_TEXT)
        rows: list[dict[str, Any]] = []
        for line in result.get("stdout", "").splitlines()[1:]:
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue
            name = parts[8]
            bind = name.rsplit(" (LISTEN)", 1)[0]
            host, sep, port = bind.rpartition(":")
            wildcard = host in {"*", "0.0.0.0", "[::]", "::"} or host.endswith("->*")
            rows.append({"process": parts[0], "pid": int(parts[1]) if parts[1].isdigit() else None,
                         "user": parts[2], "endpoint": _clip(bind, 512),
                         "port": int(port) if sep and port.isdigit() else None,
                         "wildcard": wildcard,
                         "interesting": bool(_INTERESTING.search(parts[0]))})
            if len(rows) >= _MAX_ITEMS:
                break
        return {"items": rows, "count": len(rows), "truncated": len(rows) >= _MAX_ITEMS,
                "status": {k: v for k, v in result.items() if k != "stdout"}}

    def _browser_extensions(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        roots: list[tuple[str, str, Path]] = []
        for user, home in homes:
            roots.extend([
                (user, "chrome", home / "Library/Application Support/Google/Chrome"),
                (user, "edge", home / "Library/Application Support/Microsoft Edge"),
                (user, "brave", home / "Library/Application Support/BraveSoftware/Brave-Browser"),
            ])
        rows: list[dict[str, Any]] = []
        truncated = False
        for user, browser, root in roots:
            files, cut = _walk([root], lambda p: p.name == "manifest.json", max_depth=5,
                               max_files=max(1, _MAX_ITEMS - len(rows)))
            truncated = truncated or cut
            for path in files:
                doc = _read_json(path)
                if not isinstance(doc, dict):
                    continue
                permissions = doc.get("permissions") if isinstance(doc.get("permissions"), list) else []
                hosts = doc.get("host_permissions") if isinstance(doc.get("host_permissions"), list) else []
                all_perms = [str(v) for v in [*permissions, *hosts]]
                extension_id = next((part for part in reversed(path.parts[:-1])
                                     if re.fullmatch(r"[a-z]{32}", part)), None)
                rows.append({
                    "user": user, "browser": browser, "id": extension_id,
                    "name": _clip(doc.get("name"), 256), "version": _clip(doc.get("version"), 128),
                    "manifest_version": doc.get("manifest_version"),
                    "permissions": all_perms[:200],
                    "dangerous_permissions": sorted({
                        p for p in all_perms if p.lower() in _DANGEROUS_BROWSER_PERMS
                        or p.lower() in {"http://*/*", "https://*/*", "*://*/*"}
                    }),
                    "native_messaging": any(p.lower() == "nativemessaging" for p in all_perms),
                    "path": str(path),
                })
                if len(rows) >= _MAX_ITEMS:
                    truncated = True
                    break
        return {"items": rows, "count": len(rows), "truncated": truncated}

    def _native_messaging(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        roots = [Path("/Library/Google/Chrome/NativeMessagingHosts")]
        for _, home in homes:
            roots.extend([
                home / "Library/Application Support/Google/Chrome/NativeMessagingHosts",
                home / "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
            ])
        files, truncated = _walk(roots, lambda p: p.suffix.lower() == ".json", max_depth=1)
        rows = []
        for path in files:
            doc = _read_json(path)
            if not isinstance(doc, dict):
                continue
            executable = Path(str(doc.get("path") or ""))
            rows.append({**(_file_meta(path) or {"path": str(path)}),
                         "name": _clip(doc.get("name"), 256),
                         "description": _clip(doc.get("description"), 512),
                         "executable": str(executable) if str(executable) else None,
                         "executable_meta": _file_meta(executable) if str(executable) else None,
                         "allowed_origins": (doc.get("allowed_origins") or [])[:100],
                         "allowed_extensions": (doc.get("allowed_extensions") or [])[:100]})
        return {"items": rows, "count": len(rows), "truncated": truncated}

    def _git(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        selected = re.compile(r"^(core\.(hookspath|sshcommand)|credential\.|url\.|http\..*proxy)", re.I)

        def settings(result: dict[str, Any]) -> list[dict[str, str]]:
            found = []
            for line in result.get("stdout", "").splitlines():
                origin, _, pair = line.partition("\t")
                key, sep, value = pair.partition("=")
                if sep and selected.search(key):
                    found.append({"origin": _clip(origin, 512), "key": _redact(_clip(key, 256)),
                                  "value": "[REDACTED]" if _SENSITIVE_NAME.search(key) else _redact(value)})
            return found[:200]

        for user, home in homes or [("system", Path("/var/empty"))]:
            result = _run_command(
                ["git", "config", "--global", "--show-origin", "--list"],
                home=home, run_as_user=None if user == "system" else user,
            )
            rows.append({"user": user, "settings": settings(result),
                         "status": {k: v for k, v in result.items() if k != "stdout"}})
        system = _run_command(["git", "config", "--system", "--show-origin", "--list"])
        current = Path.cwd()
        local = _run_command(["git", "config", "--local", "--show-origin", "--list"])
        hooks = []
        try:
            for hook in sorted(
                p for p in (current / ".git/hooks").iterdir()
                if p.is_file() and not p.name.endswith(".sample")
            ):
                meta = _file_meta(hook)
                if meta:
                    hooks.append(meta)
        except OSError:
            pass
        review_files = (
            ".vscode/tasks.json", ".vscode/settings.json", ".vscode/launch.json",
            ".devcontainer/devcontainer.json", "Dockerfile", "docker-compose.yml",
            "Makefile", "package.json", "pyproject.toml", "requirements.txt",
        )
        return {
            "users": rows,
            "system": {"settings": settings(system),
                       "status": {k: v for k, v in system.items() if k != "stdout"}},
            "local": {"repository": str(current), "settings": settings(local),
                      "hooks": hooks,
                      "review_files": [m for rel in review_files
                                       if (m := _file_meta(current / rel))],
                      "status": {k: v for k, v in local.items() if k != "stdout"}},
        }

    def _credentials(self, homes: list[tuple[str, Path]]) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        truncated = False
        common = (".aws", ".azure", ".config/gcloud", ".docker", ".kube", ".ssh", ".npmrc", ".pypirc")
        for user, home in homes:
            for rel in common:
                path = home / rel
                meta = _file_meta(path)
                if meta:
                    rows.append({"user": user, "kind": "common_location", **meta})
            files, cut = _walk([home], lambda p: bool(_SECRET_FILE.search(p.name)), max_depth=4,
                               max_files=max(1, _MAX_FILES - len(rows)))
            truncated = truncated or cut
            for path in files:
                meta = _file_meta(path)
                if meta:
                    rows.append({"user": user, "kind": "name_match", **meta})
                if len(rows) >= _MAX_FILES:
                    truncated = True
                    break
        keychains = _run_command(["security", "list-keychains"], max_output=32 * 1024)
        default = _run_command(["security", "default-keychain"], max_output=4 * 1024)
        return {"locations": rows[:_MAX_FILES], "count": len(rows), "truncated": truncated,
                "contents_transmitted": False,
                "keychains": [_clip(line.strip().strip('"'), 1024)
                              for line in keychains.get("stdout", "").splitlines() if line.strip()],
                "default_keychain": _clip(default.get("stdout", "").strip().strip('"'), 1024) or None}

    def _docker(self) -> dict[str, Any]:
        raw = _run_command(["docker", "ps", "-a", "--format", "{{json .}}"])
        # Docker emits one JSON object per line, not one JSON document.
        containers = []
        for line in raw.get("stdout", "").splitlines()[:_MAX_ITEMS]:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                containers.append(item)
        ps_status = {k: v for k, v in raw.items() if k != "stdout"}
        safe_fields = ("ID", "Image", "Command", "CreatedAt", "RunningFor", "Ports",
                       "State", "Status", "Size", "Names", "Mounts", "Networks")
        safe_containers = [
            {key: _redact(item.get(key)) for key in safe_fields if item.get(key) not in (None, "")}
            for item in containers if isinstance(item, dict)
        ]
        ids = [str(item.get("ID")) for item in containers if isinstance(item, dict) and item.get("ID")][:_MAX_ITEMS]
        risky: list[dict[str, Any]] = []
        if ids:
            inspected, inspect_status = _json_command(["docker", "inspect", *ids])
            for item in inspected if isinstance(inspected, list) else []:
                host = item.get("HostConfig") or {}
                binds = host.get("Binds") or []
                risky.append({
                    "id": _clip(item.get("Id"), 128), "name": _clip(item.get("Name"), 256),
                    "privileged": bool(host.get("Privileged")),
                    "network_mode": host.get("NetworkMode"),
                    "binds": [
                        _redact(v) for v in binds
                        if "/var/run/docker.sock" in str(v) or str(v).startswith("/:/host")
                    ],
                    "cap_add": host.get("CapAdd") or [],
                    "high_risk": bool(host.get("Privileged") or host.get("NetworkMode") == "host"
                                      or any("/var/run/docker.sock" in str(v) or str(v).startswith("/:/host") for v in binds)
                                      or "SYS_ADMIN" in (host.get("CapAdd") or [])),
                })
        else:
            inspect_status = {"available": ps_status.get("available", False), "ok": True}
        inventory: dict[str, Any] = {}
        for name, args in {
            "images": ["docker", "images", "--digests", "--format", "{{json .}}"],
            "volumes": ["docker", "volume", "ls", "--format", "{{json .}}"],
            "networks": ["docker", "network", "ls", "--format", "{{json .}}"],
        }.items():
            result = _run_command(args)
            items = []
            for line in result.get("stdout", "").splitlines()[:_MAX_ITEMS]:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict):
                    items.append({k: _redact(v) for k, v in item.items() if k.lower() != "labels"})
            inventory[name] = {"items": items,
                               "status": {k: v for k, v in result.items() if k != "stdout"}}
        return {"containers": safe_containers[:_MAX_ITEMS], "count": len(containers),
                "risk_posture": risky, "inventory": inventory,
                "status": ps_status, "inspect_status": inspect_status}


__all__ = ["DeveloperSecurityCollector"]
