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

# MCP-0001 — a server whose launcher IS an interpreter, or whose args pipe a
# remote payload into one, is direct RCE the moment the editor restarts.
_MCP_INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "fish", "ash", "ksh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
}
_MCP_SHELL_ARGS = re.compile(
    r"(?:^|\s)-c(?:\s|$)|(?:^|\s)-e(?:\s|$)|-Command\b|"
    r"curl\s+.*\|\s*(?:sh|bash|zsh)\b|wget\s+.*\|\s*(?:sh|bash)\b|"
    r"iwr\s+.*\|\s*iex\b|\biex\b",
    re.I,
)
# AICLI-0001 — an autonomy/sandbox-off flag turns any prompt injection in a
# repo, issue, or web page into unattended local code execution.
_AGENT_BINARY = re.compile(
    r"\b(?:claude|codex|aider|gemini|opencode|goose|cline|openhands)\b", re.I,
)
_AGENT_AUTONOMY = re.compile(
    r"--dangerously-skip-permissions\b|--yolo\b|--auto-approve\b|--full-auto\b|"
    r"--sandbox\s+(?:off|none|danger\w*)\b|--approval-mode\s+(?:never|full-auto)\b|"
    r"--no-confirm\b",
    re.I,
)
# AIAPP-0001 — exposed inference endpoints are actively scanned; ollama:11434
# and token-less jupyter are the two most common developer-laptop findings.
_INFERENCE_SERVERS = (
    "ollama", "lm-studio", "llama-server", "llama_server", "llama.cpp",
    "vllm", "text-generation-webui", "comfyui", "open-webui", "openwebui",
    "jupyter-lab", "jupyterlab", "jupyter-notebook", "jupyter",
)

# AL-DEV-007 — the collector finds credential candidates by filename, which is
# far too weak to alert on directly. These tables turn a credential-shaped NAME
# into a graded credential STORE. Cross-platform on purpose: the same basenames
# appear under $HOME on macOS/Linux and %USERPROFILE%/%APPDATA% on Windows.
_CREDENTIAL_STORE_BASENAMES = {
    # SSH / PKI
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519_sk", "identity",
    # Cloud providers
    "credentials", "credentials.db", "access_tokens.db", "adc.json",
    "application_default_credentials.json", "accessTokens.json".lower(),
    "azureprofile.json", "msal_token_cache.json", "clouds.yaml",
    # Kubernetes / containers / registries
    ".dockercfg", "kubeconfig",
    # Package registries and build tools
    ".npmrc", ".pypirc", ".netrc", "_netrc", ".pgpass", ".my.cnf",
    ".mylogin.cnf", "gradle.properties", "settings-security.xml",
    "nuget.config", ".yarnrc.yml", ".sentryclirc", ".rediscli_auth",
    # VCS and forge CLIs
    ".git-credentials", "git-credentials",
    # Infrastructure as code
    "terraform.tfstate", ".terraformrc", "terraform.rc", "vault_pass",
    ".vault_pass",
    # AI / coding-agent credential stores — the surface this platform exists for
    ".credentials.json", "claude_desktop_config.json", "buddy-tokens.json",
    "token-store.json", "token_store.json", "auth.toml",
}
# Extensions that are credential material regardless of the file's name.
_CREDENTIAL_STORE_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".asc",
    ".gpg", ".kdbx", ".token", ".keytab", ".pkcs12",
)
# Names that hold credentials only in the right company. `config.json` is the
# Vercel/Docker token store AND the `conf` package's scratch file for every
# Node CLI ever published, so it is credible only next to a vendor CLI name.
_CONTEXTUAL_CREDENTIAL_BASENAMES = {
    "config.json", "config.yaml", "config.yml", "config.toml", "config",
    "auth.json", "auth.yaml", "auth.yml", "hosts.yml", "hosts.yaml",
    "secrets.yml", "secrets.yaml", "secrets.json", "credentials.json",
    "token.json", "token", "access_token", "session.json",
}
# `.env`, `.env.local`, `.env.production` — but never `.env.example` (below).
_ENV_FILE = re.compile(r"^\.?env(\.|$)", re.I)
# A credential-store-shaped name, credible only inside a vendor CLI config dir.
_CREDENTIAL_STORE_NAME = re.compile(
    r"credential|token[-_]?store|^auth\b|secrets?[-_]?store|apikeys?", re.I,
)
# Vendor CLIs that persist a live token in their config directory. Matched as a
# substring of the parent directory, so `com.vercel.cli` and `.config/gh` hit.
_VENDOR_CLI_TOKENS = frozenset({
    "vercel", "netlify", "heroku", "wrangler", "cloudflare", "railway",
    "supabase", "doctl", "digitalocean", "fly", "circleci", "sentry", "snyk",
    "gh", "glab", "gitlab", "github", "npm", "yarn", "pnpm", "aws", "azure",
    "gcloud", "gcp", "oci", "aliyun", "kube", "docker", "helm", "pulumi",
    "terraform", "stripe", "twilio", "sendgrid", "datadog", "pagerduty",
    "openai", "anthropic", "huggingface", "replicate", "ollama", "claude",
    "codex", "cursor", "continue", "aider", "copilot", "kimi",
})
# Derived/published artefacts: placeholders by definition.
_DERIVED_SUFFIXES = (
    ".example", ".template", ".sample", ".dist", ".default", ".tmpl",
    ".tpl", ".stub", ".fixture", ".test", ".spec", "-example", "-template",
    "-sample", ".bak", ".orig",
)
# Source, docs, and compiled output. A `.py` is never a credential store, and
# `tokenizer.py` / `libtokenizers-*.rlib` are why this rule used to be useless.
_NON_CREDENTIAL_SUFFIXES = (
    ".py", ".pyc", ".pyo", ".pyi", ".rs", ".rlib", ".rmeta", ".d", ".go",
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".map", ".java", ".class",
    ".jar", ".kt", ".swift", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rb",
    ".php", ".pl", ".lua", ".sh", ".bash", ".zsh", ".ps1", ".psm1",
    ".md", ".rst", ".txt", ".adoc", ".html", ".htm", ".css", ".scss",
    ".o", ".a", ".so", ".dylib", ".dll", ".exe", ".bin", ".wasm",
    ".zip", ".gz", ".tar", ".tgz", ".7z", ".rar", ".bz2", ".xz", ".whl",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
    ".lock", ".sum", ".mod", ".snap", ".log", ".csv", ".tsv",
)
# Configuration files whose names collide with the collector's `config.json`
# pattern but which never hold credentials.
_FALSE_FRIEND_BASENAMES = {
    "tsconfig.json", "jsconfig.json", "package.json", "package-lock.json",
    "composer.json", "manifest.json", "angular.json", "nx.json",
    "babel.config.json", "jest.config.json", "eslint.config.json",
    "tslint.json", "renovate.json", "biome.json", "deno.json",
    "launch.json", "settings.json", "extensions.json", "tasks.json",
}
# Build output, dependency trees, caches, and VCS internals.
_EXCLUDED_PATH_SEGMENTS = {
    "node_modules", "__pycache__", "site-packages", "dist-packages",
    "bower_components", "vendor", "third_party", "external",
    ".git", ".svn", ".hg", ".venv", "venv", "virtualenv", ".tox", ".nox",
    "target", "build", "dist", "out", "bin", "obj", ".next", ".nuxt",
    ".output", ".parcel-cache", ".turbo", ".gradle", ".m2", ".ivy2",
    "deriveddata", "pods", ".cargo", ".rustup", ".stack", ".cabal",
    ".cache", "caches", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "coverage", "htmlcov", ".terraform",
    # Fixture and example trees: credential-shaped names are the point.
    "tests", "test", "testdata", "test-data", "__tests__", "spec", "specs",
    "fixtures", "fixture", "examples", "example", "samples", "sample",
    "mocks", "__mocks__", "demo", "demos", "task-deps", "testcases",
}
# Detection corpora, wordlists, and exploit collections: they describe secrets.
_CORPUS_SEGMENTS = {
    "nuclei-templates", "seclists", "payloadsallthethings", "wordlists",
    "wordlist", "exploitdb", "exploit-db", "metasploit-framework",
    "atomic-red-team", "sigma", "detection-rules", "yara-rules",
    "fuzzdb", "dirbuster", "rockyou", "trufflehog", "gitleaks",
    "secretfinder", "semgrep-rules", "nuclei", "templates",
}
# Key material and registry tokens: a real finding in any location, so these
# bypass the corpus-density suppression below.
_HARD_CREDENTIAL_BASENAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519_sk", "identity",
    "credentials", "credentials.db", "access_tokens.db", ".git-credentials",
    "git-credentials", ".npmrc", ".pypirc", ".netrc", "_netrc", ".pgpass",
    ".my.cnf", ".mylogin.cnf",
}
# OS and user container directories. These hold unrelated applications, so a
# high credential-name density inside them says nothing about any one app and
# must never mark the whole tree as a corpus.
_CORPUS_ROOT_EXEMPT = {
    "users", "home", "var", "opt", "etc", "usr", "private", "volumes",
    "library", "application support", "appdata", "roaming", "local",
    "localnow", "documents", "downloads", "desktop", "preferences",
    "containers", "group containers", "public", "shared", "programdata",
    ".config", ".local", ".cache", ".share", "share",
}
# A tree holding this many credential-shaped names is a corpus, not a vault.
_CORPUS_DENSITY_THRESHOLD = 8
# Credential stores are small; beyond this a match is an archive or artefact.
_CREDENTIAL_MAX_BYTES = 1024 * 1024
_CREDENTIAL_SAMPLE_LIMIT = 10

RULE_SPECS: dict[str, dict[str, str]] = {
    "AL-DEV-001": {"asset": "editor extension", "condition": "auto activation AND command execution AND side-loaded/unverified publisher", "boundary": "all three anchors are required"},
    "AL-DEV-002": {"asset": "MCP server", "condition": "mutable @latest reference OR unpinned ephemeral runner with sensitive/capability access", "boundary": "an ephemeral runner alone is not sufficient"},
    "AL-DEV-003": {"asset": "PATH directory", "condition": "world-writable executable search path entry", "boundary": "unknown or non-world-writable modes are silent"},
    "AL-DEV-004": {"asset": "browser extension", "condition": "native messaging AND at least one dangerous browser/host permission", "boundary": "both anchors are required"},
    "AL-DEV-005": {"asset": "native messaging host", "condition": "temporary executable path OR group/world-writable executable", "boundary": "ordinary 0755 read/execute access is safe"},
    "AL-DEV-006": {"asset": "Git configuration", "condition": "core.hooksPath or core.sshCommand execution override", "boundary": "unrelated Git settings are silent"},
    "AL-DEV-007": {"asset": "credential store", "condition": "group/other read or write permission on a file that grades as a real credential store (known store name, key material, env file, or vendor CLI token store), rolled up per directory", "boundary": "owner-only 0600, directories, *.example/*.template placeholders, source and build output, test fixtures, and credential-name-dense corpora are silent"},
    "AL-DEV-008": {"asset": "developer listener", "condition": "interesting developer/AI process AND wildcard bind", "boundary": "loopback or unrelated wildcard listeners are silent"},
    "AL-DEV-009": {"asset": "developer container", "condition": "privileged, host network, Docker socket/root bind, or SYS_ADMIN posture", "boundary": "ordinary bridge containers are silent"},
    "AL-DEV-010": {"asset": "MCP server", "condition": "launcher command is a shell/interpreter OR args pipe a remote payload into one (curl|sh, -c, iex)", "boundary": "a pinned npx/node/python server without inline-shell args is silent"},
    "AL-DEV-011": {"asset": "coding agent process", "condition": "a known agent binary running with an autonomy or sandbox-disabling flag", "boundary": "an agent with no autonomy flag, or an unrelated process carrying such a flag, is silent"},
    "AL-DEV-012": {"asset": "local inference server", "condition": "a known model/inference server listening on a wildcard (all-interface) bind", "boundary": "the same server bound to loopback, or a non-inference wildcard listener, is silent"},
    "AL-DEV-013": {"asset": "Git configuration", "condition": "a url.<base>.insteadOf / pushInsteadOf remote-rewrite override is configured", "boundary": "hooksPath/sshCommand (AL-DEV-006) and unrelated Git settings are silent here"},
    "AL-DEV-014": {"asset": "agent instruction file", "condition": "a repo-level agent instruction file (CLAUDE.md/AGENTS.md/.cursorrules/…) contains prompt-injection or exfiltration directives", "boundary": "instruction files with no matched injection indicator are silent"},
    "AL-DEV-015": {"asset": "editor workspace", "condition": "a repo VS Code workspace auto-runs a task on folder-open, disables workspace trust, injects terminal env, or overrides a tool binary path", "boundary": "workspace files with no auto-exec / trust-bypass / override signal are silent"},
    "AL-DEV-016": {"asset": "model artifact", "condition": "a pickle-format model artifact in an untrusted location has a dangerous unpickling opcode (high) or is a container format that cannot be scanned in place (medium)", "boundary": "a raw pickle that scans clean, and trusted-path artifacts, are silent"},
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
    fp: str | None = None,
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
        "false_positive_notes": fp or "Confirm the component and execution path against the approved developer tooling baseline.",
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


def _git_settings(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten every Git setting the collector emits across user/system/local scopes."""
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
    return settings


def _git_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    settings = _git_settings(capabilities)
    if not settings:
        return []
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


def _credential_grade(row: dict[str, Any], corpus_roots: frozenset[str]) -> tuple[str, str] | None:
    """Classify one credential-location row into a confidence grade.

    The collector finds candidates by filename (`_SECRET_FILE`), which alone is
    far too weak an anchor: on a developer laptop it matches NLP tokenizers,
    `tsconfig.json`, Rust build artifacts, and every rule file in a cloned
    detection corpus. Grading requires the row to look like an actual
    credential *store*, not merely a credential-shaped *name*.

    Returns (grade, reason) or None when the row must stay silent.
      vault    — a known credential store (`.aws/credentials`, `id_rsa`, `.npmrc`)
      declared — a credential directory the collector enumerated on purpose
      named    — a credential-store-shaped name inside a vendor CLI config dir
    """
    path = str(row.get("path") or "")
    if not path:
        return None
    normalized = path.replace("\\", "/")
    segments = [segment.lower() for segment in normalized.split("/") if segment]
    if not segments:
        return None
    basename = segments[-1]
    parent = segments[-2] if len(segments) > 1 else ""

    # A file the collector enumerated from its own known-locations list is a
    # credential store by construction — it never came from a name walk.
    if str(row.get("kind") or "") == "common_location":
        return ("declared", "known credential location")

    # Derived artefacts (.env.example, config.toml.sample) are published on
    # purpose and hold placeholders. They are the single largest FP class.
    if any(basename.endswith(suffix) for suffix in _DERIVED_SUFFIXES):
        return None
    # Source, documentation, and compiled output are not credential stores no
    # matter what they are called — `tokenizer.py`, `libtokenizers-*.rlib`.
    if any(basename.endswith(suffix) for suffix in _NON_CREDENTIAL_SUFFIXES):
        return None
    if basename in _FALSE_FRIEND_BASENAMES:
        return None
    # Build output, dependency trees, and caches restate upstream files; an
    # exposure there is a property of the source, not a distinct finding.
    if any(segment in _EXCLUDED_PATH_SEGMENTS for segment in segments):
        return None
    # A credential store is small. Multi-megabyte matches are archives or
    # build artefacts; empty files hold nothing to steal.
    size = row.get("size_bytes")
    if isinstance(size, (int, float)) and (size <= 0 or size > _CREDENTIAL_MAX_BYTES):
        return None

    # Private-key and registry-token material is a real finding wherever it
    # lands, so it is graded BEFORE the corpus checks below. A stray `id_rsa`
    # inside a cloned repository still leaks the key.
    if basename in _HARD_CREDENTIAL_BASENAMES or any(
        basename.endswith(suffix) for suffix in _CREDENTIAL_STORE_SUFFIXES
    ):
        return ("vault", f"credential material ({basename})")

    # Signature/wordlist corpora describe secrets; they do not contain them.
    # `corpus_roots` adds the same verdict for dense trees we have not seen
    # before, so a customer's private template repo is covered too.
    if any(segment in _CORPUS_SEGMENTS for segment in segments):
        return None
    if any(root in corpus_roots for root in _path_roots(segments)):
        return None

    if basename in _CREDENTIAL_STORE_BASENAMES:
        return ("vault", f"known credential store ({basename})")
    if _ENV_FILE.match(basename):
        return ("vault", "environment file with inline secrets")
    if _is_vendor_cli_dir(parent):
        if basename in _CONTEXTUAL_CREDENTIAL_BASENAMES:
            return ("vault", f"vendor CLI credential store ({parent}/{basename})")
        if _CREDENTIAL_STORE_NAME.search(basename):
            return ("named", f"credential-shaped name in a vendor CLI directory "
                             f"({parent}/{basename})")
    return None


def _is_vendor_cli_dir(directory: str) -> bool:
    """True when a directory name identifies a CLI that persists a live token.

    Matched on whole name tokens rather than substrings: `com.vercel.cli` and
    `.config/gh` must hit, while `highlight-js` must not match `gh`.
    """
    tokens = {token for token in re.split(r"[^a-z0-9]+", directory.lower()) if token}
    return bool(tokens & _VENDOR_CLI_TOKENS)


def _path_roots(segments: list[str]) -> tuple[str, ...]:
    """Candidate project roots for a path, used for corpus-density lookup.

    Starts at depth 3 and skips OS container directories, so `$HOME` and
    `~/Library/Application Support` can never themselves be graded as a
    corpus — only the project trees inside them can.
    """
    roots = []
    for depth in range(3, min(len(segments), 6) + 1):
        if segments[depth - 1] in _CORPUS_ROOT_EXEMPT:
            continue
        roots.append("/".join(segments[:depth]))
    return tuple(roots)


def _corpus_roots(rows: list[dict[str, Any]]) -> frozenset[str]:
    """Directory trees dense enough in credential-shaped names to be a corpus.

    Real credential stores are sparse — a host has one `~/.aws/credentials`,
    not 141 of them. A tree holding many name-matched candidates is a rule
    pack, a wordlist, or a source repository whose files merely mention
    tokens. This generalizes the well-known-corpus list to trees we have
    never seen, which is what makes the rule portable across customers.
    """
    density: dict[str, int] = {}
    for row in rows:
        if str(row.get("kind") or "") != "name_match":
            continue
        segments = [s.lower() for s in str(row.get("path") or "").replace("\\", "/").split("/") if s]
        for root in _path_roots(segments):
            density[root] = density.get(root, 0) + 1
    return frozenset(
        root for root, count in density.items() if count >= _CORPUS_DENSITY_THRESHOLD
    )


def _credential_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    """AL-DEV-007 — exposed credential stores, graded and rolled up per directory.

    Three anchors are required, not one: the mode must actually expose the file
    to group or other, the object must grade as a credential *store*, and it
    must not sit in a context (build output, corpus, fixture, example) where a
    credential-shaped name is expected. Findings are keyed to the containing
    directory so one misconfigured folder is one finding, not N.
    """
    rows = _items(capabilities, "credential_locations", "locations")
    corpus_roots = _corpus_roots(rows)

    groups: dict[tuple[str, str, bool], dict[str, Any]] = {}
    for row in rows:
        mode = row.get("mode")
        if not _mode_exposes_secret(mode):
            continue
        graded = _credential_grade(row, corpus_roots)
        if graded is None:
            continue
        grade, reason = graded
        writable = _mode_is_group_or_world_writable(mode)
        path = str(row.get("path") or "unknown")
        directory = path.replace("\\", "/").rsplit("/", 1)[0] or path
        key = (directory, grade, writable)
        bucket = groups.setdefault(key, {
            "directory": directory, "grade": grade, "writable": writable,
            "paths": [], "modes": set(), "reasons": set(), "user": row.get("user"),
        })
        bucket["paths"].append(path)
        bucket["modes"].add(str(mode))
        bucket["reasons"].add(reason)

    hits = []
    for (directory, grade, writable), bucket in sorted(groups.items()):
        paths = sorted(bucket["paths"])
        if writable:
            severity = "critical"
            exposure = "writable by its group or by other users"
            action = (
                "Restrict the file to its owner (chmod 600), rotate the credentials it "
                "holds, and audit for modification — a writable credential store can be "
                "replaced as well as read."
            )
        elif grade in ("vault", "declared"):
            severity = "high"
            exposure = "readable by its group or by other users"
            action = (
                "Restrict the file to its owner (chmod 600) and rotate the credentials "
                "it holds if other local accounts may have read it."
            )
        else:
            severity = "medium"
            exposure = "readable by its group or by other users"
            action = (
                "Confirm the file holds a live credential, then restrict it to its "
                "owner (chmod 600) and rotate if it was exposed."
            )
        count = len(paths)
        subject = paths[0] if count == 1 else f"{count} credential files in {directory}"
        hits.append(_hit(
            "AL-DEV-007", severity, "Credential store permissions expose secrets",
            f"{subject} is {exposure} ({', '.join(sorted(bucket['modes']))}). "
            f"Matched because: {'; '.join(sorted(bucket['reasons']))}.",
            {
                "object": directory,
                "member_count": count,
                "sample_paths": paths[:_CREDENTIAL_SAMPLE_LIMIT],
                "modes": sorted(bucket["modes"]),
                "grade": grade,
                "reasons": sorted(bucket["reasons"]),
                "group_or_world_writable": writable,
                "user": bucket["user"],
            },
            technique="T1552.001", tactic="Credential Access",
            action=action,
            item_key=f"credential_exposure:{directory}:{grade}:{'w' if writable else 'r'}",
            fp=(
                "Grading requires a real credential store, so build output, cloned rule "
                "corpora, test fixtures, and *.example templates are already excluded. "
                "Remaining false positives are vendor CLI configs that hold no live "
                "token — confirm the file's contents before rotating."
            ),
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


def _mcp_shell_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "mcp_servers", "servers"):
        name = str(row.get("name") or "unknown")
        command = str(row.get("command") or "")
        binary = command.rsplit("/", 1)[-1].strip().lower()
        args = [str(value) for value in (row.get("args") or [])]
        combined = " ".join([command, *args])
        interpreter = binary in _MCP_INTERPRETERS
        piped = bool(_MCP_SHELL_ARGS.search(combined))
        if not (interpreter or piped):
            continue
        hits.append(_hit(
            "AL-DEV-010", "critical", "MCP server launches a shell or inline interpreter",
            "An MCP server is configured to run a shell/interpreter directly or to pipe a remote "
            "payload into one, which executes with the developer's full privileges on every editor launch.",
            {"name": name, "config_path": row.get("config_path"), "command": command or None,
             "args": args[:100], "launcher_is_interpreter": interpreter, "pipes_remote_payload": piped,
             "capability_indicators": [str(v) for v in (row.get("capability_indicators") or [])]},
            technique="T1059.004", tactic="Execution",
            action="Quarantine the MCP config, replace the shell launcher with a pinned binary/package, and re-approve the server manually.",
            item_key=f"mcp_shell:{row.get('config_path')}:{name}",
            fp="Rare; a few wrappers legitimately use `sh -c`. Require a reviewed, owner-approved exception rather than allowlisting the shell mechanism.",
        ))
    return hits


def _agent_autonomy_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "processes"):
        command = str(row.get("command") or "")
        agent = _AGENT_BINARY.search(command)
        autonomy = _AGENT_AUTONOMY.search(command)
        if not (agent and autonomy):
            continue
        agent_name = agent.group(0).lower()
        flags = sorted({m.group(0).lower() for m in _AGENT_AUTONOMY.finditer(command)})
        # Deliberately exclude the volatile PID from evidence so the fingerprint
        # does not churn every snapshot (object_hash volatile-field discipline).
        hits.append(_hit(
            "AL-DEV-011", "high", "Coding agent running with approvals or sandbox disabled",
            "A known AI coding agent is running with an autonomy or sandbox-disabling flag, which converts "
            "any prompt injection in a repository, issue, or web page into unattended local code execution.",
            {"agent": agent_name, "user": row.get("user"), "flags": flags,
             "interesting": bool(row.get("interesting"))},
            technique="T1204", tactic="Execution",
            action="Verify the session was human-initiated on a non-privileged host; review the agent transcript and file writes, and block autonomy flags on CI runners.",
            item_key=f"agent_autonomy:{agent_name}:{'|'.join(flags)}",
            fp="Sanctioned sandboxed CI use is legitimate — allowlist by host role and container boundary, not by disabling the rule.",
        ))
    return hits


def _inference_exposure_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "listening_ports"):
        process = str(row.get("process") or "").lower()
        if not process or not row.get("wildcard"):
            continue
        matched = next(
            (name for name in _INFERENCE_SERVERS
             if process == name or (len(process) >= 6 and (process.startswith(name) or name.startswith(process)))),
            None,
        )
        if not matched:
            continue
        endpoint = str(row.get("endpoint") or row.get("port") or "unknown")
        hits.append(_hit(
            "AL-DEV-012", "high", "Local inference server is exposed on all interfaces",
            "A local model/inference server is bound to a wildcard address and is reachable from the network; "
            "exposed inference endpoints are actively scanned and are often unauthenticated.",
            {"process": process, "server": matched, "endpoint": endpoint, "port": row.get("port"),
             "user": row.get("user"), "wildcard": True},
            technique="T1190", tactic="Initial Access",
            action="Rebind the server to 127.0.0.1, require authentication, and review `connections` for prior external hits.",
            item_key=f"inference_exposed:{matched}:{row.get('port') or endpoint}",
            fp="Intentional lab hosts exist — require a documented exception plus a network ACL rather than a blanket allowlist.",
        ))
    return hits


def _git_url_rewrite_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    risky = [
        row for row in _git_settings(capabilities)
        if (key := str(row.get("key") or "").lower()).startswith("url.")
        and (key.endswith(".insteadof") or key.endswith(".pushinsteadof"))
    ]
    if not risky:
        return []
    keys = sorted({str(row.get("key")) for row in risky})
    return [_hit(
        "AL-DEV-013", "medium", "Git URL-rewrite override is configured",
        "Git is configured to transparently rewrite remote URLs (insteadOf/pushInsteadOf), which can silently "
        "redirect clones and dependency fetches to an attacker-controlled host.",
        {"settings": risky[:20], "keys": keys}, technique="T1195.002", tactic="Initial Access",
        action="Confirm each rewrite is managed and expected; the redirect target is the value that matters — remove any rewrite pointing off a trusted host.",
        item_key=f"git_url_rewrite:{','.join(keys)}",
        fp="A local https→ssh convenience rewrite is common and benign — triage on the rewrite *target*, and allowlist known-good pairs.",
    )]


_INJECTION_STRONG = {"ignore_previous", "hide_from_user", "hidden_text"}


def _workspace_config_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "workspace_config", "files"):
        indicators = sorted({str(value) for value in (row.get("indicators") or [])})
        if not indicators:
            continue
        filename = str(row.get("filename") or "workspace config")
        repo = row.get("repo")
        hits.append(_hit(
            "AL-DEV-015", "high", "Editor workspace auto-executes or overrides tool binaries",
            "A repository VS Code workspace runs a task on folder-open, disables workspace trust, injects "
            "terminal environment, or overrides a language/tool binary path — each is a remote-code-execution "
            "path the moment a hostile repository is opened.",
            {"filename": filename, "repo": repo, "editor": row.get("editor"), "user": row.get("user"),
             "indicators": indicators,
             "signals": [s for s in (row.get("signals") or []) if isinstance(s, dict)][:20]},
            technique="T1204.002", tactic="Execution",
            action="Do not trust the workspace; review the flagged tasks/overrides before opening it, and disable workspace-trust auto-grant by policy.",
            item_key=f"workspace_config:{repo}:{filename}",
            fp="Monorepos with legitimate folderOpen build tasks exist — allowlist by repo, not globally.",
        ))
    return hits


def _model_artifact_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "model_artifacts"):
        scan = row.get("scan") if isinstance(row.get("scan"), dict) else {}
        dangerous = bool(scan.get("dangerous"))
        unavailable = bool(scan.get("scan_unavailable"))
        if not (dangerous or unavailable):
            continue
        path = row.get("path")
        if dangerous:
            severity = "high"
            summary = ("references a dangerous module during unpickling "
                       f"({', '.join(scan.get('dangerous_modules') or []) or 'code-exec opcode'})")
        else:
            severity = "medium"
            summary = "is a pickle-based container format that cannot be verified in place"
        hits.append(_hit(
            "AL-DEV-016", severity, "Untrusted pickle-format model artifact",
            f"A model artifact in an untrusted location {summary}; loading a pickle-based model "
            "deserializes arbitrary code, so this is code execution at model load.",
            {"path": path, "extension": row.get("extension"), "format": row.get("format"),
             "location": row.get("location"), "user": row.get("user"),
             "dangerous": dangerous, "scan_unavailable": unavailable,
             "dangerous_modules": scan.get("dangerous_modules") or [],
             "globals": (scan.get("globals") or [])[:20]},
            technique="T1195.002", tactic="Execution",
            action="Quarantine the file, re-source it from a trusted registry, and prefer safetensors; treat the host as exposed if the model was already loaded.",
            item_key=f"model_artifact:{path}",
            fp="Internal training artifacts are legitimate — allowlist by internal storage path via ATTACKLENS_DEVSEC_MODEL_REGISTRIES.",
        ))
    return hits


def _agent_instruction_hits(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for row in _items(capabilities, "agent_instructions", "files"):
        indicators = sorted({str(value) for value in (row.get("indicators") or [])})
        if not indicators:
            continue
        filename = str(row.get("filename") or "agent instruction file")
        repo = row.get("repo")
        # A strong injection verb (override / hide-from-user / hidden unicode) is
        # high; a lone read-secret or egress hint in agent context is medium.
        severity = "high" if _INJECTION_STRONG.intersection(indicators) else "medium"
        hits.append(_hit(
            "AL-DEV-014", severity, "Repo agent-instruction file contains injection or exfil directives",
            "A repository-level AI-agent instruction file carries prompt-injection or data-exfiltration "
            "language, which is read as agent context the moment a coding agent opens the repository.",
            {"filename": filename, "repo": repo, "user": row.get("user"),
             "indicators": indicators, "match_count": row.get("match_count"),
             "matches": [m for m in (row.get("matches") or []) if isinstance(m, dict)][:20]},
            technique="T1204", tactic="Execution",
            action="Block agent runs in this repository, review the flagged lines, and alert the repo owner; treat the host as exposed if an agent already ran there.",
            item_key=f"agent_instruction:{repo}:{filename}",
            fp="Security-research repos and prompt-engineering docs legitimately contain sample injection payloads — allowlist by repo, not globally.",
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
        *_mcp_shell_hits(capabilities),
        *_path_hits(capabilities),
        *_browser_hits(capabilities),
        *_git_hits(capabilities),
        *_git_url_rewrite_hits(capabilities),
        *_credential_hits(capabilities),
        *_runtime_hits(capabilities),
        *_agent_autonomy_hits(capabilities),
        *_inference_exposure_hits(capabilities),
        *_agent_instruction_hits(capabilities),
        *_workspace_config_hits(capabilities),
        *_model_artifact_hits(capabilities),
    ]
    asset = hostname or agent_id
    for hit in hits:
        hit["affected_asset"] = asset
    return hits


__all__ = ["RULE_SPECS", "analyze"]
