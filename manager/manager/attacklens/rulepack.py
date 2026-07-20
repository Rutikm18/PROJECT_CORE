# ruff: noqa: E501
"""
YAML-backed telemetry rule-pack detector.

The manager/rulepacks/fleet_telemetry rule pack is intentionally portable: many
conditions are prose such as "no matching change ticket" or "against baseline".
This module evaluates the subset that can be proven from the telemetry payload
currently being processed, and keeps the YAML metadata attached to the emitted
finding so analysts can see which source rule fired.

Adding more rules is data-first:
  * add/edit YAML under manager/rulepacks/fleet_telemetry/
  * for prose/baseline conditions, add a small evaluator here once the manager
    receives the needed field or has an allowlist/baseline source.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .rules import get_tactic, severity_to_score

log = logging.getLogger("manager.attacklens.rulepack")


RuleFn = Callable[["RulePackDetector", str, dict, dict | None], dict | None]


_AUTHORITATIVE_SIGNAL_TERMS = (
    "malicious", "threat", "ioc", "feed", "kev", "cisa", "nvd", "epss",
    "osv", "registry_hash", "signature_valid == false", "remote_thread",
    "remote_memory", "log_cleared", "mfa_enforced transitions",
)
_CONTEXT_SIGNAL_TERMS = (
    "baseline", "historical", "approved", "allowlist", "previous", "old_",
    "transition", "transitions", "first_seen", "sla", "policy",
)
_INTEGRATION_TERMS: dict[str, tuple[str, ...]] = {
    "threat_intel": ("threat", "ioc", "malicious", "feed", "abuseipdb", "urlhaus", "threatfox"),
    "vulnerability_intel": ("kev", "cisa", "nvd", "epss", "osv", "cve", "vulnerability"),
    "asset_policy": ("approved", "allowlist", "baseline", "policy", "inventory", "registry"),
}
_DEFAULT_TRUSTED_INTEGRATIONS = {
    "abuseipdb", "virustotal", "urlhaus", "threatfox", "feodo", "cisa",
    "nvd", "epss", "osv", "crowdstrike", "falcon", "sentinelone",
    "defender", "mdatp", "carbonblack", "osquery", "santa",
}


@dataclass(frozen=True)
class RulePackRule:
    id: str
    section: str
    title: str
    description: str
    severity: str
    mitre_attack: list[str]
    detection: dict[str, Any]
    false_positives: list[str]
    enrichment_sources: list[str]
    response_actions: list[str]
    status: str
    source_file: str


_SECTION_ALIASES: dict[str, str] = {
    # Agent collector key. Rule-pack filenames use the analyst-facing category.
    "openfiles": "open_files",
}


def _canonical_section(section: str) -> str:
    return _SECTION_ALIASES.get(str(section or ""), str(section or ""))


_SECTION_CATEGORY: dict[str, str] = {
    "agent_health": "agent_health",
    "apps": "app",
    "arp": "arp",
    "battery": "battery",
    "binaries": "binary",
    "configs": "config",
    "connections": "connection",
    "containers": "container",
    "hardware": "hardware",
    "metrics": "behavioral",
    "mounts": "mount",
    "network": "network",
    "openfiles": "open_file",
    "open_files": "open_file",
    "packages": "package",
    "ports": "port",
    "processes": "process",
    "sbom": "sbom",
    "security": "security",
    "services": "service",
    "storage": "storage",
    "sysctl": "sysctl",
    "tasks": "task",
    "users": "user",
}

_IDENTITY_FIELDS = (
    "item_key", "id", "name", "username", "process_name", "parent_process_name",
    "child_process_name", "pid", "path", "exec_path", "binary_path", "target_path",
    "install_path", "file_path", "config_file", "package_name", "component_name",
    "service_name", "task_name", "label", "port", "listening_port", "dest_ip",
    "remote_addr", "remote_host", "source_ip", "device_id", "device_serial",
    "volume_id", "mount_point", "sysctl_key",
)

_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "account_privilege_level": ("account_privilege_level", "privilege_level", "role"),
    "account_type": ("account_type", "type", "kind"),
    "actor": ("actor", "user", "username"),
    "app_id": ("app_id", "bundle_id", "id", "name"),
    "battery_serial": ("battery_serial", "serial", "serial_number"),
    "binary_path": ("binary_path", "path", "program", "target_path", "exec_path"),
    "bssid": ("bssid", "ap_bssid"),
    "build_target": ("build_target", "target", "environment"),
    "code_signature_valid": ("code_signature_valid", "signature_valid", "signed"),
    "command_line": ("command_line", "cmdline", "cmd", "command", "new_command"),
    "component_license": ("component_license", "license"),
    "component_name": ("component_name", "name", "package_name"),
    "config_file": ("config_file", "path"),
    "config_key": ("config_key", "key"),
    "content": ("content", "value", "new_content"),
    "core_pattern": ("core_pattern", "kernel.core_pattern", "current_value", "value"),
    "current_binary_path": ("current_binary_path", "binary_path", "path", "program"),
    "current_gateway": ("current_gateway", "gateway", "default_gateway"),
    "current_ptrace_scope": ("current_ptrace_scope", "ptrace_scope", "current_value", "value"),
    "current_value": ("current_value", "value", "new_value"),
    "days_since_disclosure": ("days_since_disclosure", "age_days"),
    "days_since_last_login": ("days_since_last_login", "last_login_days"),
    "dest_domain": ("dest_domain", "domain", "remote_domain"),
    "dest_ip": ("dest_ip", "remote_ip", "ip", "remote_addr", "raddr"),
    "dest_port": ("dest_port", "remote_port", "port"),
    "device_class": ("device_class", "class", "type"),
    "device_type": ("device_type", "type"),
    "direction_of_change": ("direction_of_change", "change_direction"),
    "domain_name_entropy": ("domain_name_entropy", "entropy"),
    "domain_registration_age_days": ("domain_registration_age_days", "registration_age_days"),
    "encryption_status_new": ("encryption_status_new", "encryption_status", "new_encryption_status"),
    "encryption_status_old": ("encryption_status_old", "old_encryption_status"),
    "event_type": ("event_type", "type", "event"),
    "exec_path": ("exec_path", "path", "exe", "binary_path", "target_path", "program"),
    "file_path": ("file_path", "path"),
    "fingerprinted_protocol": ("fingerprinted_protocol", "protocol", "app_protocol"),
    "firewall": ("firewall", "firewall_state"),
    "firmware_version": ("firmware_version", "firmware"),
    "gpt_hidden_attribute": ("gpt_hidden_attribute", "hidden", "is_hidden"),
    "group_name": ("group_name", "group"),
    "hash_changed": ("hash_changed", "content_changed", "changed"),
    "host_policy_class": ("host_policy_class", "policy_class"),
    "host_role": ("host_role", "role"),
    "image": ("image", "image_name"),
    "image_name": ("image_name", "image"),
    "install_path": ("install_path", "path"),
    "installed_hash": ("installed_hash", "sha256", "hash"),
    "listening_port": ("listening_port", "port"),
    "log_channel": ("log_channel", "channel"),
    "logon_type": ("logon_type", "login_type"),
    "mfa_enforced": ("mfa_enforced", "mfa_enabled"),
    "filesystem_type": ("filesystem_type", "fstype", "filesystem", "type"),
    "mount_options": ("mount_options", "options"),
    "mount_point": ("mount_point", "mountpoint", "path"),
    "mount_source": ("mount_source", "source", "host_path"),
    "mount_type": ("mount_type", "type", "fstype", "filesystem"),
    "new_command": ("new_command", "command", "cmd", "cmdline"),
    "new_state": ("new_state", "state", "status"),
    "new_value": ("new_value", "value", "current_value"),
    "old_value": ("old_value", "previous_value"),
    "opening_process": ("opening_process", "process_name", "process", "name"),
    "owning_process_path": ("owning_process_path", "process_path", "path", "exe"),
    "package_name": ("package_name", "name"),
    "parent_process_name": ("parent_process_name", "parent_name", "parent_process"),
    "patch_available": ("patch_available", "fix_available"),
    "permission_mode": ("permission_mode", "mode", "permissions"),
    "port_range_size": ("port_range_size",),
    "privileged": ("privileged", "is_privileged"),
    "process_name": ("process_name", "name", "process", "binary"),
    "process_uid": ("process_uid", "uid", "user_id"),
    "qtype": ("qtype", "query_type", "dns_qtype"),
    "partition_size_gb": ("partition_size_gb", "total_gb", "size_gb"),
    "quota_usage_pct": ("quota_usage_pct", "usage_pct", "used_pct", "pct"),
    "registry_hash": ("registry_hash", "expected_hash"),
    "registry_hostname": ("registry_hostname", "registry", "image_registry"),
    "remote_host": ("remote_host", "host", "server"),
    "rule_action": ("rule_action", "action"),
    "rule_direction": ("rule_direction", "direction"),
    "run_as_account": ("run_as_account", "user", "username", "run_user"),
    "security_agent_service_state": ("security_agent_service_state", "agent_state", "state"),
    "service_create_event": ("service_create_event", "created", "create_event"),
    "service_name": ("service_name", "name", "label"),
    "sha256": ("sha256", "hash", "binary_hash"),
    "signature_valid": ("signature_valid", "code_signature_valid", "signed"),
    "source_cidr": ("source_cidr", "source", "src_cidr"),
    "source_repo": ("source_repo", "repository", "repo", "source"),
    "ssid": ("ssid", "wifi_ssid"),
    "start_type_new": ("start_type_new", "start_type", "new_start_type"),
    "start_type_old": ("start_type_old", "old_start_type", "previous_start_type"),
    "sysctl_key": ("sysctl_key", "key", "name"),
    "target_first_seen_days": ("target_first_seen_days", "binary_first_seen_days"),
    "target_path": ("target_path", "path", "program", "command"),
    "target_signature_valid": ("target_signature_valid", "signature_valid", "signed"),
    "task_create_event": ("task_create_event", "created", "create_event"),
    "task_state_new": ("task_state_new", "state", "new_state"),
    "task_state_old": ("task_state_old", "old_state", "previous_state"),
    "top_writing_process.first_seen": ("top_writing_process.first_seen", "top_writing_process_first_seen"),
    "trigger_type": ("trigger_type", "trigger"),
    "vulnerability_severity": ("vulnerability_severity", "severity", "cve_severity"),
}

_SUSPICIOUS_PATH_RE = re.compile(
    r"(?i)(\\Recycle\.Bin\\|/\.hidden|\\Temp\\|\\Windows\\Temp\\|/tmp/|"
    r"/var/tmp/|/dev/shm/|/Downloads/|\\Downloads\\|AppData\\(?:Local\\)?Temp|"
    r"AppData\\Roaming\\[a-z0-9]{8,}\\)"
)
_SECRETS_RE = re.compile(
    r"(?i)(password\s*=|api[_-]?key\s*=|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|"
    r"aws_secret_access_key)"
)
_OBFUSCATED_CMD_RE = re.compile(
    r"(?i)(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}|FromBase64String|"
    r"-nop\s+-w\s+hidden|IEX\s*\(|base64\s+-d|curl.*\|\s*sh|"
    r"wget.*\|\s*sh|python -c)"
)
_LOLBIN_DOWNLOAD_RE = re.compile(
    r"(?i)(-enc|-encodedcommand|urlcache|-urlcache|javascript:|vbscript:|"
    r"downloadstring|iex|/transfer|curl\s+|wget\s+)"
)
_CREDENTIAL_FILE_RE = re.compile(
    r"(?i)(/etc/shadow|/etc/passwd|\\config\\SAM|\.ssh/id_rsa|"
    r"\.aws/credentials|Login Data)"
)
_LOLBINS = {
    "certutil", "rundll32", "mshta", "regsvr32", "bitsadmin", "wmic",
    "powershell", "cmd", "curl", "wget", "bash", "sh",
}
_SYSTEM_PROCESS_PATHS = {
    "svchost.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "lsass.exe": ("c:\\windows\\system32\\",),
    "explorer.exe": ("c:\\windows\\",),
    "systemd": ("/usr/lib/systemd/", "/lib/systemd/", "/sbin/"),
    "init": ("/sbin/", "/usr/sbin/"),
}
_WELL_KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123, 135, 139, 143, 389,
    443, 445, 465, 587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9200, 27017,
}
_DEFAULT_SECURITY_SERVICES = {
    "attacklens", "osquery", "osqueryd", "falcon", "falcon-sensor",
    "crowdstrike", "sentinelone", "defender", "mdatp", "carbonblack",
    "cbdefense", "santa", "xprotect", "mrt", "gatekeeper",
}
_DEFAULT_SECURITY_PACKAGES = {
    "attacklens", "osquery", "falcon", "crowdstrike", "sentinelone",
    "defender", "mdatp", "carbonblack", "santa",
}
_DEFAULT_PRIV_GROUPS = {"admin", "administrator", "administrators", "sudo", "wheel", "domain_admin"}
_DEFAULT_SENSITIVE_MOUNTS = {"/", "/etc", "/root", "/var", "/usr", "/opt", "/Library"}
_DEFAULT_RESTRICTED_LICENSES = {"agpl", "agpl-3.0", "gpl-3.0", "sspl", "commons-clause"}


def default_rulepack_dir() -> Path:
    env = os.getenv("ATTACKLENS_RULEPACK_DIR", "").strip()
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "rulepacks" / "fleet_telemetry"


def _split_env(name: str, default: set[str] | None = None) -> set[str]:
    raw = os.getenv(name, "")
    vals = {x.strip().lower() for x in raw.split(",") if x.strip()}
    return vals if vals else set(default or set())


def _lower(v: Any) -> str:
    return str(v or "").strip().lower()


def _as_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes", "on", "enabled", "valid", "signed"):
            return True
        if s in ("false", "0", "no", "off", "disabled", "invalid", "unsigned"):
            return False
    return None


def _as_float(v: Any) -> float | None:
    try:
        if v is None or v == "":
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def _as_int(v: Any) -> int | None:
    try:
        if v is None or v == "":
            return None
        return int(v)
    except (TypeError, ValueError):
        return None


def _get(item: dict, field: str, default: Any = None) -> Any:
    aliases = _FIELD_ALIASES.get(field, (field,))
    for alias in aliases:
        cur: Any = item
        ok = True
        for part in alias.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            return cur
    return default


def _get_any(item: dict, fields: tuple[str, ...], default: Any = None) -> Any:
    for field in fields:
        value = _get(item, field)
        if value not in (None, ""):
            return value
    return default


def _name(item: dict) -> str:
    return str(_get_any(item, ("process_name", "service_name", "package_name", "component_name", "name"), ""))


def _path(item: dict) -> str:
    return str(_get_any(item, ("exec_path", "binary_path", "target_path", "file_path", "install_path"), ""))


def _signature_invalid(item: dict, field: str = "signature_valid") -> bool:
    value = _get(item, field)
    b = _as_bool(value)
    return b is False


def _bool_true(item: dict, field: str) -> bool:
    return _as_bool(_get(item, field)) is True


def _bool_false(item: dict, field: str) -> bool:
    return _as_bool(_get(item, field)) is False


def _is_world_writable_mode(mode: Any) -> bool:
    if mode is None:
        return False
    if isinstance(mode, str):
        s = mode.strip().lower()
        try:
            if s.startswith("0o"):
                return bool(int(s, 8) & 0o002)
            if re.fullmatch(r"[0-7]{3,4}", s):
                return bool(int(s, 8) & 0o002)
        except ValueError:
            return False
        return any(x in s for x in ("world-write", "world_writable", "others_write"))
    if isinstance(mode, int):
        return bool(mode & 0o002)
    return False


def _private_or_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _extract_ip(v: Any) -> str:
    s = str(v or "").strip()
    if not s:
        return ""
    if s.startswith("[") and "]" in s:
        return s.split("]", 1)[0].strip("[]")
    if ":" in s and s.count(":") == 1:
        return s.rsplit(":", 1)[0]
    return s


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _list_contains_path_prefix(value: str, prefixes: set[str]) -> bool:
    low = value.lower()
    return any(low.startswith(p.lower()) for p in prefixes)


def _trusted_integrations() -> set[str]:
    return _split_env("ATTACKLENS_TRUSTED_INTEGRATIONS", _DEFAULT_TRUSTED_INTEGRATIONS)


def _integration_sources(item: dict) -> set[str]:
    fields = (
        "integration_source", "source_platform", "provider", "vendor",
        "threat_source", "feed_source", "ioc_source", "scanner",
    )
    sources: set[str] = set()
    for field in fields:
        value = item.get(field)
        if isinstance(value, str):
            sources.add(_lower(value))
        elif isinstance(value, list):
            sources.update(_lower(x) for x in value if str(x).strip())
    for nested in ("threat_meta", "ioc", "cve", "enrichment"):
        value = item.get(nested)
        if isinstance(value, dict):
            for key in ("source", "provider", "vendor", "platform"):
                if value.get(key):
                    sources.add(_lower(value[key]))
    return {s for s in sources if s}


def _trusted_integration_sources(sources: set[str]) -> set[str]:
    trusted = _trusted_integrations()
    out: set[str] = set()
    for source in sources:
        normalized = re.sub(r"[^a-z0-9]+", "", source.lower())
        for trust in trusted:
            trust_norm = re.sub(r"[^a-z0-9]+", "", trust.lower())
            if source == trust or normalized == trust_norm or trust_norm in normalized:
                out.add(source)
                break
    return out


def _item_has_threat_assertion(item: dict) -> bool:
    return any(bool(item.get(k)) for k in (
        "malicious_ip", "threat_ip_match", "malicious_hash_hit",
        "threat_hash_match", "ioc_match", "threat_match",
    ))


def _item_has_vulnerability_assertion(item: dict) -> bool:
    if item.get("kev") or item.get("cisa_kev") or item.get("epss_score"):
        return True
    if item.get("cve_id") or item.get("cve_ids") or item.get("cves"):
        return True
    cve = item.get("cve")
    return isinstance(cve, dict) and bool(cve.get("cve_id") or cve.get("kev"))


class RulePackDetector:
    def __init__(self, rules: dict[str, list[RulePackRule]]) -> None:
        self._rules = rules
        self._approved_repos = _split_env("ATTACKLENS_APPROVED_REPOS")
        self._approved_registries = _split_env("ATTACKLENS_APPROVED_REGISTRIES")
        self._approved_file_servers = _split_env("ATTACKLENS_APPROVED_FILE_SERVERS")
        self._approved_dns = _split_env("ATTACKLENS_APPROVED_DNS_SERVERS")
        self._approved_gateways = _split_env("ATTACKLENS_APPROVED_GATEWAYS")
        self._approved_ap_bssids = _split_env("ATTACKLENS_APPROVED_AP_BSSIDS")
        self._corporate_ssids = _split_env("ATTACKLENS_CORPORATE_SSIDS")
        self._approved_ouis = _split_env("ATTACKLENS_APPROVED_OUIS")
        self._approved_usb = _split_env("ATTACKLENS_APPROVED_USB_IDS")
        self._approved_firmware = _split_env("ATTACKLENS_APPROVED_FIRMWARE")
        self._approved_mount_exceptions = _split_env("ATTACKLENS_APPROVED_MOUNT_EXCEPTIONS")
        self._sensitive_mounts = _split_env(
            "ATTACKLENS_SENSITIVE_MOUNT_POINTS", _DEFAULT_SENSITIVE_MOUNTS,
        )
        self._monitored_security_services = _split_env(
            "ATTACKLENS_MONITORED_SECURITY_SERVICES", _DEFAULT_SECURITY_SERVICES,
        )
        self._monitored_security_packages = _split_env(
            "ATTACKLENS_MONITORED_SECURITY_PACKAGES", _DEFAULT_SECURITY_PACKAGES,
        )
        self._privileged_groups = _split_env(
            "ATTACKLENS_MONITORED_PRIVILEGED_GROUPS", _DEFAULT_PRIV_GROUPS,
        )
        self._restricted_licenses = _split_env(
            "ATTACKLENS_RESTRICTED_LICENSES", _DEFAULT_RESTRICTED_LICENSES,
        )

    @classmethod
    def load(cls, directory: Path | None = None) -> RulePackDetector:
        if os.getenv("ATTACKLENS_RULEPACK_ENABLED", "true").lower() in {"0", "false", "no", "off"}:
            return cls({})
        root = directory or default_rulepack_dir()
        if not root.is_dir():
            log.info("rule pack directory not found: %s", root)
            return cls({})

        rules: dict[str, list[RulePackRule]] = {}
        for path in sorted(root.glob("*.yml")):
            try:
                doc = yaml.safe_load(path.read_text()) or {}
            except Exception as exc:
                log.warning("failed to load rule pack file %s: %s", path, exc)
                continue
            section = path.stem
            for raw in doc.get("rules") or []:
                try:
                    rule = RulePackRule(
                        id=str(raw["id"]),
                        section=section,
                        title=str(raw.get("title") or raw["id"]),
                        description=str(raw.get("description") or ""),
                        severity=_lower(raw.get("severity") or "medium"),
                        mitre_attack=[str(x) for x in (raw.get("mitre_attack") or [])],
                        detection=raw.get("detection") or {},
                        false_positives=list(raw.get("false_positives") or []),
                        enrichment_sources=list(raw.get("enrichment_sources") or []),
                        response_actions=list(raw.get("response_actions") or []),
                        status=_lower(raw.get("status") or "experimental"),
                        source_file=str(path),
                    )
                except Exception as exc:
                    log.warning("invalid rule in %s: %s", path, exc)
                    continue
                rules.setdefault(section, []).append(rule)
        log.info(
            "loaded YAML rule pack: dir=%s files=%d rules=%d executable=%d",
            root, len(list(root.glob("*.yml"))), sum(len(v) for v in rules.values()),
            len(_RULE_EVALUATORS),
        )
        return cls(rules)

    def rules_for(self, section: str) -> list[RulePackRule]:
        return self._rules.get(_canonical_section(section), [])

    async def analyze(
        self,
        agent_id: str,
        section: str,
        data: Any,
        feeds: Any | None = None,
    ) -> list[dict]:
        section = _canonical_section(section)
        rules = self.rules_for(section)
        if not rules:
            return []
        findings: list[dict] = []
        items = self._iter_items(section, data)
        for rule in rules:
            evaluator = _RULE_EVALUATORS.get(rule.id)
            if evaluator is None:
                continue
            for item in items:
                try:
                    match = evaluator(self, agent_id, item, {"feeds": feeds})
                except Exception as exc:
                    log.debug("rulepack evaluator failed rule=%s: %s", rule.id, exc)
                    continue
                if match:
                    findings.append(self._finding(agent_id, rule, item, match, {"feeds": feeds}))
        return findings

    @staticmethod
    def _iter_items(section: str, data: Any) -> list[dict]:
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if section == "configs" and isinstance(data, dict):
            return [
                {"path": k, "content": v}
                for k, v in data.items()
                if isinstance(k, str) and isinstance(v, (str, bytes))
            ]
        if isinstance(data, dict):
            return [data]
        return []

    def _finding(
        self,
        agent_id: str,
        rule: RulePackRule,
        item: dict,
        match: dict,
        ctx: dict | None = None,
    ) -> dict:
        mitre = rule.mitre_attack[0] if rule.mitre_attack else ""
        stable_id = self._stable_item_id(item)
        item_key = f"rulepack:{rule.id}:{stable_id}"
        matched = match.get("matched_conditions") or []
        quality = self._quality_profile(rule, item, match, ctx)
        evidence = dict(item)
        evidence["_rulepack"] = {
            "rule_id": rule.id,
            "source_file": rule.source_file,
            "logic": rule.detection.get("logic", ""),
            "conditions": rule.detection.get("conditions", []),
            "matched_conditions": matched,
            "threshold": rule.detection.get("threshold", ""),
            "status": rule.status,
            "false_positives": rule.false_positives,
            "enrichment_sources": rule.enrichment_sources,
            "response_actions": rule.response_actions,
            "match_reason": match.get("reason", ""),
            "evidence_strength": quality["evidence_strength"],
            "condition_coverage": quality["condition_coverage"],
            "matched_condition_count": len(matched),
            "rule_condition_count": quality["rule_condition_count"],
            "authoritative_corroboration": quality["authoritative_corroboration"],
            "contextual_corroboration": quality["contextual_corroboration"],
            "integration_state": quality["integration_state"],
            "calibration": quality["calibration"],
        }
        severity = match.get("severity") or rule.severity or "medium"
        confidence = quality["confidence"]
        return {
            "agent_id": agent_id,
            "category": _SECTION_CATEGORY.get(rule.section, rule.section),
            "item_key": item_key,
            "severity": severity,
            "score": severity_to_score(severity),
            "title": rule.title,
            "description": rule.description,
            "evidence": evidence,
            "source": "rulepack",
            "rule_id": f"rulepack:{rule.id}",
            "mitre_technique": mitre,
            "mitre_tactic": get_tactic(mitre),
            "tags": ["rulepack", rule.section, rule.id],
            "confidence": round(confidence, 3),
            "weight": float(match.get("weight") or self._weight(rule, confidence)),
            "precision_score": round(quality["precision_score"], 3),
            "precision_factors": quality["precision_factors"],
        }

    @staticmethod
    def _stable_item_id(item: dict) -> str:
        parts = []
        for field in _IDENTITY_FIELDS:
            value = _get(item, field)
            if value not in (None, "", [], {}):
                parts.append(f"{field}={value}")
            if len(parts) >= 3:
                break
        if not parts:
            stable = {
                k: v for k, v in item.items()
                if k not in {"pid", "ppid", "timestamp", "collected_at", "created_at"}
            }
            parts.append(json.dumps(stable, sort_keys=True, default=str)[:400])
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    @staticmethod
    def _confidence(rule: RulePackRule) -> float:
        if rule.status == "stable":
            return {"critical": 0.88, "high": 0.82, "medium": 0.72, "low": 0.62}.get(
                rule.severity, 0.70,
            )
        if rule.status in {"tuning", "experimental"}:
            return {"critical": 0.72, "high": 0.66, "medium": 0.58, "low": 0.50}.get(
                rule.severity, 0.55,
            )
        return 0.60

    @staticmethod
    def _weight(rule: RulePackRule, confidence: float) -> float:
        if rule.severity == "critical":
            return max(0.80, confidence)
        if rule.severity == "high":
            return max(0.72, confidence)
        if rule.severity == "medium":
            return max(0.58, confidence)
        return max(0.45, confidence)

    def _quality_profile(
        self,
        rule: RulePackRule,
        item: dict,
        match: dict,
        ctx: dict | None,
    ) -> dict[str, Any]:
        matched = [str(x) for x in (match.get("matched_conditions") or []) if str(x)]
        rule_conditions = rule.detection.get("conditions") or []
        rule_condition_count = max(1, len(rule_conditions))
        matched_count = len(matched)
        condition_coverage = min(1.0, matched_count / rule_condition_count)

        text = " ".join([
            rule.title,
            rule.description,
            str(rule.detection.get("logic") or ""),
            " ".join(map(str, rule_conditions)),
            " ".join(map(str, rule.enrichment_sources)),
            " ".join(matched),
            str(match.get("reason") or ""),
        ]).lower()
        authoritative = any(term in text for term in _AUTHORITATIVE_SIGNAL_TERMS)
        contextual = any(term in text for term in _CONTEXT_SIGNAL_TERMS)
        integration_state = self._integration_state(rule, item, ctx)
        integration_missing = bool(integration_state["missing"])
        if integration_missing and set(integration_state["missing"]) & {
            "threat_intel", "vulnerability_intel",
        }:
            authoritative = False

        base = float(match.get("confidence") or self._confidence(rule))
        adjustments: list[dict[str, Any]] = [{"factor": "base_rule_confidence", "delta": round(base, 3)}]

        delta = 0.0
        if matched_count >= 2:
            delta += 0.04
            adjustments.append({"factor": "multi_condition_match", "delta": 0.04})
        if matched_count >= 3:
            delta += 0.03
            adjustments.append({"factor": "three_or_more_conditions", "delta": 0.03})
        if authoritative:
            delta += 0.05
            adjustments.append({"factor": "authoritative_corroboration", "delta": 0.05})
        if contextual:
            delta += 0.03
            adjustments.append({"factor": "contextual_baseline_or_policy", "delta": 0.03})
        if integration_missing:
            penalty = max(-0.12, -0.04 * len(integration_state["missing"]))
            delta += penalty
            adjustments.append({
                "factor": "missing_required_integration",
                "delta": penalty,
                "missing": integration_state["missing"],
            })

        single_heuristic = matched_count <= 1 and not authoritative and not contextual
        if single_heuristic:
            penalty = -0.06 if rule.severity in {"critical", "high"} else -0.04
            delta += penalty
            adjustments.append({"factor": "single_uncorroborated_heuristic", "delta": penalty})
        if rule.status == "experimental":
            delta -= 0.06
            adjustments.append({"factor": "experimental_rule", "delta": -0.06})
        elif rule.status == "tuning":
            delta -= 0.03
            adjustments.append({"factor": "tuning_rule", "delta": -0.03})

        confidence = max(0.30, min(0.99, base + delta))
        if authoritative and rule.severity in {"critical", "high"}:
            confidence = max(confidence, 0.90)

        if confidence >= 0.93 and (authoritative or matched_count >= 2):
            strength = "authoritative"
        elif confidence >= 0.80:
            strength = "strong"
        elif confidence >= 0.65:
            strength = "moderate"
        else:
            strength = "weak"

        status_factor = {
            "stable": 1.0,
            "tuning": 0.72,
            "experimental": 0.58,
        }.get(rule.status, 0.70)
        precision_factors = {
            "rule_confidence": round(confidence, 3),
            "condition_coverage": round(condition_coverage, 3),
            "authoritative_corroboration": 1.0 if authoritative else 0.0,
            "contextual_corroboration": 1.0 if contextual else 0.0,
            "rule_maturity": status_factor,
            "single_heuristic_penalty": 0.0 if single_heuristic else 1.0,
        }
        precision_score = (
            0.58 * precision_factors["rule_confidence"]
            + 0.14 * precision_factors["condition_coverage"]
            + 0.12 * precision_factors["authoritative_corroboration"]
            + 0.08 * precision_factors["contextual_corroboration"]
            + 0.08 * precision_factors["rule_maturity"]
        )
        if single_heuristic:
            precision_score *= 0.92

        return {
            "confidence": round(confidence, 3),
            "precision_score": max(0.0, min(1.0, precision_score)),
            "precision_factors": precision_factors,
            "evidence_strength": strength,
            "condition_coverage": round(condition_coverage, 3),
            "rule_condition_count": rule_condition_count,
            "authoritative_corroboration": authoritative,
            "contextual_corroboration": contextual,
            "integration_state": integration_state,
            "calibration": adjustments,
        }

    @staticmethod
    def _integration_state(rule: RulePackRule, item: dict, ctx: dict | None) -> dict[str, Any]:
        text = " ".join([
            str(rule.detection.get("logic") or ""),
            " ".join(map(str, rule.detection.get("conditions") or [])),
            " ".join(map(str, rule.enrichment_sources)),
        ]).lower()
        required = [
            name for name, terms in _INTEGRATION_TERMS.items()
            if any(term in text for term in terms)
        ]
        feeds = (ctx or {}).get("feeds")
        source_values = _integration_sources(item)
        trusted_sources = _trusted_integration_sources(source_values)
        has_trusted_ti = bool(trusted_sources and _item_has_threat_assertion(item))
        has_trusted_vuln = bool(trusted_sources and _item_has_vulnerability_assertion(item))
        available = {
            "threat_intel": bool(feeds and hasattr(feeds, "is_malicious_ip")) or has_trusted_ti,
            "vulnerability_intel": bool(
                feeds and (
                    hasattr(feeds, "is_kev_cve")
                    or hasattr(feeds, "bulk_epss")
                    or hasattr(feeds, "get_epss")
                )
            ) or has_trusted_vuln,
            "asset_policy": True,
        }
        missing = [name for name in required if not available.get(name, False)]
        return {
            "required": required,
            "available": {name: available.get(name, False) for name in required},
            "missing": missing,
            "trusted_sources": sorted(trusted_sources),
            "reported_sources": sorted(source_values),
        }


def _matched(*conditions: str, reason: str = "", **extra: Any) -> dict:
    return {"matched_conditions": list(conditions), "reason": reason, **extra}


# ── Rule evaluators ──────────────────────────────────────────────────────────

def _agent_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    restart_count = _as_int(_get(item, "restart_count")) or 0
    binary_hash = _lower(_get(item, "sha256") or _get(item, "agent_binary_hash"))
    known = _split_env("ATTACKLENS_KNOWN_GOOD_AGENT_HASHES")
    if binary_hash and known and binary_hash not in known and restart_count >= 3:
        return _matched("sha256(agent_binary_path) not in known_good_release_hashes",
                        "agent process restart_count >= 3 within 10 minutes")
    return None


def _agent_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    skew = _as_float(_get(item, "clock_skew_seconds") or _get(item, "time_skew_seconds"))
    if skew is not None and abs(skew) > 300:
        return _matched("abs(host_reported_time - collector_receive_time) > 300 seconds")
    return None


def _apps_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _signature_invalid(item, "code_signature_valid"):
        return _matched("code_signature_valid == false")
    return None


def _apps_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    path = str(_get(item, "install_path") or "")
    if path and re.search(r"(?i)(\\Temp\\|/tmp/|\\Downloads\\|/Downloads/|AppData\\Local\\Temp)", path):
        return _matched("install_path matches suspicious temp/download pattern")
    return None


def _binaries_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _signature_invalid(item):
        return _matched("signature_valid == false")
    return None


def _binaries_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if item.get("malware_hash_hit") or item.get("threat_hash_match"):
        return _matched("sha256(binary) in malicious_hash_feed", confidence=0.96, weight=0.92)
    return None


def _binaries_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    path = _path(item)
    if path and re.search(r"(?i)(/tmp/|/var/tmp/|\\Temp\\|\\Windows\\Temp\\|/dev/shm/)", path):
        return _matched("exec_path matches temp/world-writable path")
    return None


def _binaries_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    name = _lower(_name(item)).split("/")[-1].split("\\")[-1]
    cmd = str(_get(item, "command_line") or "")
    if name in _LOLBINS and _LOLBIN_DOWNLOAD_RE.search(cmd):
        return _matched("process_name in known_lolbin_set",
                        "command_line indicates a download/action pattern",
                        confidence=0.86, weight=0.82)
    return None


def _binaries_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    ent = _as_float(_get(item, "shannon_entropy") or _get(item, "entropy"))
    if ent is not None and ent > 7.2 and _signature_invalid(item):
        return _matched("shannon_entropy(binary) > 7.2", "signature_valid == false")
    return None


def _binaries_006(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    name = _lower(_name(item)).split("/")[-1].split("\\")[-1]
    path = _lower(_path(item))
    expected = _SYSTEM_PROCESS_PATHS.get(name)
    if expected and path and not any(path.startswith(p) for p in expected):
        return _matched("process_name in system process set",
                        "exec_path not in expected_system_paths[process_name]")
    return None


def _configs_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    content = str(_get(item, "content") or "")
    if content and _SECRETS_RE.search(content):
        return _matched("content matches plaintext credential/secret pattern",
                        confidence=0.90, weight=0.84)
    return None


def _configs_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if item.get("world_writable") is True or _is_world_writable_mode(_get(item, "permission_mode")):
        return _matched("permission_mode allows world-write")
    return None


def _connections_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    feeds = (ctx or {}).get("feeds")
    ip = _extract_ip(_get(item, "dest_ip") or _get(item, "remote_addr"))
    if not ip or _private_or_internal(ip):
        return None
    if feeds is not None:
        try:
            if feeds.is_malicious_ip(ip):
                return _matched("dest_ip in ti_malicious_ip_feed", confidence=0.96, weight=0.90)
        except Exception:
            return None
    if item.get("malicious_ip") or item.get("threat_ip_match"):
        return _matched("dest_ip in ti_malicious_ip_feed", confidence=0.96, weight=0.90)
    return None


def _connections_006(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    proto = _lower(_get(item, "fingerprinted_protocol"))
    port = _as_int(_get(item, "dest_port"))
    if proto == "http" and port is not None and port not in {80, 8080, 8000}:
        return _matched("fingerprinted_protocol == 'HTTP' and dest_port not in [80,8080,8000]")
    if proto == "tls" and port is not None and port not in {443, 8443}:
        return _matched("fingerprinted_protocol == 'TLS' and dest_port not in [443,8443]")
    return None


def _containers_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _bool_true(item, "privileged"):
        return _matched("privileged == true")
    return None


def _containers_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    source = _lower(_get(item, "mount_source"))
    if source in {"/var/run/docker.sock", "/proc", "/etc", "/root"}:
        return _matched("mount_source in sensitive host path list")
    mounts = item.get("mounts") or []
    if isinstance(mounts, list):
        for m in mounts:
            if isinstance(m, dict) and _lower(m.get("source")) in {
                "/var/run/docker.sock", "/proc", "/etc", "/root",
            }:
                return _matched("mount_source in sensitive host path list")
    return None


def _containers_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    registry = _lower(_get(item, "registry_hostname"))
    if registry and det._approved_registries and registry not in det._approved_registries:
        return _matched("registry_hostname not in approved_registry_list")
    return None


def _containers_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    target = str(_get(item, "write_target") or _get(item, "target_path") or "")
    if target and re.search(r"(?i)(cgroup.*release_agent|/proc/sys/kernel/core_pattern)", target):
        return _matched("write_target matches container escape target")
    if item.get("host_pid_namespace") is True or item.get("host_pid_enumerated") is True:
        return _matched("container process enumerates host PID namespace unexpectedly")
    return None


def _containers_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if (_as_int(_get(item, "process_uid")) or -1) == 0:
        return _matched("process_uid == 0")
    return None


_MASS_STORAGE_HINT_RE = re.compile(
    r"(?i)(mass\s*storage|flash|thumb|usb\s*(disk|drive)|external\s*(disk|drive)|"
    r"storage|sd\s*card|card\s*reader)"
)


def _is_mass_storage_device(item: dict) -> bool:
    device_class = _lower(_get(item, "device_class"))
    if device_class in {"mass_storage", "mass storage", "removable_storage", "disk", "storage"}:
        return True
    bus = _lower(item.get("bus"))
    label = " ".join(
        _lower(item.get(k)) for k in ("name", "vendor", "product_id") if item.get(k)
    )
    return bus == "usb" and bool(_MASS_STORAGE_HINT_RE.search(label))


def _remote_host_from_mount(item: dict) -> str:
    remote = _lower(_get(item, "remote_host"))
    if remote:
        return remote
    device = str(item.get("device") or _get(item, "mount_source") or "").strip()
    if device.startswith("//"):
        return _lower(device[2:].split("/", 1)[0])
    if ":" in device and not device.startswith(("/", "\\")):
        return _lower(device.split(":", 1)[0])
    return ""


def _hardware_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if not _is_mass_storage_device(item):
        return None
    ident = ":".join(_lower(item.get(k)) for k in ("vendor_id", "product_id", "serial"))
    if det._approved_usb and ident not in det._approved_usb:
        return _matched("device_class == 'mass_storage'",
                        "(vendor_id, product_id, serial) not in approved_usb_allowlist")
    if item.get("approved") is False or item.get("authorized") is False:
        return _matched("device_class == 'mass_storage'", "device not approved")
    return None


def _hardware_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _bool_false(item, "secure_boot_enabled") and item.get("previous_state") is True:
        return _matched("secure_boot_enabled == false and previous_state == true")
    if _lower(item.get("tpm_attestation_status")) == "failed" and _lower(item.get("previous_status")) == "passed":
        return _matched("tpm_attestation_status == 'failed' and previous_status == 'passed'")
    return None


def _mounts_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _lower(_get(item, "device_type")) != "removable":
        return None
    if _lower(_get(item, "host_policy_class")) == "removable_restricted":
        device = _lower(item.get("device") or item.get("device_id") or item.get("volume_id"))
        if not det._approved_mount_exceptions or device not in det._approved_mount_exceptions:
            return _matched("device_type == 'removable'",
                            "host_policy_class == 'removable_restricted'")
    return None


def _mounts_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _lower(_get(item, "mount_type")) in {"nfs", "smb", "cifs"}:
        remote = _remote_host_from_mount(item)
        if remote and det._approved_file_servers and remote not in det._approved_file_servers:
            return _matched("mount_type in ['nfs','smb','cifs']",
                            "remote_host not in approved_file_server_list")
    return None


def _mounts_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    mount = str(_get(item, "mount_point") or "")
    options = _lower(_get(item, "mount_options"))
    if mount and _list_contains_path_prefix(mount, det._sensitive_mounts):
        if "world" in options or "o+w" in options or item.get("world_writable") is True:
            return _matched("mount_point in sensitive_mount_points",
                            "mount_options indicate world-write permission")
    return None


def _network_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    ssid = _lower(_get(item, "ssid"))
    bssid = _lower(_get(item, "bssid"))
    if ssid and bssid and det._corporate_ssids and ssid in det._corporate_ssids:
        if det._approved_ap_bssids and bssid not in det._approved_ap_bssids:
            return _matched("ssid in corporate_ssid_list", "bssid not in approved_ap_bssid_list")
    return None


def _network_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _bool_true(item, "promiscuous_mode") and _lower(_get(item, "host_role")) != "network_sensor":
        return _matched("promiscuous_mode == true", "host_role != 'network_sensor'")
    return None


def _network_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    gateway = _lower(_get(item, "current_gateway"))
    if gateway and det._approved_gateways and gateway not in det._approved_gateways:
        return _matched("current_gateway != approved_dhcp_gateway_for_subnet")
    dns = item.get("current_dns_servers") or item.get("dns_servers") or []
    if isinstance(dns, str):
        dns = [x.strip() for x in dns.split(",") if x.strip()]
    if dns and det._approved_dns and not set(map(_lower, dns)).issubset(det._approved_dns):
        return _matched("current_dns_servers not subset of approved_dhcp_dns_for_subnet")
    return None


def _network_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    age = _as_float(_get(item, "domain_registration_age_days"))
    ent = _as_float(_get(item, "domain_name_entropy"))
    domain = str(item.get("domain") or item.get("domain_name") or "")
    if age is not None and age < 7:
        return _matched("domain_registration_age_days < 7")
    if ent is None and domain:
        labels = [x for x in domain.split(".") if x]
        ent = max((_entropy(x) for x in labels), default=0.0)
    if ent is not None and ent > 3.5:
        return _matched("domain_name_entropy > 3.5")
    return None


def _open_files_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    path = str(_get(item, "file_path") or "")
    if path and _CREDENTIAL_FILE_RE.search(path):
        return _matched("file_path matches sensitive credential store pattern",
                        confidence=0.88, weight=0.82)
    return None


def _packages_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    repo = _lower(_get(item, "source_repo"))
    if repo and det._approved_repos and repo not in det._approved_repos:
        return _matched("source_repo not in approved_repo_list")
    return None


def _packages_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    installed = _lower(_get(item, "installed_hash"))
    expected = _lower(_get(item, "registry_hash"))
    if installed and expected and installed != expected:
        return _matched("installed_hash != registry_hash", confidence=0.92, weight=0.86)
    return None


def _packages_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    name = _lower(_get(item, "package_name"))
    if name in det._monitored_security_packages and _bool_true(item, "removal_event"):
        return _matched("package_name in monitored_security_package_list",
                        "removal_event == true")
    return None


def _ports_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    port = _as_int(_get(item, "listening_port"))
    if port not in _WELL_KNOWN_PORTS:
        return None
    approved_map = os.getenv("ATTACKLENS_APPROVED_BINARY_FOR_PORT", "").strip()
    if not approved_map:
        return None
    try:
        mapping = json.loads(approved_map)
    except json.JSONDecodeError:
        return None
    expected = str(mapping.get(str(port)) or "").lower()
    actual = _lower(_get(item, "owning_process_path"))
    if expected and actual and actual != expected:
        return _matched("listening_port in well_known_service_ports",
                        "owning_process_path != approved_binary_for_port[listening_port]")
    return None


def _processes_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    parent = _lower(_get(item, "parent_process_name"))
    child = _lower(_get(item, "child_process_name") or _get(item, "process_name"))
    parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe",
               "firefox.exe", "acrobat.exe"}
    children = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "bash", "sh", "mshta.exe"}
    if parent in parents and child in children:
        return _matched("parent_process_name in office/browser list",
                        "child_process_name in shell/script interpreter list",
                        confidence=0.94, weight=0.90)
    return None


def _processes_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    cmd = str(_get(item, "command_line") or "")
    if cmd and _OBFUSCATED_CMD_RE.search(cmd):
        return _matched("command_line matches obfuscation/encoding pattern",
                        confidence=0.88, weight=0.84)
    return None


def _processes_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _bool_true(item, "remote_memory_allocation") and _bool_true(item, "remote_thread_created"):
        return _matched("remote_memory_allocation(...) == true",
                        "remote_thread_created(...) == true",
                        confidence=0.96, weight=0.94)
    return None


def _processes_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    path = _path(item)
    if path and _SUSPICIOUS_PATH_RE.search(path):
        return _matched("exec_path matches suspicious-location patterns")
    return None


def _processes_006(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    name = _lower(_name(item)).split("/")[-1].split("\\")[-1]
    cmd = str(_get(item, "command_line") or "")
    if name in _LOLBINS and _LOLBIN_DOWNLOAD_RE.search(cmd):
        return _matched("process_name in known_lolbin_set",
                        "command_line indicates a download action",
                        confidence=0.86, weight=0.82)
    return None


def _sbom_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _bool_false(item, "provenance_attestation_present"):
        return _matched("provenance_attestation_present == false")
    origin = _lower(item.get("component_origin") or item.get("origin"))
    approved = _split_env("ATTACKLENS_APPROVED_COMPONENT_SOURCES")
    if origin and approved and origin not in approved:
        return _matched("component_origin not in approved_source_list")
    return None


def _sbom_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    lic = _lower(_get(item, "component_license"))
    target = _lower(_get(item, "build_target"))
    if lic in det._restricted_licenses and target == "production":
        return _matched("component_license in restricted_license_list",
                        "build_target == 'production'")
    return None


def _security_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    state = _lower(_get(item, "security_agent_service_state"))
    if state in {"stopped", "disabled", "off"}:
        return _matched("security_agent_service_state == 'stopped' or 'disabled'",
                        confidence=0.92, weight=0.88)
    return None


def _security_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _lower(_get(item, "event_type")) == "log_cleared" and _lower(_get(item, "log_channel")) in {"security", "audit"}:
        return _matched("event_type == 'log_cleared'", "log_channel in ['Security','Audit']")
    return None


def _security_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _lower(_get(item, "rule_action")) != "allow" or _lower(_get(item, "rule_direction")) != "inbound":
        return None
    cidr = _lower(_get(item, "source_cidr"))
    size = _as_int(_get(item, "port_range_size")) or 0
    if cidr in {"0.0.0.0/0", "::/0", "any"} or size > 100:
        return _matched("rule_action == 'allow'", "rule_direction == 'inbound'",
                        "source_cidr == '0.0.0.0/0' or port_range_size > 100")
    return None


def _security_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    days = _as_float(_get(item, "days_since_disclosure"))
    sla = _as_float(item.get("sla_days") or item.get("sla_days_for_severity_critical")) or 30.0
    if _lower(_get(item, "vulnerability_severity")) == "critical" and days is not None:
        if days > sla and _bool_true(item, "patch_available"):
            return _matched("vulnerability_severity == 'critical'",
                            "days_since_disclosure > sla_days_for_severity['critical']",
                            "patch_available == true")
    return None


def _security_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    priv = _lower(_get(item, "account_privilege_level"))
    old = item.get("mfa_enforced_old")
    new = _get(item, "mfa_enforced")
    if priv in {"admin", "domain_admin", "root"} and _as_bool(old) is True and _as_bool(new) is False:
        return _matched("account_privilege_level in ['admin','domain_admin','root']",
                        "mfa_enforced transitions true -> false")
    return None


def _services_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _bool_true(item, "service_create_event") and (
        _signature_invalid(item) or _SUSPICIOUS_PATH_RE.search(_path(item))
    ):
        return _matched("service_create_event == true",
                        "signature_valid == false OR binary_path matches suspicious-location pattern")
    return None


def _services_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    service = _lower(_get(item, "service_name"))
    state = _lower(_get(item, "new_state"))
    if any(s in service for s in det._monitored_security_services) and state in {"stopped", "disabled"}:
        return _matched("service_name in monitored_security_services",
                        "new_state in ['stopped','disabled']")
    return None


def _services_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    acct = _lower(_get(item, "run_as_account"))
    first_seen = _as_float(_get(item, "target_first_seen_days"))
    if acct in {"system", "root", "localsystem"} and (
        _signature_invalid(item) or (first_seen is not None and first_seen < 1)
    ):
        return _matched("run_as_account in ['SYSTEM','root','LocalSystem']",
                        "signature_valid == false OR binary_first_seen_days < 1")
    return None


def _services_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _lower(_get(item, "start_type_new")) == "automatic" and _lower(_get(item, "start_type_old")) in {"manual", "disabled"}:
        return _matched("start_type_new == 'automatic'",
                        "start_type_old in ['manual','disabled']")
    return None


def _storage_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    new = _lower(_get(item, "encryption_status_new"))
    old = _lower(_get(item, "encryption_status_old"))
    if new == "encrypted" and old == "unencrypted":
        return _matched("encryption_status_new == 'encrypted' and encryption_status_old == 'unencrypted'")
    if item.get("key_identifier_changed") is True:
        return _matched("key_identifier changed unexpectedly")
    return None


def _storage_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    quota = _as_float(_get(item, "quota_usage_pct"))
    first_seen = _as_float(_get(item, "top_writing_process.first_seen"))
    if quota is not None and quota > 90 and first_seen is not None and first_seen < 24:
        return _matched("quota_usage_pct > 90", "top_writing_process.first_seen within last 24h")
    return None


def _storage_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    fs = _lower(_get(item, "filesystem_type"))
    size = _as_float(_get(item, "partition_size_gb")) or 0.0
    if _bool_true(item, "gpt_hidden_attribute") or (fs == "unknown" and size > 1):
        return _matched("gpt_hidden_attribute == true OR unknown filesystem with partition_size_gb > 1")
    return None


def _sysctl_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    role = _lower(_get(item, "host_role"))
    key = _lower(_get(item, "sysctl_key"))
    value = str(_get(item, "current_value") or item.get(key) or "").strip()
    if key in {"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"} and value in {"1", "true", "enabled"}:
        if role not in {"router", "gateway", "firewall"}:
            return _matched("net.ipv4.ip_forward == 1 or net.ipv6.conf.all.forwarding == 1",
                            "host_role not in ['router','gateway','firewall']")
    if item.get("net.ipv4.ip_forward") in (1, "1", True) and role not in {"router", "gateway", "firewall"}:
        return _matched("net.ipv4.ip_forward == 1", "host_role not in router/gateway/firewall")
    return None


def _sysctl_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    pattern = str(_get(item, "core_pattern") or "")
    if pattern.startswith("|") or item.get("core_pattern_world_writable") is True:
        return _matched("core_pattern matches '^|' OR target path is world-writable")
    return None


def _sysctl_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    cur = _as_int(_get(item, "current_ptrace_scope"))
    base = _as_int(item.get("baseline_ptrace_scope"))
    if cur is not None and base is not None and cur < base:
        return _matched("current_ptrace_scope < baseline_ptrace_scope")
    return None


def _tasks_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _bool_true(item, "task_create_event") and (
        _signature_invalid(item, "target_signature_valid") or _SUSPICIOUS_PATH_RE.search(_path(item))
    ):
        return _matched("task_create_event == true",
                        "target_signature_valid == false OR target_path matches suspicious-location pattern")
    return None


def _tasks_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    acct = _lower(_get(item, "run_as_account"))
    first_seen = _as_float(_get(item, "target_first_seen_days"))
    if acct in {"system", "root"} and (
        _signature_invalid(item, "target_signature_valid") or (first_seen is not None and first_seen < 1)
    ):
        return _matched("run_as_account in ['SYSTEM','root']",
                        "target_signature_valid == false OR target_first_seen_days < 1")
    return None


def _tasks_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _lower(_get(item, "task_state_new")) == "enabled" and _lower(_get(item, "task_state_old")) in {"disabled", "hidden"}:
        return _matched("task_state_new == 'enabled'", "task_state_old in ['disabled','hidden']")
    return None


def _tasks_004(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _lower(_get(item, "trigger_type")) == "on_logon" and _SUSPICIOUS_PATH_RE.search(_path(item)):
        return _matched("trigger_type == 'on_logon'",
                        "target_path matches suspicious-location pattern")
    return None


def _tasks_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    cmd = str(_get(item, "new_command") or "")
    if item.get("cron_entry_modified") is True and _OBFUSCATED_CMD_RE.search(cmd):
        return _matched("cron_entry_modified == true", "new_command matches encoded/download pattern")
    return None


def _users_001(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _bool_true(item, "account_create_event") and _lower(_get(item, "account_type")) == "local":
        return _matched("account_create_event == true", "account_type == 'local'")
    return None


def _users_002(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    group = _lower(_get(item, "group_name"))
    if group in det._privileged_groups and _bool_true(item, "membership_add_event"):
        return _matched("group_name in monitored_privileged_groups",
                        "membership_add_event == true")
    return None


def _users_003(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    days = _as_float(_get(item, "days_since_last_login"))
    if days is not None and days > 90 and _bool_true(item, "login_success"):
        return _matched("days_since_last_login > 90", "login_success == true")
    return None


def _users_005(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _as_bool(item.get("password_never_expires_old")) is False and _as_bool(item.get("password_never_expires")) is True:
        return _matched("password_never_expires transitions false -> true")
    if _as_bool(item.get("complexity_required_old")) is True and _as_bool(item.get("complexity_required")) is False:
        return _matched("complexity_required transitions true -> false")
    return None


def _users_006(det: RulePackDetector, agent_id: str, item: dict, ctx: dict | None) -> dict | None:
    if _lower(_get(item, "account_type")) == "service_account":
        logon = _lower(_get(item, "logon_type"))
        if logon in {"interactive", "remote_interactive", "ssh"}:
            return _matched("account_type == 'service_account'",
                            "logon_type in ['interactive','remote_interactive','ssh']")
    return None


_RULE_EVALUATORS: dict[str, RuleFn] = {
    "AGENT-HEALTH-003": _agent_003,
    "AGENT-HEALTH-004": _agent_004,
    "APPS-002": _apps_002,
    "APPS-003": _apps_003,
    "BINARIES-001": _binaries_001,
    "BINARIES-002": _binaries_002,
    "BINARIES-003": _binaries_003,
    "BINARIES-004": _binaries_004,
    "BINARIES-005": _binaries_005,
    "BINARIES-006": _binaries_006,
    "CONFIGS-003": _configs_003,
    "CONFIGS-004": _configs_004,
    "CONNECTIONS-002": _connections_002,
    "CONNECTIONS-006": _connections_006,
    "CONTAINERS-001": _containers_001,
    "CONTAINERS-002": _containers_002,
    "CONTAINERS-003": _containers_003,
    "CONTAINERS-004": _containers_004,
    "CONTAINERS-005": _containers_005,
    "HARDWARE-001": _hardware_001,
    "HARDWARE-004": _hardware_004,
    "MOUNTS-001": _mounts_001,
    "MOUNTS-002": _mounts_002,
    "MOUNTS-003": _mounts_003,
    "NETWORK-001": _network_001,
    "NETWORK-002": _network_002,
    "NETWORK-003": _network_003,
    "NETWORK-004": _network_004,
    "OPEN_FILES-001": _open_files_001,
    "PACKAGES-001": _packages_001,
    "PACKAGES-003": _packages_003,
    "PACKAGES-005": _packages_005,
    "PORTS-003": _ports_003,
    "PROCESSES-001": _processes_001,
    "PROCESSES-002": _processes_002,
    "PROCESSES-003": _processes_003,
    "PROCESSES-004": _processes_004,
    "PROCESSES-006": _processes_006,
    "SBOM-002": _sbom_002,
    "SBOM-004": _sbom_004,
    "SECURITY-001": _security_001,
    "SECURITY-002": _security_002,
    "SECURITY-003": _security_003,
    "SECURITY-004": _security_004,
    "SECURITY-005": _security_005,
    "SERVICES-001": _services_001,
    "SERVICES-002": _services_002,
    "SERVICES-004": _services_004,
    "SERVICES-005": _services_005,
    "STORAGE-003": _storage_003,
    "STORAGE-004": _storage_004,
    "STORAGE-005": _storage_005,
    "SYSCTL-001": _sysctl_001,
    "SYSCTL-003": _sysctl_003,
    "SYSCTL-005": _sysctl_005,
    "TASKS-001": _tasks_001,
    "TASKS-002": _tasks_002,
    "TASKS-003": _tasks_003,
    "TASKS-004": _tasks_004,
    "TASKS-005": _tasks_005,
    "USERS-001": _users_001,
    "USERS-002": _users_002,
    "USERS-003": _users_003,
    "USERS-005": _users_005,
    "USERS-006": _users_006,
}
