"""
manager/manager/attacklens/detections/sbom_posture.py
SBOM vulnerability scanning and endpoint security posture validation.

Validates software dependencies against threat intelligence feeds and validates
OS-level security feature status. Detects posture drift (controls transitioning
from enabled → disabled).

Telemetry sections handled:
  sbom, sbom_cyclonedx, sbom_spdx, security_posture, endpoint_posture,
  pip_list, npm_list, gem_list

COMPLIANCE MAPPING:
  NIST CSF:    PR.IP-1 (Baseline config maintained), ID.SC-4 (Supply chain risk)
  CIS Control: 2 (Software Asset Management), 18 (Pen Test)
  SOC 2:       CC7.1 (Vulnerability detection), CC8.1 (Change management)
  ISO 27001:   A.12.6.1 (Technical vulnerabilities), A.14.2.1 (Secure dev policy)

MITRE ATT&CK:
  T1195   (Supply Chain Compromise)
  T1562   (Impair Defenses)
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("manager.attacklens.detections.sbom_posture")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

CVSS_HIGH_THRESHOLD: float   = 7.0
CVSS_MEDIUM_THRESHOLD: float = 4.0

# XProtect / AV definition staleness threshold
AV_STALE_DAYS: int           = 7
OS_PATCH_STALE_DAYS: int     = 30

# License categories that conflict with typical enterprise policy
RESTRICTED_LICENSES: frozenset[str] = frozenset({
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "GPL-2.0", "GPL-2.0-only",
    "SSPL-1.0", "BUSL-1.1", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0",
    "Commons-Clause",
})

# Security controls expected on managed endpoints.
# Maps control_key → human_readable_name.
CRITICAL_CONTROLS: dict[str, str] = {
    # macOS
    "sip_enabled":          "System Integrity Protection (SIP)",
    "gatekeeper_enabled":   "Gatekeeper",
    "filevault_enabled":    "FileVault Disk Encryption",
    "firewall_enabled":     "macOS Application Firewall",
    # Linux
    "selinux_enforcing":    "SELinux enforcing mode",
    "apparmor_enforcing":   "AppArmor enforcing mode",
    "auditd_running":       "auditd",
    "ufw_enabled":          "UFW Firewall",
    "firewalld_enabled":    "firewalld",
    # Windows
    "defender_realtime":    "Windows Defender Real-Time Protection",
    "bitlocker_enabled":    "BitLocker Drive Encryption",
    "windows_firewall":     "Windows Firewall",
    "secure_boot":          "Secure Boot",
    "uac_enabled":          "User Account Control (UAC)",
}

# Controls whose disabled state is CRITICAL (not just HIGH)
CRITICAL_DISABLED: frozenset[str] = frozenset({
    "sip_enabled", "gatekeeper_enabled", "filevault_enabled",
    "defender_realtime", "bitlocker_enabled", "secure_boot",
})

# Controls whose disabled state is HIGH
HIGH_DISABLED: frozenset[str] = frozenset({
    "firewall_enabled", "selinux_enforcing", "apparmor_enforcing",
    "ufw_enabled", "firewalld_enabled", "windows_firewall", "uac_enabled",
    "auditd_running",
})

# Sections this module handles
SBOM_SECTIONS: frozenset[str] = frozenset({
    "sbom", "sbom_cyclonedx", "sbom_spdx",
    "pip_list", "npm_list", "gem_list",
    "security_posture", "endpoint_posture",
})

CVE_CACHE_TTL_SECS: int          = 21600   # 6 hours
NVD_RATE_LIMIT_PER_30S: int      = 5
MAX_CVE_LOOKUPS_PER_SCAN: int    = 25
DEDUP_WINDOW_SECS: int           = 86400   # 24 hours
RATE_LIMIT_MAX_PER_HOUR: int     = 50

# ─────────────────────────────────────────────────────────────────────────────
# MODULE STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]                   = {}
_rate_counter: dict[str, list[float]]            = {}
_nvd_request_times: list[float]                  = []
_cve_result_cache: dict[str, tuple[float, list]] = {}
_scan_nvd_calls: dict[str, int]                  = {}

# ─────────────────────────────────────────────────────────────────────────────
# DEDUP / RATE-LIMIT
# ─────────────────────────────────────────────────────────────────────────────

def _dedup_key(agent_id: str, rule_id: str, item: str) -> str:
    return hashlib.sha256(f"{agent_id}:{rule_id}:{item}".encode()).hexdigest()[:16]


def _should_suppress(agent_id: str, rule_id: str, item: str) -> bool:
    now = time.time()
    key = _dedup_key(agent_id, rule_id, item)
    if now - _dedup_cache.get(key, 0) < DEDUP_WINDOW_SECS:
        return True
    times = [t for t in _rate_counter.get(agent_id, []) if now - t < 3600]
    if len(times) >= RATE_LIMIT_MAX_PER_HOUR:
        log.debug("Rate limit: agent=%s module=sbom_posture", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False

# ─────────────────────────────────────────────────────────────────────────────
# NVD RATE GATE / CACHE
# ─────────────────────────────────────────────────────────────────────────────

def _nvd_rate_gate() -> bool:
    now = time.time()
    window = [t for t in _nvd_request_times if now - t < 30]
    if len(window) >= NVD_RATE_LIMIT_PER_30S:
        return False
    window.append(now)
    _nvd_request_times[:] = window
    return True


def _can_nvd_lookup(agent_id: str) -> bool:
    count = _scan_nvd_calls.get(agent_id, 0)
    if count >= MAX_CVE_LOOKUPS_PER_SCAN:
        return False
    _scan_nvd_calls[agent_id] = count + 1
    return True


def _get_cve_cache(name: str, version: str) -> Optional[list]:
    entry = _cve_result_cache.get(f"{name}:{version}")
    if entry and time.time() - entry[0] < CVE_CACHE_TTL_SECS:
        return entry[1]
    return None


def _set_cve_cache(name: str, version: str, results: list) -> None:
    _cve_result_cache[f"{name}:{version}"] = (time.time(), results)

# ─────────────────────────────────────────────────────────────────────────────
# SBOM INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def _parse_purl(purl: str) -> tuple[str, str]:
    """Extract (name, version) from a package URL (purl) string."""
    if not purl:
        return "", ""
    # pkg:type/namespace/name@version?qualifiers#subpath
    try:
        rest = re.sub(r"^pkg:[^/]+/", "", purl)
        # strip qualifiers and subpath
        rest = rest.split("?")[0].split("#")[0]
        if "@" in rest:
            name_part, version = rest.rsplit("@", 1)
        else:
            name_part, version = rest, ""
        # Take last path component as name
        name = name_part.split("/")[-1]
        return name.lower(), version
    except Exception:
        return "", ""


def ingest_sbom(section: str, data: Any) -> list[dict]:
    """
    Normalize SBOM data from CycloneDX JSON, SPDX JSON, or pip/npm/gem list
    into: [{name, version, purl, license, supplier, runtime}]
    """
    components: list[dict] = []

    if isinstance(data, dict):
        # ── CycloneDX JSON ───────────────────────────────────────────────────
        if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
            for comp in data.get("components", []):
                name    = comp.get("name", "").lower()
                version = comp.get("version", "")
                purl    = comp.get("purl", "")
                license_ids: list[str] = []
                lic = comp.get("licenses", [])
                if isinstance(lic, list):
                    for l in lic:
                        if isinstance(l, dict):
                            license_ids.append(
                                l.get("license", {}).get("id", "") or
                                l.get("expression", "")
                            )
                components.append({
                    "name":     name,
                    "version":  version,
                    "purl":     purl,
                    "license":  ", ".join(filter(None, license_ids)),
                    "supplier": comp.get("supplier", {}).get("name", "") if isinstance(comp.get("supplier"), dict) else comp.get("supplier", ""),
                    "runtime":  True,
                })
            return components

        # ── SPDX JSON ────────────────────────────────────────────────────────
        if "spdxVersion" in data or "SPDXID" in data:
            for pkg in data.get("packages", []):
                name    = pkg.get("name", "").lower()
                version = pkg.get("versionInfo", "")
                purl    = ""
                for ref in pkg.get("externalRefs", []):
                    if ref.get("referenceType") == "purl":
                        purl = ref.get("referenceLocator", "")
                        break
                components.append({
                    "name":     name,
                    "version":  version,
                    "purl":     purl,
                    "license":  pkg.get("licenseConcluded", "") or pkg.get("licenseDeclared", ""),
                    "supplier": pkg.get("supplier", ""),
                    "runtime":  True,
                })
            return components

        # ── pip list JSON: [{name, version}] or {name: version} ──────────────
        if "packages" in data:
            data = data["packages"]

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                # Text line "name==version" or "name version"
                line = str(item).strip()
                m = re.match(r"^(\S+)\s*[=@><~!^]+\s*(\S+)", line)
                if m:
                    components.append({
                        "name": m.group(1).lower(), "version": m.group(2),
                        "purl": "", "license": "", "supplier": "", "runtime": True,
                    })
                continue
            name    = (item.get("name") or item.get("Name") or "").lower()
            version = item.get("version") or item.get("Version") or ""
            purl    = item.get("purl", "")
            if not name and purl:
                name, version = _parse_purl(purl)
            components.append({
                "name":     name,
                "version":  version,
                "purl":     purl,
                "license":  item.get("license", "") or item.get("License", ""),
                "supplier": item.get("supplier", "") or item.get("Supplier", ""),
                "runtime":  bool(item.get("runtime", True)),
            })
        return components

    if isinstance(data, str):
        # pip list text: "name  version"
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("Package"):
                continue
            parts = re.split(r"\s+", line)
            if len(parts) >= 2:
                components.append({
                    "name": parts[0].lower(), "version": parts[1],
                    "purl": "", "license": "", "supplier": "", "runtime": True,
                })

    return components


def ingest_posture(data: Any) -> dict[str, Any]:
    """
    Normalize security posture data from any OS format into a flat dict:
      {control_key: bool/str/int, "last_update_days": int, "av_definition_days": int, ...}
    """
    if not isinstance(data, dict):
        return {}
    posture: dict[str, Any] = {}

    # macOS controls
    if "sip" in data or "sip_enabled" in data:
        val = data.get("sip") or data.get("sip_enabled")
        posture["sip_enabled"] = _truthy(val)
    if "gatekeeper" in data or "gatekeeper_enabled" in data:
        posture["gatekeeper_enabled"] = _truthy(data.get("gatekeeper") or data.get("gatekeeper_enabled"))
    if "filevault" in data or "filevault_enabled" in data:
        posture["filevault_enabled"] = _truthy(data.get("filevault") or data.get("filevault_enabled"))
    if "firewall" in data or "firewall_enabled" in data:
        posture["firewall_enabled"] = _truthy(data.get("firewall") or data.get("firewall_enabled"))
    if "xprotect_version" in data:
        posture["xprotect_version"] = str(data["xprotect_version"])
    if "av_definition_days" in data:
        posture["av_definition_days"] = int(data["av_definition_days"])

    # Linux controls
    for k in ("selinux_enforcing", "apparmor_enforcing", "auditd_running",
              "ufw_enabled", "firewalld_enabled"):
        if k in data:
            posture[k] = _truthy(data[k])

    # Windows controls
    for k in ("defender_realtime", "bitlocker_enabled", "windows_firewall",
              "secure_boot", "uac_enabled"):
        if k in data:
            posture[k] = _truthy(data[k])

    # Patch status
    if "last_update_days" in data:
        posture["last_update_days"] = int(data["last_update_days"])
    if "os_patch_days" in data:
        posture["last_update_days"] = int(data["os_patch_days"])

    return posture


def _truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    s = str(val).lower().strip()
    return s in ("true", "enabled", "enforcing", "on", "1", "yes", "running", "active")

# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _make_alert(
    agent_id: str, hostname: str, severity: str, rule_id: str,
    title: str, description: str, mitre_technique: str,
    evidence: dict, raw_telemetry: Any,
) -> dict:
    tactic = "Initial Access" if "T1195" in mitre_technique else "Defense Evasion"
    return {
        "alert_id":            str(uuid.uuid4()),
        "severity":            severity,
        "title":               title,
        "description":         description,
        "affected_asset":      hostname or agent_id,
        "mitre_tactic":        tactic,
        "mitre_technique":     mitre_technique,
        "evidence":            evidence,
        "raw_telemetry":       raw_telemetry if isinstance(raw_telemetry, dict) else {"raw": str(raw_telemetry)},
        "compliance_controls": [
            "NIST CSF PR.IP-1", "NIST CSF ID.SC-4",
            "CIS Control 2", "CIS Control 18",
            "SOC 2 CC7.1", "SOC 2 CC8.1",
            "ISO 27001 A.12.6.1", "ISO 27001 A.14.2.1",
        ],
        "recommended_action":  _rec_action(rule_id),
        "false_positive_notes": _fp_note(rule_id),
        "timestamp_utc":       datetime.now(timezone.utc).isoformat(),
        "agent_id":            agent_id,
        "detection_module":    "sbom_posture",
        "rule_id":             rule_id,
    }


def _rec_action(rule_id: str) -> str:
    m = {
        "sbom_kev":       "Upgrade or patch the affected package immediately. File a P0 incident.",
        "sbom_cve_high":  "Upgrade the package to a patched version. Review if used in production runtime.",
        "sbom_license":   "Review the package license with legal. Replace if it conflicts with policy.",
        "posture_critical_disabled": "Re-enable the security control immediately. Investigate who/what disabled it.",
        "posture_high_disabled":    "Enable the security control and investigate the configuration change.",
        "posture_av_stale":         "Update AV/XProtect definitions immediately.",
        "posture_patch_stale":      "Apply pending OS security patches.",
        "posture_drift":            "Investigate who changed the security control. Re-enable if unauthorized.",
    }
    return m.get(rule_id, "Investigate and remediate the flagged security issue.")


def _fp_note(rule_id: str) -> str:
    m = {
        "sbom_kev":       "Verify the CVE applies to the specific version and configuration in use.",
        "sbom_cve_high":  "Vendor backports may make the installed version safe. Check vendor advisory.",
        "sbom_license":   "License exceptions may be pre-approved. Check with the legal team.",
        "posture_critical_disabled": "Control may be intentionally disabled for maintenance — but must be re-enabled.",
        "posture_high_disabled":    "Check if a replacement security control is active (e.g., a third-party firewall).",
        "posture_av_stale":         "AV updates may be in progress. Verify update agent is healthy.",
        "posture_patch_stale":      "Patches may be staged but not yet applied. Verify update pipeline.",
        "posture_drift":            "Authorized configuration changes may trigger this. Verify with the admin.",
    }
    return m.get(rule_id, "Review context before escalating.")

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION PASSES
# ─────────────────────────────────────────────────────────────────────────────

async def detect_sbom_vulnerabilities(
    agent_id: str,
    components: list[dict],
    nvd_client: Any,
) -> list[dict]:
    """CRITICAL (KEV) / HIGH (CVSS ≥ 7.0) — SBOM packages with known CVEs."""
    findings: list[dict] = []
    if nvd_client is None:
        return findings

    _scan_nvd_calls[agent_id] = 0
    for comp in components:
        name    = comp.get("name", "")
        version = comp.get("version", "")
        if not name or not version:
            continue

        cached = _get_cve_cache(name, version)
        if cached is not None:
            cves = cached
        elif not _can_nvd_lookup(agent_id) or not _nvd_rate_gate():
            break
        else:
            try:
                cves = await nvd_client.lookup(name, version)
                _set_cve_cache(name, version, cves)
            except Exception as exc:
                log.debug("NVD lookup failed name=%s: %s", name, exc)
                continue

        for cve in (cves or []):
            cvss   = float(cve.get("cvss_score", 0) or 0)
            kev    = bool(cve.get("kev"))
            cve_id = cve.get("cve_id", "unknown")

            if cvss < CVSS_MEDIUM_THRESHOLD and not kev:
                continue

            severity = "critical" if kev else ("high" if cvss >= CVSS_HIGH_THRESHOLD else "medium")
            item_key = f"{name}:{version}:{cve_id}"
            if _should_suppress(agent_id, "sbom_kev" if kev else "sbom_cve_high", item_key):
                continue

            evidence = {
                "package": name, "version": version, "purl": comp.get("purl", ""),
                "cve_id": cve_id, "cvss_score": cvss, "kev": kev,
                "runtime": comp.get("runtime", True),
                "description": cve.get("description", ""),
            }
            if kev:
                evidence["kev_date_added"] = cve.get("kev_date_added", "")

            rule_id = "sbom_kev" if kev else "sbom_cve_high"
            findings.append(_make_alert(
                agent_id=agent_id, hostname="",
                severity=severity, rule_id=rule_id,
                title=f"SBOM package {name} {version} — {cve_id} "
                      + ("(CISA KEV)" if kev else f"(CVSS {cvss:.1f})"),
                description=(
                    f"Dependency '{name}' version {version} in the software bill of materials "
                    f"has CVE {cve_id} (CVSS {cvss:.1f}). "
                    + ("CISA KEV: actively exploited in the wild. " if kev else "")
                    + cve.get("description", "")
                ),
                mitre_technique="T1195",
                evidence=evidence,
                raw_telemetry=comp,
            ))

    return findings


def detect_license_conflicts(agent_id: str, components: list[dict]) -> list[dict]:
    """LOW — Package with a license that conflicts with organizational policy."""
    findings: list[dict] = []
    for comp in components:
        license_str = comp.get("license", "") or ""
        flagged = [lic for lic in RESTRICTED_LICENSES
                   if lic.lower() in license_str.lower()]
        if not flagged:
            continue
        name = comp.get("name", "")
        item_key = f"{name}:{','.join(flagged)}"
        if _should_suppress(agent_id, "sbom_license", item_key):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="low", rule_id="sbom_license",
            title=f"License conflict: {name} uses {', '.join(flagged)}",
            description=(
                f"Package '{name}' is licensed under {license_str}, which may conflict "
                "with organizational IP policy. Copyleft and commercial-use-restriction "
                "licenses can impose obligations on proprietary software."
            ),
            mitre_technique="T1195",
            evidence={
                "package": name, "version": comp.get("version", ""),
                "license": license_str, "conflicting": flagged,
            },
            raw_telemetry=comp,
        ))
    return findings


def detect_posture_issues(agent_id: str, posture: dict) -> list[dict]:
    """
    CRITICAL / HIGH — Security controls that are disabled.
    MEDIUM — Stale AV definitions or OS patches.
    """
    findings: list[dict] = []

    for control_key, control_name in CRITICAL_CONTROLS.items():
        if control_key not in posture:
            continue
        enabled = posture[control_key]
        if not isinstance(enabled, bool):
            continue
        if enabled:
            continue

        severity = "critical" if control_key in CRITICAL_DISABLED else "high"
        rule_id  = "posture_critical_disabled" if severity == "critical" else "posture_high_disabled"
        item_key = f"{control_key}:disabled"
        if _should_suppress(agent_id, rule_id, item_key):
            continue

        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity=severity, rule_id=rule_id,
            title=f"Security control disabled: {control_name}",
            description=(
                f"The security control '{control_name}' is currently disabled on this endpoint. "
                + ("This is a critical defense evasion pre-condition. " if severity == "critical" else "")
                + "Attackers often disable security controls before deploying payloads."
            ),
            mitre_technique="T1562",
            evidence={"control_key": control_key, "control_name": control_name, "status": "disabled"},
            raw_telemetry=posture,
        ))

    # Stale AV definitions
    av_days = posture.get("av_definition_days")
    if isinstance(av_days, int) and av_days > AV_STALE_DAYS:
        if not _should_suppress(agent_id, "posture_av_stale", "av_definitions"):
            findings.append(_make_alert(
                agent_id=agent_id, hostname="",
                severity="medium", rule_id="posture_av_stale",
                title=f"AV/XProtect definitions stale ({av_days} days old)",
                description=(
                    f"Antivirus / XProtect definitions have not been updated in {av_days} days "
                    f"(threshold: {AV_STALE_DAYS} days). New threats may not be detected."
                ),
                mitre_technique="T1562",
                evidence={"av_definition_days": av_days, "threshold": AV_STALE_DAYS},
                raw_telemetry=posture,
            ))

    # Stale OS patches
    patch_days = posture.get("last_update_days")
    if isinstance(patch_days, int) and patch_days > OS_PATCH_STALE_DAYS:
        if not _should_suppress(agent_id, "posture_patch_stale", "os_patches"):
            findings.append(_make_alert(
                agent_id=agent_id, hostname="",
                severity="medium", rule_id="posture_patch_stale",
                title=f"OS security patches stale ({patch_days} days since last update)",
                description=(
                    f"The endpoint has not applied OS security updates in {patch_days} days "
                    f"(threshold: {OS_PATCH_STALE_DAYS} days). "
                    "Unpatched systems are significantly more vulnerable to exploitation."
                ),
                mitre_technique="T1562",
                evidence={"last_update_days": patch_days, "threshold": OS_PATCH_STALE_DAYS},
                raw_telemetry=posture,
            ))

    return findings


async def detect_posture_drift(
    agent_id: str,
    posture: dict,
    db: Any,
) -> list[dict]:
    """
    Alert when any security control transitions from enabled → disabled.
    Baseline persisted per agent in entity state.
    """
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "sbom_posture", "security_posture_baseline")
    baseline: dict[str, Any] = {}
    if raw_state:
        try:
            baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            baseline = {}

    updated = dict(baseline)
    for control_key, control_name in CRITICAL_CONTROLS.items():
        current = posture.get(control_key)
        if current is None:
            continue
        updated[control_key] = current
        prev = baseline.get(control_key)
        if prev is None:
            continue  # first-time baseline — no drift yet
        # Drift: was True, now False
        if prev is True and current is False:
            severity = "critical" if control_key in CRITICAL_DISABLED else "high"
            item_key = f"{control_key}:drift"
            if _should_suppress(agent_id, "posture_drift", item_key):
                continue
            findings.append(_make_alert(
                agent_id=agent_id, hostname="",
                severity=severity, rule_id="posture_drift",
                title=f"Security posture drift: {control_name} was enabled, now disabled",
                description=(
                    f"Security control '{control_name}' was enabled in the last baseline "
                    f"but is now disabled. This is a strong indicator of defense evasion "
                    f"or unauthorized configuration change."
                ),
                mitre_technique="T1562",
                evidence={
                    "control_key": control_key, "control_name": control_name,
                    "previous_state": "enabled", "current_state": "disabled",
                },
                raw_telemetry=posture,
            ))

    try:
        await db.set_entity_state(
            agent_id, "sbom_posture", "security_posture_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist posture baseline agent=%s: %s", agent_id, exc)

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

async def analyze(
    agent_id: str,
    section:  str,
    data:     Any,
    db:       Any,
    hostname: str = "",
    *,
    nvd_client=None,
    feeds_manager=None,
) -> list[dict]:
    if section not in SBOM_SECTIONS:
        return []

    findings: list[dict] = []

    if section in {"security_posture", "endpoint_posture"}:
        posture = ingest_posture(data)
        for f in detect_posture_issues(agent_id, posture):
            f["affected_asset"] = hostname or agent_id
            findings.append(f)
        for f in await detect_posture_drift(agent_id, posture, db):
            f["affected_asset"] = hostname or agent_id
            findings.append(f)
    else:
        components = ingest_sbom(section, data)
        cve_findings = await detect_sbom_vulnerabilities(agent_id, components, nvd_client)
        for f in cve_findings:
            f["affected_asset"] = hostname or agent_id
            findings.append(f)
        for f in detect_license_conflicts(agent_id, components):
            f["affected_asset"] = hostname or agent_id
            findings.append(f)

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio
    import sys

    PASS = "\033[92mPASS\033[0m"
    FAIL = "\033[91mFAIL\033[0m"
    passed = failed = 0

    def check(label: str, cond: bool) -> None:
        global passed, failed
        if cond:
            print(f"  {PASS}  {label}")
            passed += 1
        else:
            print(f"  {FAIL}  {label}")
            failed += 1

    class MockNVD:
        async def lookup(self, name, version=""):
            DB = {
                ("log4j", "2.14.1"): [{
                    "cve_id": "CVE-2021-44228", "cvss_score": 10.0,
                    "severity": "critical", "description": "Log4Shell",
                    "kev": True, "kev_date_added": "2021-12-10",
                }],
                ("lodash", "4.17.20"): [{
                    "cve_id": "CVE-2021-23337", "cvss_score": 7.2,
                    "severity": "high", "description": "Command injection",
                    "kev": False,
                }],
                ("pyyaml", "5.3.1"): [{
                    "cve_id": "CVE-2020-14343", "cvss_score": 9.8,
                    "severity": "critical", "description": "Arbitrary code execution",
                    "kev": False,
                }],
            }
            return DB.get((name.lower(), version), [])

    class MockDB:
        def __init__(self):
            self._store: dict = {}

        async def get_entity_state(self, agent_id, ns, key):
            return self._store.get(f"{agent_id}:{ns}:{key}")

        async def set_entity_state(self, agent_id, ns, key, value, ts):
            self._store[f"{agent_id}:{ns}:{key}"] = value

    def fresh():
        _dedup_cache.clear()
        _rate_counter.clear()
        _nvd_request_times.clear()
        _cve_result_cache.clear()
        _scan_nvd_calls.clear()

    nvd = MockNVD()

    async def run_tests():
        global passed, failed

        # ── 1. CycloneDX ingestion ──────────────────────────────────────────
        print("\nTest 1: CycloneDX JSON ingestion")
        cdx = {
            "bomFormat": "CycloneDX", "specVersion": "1.4",
            "components": [
                {"name": "log4j", "version": "2.14.1",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                 "licenses": [{"license": {"id": "Apache-2.0"}}]},
                {"name": "lodash", "version": "4.17.20",
                 "purl": "pkg:npm/lodash@4.17.20",
                 "licenses": [{"license": {"id": "MIT"}}]},
            ],
        }
        comps = ingest_sbom("sbom_cyclonedx", cdx)
        check("2 components parsed", len(comps) == 2)
        check("log4j present", comps[0]["name"] == "log4j")
        check("purl preserved", "log4j-core" in comps[0]["purl"])

        # ── 2. SPDX JSON ingestion ──────────────────────────────────────────
        print("\nTest 2: SPDX JSON ingestion")
        spdx = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "requests", "versionInfo": "2.28.0",
                 "licenseConcluded": "Apache-2.0",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:pypi/requests@2.28.0"}]},
            ],
        }
        comps = ingest_sbom("sbom_spdx", spdx)
        check("1 component", len(comps) == 1)
        check("version correct", comps[0]["version"] == "2.28.0")

        # ── 3. pip list text ingestion ──────────────────────────────────────
        print("\nTest 3: pip list text ingestion")
        pip_text = "Package    Version\n---------- -------\nnumpy      1.24.0\npandas     2.0.0\n"
        comps = ingest_sbom("pip_list", pip_text)
        check("2 packages", len(comps) == 2)
        check("numpy found", any(c["name"] == "numpy" for c in comps))

        # ── 4. CVE: KEV → CRITICAL ───────────────────────────────────────────
        print("\nTest 4: SBOM CVE — Log4Shell (KEV → critical)")
        fresh()
        db = MockDB()
        comps = [{"name": "log4j", "version": "2.14.1", "purl": "", "license": "", "supplier": "", "runtime": True}]
        findings = await detect_sbom_vulnerabilities("agentA", comps, nvd)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("kev true", findings[0]["evidence"]["kev"] is True)
        check("rule sbom_kev", findings[0]["rule_id"] == "sbom_kev")

        # ── 5. CVE: HIGH (CVSS 7.2, no KEV) ─────────────────────────────────
        print("\nTest 5: SBOM CVE — lodash HIGH")
        fresh()
        comps = [{"name": "lodash", "version": "4.17.20", "purl": "", "license": "", "supplier": "", "runtime": True}]
        findings = await detect_sbom_vulnerabilities("agentB", comps, nvd)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("rule sbom_cve_high", findings[0]["rule_id"] == "sbom_cve_high")

        # ── 6. CVE: no match → no findings ───────────────────────────────────
        print("\nTest 6: SBOM CVE — no match")
        fresh()
        comps = [{"name": "numpy", "version": "1.24.0", "purl": "", "license": "", "supplier": "", "runtime": True}]
        findings = await detect_sbom_vulnerabilities("agentC", comps, nvd)
        check("no findings", len(findings) == 0)

        # ── 7. CVE: None nvd_client → no crash ───────────────────────────────
        print("\nTest 7: None nvd_client → no findings")
        fresh()
        comps = [{"name": "log4j", "version": "2.14.1", "purl": "", "license": "", "supplier": "", "runtime": True}]
        findings = await detect_sbom_vulnerabilities("agentD", comps, None)
        check("no findings", len(findings) == 0)

        # ── 8. License: AGPL-3.0 → LOW ───────────────────────────────────────
        print("\nTest 8: License conflict AGPL-3.0")
        fresh()
        comps = [{"name": "mypkg", "version": "1.0", "purl": "", "license": "AGPL-3.0", "supplier": "", "runtime": True}]
        findings = detect_license_conflicts("agentE", comps)
        check("1 finding", len(findings) == 1)
        check("severity low", findings[0]["severity"] == "low")
        check("AGPL in conflicting", "AGPL-3.0" in findings[0]["evidence"]["conflicting"])

        # ── 9. License: MIT → no alert ────────────────────────────────────────
        print("\nTest 9: Permissive license — no alert")
        fresh()
        comps = [{"name": "requests", "version": "2.28.0", "purl": "", "license": "MIT", "supplier": "", "runtime": True}]
        findings = detect_license_conflicts("agentF", comps)
        check("no findings", len(findings) == 0)

        # ── 10. Posture: SIP disabled → CRITICAL ─────────────────────────────
        print("\nTest 10: SIP disabled → CRITICAL")
        fresh()
        posture = {"sip_enabled": False}
        findings = detect_posture_issues("agentG", posture)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule posture_critical_disabled", findings[0]["rule_id"] == "posture_critical_disabled")

        # ── 11. Posture: Gatekeeper disabled → CRITICAL ───────────────────────
        print("\nTest 11: Gatekeeper disabled → CRITICAL")
        fresh()
        posture = {"gatekeeper_enabled": False}
        findings = detect_posture_issues("agentH", posture)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")

        # ── 12. Posture: SELinux permissive → HIGH ────────────────────────────
        print("\nTest 12: SELinux permissive → HIGH")
        fresh()
        posture = {"selinux_enforcing": False}
        findings = detect_posture_issues("agentI", posture)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")

        # ── 13. Posture: all controls enabled → no alert ─────────────────────
        print("\nTest 13: All controls enabled — no alert")
        fresh()
        posture = {
            "sip_enabled": True, "gatekeeper_enabled": True,
            "filevault_enabled": True, "firewall_enabled": True,
        }
        findings = detect_posture_issues("agentJ", posture)
        check("no findings", len(findings) == 0)

        # ── 14. Posture: stale AV definitions → MEDIUM ───────────────────────
        print("\nTest 14: Stale AV definitions → MEDIUM")
        fresh()
        posture = {"av_definition_days": 10}
        findings = detect_posture_issues("agentK", posture)
        check("1 finding", len(findings) == 1)
        check("severity medium", findings[0]["severity"] == "medium")
        check("rule posture_av_stale", findings[0]["rule_id"] == "posture_av_stale")

        # ── 15. Posture: stale OS patches → MEDIUM ────────────────────────────
        print("\nTest 15: Stale OS patches → MEDIUM")
        fresh()
        posture = {"last_update_days": 45}
        findings = detect_posture_issues("agentL", posture)
        check("1 finding", len(findings) == 1)
        check("rule posture_patch_stale", findings[0]["rule_id"] == "posture_patch_stale")

        # ── 16. Posture drift: SIP enabled → disabled → CRITICAL ─────────────
        print("\nTest 16: Posture drift SIP enabled → disabled")
        fresh()
        db16 = MockDB()
        # First scan: SIP enabled
        await detect_posture_drift("agentM", {"sip_enabled": True}, db16)
        # Second scan: SIP disabled
        findings = await detect_posture_drift("agentM", {"sip_enabled": False}, db16)
        check("1 drift finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule posture_drift", findings[0]["rule_id"] == "posture_drift")
        check("previous_state enabled", findings[0]["evidence"]["previous_state"] == "enabled")

        # ── 17. Posture drift: disabled → disabled → no extra alert ───────────
        print("\nTest 17: Drift disabled→disabled → no duplicate")
        fresh()
        db17 = MockDB()
        await detect_posture_drift("agentN", {"firewall_enabled": False}, db17)
        findings = await detect_posture_drift("agentN", {"firewall_enabled": False}, db17)
        check("no drift finding (stable disabled)", len(findings) == 0)

        # ── 18. Posture drift: first baseline — no finding ───────────────────
        print("\nTest 18: First baseline — no drift alert")
        fresh()
        db18 = MockDB()
        findings = await detect_posture_drift("agentO", {"sip_enabled": True}, db18)
        check("no findings (first baseline)", len(findings) == 0)

        # ── 19. Full analyze() — SBOM section ────────────────────────────────
        print("\nTest 19: Full analyze() SBOM section")
        fresh()
        db19 = MockDB()
        data = {
            "bomFormat": "CycloneDX", "specVersion": "1.4",
            "components": [
                {"name": "log4j", "version": "2.14.1", "purl": "", "licenses": []},
                {"name": "mypkg", "version": "1.0", "purl": "", "licenses": [{"license": {"id": "AGPL-3.0"}}]},
            ],
        }
        findings = await analyze("agentP", "sbom", data, db19, hostname="host-p", nvd_client=nvd)
        rule_ids = {f["rule_id"] for f in findings}
        check("sbom_kev fired", "sbom_kev" in rule_ids)
        check("sbom_license fired", "sbom_license" in rule_ids)
        check("affected_asset set", all(f["affected_asset"] == "host-p" for f in findings))

        # ── 20. Full analyze() — posture section ─────────────────────────────
        print("\nTest 20: Full analyze() posture section")
        fresh()
        db20 = MockDB()
        posture_data = {"sip_enabled": False, "filevault_enabled": False, "av_definition_days": 10}
        findings = await analyze("agentQ", "security_posture", posture_data, db20)
        rule_ids = {f["rule_id"] for f in findings}
        check("posture_critical_disabled fired", "posture_critical_disabled" in rule_ids)
        check("posture_av_stale fired", "posture_av_stale" in rule_ids)

        # ── 21. Non-SBOM section → empty ─────────────────────────────────────
        print("\nTest 21: Non-SBOM section → empty")
        fresh()
        db21 = MockDB()
        findings = await analyze("agentR", "processes", [], db21)
        check("empty for non-SBOM section", len(findings) == 0)

        print(f"\n{'─'*50}")
        total = passed + failed
        print(f"Results: {passed}/{total} passed", end="")
        if failed:
            print(f"  ({failed} FAILED)")
            sys.exit(1)
        else:
            print("  — all OK")

    asyncio.run(run_tests())
