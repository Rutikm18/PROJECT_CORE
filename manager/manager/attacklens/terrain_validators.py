"""
manager/manager/attacklens/terrain_validators.py — Terrain-aware Validated
Findings scoring.

Each finding belongs to exactly one *attack terrain* (Citadels / Vector /
Origin / Identity / Posture / Mesh).  Within that terrain we evaluate a fixed,
named list of criteria — KEV listing, AI verdict, exploitability, posture
status, etc. — and compute a weighted percentage.  The Validated Findings
page filters at the analyst-configured threshold (Settings → Validation).

Why per-terrain:
  Different terrains demand different proof.  A vulnerability finding cares
  about KEV + EPSS + exploit + reachability.  A network finding cares about
  multi-source IOC + beaconing.  A persistence finding cares about path,
  signer, and parent-child lineage.  Forcing every finding through the same
  generic factor list dilutes the signal.

Each criterion is:
  {
    "name":        <stable id used in the UI>,
    "label":       <human-readable title>,
    "description": <what is being checked>,
    "weight":      <0..1 — contribution to the final percentage>,
    "evaluate":    callable(finding, enriched) -> float in [0..1]
                   (1.0 = fully met, 0.5 = partial, 0.0 = not met)
  }

The result of `evaluate_finding(finding, enriched, ai_verdict)` is:
  {
    "terrain":     "origin",
    "score":       0..1   (weighted average over criteria),
    "percentage":  0..100,
    "criteria":    [{name, label, description, weight, met (float),
                     status ("met"|"partial"|"not_met"|"n/a"),
                     contribution (weight × met)}],
    "met_count":   <int>,
    "total_count": <int>,
  }
"""
from __future__ import annotations

import json
import ipaddress
import logging
import re
from typing import Any, Callable, Optional

from .terrain_catalog import (
    UNCLASSIFIED_TERRAIN_ID,
    all_terrains,
    terrain_for_category,
)

log = logging.getLogger("manager.attacklens.terrain_validators")


# Backward-compatible export for callers that iterate category assignments.
# The source of truth lives in terrain_catalog.py.
CATEGORY_TO_TERRAIN: dict[str, str] = {
    category: definition.id
    for definition in all_terrains()
    for category in definition.categories
}


def terrain_for(finding: dict) -> str:
    explicit = str(finding.get("terrain_id") or "").strip().lower()
    known_ids = {definition.id for definition in all_terrains()}
    if explicit in known_ids or explicit == UNCLASSIFIED_TERRAIN_ID:
        return explicit
    cat = (finding.get("category") or "").lower()
    return terrain_for_category(cat) or UNCLASSIFIED_TERRAIN_ID


# ── Helpers ─────────────────────────────────────────────────────────────────

def _ev(f: dict) -> dict:
    """Parse evidence whether stored as dict or JSON string."""
    e = f.get("evidence")
    if isinstance(e, dict):
        return e
    if isinstance(e, str):
        try:
            return json.loads(e) or {}
        except json.JSONDecodeError:
            return {}
    return {}


def _list(v) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            d = json.loads(v)
            return d if isinstance(d, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _has_cve(f: dict) -> bool:
    cves = _list(f.get("cve_ids"))
    if cves:
        return True
    ev = _ev(f)
    return bool(ev.get("cve_id") or ev.get("cve_ids") or
                (isinstance(ev.get("cve"), dict) and ev["cve"].get("cve_id")))


def _epss(f: dict) -> float:
    try:
        v = float(f.get("epss_score") or 0)
        if v > 0:
            return v
    except (TypeError, ValueError):
        pass
    ev = _ev(f)
    try:
        return float(ev.get("epss_score") or ev.get("epss") or
                     (isinstance(ev.get("cve"), dict)
                      and (ev["cve"].get("epss_score") or ev["cve"].get("epss")))
                     or 0)
    except (TypeError, ValueError):
        return 0.0


def _kev(f: dict, enriched: dict) -> bool:
    if enriched.get("kev_hit"):
        return True
    if f.get("kev"):
        return True
    ev = _ev(f)
    if ev.get("kev") or ev.get("cisa_kev"):
        return True
    cve = ev.get("cve")
    if isinstance(cve, dict) and (cve.get("kev") or cve.get("cisa_kev")):
        return True
    return False


def _exploit_available(f: dict) -> bool:
    if f.get("exploit_available"):
        return True
    srcs = _list(f.get("exploit_sources"))
    if srcs:
        return True
    ev = _ev(f)
    if ev.get("exploit_available"):
        return True
    cve = ev.get("cve") if isinstance(ev.get("cve"), dict) else None
    if cve and cve.get("exploit_available"):
        return True
    if cve and cve.get("reference_tags") and "Exploit" in cve["reference_tags"]:
        return True
    return False


def _ai_score(ai_verdict: Optional[dict]) -> float:
    """Map AI verdict to a 0..1 contribution. Uncertain/None → 0.5."""
    if not ai_verdict or not isinstance(ai_verdict, dict):
        return 0.5
    label = (ai_verdict.get("label") or "").lower()
    conf  = float(ai_verdict.get("confidence") or 0.5)
    if label == "tp":
        return max(0.5, conf)
    if label == "fp":
        return max(0.0, 1.0 - conf)
    return 0.5


# ── Criterion lists per terrain ─────────────────────────────────────────────
# Each terrain has 6-7 criteria covering the analyst playbook for that
# attack surface.  Weights sum to 1.0 per terrain.

ORIGIN_CRITERIA: list[dict] = [
    {
        "name":  "kev_listed",
        "label": "CISA KEV listed",
        "description": "Vulnerability is in CISA's Known Exploited Vulnerabilities catalogue (actively exploited in the wild).",
        "weight": 0.25,
        "anchor": True,   # KEV alone is a definitive TP signal
        "evaluate": lambda f, e: 1.0 if _kev(f, e) else 0.0,
    },
    {
        "name":  "epss_high",
        "label": "EPSS exploitation probability",
        "description": "Predicted probability of in-the-wild exploitation within 30 days. ≥0.7 = high, ≥0.3 = moderate.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if _epss(f) >= 0.7 else (0.6 if _epss(f) >= 0.3 else (0.3 if _epss(f) >= 0.05 else 0.0)),
    },
    {
        "name":  "public_exploit",
        "label": "Public exploit confirmed",
        "description": "ExploitDB / Metasploit module / PoC reference attached to the CVE.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if _exploit_available(f) else 0.0,
    },
    {
        "name":  "cvss_severe",
        "label": "CVSS base score severity",
        "description": "Computed severity from CVSS v3.1 base metric. ≥9 critical, ≥7 high.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if (f.get("cvss_score") or 0) >= 9 else (0.7 if (f.get("cvss_score") or 0) >= 7 else (0.4 if (f.get("cvss_score") or 0) >= 4 else 0.0)),
    },
    {
        "name":  "package_running",
        "label": "Package actively running",
        "description": "Detected by behavioral / process telemetry — vulnerability is loaded, not just installed.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if (e.get("package_running") or _ev(f).get("running") or _ev(f).get("process_present")) else 0.0,
    },
    {
        "name":  "service_reachable",
        "label": "Service reachable",
        "description": "Open / listening port belonging to the vulnerable package — exploitable from network.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if (e.get("port_open") or _ev(f).get("port") or _ev(f).get("listen")) else 0.0,
    },
    {
        "name":  "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "Senior-SOC-analyst LLM review agrees this is a true positive.",
        "weight": 0.10,
        "evaluate": lambda f, e, ai=None: _ai_score(ai),
    },
]

def _is_port_finding(f: dict) -> bool:
    return f.get("category") == "port"


def _is_connection_finding(f: dict) -> bool:
    return f.get("category") in ("connection", "network")


def _risky_port(f: dict) -> bool:
    """Port is on the malicious-port list OR exposed to 0.0.0.0."""
    ev = _ev(f)
    if "rule:malicious_port" in str(f.get("source") or "") or "rule:wildcard_bind" in str(f.get("source") or ""):
        return True
    if str(ev.get("bind_addr") or ev.get("addr") or "") in ("0.0.0.0", "::"):
        return True
    try:
        port = int(ev.get("port") or 0)
        if port in (3389, 5900, 23, 21, 445, 135, 139, 1433, 3306):
            return True
    except (TypeError, ValueError):
        pass
    return False


def _source_feed_count(f: dict) -> int:
    """Count IOC feeds corroborating this finding from its source string."""
    src = str(f.get("source") or "")
    if not src:
        return 0
    if src.startswith("feed:") or src in ("abuseipdb","greynoise","shodan","urlhaus"):
        return 1
    return 0


def _external_exposure_score(f: dict) -> float:
    """Score public destinations and wildcard listeners without string heuristics."""
    ev = _ev(f)
    raw_ip = str(
        ev.get("dst_ip")
        or ev.get("remote_ip")
        or ev.get("remote_address")
        or ""
    ).strip()
    if raw_ip:
        candidate = raw_ip
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1:candidate.index("]")]
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            try:
                address = ipaddress.ip_address(candidate.rsplit(":", 1)[0])
            except ValueError:
                address = None
        if address is not None and address.is_global:
            return 1.0

    if str(ev.get("bind_addr") or ev.get("addr") or "") in ("0.0.0.0", "::"):
        return 0.5
    return 0.0


VECTOR_CRITERIA: list[dict] = [
    {
        "name":  "ioc_corroborated",
        "label": "Threat-intel corroboration",
        "description": "Destination is on a threat-intel feed (Feodo, ThreatFox, URLhaus, AbuseIPDB, Spamhaus). ≥ 2 feeds = strong.",
        "weight": 0.22,
        "anchor": True,   # any IOC feed hit is a strong TP signal
        "evaluate": lambda f, e: 1.0 if int(e.get("threat_intel_source_count", 0) or 0) >= 2 or (e.get("malicious_ip_hit") and _source_feed_count(f) >= 1) else (0.7 if e.get("malicious_ip_hit") or _source_feed_count(f) >= 1 else 0.0),
    },
    {
        "name":  "risky_port_exposure",
        "label": "Risky / wildcard-bound port",
        "description": "Listening port matches a known-malicious port list (Cobalt Strike 50050, Metasploit, RAT defaults) OR is bound to 0.0.0.0.",
        "weight": 0.18,
        # rule:malicious_port = explicit IOC match → smoking gun; wildcard bind alone is not.
        "anchor": True,
        "evaluate": lambda f, e: 1.0 if (_is_port_finding(f) and "rule:malicious_port" in str(f.get("source") or "")) else (0.6 if _is_port_finding(f) and _risky_port(f) else 0.0),
    },
    {
        "name":  "active_connection",
        "label": "Active established connection",
        "description": "Connection was ESTABLISHED at observation time with bytes transferred — not just a probe.",
        "weight": 0.12,
        "evaluate": lambda f, e: 1.0 if (_is_connection_finding(f) and (str(_ev(f).get("state","")).upper() == "ESTABLISHED" or _ev(f).get("bytes_out"))) else 0.0,
    },
    {
        "name":  "beacon_pattern",
        "label": "Beaconing pattern",
        "description": "Regular-interval connections suggesting C2 callback (FFT / interval-stddev analysis).",
        "weight": 0.08,
        "evaluate": lambda f, e: 1.0 if float(_ev(f).get("beacon_score") or 0) >= 0.8 else (0.5 if float(_ev(f).get("beacon_score") or 0) >= 0.5 else 0.0),
    },
    {
        "name":  "owner_suspicious",
        "label": "Owning process suspicious",
        "description": "Process making/owning the network call is unsigned, in temp path, or matches a LOLBin pattern.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if _ev(f).get("signed") is False or re.search(r"^(/tmp/|/var/tmp/|/dev/shm/)", str(_ev(f).get("path") or _ev(f).get("exe") or "")) or _ev(f).get("codesign_failed") else 0.0,
    },
    {
        "name":  "external_exposure",
        "label": "External / non-loopback destination",
        "description": "Connection is to a public-internet host or the port is reachable from outside (not 127.0.0.1).",
        "weight": 0.15,
        "evaluate": lambda f, e: _external_exposure_score(f),
    },
    {
        "name":  "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "LLM senior-analyst review labelled this true positive.",
        "weight": 0.15,
        "evaluate": lambda f, e, ai=None: _ai_score(ai),
    },
]

CITADELS_CRITERIA: list[dict] = [
    {
        "name":  "parent_child_anomaly",
        "label": "Suspicious parent → child spawn",
        "description": "Office app / browser / mail client spawned a shell or scripting interpreter (drive-by / macro exploit).",
        "weight": 0.20,
        "anchor": True,   # office→shell etc. is a definitive TP
        "evaluate": lambda f, e: 1.0 if (_ev(f).get("parent_child_anomaly") or "rule:process_lineage" in (f.get("source", "") or "")) else 0.0,
    },
    {
        "name":  "unsigned_binary",
        "label": "Unsigned / quarantined binary",
        "description": "Process binary fails codesign verification or carries the macOS quarantine xattr.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if _ev(f).get("signed") is False or _ev(f).get("quarantined") else 0.0,
    },
    {
        "name":  "temp_path_exec",
        "label": "Execution from temp / dev / Downloads",
        "description": "Binary path is in /tmp, /var/tmp, /dev/shm, ~/Downloads, or /var/folders — non-canonical install location.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if re.search(r"^(/tmp/|/var/tmp/|/dev/shm/|/Users/[^/]+/Downloads/|/var/folders/)", str(_ev(f).get("path") or _ev(f).get("exe") or "")) else 0.0,
    },
    {
        "name":  "memory_only",
        "label": "Memory-only / hollowed execution",
        "description": "Disk hash differs from in-memory hash (process hollowing / unbacked code).",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if _ev(f).get("image_disk_sha256") and _ev(f).get("image_mem_sha256") and _ev(f).get("image_disk_sha256") != _ev(f).get("image_mem_sha256") else 0.0,
    },
    {
        "name":  "persistence_paired",
        "label": "Paired with persistence",
        "description": "Same cluster contains a persistence-class signal (launchd, cron, scheduled task) — execution + foothold.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if e.get("paired_with_persistence") or e.get("cross_layer_match") else 0.0,
    },
    {
        "name":  "malware_hash",
        "label": "Malware hash match",
        "description": "SHA256 of the binary appears in a known-malicious-hash IOC feed.",
        "weight": 0.10,
        "anchor": True,   # malware-hash match is definitive
        "evaluate": lambda f, e: 1.0 if e.get("malicious_hash_hit") else 0.0,
    },
    {
        "name":  "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "LLM senior-analyst review labelled this true positive.",
        "weight": 0.15,
        "evaluate": lambda f, e, ai=None: _ai_score(ai),
    },
]

IDENTITY_CRITERIA: list[dict] = [
    {
        "name":  "uid_zero_non_root",
        "label": "UID 0 account other than root",
        "description": "A user with UID 0 exists with a non-`root` name — classic backdoor admin.",
        "weight": 0.30,
        "anchor": True,   # non-root UID 0 is a definitive TP
        "evaluate": lambda f, e: 1.0 if (str(_ev(f).get("uid", "")) == "0" and _ev(f).get("name", "") not in ("root", "")) else 0.0,
    },
    {
        "name":  "new_admin_recently",
        "label": "Newly-elevated admin",
        "description": "Account was granted admin privileges within the last 7 days (per behavioural baseline).",
        "weight": 0.20,
        "evaluate": lambda f, e: 1.0 if _ev(f).get("admin_recently_granted") or "behavioral_change" in (f.get("source", "") or "") else 0.0,
    },
    {
        "name":  "service_with_shell",
        "label": "System account with interactive shell",
        "description": "Service account (UID < 500) has a non-`/sbin/nologin` shell — privilege-escalation vector.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if (int(_ev(f).get("uid", -1) or -1) in range(1, 500) and _ev(f).get("shell") not in ("/bin/false","/usr/bin/false","/sbin/nologin","")) else 0.0,
    },
    {
        "name":  "stale_active",
        "label": "Stale-yet-active credential",
        "description": "Account not logged in for ≥90 days yet still enabled — abandoned access.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if _ev(f).get("last_login_days_ago", 0) >= 90 and _ev(f).get("enabled") else 0.0,
    },
    {
        "name":  "lateral_signal",
        "label": "Lateral-movement signal",
        "description": "Login from an unusual source IP, ASN, or geolocation for this account.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if _ev(f).get("lateral_movement") else 0.0,
    },
    {
        "name":  "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "LLM senior-analyst review labelled this true positive.",
        "weight": 0.15,
        "evaluate": lambda f, e, ai=None: _ai_score(ai),
    },
]

def _posture_key_off(f: dict, key_name: str) -> bool:
    """Detect a disabled posture control.  The engine's security handler emits
    findings with item_key='sec:<key>' and evidence={'<key>': False} — so we
    check both the item_key and the evidence-dict for the named key."""
    ev = _ev(f)
    if ev.get(key_name) is False:
        return True
    # Some emitters use {key: <name>, value: <bool>} shape
    if ev.get("key") == key_name and ev.get("value") is False:
        return True
    if str(f.get("item_key", "")).endswith(f":{key_name}") and ev.get(key_name) is False:
        return True
    return False


POSTURE_CRITERIA: list[dict] = [
    {
        "name":  "sip_disabled",
        "label": "SIP / kernel protection disabled",
        "description": "macOS System Integrity Protection is OFF — attacker can modify protected files. Critical baseline failure.",
        "weight": 0.25,
        "anchor": True,   # SIP off is a definitive baseline failure
        "evaluate": lambda f, e: 1.0 if _posture_key_off(f, "sip_enabled") else 0.0,
    },
    {
        "name":  "gatekeeper_off",
        "label": "Gatekeeper disabled",
        "description": "Unsigned applications can execute without prompt — code-signing enforcement bypassed.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if _posture_key_off(f, "gatekeeper") else 0.0,
    },
    {
        "name":  "filevault_off",
        "label": "FileVault disabled",
        "description": "Full-disk encryption is OFF — data extractable if device lost.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if _posture_key_off(f, "filevault") else 0.0,
    },
    {
        "name":  "firewall_off",
        "label": "Application firewall disabled",
        "description": "macOS application firewall is OFF — inbound connections unfiltered.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if _posture_key_off(f, "firewall") else 0.0,
    },
    {
        "name":  "multi_controls_off",
        "label": "Multiple controls disabled",
        "description": "Two or more security controls are off at the same time — coordinated tampering or severe misconfiguration.",
        "weight": 0.15,
        "evaluate": lambda f, e: 1.0 if int(e.get("controls_disabled_count", 0) or 0) >= 2 else 0.0,
    },
    {
        "name":  "crown_jewel_asset",
        "label": "Crown-jewel asset",
        "description": "Affected host is tagged crown_jewel — posture failures here have outsized blast radius.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if (e.get("asset_tier") or f.get("asset_tier")) == "crown_jewel" else (0.5 if (e.get("asset_tier") or f.get("asset_tier")) == "server" else 0.0),
    },
    {
        "name":  "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "LLM senior-analyst review labelled this true positive.",
        "weight": 0.10,
        "evaluate": lambda f, e, ai=None: _ai_score(ai),
    },
]


def _mesh_rule_id(f: dict) -> str:
    """Return the stable DeepMesh rule ID from either persisted field."""
    rule_id = str(f.get("rule_id") or "")
    if rule_id.startswith("AL-DEV-"):
        return rule_id
    source = str(f.get("source") or "")
    return source if source.startswith("AL-DEV-") else ""


def _mesh_rule_evidence_complete(f: dict) -> float:
    """Check the minimum persisted evidence required to reproduce each rule."""
    rule_id = _mesh_rule_id(f)
    ev = _ev(f)
    checks = {
        "AL-DEV-001": lambda: ev.get("auto_activates") is True and bool(ev.get("indicators")),
        "AL-DEV-002": lambda: bool(ev.get("name")) and bool(
            ev.get("uses_latest") or ev.get("uses_unpinned_ephemeral_runner")
        ),
        "AL-DEV-003": lambda: bool(ev.get("paths")),
        "AL-DEV-004": lambda: bool(ev.get("id")) and bool(ev.get("dangerous_permissions")),
        "AL-DEV-005": lambda: bool(ev.get("executable")) and bool(ev.get("manifest")),
        "AL-DEV-006": lambda: bool(ev.get("settings")) and bool(ev.get("keys")),
        "AL-DEV-007": lambda: bool(ev.get("path")) and bool(ev.get("mode")),
        "AL-DEV-008": lambda: bool(ev.get("endpoint") or ev.get("port")),
        "AL-DEV-009": lambda: bool(ev.get("id") or ev.get("name")) and bool(
            ev.get("privileged")
            or ev.get("network_mode") == "host"
            or ev.get("binds")
            or ev.get("cap_add")
        ),
    }
    check = checks.get(rule_id)
    return 1.0 if check is not None and check() else 0.0


def _mesh_execution_capability(f: dict) -> float:
    ev = _ev(f)
    if _mesh_rule_id(f) == "AL-DEV-001" and ev.get("auto_activates") and ev.get("indicators"):
        return 1.0
    if _mesh_rule_id(f) in {"AL-DEV-002", "AL-DEV-005", "AL-DEV-006"}:
        return 1.0
    return 0.0


def _mesh_mutable_or_untrusted(f: dict) -> float:
    ev = _ev(f)
    if ev.get("uses_latest") or ev.get("uses_unpinned_ephemeral_runner"):
        return 1.0
    if ev.get("installed_from_vsix") or ev.get("unknown_publisher"):
        return 1.0
    if str(ev.get("executable") or "").startswith(("/tmp/", "/private/tmp/", "/var/tmp/")):
        return 0.8
    return 0.0


def _mesh_sensitive_access(f: dict) -> float:
    ev = _ev(f)
    if ev.get("sensitive_env_keys") or _mesh_rule_id(f) == "AL-DEV-007":
        return 1.0
    if ev.get("dangerous_permissions") or ev.get("binds"):
        return 0.7
    return 0.0


def _mesh_unsafe_permissions_or_privilege(f: dict) -> float:
    ev = _ev(f)
    if ev.get("privileged") or ev.get("network_mode") == "host":
        return 1.0
    if ev.get("paths") or ev.get("binds") or ev.get("cap_add"):
        return 0.8
    if _mesh_rule_id(f) in {"AL-DEV-005", "AL-DEV-007"} and ev.get("mode"):
        return 0.8
    return 0.0


def _mesh_external_exposure(f: dict) -> float:
    ev = _ev(f)
    if _mesh_rule_id(f) == "AL-DEV-008":
        return 1.0
    if ev.get("network_mode") == "host":
        return 0.8
    if _mesh_rule_id(f) == "AL-DEV-004" and ev.get("dangerous_permissions"):
        return 0.5
    return 0.0


MESH_CRITERIA: list[dict] = [
    {
        "name": "rule_evidence_complete",
        "label": "Rule evidence complete",
        "description": "The persisted evidence contains the minimum fields required to reproduce the DeepMesh rule decision.",
        "weight": 0.35,
        "anchor": True,
        "evaluate": lambda f, e: _mesh_rule_evidence_complete(f),
    },
    {
        "name": "execution_capability",
        "label": "Effective execution capability",
        "description": "The developer component can automatically or indirectly execute commands on the endpoint.",
        "weight": 0.15,
        "evaluate": lambda f, e: _mesh_execution_capability(f),
    },
    {
        "name": "mutable_or_untrusted_source",
        "label": "Mutable or untrusted source",
        "description": "The component is unpinned, side-loaded, unverified, or launched from a mutable location.",
        "weight": 0.15,
        "evaluate": lambda f, e: _mesh_mutable_or_untrusted(f),
    },
    {
        "name": "sensitive_access",
        "label": "Sensitive data access",
        "description": "The component can receive credentials, broad browser permissions, or sensitive host mounts.",
        "weight": 0.15,
        "evaluate": lambda f, e: _mesh_sensitive_access(f),
    },
    {
        "name": "unsafe_permissions_or_privilege",
        "label": "Unsafe permissions or privilege",
        "description": "File permissions, container privileges, capabilities, or host mounts expand control beyond the intended boundary.",
        "weight": 0.10,
        "evaluate": lambda f, e: _mesh_unsafe_permissions_or_privilege(f),
    },
    {
        "name": "external_exposure",
        "label": "External exposure",
        "description": "A developer service or native bridge is reachable outside its expected local trust boundary.",
        "weight": 0.05,
        "evaluate": lambda f, e: _mesh_external_exposure(f),
    },
    {
        "name": "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "An optional LLM review agrees that the observed DeepMesh evidence is actionable.",
        "weight": 0.05,
        "evaluate": lambda f, e, ai=None: _ai_score(ai),
    },
]


TERRAIN_CRITERIA: dict[str, list[dict]] = {
    "origin":   ORIGIN_CRITERIA,
    "vector":   VECTOR_CRITERIA,
    "citadels": CITADELS_CRITERIA,
    "identity": IDENTITY_CRITERIA,
    "posture":  POSTURE_CRITERIA,
    "mesh":     MESH_CRITERIA,
}


# ── Public API ──────────────────────────────────────────────────────────────

def evaluate_finding(
    finding: dict,
    enriched: Optional[dict] = None,
    ai_verdict: Optional[dict] = None,
) -> dict:
    """
    Evaluate a finding against its terrain's criteria.

    Two fairness rules applied on top of the raw weighted average:

      1.  *AI abstention*: when the LLM verdict wasn't computed (no analyst,
          no key, or label='uncertain' with zero confidence), the AI criterion
          gets dropped from the weight pool entirely.  Otherwise an absent
          LLM step drags a strong-evidence finding down to ~50%.

      2.  *Anchor floor*: each terrain has 1–2 "anchor" criteria that are
          definitive TP indicators on their own (KEV CVE, UID 0 backdoor,
          malicious-IP IOC hit, SIP off, etc.).  When an anchor is fully met
          (≥ 0.9), the final score is floored at 0.80 — preserving the
          analyst expectation that "ONE smoking-gun signal = high confidence".
    """
    enriched = enriched or {}
    terrain  = terrain_for(finding)
    criteria = TERRAIN_CRITERIA.get(terrain, [])

    items: list[dict] = []
    total_score    = 0.0
    total_weight   = 0.0
    met_count      = 0
    anchor_hit     = False
    ai_actually_ran = bool(ai_verdict) and isinstance(ai_verdict, dict) \
                      and (ai_verdict.get("label") in ("tp","fp"))

    for c in criteria:
        try:
            sig = c["evaluate"].__code__.co_argcount
            if sig >= 3:
                met = float(c["evaluate"](finding, enriched, ai_verdict))
            else:
                met = float(c["evaluate"](finding, enriched))
        except Exception as exc:
            log.debug("criterion %s threw %s — counting as 0", c["name"], exc)
            met = 0.0
        met = max(0.0, min(1.0, met))
        weight = float(c.get("weight", 0))

        # Rule 1: skip AI criterion entirely when the LLM didn't actually run.
        # Otherwise an abstain (0.5) on a 15 % weight drags the score down 7.5
        # points and Detection Confidence is unfairly penalised for an analyst
        # config the finding has no control over.
        is_ai = c["name"] == "ai_verdict_tp"
        skipped = is_ai and not ai_actually_ran
        contribution = 0.0 if skipped else met * weight

        if not skipped:
            total_score  += contribution
            total_weight += weight

        if met >= 0.8:
            status = "met"
            met_count += 1
            if c.get("anchor"):
                anchor_hit = True
        elif met >= 0.4:
            status = "partial"
        else:
            status = "not_met"

        items.append({
            "name":         c["name"],
            "label":        c["label"],
            "description":  c["description"],
            "weight":       round(weight, 3),
            "met":          round(met, 3),
            "status":       "skipped" if skipped else status,
            "contribution": round(contribution, 3),
            "is_anchor":    bool(c.get("anchor")),
            "skipped":      skipped,
        })

    score = (total_score / total_weight) if total_weight > 0 else 0.0

    # Rule 2: anchor floor — a single smoking-gun criterion forces ≥ 0.80.
    if anchor_hit:
        score = max(score, 0.80)

    score = max(0.0, min(1.0, score))

    summary = f"{met_count} of {len(items)} criteria met"
    if anchor_hit and score >= 0.80:
        summary += " · anchor floor applied"

    return {
        "terrain":     terrain,
        "score":       round(score, 3),
        "percentage":  round(score * 100, 1),
        "criteria":    items,
        "met_count":   met_count,
        "total_count": len(items),
        "anchor_hit":  anchor_hit,
        "ai_ran":      ai_actually_ran,
        "summary":     summary,
    }


def list_criteria_for_terrain(terrain: str) -> list[dict]:
    """Return the criterion catalogue for a terrain — used by the Settings UI."""
    crits = TERRAIN_CRITERIA.get(terrain.lower(), [])
    return [
        {
            "name":        c["name"],
            "label":       c["label"],
            "description": c["description"],
            "weight":      round(float(c.get("weight", 0)), 3),
        }
        for c in crits
    ]
