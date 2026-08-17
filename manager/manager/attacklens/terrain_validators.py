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


# Behavioral anomalies are cross-cutting — the terrain a given anomaly belongs
# to is decided by *what* deviated, not the generic "behavioral" category. Route
# by the metric / item_key so a connection-count spike lands in Vector, an admin
# spike in Identity, a process/resource spike in Citadels, etc. Without this,
# every behavioral finding fell through to UNCLASSIFIED and was invisible on the
# six-bucket Attack Terrain map (it only showed under All Incidents).
_BEHAVIORAL_METRIC_TERRAIN: tuple[tuple[str, str], ...] = (
    ("conn", "vector"), ("port", "vector"), ("dns", "vector"),
    ("beacon", "vector"), ("scan", "vector"), ("net", "vector"),
    ("admin", "identity"), ("user", "identity"), ("login", "identity"),
    ("pkg", "origin"), ("package", "origin"), ("app", "origin"),
    ("proc", "citadels"), ("service", "citadels"), ("task", "citadels"),
    ("suid", "citadels"), ("unsigned", "citadels"),
    ("cpu", "citadels"), ("mem", "citadels"), ("load", "citadels"),
)


def _behavioral_terrain(finding: dict) -> str:
    """Map a behavioral anomaly to a terrain bucket from its metric/item_key."""
    ev = _ev(finding)
    hint = str(ev.get("metric") or finding.get("item_key") or "").lower()
    for token, terrain in _BEHAVIORAL_METRIC_TERRAIN:
        if token in hint:
            return terrain
    # Impact/execution is the safest home for an otherwise-unclassified anomaly.
    return "citadels"


def terrain_for(finding: dict) -> str:
    explicit = str(finding.get("terrain_id") or "").strip().lower()
    known_ids = {definition.id for definition in all_terrains()}
    if explicit in known_ids or explicit == UNCLASSIFIED_TERRAIN_ID:
        return explicit
    cat = (finding.get("category") or "").lower()
    if cat == "behavioral":
        return _behavioral_terrain(finding)
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
        # n/a (None) when unconfirmed: a vulnerable library is loaded *into* other
        # processes and is never itself a process name, so absence of a positive
        # match means "can't tell", not "not running". Scoring it 0 dragged every
        # library CVE below threshold. Confirmed → 1.0; otherwise drop from pool.
        "evaluate": lambda f, e: 1.0 if (e.get("package_running") or _ev(f).get("running") or _ev(f).get("process_present")) else None,
    },
    {
        "name":  "service_reachable",
        "label": "Service reachable",
        "description": "Open / listening port belonging to the vulnerable package — exploitable from network.",
        "weight": 0.10,
        # n/a (None) when unconfirmed — same rationale as package_running.
        "evaluate": lambda f, e: 1.0 if (e.get("port_open") or _ev(f).get("port") or _ev(f).get("listen")) else None,
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

# Identity has the same two-emitter split as posture (see _disabled_control):
# the routed detections/user_account module emits {"username": ..., "uid": ...}
# with rule_id="uid_zero_clone", while the inline engine._users emits
# {"name": ..., "uid": ...} with source="rule:uid0". The criteria below
# originally read only "name", so a module-emitted UID 0 backdoor — the single
# most definitive identity finding there is — scored 0.0.
_IDENTITY_NAME_KEYS = ("name", "username", "user", "account")

# rule_id / source values that mean "this account was just given privilege".
_PRIV_ESCALATION_SOURCES = frozenset({
    "behavioral_change",        # inline behavioural baseline
    "privgroup_added",          # detections/user_account
    "new_account",
})

_NOLOGIN_SHELLS = frozenset({
    "/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin",
    "/bin/nologin", "/dev/null", "",
})


def _identity_username(f: dict) -> str:
    ev = _ev(f)
    for key in _IDENTITY_NAME_KEYS:
        value = ev.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _uid_zero_non_root(f: dict) -> float:
    """A root-equivalent account that is not `root` itself.

    Checks gid as well as uid: detections/user_account flags either, because a
    GID 0 clone is the same backdoor with one field changed.
    """
    ev = _ev(f)
    ids = [ev.get("uid"), ev.get("gid")]
    if not any(str(value) == "0" for value in ids if value is not None):
        return 0.0
    username = _identity_username(f)
    if not username:
        # No name recorded but a UID 0 account was flagged — still a real
        # signal, just not one we can confirm is non-root. Partial, not zero:
        # zero would silently drop the terrain's anchor.
        return 0.5
    return 0.0 if username.lower() == "root" else 1.0


def _service_account_shell(f: dict) -> float:
    ev = _ev(f)
    try:
        uid = int(ev.get("uid", -1) or -1)
    except (TypeError, ValueError):
        return 0.0
    if not 1 <= uid < 500:
        return 0.0
    shell = str(ev.get("shell") or "").strip()
    return 1.0 if shell.lower() not in _NOLOGIN_SHELLS else 0.0


def _privilege_recently_granted(f: dict) -> float:
    ev = _ev(f)
    if ev.get("admin_recently_granted") or ev.get("newly_added"):
        return 1.0
    source = str(f.get("source") or f.get("rule_id") or "")
    return 1.0 if any(name in source for name in _PRIV_ESCALATION_SOURCES) else 0.0


IDENTITY_CRITERIA: list[dict] = [
    {
        "name":  "uid_zero_non_root",
        "label": "UID 0 account other than root",
        "description": "A user with UID or GID 0 exists under a non-`root` name — classic backdoor admin.",
        "weight": 0.30,
        "anchor": True,   # non-root UID 0 is a definitive TP
        "evaluate": lambda f, e: _uid_zero_non_root(f),
    },
    {
        "name":  "new_admin_recently",
        "label": "Newly-elevated admin",
        "description": "Account was newly created or added to a privileged group — per the behavioural baseline or the account-change detector.",
        "weight": 0.20,
        "evaluate": lambda f, e: _privilege_recently_granted(f),
    },
    {
        "name":  "service_with_shell",
        "label": "System account with interactive shell",
        "description": "Service account (UID < 500) has a non-`nologin` shell — privilege-escalation vector.",
        "weight": 0.15,
        "evaluate": lambda f, e: _service_account_shell(f),
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
        "description": "Login from an unusual source IP, ASN, or geolocation for this account, or a hidden / relocated home directory.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if (
            _ev(f).get("lateral_movement")
            or str(f.get("source") or "") in {"hidden_user", "home_changed"}
        ) else 0.0,
    },
    {
        "name":  "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "LLM senior-analyst review labelled this true positive.",
        "weight": 0.15,
        "evaluate": lambda f, e, ai=None: _ai_score(ai),
    },
]

# Two different emitters produce posture findings and they do not agree on
# either the control's name or the evidence shape:
#
#   detections/sbom_posture.detect_posture_issues (the ROUTED path — this is
#     what actually runs, because ENGINE_CONFIG["use_detection_modules"]
#     defaults to True and _DETECTION_MODULE_ROUTES maps "security" to it)
#       evidence = {"control_key": "sip_enabled", "status": "disabled"}
#
#   engine._security (the inline fallback)
#       item_key = "sec:sip", evidence = {"sip": "disabled"}
#
# The criteria below were written against a third shape that neither emitter
# produces ({"sip_enabled": False}), so every control criterion scored 0.0 for
# every real posture finding. Confirmed live against a critical "Security
# control disabled: Secure Boot" finding that scored 0.0%.
#
# Aliases map every spelling of a control onto one canonical group.
_CONTROL_ALIASES: dict[str, str] = {
    "sip": "sip", "sip_enabled": "sip", "csrutil": "sip",
    "gatekeeper": "gatekeeper", "gatekeeper_enabled": "gatekeeper",
    "filevault": "filevault", "filevault_enabled": "filevault",
    "firewall": "firewall", "firewall_enabled": "firewall",
    "ufw_enabled": "firewall", "firewalld_enabled": "firewall",
    "windows_firewall": "firewall",
}

# Values that mean "this control is not protecting the host". Strings, because
# the collectors report posture as text far more often than as a bool.
_OFF_VALUES = {"disabled", "off", "false", "no", "inactive", "0", "permissive"}


def _canonical_control(name: object) -> str:
    key = str(name or "").strip().lower()
    return _CONTROL_ALIASES.get(key, key)


def _is_off(value: object) -> bool:
    if value is False:
        return True
    if value is True or value is None:
        return False
    return str(value).strip().lower() in _OFF_VALUES


def _disabled_control(f: dict) -> str:
    """Return the canonical control this finding reports as disabled, else ''.

    Understands every emitter shape rather than one, so a routed-module finding
    and an inline-analyzer finding for the same control score identically.
    """
    ev = _ev(f)

    # Routed detection module: {"control_key": ..., "status": "disabled"}.
    control_key = ev.get("control_key")
    if control_key and _is_off(ev.get("status", "disabled")):
        return _canonical_control(control_key)

    # Legacy {"key": <name>, "value": <bool>} shape.
    if ev.get("key") is not None and _is_off(ev.get("value")):
        return _canonical_control(ev.get("key"))

    # Inline analyzer: item_key="sec:<key>" with evidence {"<key>": "disabled"}.
    item_key = str(f.get("item_key") or "")
    if ":" in item_key:
        tail = item_key.rsplit(":", 1)[-1]
        if tail and _is_off(ev.get(tail, ev.get(_canonical_control(tail)))):
            return _canonical_control(tail)

    # Last resort: any evidence key that names a known control and reads off.
    for name, value in ev.items():
        if name in _CONTROL_ALIASES and _is_off(value):
            return _canonical_control(name)
    return ""


def _posture_key_off(f: dict, key_name: str) -> bool:
    """True when this finding reports the named security control as disabled."""
    return _disabled_control(f) == _canonical_control(key_name)


def _critical_control_off(f: dict) -> float:
    """Any control the detection module classes as critical-when-disabled.

    The four macOS controls have their own criteria below; this covers the rest
    of the cross-platform catalogue (Secure Boot, Defender, SELinux, BitLocker,
    …) so a Windows or Linux posture failure is not silently scored zero for
    being spelled differently from a Mac one.
    """
    ev = _ev(f)
    control = _disabled_control(f)
    if not control:
        return 0.0
    try:
        from .detections.sbom_posture import CRITICAL_DISABLED
        critical = {_canonical_control(name) for name in CRITICAL_DISABLED}
    except Exception:
        critical = {"sip", "gatekeeper", "filevault"}
    if control in critical:
        return 1.0
    # A control outside the critical set is still a real control failure — the
    # module rates it "high", so score it as partial rather than not-met.
    known = bool(ev.get("control_key")) or control in _CONTROL_ALIASES
    return 0.5 if known else 0.0


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
        "name":  "critical_control_disabled",
        "label": "Critical security control disabled",
        "description": "A control the detection module rates critical-when-disabled is OFF — Secure Boot, Defender real-time, SELinux, BitLocker, and the macOS controls below. Cross-platform, so a Windows or Linux baseline failure scores the same as a Mac one.",
        "weight": 0.20,
        "anchor": True,   # the module already judged this definitive, not suggestive
        "evaluate": lambda f, e: _critical_control_off(f),
    },
    {
        "name":  "gatekeeper_off",
        "label": "Gatekeeper disabled",
        "description": "Unsigned applications can execute without prompt — code-signing enforcement bypassed.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if _posture_key_off(f, "gatekeeper") else 0.0,
    },
    {
        "name":  "filevault_off",
        "label": "FileVault disabled",
        "description": "Full-disk encryption is OFF — data extractable if device lost.",
        "weight": 0.10,
        "evaluate": lambda f, e: 1.0 if _posture_key_off(f, "filevault") else 0.0,
    },
    {
        "name":  "firewall_off",
        "label": "Application firewall disabled",
        "description": "Host firewall is OFF — inbound connections unfiltered.",
        "weight": 0.08,
        "evaluate": lambda f, e: 1.0 if _posture_key_off(f, "firewall") else 0.0,
    },
    {
        "name":  "multi_controls_off",
        "label": "Multiple controls disabled",
        "description": "Two or more security controls are off at the same time — coordinated tampering or severe misconfiguration.",
        "weight": 0.12,
        "evaluate": lambda f, e: 1.0 if int(e.get("controls_disabled_count", 0) or 0) >= 2 else 0.0,
    },
    {
        "name":  "crown_jewel_asset",
        "label": "Crown-jewel asset",
        "description": "Affected host is tagged crown_jewel — posture failures here have outsized blast radius.",
        "weight": 0.08,
        "evaluate": lambda f, e: 1.0 if (e.get("asset_tier") or f.get("asset_tier")) == "crown_jewel" else (0.5 if (e.get("asset_tier") or f.get("asset_tier")) == "server" else 0.0),
    },
    {
        "name":  "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "LLM senior-analyst review labelled this true positive.",
        "weight": 0.07,
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


# ── Generic criteria ─────────────────────────────────────────────────────────
# Behavioral anomalies, SCA/compliance failures, and any finding whose category
# has no terrain-specific playbook are scored here.  Previously these matched an
# empty criteria list → score 0 → never validated and invisible on the terrain
# map.  The rubric rewards the signals these findings actually carry: severity,
# deviation magnitude, MITRE mapping, corroboration, persistence, and asset tier.

def _severity_rank(f: dict) -> float:
    sev = str(f.get("severity") or "").strip().lower()
    if sev == "critical": return 1.0
    if sev == "high":     return 0.75
    if sev == "medium":   return 0.5
    if sev == "low":      return 0.3
    try:
        return max(0.0, min(1.0, float(f.get("score") or 0) / 10.0))
    except (TypeError, ValueError):
        return 0.0


def _deviation_magnitude(f: dict) -> float:
    """z-score / velocity distance from baseline, or a failed compliance check."""
    ev = _ev(f)
    for k in ("zscore", "z_score", "sigma"):
        try:
            z = abs(float(ev.get(k)))
        except (TypeError, ValueError):
            continue
        if z:
            return 1.0 if z >= 4 else (0.7 if z >= 3 else (0.4 if z >= 2 else 0.2))
    try:
        val  = float(ev.get("value"))
        base = float(ev.get("threshold") or ev.get("prev_mean") or ev.get("mean") or 0)
        if base > 0:
            r = val / base
            return 1.0 if r >= 3 else (0.7 if r >= 2 else (0.4 if r >= 1.2 else 0.0))
    except (TypeError, ValueError):
        pass
    if str(ev.get("result") or "").lower() == "failed":
        return 0.6            # a failed CIS/SCA check is itself the deviation
    return 0.0


def _generic_corroborated(f: dict, e: dict) -> float:
    if e.get("kev_hit") or e.get("malicious_ip_hit") or e.get("malicious_hash_hit"):
        return 1.0
    c = int(e.get("threat_intel_source_count", 0) or 0)
    if c >= 2:
        return 1.0
    if c >= 1:
        return 0.6
    return 1.0 if (e.get("cross_layer_match") or e.get("paired_with_persistence")) else 0.0


def _sustained(f: dict) -> float:
    ev = _ev(f)
    if ev.get("sustained") or "velocity" in str(f.get("source") or ""):
        return 1.0
    try:
        if int(ev.get("count") or ev.get("occurrences") or 0) > 1:
            return 0.6
    except (TypeError, ValueError):
        pass
    return 0.0


def _mapped_technique(f: dict) -> float:
    ev = _ev(f)
    return 1.0 if (f.get("mitre_technique") or ev.get("mitre_technique")
                   or ev.get("mitre") or ev.get("mitre_attack")) else 0.0


def _asset_critical(f: dict, e: dict) -> float:
    tier = e.get("asset_tier") or f.get("asset_tier")
    if tier == "crown_jewel":
        return 1.0
    if tier == "server":
        return 0.5
    return 0.0


GENERIC_CRITERIA: list[dict] = [
    {
        "name":  "severity_weighted",
        "label": "Severity",
        "description": "Analyst-facing severity of the anomaly or control failure (critical / high / medium / low).",
        "weight": 0.25,
        "anchor": True,   # a critical anomaly is actionable on its own
        "evaluate": lambda f, e: _severity_rank(f),
    },
    {
        "name":  "deviation_magnitude",
        "label": "Deviation from baseline",
        "description": "Statistical distance from the learned baseline (z-score / velocity), or a failed compliance check.",
        "weight": 0.20,
        "evaluate": lambda f, e: _deviation_magnitude(f),
    },
    {
        "name":  "intel_corroborated",
        "label": "Corroborating signal",
        "description": "An independent threat-intel hit, or a cross-layer / persistence pairing, supports the anomaly.",
        "weight": 0.15,
        "evaluate": lambda f, e: _generic_corroborated(f, e),
    },
    {
        "name":  "mapped_technique",
        "label": "MITRE ATT&CK mapped",
        "description": "The finding carries a MITRE technique — a concrete adversary behaviour, not just a metric wobble.",
        "weight": 0.15,
        "evaluate": lambda f, e: _mapped_technique(f),
    },
    {
        "name":  "sustained",
        "label": "Sustained / repeated",
        "description": "The deviation is sustained or velocity-driven rather than a single transient sample.",
        "weight": 0.10,
        "evaluate": lambda f, e: _sustained(f),
    },
    {
        "name":  "asset_critical",
        "label": "High-value asset",
        "description": "Affected host is a crown-jewel or server tier — raising the stakes of any anomaly.",
        "weight": 0.05,
        "evaluate": lambda f, e: _asset_critical(f, e),
    },
    {
        "name":  "ai_verdict_tp",
        "label": "AI analyst verdict",
        "description": "LLM senior-analyst review labelled this true positive.",
        "weight": 0.10,
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


def _criteria_for(finding: dict, terrain: str) -> list[dict]:
    """Pick the scoring rubric: category-specific anomalies (behavioral,
    compliance) and any unmapped terrain fall back to the generic rubric so no
    finding is ever scored against an empty criteria list."""
    cat = (finding.get("category") or "").lower()
    if cat in ("behavioral", "compliance"):
        return GENERIC_CRITERIA
    return TERRAIN_CRITERIA.get(terrain) or GENERIC_CRITERIA


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
    criteria = _criteria_for(finding, terrain)

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
                raw = c["evaluate"](finding, enriched, ai_verdict)
            else:
                raw = c["evaluate"](finding, enriched)
        except Exception as exc:
            log.debug("criterion %s threw %s — counting as 0", c["name"], exc)
            raw = 0.0
        # A criterion may return None to mean "not applicable — the telemetry
        # cannot answer this" (e.g. reachability for a vulnerable *library* that
        # is never itself a running process). An n/a criterion is dropped from
        # the weight pool exactly like an AI abstention, so a finding is never
        # dragged toward 0 for evidence it structurally cannot have. Reachability
        # is an input, never a negative verdict — it can only raise the score.
        na = raw is None
        met = 0.0 if na else max(0.0, min(1.0, float(raw)))
        weight = float(c.get("weight", 0))

        # Rule 1: skip a criterion entirely when it didn't/can't run — the AI
        # criterion when the LLM didn't actually run, or any criterion that
        # returned n/a. Otherwise an abstain drags the weighted average down and
        # the finding is penalised for a signal it has no control over.
        is_ai = c["name"] == "ai_verdict_tp"
        skipped = na or (is_ai and not ai_actually_ran)
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
