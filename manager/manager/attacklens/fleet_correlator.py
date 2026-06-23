"""
manager/manager/attacklens/fleet_correlator.py — Fleet-wide / global-threat correlation.

The per-agent CorrelationEngine (correlator.py) is blind by construction: it only
ever sees ONE host's findings at a time. Real adversary activity is rarely
confined to a single host — it is a *campaign*:

  • the same external C2 IP beaconed from a dozen endpoints  (distributed C2)
  • the same unsigned binary hash dropped across hosts        (worm / dropper)
  • the same CVE present fleet-wide                            (supply-chain outbreak)
  • the same backdoor admin account created on many hosts      (coordinated persistence)
  • security controls disabled across many hosts at once       (mass tampering / rogue MDM push)
  • many hosts scanning the same subnet                         (internal worm spread)

This module is the cross-host layer that turns N independent single-host findings
into ONE high-confidence campaign incident. It is read-only over IntelDB
(`get_active_findings_global`) and emits correlation rows under the reserved
`__fleet__` pseudo-agent, so it never touches agents and never recurses on its
own output.

Design contract (mirrors correlator.py so the storage + UI layers are reused):
  • Every fleet rule groups confirmed per-host findings by a SHARED indicator
    (IP, hash, CVE, package, username, control-name, subnet).
  • A rule fires only when ≥ `min_hosts` DISTINCT agents share that indicator
    within `time_window_hours`.
  • Because it aggregates findings that already passed the per-host detection +
    validation pipeline, it inherits their signal quality — the fleet layer adds
    breadth, not new raw guesses.
  • Score escalates with host count (outbreak adjustment) and with exploit
    intelligence (KEV / EPSS / public exploit).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import time
from typing import Any, Callable, Optional

from .allowlist import is_trusted_ip
from .config import ENGINE_CONFIG
from ..indexer import FLEET_AGENT_ID

log = logging.getLogger("manager.attacklens.fleet_correlator")


# ── Evidence helpers ──────────────────────────────────────────────────────────

def _evidence(f: dict) -> dict:
    """Findings store `evidence` as a JSON string (or sometimes already a dict).
    Return a dict no matter what, never raise."""
    ev = f.get("evidence")
    if isinstance(ev, dict):
        return ev
    if isinstance(ev, str) and ev:
        try:
            obj = json.loads(ev)
            return obj if isinstance(obj, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


def _first(d: dict, *keys: str) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return str(v)
    return None


def _cve_ids(f: dict) -> list[str]:
    raw = f.get("cve_ids")
    if isinstance(raw, list):
        return [str(c) for c in raw if c]
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(c) for c in parsed if c]
        except (json.JSONDecodeError, ValueError):
            pass
        # bare "CVE-2024-1234" string
        return re.findall(r"CVE-\d{4}-\d{4,7}", raw, re.IGNORECASE)
    return []


def _is_external_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_unspecified or addr.is_reserved)


def _subnet_24(ip: str) -> Optional[str]:
    """Group an IP into its /24 (IPv4) so many hosts hitting 10.0.5.* aggregate."""
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except ValueError:
        return None


# ── Indicator extractors ──────────────────────────────────────────────────────
# Each returns the SHARED key that groups a finding across hosts, or None to skip
# this finding for the rule. Defensive: evidence shape varies by analyzer, so we
# probe several field names.

def _ix_external_dest(f: dict) -> Optional[str]:
    ev = _evidence(f)
    ip = _first(ev, "remote_addr", "remote_ip", "dest_ip", "dst", "ip", "destination")
    if not ip:
        # Some connection findings carry the IP only in item_key/title.
        ip = _first(f, "item_key")
        ip = ip.split(":")[-1] if ip and ip.count(".") == 3 else None
    if not ip or not _is_external_ip(ip):
        return None
    if is_trusted_ip(ip):
        return None
    return ip


def _ix_binary_hash(f: dict) -> Optional[str]:
    ev = _evidence(f)
    h = _first(ev, "sha256", "hash", "hash_sha256", "sha_256")
    if h and len(h) >= 32:
        return h.lower()
    return None


def _ix_app_path_unsigned(f: dict) -> Optional[str]:
    """Fallback grouping for malware/trojan spread when no binary hash is
    available: identical unsigned APP path across hosts.

    Originally targeted the "binary" category, but BinariesCollector
    (agent/os/macos/collectors/inventory.py) only scans fixed system PATH
    directories (/usr/bin, /usr/local/bin, ...) and never emits a `signed`
    field at all — so `ev.get("signed")` was always None there and this rule
    could never fire. AppsCollector genuinely emits `signed: bool` and scans
    user-installed .app bundles (the actual trojan-drop surface), so this now
    targets "app" instead — confirmed against the live collector schema.
    """
    ev = _evidence(f)
    path = _first(ev, "path", "bundle_id")
    signed = ev.get("signed")
    if path and signed is False:
        return path
    return None


def _ix_cve(f: dict) -> Optional[str]:
    cves = _cve_ids(f)
    if not cves:
        ev = _evidence(f)
        cid = _first(ev, "cve_id", "cve")
        if cid:
            cves = [cid]
    if not cves:
        return None
    # Group on the highest-priority CVE: prefer KEV, else lexical max (stable).
    return sorted(cves)[-1].upper()


def _ix_malicious_package(f: dict) -> Optional[str]:
    ev = _evidence(f)
    src = (f.get("source") or "") + " " + (f.get("rule_id") or "")
    title = (f.get("title") or "").lower()
    flagged = any(t in (src.lower() + " " + title)
                  for t in ("typosquat", "malicious", "risky", "banned", "untrusted"))
    if not flagged:
        return None
    name = _first(ev, "package", "name", "component")
    return f"pkg:{name}" if name else None


def _ix_username(f: dict) -> Optional[str]:
    ev = _evidence(f)
    name = _first(ev, "username", "user", "name")
    return f"user:{name}" if name else None


def _ix_security_control(f: dict) -> Optional[str]:
    """Which control was disabled/degraded — sip, gatekeeper, filevault, firewall…"""
    ev = _evidence(f)
    ctrl = _first(ev, "control", "setting", "feature", "item_key", "name")
    if not ctrl:
        # derive from title, e.g. "Gatekeeper disabled"
        m = re.search(r"(sip|gatekeeper|filevault|firewall|xprotect|secure boot|"
                      r"lockdown|defender|selinux)", (f.get("title") or "").lower())
        ctrl = m.group(1) if m else None
    return f"ctrl:{ctrl}" if ctrl else None


def _ix_recon_subnet(f: dict) -> Optional[str]:
    ev = _evidence(f)
    ip = _first(ev, "remote_addr", "remote_ip", "dest_ip", "dst", "ip", "destination")
    if not ip:
        return None
    # Internal recon: target is private; group by /24 to catch subnet sweeps.
    try:
        if not ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None
    sn = _subnet_24(ip)
    return f"net:{sn}" if sn else None


def _ix_offensive_tool(f: dict) -> Optional[str]:
    """Same offensive/dual-use tool seen across hosts (campaign tooling)."""
    ev = _evidence(f)
    src = (f.get("source") or "").lower()
    title = (f.get("title") or "").lower()
    if not any(t in (src + " " + title) for t in
               ("c2", "offensive", "dual_use", "dual-use", "hacktool", "pentest",
                "process_pattern", "lolbin", "tunnel")):
        return None
    name = _first(ev, "process", "process_name", "name", "binary")
    return f"tool:{name.lower()}" if name else None


# ── Fleet rule definitions ────────────────────────────────────────────────────
# semantics:
#   "coordination" — same indicator on many hosts == a coordinated operation
#   "propagation"  — a bad artifact is spreading host-to-host (worm/dropper)
#   "outbreak"     — a vulnerability/weakness is fleet-wide (blast radius grows)

FLEET_RULES: list[dict] = [

    {
        "id": "fleet:distributed_c2",
        "title": "Distributed C2 — same external destination beaconed across the fleet",
        "categories": ["connection"],
        "indicator": _ix_external_dest,
        "min_hosts": 3,
        "time_window_hours": 24,
        "semantics": "coordination",
        "severity_base": "high", "score_base": 8.5, "confidence_base": 80,
        "host_weight": 1.0, "outbreak_hosts": 6,
        "attack_chain": [
            {"tactic": "Command and Control", "technique": "T1071", "label": "Shared C2 destination across hosts"},
            {"tactic": "Command and Control", "technique": "T1102", "label": "Coordinated beaconing"},
        ],
        "description": (
            "Multiple hosts hold an active connection finding to the SAME external "
            "destination within the window. A single host talking to a rare IP is a "
            "lead; many hosts sharing it is a coordinated command-and-control campaign."
        ),
        "recommendation": (
            "Treat the shared destination as a confirmed C2 indicator: block it at "
            "the egress firewall/DNS for the whole org, then sweep every affected "
            "host for the implant/process that owns the connection and for shared "
            "persistence. Pivot threat-intel on the IP/ASN for related infrastructure."
        ),
    },

    {
        "id": "fleet:malware_propagation_hash",
        "title": "Malware propagation — identical binary hash across multiple hosts",
        "categories": ["binary"],
        "indicator": _ix_binary_hash,
        "min_hosts": 2,
        "time_window_hours": 72,
        "semantics": "propagation",
        "severity_base": "high", "score_base": 8.0, "confidence_base": 78,
        "host_weight": 1.2, "outbreak_hosts": 5,
        "attack_chain": [
            {"tactic": "Lateral Movement", "technique": "T1570", "label": "Tool transferred between hosts"},
            {"tactic": "Execution",        "technique": "T1059", "label": "Same binary executed fleet-wide"},
        ],
        "description": (
            "The same executable (by SHA-256) appears on two or more hosts. Identical "
            "non-OS binaries spreading across endpoints indicate worm-like propagation, "
            "a shared dropper, or a supply-chain artifact pushed to many machines."
        ),
        "recommendation": (
            "Capture the hash and check it against malware intel/VirusTotal. If "
            "unknown-bad, quarantine on every affected host, identify the delivery "
            "vector (shared mount, package, deployment tool), and block the hash."
        ),
    },

    {
        "id": "fleet:malware_propagation_path",
        "title": "Malware propagation — same unsigned app path across hosts",
        "categories": ["app"],
        "indicator": _ix_app_path_unsigned,
        "min_hosts": 3,
        "time_window_hours": 72,
        "semantics": "propagation",
        "severity_base": "medium", "score_base": 6.5, "confidence_base": 68,
        "host_weight": 1.0, "outbreak_hosts": 6,
        "attack_chain": [
            {"tactic": "Lateral Movement", "technique": "T1570", "label": "Identical artifact placed across hosts"},
            {"tactic": "Defense Evasion",  "technique": "T1036", "label": "Unsigned app in shared path"},
        ],
        "description": (
            "An unsigned application at the SAME path exists on three or more hosts "
            "(hash unavailable). Lower confidence than a hash match, but an identical "
            "unsigned drop location fleet-wide is a propagation signal."
        ),
        "recommendation": (
            "Collect and hash the app bundle from several hosts to confirm they are the "
            "same artifact, then treat as a propagation event: quarantine, find the "
            "delivery mechanism, and add the path/hash to blocklists."
        ),
    },

    {
        "id": "fleet:supply_chain_cve_outbreak",
        "title": "Supply-chain outbreak — same CVE present across the fleet",
        "categories": ["package", "sbom", "app"],
        "indicator": _ix_cve,
        "min_hosts": 3,
        "time_window_hours": 336,   # 14d — vuln exposure is slow-moving
        "semantics": "outbreak",
        "severity_base": "medium", "score_base": 6.0, "confidence_base": 70,
        "host_weight": 1.3, "outbreak_hosts": 10,
        "attack_chain": [
            {"tactic": "Initial Access", "technique": "T1190", "label": "Vulnerable component fleet-wide"},
            {"tactic": "Execution",      "technique": "T1203", "label": "Exploitation surface"},
        ],
        "description": (
            "The same CVE is present on many hosts. Fleet-wide exposure dramatically "
            "raises blast radius and makes the host the cheapest pivot for an "
            "attacker. Escalated automatically when the CVE is CISA-KEV or high-EPSS."
        ),
        "recommendation": (
            "Prioritise a fleet-wide patch/upgrade campaign for the shared CVE. If "
            "it is KEV or EPSS-high, treat as actively exploited: apply compensating "
            "controls (egress/ingress restriction) on every affected host until patched."
        ),
    },

    {
        "id": "fleet:malicious_package_campaign",
        "title": "Supply-chain compromise — risky/typosquat package across hosts",
        "categories": ["package", "sbom"],
        "indicator": _ix_malicious_package,
        "min_hosts": 2,
        "time_window_hours": 336,
        "semantics": "propagation",
        "severity_base": "high", "score_base": 8.0, "confidence_base": 76,
        "host_weight": 1.1, "outbreak_hosts": 5,
        "attack_chain": [
            {"tactic": "Initial Access", "technique": "T1195.002", "label": "Compromised dependency distributed"},
            {"tactic": "Execution",      "technique": "T1059",     "label": "Malicious package installed"},
        ],
        "description": (
            "The same package flagged as malicious / typosquat / banned / untrusted "
            "is installed on multiple hosts. A bad dependency appearing fleet-wide is "
            "a software supply-chain compromise, not a one-off mistake."
        ),
        "recommendation": (
            "Remove the package everywhere, pin/withdraw it in the internal registry "
            "and CI, and audit what it executed on each host (post-install scripts, "
            "spawned processes, outbound connections)."
        ),
    },

    {
        "id": "fleet:backdoor_admin_campaign",
        "title": "Coordinated persistence — same suspicious account across hosts",
        "categories": ["user"],
        "indicator": _ix_username,
        "min_hosts": 2,
        "time_window_hours": 72,
        "semantics": "coordination",
        "severity_base": "high", "score_base": 8.2, "confidence_base": 80,
        "host_weight": 1.1, "outbreak_hosts": 4,
        "attack_chain": [
            {"tactic": "Persistence",          "technique": "T1136", "label": "Same account created across hosts"},
            {"tactic": "Privilege Escalation", "technique": "T1078", "label": "Coordinated privileged access"},
        ],
        "description": (
            "A user account that triggered a finding (new admin / UID-0 / hidden "
            "service account) exists on multiple hosts under the same name. An "
            "identical suspicious account fleet-wide is attacker-provisioned backdoor "
            "access, not organic user creation."
        ),
        "recommendation": (
            "Disable the account on every affected host, rotate all admin credentials, "
            "and review how it was provisioned (config-management push vs hands-on-keyboard). "
            "Hunt for the same name on hosts not yet flagged."
        ),
    },

    {
        "id": "fleet:mass_posture_collapse",
        "title": "Mass defense tampering — security control disabled across hosts",
        "categories": ["security"],
        "indicator": _ix_security_control,
        "min_hosts": 4,
        "time_window_hours": 24,
        "semantics": "coordination",
        "severity_base": "high", "score_base": 8.0, "confidence_base": 78,
        "host_weight": 1.2, "outbreak_hosts": 8,
        "attack_chain": [
            {"tactic": "Defense Evasion", "technique": "T1562.001", "label": "Same control disabled fleet-wide"},
        ],
        "description": (
            "The same security control (SIP / Gatekeeper / FileVault / Firewall / "
            "XProtect …) is disabled or degraded on many hosts at once. Simultaneous "
            "fleet-wide weakening points to a rogue management push, a malicious "
            "script run everywhere, or an insider — not coincidental drift."
        ),
        "recommendation": (
            "Re-enable the control fleet-wide and find the common cause: review MDM/"
            "config-management change history and any script/package that ran across "
            "the affected hosts in the window. Treat as active defense evasion."
        ),
    },

    {
        "id": "fleet:coordinated_internal_recon",
        "title": "Internal worm spread — many hosts probing the same subnet",
        "categories": ["connection", "arp"],
        "indicator": _ix_recon_subnet,
        "min_hosts": 3,
        "time_window_hours": 12,
        "semantics": "coordination",
        "severity_base": "high", "score_base": 7.8, "confidence_base": 74,
        "host_weight": 1.0, "outbreak_hosts": 6,
        "attack_chain": [
            {"tactic": "Discovery",        "technique": "T1046", "label": "Distributed network scanning"},
            {"tactic": "Lateral Movement", "technique": "T1021", "label": "Coordinated subnet targeting"},
        ],
        "description": (
            "Several hosts have connection/ARP findings toward the SAME internal /24 "
            "within a short window. Many sources converging on one subnet is "
            "distributed reconnaissance — a hallmark of worm propagation or a "
            "hands-on operator expanding across the network."
        ),
        "recommendation": (
            "Segment the targeted subnet and the scanning hosts. Identify the common "
            "process/tool driving the scans and whether the sources share a root "
            "cause (same implant). Review what services in the subnet were reached."
        ),
    },

    {
        "id": "fleet:offensive_tool_campaign",
        "title": "Campaign tooling — same offensive/dual-use tool across hosts",
        "categories": ["process"],
        "indicator": _ix_offensive_tool,
        "min_hosts": 3,
        "time_window_hours": 24,
        "semantics": "coordination",
        "severity_base": "high", "score_base": 7.8, "confidence_base": 75,
        "host_weight": 1.0, "outbreak_hosts": 6,
        "attack_chain": [
            {"tactic": "Execution",           "technique": "T1059", "label": "Same tool run across hosts"},
            {"tactic": "Command and Control", "technique": "T1219", "label": "Coordinated tooling"},
        ],
        "description": (
            "The same offensive or dual-use tool (C2 agent, tunneller, LOLBin abuse, "
            "remote-admin) is running on multiple hosts. Identical tooling fleet-wide "
            "indicates an operator working through the environment, not isolated use."
        ),
        "recommendation": (
            "Correlate execution times and parent lineage across hosts to map the "
            "operator's path. Block/uninstall the tool, and check each host for the "
            "persistence and C2 that usually accompany it."
        ),
    },
]


# ── Scoring ───────────────────────────────────────────────────────────────────

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _escalate(severity: str, steps: int) -> str:
    try:
        i = _SEV_ORDER.index(severity)
    except ValueError:
        i = 2
    return _SEV_ORDER[min(len(_SEV_ORDER) - 1, i + steps)]


def _intel_boost(findings: list[dict]) -> float:
    """KEV / EPSS / public-exploit boost — mirrors correlator._intel_boost so
    fleet scoring is consistent with per-host correlation scoring."""
    boost = 0.0
    for f in findings:
        ev_cve = _evidence(f).get("cve") or {}
        kev = bool(f.get("kev") or ev_cve.get("kev") or ev_cve.get("cisa_kev"))
        exploit = bool(f.get("exploit_available") or ev_cve.get("exploit_available"))
        epss = float(f.get("epss_score") or ev_cve.get("epss_score")
                     or ev_cve.get("epss") or 0)
        if kev:
            boost += 0.4
        if exploit:
            boost += 0.3
        if epss >= 0.7:
            boost += 0.3
        elif epss >= 0.5:
            boost += 0.15
    return min(1.5, boost)


def _score_campaign(rule: dict, hosts: list[str], findings: list[dict]) -> dict:
    """Outbreak-aware scoring: more affected hosts + exploit intel ⇒ higher
    severity/score/confidence. Severity escalates one notch past the rule's
    `outbreak_hosts` threshold, two notches at 2× it."""
    host_count = len(hosts)
    min_hosts = rule["min_hosts"]
    outbreak_at = rule.get("outbreak_hosts", min_hosts * 3)

    # Outbreak factor 0..1 scaled between min_hosts and outbreak_at.
    span = max(1, outbreak_at - min_hosts)
    host_factor = min(1.0, (host_count - min_hosts) / span)

    intel = _intel_boost(findings)
    score = rule["score_base"] + rule.get("host_weight", 1.0) * host_factor + intel
    score = round(min(10.0, score), 1)

    confidence = rule["confidence_base"] + int(12 * host_factor) + int(10 * min(1.0, intel))
    confidence = min(99, confidence)

    severity = rule["severity_base"]
    if host_count >= outbreak_at * 2:
        severity = _escalate(severity, 2)
    elif host_count >= outbreak_at:
        severity = _escalate(severity, 1)
    if intel >= 0.4:                       # KEV/exploit present ⇒ at least high
        severity = _escalate(severity, 1)
    # never exceed critical
    return {"severity": severity, "score": score, "confidence": confidence,
            "host_factor": round(host_factor, 2), "intel_boost": round(intel, 2)}


# ── Engine ────────────────────────────────────────────────────────────────────

class FleetCorrelator:
    """Cross-host campaign detection. Read-only over IntelDB; emits correlation
    rows under FLEET_AGENT_ID. Stateless apart from the DB handle."""

    def __init__(self, intel_db, db=None) -> None:
        self._idb = intel_db
        self._db  = db   # manager.db Database — optional, enables stale-agent exclusion

    async def correlate(self) -> list[dict]:
        # One bounded global read covering every category any rule needs, over
        # the widest window any rule uses. Each rule then filters in memory.
        categories = sorted({c for r in FLEET_RULES for c in r["categories"]})
        max_window_h = max(r["time_window_hours"] for r in FLEET_RULES)
        since = time.time() - max_window_h * 3600

        # A campaign rule's min_hosts should mean min_hosts CURRENTLY-reporting
        # hosts. Without this, a host that went dark weeks ago can still be the
        # deciding vote that turns 2 real hits into a 3-host "campaign".
        live_agent_ids = None
        if self._db is not None:
            try:
                live_agent_ids = await self._db.get_live_agent_ids(
                    ENGINE_CONFIG.get("stale_agent_sec", 86400)
                )
            except Exception as exc:
                log.warning("FleetCorrelator live-agent lookup failed: %s", exc)

        try:
            rows = await self._idb.get_active_findings_global(
                categories=categories, since=since, limit=8000,
                live_agent_ids=live_agent_ids,
            )
        except Exception as exc:
            log.warning("FleetCorrelator global fetch failed: %s", exc)
            return []

        by_cat: dict[str, list[dict]] = {}
        for r in rows:
            by_cat.setdefault(r.get("category", ""), []).append(r)

        out: list[dict] = []
        now = time.time()
        for rule in FLEET_RULES:
            out.extend(self._eval_rule(rule, by_cat, now))
        return out

    def _eval_rule(self, rule: dict, by_cat: dict, now: float) -> list[dict]:
        cutoff = now - rule["time_window_hours"] * 3600
        indicator: Callable[[dict], Optional[str]] = rule["indicator"]

        # Group findings by shared indicator → {indicator: {agent_id: [findings]}}
        groups: dict[str, dict[str, list[dict]]] = {}
        for cat in rule["categories"]:
            for f in by_cat.get(cat, []):
                if (f.get("last_detected_at") or f.get("first_detected_at") or 0) < cutoff:
                    continue
                try:
                    key = indicator(f)
                except Exception:
                    key = None
                if not key:
                    continue
                groups.setdefault(key, {}).setdefault(f.get("agent_id", ""), []).append(f)

        results: list[dict] = []
        for indicator_key, host_map in groups.items():
            hosts = sorted(h for h in host_map if h)
            if len(hosts) < rule["min_hosts"]:
                continue

            # Representative evidence: highest-scoring finding per host (capped).
            reps: list[dict] = []
            for h in hosts:
                best = max(host_map[h],
                           key=lambda x: x.get("composite_score") or x.get("score", 0))
                reps.append(best)
            reps.sort(key=lambda x: x.get("composite_score") or x.get("score", 0),
                      reverse=True)

            scoring = _score_campaign(rule, hosts, reps)
            results.append(self._build(rule, indicator_key, hosts, reps[:12], scoring))
        return results

    def _build(self, rule: dict, indicator_key: str, hosts: list[str],
               reps: list[dict], scoring: dict) -> dict:
        ind_hash = hashlib.sha256(indicator_key.encode()).hexdigest()[:12]
        rule_id = f"{rule['id']}:{ind_hash}"
        host_count = len(hosts)
        chain = rule["attack_chain"]

        signals = [{
            "agent_id":   r.get("agent_id"),
            "finding_id": r.get("id"),
            "category":   r.get("category"),
            "title":      r.get("title"),
            "severity":   r.get("severity"),
            "score":      r.get("composite_score") or r.get("score"),
        } for r in reps]

        return {
            "agent_id":    FLEET_AGENT_ID,
            "rule_id":     rule_id,
            "category":    "fleet_correlation",
            "item_key":    rule_id,
            "severity":    scoring["severity"],
            "score":       scoring["score"],
            "confidence":  scoring["confidence"],
            "title":       f"{rule['title']} ({host_count} hosts)",
            "description": (
                f"{rule['description']}\n\n"
                f"Shared indicator: {indicator_key}\n"
                f"Affected hosts ({host_count}): {', '.join(hosts[:20])}"
                + (" …" if host_count > 20 else "")
            ),
            "recommendation":   rule["recommendation"],
            "attack_chain":     chain,
            "attack_path":      self._attack_path(chain, reps, indicator_key),
            "blast_radius": {
                "scope":            "fleet",
                "semantics":        rule["semantics"],
                "host_count":       host_count,
                "shared_indicator": indicator_key,
                "outbreak_factor":  scoring["host_factor"],
                "intel_boost":      scoring["intel_boost"],
                "estimated_scope":  "organization-wide" if host_count >= rule.get("outbreak_hosts", 6)
                                    else "multi-host",
                "rationale": (
                    f"{rule['id']} grouped {host_count} hosts on a shared "
                    f"{rule['semantics']} indicator within "
                    f"{rule['time_window_hours']}h."
                ),
            },
            "entry_points":      [indicator_key],
            "affected_assets":   hosts,
            "likely_next_steps": self._next_steps(rule, host_count),
            "signals":           signals,
            "signal_count":      len(signals),
            "source":            "fleet_correlator",
            "detected_at":       time.time(),
        }

    @staticmethod
    def _attack_path(chain: list[dict], reps: list[dict], indicator_key: str) -> list[dict]:
        path = []
        for idx, step in enumerate(chain):
            ev = reps[min(idx, len(reps) - 1)] if reps else {}
            path.append({
                "stage":     idx + 1,
                "tactic":    step.get("tactic", ""),
                "technique": step.get("technique", ""),
                "label":     step.get("label", ""),
                "evidence":  ev.get("title", indicator_key),
                "category":  ev.get("category", ""),
            })
        return path

    @staticmethod
    def _next_steps(rule: dict, host_count: int) -> list[str]:
        steps = [
            f"Scope the campaign: confirm all {host_count} hosts share the same "
            f"root cause before remediating piecemeal.",
            "Hunt for the indicator on hosts not yet flagged (the fleet view only "
            "shows hosts that already produced a finding).",
        ]
        if rule["semantics"] == "outbreak":
            steps.append("Drive a prioritized fleet-wide patch/remediation campaign.")
        elif rule["semantics"] == "propagation":
            steps.append("Identify and cut the propagation vector (shared mount, "
                         "package feed, deployment tool) to stop further spread.")
        else:  # coordination
            steps.append("Block the shared indicator org-wide at the network/identity "
                         "layer, then run host-level eradication in parallel.")
        return steps


def build_fleet_summary(correlations: list[dict]) -> dict:
    """Summarise fleet correlations for a dashboard hero card."""
    if not correlations:
        return {"total": 0, "critical": 0, "high": 0, "max_hosts": 0,
                "max_score": 0.0, "top_campaign": None}
    by_sev: dict[str, int] = {}
    max_hosts = 0
    max_score = 0.0
    top = None
    for c in correlations:
        sev = c.get("severity", "info")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        hc = (c.get("blast_radius") or {}).get("host_count", 0)
        max_hosts = max(max_hosts, hc)
        if c.get("score", 0) > max_score:
            max_score = c["score"]
            top = c
    return {
        "total":        len(correlations),
        "critical":     by_sev.get("critical", 0),
        "high":         by_sev.get("high", 0),
        "max_hosts":    max_hosts,
        "max_score":    round(max_score, 1),
        "top_campaign": top,
    }
