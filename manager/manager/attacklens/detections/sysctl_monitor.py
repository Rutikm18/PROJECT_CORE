"""
manager/manager/attacklens/detections/sysctl_monitor.py
Detection of unauthorized kernel parameter changes, insecure sysctl modifications,
and stealth rootkit indicators at the kernel level.

Telemetry sections handled:
  sysctl, kernel_params, sysctl_output

COMPLIANCE MAPPING:
  NIST CSF:    PR.IP-1 (Baseline configuration maintained)
  CIS Benchmark: macOS/Linux Kernel Hardening sections
  SOC 2:       CC6.1 (Logical access security)
  ISO 27001:   A.12.1.2 (Change management)

MITRE ATT&CK:
  T1601   (Modify System Image)
  T1014   (Rootkit)
  T1562.006 (Indicator Blocking — kernel parameter abuse)
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

log = logging.getLogger("manager.attacklens.detections.sysctl_monitor")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Parameters that are dangerous when changed to the indicated value.
# Format: {param_key: {value_that_triggers_alert, severity, description}}
CRITICAL_PARAM_RULES: dict[str, dict] = {
    # macOS
    "kern.bootargs": {
        "trigger": "changed",   # any change is suspicious
        "severity": "critical",
        "desc": "Kernel boot arguments modified — possible bootkit or SIP bypass",
    },
    "kern.secure_kernel": {
        "trigger": "0",
        "severity": "critical",
        "desc": "Secure Kernel disabled — kernel memory protections removed",
    },
    "vm.cs_enforcement_disable": {
        "trigger": "1",
        "severity": "critical",
        "desc": "Code signing enforcement disabled — unsigned code can execute in kernel",
    },
    "net.inet.ip.forwarding": {
        "trigger": "1",
        "severity": "critical",
        "desc": "IP forwarding enabled — possible MITM/routing attack setup on non-router host",
    },
    "kern.coredump": {
        "trigger": "changed",
        "severity": "high",
        "desc": "Kernel coredump setting changed — may expose sensitive memory to disk",
    },
    # Linux
    "kernel.randomize_va_space": {
        "trigger": "0",
        "severity": "critical",
        "desc": "ASLR disabled — memory layout predictable, exploitation trivially easier",
    },
    "net.ipv4.ip_forward": {
        "trigger": "1",
        "severity": "critical",
        "desc": "IPv4 forwarding enabled on non-router host — possible MITM setup",
    },
    "kernel.dmesg_restrict": {
        "trigger": "0",
        "severity": "high",
        "desc": "dmesg unrestricted — kernel addresses leaked to unprivileged users",
    },
    "kernel.kptr_restrict": {
        "trigger": "0",
        "severity": "high",
        "desc": "Kernel pointer restriction disabled — kernel ASLR bypassed via /proc/kallsyms",
    },
    "net.ipv4.conf.all.rp_filter": {
        "trigger": "0",
        "severity": "high",
        "desc": "Reverse path filtering disabled — IP spoofing possible",
    },
    "kernel.perf_event_paranoid": {
        "trigger": "-1",
        "severity": "high",
        "desc": "Perf events unrestricted — unprivileged kernel profiling and ASLR bypass",
    },
    "kernel.unprivileged_bpf_disabled": {
        "trigger": "0",
        "severity": "high",
        "desc": "Unprivileged eBPF enabled — kernel attack surface greatly expanded",
    },
    "net.core.bpf_jit_harden": {
        "trigger": "0",
        "severity": "medium",
        "desc": "BPF JIT hardening disabled — JIT spraying attacks possible",
    },
}

# High-risk parameter changes that are HIGH severity (hostname / identity)
HIGH_PARAM_RULES: dict[str, dict] = {
    "kernel.hostname": {
        "trigger": "changed",
        "severity": "high",
        "desc": "Kernel hostname changed — possible system staging or identity masking",
    },
    "kern.hostname": {
        "trigger": "changed",
        "severity": "high",
        "desc": "Kernel hostname changed (macOS) — possible lateral movement staging",
    },
    "net.ipv4.ip_local_port_range": {
        "trigger": "changed",
        "severity": "medium",
        "desc": "Local port range modified — may facilitate covert channel or port reuse",
    },
    "net.core.somaxconn": {
        "trigger": "changed",
        "severity": "medium",
        "desc": "Max socket connection backlog changed — unusual for non-server configuration",
    },
    "net.ipv4.tcp_syncookies": {
        "trigger": "0",
        "severity": "medium",
        "desc": "SYN cookie protection disabled — SYN flood DoS attacks easier",
    },
}

# Hypervisor detection: presence of these params on a non-VM host is suspicious
HYPERVISOR_PARAMS: frozenset[str] = frozenset({
    "kern.hv_support",     # macOS: should only be present on Apple Silicon
    "kern.hv_vmm_present", # macOS: 1 = running inside a VM
})

# Sections this module handles
SYSCTL_SECTIONS: frozenset[str] = frozenset({
    "sysctl", "kernel_params", "sysctl_output",
})

DEDUP_WINDOW_SECS: int       = 1800   # 30-min dedup (kernel params change slowly)
RATE_LIMIT_MAX_PER_HOUR: int = 30

# ─────────────────────────────────────────────────────────────────────────────
# MODULE STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]        = {}
_rate_counter: dict[str, list[float]] = {}

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
        log.debug("Rate limit: agent=%s module=sysctl_monitor", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False

# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def ingest_sysctl(data: Any) -> dict[str, str]:
    """
    Normalize sysctl data from any format into {param_key: value_string}.

    Accepts:
      - dict: {key: value}
      - list: [{"key": k, "value": v}, ...]
      - str:  "key = value" or "key: value" lines (sysctl -a output)
    """
    params: dict[str, str] = {}

    if isinstance(data, dict):
        # Direct dict or wrapper
        if "params" in data:
            data = data["params"]
        elif "sysctl" in data:
            data = data["sysctl"]
        if isinstance(data, dict):
            for k, v in data.items():
                params[k.strip()] = str(v).strip()
            return params

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                key = str(item.get("key") or item.get("name") or item.get("param") or "").strip()
                val = str(item.get("value") or item.get("val") or "").strip()
                if key:
                    params[key] = val
        return params

    if isinstance(data, str):
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            # "key = value" or "key: value"
            for sep in (" = ", ": ", "="):
                if sep in line:
                    parts = line.split(sep, 1)
                    params[parts[0].strip()] = parts[1].strip()
                    break

    return params

# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _make_alert(
    agent_id: str, hostname: str, severity: str, rule_id: str,
    title: str, description: str, mitre_technique: str,
    evidence: dict, raw: dict,
) -> dict:
    tactic_map = {
        "T1601":     "Defense Evasion",
        "T1014":     "Defense Evasion",
        "T1562.006": "Defense Evasion",
    }
    return {
        "alert_id":            str(uuid.uuid4()),
        "severity":            severity,
        "title":               title,
        "description":         description,
        "affected_asset":      hostname or agent_id,
        "mitre_tactic":        tactic_map.get(mitre_technique, "Defense Evasion"),
        "mitre_technique":     mitre_technique,
        "evidence":            evidence,
        "raw_telemetry":       raw,
        "compliance_controls": [
            "NIST CSF PR.IP-1", "CIS Kernel Hardening",
            "SOC 2 CC6.1", "ISO 27001 A.12.1.2",
        ],
        "recommended_action":  _rec_action(rule_id),
        "false_positive_notes": _fp_note(rule_id),
        "timestamp_utc":       datetime.now(timezone.utc).isoformat(),
        "agent_id":            agent_id,
        "detection_module":    "sysctl_monitor",
        "rule_id":             rule_id,
    }


def _rec_action(rule_id: str) -> str:
    m = {
        "sysctl_critical": "Revert the parameter to its baseline value immediately. "
                           "Investigate what process changed it and hunt for rootkit presence.",
        "sysctl_high":     "Review who changed this parameter and whether it is authorized. "
                           "Revert if not part of an approved change.",
        "sysctl_medium":   "Verify whether this change was intentional. "
                           "Revert if not approved.",
        "sysctl_drift":    "Compare current value against approved baseline. "
                           "Revert if the change is unauthorized.",
        "hypervisor_detected": "Confirm whether this host is expected to run in a VM. "
                               "If not, investigate for rootkit or hypervisor injection.",
    }
    return m.get(rule_id, "Investigate the flagged kernel parameter change.")


def _fp_note(rule_id: str) -> str:
    m = {
        "sysctl_critical":  "Some kernel parameters may be changed by legitimate OS updates or tuning scripts. "
                            "Verify with the sysadmin before escalating.",
        "sysctl_high":      "Network parameter tuning by performance teams is common. "
                            "Verify with a change ticket before escalating.",
        "sysctl_medium":    "Database and web servers often tune somaxconn and port ranges. "
                            "Check for authorized configuration management.",
        "sysctl_drift":     "Kernel parameters may change after OS updates. "
                            "Re-baseline after confirmed OS upgrades.",
        "hypervisor_detected": "Cloud instances and VMs will always show hypervisor presence. "
                               "Ensure asset inventory is accurate about virtualization status.",
    }
    return m.get(rule_id, "Review context before escalating.")

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION PASSES
# ─────────────────────────────────────────────────────────────────────────────

def detect_dangerous_param(agent_id: str, params: dict[str, str]) -> list[dict]:
    """
    CRITICAL/HIGH/MEDIUM — Known dangerous sysctl values set.
    Covers both CRITICAL_PARAM_RULES and HIGH_PARAM_RULES.
    """
    findings: list[dict] = []
    all_rules = list(CRITICAL_PARAM_RULES.items()) + list(HIGH_PARAM_RULES.items())

    for param_key, rule in all_rules:
        if param_key not in params:
            continue
        current_val = params[param_key]
        trigger     = rule["trigger"]
        severity    = rule["severity"]

        triggered = (
            (trigger == "changed") or
            (str(current_val).strip() == str(trigger).strip())
        )
        if not triggered:
            continue

        item_key = f"{param_key}:{current_val}"
        rule_id  = f"sysctl_{severity}"
        if _should_suppress(agent_id, rule_id, item_key):
            continue

        mitre = "T1562.006" if severity in ("critical", "high") else "T1601"
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity=severity, rule_id=rule_id,
            title=f"Dangerous kernel parameter: {param_key} = {current_val}",
            description=(
                f"Kernel parameter '{param_key}' is set to '{current_val}'. "
                f"{rule['desc']}"
            ),
            mitre_technique=mitre,
            evidence={
                "param":        param_key,
                "current_value": current_val,
                "trigger_value": trigger,
                "description":  rule["desc"],
            },
            raw={"param": param_key, "value": current_val},
        ))

    return findings


async def detect_param_drift(
    agent_id: str,
    params: dict[str, str],
    db: Any,
) -> list[dict]:
    """
    Alert when any tracked kernel parameter changes from its last-known baseline value.
    """
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "sysctl_monitor", "param_baseline")
    baseline: dict[str, str] = {}
    if raw_state:
        try:
            baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            baseline = {}

    tracked = set(CRITICAL_PARAM_RULES) | set(HIGH_PARAM_RULES)
    updated = dict(baseline)

    for param_key in tracked:
        if param_key not in params:
            continue
        current_val = params[param_key]
        updated[param_key] = current_val
        prev_val = baseline.get(param_key)

        if prev_val is None:
            continue  # first-time baseline
        if prev_val == current_val:
            continue

        # Determine severity: use the rule's severity or default to high
        rule = CRITICAL_PARAM_RULES.get(param_key) or HIGH_PARAM_RULES.get(param_key, {})
        severity = rule.get("severity", "high")

        item_key = f"{param_key}:{prev_val}→{current_val}"
        if _should_suppress(agent_id, "sysctl_drift", item_key):
            continue

        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity=severity, rule_id="sysctl_drift",
            title=f"Kernel parameter changed: {param_key} ({prev_val} → {current_val})",
            description=(
                f"Kernel parameter '{param_key}' changed from '{prev_val}' to '{current_val}'. "
                "This change may indicate unauthorized kernel configuration modification, "
                "rootkit activity, or defense evasion."
            ),
            mitre_technique="T1601",
            evidence={
                "param":          param_key,
                "previous_value": prev_val,
                "current_value":  current_val,
            },
            raw={"param": param_key, "value": current_val},
        ))

    try:
        await db.set_entity_state(
            agent_id, "sysctl_monitor", "param_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist sysctl baseline agent=%s: %s", agent_id, exc)

    return findings


def detect_hypervisor(
    agent_id: str,
    params: dict[str, str],
    is_known_vm: bool = False,
) -> list[dict]:
    """
    HIGH — Hypervisor flags present on a host declared as bare-metal.
    is_known_vm: caller passes True when asset inventory says host is a VM.
    """
    findings: list[dict] = []
    if is_known_vm:
        return findings

    for param_key in HYPERVISOR_PARAMS:
        val = params.get(param_key)
        if val is None:
            continue
        # kern.hv_vmm_present = 1 → definitely inside a VM
        if param_key == "kern.hv_vmm_present" and str(val).strip() != "1":
            continue

        item_key = f"{param_key}:{val}"
        if _should_suppress(agent_id, "hypervisor_detected", item_key):
            continue

        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high", rule_id="hypervisor_detected",
            title=f"Unexpected hypervisor detected: {param_key} = {val}",
            description=(
                f"Kernel parameter '{param_key}' indicates hypervisor/virtualization presence "
                f"(value: {val}) on a host declared as bare-metal in the asset inventory. "
                "Possible rootkit or hypervisor injection (e.g., Blue Pill attack)."
            ),
            mitre_technique="T1014",
            evidence={
                "param":        param_key,
                "current_value": val,
                "is_known_vm":  is_known_vm,
            },
            raw={"param": param_key, "value": val},
        ))

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
) -> list[dict]:
    if section not in SYSCTL_SECTIONS:
        return []

    is_known_vm = False
    raw = data
    if isinstance(data, dict) and "is_known_vm" in data:
        is_known_vm = bool(data.pop("is_known_vm"))
        raw = data

    params = ingest_sysctl(raw)
    if not params:
        return []

    findings: list[dict] = []

    for f in detect_dangerous_param(agent_id, params):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in await detect_param_drift(agent_id, params, db):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_hypervisor(agent_id, params, is_known_vm=is_known_vm):
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

    async def run_tests():
        global passed, failed

        # ── 1. Secure kernel disabled → CRITICAL ─────────────────────────────
        print("\nTest 1: kern.secure_kernel = 0 → CRITICAL")
        fresh()
        params = {"kern.secure_kernel": "0"}
        findings = detect_dangerous_param("agentA", params)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule sysctl_critical", findings[0]["rule_id"] == "sysctl_critical")

        # ── 2. IP forwarding enabled → CRITICAL ──────────────────────────────
        print("\nTest 2: net.ipv4.ip_forward = 1 → CRITICAL")
        fresh()
        params = {"net.ipv4.ip_forward": "1"}
        findings = detect_dangerous_param("agentB", params)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")

        # ── 3. ASLR disabled → CRITICAL ───────────────────────────────────────
        print("\nTest 3: kernel.randomize_va_space = 0 → CRITICAL")
        fresh()
        params = {"kernel.randomize_va_space": "0"}
        findings = detect_dangerous_param("agentC", params)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")

        # ── 4. Safe values → no alert ─────────────────────────────────────────
        print("\nTest 4: Safe kernel params — no alert")
        fresh()
        params = {
            "kern.secure_kernel": "1",
            "net.ipv4.ip_forward": "0",
            "kernel.randomize_va_space": "2",
        }
        findings = detect_dangerous_param("agentD", params)
        check("no findings", len(findings) == 0)

        # ── 5. dmesg_restrict = 0 → HIGH ─────────────────────────────────────
        print("\nTest 5: kernel.dmesg_restrict = 0 → HIGH")
        fresh()
        params = {"kernel.dmesg_restrict": "0"}
        findings = detect_dangerous_param("agentE", params)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")

        # ── 6. kptr_restrict = 0 → HIGH ───────────────────────────────────────
        print("\nTest 6: kernel.kptr_restrict = 0 → HIGH")
        fresh()
        params = {"kernel.kptr_restrict": "0"}
        findings = detect_dangerous_param("agentF", params)
        check("1 finding", len(findings) == 1)
        check("rule sysctl_high", findings[0]["rule_id"] == "sysctl_high")

        # ── 7. Hostname changed → HIGH ────────────────────────────────────────
        print("\nTest 7: kernel.hostname changed → HIGH")
        fresh()
        params = {"kernel.hostname": "attacker-staging"}
        findings = detect_dangerous_param("agentG", params)
        check("1 finding (changed trigger)", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")

        # ── 8. somaxconn changed → MEDIUM ─────────────────────────────────────
        print("\nTest 8: net.core.somaxconn changed → MEDIUM")
        fresh()
        params = {"net.core.somaxconn": "65535"}
        findings = detect_dangerous_param("agentH", params)
        check("1 finding", len(findings) == 1)
        check("severity medium", findings[0]["severity"] == "medium")

        # ── 9. Param drift: value changed ─────────────────────────────────────
        print("\nTest 9: Param drift detection")
        fresh()
        db9 = MockDB()
        # Seed baseline: ip_forward = 0
        await detect_param_drift("agentI", {"net.ipv4.ip_forward": "0"}, db9)
        # Now ip_forward = 1
        findings = await detect_param_drift("agentI", {"net.ipv4.ip_forward": "1"}, db9)
        check("1 drift finding", len(findings) == 1)
        check("rule sysctl_drift", findings[0]["rule_id"] == "sysctl_drift")
        check("previous_value = 0", findings[0]["evidence"]["previous_value"] == "0")
        check("current_value = 1", findings[0]["evidence"]["current_value"] == "1")

        # ── 10. Param drift: no change ────────────────────────────────────────
        print("\nTest 10: Param drift — no change → no alert")
        fresh()
        db10 = MockDB()
        await detect_param_drift("agentJ", {"kernel.dmesg_restrict": "1"}, db10)
        findings = await detect_param_drift("agentJ", {"kernel.dmesg_restrict": "1"}, db10)
        check("no findings", len(findings) == 0)

        # ── 11. Param drift: first baseline → no finding ──────────────────────
        print("\nTest 11: First baseline — no drift alert")
        fresh()
        db11 = MockDB()
        findings = await detect_param_drift("agentK", {"net.ipv4.ip_forward": "1"}, db11)
        check("no findings (first baseline)", len(findings) == 0)

        # ── 12. Hypervisor detected on bare-metal ─────────────────────────────
        print("\nTest 12: Hypervisor on bare-metal → HIGH")
        fresh()
        params = {"kern.hv_vmm_present": "1"}
        findings = detect_hypervisor("agentL", params, is_known_vm=False)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("rule hypervisor_detected", findings[0]["rule_id"] == "hypervisor_detected")

        # ── 13. Hypervisor on known VM → no alert ────────────────────────────
        print("\nTest 13: Hypervisor on known VM — no alert")
        fresh()
        params = {"kern.hv_vmm_present": "1"}
        findings = detect_hypervisor("agentM", params, is_known_vm=True)
        check("no findings (known VM)", len(findings) == 0)

        # ── 14. Dict ingestion ────────────────────────────────────────────────
        print("\nTest 14: Dict ingestion")
        fresh()
        raw = {"kern.secure_kernel": 0, "net.ipv4.ip_forward": 0}
        params = ingest_sysctl(raw)
        check("2 params", len(params) == 2)
        check("value as string", params["kern.secure_kernel"] == "0")

        # ── 15. Text ingestion: 'key = value' ────────────────────────────────
        print("\nTest 15: sysctl text ingestion")
        fresh()
        raw = "kern.secure_kernel = 1\nnet.ipv4.ip_forward = 0\nkernel.hostname = prod-server\n"
        params = ingest_sysctl(raw)
        check("3 params", len(params) == 3)
        check("hostname correct", params.get("kernel.hostname") == "prod-server")

        # ── 16. List ingestion ────────────────────────────────────────────────
        print("\nTest 16: List ingestion")
        fresh()
        raw = [
            {"key": "kernel.randomize_va_space", "value": "2"},
            {"key": "net.ipv4.ip_forward", "value": "0"},
        ]
        params = ingest_sysctl(raw)
        check("2 params", len(params) == 2)
        check("ASLR value", params.get("kernel.randomize_va_space") == "2")

        # ── 17. cs_enforcement_disable → CRITICAL ────────────────────────────
        print("\nTest 17: vm.cs_enforcement_disable = 1 → CRITICAL")
        fresh()
        params = {"vm.cs_enforcement_disable": "1"}
        findings = detect_dangerous_param("agentN", params)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")

        # ── 18. Dedup: same param suppressed ─────────────────────────────────
        print("\nTest 18: Dedup — same dangerous param suppressed")
        fresh()
        params = {"net.ipv4.ip_forward": "1"}
        f1 = detect_dangerous_param("agentO", params)
        f2 = detect_dangerous_param("agentO", params)
        check("first fires", len(f1) == 1)
        check("second suppressed", len(f2) == 0)

        # ── 19. rp_filter = 0 → HIGH ─────────────────────────────────────────
        print("\nTest 19: net.ipv4.conf.all.rp_filter = 0 → HIGH")
        fresh()
        params = {"net.ipv4.conf.all.rp_filter": "0"}
        findings = detect_dangerous_param("agentP", params)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")

        # ── 20. Full analyze() ────────────────────────────────────────────────
        print("\nTest 20: Full analyze() pipeline")
        fresh()
        db20 = MockDB()
        # Seed baseline: ASLR enabled
        await analyze("agentQ", "sysctl", {"kernel.randomize_va_space": "2"}, db20)
        _dedup_cache.clear()
        # Now: ASLR disabled → triggers dangerous + drift
        params_data = {"kernel.randomize_va_space": "0"}
        findings = await analyze("agentQ", "sysctl", params_data, db20, hostname="host-q")
        rule_ids = {f["rule_id"] for f in findings}
        check("sysctl_critical fired", "sysctl_critical" in rule_ids)
        check("sysctl_drift fired", "sysctl_drift" in rule_ids)
        check("affected_asset set", all(f["affected_asset"] == "host-q" for f in findings))

        # ── 21. Non-sysctl section → empty ───────────────────────────────────
        print("\nTest 21: Non-sysctl section → empty")
        fresh()
        db21 = MockDB()
        findings = await analyze("agentR", "processes", {}, db21)
        check("empty", len(findings) == 0)

        print(f"\n{'─'*50}")
        total = passed + failed
        print(f"Results: {passed}/{total} passed", end="")
        if failed:
            print(f"  ({failed} FAILED)")
            sys.exit(1)
        else:
            print("  — all OK")

    asyncio.run(run_tests())
