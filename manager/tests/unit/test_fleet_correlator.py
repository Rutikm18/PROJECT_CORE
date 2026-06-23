"""
manager/tests/unit/test_fleet_correlator.py — cross-host / global-threat correlation.

The per-agent correlator can never see a campaign that spans hosts. These tests
pin the fleet layer's contract against a real IntelDB:

  • a shared external C2 destination across ≥3 hosts fires ONE campaign whose
    affected_assets lists every host
  • the same indicator on too few hosts does NOT fire (min_hosts gate)
  • trusted destinations never fire a coordination campaign (FP control)
  • outbreak scoring escalates severity as host count grows
  • fleet campaigns persist under the reserved __fleet__ pseudo-agent and are
    excluded from the global read (no self-recursion)
  • a fleet-wide CVE outbreak fires and KEV/EPSS intel boosts the score

Uses pg_intel_dsn (conftest.py) — a freshly CREATEd, then DROPped, real
Postgres database per test.
"""
from __future__ import annotations

import json
import time

from manager.manager.indexer import IntelDB, FLEET_AGENT_ID
from manager.manager.attacklens.fleet_correlator import (
    FleetCorrelator, build_fleet_summary,
)


async def _mk_db(dsn: str) -> IntelDB:
    idb = IntelDB(dsn)
    await idb.init()
    return idb


async def _add_finding(idb, agent_id, category, item_key, *, severity="high",
                       evidence=None, title="t", score=7.0, cve_ids=None,
                       kev=0, epss=0.0, source="rule:test"):
    f = {
        "agent_id": agent_id,
        "category": category,
        "item_key": item_key,
        "severity": severity,
        "score": score,
        "title": title,
        "source": source,
        "rule_id": source,
        "evidence": evidence or {},
        "cve_ids": json.dumps(cve_ids or []),
        "kev": kev,
        "epss_score": epss,
    }
    await idb.upsert_finding(f, time.time())


async def test_distributed_c2_fires_across_hosts(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        # Same external C2 IP on 3 distinct hosts.
        for host in ("mac-1", "mac-2", "mac-3"):
            await _add_finding(
                idb, host, "connection", f"conn:{host}",
                evidence={"remote_addr": "45.33.32.156", "process": "nc"},
                title="External connection to 45.33.32.156")

        campaigns = await FleetCorrelator(idb).correlate()
        c2 = [c for c in campaigns if c["rule_id"].startswith("fleet:distributed_c2")]
        assert len(c2) == 1, "exactly one distributed-C2 campaign expected"
        camp = c2[0]
        assert set(camp["affected_assets"]) == {"mac-1", "mac-2", "mac-3"}
        assert camp["blast_radius"]["host_count"] == 3
        assert camp["agent_id"] == FLEET_AGENT_ID
        assert "45.33.32.156" in camp["entry_points"]
    finally:
        await idb.close()


async def test_below_min_hosts_does_not_fire(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        # Only 2 hosts — distributed_c2 needs 3.
        for host in ("mac-1", "mac-2"):
            await _add_finding(
                idb, host, "connection", f"conn:{host}",
                evidence={"remote_addr": "45.33.32.156"})
        campaigns = await FleetCorrelator(idb).correlate()
        assert not any(c["rule_id"].startswith("fleet:distributed_c2")
                       for c in campaigns), "must not fire below min_hosts"
    finally:
        await idb.close()


async def test_trusted_destination_is_not_a_campaign(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        # A private/loopback-ish or known-trusted IP must be filtered.
        for host in ("mac-1", "mac-2", "mac-3", "mac-4"):
            await _add_finding(
                idb, host, "connection", f"conn:{host}",
                evidence={"remote_addr": "10.0.0.5"})  # private → not external
        campaigns = await FleetCorrelator(idb).correlate()
        assert not any(c["rule_id"].startswith("fleet:distributed_c2")
                       for c in campaigns), "private dest must not fire C2 campaign"
    finally:
        await idb.close()


async def test_outbreak_scoring_escalates_with_host_count(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        # distributed_c2 outbreak_hosts=6 → at 12 hosts severity escalates 2 notches.
        for i in range(12):
            host = f"mac-{i}"
            await _add_finding(
                idb, host, "connection", f"conn:{host}",
                evidence={"remote_addr": "45.33.32.156"})
        campaigns = await FleetCorrelator(idb).correlate()
        c2 = next(c for c in campaigns if c["rule_id"].startswith("fleet:distributed_c2"))
        assert c2["severity"] == "critical", "12 hosts (≥2×outbreak) → critical"
        assert c2["blast_radius"]["host_count"] == 12
        assert c2["blast_radius"]["estimated_scope"] == "organization-wide"
        assert c2["score"] >= 9.0
    finally:
        await idb.close()


async def test_cve_outbreak_with_kev_boosts_score(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        for host in ("mac-1", "mac-2", "mac-3"):
            await _add_finding(
                idb, host, "package", f"pkg:{host}",
                severity="medium", score=5.0,
                cve_ids=["CVE-2024-3094"], kev=1, epss=0.8,
                evidence={"package": "xz", "cve": {"kev": True, "epss_score": 0.8}},
                title="xz vulnerable to CVE-2024-3094")
        campaigns = await FleetCorrelator(idb).correlate()
        cve = [c for c in campaigns
               if c["rule_id"].startswith("fleet:supply_chain_cve_outbreak")]
        assert len(cve) == 1
        camp = cve[0]
        assert camp["blast_radius"]["intel_boost"] > 0, "KEV/EPSS must boost"
        # base medium + KEV intel escalation → at least high
        assert camp["severity"] in ("high", "critical")
    finally:
        await idb.close()


async def test_fleet_campaigns_excluded_from_global_read(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        for host in ("mac-1", "mac-2", "mac-3"):
            await _add_finding(
                idb, host, "connection", f"conn:{host}",
                evidence={"remote_addr": "45.33.32.156"})
        fc = FleetCorrelator(idb)
        campaigns = await fc.correlate()
        ts = time.time()
        for c in campaigns:
            await idb.upsert_correlation(c, ts)

        # Global finding read must never include the __fleet__ pseudo-agent,
        # so a second sweep can't recurse on its own output.
        rows = await idb.get_active_findings_global()
        assert all(r.get("agent_id") != FLEET_AGENT_ID for r in rows)

        # Re-running is stable (idempotent upsert by agent_id+rule_id).
        again = await fc.correlate()
        c2_first = [c for c in campaigns if "distributed_c2" in c["rule_id"]]
        c2_again = [c for c in again if "distributed_c2" in c["rule_id"]]
        assert len(c2_first) == len(c2_again) == 1
    finally:
        await idb.close()


def test_build_fleet_summary():
    summary = build_fleet_summary([
        {"severity": "critical", "score": 9.5, "blast_radius": {"host_count": 12}},
        {"severity": "high", "score": 8.0, "blast_radius": {"host_count": 4}},
    ])
    assert summary["total"] == 2
    assert summary["critical"] == 1
    assert summary["max_hosts"] == 12
    assert summary["top_campaign"]["score"] == 9.5


def test_empty_fleet_summary():
    s = build_fleet_summary([])
    assert s == {"total": 0, "critical": 0, "high": 0, "max_hosts": 0,
                 "max_score": 0.0, "top_campaign": None}
