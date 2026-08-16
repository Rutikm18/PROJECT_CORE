# Fleet Telemetry Detection Rule Pack

**Purpose:** Research/study reference implementation of a detection-engineering rule pack
for endpoint/fleet inventory + telemetry data (agent-collected asset & activity data —
the kind of categories exposed by osquery-style fleet agents: processes, ports, packages,
SBOM, ARP, hardware, etc.).

This is **detection logic only** — no exploit code, no offensive tooling. Each rule
describes *what condition to check for* and *why it matters*, so it can be translated
into your SIEM/EDR query language of choice (Sigma, KQL, SPL, osquery `diff` queries,
EQL, etc.).

## Layout

One YAML file per telemetry category (matches the fields you listed):

```
agent_health.yml   apps.yml           arp.yml            battery.yml
binaries.yml       configs.yml        connections.yml    containers.yml
hardware.yml       metrics.yml        mounts.yml         network.yml
open_files.yml     packages.yml       ports.yml          processes.yml
sbom.yml           security.yml       services.yml       storage.yml
sysctl.yml         tasks.yml          users.yml
```

## Rule schema

Every rule in every file follows this shape:

```yaml
id: CATEGORY-###
title: short human name
description: what the rule catches and why it matters
mitre_attack: [Txxxx, Txxxx.xxx]      # ATT&CK technique(s), where applicable
severity: critical | high | medium | low
data_source: which collected fields/tables feed this rule
detection:
  logic: plain-language detection statement (portable to any query engine)
  conditions:
    - discrete boolean condition 1
    - discrete boolean condition 2
  threshold: rate/count/time window that turns "interesting" into "alertable"
false_positives:
  - legitimate scenario that can trigger this rule
enrichment_sources:
  - external/internal data that improves precision if integrated
response_actions:
  - suggested first triage/containment step
status: stable | experimental | tuning
```

## Design principles used throughout

1. **Baseline-relative, not just signature-based.** Most rules compare current state to
   a learned/managed baseline (last-known-good config hash, approved app allowlist,
   asset CMDB record, prior agent version) rather than relying purely on static IOCs,
   because a lot of this telemetry (hardware, configs, packages, sysctl) is about
   **drift detection**.
2. **Conditions are decomposed** so each one can be tuned/disabled independently instead
   of shipping one monolithic boolean.
3. **Correlation over single-event firing** where it meaningfully cuts noise (e.g.
   "high CPU" alone is not a rule; "high CPU + new/unsigned process + persistent
   network beacon" is).
4. **Every rule names its false-positive scenarios** — required before this goes
   anywhere near production alerting.

## Enrichment / source integration plan

These are the categories of external sources referenced across the rule pack. Wiring
these in is what turns "condition matched" into "condition matched *and* confirmed
malicious/anomalous":

| Enrichment type | Example sources | Used by |
|---|---|---|
| IP/domain reputation | MISP, AbuseIPDB, GreyNoise, OTX, Spamhaus, VirusTotal | connections, network, security |
| File/hash reputation | VirusTotal, MalwareBazaar, internal EDR hash DB | binaries, apps, packages |
| Vulnerability intel | NVD, CISA KEV, EPSS | packages, sbom, security |
| Newly-registered / DGA domains | WHOIS/RDAP feeds, DNS TI feeds | network, connections |
| Asset/identity ground truth | CMDB, IAM/HR system, MDM inventory | hardware, users, apps |
| Vendor hardware ID allowlist | USB ID database, NIC OUI registry | hardware, arp |
| Baseline/golden config store | your own CI/CD or config-management history | configs, sysctl, services |
| Geo/ASN for logins | GeoIP + impossible-travel logic | users |

Each rule's `enrichment_sources` field lists which of these apply to it specifically.

## How to extend

1. Add a new rule to the relevant category file following the schema above.
2. Assign the next sequential ID (`CATEGORY-00N`).
3. Map to MITRE ATT&CK if the behavior maps to adversary tradecraft (not everything
   does — e.g. some `battery`/`hardware` rules are integrity/tamper checks, not ATT&CK
   techniques).
4. Set `status: experimental` until it's been tuned against real fleet data (expect a
   noisy first pass on baseline-drift rules especially).

## Suggested next steps for your research

- Pick 2-3 rules per category and prototype them against real osquery/Fleet data to see
  actual hit rates before writing detection content for all ~100 rules.
- Build a small “baseline store” (even a JSON file keyed by host_id) — a large fraction
  of these rules depend on drift-from-baseline, not static signatures.
- Decide your correlation layer (Sigma correlation rules, a SOAR playbook, or a stream
  processor) since several rules here are intentionally multi-condition.
