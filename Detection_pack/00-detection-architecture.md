# Endpoint & Supply-Chain Detection Engineering — Architecture

**Scope:** every collector listed (editor extensions, MCP servers, browser extensions, native messaging, AI/agent CLI tools, AI apps, ports, processes, LaunchDaemons, cron, shell startup, node/python/homebrew packages, git, credential locations, docker/containers, ARP, binaries, configs, connections, dev security, hardware, metrics, mounts, network, open files, packages, SBOM/SCA, security, services, storage, sysctl, tasks, users, agent health).

**Assumption stated up front:** the collectors behave like an osquery-style state agent (periodic inventory snapshots) plus an event stream (process exec, file write, socket connect). Rules below are written in a portable YAML schema with pseudo-SQL predicates so they can be compiled to osquery packs, Sigma, KQL, SPL, or a stream processor. Platform bias is macOS/Linux (LaunchDaemons + Homebrew imply macOS fleet); Windows equivalents are noted where the technique is shared.

---

## 1. Why inventory data needs a different detection model than logs

Log-based SIEM rules match *events*. Half of the collectors here emit *state*. State-based detection has three primitives that classic rules miss — build all three or the pack under-performs:

| Primitive | Question it answers | Example |
|---|---|---|
| **Match** | Does this object look bad right now? | LaunchDaemon `ProgramArguments` contains `curl \| sh` |
| **Diff (drift)** | What changed since the last snapshot? | New `core.hooksPath` in `.git/config`; SIP flipped to disabled |
| **Rarity** | How unusual is this across the fleet? | Extension present on 1 of 4,000 hosts |

Rarity is the highest-value and most-skipped signal. Compute `fleet_prevalence = hosts_with_object / hosts_reporting` for every object key (extension ID, binary SHA-256, npm name@version, MCP server command, LaunchDaemon label, listening port+process, container image digest). A first-seen-in-fleet + first-seen-globally object is the single best supply-chain lead you have.

---

## 2. Pipeline

```
COLLECT          NORMALIZE            ENRICH                DETECT                   SCORE / ACT
─────────        ─────────            ──────                ──────                   ───────────
agent tables ─▶  common schema  ─▶  identity + asset  ─▶  L1 atomic rules      ─▶  risk engine
event stream     (ECS-ish)          MITRE ATT&CK          L2 drift/diff            per-host score
                 stable object_key   NVD/KEV/EPSS          L3 rarity/baseline       chain bonus
                 dedupe + hash       OSV / deps.dev        L4 correlation chains    suppression
                                     threat feeds          L5 anomaly (stat)        alert / ticket
                                     code-sign / VT hash                            auto-response
                                     WHOIS age / ASN
```

### 2.1 Normalized object model

Every collector row becomes an `object` so one rule engine covers all 40 domains:

```json
{
  "ts": "2026-08-16T09:14:02Z",
  "host": {"id":"...","os":"macos","version":"15.5","role":"engineering-laptop"},
  "domain": "mcp_servers",
  "object_key": "mcp:cursor:filesystem-tools",
  "object_hash": "sha256:...",          // hash of security-relevant fields only
  "first_seen": "...", "last_seen": "...",
  "attrs": { "...collector-specific..." },
  "provenance": {"installer":"...","parent_process":"...","user":"..."},
  "signature": {"signed":true,"authority":"Developer ID: X","valid":true,"notarized":true},
  "enrichment": {"fleet_prevalence":0.0002,"cve":[],"epss":null,"intel":[]}
}
```

`object_hash` must exclude volatile fields (timestamps, PIDs, byte counts) or every snapshot looks like drift. Include: paths, command lines, permissions, URLs, publishers, versions, signature status, tool descriptions.

### 2.2 Enrichment sources (all free tier / API-key tier)

| Source | Endpoint | Use |
|---|---|---|
| MITRE ATT&CK | `github.com/mitre/cti` (STIX 2.1), or `attack-stix-data` | technique metadata, coverage map, tactic ordering for chain rules |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` (API key → 50 req/30s) | CVE detail, CVSS v3.1/v4, CPE match for `packages`/`sbom` |
| CISA KEV | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | *the* prioritization gate — exploited in the wild |
| EPSS | `api.first.org/data/v1/epss?cve=CVE-...` | exploit probability; use `epss >= 0.1` as a second gate |
| OSV.dev | `api.osv.dev/v1/querybatch` | best source for npm/PyPI/Go/crates — batch up to 1000 |
| deps.dev | `api.deps.dev/v3alpha/...` | package provenance, maintainer count, dependents |
| GitHub Advisory | GraphQL `securityAdvisories` | malware advisories (`MALWARE` type) for npm/PyPI |
| abuse.ch | ThreatFox / URLhaus / MalwareBazaar (auth key) | IOC match on `connections`, hash match on `binaries` |
| Spamhaus DROP, Emerging Threats, Tor exit list, CINS | plain lists | IP reputation on `connections` |
| GreyNoise Community | `api.greynoise.io/v3/community/{ip}` | separate internet-noise scanners from targeted |
| VirusTotal v3 | `/files/{sha256}` **hash lookup only** | never upload fleet binaries; hash-only preserves confidentiality |
| Sigma / SigmaHQ | rule corpus | cross-check coverage, reuse process-creation logic |
| Atomic Red Team | `atomics/` | validation tests per technique |

**Enrichment hygiene:** cache aggressively (CVE data 24h, KEV 1h, WHOIS 7d, hash verdicts 30d), never block detection on an API call — enrich asynchronously and re-score, and never send raw internal identifiers (hostnames, repo names, internal domains) to third-party APIs.

---

## 3. Detection layers

**L1 — Atomic rules.** Deterministic bad configuration or known-bad indicator. Fire immediately. (Most rules in the packs.)

**L2 — Drift.** `object_hash` changed between snapshots for a security-relevant object. Persistence, hooks, sudoers, trust store, sshd_config, MCP tool descriptions, extension permissions, container image digest. Rug-pull detection lives entirely here.

**L3 — Rarity / baseline.** After a 14–30 day learn window per host role: object unseen in fleet, or unseen for this host role, or outside this host's historical behaviour (new listening port, new egress ASN, new parent-child pair).

**L4 — Correlation chains.** Sequence of L1–L3 signals within a window, weighted by ATT&CK tactic progression. This is where you catch real intrusions; single-signal rules catch misconfiguration. Chains are in `50-correlation-chains.md`.

**L5 — Statistical anomaly.** Beaconing (periodicity + low jitter on `connections`), exfil (upload:download ratio + volume), mining (sustained CPU/GPU on `metrics` + thermal + long-lived process), telemetry gaps on `agent_health`.

---

## 4. Risk scoring

Per-signal score, then per-host aggregation with decay:

```
signal_score = base[severity] * confidence * rarity_multiplier * asset_criticality * intel_multiplier

base           : info 1, low 5, medium 15, high 40, critical 90
confidence     : 0.4 low, 0.7 medium, 1.0 high
rarity_mult    : 1.0 common(>10% fleet) … 1.5 uncommon(1-10%) … 2.0 rare(<1%) … 2.5 first-seen-global
asset_crit     : 1.0 standard … 1.5 privileged dev … 2.0 CI runner / signing host / admin
intel_mult     : 1.0 none … 1.5 feed match … 2.0 KEV or confirmed-malicious hash

host_risk(t) = Σ signal_score * e^(-λ * age_hours)     λ ≈ 0.02  (≈35h half-life)
chain_bonus  = +50% when signals span ≥3 distinct ATT&CK tactics within 24h
```

Alert thresholds: 40 = analyst queue, 100 = page, 200 = auto-isolate candidate. Tune with a two-week shadow run before enabling paging.

---

## 5. Rule schema

```yaml
- id: MCP-0003
  title: MCP server tool description changed after approval (rug pull)
  domain: mcp_servers
  layer: L2
  severity: high
  confidence: medium
  attack: [T1195.002, T1059, TA0002]
  logic: |
    domain = 'mcp_servers'
    AND drift(attrs.tools[*].description) = true
    AND prior_state.approved = true
  signals: [tool_description_hash, approval_timestamp]
  fp: legitimate server upgrades — suppress when publisher signature valid AND version bumped in lockfile
  response: quarantine server config, diff descriptions, re-approve manually
  validation: modify a local MCP server's tool description and confirm alert
```

Fields `id / domain / layer / severity / attack / logic / fp / response` are mandatory. Rules without an `fp` clause and a `validation` step do not ship — that is the single biggest quality gate.

---

## 6. Operating the pack

- **Detection-as-code:** rules in git, PR review by a second engineer, CI validates schema + runs each rule against a labelled event corpus (true positives from Atomic Red Team, false positives from a golden fleet sample).
- **Learn window:** every L3 rule ships disabled for 14 days per new host role while baselines fill.
- **Suppression, not deletion:** noisy rule → scoped allowlist with owner + expiry date, never a silent disable.
- **Coverage map:** render fired-and-tunable rules onto the ATT&CK Navigator layer monthly; gaps in Credential Access and Defense Evasion are the usual finding.
- **Dead-man switch:** `agent_health` silence is itself a detection (AH-0001). An attacker's first move against this pipeline is to stop the collector.
- **Metrics that matter:** precision per rule, mean time to triage, % alerts with enrichment complete at triage time, % techniques with ≥1 validated rule.

---

## 7. Coverage summary by domain

| Domain | Primary layers | Headline techniques |
|---|---|---|
| Editor extensions | L1 L2 L3 | T1176.002, T1195.002, T1546 |
| MCP servers | L1 L2 | T1195.002, T1059, T1204, prompt-injection (no ATT&CK ID yet — track under T1204.004 abuse) |
| Browser extensions | L1 L2 L3 | T1176.001, T1539, T1185 |
| Native messaging | L1 L2 | T1176, T1059 |
| AI / agent CLI | L1 L2 L4 | T1059, T1552, T1567 |
| AI applications | L1 L3 | T1190, T1133, insecure deserialization |
| Listening ports | L1 L3 | T1571, T1090, T1021 |
| Processes | L1 L3 L4 | T1059, T1036, T1055, T1620 |
| LaunchDaemons / Services / Cron / Tasks | L1 L2 | T1543, T1053, T1547 |
| Shell startup | L1 L2 | T1546.004, T1554 |
| Node / Python / Homebrew / Packages / SBOM / SCA | L1 L3 + NVD/OSV/KEV | T1195.001, T1195.002, T1072 |
| Git | L1 L2 | T1195.002, T1552.001, T1546 |
| Credential locations / Open files | L1 L4 | T1552, T1555, T1528 |
| Docker / Containers | L1 L2 | T1610, T1611, T1613 |
| ARP / Network / Connections | L1 L5 | T1557.002, T1071, T1041, T1090 |
| Users / Security / Configs / Sysctl | L1 L2 | T1136, T1098, T1562, T1553 |
| Binaries / Apps | L1 L3 | T1036, T1553, T1554, T1574 |
| Hardware / Mounts / Storage | L1 L3 | T1200, T1052, T1091, T1490 |
| Metrics / Agent health | L5 | T1496, T1562.001 |
