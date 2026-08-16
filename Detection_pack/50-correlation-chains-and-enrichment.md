# Correlation Chains, Enrichment Implementation, Rollout

Single rules find misconfiguration. Chains find intrusions. Every chain below is expressed as an ordered set of rule IDs from packs 10–40 within a time window, scored on ATT&CK tactic breadth.

---

## 1. Correlation chains

```yaml
- id: CHAIN-001
  title: Developer supply-chain compromise → credential theft → exfiltration
  window: 6h
  scope: same host
  sequence:
    - any: [PKG-0001, PKG-0002, PKG-0004, EXT-0001, EXT-0002, MCP-0002]   # untrusted code introduced
    - any: [PROC-0006, PROC-0001, PKG-0007]                               # execution
    - any: [OF-0001, OF-0002, CRED-0003, CRED-0004, GIT-0005]             # credential access
    - any: [NET-0004, NET-0002, STOR-0002]                                # staging / exfil
  min_stages: 3
  severity: critical
  action: isolate host; rotate every credential present on it; audit git pushes and CI runs since stage 1
  notes: the dominant npm/PyPI worm pattern — install script → scanner → token harvest → webhook egress

- id: CHAIN-002
  title: Agentic AI compromise via prompt injection
  window: 2h
  scope: same host + same agent session
  sequence:
    - any: [AICLI-0003, MCP-0004, EXT-0005]        # injected instructions present in context
    - any: [AICLI-0001, AICLI-0002]                # autonomy or hooks enabled
    - any: [AICLI-0004, OF-0001, NET-0007]         # credential read or unexpected egress by the agent
  min_stages: 2
  severity: critical
  action: kill session, preserve the transcript, diff every file the agent wrote
  notes: |
    Unique property of this chain — the "user" never issued a malicious instruction.
    Attribution must come from the agent transcript, so transcript capture is a prerequisite control.

- id: CHAIN-003
  title: macOS infostealer install chain
  window: 30m
  scope: same host
  sequence:
    - MNT-0001                    # DMG mounted from Downloads
    - any: [BIN-0003, PROC-0001]  # quarantine stripped / execution from temp
    - any: [CRED-0003, OF-0002]   # osascript password prompt or keychain/browser store access
    - any: [NET-0004, NET-0002]   # upload to attacker infrastructure
  min_stages: 3
  severity: critical
  action: isolate, rotate keychain contents, invalidate all browser sessions

- id: CHAIN-004
  title: Persistence establishment following execution
  window: 1h
  scope: same host
  sequence:
    - any: [PROC-0006, PROC-0004, PROC-0001, PROC-0007]
    - any: [PERS-0001, PERS-0002, CRON-0001, SHELL-0002, NMH-0001, TASK-0001, USER-0005]
  min_stages: 2
  severity: critical
  action: full timeline reconstruction from the first execution event

- id: CHAIN-005
  title: Defense evasion preceding or following any detection
  window: 24h
  scope: same host
  sequence:
    - any: [SEC-0001, PROC-0005, NETCFG-0001, SYSCTL-0001, AH-0001, AH-0002, AH-0003]
    - any: [ANY_RULE severity >= high]
  bidirectional: true
  severity: critical
  action: treat all telemetry from this host in the window as untrusted; verify out-of-band
  notes: order-independent by design — evasion before an alert and evasion after an alert are equally damning

- id: CHAIN-006
  title: Container escape to host persistence
  window: 1h
  scope: same host
  sequence:
    - any: [CNT-0001, CNT-0002, CNT-0005]
    - any: [CNT-0004, PROC-0008]              # nsenter/chroot/injection
    - any: [PERS-0001, USER-0002, USER-0004, BIN-0001]
  min_stages: 2
  severity: critical
  action: rebuild the node; container escape invalidates the host

- id: CHAIN-007
  title: Lateral movement staging
  window: 12h
  scope: same host
  sequence:
    - any: [OF-0001, CRED-0002, CRED-0003, GIT-0002]
    - any: [ARP-0001, ARP-0002, NETIF-0001, PORT-0005]
    - any: [MNT-0002, NET-0006]
  min_stages: 2
  severity: high
  action: scope to the network segment; check peer hosts for the same indicators

- id: CHAIN-008
  title: Pre-ransomware indicators
  window: 4h
  scope: same host
  sequence:
    - any: [STOR-0001]                        # backup destruction
    - any: [SEC-0001, PROC-0005]              # defense disabled
    - any: [PERS-0001, USER-0002]             # persistence / privilege
  min_stages: 2
  severity: critical
  action: immediate isolation, no analyst delay
```

**Scoring the chain:** `chain_score = Σ member_signal_scores × 1.5` when ≥3 distinct ATT&CK *tactics* are represented. Tactic breadth is a better intrusion signal than raw count — five Execution alerts is a noisy developer, one Execution + one Credential Access + one Exfiltration is an incident.

---

## 2. Enrichment implementation

Enrichment runs asynchronously against a queue; detections fire without it and are re-scored when it lands.

```python
# enrichment/vuln.py — the correlation that drives SCA-0001
import httpx, json, time
from functools import lru_cache

KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL  = "https://api.osv.dev/v1/querybatch"

@lru_cache(maxsize=1)
def kev_set(_hour: int):                       # cache key rotates hourly
    data = httpx.get(KEV_URL, timeout=30).json()
    return {v["cveID"] for v in data["vulnerabilities"]}

def epss(cves: list[str]) -> dict[str, float]:
    out = {}
    for i in range(0, len(cves), 100):         # API caps the CSV param
        r = httpx.get(EPSS_URL, params={"cve": ",".join(cves[i:i+100])}, timeout=30)
        out |= {d["cve"]: float(d["epss"]) for d in r.json().get("data", [])}
    return out

def osv_batch(components: list[dict]) -> list[dict]:
    """components: [{'ecosystem':'npm','name':'lodash','version':'4.17.20'}, ...]"""
    queries = [{"package": {"ecosystem": c["ecosystem"], "name": c["name"]},
                "version": c["version"]} for c in components]
    results = []
    for i in range(0, len(queries), 1000):     # OSV batch limit
        r = httpx.post(OSV_URL, json={"queries": queries[i:i+1000]}, timeout=60)
        results.extend(r.json()["results"])
    return results

def nvd_cve(cve_id: str, api_key: str | None = None) -> dict:
    hdrs = {"apiKey": api_key} if api_key else {}
    r = httpx.get(NVD_URL, params={"cveId": cve_id}, headers=hdrs, timeout=30)
    time.sleep(0.6 if api_key else 6.0)        # 50/30s with key, 5/30s without
    return r.json()["vulnerabilities"][0]["cve"]

def prioritize(component, cves, reachable: bool) -> str:
    kev = kev_set(int(time.time() // 3600))
    scores = epss(cves)
    if reachable and any(c in kev for c in cves):                  return "P0-same-day"
    if reachable and max((scores.get(c, 0) for c in cves), default=0) >= 0.5: return "P1-7-days"
    if any(c in kev for c in cves):                                return "P1-7-days"
    return "P2-30-days" if reachable else "P3-backlog"
```

**Reachability join** — the step that removes most SCA noise:

```sql
-- a component is "reachable" if its code is actually loaded or its port is bound
SELECT s.component, s.version, s.cve
FROM   sbom s
LEFT JOIN open_files  o ON o.path LIKE '%' || s.component || '%'
LEFT JOIN processes   p ON p.path LIKE '%' || s.component || '%'
LEFT JOIN ports       t ON t.pid  = p.pid AND t.address <> '127.0.0.1'
WHERE  s.cve IN (SELECT cve FROM cisa_kev)
  AND (o.path IS NOT NULL OR p.pid IS NOT NULL OR t.port IS NOT NULL);
```

**Threat-feed matching** — normalize every feed into one indicator table (`type, value, source, confidence, first_seen, expires`), match on `connections.remote_ip`, `connections.remote_domain`, `binaries.sha256`, `containers.image_digest`. Expire indicators aggressively (IPs 30d, domains 90d, hashes never) or precision collapses.

**MITRE mapping** — load `enterprise-attack.json` (STIX 2.1) once, build `{technique_id: {name, tactics, platforms, data_sources}}`, and validate at CI time that every rule's `attack:` list contains only live (non-deprecated, non-revoked) IDs. Emit an ATT&CK Navigator layer from rule coverage plus 90-day fire counts.

---

## 3. Rollout

| Phase | Duration | Goal |
|---|---|---|
| 1. Collect + normalize | 2 weeks | all domains landing in the common object model; `object_hash` stable (no phantom drift) |
| 2. Baseline | 2–4 weeks | fleet prevalence per object key; per-host-role baselines; **no alerting** |
| 3. L1 atomic, shadow | 2 weeks | rules fire to a triage queue only; measure precision per rule; tune `fp` clauses |
| 4. L1 live + L2 drift | 2 weeks | page on critical only; drift rules need phase-2 baselines to be usable |
| 5. L3 rarity + L4 chains | 2 weeks | chains only after member rules have measured precision |
| 6. L5 statistical | ongoing | beaconing/exfil/mining models need ≥30 days of clean data |

**Order of implementation if you can only do part of this:** AH-0001 (agent silence) → PROC-0005/0006 (evasion + remote payload) → PERS-0002 (persistence with interpreter) → OF-0002 (credential staging) → PKG-0001 (install scripts) → MCP-0001/0002 (MCP command execution) → SCA-0001 (KEV + reachable). Those seven cover the majority of realistic first-stage activity on a developer fleet.

**Validation:** every rule needs a test. Atomic Red Team covers the classic techniques (T1543.001, T1546.004, T1053.003, T1552.001). For the AI/extension surface there are no public atomics — write your own: a benign VSIX with a `postinstall`, an MCP config using `npx @latest`, a tool description containing injection phrasing, a `CLAUDE.md` with a hidden directive. Run them monthly in a lab host and fail CI when a rule stops firing.

**What this pack does not cover** and you should plan for separately: identity provider logs (impossible/atypical travel, MFA fatigue), cloud control-plane audit logs (CloudTrail/GCP), email and collaboration security, and network-tap-level detection (this is endpoint-observed connection metadata only).
