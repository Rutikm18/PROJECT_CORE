# Phase 2 Detection-Logic Verification

Status date: 2026-08-14

This is the release gate for the manual detection-logic phase. It separates
rules that can execute from YAML declarations that are still product backlog.
The distinction matters: loading a YAML file does not prove that a finding can
be generated.

## Current inventory

| Detection surface | Declared/loaded | Executable | Declarative only | Verification |
| --- | ---: | ---: | ---: | --- |
| Fleet telemetry YAML rules | 118 | 65 | 53 | 65 positive and 65 benign-negative scenarios |
| Dedicated detection modules | 23 | 23 | 0 | Direct pytest suites or embedded TP/FP harness |
| Developer-security rules | 9 | 9 | 0 | Positive, negative, boundary, redaction, and dedup tests |

YAML rule maturity is currently:

| Status | Total | Executable | Declarative only |
| --- | ---: | ---: | ---: |
| Stable | 82 | 56 | 26 |
| Tuning | 25 | 6 | 19 |
| Experimental | 11 | 3 | 8 |

The `/api/v1/custom-correlations/reload-rules` response exposes these counts,
their per-status breakdown, and the declarative-only rule IDs. Product and
release reporting must use `executable_rules`, not `total_yaml_rules`.

## Automated acceptance gate

Start PostgreSQL for the routing tests, then run:

```bash
docker compose up -d postgres
make test-detection-validation
```

The gate verifies:

- every registered rule-pack evaluator has a controlled positive fixture;
- every registered evaluator stays silent for representative benign data;
- all canonical telemetry sources have at least one executable detection path;
- live agent field shapes reach the intended detectors;
- severity, evidence, deduplication, and latency contracts remain valid;
- agent-health and hardware-baseline changes have explicit TP/FP coverage;
- all 17 legacy rich-detector self-test harnesses complete successfully; and
- rule inventory reports executable and declarative-only counts accurately.

## Stable rules that are not executable YAML rules

These 26 rules must not be reported as rule-pack coverage until each has either
an evaluator or an explicit, tested mapping to an equivalent production
detector:

- Agent health: `AGENT-HEALTH-001`, `AGENT-HEALTH-002`, `AGENT-HEALTH-005`
- Applications: `APPS-001`, `APPS-005`
- ARP: `ARP-001`, `ARP-002`, `ARP-003`, `ARP-005`
- Battery: `BATTERY-002`
- Configuration: `CONFIGS-001`, `CONFIGS-002`
- Connections: `CONNECTIONS-005`
- Hardware: `HARDWARE-003`, `HARDWARE-005`
- Metrics: `METRICS-003`
- Open files: `OPEN_FILES-002`
- Packages: `PACKAGES-002`, `PACKAGES-004`
- Ports: `PORTS-001`, `PORTS-002`
- SBOM: `SBOM-001`, `SBOM-005`
- Services: `SERVICES-003`
- Storage: `STORAGE-002`
- Sysctl: `SYSCTL-002`

Several have equivalent behavior in dedicated modules, but that equivalence
still needs to be captured in an acceptance matrix with the runtime rule ID.
Others require new telemetry, state, or integration context. Creating a weak
single-event heuristic merely to make the count green is not acceptable.

## Manual scenario record

For every supported runtime rule, record the following during controlled
Windows and macOS validation:

| Field | Required evidence |
| --- | --- |
| Rule | Declared rule ID and actual runtime rule ID |
| Platform | Windows or macOS version and agent build |
| Positive action | Exact controlled action or replayed telemetry |
| Negative control | Similar legitimate activity that must stay silent |
| Expected result | Finding, minimum severity, and maximum latency |
| Actual result | Finding ID, evidence fields, timestamps, and screenshot/link |
| Pipeline trace | Raw event ID, ledger/outbox state, and dashboard record |
| Outcome | Pass, false negative, false positive, or blocked |
| Follow-up | Owner, defect link, and retest date |

Do not use real credentials, production malware, or unauthorized attack
activity. Prefer synthetic payloads, harmless commands, test accounts, and
isolated lab endpoints.

## Exit criteria

Phase 2 is complete only when:

1. the automated acceptance gate passes;
2. every rule marketed as supported has both positive and negative evidence;
3. declarative-only stable rules are implemented, explicitly mapped, or
   reclassified so product status is truthful;
4. false positives and false negatives are logged and retested; and
5. the signed Windows and macOS builds pass the manual matrix on clean hosts.

The automated rule-pack gate is green. The 26 stable declarative-only rules were
resolved on 2026-08-16 (20 implemented as single-item evaluators, 6 reclassified
to `experimental` with a `status_reason` where windowed/absence/flow state is
required) — `stable` is now 76/76 executable, 0 declarative-only, and every
executable rule carries a positive + benign-negative fixture. Native endpoint
execution on signed clean-host builds remains release work.
