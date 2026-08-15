# AttackLens Two-Week Phase Status

Status date: 2026-08-14

## Completed engineering increments

### 1. End-to-end pipeline validation

- Added one telemetry-to-dashboard acceptance target.
- Added malformed event-time rejection, optional strict section-schema
  enforcement, and bounded compatibility-gap telemetry.
- Added missing/partial developer-security, duplicate replay, delayed event,
  restart recovery, and dashboard/backend consistency scenarios.
- Verified the real RabbitMQ publish/consume contract and Windows/macOS agent
  unit surfaces.

Evidence: 104 pipeline tests, 251 platform-agent tests, and 1 real-broker
contract test passed.

### 2. Detection-logic verification

- Every one of the 65 executable YAML rules now has both a positive trigger
  and representative benign-negative scenario.
- Agent-health and hardware-integrity modules gained explicit TP/FP tests.
- Added a single detection acceptance target and ran all 17 rich-detector
  embedded harnesses.
- Corrected rule inventory reporting so 118 loaded declarations cannot be
  represented as 118 executable detections.

Evidence: 209 automated detection checks and all 17 embedded module harnesses
passed.

### 3. AI validation and LangGraph

- Added schema-aware structured response validation and invalid-response
  fallback.
- Added model-call audit records for hypothesis, verdict, and remediation
  stages.
- Verified transient retries, provider failures, deterministic fallback,
  analyst approval boundaries, and PostgreSQL checkpoint resume.
- Connected pending/completed/rejected/failed investigation lifecycle events to
  the durable notification workflow.

Evidence: 96 AI/LangGraph acceptance tests passed.

### 4. Email integration

- Added a PostgreSQL delivery queue and audit trail with atomic claims,
  deduplication, bounded replay/backoff, stale-claim recovery, and exhaustion.
- Connected critical/exploitable findings, investigation lifecycle events,
  remediation-ready events, SLA breaches, and daily digests.
- Added configuration validation, recipient/header-injection protection,
  endpoint-field HTML escaping, transport timeouts, and minimized retry
  payloads.
- Added health and redacted delivery-audit APIs.

Evidence: 28 email/workflow/retention tests passed, including a synthetic
persisted-finding-to-sent-delivery scenario.

## Release gaps that remain explicit

The code-level phase is not the same as production sign-off. These gates still
require the target deployment environments or product decisions:

1. Run signed installers and reboot/network-interruption scenarios on clean
   supported Windows and macOS hosts (Intel and Apple Silicon as applicable).
2. ~~Resolve the 26 YAML rules marked stable but lacking rule-pack evaluators:
   implement them, prove an equivalent runtime detector mapping, or reclassify
   them so product status remains truthful.~~ **Resolved 2026-08-16.** 20 were
   implemented as single-item evaluators (inline old/new transitions, baselines,
   TI flags, or configured allowlists) with positive + benign-negative fixtures;
   6 that genuinely require windowed / absence / network-flow state (AGENT-HEALTH-001,
   ARP-001, ARP-002, METRICS-003, OPEN_FILES-002, PORTS-002) were reclassified to
   `experimental` with a `status_reason`, and are owned by the rich detector
   modules rather than the per-item rule pack. Result: `stable` = 76/76 executable,
   0 declarative-only; total executable evaluators 65 → 85.
3. Run a non-sensitive smoke test against every selected live AI provider and
   retain model-call, checkpoint, and analyst-decision evidence.
4. Run a test-mailbox smoke test for the deployment's SMTP or Microsoft Graph
   credentials, including one transient and one permanent failure.
5. Complete the manual rule-by-rule Windows/macOS scenario register described
   in the Phase 2 acceptance document.

## Acceptance commands

```bash
make test-pipeline-validation
make test-detection-validation
make test-ai-validation
make test-email-validation
```

Detailed procedures and evidence requirements are in the four phase documents
in this directory.
