# Phase 1: End-to-End Pipeline Acceptance

This is the release gate for the path from endpoint collection to the SOC
dashboard. A green unit suite alone is not sufficient: the automated suite,
broker contract, and native operating-system checks below must all have recorded
evidence before Windows or macOS is marked validated for controlled deployment.

## Data flow under test

```text
collector -> normalizer -> encrypted sender/spool -> ingest API
          -> durable raw storage/outbox -> detection -> findings APIs
          -> dashboard aggregates and live updates
```

## Automated acceptance matrix

| Risk | Acceptance evidence |
|---|---|
| Enrollment and authenticated transport | Enroll, encrypt, ingest, wrong-key, cross-agent attribution, and replay tests |
| Missing or malformed telemetry | Required-field, event-time, section-shape, unsupported-section, and strict-mode tests |
| Duplicate delivery | Replayed nonce receives an idempotent acknowledgement and creates exactly one raw record |
| Delayed delivery | A fresh transmission with an older `collected_at` value is stored and queryable by event time |
| Partial collection | Partial developer-security data and its capability errors are preserved for the UI |
| Network interruption | Offline spool drains with zero loss, no duplicates, and FIFO order after reconnect |
| Process restart | A new sender instance drains the previous process's spool; the durable detection ledger remains replayable |
| Storage or broker failure | Raw persistence gates detection fan-out; optional archive failure does not block detection; reconciliation republishes missed work |
| Data consistency | Active finding rows, per-agent summary counts, and dashboard KPIs match by severity |
| Data readiness | Coverage API distinguishes `ok`, `empty`, `stale`, and `missing` sections |

### Run the core acceptance suite

Prerequisites: PostgreSQL must be reachable using `TEST_POSTGRES_ADMIN_DSN`
(the default is the local Compose PostgreSQL service).

```bash
docker compose up -d postgres rabbitmq
make test-pipeline-validation
```

### Run the real RabbitMQ contract

Use an isolated test broker or the local development broker. Do not point this
test at production.

```bash
RABBITMQ_TEST_URL='amqp://attacklens:changeme@127.0.0.1:5672/' \
  python3 -m pytest -q manager/tests/integration/test_queue_runtime.py
```

Record the commit, date, environment, command, pass/fail counts, skipped tests,
and artifact/log location for each run.

## Native macOS release gate

- Build and install the signed PKG on a clean supported Intel Mac and Apple
  Silicon Mac.
- Enroll through the production-equivalent TLS endpoint and verify every
  expected section through `/api/v1/raw/coverage`.
- Compare representative raw records with local OS commands and verify the
  dashboard values and timestamps.
- Disconnect networking long enough to create a spool, reconnect, and confirm
  zero loss and no duplicate raw records.
- Reboot with no user logged in, then confirm launchd startup, key access,
  collection, spool replay, and self-healing.
- Exercise complete, empty, permission-denied, timeout, and partial collector
  states without placing secrets or credential values in telemetry.

## Native Windows release gate

- Build and install the signed MSI on every supported Windows architecture and
  version.
- Enroll through the production-equivalent TLS endpoint and verify every
  expected Windows section through `/api/v1/raw/coverage`.
- Compare representative raw records with PowerShell/CIM source data and verify
  the dashboard values and timestamps.
- Interrupt networking, restart the Windows services, and reboot the host;
  confirm spool replay, service recovery, key access, zero loss, and no duplicate
  raw records.
- Exercise complete, empty, access-denied, timeout, and partial collector states.

## Exit criteria

Phase 1 is complete only when:

1. The core suite and real-broker contract pass on the release commit.
2. macOS and Windows native gates have attached evidence with no unresolved
   blocker or high-severity defect.
3. Raw telemetry, findings, summaries, and dashboard counts agree for the same
   agent and time window.
4. Every known gap has an owner, severity, and target release; skipped checks
   are not counted as passes.
