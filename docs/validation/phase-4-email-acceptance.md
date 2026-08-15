# Phase 4 Email Integration Acceptance

Status date: 2026-08-14

Eligible email work is now persisted before a transport attempt instead of
being sent as a fire-and-forget side effect. Finding creation remains
independent of SMTP or Microsoft Graph availability; each queued notification
is atomically claimed per attempt, audited, retried with bounded backoff, and
marked sent, failed, or exhausted.

## Notification triggers

| Trigger | Enablement | Delivery |
| --- | --- | --- |
| New or newly escalated finding | `notif_critical_email=true` and severity/exploitability policy | Immediate finding alert |
| LangGraph pending review, completed, rejected, or failed | Critical-alert setting and eligible finding | Workflow update |
| Remediation plan generated with `notify=true` | Critical-alert setting | Remediation-ready message |
| Active finding crosses its SLA | `notif_sla_breach=true` | One message per finding/SLA due time |
| Daily active-finding digest | `notif_digest_daily=true` | Once per UTC date after configured hour |

`EMAIL_ALERT_SEVERITIES` controls immediate and workflow severity eligibility
and defaults to `critical`. Critical exploitability-band findings or findings
with exploitability score at least 90 are always eligible. Example:

```bash
EMAIL_ALERT_SEVERITIES=critical,high
```

Recipients come from the persisted `notif_email_recipient` setting, falling
back to `ALERT_RECIPIENTS` (or `DIGEST_RECIPIENTS` for digests). Invalid,
duplicate, whitespace-containing, or header-injection addresses are discarded.

## Delivery reliability and audit

The `notification_deliveries` table records:

- deduplication identity, finding ID, notification type, event, and transport;
- recipients and a minimized server-side delivery payload (raw evidence excluded);
- status, attempt count, last error, next-attempt time, and delivery time; and
- terminal `sent` or `exhausted` state.

The maintenance role replays queued and failed deliveries every 30 seconds.
Each replay uses an atomic claim, recovers stale `sending` claims after five
minutes, and backs off from 60 seconds to a maximum of one hour. A delivery is
exhausted after `EMAIL_DELIVERY_MAX_ATTEMPTS` (default 5). Each transport attempt
also has its own bounded transient retry and circuit breaker.

Delivery is at least once: the deduplication key prevents repeated workflow
events from creating new queue records, but a process failure after the mail
provider accepts a message and before the database marks it sent can produce a
duplicate. Message consumers must not treat an email as an exactly-once event.

Operators can inspect transport health and the redacted delivery audit at:

```text
GET /api/v1/integrations/health
GET /api/v1/integrations/notification-deliveries
GET /api/v1/integrations/notification-deliveries?finding_id=123
```

The audit API omits the stored payload so endpoint evidence is not copied into
operational delivery views.

## Transport configuration

### SMTP

```text
SMTP_HOST
SMTP_PORT=587
SMTP_USER
SMTP_PASS
SMTP_FROM
SMTP_TLS=starttls|ssl|none
```

SMTP port, sender, and TLS mode are validated without crashing manager startup.
SMTP and Graph calls use bounded connect/total timeouts. Permanent authentication
or request errors fail fast; transient network, rate-limit, and server errors
are retried.

### Microsoft Graph

```text
OUTLOOK_CLIENT_ID
OUTLOOK_CLIENT_SECRET
OUTLOOK_TENANT_ID
OUTLOOK_SENDER
```

Graph uses client-credentials authentication, caches its access token until
near expiry, honors `Retry-After`, and categorizes 429/5xx as transient while
treating other 4xx responses as permanent.

Secrets remain environment/key-management inputs and are never written to the
delivery table or audit API.

## Automated acceptance gate

Start PostgreSQL and run:

```bash
docker compose up -d postgres
make test-email-validation
```

The gate covers:

- transient SMTP retry and permanent-error fail-fast behavior;
- configuration and recipient validation;
- HTML escaping of endpoint-controlled finding fields;
- durable queue insert, atomic claim, completion, deduplication, and replay;
- finding persistence through the post-persist hook to a sent email record;
- workflow, daily-digest, SLA-breach, and remediation delivery routing;
- LangGraph lifecycle notification events;
- audit API payload redaction; and
- retention of pending deliveries while terminal audit records age out normally.

## Live-delivery release gate

Automated tests do not send external email. Before controlled deployment, use a
test mailbox and synthetic finding to verify:

1. SMTP or Graph authentication and sender permissions;
2. one received message with correct subject, escaped content, and recipients;
3. a matching `sent` delivery record with one attempt;
4. a controlled temporary failure that retries and later succeeds;
5. a permanent authentication failure that becomes failed/exhausted without
   blocking finding persistence; and
6. daily digest and SLA scheduling on the maintenance-role deployment.

Do not use production customer evidence for the transport smoke test.
