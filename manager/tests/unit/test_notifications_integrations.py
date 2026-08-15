from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.integrations import router as integrations_router
from manager.manager.indexer import IntelDB
from manager.manager.integrations.resilience import (
    PermanentError,
    RetryPolicy,
    TransientError,
    registry,
)
from manager.manager.notifications.dispatcher import FindingNotificationDispatcher
from manager.manager.notifications.email import EmailNotifier


@pytest.fixture(autouse=True)
def _reset_registry():
    registry.reset()
    yield
    registry.reset()


@pytest.mark.asyncio
async def test_email_notifier_retries_transient_smtp_failure(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_USER", "alerts@example.test")
    monkeypatch.setenv("SMTP_PASS", "secret")
    monkeypatch.setenv("ALERT_RECIPIENTS", "soc@example.test")

    notifier = EmailNotifier()
    notifier._smtp_client._retry = RetryPolicy(max_attempts=2, base_delay=0, max_delay=0, jitter=False)

    calls = 0

    async def fake_send(to, subject, body):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TransientError("email.smtp", "temporary smtp outage")
        return True

    monkeypatch.setattr(notifier, "_send_smtp", fake_send)

    ok = await notifier.send_critical_alert({
        "id": 7,
        "agent_id": "agent-a",
        "severity": "critical",
        "title": "Critical finding",
    })

    assert ok is True
    assert calls == 2
    smtp = next(i for i in registry.snapshot()["integrations"] if i["name"] == "email.smtp")
    assert smtp["successes"] == 1
    assert smtp["failures"] == 0
    assert smtp["retries"] == 1


@pytest.mark.asyncio
async def test_email_notifier_does_not_retry_permanent_failure(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_USER", "alerts@example.test")
    monkeypatch.setenv("SMTP_PASS", "secret")
    monkeypatch.setenv("ALERT_RECIPIENTS", "soc@example.test")

    notifier = EmailNotifier()
    notifier._smtp_client._retry = RetryPolicy(max_attempts=3, base_delay=0, max_delay=0, jitter=False)

    calls = 0

    async def fake_send(to, subject, body):
        nonlocal calls
        calls += 1
        raise PermanentError("email.smtp", "auth failed")

    monkeypatch.setattr(notifier, "_send_smtp", fake_send)

    ok = await notifier.send_critical_alert({
        "id": 8,
        "agent_id": "agent-a",
        "severity": "critical",
        "title": "Critical finding",
    })

    assert ok is False
    assert calls == 1
    smtp = next(i for i in registry.snapshot()["integrations"] if i["name"] == "email.smtp")
    assert smtp["failures"] == 1
    assert smtp["retries"] == 0


@pytest.mark.asyncio
async def test_finding_notification_dispatcher_uses_persisted_recipient():
    class FakeDB:
        async def _fetchall(self, sql, args):
            return [
                {"key": "notif_critical_email", "value": "true"},
                {"key": "notif_email_recipient", "value": "settings@example.test"},
            ]

    class FakeEmail:
        enabled = True
        transport = "smtp"

        def __init__(self):
            self.sent = []

        def default_alert_recipients(self):
            return ["env@example.test"]

        def health_status(self):
            return {"status": "healthy", "enabled": True, "configured": True}

        async def send_critical_alert(self, finding, recipients=None):
            self.sent.append((finding, recipients))
            return True

    email = FakeEmail()
    dispatcher = FindingNotificationDispatcher(FakeDB(), email)

    await dispatcher.handle_finding_event(
        {"id": 1, "severity": "low", "title": "noise"}, "created",
    )
    assert email.sent == []

    await dispatcher.handle_finding_event(
        {"id": 2, "severity": "high", "exploitability_band": "critical", "title": "risk"},
        "created",
    )

    assert len(email.sent) == 1
    finding, recipients = email.sent[0]
    assert finding["notification_event"] == "created"
    assert recipients == ["settings@example.test"]


@pytest.mark.asyncio
async def test_integrations_health_includes_platform_notification_services():
    class FakeEmail:
        def health_status(self):
            return {
                "status": "healthy",
                "enabled": True,
                "configured": True,
                "transport": "smtp",
            }

    class FakeDispatcher:
        async def health_status(self):
            return {
                "status": "healthy",
                "critical_alerts_enabled": True,
                "recipients_configured": True,
            }

    app = FastAPI()
    app.state.email_notifier = FakeEmail()
    app.state.finding_notification_dispatcher = FakeDispatcher()
    app.include_router(integrations_router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/integrations/health")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["overall"] == "healthy"
    assert body["platform_services"]["email"]["transport"] == "smtp"
    assert body["platform_services"]["finding_notifications"]["critical_alerts_enabled"] is True


@pytest.mark.asyncio
async def test_notification_delivery_api_exposes_audit_without_payload():
    class FakeDB:
        async def get_notification_deliveries(self, **kwargs):
            assert kwargs == {"finding_id": 7, "limit": 20}
            return [{
                "delivery_id": "delivery-7",
                "finding_id": 7,
                "status": "sent",
                "recipients": ["soc@example.test"],
                "payload": {"finding": {"evidence": "sensitive"}},
            }]

    app = FastAPI()
    app.state.intel_db = FakeDB()
    app.include_router(integrations_router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        response = await c.get(
            "/api/v1/integrations/notification-deliveries?finding_id=7&limit=20",
        )

    assert response.status_code == 200
    delivery = response.json()["deliveries"][0]
    assert delivery["status"] == "sent"
    assert "payload" not in delivery


class FakeDeliveryDB:
    def __init__(self, settings=None, *, active=None, breached=None):
        self.settings = settings or {
            "notif_critical_email": "true",
            "notif_sla_breach": "false",
            "notif_digest_daily": "false",
            "notif_email_recipient": "soc@example.test",
        }
        self.active = active or []
        self.breached = breached or []
        self.deliveries: dict[str, dict] = {}

    async def _fetchall(self, sql, args):
        return [
            {"key": key, "value": value}
            for key, value in self.settings.items()
            if key in args
        ]

    async def get_or_create_notification_delivery(self, **kwargs):
        existing = next(
            (
                row for row in self.deliveries.values()
                if row["dedupe_key"] == kwargs["dedupe_key"]
            ),
            None,
        )
        if existing:
            return dict(existing)
        delivery_id = uuid.uuid4().hex
        row = {
            "delivery_id": delivery_id,
            **kwargs,
            "status": "queued",
            "attempts": 0,
            "last_error": "",
            "next_attempt_at": 0.0,
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        self.deliveries[delivery_id] = row
        return dict(row)

    async def claim_notification_delivery(self, delivery_id, **kwargs):
        row = self.deliveries[delivery_id]
        if row["status"] not in {"queued", "failed"}:
            return None
        if row["attempts"] >= kwargs.get("max_attempts", 5):
            return None
        row["status"] = "sending"
        row["attempts"] += 1
        return dict(row)

    async def finish_notification_delivery(
        self, delivery_id, *, sent, error, next_attempt_at, exhausted,
    ):
        row = self.deliveries[delivery_id]
        row["status"] = "sent" if sent else ("exhausted" if exhausted else "failed")
        row["last_error"] = error
        row["next_attempt_at"] = next_attempt_at
        return dict(row)

    async def get_pending_notification_deliveries(self, **kwargs):
        now = time.time()
        return [
            dict(row) for row in self.deliveries.values()
            if row["status"] in {"queued", "failed"}
            and row["attempts"] < kwargs.get("max_attempts", 5)
            and row["next_attempt_at"] <= now
        ]

    async def get_notification_deliveries(self, **kwargs):
        rows = list(self.deliveries.values())
        finding_id = kwargs.get("finding_id")
        if finding_id is not None:
            rows = [row for row in rows if row["finding_id"] == finding_id]
        return [dict(row) for row in rows[:kwargs.get("limit", 100)]]

    async def get_soc_findings(self, **kwargs):
        return list(self.breached if kwargs.get("sla_breached") else self.active)


class FakeDeliveryEmail:
    enabled = True
    transport = "smtp"

    def __init__(self):
        self.failures_remaining = 0
        self.calls: list[tuple[str, object]] = []

    def default_alert_recipients(self):
        return ["env@example.test"]

    def health_status(self):
        return {"status": "healthy", "enabled": True, "configured": True}

    async def _result(self, kind, payload):
        self.calls.append((kind, payload))
        if self.failures_remaining:
            self.failures_remaining -= 1
            return False
        return True

    async def send_critical_alert(self, finding, recipients=None):
        return await self._result("finding_alert", (finding, recipients))

    async def send_soc_action(self, finding, action, actor, detail, recipients=None):
        return await self._result(
            "workflow_update", (finding, action, actor, detail, recipients),
        )

    async def send_remediation_ready(self, finding, os_type, recipients=None):
        return await self._result("remediation_ready", (finding, os_type, recipients))

    async def send_digest(self, findings, period="daily", recipients=None):
        return await self._result("daily_digest", (findings, period, recipients))


@pytest.mark.asyncio
async def test_failed_delivery_is_audited_replayed_and_deduplicated():
    db = FakeDeliveryDB()
    email = FakeDeliveryEmail()
    email.failures_remaining = 1
    dispatcher = FindingNotificationDispatcher(db, email)
    finding = {
        "id": 71,
        "severity": "critical",
        "title": "Critical finding",
        "last_detected_at": 1234,
    }

    await dispatcher.handle_finding_event(finding, "created")
    delivery = next(iter(db.deliveries.values()))
    assert delivery["status"] == "failed"
    assert delivery["attempts"] == 1
    assert delivery["last_error"]

    delivery["next_attempt_at"] = 0
    assert await dispatcher.replay_pending() == 1
    assert delivery["status"] == "sent"
    assert delivery["attempts"] == 2

    await dispatcher.handle_finding_event(finding, "created")
    assert len(db.deliveries) == 1
    assert len(email.calls) == 2


@pytest.mark.asyncio
async def test_unavailable_transport_leaves_delivery_queued_for_recovery():
    db = FakeDeliveryDB()
    email = FakeDeliveryEmail()
    email.enabled = False
    dispatcher = FindingNotificationDispatcher(db, email)

    await dispatcher.handle_finding_event(
        {
            "id": 72,
            "severity": "critical",
            "title": "Critical finding while email is unavailable",
            "last_detected_at": 1235,
        },
        "created",
    )

    delivery = next(iter(db.deliveries.values()))
    assert delivery["status"] == "queued"
    assert delivery["attempts"] == 0
    assert email.calls == []


@pytest.mark.asyncio
async def test_workflow_digest_and_sla_events_use_durable_delivery_types(monkeypatch):
    monkeypatch.setenv("EMAIL_DIGEST_HOUR_UTC", "0")
    critical = {"id": 81, "severity": "critical", "title": "Review finding"}
    breached = {
        "id": 82,
        "severity": "high",
        "title": "SLA finding",
        "sla_due": 100,
    }
    db = FakeDeliveryDB(
        settings={
            "notif_critical_email": "true",
            "notif_sla_breach": "true",
            "notif_digest_daily": "true",
            "notif_email_recipient": "soc@example.test",
        },
        active=[critical],
        breached=[breached],
    )
    email = FakeDeliveryEmail()
    dispatcher = FindingNotificationDispatcher(db, email)

    await dispatcher.handle_workflow_event(
        critical,
        event="investigation_pending_review",
        actor="AttackLens",
        run_id="run-81",
    )
    await dispatcher.handle_remediation_ready(
        critical, os_type="macos", plan_identity="plan-81",
    )
    await dispatcher._queue_scheduled_notifications()

    assert {row["notification_type"] for row in db.deliveries.values()} == {
        "workflow_update",
        "remediation_ready",
        "daily_digest",
    }
    assert {kind for kind, _ in email.calls} == {
        "workflow_update",
        "remediation_ready",
        "daily_digest",
    }
    assert [kind for kind, _ in email.calls].count("workflow_update") == 2


def test_email_configuration_and_recipient_validation_do_not_crash(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_PORT", "not-a-port")
    monkeypatch.setenv("SMTP_USER", "alerts@example.test")
    monkeypatch.setenv("ALERT_RECIPIENTS", "valid@example.test,bad\r\nBcc:x@example.test")

    notifier = EmailNotifier()

    assert notifier.enabled is False
    assert notifier.health_status()["status"] == "degraded"
    assert notifier.default_alert_recipients() == ["valid@example.test"]
    assert notifier.health_status()["configuration_errors"]


def test_email_template_escapes_untrusted_finding_fields(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_USER", "alerts@example.test")
    notifier = EmailNotifier()

    body = notifier._render_critical_alert({
        "id": 9,
        "severity": "critical",
        "title": "<script>alert(1)</script>",
        "agent_id": "<img src=x onerror=alert(1)>",
        "cve_ids": ["<b>CVE-TEST</b>"],
        "last_detected_at": "malformed",
    })

    assert "<script>" not in body
    assert "<img src=x" not in body
    assert "&lt;script&gt;" in body
    assert "&lt;b&gt;CVE-TEST&lt;/b&gt;" in body


@pytest.mark.asyncio
async def test_notification_delivery_persists_attempt_and_result(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        delivery = await idb.get_or_create_notification_delivery(
            dedupe_key=f"test:{uuid.uuid4().hex}",
            finding_id=999,
            notification_type="finding_alert",
            event="created",
            recipients=["soc@example.test"],
            transport="smtp",
            payload={"finding": {"id": 999, "severity": "critical"}},
        )
        claimed = await idb.claim_notification_delivery(delivery["delivery_id"])
        assert claimed["status"] == "sending"
        assert claimed["attempts"] == 1

        finished = await idb.finish_notification_delivery(
            delivery["delivery_id"], sent=True,
        )
        assert finished["status"] == "sent"
        assert finished["delivered_at"] > 0
        rows = await idb.get_notification_deliveries(finding_id=999)
        assert any(row["delivery_id"] == delivery["delivery_id"] for row in rows)
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_persisted_detection_reaches_durable_email_delivery(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    email = FakeDeliveryEmail()
    delivered = asyncio.Event()
    original_result = email._result

    async def signal_delivery(kind, payload):
        result = await original_result(kind, payload)
        delivered.set()
        return result

    email._result = signal_delivery
    dispatcher = FindingNotificationDispatcher(idb, email)
    idb.set_finding_notification_handler(dispatcher.handle_finding_event)
    unique = uuid.uuid4().hex
    try:
        for key, value in (
            ("notif_critical_email", "true"),
            ("notif_email_recipient", "soc@example.test"),
        ):
            await idb._conn.execute(
                "INSERT INTO org_settings(key,value,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at",
                (key, value, time.time()),
            )
        await idb._conn.commit()

        assert await idb.upsert_finding({
            "agent_id": f"email-agent-{unique}",
            "category": "process",
            "item_key": f"email-item-{unique}",
            "severity": "critical",
            "score": 9.8,
            "title": "Controlled email integration finding",
            "description": "Synthetic acceptance scenario",
            "source": "test:email-integration",
            "rule_id": "TEST-EMAIL-001",
            "evidence": {"scenario": "controlled"},
        }, time.time()) == "new"

        await asyncio.wait_for(delivered.wait(), timeout=2.0)
        sent_finding = email.calls[0][1][0]
        rows = []
        for _ in range(20):
            rows = await idb.get_notification_deliveries(
                finding_id=sent_finding["id"],
            )
            if rows and rows[0]["status"] == "sent":
                break
            await asyncio.sleep(0.01)
        assert len(rows) == 1
        assert rows[0]["status"] == "sent"
        assert rows[0]["attempts"] == 1
        assert rows[0]["notification_type"] == "finding_alert"
        assert rows[0]["recipients"] == ["soc@example.test"]
        assert "evidence" not in rows[0]["payload"]["finding"]
    finally:
        idb.set_finding_notification_handler(None)
        await idb.close()
