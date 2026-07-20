from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.integrations import router as integrations_router
from manager.manager.integrations.resilience import PermanentError, RetryPolicy, TransientError, registry
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
