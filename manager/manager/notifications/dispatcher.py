"""
manager/manager/notifications/dispatcher.py — Finding notification routing.

Connects persisted platform settings to transport-specific notifiers without
making the finding write path depend on SMTP/Graph availability.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Optional

from .email import EmailNotifier

log = logging.getLogger("manager.notifications.dispatcher")

_SETTINGS_TTL_SEC = 30.0
_REPLAY_INTERVAL_SEC = 30.0
_SCHEDULE_INTERVAL_SEC = 60.0
_NOTIFICATION_KEYS = (
    "notif_critical_email",
    "notif_sla_breach",
    "notif_digest_daily",
    "notif_email_recipient",
)
_NOTIFICATION_DEFAULTS = {
    "notif_critical_email": "false",
    "notif_sla_breach": "false",
    "notif_digest_daily": "false",
    "notif_email_recipient": "",
}
_NOTIFICATION_FINDING_FIELDS = {
    "id",
    "external_id",
    "agent_id",
    "severity",
    "category",
    "title",
    "description",
    "status",
    "composite_score",
    "exploitability_score",
    "exploitability_band",
    "kev",
    "epss_score",
    "cve_ids",
    "mitre_technique",
    "recommendation",
    "last_detected_at",
    "sla_due",
    "validation_state",
    "fingerprint",
}


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _split_recipients(value: object) -> list[str]:
    raw = str(value or "")
    return [r.strip() for r in raw.split(",") if r.strip()]


def _notification_finding(finding: dict) -> dict:
    """Keep retry payloads useful without duplicating raw endpoint evidence."""
    return {
        key: value
        for key, value in finding.items()
        if key in _NOTIFICATION_FINDING_FIELDS
    }


def _alertable(finding: dict) -> bool:
    severity = str(finding.get("severity") or "").lower()
    configured_severities = {
        item.strip().lower()
        for item in os.environ.get("EMAIL_ALERT_SEVERITIES", "critical").split(",")
        if item.strip()
    }
    band = str(finding.get("exploitability_band") or "").lower()
    try:
        exploitability = float(finding.get("exploitability_score") or 0.0)
    except (TypeError, ValueError):
        exploitability = 0.0
    return (
        severity in configured_severities
        or band == "critical"
        or exploitability >= 90.0
    )


class FindingNotificationDispatcher:
    """Routes finding events through enabled platform notification settings."""

    def __init__(self, intel_db, email_notifier: Optional[EmailNotifier]) -> None:
        self._idb = intel_db
        self._email = email_notifier
        self._settings_cache: dict[str, str] | None = None
        self._settings_loaded_at = 0.0
        self._last_schedule_check = 0.0
        try:
            self._max_attempts = max(
                1, min(int(os.environ.get("EMAIL_DELIVERY_MAX_ATTEMPTS", "5")), 20),
            )
        except ValueError:
            self._max_attempts = 5

    def _validated_recipients(self, recipients: list[str]) -> list[str]:
        normalizer = getattr(self._email, "normalize_recipients", None)
        return normalizer(recipients) if callable(normalizer) else recipients

    async def handle_finding_event(self, finding: dict, event: str) -> None:
        if not _alertable(finding):
            return
        settings = await self._load_settings()
        if not _truthy(settings.get("notif_critical_email")):
            return
        if not self._email:
            log.warning("critical finding notification skipped: email notifier unavailable")
            return

        recipients = self._validated_recipients(
            _split_recipients(settings.get("notif_email_recipient"))
            or self._email.default_alert_recipients()
        )
        if not recipients:
            log.warning("critical finding notification skipped: no alert recipients configured")
            return

        finding_payload = _notification_finding(finding)
        finding_payload["notification_event"] = event
        await self._queue_and_attempt(
            notification_type="finding_alert",
            event=event,
            finding_id=int(finding_payload.get("id") or 0),
            recipients=recipients,
            payload={"finding": finding_payload},
            identity={
                "finding_id": finding_payload.get("id"),
                "event": event,
                "fingerprint": finding_payload.get("fingerprint"),
                "last_detected_at": finding_payload.get("last_detected_at"),
            },
        )

    async def handle_workflow_event(
        self,
        finding: dict,
        *,
        event: str,
        actor: str = "system",
        detail: str = "",
        run_id: str = "",
    ) -> None:
        """Queue an analyst-review or investigation lifecycle update."""
        if not _alertable(finding):
            return
        settings = await self._load_settings()
        if not _truthy(settings.get("notif_critical_email")) or not self._email:
            return
        recipients = self._validated_recipients(
            _split_recipients(settings.get("notif_email_recipient"))
            or self._email.default_alert_recipients()
        )
        if not recipients:
            return
        action = event.replace("_", " ").strip().title()
        await self._queue_and_attempt(
            notification_type="workflow_update",
            event=event,
            finding_id=int(finding.get("id") or 0),
            recipients=recipients,
            payload={
                "finding": _notification_finding(finding),
                "action": action,
                "actor": actor or "system",
                "detail": detail,
                "run_id": run_id,
            },
            identity={"finding_id": finding.get("id"), "event": event, "run_id": run_id},
        )

    async def handle_remediation_ready(
        self,
        finding: dict,
        *,
        os_type: str,
        plan_identity: str = "",
    ) -> None:
        settings = await self._load_settings()
        if not _truthy(settings.get("notif_critical_email")) or not self._email:
            return
        recipients = self._validated_recipients(
            _split_recipients(settings.get("notif_email_recipient"))
            or self._email.default_alert_recipients()
        )
        if not recipients:
            return
        await self._queue_and_attempt(
            notification_type="remediation_ready",
            event="remediation_ready",
            finding_id=int(finding.get("id") or 0),
            recipients=recipients,
            payload={"finding": _notification_finding(finding), "os_type": os_type},
            identity={
                "finding_id": finding.get("id"),
                "event": "remediation_ready",
                "os_type": os_type,
                "plan_identity": plan_identity,
            },
        )

    async def run(self) -> None:
        """Replay failed deliveries and materialize digest/SLA schedules."""
        while True:
            try:
                await self.replay_pending()
                if time.time() - self._last_schedule_check >= _SCHEDULE_INTERVAL_SEC:
                    self._last_schedule_check = time.time()
                    await self._queue_scheduled_notifications()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("notification delivery loop failed")
            await asyncio.sleep(_REPLAY_INTERVAL_SEC)

    async def replay_pending(self) -> int:
        if not self._email or not hasattr(self._idb, "get_pending_notification_deliveries"):
            return 0
        deliveries = await self._idb.get_pending_notification_deliveries(
            limit=100, max_attempts=self._max_attempts,
        )
        processed = 0
        for delivery in deliveries:
            if await self._attempt_delivery(delivery):
                processed += 1
        return processed

    async def _queue_scheduled_notifications(self) -> None:
        if not self._email:
            return
        settings = await self._load_settings()
        settings_recipients = _split_recipients(settings.get("notif_email_recipient"))
        alert_recipients = self._validated_recipients(
            settings_recipients or self._email.default_alert_recipients()
        )
        default_digest = getattr(self._email, "default_digest_recipients", None)
        digest_recipients = self._validated_recipients(
            settings_recipients or (
                default_digest() if callable(default_digest)
                else self._email.default_alert_recipients()
            )
        )
        if not alert_recipients and not digest_recipients:
            return

        now = time.time()
        date_key = time.strftime("%Y-%m-%d", time.gmtime(now))
        try:
            digest_hour = max(
                0, min(int(os.environ.get("EMAIL_DIGEST_HOUR_UTC", "8")), 23),
            )
        except ValueError:
            digest_hour = 8
        if (
            _truthy(settings.get("notif_digest_daily"))
            and time.gmtime(now).tm_hour >= digest_hour
            and hasattr(self._idb, "get_soc_findings")
        ):
            findings = await self._idb.get_soc_findings(active_only=True, limit=500)
            if findings and digest_recipients:
                await self._queue_and_attempt(
                    notification_type="daily_digest",
                    event="daily_digest",
                    finding_id=0,
                    recipients=digest_recipients,
                    payload={
                        "findings": [_notification_finding(item) for item in findings],
                        "period": "daily",
                    },
                    identity={"event": "daily_digest", "date": date_key},
                )

        if (
            _truthy(settings.get("notif_sla_breach"))
            and hasattr(self._idb, "get_soc_findings")
        ):
            breached = await self._idb.get_soc_findings(
                active_only=True, sla_breached=True, limit=500,
            )
            for finding in breached:
                if not alert_recipients:
                    break
                await self._queue_and_attempt(
                    notification_type="workflow_update",
                    event="sla_breach",
                    finding_id=int(finding.get("id") or 0),
                    recipients=alert_recipients,
                    payload={
                        "finding": _notification_finding(finding),
                        "action": "SLA Breached",
                        "actor": "AttackLens",
                        "detail": "The active finding exceeded its response SLA.",
                    },
                    identity={
                        "finding_id": finding.get("id"),
                        "event": "sla_breach",
                        "sla_due": finding.get("sla_due"),
                    },
                )

    @staticmethod
    def _dedupe_key(notification_type: str, identity: dict) -> str:
        encoded = json.dumps(identity, sort_keys=True, default=str, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        return f"email:{notification_type}:{digest}"

    async def _queue_and_attempt(
        self,
        *,
        notification_type: str,
        event: str,
        finding_id: int,
        recipients: list[str],
        payload: dict,
        identity: dict,
    ) -> bool:
        if not self._email:
            return False
        if not hasattr(self._idb, "get_or_create_notification_delivery"):
            # Compatibility path for lightweight embedders. Production IntelDB
            # always provides the durable queue.
            return (
                await self._send_payload(notification_type, payload, recipients)
                if self._email.enabled else False
            )
        delivery = await self._idb.get_or_create_notification_delivery(
            dedupe_key=self._dedupe_key(notification_type, identity),
            finding_id=finding_id,
            notification_type=notification_type,
            event=event,
            recipients=recipients,
            transport=self._email.transport,
            payload=payload,
        )
        if delivery.get("status") in {"sent", "exhausted"}:
            return delivery.get("status") == "sent"
        if not self._email.enabled:
            # Preserve the queued audit record for replay after configuration
            # or service recovery without consuming an attempt now.
            return False
        return await self._attempt_delivery(delivery)

    async def _attempt_delivery(self, delivery: dict) -> bool:
        if not self._email:
            return False
        claimed = await self._idb.claim_notification_delivery(
            delivery["delivery_id"], max_attempts=self._max_attempts,
        )
        if not claimed:
            return False
        sent = False
        error = ""
        try:
            sent = await self._send_payload(
                str(claimed.get("notification_type") or ""),
                claimed.get("payload") or {},
                claimed.get("recipients") or [],
            )
            if not sent:
                error = str(getattr(self._email, "last_error", "") or (
                    f"{self._email.transport} transport returned false; "
                    "see integration health metrics"
                ))[:1000]
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:300]}"
            log.exception("notification delivery failed id=%s", claimed.get("delivery_id"))
        attempts = int(claimed.get("attempts") or 0)
        exhausted = not sent and attempts >= self._max_attempts
        retry_at = 0.0 if sent or exhausted else time.time() + min(
            3600.0, 60.0 * (2 ** max(0, attempts - 1)),
        )
        await self._idb.finish_notification_delivery(
            claimed["delivery_id"],
            sent=sent,
            error=error,
            next_attempt_at=retry_at,
            exhausted=exhausted,
        )
        return sent

    async def _send_payload(
        self, notification_type: str, payload: dict, recipients: list[str],
    ) -> bool:
        if notification_type == "finding_alert":
            return await self._email.send_critical_alert(
                payload.get("finding") or {}, recipients=recipients,
            )
        if notification_type == "workflow_update":
            return await self._email.send_soc_action(
                payload.get("finding") or {},
                str(payload.get("action") or "Workflow update"),
                str(payload.get("actor") or "system"),
                str(payload.get("detail") or ""),
                recipients=recipients,
            )
        if notification_type == "remediation_ready":
            return await self._email.send_remediation_ready(
                payload.get("finding") or {},
                str(payload.get("os_type") or "unknown"),
                recipients=recipients,
            )
        if notification_type == "daily_digest":
            return await self._email.send_digest(
                payload.get("findings") or [],
                period=str(payload.get("period") or "daily"),
                recipients=recipients,
            )
        raise ValueError(f"unsupported notification type: {notification_type}")

    async def health_status(self) -> dict:
        settings = await self._load_settings()
        critical_enabled = _truthy(settings.get("notif_critical_email"))
        settings_recipients = _split_recipients(settings.get("notif_email_recipient"))
        email_health = self._email.health_status() if self._email else None
        env_recipients = self._email.default_alert_recipients() if self._email else []
        recipients_configured = bool(settings_recipients or env_recipients)
        delivery_counts: dict[str, int] = {}
        if hasattr(self._idb, "get_notification_deliveries"):
            try:
                deliveries = await self._idb.get_notification_deliveries(limit=500)
                for delivery in deliveries:
                    delivery_status = str(delivery.get("status") or "unknown")
                    delivery_counts[delivery_status] = (
                        delivery_counts.get(delivery_status, 0) + 1
                    )
            except Exception as exc:
                log.debug("notification delivery health load failed: %s", exc)

        if not critical_enabled:
            status = "disabled"
        elif not self._email:
            status = "down"
        elif not self._email.enabled:
            status = "degraded"
        elif not recipients_configured:
            status = "degraded"
        else:
            status = email_health.get("status", "healthy") if email_health else "healthy"

        return {
            "status": status,
            "critical_alerts_enabled": critical_enabled,
            "sla_breach_enabled": _truthy(settings.get("notif_sla_breach")),
            "daily_digest_enabled": _truthy(settings.get("notif_digest_daily")),
            "alert_severities": sorted({
                item.strip().lower()
                for item in os.environ.get("EMAIL_ALERT_SEVERITIES", "critical").split(",")
                if item.strip()
            }),
            "settings_recipients": len(settings_recipients),
            "env_recipients": len(env_recipients),
            "recipients_configured": recipients_configured,
            "delivery_counts": delivery_counts,
            "email": email_health,
        }

    async def _load_settings(self) -> dict[str, str]:
        now = time.time()
        if self._settings_cache is not None and now - self._settings_loaded_at < _SETTINGS_TTL_SEC:
            return self._settings_cache
        data = dict(_NOTIFICATION_DEFAULTS)
        try:
            placeholders = ",".join("?" for _ in _NOTIFICATION_KEYS)
            rows = await self._idb._fetchall(
                f"SELECT key, value FROM org_settings WHERE key IN ({placeholders})",
                _NOTIFICATION_KEYS,
            )
            data.update({r["key"]: r["value"] for r in rows})
        except Exception as exc:
            log.debug("notification settings load failed: %s", exc)
        self._settings_cache = data
        self._settings_loaded_at = now
        return data
