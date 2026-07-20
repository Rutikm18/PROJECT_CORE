"""
manager/manager/notifications/dispatcher.py — Finding notification routing.

Connects persisted platform settings to transport-specific notifiers without
making the finding write path depend on SMTP/Graph availability.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from .email import EmailNotifier

log = logging.getLogger("manager.notifications.dispatcher")

_SETTINGS_TTL_SEC = 30.0
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


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _split_recipients(value: object) -> list[str]:
    raw = str(value or "")
    return [r.strip() for r in raw.split(",") if r.strip()]


def _alertable(finding: dict) -> bool:
    severity = str(finding.get("severity") or "").lower()
    band = str(finding.get("exploitability_band") or "").lower()
    try:
        exploitability = float(finding.get("exploitability_score") or 0.0)
    except (TypeError, ValueError):
        exploitability = 0.0
    return severity == "critical" or band == "critical" or exploitability >= 90.0


class FindingNotificationDispatcher:
    """Routes finding events through enabled platform notification settings."""

    def __init__(self, intel_db, email_notifier: Optional[EmailNotifier]) -> None:
        self._idb = intel_db
        self._email = email_notifier
        self._settings_cache: dict[str, str] | None = None
        self._settings_loaded_at = 0.0

    async def handle_finding_event(self, finding: dict, event: str) -> None:
        if not _alertable(finding):
            return
        settings = await self._load_settings()
        if not _truthy(settings.get("notif_critical_email")):
            return
        if not self._email:
            log.warning("critical finding notification skipped: email notifier unavailable")
            return

        recipients = (
            _split_recipients(settings.get("notif_email_recipient"))
            or self._email.default_alert_recipients()
        )
        if not recipients:
            log.warning("critical finding notification skipped: no alert recipients configured")
            return

        payload = dict(finding)
        payload["notification_event"] = event
        ok = await self._email.send_critical_alert(payload, recipients=recipients)
        if not ok:
            log.warning(
                "critical finding notification failed finding=%s event=%s transport=%s",
                payload.get("id") or payload.get("external_id"),
                event,
                self._email.transport,
            )

    async def health_status(self) -> dict:
        settings = await self._load_settings()
        critical_enabled = _truthy(settings.get("notif_critical_email"))
        settings_recipients = _split_recipients(settings.get("notif_email_recipient"))
        email_health = self._email.health_status() if self._email else None
        env_recipients = self._email.default_alert_recipients() if self._email else []
        recipients_configured = bool(settings_recipients or env_recipients)

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
            "settings_recipients": len(settings_recipients),
            "env_recipients": len(env_recipients),
            "recipients_configured": recipients_configured,
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
