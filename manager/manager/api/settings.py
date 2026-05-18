"""
manager/manager/api/settings.py — Organisation & platform settings API.

Endpoints (mounted at /api/v1/settings):
  GET  /            — return all settings as a flat JSON object
  PUT  /            — update one or more settings fields, returns updated object
  GET  /license     — derived license status (active / expiring / expired + days left)
  POST /reset       — reset all settings to factory defaults (admin only)

Settings are stored in the org_settings key-value table in intel.db.
All keys are strings; callers are responsible for type coercion of typed fields
(dates, booleans, integers).  The frontend stores ISO-8601 date strings.
"""
from __future__ import annotations

import time
import logging
from typing import Optional, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

log = logging.getLogger("manager.settings")

# ── Default settings ──────────────────────────────────────────────────────────

DEFAULTS: dict[str, str] = {
    # Organisation
    "org_name":            "",
    "org_description":     "",
    "org_location":        "",
    "contact_email":       "",
    "org_industry":        "",
    "org_size":            "",
    # License / validity
    "issue_date":          "",
    "valid_until":         "",
    "license_key":         "",
    # Role access — stored as comma-separated list of allowed actions per role
    # viewer:  read-only  analyst: findings+comments  admin: everything
    "role_admin_label":    "Administrator",
    "role_analyst_label":  "SOC Analyst",
    "role_viewer_label":   "Read-Only Viewer",
    # Platform
    "platform_refresh_secs": "30",
    "platform_timezone":     "UTC",
    "platform_max_page":     "50",
    # Notifications (boolean strings)
    "notif_critical_email":  "false",
    "notif_sla_breach":      "false",
    "notif_digest_daily":    "false",
    "notif_email_recipient": "",
}

REQUIRED_FIELDS = {"org_name", "issue_date", "valid_until"}

# ── Pydantic models ───────────────────────────────────────────────────────────

class SettingsUpdate(BaseModel):
    org_name:            Optional[str] = None
    org_description:     Optional[str] = None
    org_location:        Optional[str] = None
    contact_email:       Optional[str] = None
    org_industry:        Optional[str] = None
    org_size:            Optional[str] = None
    issue_date:          Optional[str] = None   # ISO-8601 date: YYYY-MM-DD
    valid_until:         Optional[str] = None   # ISO-8601 date: YYYY-MM-DD
    license_key:         Optional[str] = None
    role_admin_label:    Optional[str] = None
    role_analyst_label:  Optional[str] = None
    role_viewer_label:   Optional[str] = None
    platform_refresh_secs: Optional[str] = None
    platform_timezone:   Optional[str] = None
    platform_max_page:   Optional[str] = None
    notif_critical_email:  Optional[str] = None
    notif_sla_breach:      Optional[str] = None
    notif_digest_daily:    Optional[str] = None
    notif_email_recipient: Optional[str] = None

    @field_validator("org_name")
    @classmethod
    def name_not_empty(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip() == "":
            raise ValueError("org_name cannot be empty")
        return v

    @field_validator("issue_date", "valid_until")
    @classmethod
    def valid_date_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return v
        import re
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", v):
            raise ValueError("Date must be YYYY-MM-DD")
        return v

# ── License status helper ─────────────────────────────────────────────────────

def _license_status(settings: dict[str, str]) -> dict[str, Any]:
    from datetime import date, datetime
    valid_until_str = settings.get("valid_until", "")
    issue_date_str  = settings.get("issue_date",  "")

    if not valid_until_str:
        return {"status": "unconfigured", "days_remaining": None,
                "issue_date": issue_date_str, "valid_until": valid_until_str}

    try:
        expiry = date.fromisoformat(valid_until_str)
        today  = date.today()
        days   = (expiry - today).days
        if days < 0:
            status = "expired"
        elif days <= 30:
            status = "expiring"
        else:
            status = "active"
        return {
            "status":         status,
            "days_remaining": days,
            "expiry_date":    valid_until_str,
            "issue_date":     issue_date_str,
            "valid_until":    valid_until_str,
        }
    except ValueError:
        return {"status": "invalid_date", "days_remaining": None,
                "issue_date": issue_date_str, "valid_until": valid_until_str}


# ── Role access matrix (static, not stored) ───────────────────────────────────

ROLE_MATRIX = {
    "admin": {
        "label":       "Administrator",
        "description": "Full platform access — manage settings, keys, bulk actions, all findings",
        "permissions": [
            "view_all_findings", "update_finding", "bulk_action",
            "add_comment", "manage_settings", "manage_keys",
            "view_raw_data", "export_data", "manage_users",
        ],
        "color": "red",
    },
    "analyst": {
        "label":       "SOC Analyst",
        "description": "Investigate and manage findings — update status, add notes, bulk triage",
        "permissions": [
            "view_all_findings", "update_finding", "bulk_action",
            "add_comment", "view_raw_data",
        ],
        "color": "blue",
    },
    "viewer": {
        "label":       "Read-Only Viewer",
        "description": "Read-only access to findings, dashboards, and reports — no mutations",
        "permissions": [
            "view_all_findings",
        ],
        "color": "gray",
    },
}


# ── Router factory ────────────────────────────────────────────────────────────

def make_settings_router(intel_db) -> APIRouter:
    router = APIRouter()

    async def _get_all() -> dict[str, str]:
        """Load all settings from DB, filling missing keys with defaults."""
        rows = await intel_db._fetchall(
            "SELECT key, value FROM org_settings ORDER BY key", ()
        )
        stored = {r["key"]: r["value"] for r in rows}
        return {**DEFAULTS, **stored}

    async def _set(key: str, value: str) -> None:
        ts = time.time()
        await intel_db._conn.execute(
            "INSERT INTO org_settings(key, value, updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, ts),
        )

    # ── GET /api/v1/settings ─────────────────────────────────────────────────
    @router.get("")
    async def get_settings():
        """Return all platform and organisation settings."""
        try:
            settings = await _get_all()
            return {
                "settings":  settings,
                "license":   _license_status(settings),
                "roles":     ROLE_MATRIX,
                "required":  list(REQUIRED_FIELDS),
            }
        except Exception as exc:
            log.exception("get_settings failed")
            raise HTTPException(500, f"Failed to load settings: {exc}")

    # ── PUT /api/v1/settings ─────────────────────────────────────────────────
    @router.put("")
    async def update_settings(body: SettingsUpdate):
        """
        Persist one or more settings fields.
        Only fields explicitly provided (not None) are written.
        Returns the full updated settings object.
        """
        updates = {k: v for k, v in body.model_dump().items() if v is not None}
        if not updates:
            raise HTTPException(400, "No fields to update")

        try:
            async with intel_db._lock:
                for key, value in updates.items():
                    await _set(key, str(value))
                await intel_db._conn.commit()

            settings = await _get_all()
            return {
                "settings": settings,
                "license":  _license_status(settings),
                "updated":  list(updates.keys()),
            }
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        except Exception as exc:
            log.exception("update_settings failed")
            raise HTTPException(500, f"Failed to save settings: {exc}")

    # ── GET /api/v1/settings/license ─────────────────────────────────────────
    @router.get("/license")
    async def license_status():
        """Return current license validity without the full settings payload."""
        try:
            settings = await _get_all()
            lic = _license_status(settings)
            lic["org_name"] = settings.get("org_name", "")
            return lic
        except Exception as exc:
            log.exception("license_status failed")
            raise HTTPException(500, f"Failed to compute license status: {exc}")

    # ── GET /api/v1/settings/roles ────────────────────────────────────────────
    @router.get("/roles")
    async def get_roles():
        """Return the role access matrix."""
        return {"roles": ROLE_MATRIX}

    # ── POST /api/v1/settings/reset ───────────────────────────────────────────
    @router.post("/reset")
    async def reset_settings():
        """Reset all settings to factory defaults."""
        try:
            async with intel_db._lock:
                await intel_db._conn.execute("DELETE FROM org_settings", ())
                await intel_db._conn.commit()
            return {"reset": True, "settings": DEFAULTS}
        except Exception as exc:
            log.exception("reset_settings failed")
            raise HTTPException(500, f"Failed to reset settings: {exc}")

    return router
