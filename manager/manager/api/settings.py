"""
manager/manager/api/settings.py — Organisation & platform settings API.

Endpoints (mounted at /api/v1/settings):
  GET  /              — all settings + derived license + role matrix
  PUT  /              — partial update (only non-None fields written)
  GET  /license       — license status only (days remaining, status)
  GET  /roles         — role permission matrix
  GET  /audit         — change history (last 100 entries)
  POST /reset         — factory-reset (wipes all rows, re-seeds defaults)

Design:
  • org_settings  — key/value store in intel.db (persisted)
  • settings_audit — every write is journalled with old/new value + actor + ip
  • REQUIRED_FIELDS validated on PUT: org_name, issue_date, valid_until
  • READ_ONLY_FIELDS cannot be overwritten via API: license_key is masked on read
  • All field values are stripped of leading/trailing whitespace before saving
  • Date fields (issue_date, valid_until) must be YYYY-MM-DD
  • Boolean fields (notif_*) coerced to "true"/"false"
  • Numeric fields (platform_refresh_secs, platform_max_page) range-checked
"""
from __future__ import annotations

import re
import time
import logging
from datetime import date
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator, model_validator

log = logging.getLogger("manager.settings")

# ── Canonical defaults ────────────────────────────────────────────────────────

DEFAULTS: dict[str, str] = {
    "org_name":               "",
    "org_description":        "",
    "org_location":           "",
    "contact_email":          "",
    "org_industry":           "",
    "org_size":               "",
    "issue_date":             "",
    "valid_until":            "",
    "license_key":            "",
    "role_admin_label":       "Administrator",
    "role_analyst_label":     "SOC Analyst",
    "role_viewer_label":      "Read-Only Viewer",
    "platform_refresh_secs":  "30",
    "platform_timezone":      "UTC",
    "platform_max_page":      "50",
    "notif_critical_email":   "false",
    "notif_sla_breach":       "false",
    "notif_digest_daily":     "false",
    "notif_email_recipient":  "",
}

REQUIRED_FIELDS   = {"org_name", "issue_date", "valid_until"}
BOOLEAN_FIELDS    = {"notif_critical_email", "notif_sla_breach", "notif_digest_daily"}
DATE_FIELDS       = {"issue_date", "valid_until"}

NUMERIC_BOUNDS: dict[str, tuple[int, int]] = {
    "platform_refresh_secs": (10, 3600),
    "platform_max_page":     (10, 500),
}

VALID_TIMEZONES = {
    "UTC","Asia/Kolkata","Asia/Singapore","Asia/Tokyo","Asia/Dubai",
    "America/New_York","America/Chicago","America/Los_Angeles","America/Toronto",
    "Europe/London","Europe/Paris","Europe/Berlin","Australia/Sydney",
    "Africa/Lagos","America/Sao_Paulo",
}

# Mask sensitive value on read
MASKED_FIELDS = {"license_key"}

# ── Role access matrix (authoritative, not stored in DB) ──────────────────────

ROLE_MATRIX: dict[str, dict] = {
    "admin": {
        "label":       "Administrator",
        "description": "Full platform access — manage settings, API keys, bulk actions, all findings",
        "color":       "red",
        "permissions": [
            "view_all_findings",
            "update_finding",
            "bulk_action",
            "add_comment",
            "manage_settings",
            "manage_keys",
            "view_raw_data",
            "export_data",
            "manage_users",
            "view_audit_log",
        ],
    },
    "analyst": {
        "label":       "SOC Analyst",
        "description": "Investigate and manage findings — update status, add notes, bulk triage",
        "color":       "blue",
        "permissions": [
            "view_all_findings",
            "update_finding",
            "bulk_action",
            "add_comment",
            "view_raw_data",
        ],
    },
    "viewer": {
        "label":       "Read-Only Viewer",
        "description": "Read-only access to findings, dashboards, and reports — no mutations",
        "color":       "gray",
        "permissions": [
            "view_all_findings",
        ],
    },
}

PERMISSION_LABELS: dict[str, str] = {
    "view_all_findings": "View all findings",
    "update_finding":    "Update findings",
    "bulk_action":       "Bulk actions",
    "add_comment":       "Add comments",
    "manage_settings":   "Manage settings",
    "manage_keys":       "Manage API keys",
    "view_raw_data":     "View raw telemetry",
    "export_data":       "Export data",
    "manage_users":      "Manage users",
    "view_audit_log":    "View audit log",
}

# ── Pydantic models ───────────────────────────────────────────────────────────

class SettingsUpdate(BaseModel):
    org_name:               Optional[str] = None
    org_description:        Optional[str] = None
    org_location:           Optional[str] = None
    contact_email:          Optional[str] = None
    org_industry:           Optional[str] = None
    org_size:               Optional[str] = None
    issue_date:             Optional[str] = None
    valid_until:            Optional[str] = None
    license_key:            Optional[str] = None
    role_admin_label:       Optional[str] = None
    role_analyst_label:     Optional[str] = None
    role_viewer_label:      Optional[str] = None
    platform_refresh_secs:  Optional[str] = None
    platform_timezone:      Optional[str] = None
    platform_max_page:      Optional[str] = None
    notif_critical_email:   Optional[str] = None
    notif_sla_breach:       Optional[str] = None
    notif_digest_daily:     Optional[str] = None
    notif_email_recipient:  Optional[str] = None

    @field_validator("org_name")
    @classmethod
    def org_name_not_blank(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError("org_name cannot be empty")
        return v.strip() if v else v

    @field_validator("contact_email", "notif_email_recipient")
    @classmethod
    def valid_email(cls, v: Optional[str]) -> Optional[str]:
        if v and v.strip():
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v.strip()):
                raise ValueError(f"Invalid email address: {v!r}")
        return v.strip() if v else v

    @field_validator("issue_date", "valid_until")
    @classmethod
    def valid_iso_date(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return v
        v = v.strip()
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", v):
            raise ValueError(f"Date must be YYYY-MM-DD, got {v!r}")
        try:
            date.fromisoformat(v)
        except ValueError:
            raise ValueError(f"Invalid calendar date: {v!r}")
        return v

    @field_validator("platform_timezone")
    @classmethod
    def valid_timezone(cls, v: Optional[str]) -> Optional[str]:
        if v and v.strip() not in VALID_TIMEZONES:
            raise ValueError(f"Unknown timezone: {v!r}. Allowed: {sorted(VALID_TIMEZONES)}")
        return v.strip() if v else v

    @field_validator("platform_refresh_secs", "platform_max_page")
    @classmethod
    def numeric_range(cls, v: Optional[str], info) -> Optional[str]:
        if v is None:
            return v
        field = info.field_name
        lo, hi = NUMERIC_BOUNDS.get(field, (1, 10_000))
        try:
            n = int(v.strip())
        except ValueError:
            raise ValueError(f"{field} must be an integer, got {v!r}")
        if not (lo <= n <= hi):
            raise ValueError(f"{field} must be between {lo} and {hi}, got {n}")
        return str(n)

    @field_validator("notif_critical_email", "notif_sla_breach", "notif_digest_daily")
    @classmethod
    def coerce_bool(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        low = v.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return "true"
        if low in ("0", "false", "no", "off"):
            return "false"
        raise ValueError(f"Boolean field expects true/false, got {v!r}")

    @model_validator(mode="after")
    def dates_ordered(self) -> "SettingsUpdate":
        if self.issue_date and self.valid_until:
            try:
                if date.fromisoformat(self.issue_date) > date.fromisoformat(self.valid_until):
                    raise ValueError("issue_date must be before valid_until")
            except ValueError as e:
                if "must be before" in str(e):
                    raise
        return self


# ── License status helper ─────────────────────────────────────────────────────

def _license_status(settings: dict[str, str]) -> dict[str, Any]:
    valid_until_str = settings.get("valid_until", "").strip()
    issue_date_str  = settings.get("issue_date",  "").strip()
    org_name        = settings.get("org_name",    "").strip()

    base = {
        "org_name":    org_name,
        "issue_date":  issue_date_str,
        "valid_until": valid_until_str,
        "license_key": _mask(settings.get("license_key", "")),
    }

    if not valid_until_str:
        return {**base, "status": "unconfigured", "days_remaining": None,
                "label": "Not Configured", "color": "gray"}

    try:
        expiry     = date.fromisoformat(valid_until_str)
        issue      = date.fromisoformat(issue_date_str) if issue_date_str else None
        today      = date.today()
        days       = (expiry - today).days
        total_days = (expiry - issue).days if issue else 365

        if days < 0:
            status, color, label = "expired",  "red",   "Expired"
        elif days <= 30:
            status, color, label = "expiring", "amber", "Expiring Soon"
        else:
            status, color, label = "active",   "green", "Active"

        return {
            **base,
            "status":        status,
            "days_remaining": days,
            "total_days":    total_days,
            "pct_elapsed":   round(max(0, min(100, (1 - days / max(1, total_days)) * 100)), 1),
            "label":         label,
            "color":         color,
        }
    except ValueError as exc:
        return {**base, "status": "invalid_date", "days_remaining": None,
                "label": "Invalid Date", "color": "gray", "error": str(exc)}


def _mask(value: str) -> str:
    """Partially mask a license key for display (show last 4 chars only)."""
    if not value or len(value) < 4:
        return value
    return "•" * (len(value) - 4) + value[-4:]


# ── Router factory ────────────────────────────────────────────────────────────

def make_settings_router(intel_db) -> APIRouter:
    router = APIRouter()

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _load() -> dict[str, str]:
        """Load all settings from DB merged with defaults."""
        rows = await intel_db._fetchall(
            "SELECT key, value FROM org_settings ORDER BY key", ()
        )
        return {**DEFAULTS, **{r["key"]: r["value"] for r in rows}}

    async def _write(key: str, value: str, actor: str, ip: str) -> None:
        """Write a single key and append an audit row inside the caller's transaction."""
        ts = time.time()
        old_row = await intel_db._fetchone(
            "SELECT value FROM org_settings WHERE key=?", (key,)
        )
        old_val = old_row["value"] if old_row else DEFAULTS.get(key, "")

        await intel_db._conn.execute(
            "INSERT INTO org_settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, ts),
        )
        if old_val != value:
            await intel_db._conn.execute(
                "INSERT INTO settings_audit(key,old_value,new_value,actor,ip,changed_at) "
                "VALUES(?,?,?,?,?,?)",
                (key, old_val, value, actor, ip, ts),
            )

    def _redact(settings: dict[str, str]) -> dict[str, str]:
        """Mask sensitive fields before sending to client."""
        out = dict(settings)
        for k in MASKED_FIELDS:
            if out.get(k):
                out[k] = _mask(out[k])
        return out

    def _actor_ip(request: Request) -> tuple[str, str]:
        actor = request.headers.get("X-Actor", "analyst")
        ip    = request.client.host if request.client else "unknown"
        return actor, ip

    # ── GET / ─────────────────────────────────────────────────────────────────
    @router.get("")
    async def get_settings():
        """Return full settings object, derived license status, and role matrix."""
        try:
            raw      = await _load()
            settings = _redact(raw)
            return {
                "settings":           settings,
                "license":            _license_status(raw),
                "roles":              ROLE_MATRIX,
                "permission_labels":  PERMISSION_LABELS,
                "required_fields":    sorted(REQUIRED_FIELDS),
                "boolean_fields":     sorted(BOOLEAN_FIELDS),
                "date_fields":        sorted(DATE_FIELDS),
            }
        except Exception as exc:
            log.exception("get_settings failed")
            raise HTTPException(500, f"Failed to load settings: {exc}")

    # ── PUT / ─────────────────────────────────────────────────────────────────
    @router.put("")
    async def update_settings(body: SettingsUpdate, request: Request):
        """
        Persist settings fields.  Only non-None fields are written.
        Every change is appended to settings_audit with actor + client IP.
        """
        updates = {k: v for k, v in body.model_dump().items() if v is not None}
        if not updates:
            raise HTTPException(400, "No fields provided — nothing to update")

        actor, ip = _actor_ip(request)

        try:
            async with intel_db._lock:
                for key, value in updates.items():
                    await _write(key, str(value).strip(), actor, ip)
                await intel_db._conn.commit()

            raw      = await _load()
            settings = _redact(raw)
            return {
                "settings": settings,
                "license":  _license_status(raw),
                "updated":  sorted(updates.keys()),
                "actor":    actor,
            }
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        except Exception as exc:
            log.exception("update_settings failed")
            raise HTTPException(500, f"Failed to save settings: {exc}")

    # ── GET /license ──────────────────────────────────────────────────────────
    @router.get("/license")
    async def license_status():
        """Derived license validity — status, days remaining, expiry metadata."""
        try:
            raw = await _load()
            return _license_status(raw)
        except Exception as exc:
            log.exception("license_status failed")
            raise HTTPException(500, f"Failed to compute license status: {exc}")

    # ── GET /roles ────────────────────────────────────────────────────────────
    @router.get("/roles")
    async def get_roles():
        """Role permission matrix with labels."""
        return {
            "roles":             ROLE_MATRIX,
            "permission_labels": PERMISSION_LABELS,
        }

    # ── GET /audit ────────────────────────────────────────────────────────────
    @router.get("/audit")
    async def get_audit(limit: int = 100, key: Optional[str] = None):
        """
        Settings change history.  Returns up to `limit` most-recent entries,
        optionally filtered by `key`.  Requires admin role in production.
        """
        try:
            if key:
                rows = await intel_db._fetchall(
                    "SELECT * FROM settings_audit WHERE key=? ORDER BY changed_at DESC LIMIT ?",
                    (key, min(limit, 500)),
                )
            else:
                rows = await intel_db._fetchall(
                    "SELECT * FROM settings_audit ORDER BY changed_at DESC LIMIT ?",
                    (min(limit, 500),),
                )
            entries = []
            for r in rows:
                d = dict(r)
                # Mask sensitive values in audit log too
                if d.get("key") in MASKED_FIELDS:
                    d["old_value"] = _mask(d.get("old_value", ""))
                    d["new_value"] = _mask(d.get("new_value", ""))
                entries.append(d)
            return {"audit": entries, "count": len(entries)}
        except Exception as exc:
            log.exception("get_audit failed")
            raise HTTPException(500, f"Failed to load audit log: {exc}")

    # ── POST /reset ───────────────────────────────────────────────────────────
    @router.post("/reset")
    async def reset_settings(request: Request):
        """
        Wipe all rows and re-seed with DEFAULTS.
        Writes a single audit entry per key marking the reset.
        """
        actor, ip = _actor_ip(request)
        try:
            async with intel_db._lock:
                # Load current values for audit trail
                raw = await _load()
                await intel_db._conn.execute("DELETE FROM org_settings", ())
                ts = time.time()
                for key, value in DEFAULTS.items():
                    old_val = raw.get(key, "")
                    await intel_db._conn.execute(
                        "INSERT INTO org_settings(key,value,updated_at) VALUES(?,?,?)",
                        (key, value, ts),
                    )
                    if old_val != value:
                        await intel_db._conn.execute(
                            "INSERT INTO settings_audit(key,old_value,new_value,actor,ip,changed_at) "
                            "VALUES(?,?,?,?,?,?)",
                            (key, old_val, value, actor, ip, ts),
                        )
                await intel_db._conn.commit()

            return {
                "reset":    True,
                "settings": _redact(DEFAULTS),
                "actor":    actor,
            }
        except Exception as exc:
            log.exception("reset_settings failed")
            raise HTTPException(500, f"Failed to reset settings: {exc}")

    # ── GET /export ───────────────────────────────────────────────────────────
    @router.get("/export")
    async def export_settings():
        """
        Export current settings as a JSON snapshot (for backup / migration).
        Sensitive fields are NOT masked in the export so it can be re-imported.
        Treat the output as confidential.
        """
        try:
            raw = await _load()
            return {
                "export_version": "1",
                "exported_at":    time.time(),
                "settings":       raw,          # full unmasked export
            }
        except Exception as exc:
            log.exception("export_settings failed")
            raise HTTPException(500, f"Failed to export settings: {exc}")

    # ── POST /import ──────────────────────────────────────────────────────────
    @router.post("/import")
    async def import_settings(payload: dict, request: Request):
        """
        Import settings from a previously-exported snapshot.
        Only known keys are written; unknown keys are ignored.
        """
        actor, ip = _actor_ip(request)
        src = payload.get("settings", payload)  # accept both export envelope and raw dict
        if not isinstance(src, dict):
            raise HTTPException(400, "Payload must be a JSON object or export envelope with 'settings' key")

        valid_keys = set(DEFAULTS.keys())
        to_write   = {k: str(v).strip() for k, v in src.items() if k in valid_keys and v is not None}
        if not to_write:
            raise HTTPException(400, "No recognisable settings keys in payload")

        try:
            async with intel_db._lock:
                for key, value in to_write.items():
                    await _write(key, value, actor, ip)
                await intel_db._conn.commit()
            raw = await _load()
            return {
                "imported": sorted(to_write.keys()),
                "skipped":  sorted(set(src.keys()) - valid_keys),
                "settings": _redact(raw),
                "license":  _license_status(raw),
            }
        except Exception as exc:
            log.exception("import_settings failed")
            raise HTTPException(500, f"Failed to import settings: {exc}")

    return router
