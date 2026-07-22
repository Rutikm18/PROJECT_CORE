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

import json
import re
import time
import logging
from datetime import date
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator, model_validator

from ..attacklens.asset_priority import (
    ASSET_PRIORITY_LEVELS,
    normalize_agent_priorities,
    priority_options,
)

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
    "platform_timezone":      "Asia/Kolkata",
    "platform_max_page":      "50",
    "notif_critical_email":   "false",
    "notif_sla_breach":       "false",
    "notif_digest_daily":     "false",
    "notif_email_recipient":  "",
    # Data retention: how long raw telemetry stays queryable, and what
    # happens to it past that point. See manager/store.py (cold tier doubles
    # as the archive when retention_action="archive") and server.py's
    # _cleanup_store (reads these live, so a change here takes effect on the
    # next hourly sweep with no restart). The setting name is kept for
    # backwards compatibility; values 0/7/15 are day presets, values 1+
    # below are month presets.
    "retention_period_months": "0",        # default: 1 day — keeps the smallest hot dataset
    "retention_action":        "delete",  # default: delete — "archive" keeps a
                                          # compressed copy instead (see /retention)
    # Auto-resolve: how long after evidence disappears from agent telemetry
    # before findings are automatically marked resolved. 2 days (48h) default
    # safely exceeds the longest per-rule alert-dedup window (24h), so a still-
    # present entity isn't wrongly resolved during its dedup window.
    "auto_resolve_stale_days": "2",       # default: 2 days (48h) — range 1–14d
}

REQUIRED_FIELDS   = {"org_name", "issue_date", "valid_until"}
BOOLEAN_FIELDS    = {"notif_critical_email", "notif_sla_breach", "notif_digest_daily"}
DATE_FIELDS       = {"issue_date", "valid_until"}

# Allowed retention period codes. The persisted key remains
# `retention_period_months` for API/storage compatibility, but short windows
# use sentinel codes:
#   0  -> 1 day
#   7  -> 7 days
#   15 -> 15 days
# Month windows are actual month counts (30 days/month).
RETENTION_DAY_SENTINELS: dict[int, int] = {0: 1, 7: 7, 15: 15}
RETENTION_MONTH_PERIODS: tuple[int, ...] = (1, 3, 6, 12, 24)
RETENTION_PERIODS_MONTHS: tuple[int, ...] = (
    *RETENTION_DAY_SENTINELS.keys(),
    *RETENTION_MONTH_PERIODS,
)
RETENTION_SLOW_FETCH_MONTHS: frozenset[int] = frozenset({12, 24})
RETENTION_ACTIONS = ("delete", "archive")
AUTO_RESOLVE_STALE_DAY_BOUNDS = (1, 14)
AUTO_RESOLVE_STALE_DAY_DEFAULT = 2


def retention_period_code(months_str: str) -> int:
    """Return a valid retention period code from a stored setting value."""
    try:
        months = int(months_str)
    except (TypeError, ValueError):
        months = 0
    if months not in RETENTION_PERIODS_MONTHS:
        months = min(RETENTION_PERIODS_MONTHS, key=lambda m: abs(m - months))
    return months


def retention_period_days(months_str: str) -> int:
    """Convert a retention_period_months setting value to days.

    The legacy setting stores period codes, not strictly months:
    0/7/15 are day presets, and 1/3/6/12/24 are month presets. Falls back to
    the 1-day default for unset/invalid values rather than raising — retention
    enforcement must never crash the cleanup job over a bad setting.
    """
    months = retention_period_code(months_str)
    if months in RETENTION_DAY_SENTINELS:
        return RETENTION_DAY_SENTINELS[months]
    return months * 30


def retention_action_value(action: str) -> str:
    """Return a safe retention action from a stored setting value."""
    value = str(action or "").strip().lower()
    return value if value in RETENTION_ACTIONS else "delete"


def auto_resolve_stale_days_value(value: str) -> int:
    """Return a safe auto-resolve day count from a stored setting value."""
    try:
        days = int(str(value).strip())
    except (TypeError, ValueError):
        return AUTO_RESOLVE_STALE_DAY_DEFAULT
    lo, hi = AUTO_RESOLVE_STALE_DAY_BOUNDS
    return max(lo, min(hi, days))

# ── Validation / Confidence Scoring keys ──────────────────────────────────────
# All persisted in the same org_settings table. JSON-encoded keys hold maps.
VALIDATION_DEFAULTS: dict[str, str] = {
    # Default 0.80 — anchor criteria (KEV, UID 0, IOC hit, SIP off) floor a
    # finding's Detection Confidence at 80 %, so this lets any finding with a
    # smoking-gun signal pass without configuration.  Bump to 0.90 once the
    # operator has calibrated their own corroboration sources.
    "validation_global_threshold":   "0.80",
    "validation_terrain_thresholds": "{}",     # JSON: {terrain: float}
    "validation_agent_thresholds":   "{}",     # JSON: {agent_id: float}
    "validation_agent_priorities":   "{}",     # JSON: {agent_id: top|high|standard|low}
    "validation_use_ai_verdict":     "true",   # bool — whether to call the LLM
    "validation_min_strength":       "0.6",    # float — quality floor (G7)
}
VALIDATION_KEYS = set(VALIDATION_DEFAULTS.keys())
ALL_DEFAULTS: dict[str, str] = {**DEFAULTS, **VALIDATION_DEFAULTS}

# Terrains shown in the dashboard sidebar. Order matters — UI renders them
# in the same order.  Each maps to one or more finding categories.
VALIDATION_TERRAINS: list[str] = ["citadels", "vector", "origin", "identity", "posture"]
VALIDATION_TERRAIN_CATEGORIES: dict[str, list[str]] = {
    "citadels": ["execution","process","script","container","persistence","service","task","malware"],
    "vector":   ["network","connection","port","arp","covert","lateral","mount"],
    "origin":   ["package","vulnerability","sbom","config","binary","sysctl","app","open_file","storage"],
    "identity": ["user","identity","account","credential"],
    "posture":  ["security","posture","sip","firewall","agent_health","battery","hardware"],
}
VALIDATION_TERRAIN_LABELS: dict[str, str] = {
    "citadels": "Citadels (Execution & Persistence)",
    "vector":   "Vector (Network & Reachability)",
    "origin":   "Origin (Surface, Packages, Configs)",
    "identity": "Identity (Accounts & Credentials)",
    "posture":  "Posture (Security Controls)",
}
VALIDATION_THRESHOLD_BOUNDS = (0.50, 1.00)   # inclusive — 0.50 floor prevents footgun


def _clamp_threshold(value: float) -> float:
    lo, hi = VALIDATION_THRESHOLD_BOUNDS
    return max(lo, min(hi, float(value)))


def category_to_terrain(category: str) -> Optional[str]:
    """Map a finding category to its dashboard terrain (None if unknown)."""
    c = (category or "").lower()
    for terrain, cats in VALIDATION_TERRAIN_CATEGORIES.items():
        if c in cats:
            return terrain
    return None

NUMERIC_BOUNDS: dict[str, tuple[int, int]] = {
    "platform_refresh_secs": (10, 3600),
    "platform_max_page":     (10, 500),
}

def _is_valid_iana_timezone(tz: str) -> bool:
    """Return True if tz is a timezone the Python runtime recognises."""
    try:
        from zoneinfo import ZoneInfo   # Python 3.9+
        ZoneInfo(tz)
        return True
    except (KeyError, ImportError):
        pass
    try:
        import pytz                     # fallback if zoneinfo unavailable
        pytz.timezone(tz)
        return True
    except Exception:
        return False

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

class ValidationUpdate(BaseModel):
    """Body for PUT /api/v1/settings/validation."""
    global_threshold:   Optional[float] = Field(None, ge=0.0, le=1.0)
    terrain_thresholds: Optional[dict[str, float]] = None
    agent_thresholds:   Optional[dict[str, float]] = None
    agent_priorities:   Optional[dict[str, str]] = None
    use_ai_verdict:     Optional[bool] = None
    min_strength:       Optional[float] = Field(None, ge=0.0, le=1.0)

    @field_validator("terrain_thresholds")
    @classmethod
    def _validate_terrain(cls, v):
        if v is None:
            return v
        unknown = sorted(set(v.keys()) - set(VALIDATION_TERRAINS))
        if unknown:
            raise ValueError(f"Unknown terrain(s): {unknown}. "
                             f"Valid: {VALIDATION_TERRAINS}")
        return {k: _clamp_threshold(float(val)) for k, val in v.items()}

    @field_validator("agent_thresholds")
    @classmethod
    def _validate_agents(cls, v):
        if v is None:
            return v
        return {k: _clamp_threshold(float(val)) for k, val in v.items() if k}

    @field_validator("agent_priorities")
    @classmethod
    def _validate_agent_priorities(cls, v):
        if v is None:
            return v
        return normalize_agent_priorities(v)


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
    retention_period_months: Optional[str] = None
    retention_action:        Optional[str] = None
    auto_resolve_stale_days: Optional[str] = None

    @field_validator("org_name")
    @classmethod
    def org_name_not_blank(cls, v: Optional[str]) -> Optional[str]:
        # Allow empty string — org_name is optional; empty means "not yet configured"
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
        if v and v.strip():
            tz = v.strip()
            if not _is_valid_iana_timezone(tz):
                raise ValueError(f"Unknown timezone: {tz!r}. Must be a valid IANA timezone string.")
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

    @field_validator("retention_period_months")
    @classmethod
    def valid_retention_period(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            months = int(v.strip())
        except ValueError:
            raise ValueError(f"retention_period_months must be an integer, got {v!r}")
        if months not in RETENTION_PERIODS_MONTHS:
            raise ValueError(
                f"retention_period_months must be one of {RETENTION_PERIODS_MONTHS}, got {months}"
            )
        return str(months)

    @field_validator("retention_action")
    @classmethod
    def valid_retention_action(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        action = v.strip().lower()
        if action not in RETENTION_ACTIONS:
            raise ValueError(f"retention_action must be one of {RETENTION_ACTIONS}, got {v!r}")
        return action

    @field_validator("auto_resolve_stale_days")
    @classmethod
    def valid_auto_resolve_days(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            days = int(v.strip())
        except ValueError:
            raise ValueError(f"auto_resolve_stale_days must be an integer, got {v!r}")
        lo, hi = AUTO_RESOLVE_STALE_DAY_BOUNDS
        if days < lo or days > hi:
            raise ValueError(f"auto_resolve_stale_days must be {lo}–{hi}, got {days}")
        return str(days)

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

def make_settings_router(intel_db, store=None, db=None) -> APIRouter:
    """store (TelemetryStore) and db (manager Database) are optional — only
    needed for GET /retention's live size stats. Settings CRUD works without
    them; the retention endpoint degrades to config-only if omitted."""
    router = APIRouter()

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _load() -> dict[str, str]:
        """Load all settings from DB merged with defaults."""
        rows = await intel_db._fetchall(
            "SELECT key, value FROM org_settings ORDER BY key", ()
        )
        return {**ALL_DEFAULTS, **{r["key"]: r["value"] for r in rows}}

    async def _write(key: str, value: str, actor: str, ip: str) -> None:
        """Write a single key and append an audit row inside the caller's transaction."""
        ts = time.time()
        old_row = await intel_db._fetchone(
            "SELECT value FROM org_settings WHERE key=?", (key,)
        )
        old_val = old_row["value"] if old_row else ALL_DEFAULTS.get(key, "")

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

    # ── GET /retention ────────────────────────────────────────────────────────
    @router.get("/retention")
    async def get_retention():
        """Current data-retention config + live size stats for the dashboard.

        config.period_months / .action come straight from org_settings (same
        store as every other setting — no new table). period_months is a
        legacy field name: 0/7/15 are day presets, 1+ values are month presets.
        stats are computed live:
        - live_payloads: row count + estimated bytes in manager.db's `payloads`
          table — the table Deep Analysis (/api/v1/raw/*) actually queries.
        - archive: only meaningful when action="archive" — size/location/file
          count of the cold tier, which becomes the permanent archive once its
          pruning is skipped (see store.py TelemetryStore.cleanup/archive_stats).
        """
        try:
            raw = await _load()
            period_raw = raw.get("retention_period_months", "0")
            months = retention_period_code(period_raw)
            action = retention_action_value(raw.get("retention_action", "delete"))
            auto_resolve_days = auto_resolve_stale_days_value(
                raw.get("auto_resolve_stale_days", str(AUTO_RESOLVE_STALE_DAY_DEFAULT))
            )
            config = {
                "period_months": months,
                "period_days":   retention_period_days(period_raw),
                "action":        action,
                "slow_fetch_warning": months in RETENTION_SLOW_FETCH_MONTHS,
                "auto_resolve_stale_days": auto_resolve_days,
                "available_periods": list(RETENTION_PERIODS_MONTHS),
                "available_actions": list(RETENTION_ACTIONS),
            }

            stats: dict[str, Any] = {"live_payloads": None, "archive": None, "postgres": None}
            if db is not None:
                try:
                    async with db._pool.read() as conn:
                        # Single query: payload counts + Postgres-native table/DB sizes
                        async with conn.execute(
                            "SELECT COUNT(*) AS row_count,"
                            "       SUM(octet_length(data)) AS approx_bytes,"
                            "       pg_total_relation_size('payloads') AS table_bytes,"
                            "       pg_database_size(current_database()) AS db_bytes"
                            " FROM payloads"
                        ) as cur:
                            row = await cur.fetchone()
                    if row:
                        stats["live_payloads"] = {
                            "row_count":    int(row["row_count"] or 0),
                            "approx_bytes": int(row["approx_bytes"] or 0),
                            "table_bytes":  int(row["table_bytes"] or 0),
                        }
                        stats["postgres"] = {
                            "db_bytes": int(row["db_bytes"] or 0),
                        }
                except Exception as exc:
                    log.debug("retention live_payloads stats failed: %s", exc)
            if store is not None and action == "archive":
                try:
                    stats["archive"] = await store.archive_stats()
                except Exception as exc:
                    log.debug("retention archive_stats failed: %s", exc)

            return {"config": config, "stats": stats}
        except Exception as exc:
            log.exception("get_retention failed")
            raise HTTPException(500, f"Failed to load retention settings: {exc}")

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
                for key, value in ALL_DEFAULTS.items():
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
                "settings": _redact(ALL_DEFAULTS),
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
        Sensitive fields (license_key etc.) are masked in the export.
        Treat the output as confidential.
        """
        try:
            raw = await _load()
            safe = {k: (_mask(v) if k in MASKED_FIELDS else v) for k, v in raw.items()}
            return {
                "export_version": "1",
                "exported_at":    time.time(),
                "settings":       safe,
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

        valid_keys = set(ALL_DEFAULTS.keys())
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

    # ── GET /validation ──────────────────────────────────────────────────────
    @router.get("/validation")
    async def get_validation_settings():
        """
        Return the AI Precision Validator thresholds — global, per-terrain,
        per-agent — together with the agent list (so the UI can render an
        agent picker without a second round-trip) and the terrain catalogue.
        """
        try:
            raw = await _load()

            global_thr = float(raw.get("validation_global_threshold")
                                or VALIDATION_DEFAULTS["validation_global_threshold"])
            try:
                terrain_thr = json.loads(raw.get("validation_terrain_thresholds") or "{}")
            except json.JSONDecodeError:
                terrain_thr = {}
            try:
                agent_thr = json.loads(raw.get("validation_agent_thresholds") or "{}")
            except json.JSONDecodeError:
                agent_thr = {}
            try:
                agent_priorities = normalize_agent_priorities(
                    raw.get("validation_agent_priorities") or "{}"
                )
            except ValueError:
                agent_priorities = {}

            use_ai = (raw.get("validation_use_ai_verdict")
                      or VALIDATION_DEFAULTS["validation_use_ai_verdict"]).lower() == "true"
            min_strength = float(raw.get("validation_min_strength")
                                 or VALIDATION_DEFAULTS["validation_min_strength"])

            # Best-effort agent enumeration for the picker. Uses asset_registry
            # (preferred — has OS/hostname) and falls back to nothing if missing.
            agents: list[dict] = []
            try:
                rows = await intel_db._fetchall(
                    "SELECT agent_id, hostname, os, asset_tier "
                    "FROM asset_registry "
                    "ORDER BY (CASE asset_tier "
                    "  WHEN 'crown_jewel' THEN 0 "
                    "  WHEN 'server' THEN 1 "
                    "  WHEN 'workstation' THEN 2 "
                    "  WHEN 'endpoint' THEN 3 "
                    "  ELSE 4 END), hostname",
                    (),
                )
                for r in rows:
                    aid = r["agent_id"]
                    agents.append({
                        "agent_id":   aid,
                        "hostname":   r["hostname"] or aid,
                        "os":         r["os"] or "",
                        "asset_tier": r["asset_tier"] or "endpoint",
                        "threshold":  float(agent_thr.get(aid)) if aid in agent_thr else None,
                        "priority":   agent_priorities.get(aid, "standard"),
                    })
            except Exception as exc:
                log.debug("agent enumeration failed: %s", exc)

            return {
                "global_threshold":    _clamp_threshold(global_thr),
                "terrain_thresholds":  {
                    t: float(terrain_thr.get(t)) for t in VALIDATION_TERRAINS
                    if t in terrain_thr
                },
                "agent_thresholds":    {k: float(v) for k, v in agent_thr.items()},
                "agent_priorities":    agent_priorities,
                "use_ai_verdict":      use_ai,
                "min_strength":        max(0.0, min(1.0, min_strength)),
                "priority_levels":      list(ASSET_PRIORITY_LEVELS),
                "priority_options":     priority_options(),
                "terrains":            [
                    {
                        "id":          t,
                        "label":       VALIDATION_TERRAIN_LABELS[t],
                        "categories":  VALIDATION_TERRAIN_CATEGORIES[t],
                        "threshold":   float(terrain_thr.get(t)) if t in terrain_thr else None,
                    }
                    for t in VALIDATION_TERRAINS
                ],
                "agents":              agents,
                "bounds":              {"min": VALIDATION_THRESHOLD_BOUNDS[0],
                                         "max": VALIDATION_THRESHOLD_BOUNDS[1]},
            }
        except Exception as exc:
            log.exception("get_validation_settings failed")
            raise HTTPException(500, f"Failed to load validation settings: {exc}")

    # ── PUT /validation ──────────────────────────────────────────────────────
    @router.put("/validation")
    async def update_validation_settings(body: ValidationUpdate, request: Request):
        """
        Persist per-key updates.  Only fields supplied in the body are written;
        omitted keys keep their current value.  Every change is journalled in
        settings_audit just like every other setting.
        """
        actor, ip = _actor_ip(request)
        payload = body.model_dump(exclude_unset=True)
        if not payload:
            raise HTTPException(400, "No fields provided — nothing to update")

        updates: dict[str, str] = {}
        if "global_threshold" in payload:
            updates["validation_global_threshold"] = str(_clamp_threshold(payload["global_threshold"]))
        if "terrain_thresholds" in payload:
            # Drop empty / None entries so the JSON stays compact.
            tt = {k: float(v) for k, v in (payload["terrain_thresholds"] or {}).items() if v is not None}
            updates["validation_terrain_thresholds"] = json.dumps(tt, sort_keys=True)
        if "agent_thresholds" in payload:
            at = {k: float(v) for k, v in (payload["agent_thresholds"] or {}).items() if v is not None}
            updates["validation_agent_thresholds"] = json.dumps(at, sort_keys=True)
        if "agent_priorities" in payload:
            ap = normalize_agent_priorities(payload["agent_priorities"] or {})
            updates["validation_agent_priorities"] = json.dumps(ap, sort_keys=True)
        if "use_ai_verdict" in payload:
            updates["validation_use_ai_verdict"] = "true" if payload["use_ai_verdict"] else "false"
        if "min_strength" in payload:
            updates["validation_min_strength"] = f"{max(0.0, min(1.0, float(payload['min_strength']))):.3f}"

        try:
            async with intel_db._lock:
                for key, value in updates.items():
                    await _write(key, value, actor, ip)
                await intel_db._conn.commit()
        except Exception as exc:
            log.exception("update_validation_settings failed")
            raise HTTPException(500, f"Failed to save validation settings: {exc}")

        # Tell the engine to pick up the new thresholds on the next cluster
        # without waiting for the 30s TTL.
        try:
            from ..attacklens.ai_validator import invalidate_validation_settings_cache
            invalidate_validation_settings_cache()
        except Exception:
            pass

        # When the analyst changes a validation knob, historical findings
        # still carry their old precision_score.  Run the rescore INLINE so
        # the immediately-following GET reflects the new configuration —
        # background scheduling left the UI stale for the analyst's first
        # refresh and caused "I configured it but nothing shows up" reports.
        rescore_report = None
        if "global_threshold" in payload or "terrain_thresholds" in payload \
                or "agent_thresholds" in payload or "agent_priorities" in payload:
            try:
                rescore_report = await intel_db.recompute_terrain_validation_all()
            except Exception as exc:
                log.warning("inline recompute on settings change failed: %s", exc)

        # Return the fresh canonical shape via the same loader as GET.
        result = await get_validation_settings()
        if rescore_report is not None:
            result["rescore"] = rescore_report
        return result

    # ── POST /validation/recompute ───────────────────────────────────────────
    @router.post("/validation/recompute")
    async def recompute_validation(
        only_unscored: bool = Query(
            False,
            description="If true, only re-evaluate findings whose precision_score is 0. "
                        "Faster but won't fix already-rescored findings whose criteria changed.",
        ),
        limit: int = Query(5000, ge=1, le=100000),
    ):
        """
        Manually trigger a full retro-rescore of every active finding against
        the current terrain validators.  Use this after upgrading the manager,
        after changing the criteria catalogue, or whenever Validated Findings
        unexpectedly shows fewer results than the active-findings count.

        Returns a histogram of how many findings landed in each score band so
        the analyst can immediately tell whether to relax the threshold.
        """
        try:
            result = await intel_db.recompute_terrain_validation_all(
                only_unscored=only_unscored, limit=limit,
            )
            return {"status": "ok", **result}
        except Exception as exc:
            log.exception("recompute_validation failed")
            raise HTTPException(500, f"Recompute failed: {exc}")

    # ── GET /validation/status ────────────────────────────────────────────────
    @router.get("/validation/status")
    async def validation_status(request: Request):
        """
        Runtime status of the AI Precision Validator and the threat-intel
        feeds it depends on. The Validated Findings UI calls this to decide
        whether to show the panel as 'active', 'partial', or 'disabled' —
        instead of misleading the analyst with a 0% rejection state when the
        validator never actually ran.

        Reports:
          • pipeline_enabled    — ATTACKLENS_VALIDATION env / ENGINE_CONFIG
          • ai_validation_on    — ATTACKLENS_AI_VALIDATION + Settings toggle
          • ai_analyst_ready    — Anthropic API key present + client built
          • kev_status          — last-loaded count + freshness from CISA KEV
          • threshold_summary   — global + override counts
          • last_error          — most recent validator failure (if any)
        """
        import os as _os
        try:
            from ..attacklens.config       import ENGINE_CONFIG as _CFG
            from ..attacklens.ai_validator import _load_validation_settings
        except Exception:
            _CFG = {}

        pipeline_on = bool(_CFG.get("validation_pipeline_enabled", False))
        ai_on_env   = (_os.getenv("ATTACKLENS_AI_VALIDATION", "").strip().lower()
                       in ("true","1","yes","on"))

        # Read the settings-level master switch
        ai_on_settings = True
        try:
            v = await _load_validation_settings(intel_db)
            ai_on_settings = bool(v.get("use_ai", True))
        except Exception:
            pass
        ai_validation_on = (ai_on_env or _CFG.get("ai_validation_enabled", False)) and ai_on_settings

        # AI analyst readiness — check the app-state instance
        analyst = getattr(request.app.state, "ai_analyst", None)
        ai_analyst_ready = bool(analyst and getattr(analyst, "enabled", False))

        # KEV feed status — pulled from FeedManager + DB
        kev_status = {"loaded": 0, "last_refresh_ts": None, "freshness_hours": None, "source": "CISA KEV"}
        try:
            feeds = getattr(request.app.state, "feeds", None)
            if feeds is not None and hasattr(feeds, "get_stats"):
                stats = feeds.get_stats()
                kev_status["loaded"] = int(stats.get("kev_cves") or 0)
            # Most-recent CISA KEV upsert in DB (so we know when it was last refreshed)
            row = await intel_db._fetchone(
                "SELECT MAX(cached_at) AS last_ts FROM cisa_kev", (),
            )
            if row and row["last_ts"]:
                last = float(row["last_ts"])
                kev_status["last_refresh_ts"] = last
                kev_status["freshness_hours"] = round((time.time() - last) / 3600, 2)
        except Exception as exc:
            log.debug("kev_status probe error: %s", exc)
            kev_status["error"] = str(exc)[:160]

        # Threshold summary
        global_thr   = 0.90
        terrain_n    = 0
        agent_n      = 0
        priority_n   = 0
        try:
            raw = await _load()
            global_thr = float(raw.get("validation_global_threshold")
                               or VALIDATION_DEFAULTS["validation_global_threshold"])
            try:
                terrain_n = len(json.loads(raw.get("validation_terrain_thresholds") or "{}"))
            except Exception:
                terrain_n = 0
            try:
                agent_n = len(json.loads(raw.get("validation_agent_thresholds") or "{}"))
            except Exception:
                agent_n = 0
            try:
                priority_n = len(normalize_agent_priorities(
                    raw.get("validation_agent_priorities") or "{}"
                ))
            except Exception:
                priority_n = 0
        except Exception:
            pass

        # Last validator error (logged via SOC activity if we ever wire it)
        last_error: Optional[str] = None
        try:
            row = await intel_db._fetchone(
                "SELECT detail FROM signal_clusters "
                "WHERE status LIKE 'ai_precision:%' AND detail IS NOT NULL "
                "ORDER BY created_at DESC LIMIT 1", (),
            )
            if row and row["detail"]:
                last_error = str(row["detail"])[:240]
        except Exception:
            pass

        # Compute a single banner status the UI can render directly.
        if not pipeline_on:
            banner_status = "disabled"
            banner_msg    = "Validation pipeline is OFF. Set ATTACKLENS_VALIDATION=true and restart."
        elif not ai_validation_on:
            banner_status = "deterministic_only"
            banner_msg    = "AI verdict step is OFF — findings use deterministic factors only."
        elif not ai_analyst_ready:
            banner_status = "degraded"
            banner_msg    = "LLM verdict configured ON but ANTHROPIC_API_KEY missing — degrading to deterministic."
        elif kev_status["loaded"] == 0:
            banner_status = "warning"
            banner_msg    = "CISA KEV feed has not loaded yet — KEV multiplier and gate G4 unavailable."
        else:
            banner_status = "active"
            banner_msg    = f"Active. {kev_status['loaded']} KEV CVEs loaded."

        return {
            "pipeline_enabled":  pipeline_on,
            "ai_validation_on":  ai_validation_on,
            "ai_analyst_ready":  ai_analyst_ready,
            "ai_settings_on":    ai_on_settings,
            "kev_status":        kev_status,
            "thresholds": {
                "global":  global_thr,
                "terrain_overrides": terrain_n,
                "agent_overrides":   agent_n,
                "priority_overrides": priority_n,
            },
            "last_rejection_reason": last_error,
            "banner": {"status": banner_status, "message": banner_msg},
        }

    return router
