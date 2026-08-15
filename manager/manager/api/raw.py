"""
manager/api/raw.py — Deep Analysis (raw telemetry explorer) endpoints.

GET /api/v1/raw/agents     — list all known agents with live status
GET /api/v1/raw/sections   — distinct payload sections (optionally by agent)
GET /api/v1/raw/query      — paginated payload query with all filter combinations
GET /api/v1/raw/count      — total row count for current filter (pagination support)

Search algorithm:
  - Time + agent + section: covered index scan on idx_payloads_agent_section_ts
  - Free-text search: LIKE '%term%' scan within the already-filtered result set
  - Count query reuses same WHERE clause to avoid double full-scan
  All queries are bounded by LIMIT/OFFSET so no result set is unbounded.
"""
from __future__ import annotations

import asyncio
import time
import logging
from typing import Optional, TYPE_CHECKING

from fastapi import APIRouter, Query
from shared.sections import VALID_SECTION_NAMES
# Single source of truth for the Deep Mesh capability → record-key map. Defined
# in shared/schema.py so the composite validator (validate_section) and the
# counts computed here can never drift. Imported under the original local name
# to keep the counting helpers below unchanged.
from shared.schema import DEVSEC_CAPABILITY_ITEMS as _DEVSEC_CAP_ITEMS

if TYPE_CHECKING:
    from ..db import Database

from manager.manager.timewindow import resolve_window as _shared_resolve, WindowError

log = logging.getLogger("manager.api.raw")


def make_raw_router(db: "Database") -> APIRouter:
    router = APIRouter()

    @router.get("/agents")
    async def list_agents():
        """All enrolled agents with last-seen timestamp and online status."""
        agents = await db.get_all_agents()
        now = int(time.time())
        result = []
        for a in agents:
            last_seen = int(a.get("last_seen") or 0)
            elapsed = now - last_seen
            if elapsed < 60:
                status = "online"
            elif elapsed < 300:
                status = "stale"
            else:
                status = "offline"
            result.append({
                "agent_id":  a["agent_id"],
                "name":      a.get("name") or a["agent_id"],
                "last_seen": last_seen,
                "last_ip":   a.get("last_ip", ""),
                "status":    status,
                "elapsed_s": elapsed,
            })
        return result

    @router.get("/sections")
    async def list_sections(agent_id: Optional[str] = Query(None)):
        """Distinct telemetry sections, optionally scoped to one agent."""
        sections = await db.get_distinct_sections(agent_id)
        return {"sections": sections}

    @router.get("/count")
    async def count_payloads(
        agent_id: Optional[str] = Query(None),
        section:  Optional[str] = Query(None),
        window:   Optional[str] = Query(None, description="5m|1h|6h|24h|7d"),
        start:    Optional[int] = Query(None, description="Unix timestamp"),
        end:      Optional[int] = Query(None, description="Unix timestamp"),
        search:   Optional[str] = Query(None, max_length=256),
    ):
        """Row count matching the current filter set (for pagination UI)."""
        now = int(time.time())
        resolved_start, resolved_end = _resolve_window(window, start, end, now)
        # Use an efficient COUNT(*) query rather than loading all rows.
        count = await db.count_payloads(
            agent_id=agent_id,
            section=section,
            start=resolved_start,
            end=resolved_end,
            search=search,
        )
        return {"count": count}

    @router.get("/query")
    async def query_payloads(
        agent_id: Optional[str] = Query(None),
        section:  Optional[str] = Query(None),
        window:   Optional[str] = Query(None, description="5m|1h|6h|24h|7d"),
        start:    Optional[int] = Query(None, description="Unix timestamp"),
        end:      Optional[int] = Query(None, description="Unix timestamp"),
        search:   Optional[str] = Query(None, max_length=256),
        limit:    int = Query(200, ge=1, le=1000),
        offset:   int = Query(0, ge=0),
        include_data: bool = Query(True, description="Set false for a lightweight "
                                   "metadata-only list (omits the full payload)"),
    ):
        """
        Paginated raw payload query.

        Returns rows ordered by collected_at DESC.
        Each row contains metadata + a compact preview + summary; the full payload
        JSON is included only when `include_data=true` (the default). Pass
        `include_data=false` to build a cheap timeline/list — some sections (e.g.
        developer_security) ship ~300 KB snapshots, so loading N of them just to
        show timestamps is wasteful. Fetch the full payload per row on demand via
        GET /raw/record?id=.

        Filter combinations:
          - No filters        → most recent N rows across all agents/sections
          - agent_id only     → all sections for that agent
          - agent_id+section  → section-specific data for that agent
          - window            → resolves to (start, end) timestamp range
          - search            → substring match against payload JSON
        """
        now = int(time.time())
        resolved_start, resolved_end = _resolve_window(window, start, end, now)

        rows = await db.query_payloads(
            agent_id=agent_id,
            section=section,
            start=resolved_start,
            end=resolved_end,
            search=search,
            limit=limit,
            offset=offset,
        )

        # Enrich each row with a section-aware preview + summary. The preview and
        # summary are always computed server-side (cheap), so a metadata-only list
        # still shows meaningful content without shipping the payload.
        result = []
        for r in rows:
            data = r.get("data", {})
            row = {
                "id":           r["id"],
                "agent_id":     r["agent_id"],
                "section":      r["section"],
                "collected_at": r["collected_at"],
                "received_at":  r["received_at"],
                "record_count": _record_count(data, r["section"]),
                "preview":      _data_preview(data, r["section"]),
                "summary":      _section_summary(data, r["section"]),
            }
            if include_data:
                row["data"] = data
            result.append(row)

        return {
            "rows":    result,
            "limit":   limit,
            "offset":  offset,
            "included_data": include_data,
            "filters": {
                "agent_id": agent_id,
                "section":  section,
                "start":    resolved_start,
                "end":      resolved_end,
                "search":   search,
            },
        }

    @router.get("/record")
    async def get_record(id: int = Query(..., ge=1, description="payload row id")):
        """Fetch ONE full payload by id — used to lazy-load a row's data after a
        metadata-only list (include_data=false), so large snapshots are fetched
        only when a row is actually expanded."""
        row = await db.get_payload_by_id(id)
        if row is None:
            return {"found": False, "id": id}
        data = row.get("data", {})
        return {
            "found":        True,
            "id":           row["id"],
            "agent_id":     row["agent_id"],
            "section":      row["section"],
            "collected_at": row["collected_at"],
            "received_at":  row["received_at"],
            "record_count": _record_count(data, row["section"]),
            "summary":      _section_summary(data, row["section"]),
            "data":         data,
        }

    # ── First-layer data checkpoint ─────────────────────────────────────────
    # Every section a macOS agent is expected to report, and whether it feeds
    # executable detection logic (inline analyzers, rich modules, or rule-pack
    # evaluators). Battery is kept non-feeding until its rule-pack conditions
    # have the required historical/CMDB inputs.
    _EXPECTED_SECTIONS: dict[str, bool] = {
        section: True for section in VALID_SECTION_NAMES
    }

    def _has_real_data(data) -> bool:
        """True only if the section's latest payload carries actual telemetry —
        not empty and not a collector-error ({"error": ...}) payload."""
        if not data:
            return False
        if isinstance(data, dict):
            if set(data.keys()) == {"error"}:
                return False
            return any(v not in (None, "", [], {}) for v in data.values())
        if isinstance(data, (list, tuple)):
            return len(data) > 0
        return False

    @router.get("/coverage")
    async def coverage(
        agent_id:  Optional[str] = Query(None, description="Agent to check; default = most recently active"),
        stale_sec: int           = Query(7200, ge=1, description="A section older than this is 'stale'"),
    ):
        """First-layer checkpoint: for ONE agent, verify every expected section is
        PRESENT, FRESH, and carrying REAL data (not empty / not an {error}
        payload). `ok` is True only when every detection-feeding section passes —
        i.e. the agent is actually delivering the data the 14 detection modules
        need. Per-section `status` ∈ ok | stale | empty | missing pinpoints gaps.
        """
        if not agent_id:
            agents = await db.get_all_agents()
            if not agents:
                return {"ok": False, "error": "no agents have reported yet",
                        "agent_id": None, "sections": []}
            agent_id = agents[0]["agent_id"]    # ordered by last_seen DESC

        last_times = await db.get_section_last_times(agent_id)
        now = int(time.time())

        # Each present section needs a latest-row lookup to confirm it carries
        # real data (not empty / not an {error} payload). Probe those rows
        # concurrently instead of serially: an agent reporting all sections
        # otherwise costs one DB round-trip per section, turning this operator
        # checkpoint into ~N sequential hops. Bounded by a semaphore so a burst
        # never monopolises the read pool (max_size=10) against live requests.
        present_sections = [
            sec for sec in _EXPECTED_SECTIONS if last_times.get(sec) is not None
        ]
        _probe_sema = asyncio.Semaphore(8)

        async def _probe(sec: str):
            """Latest-row real-data check for one section; never raises.
            Returns True/False, or None when the lookup itself failed (unknown —
            treated as non-blocking so a transient read error never flips a
            fresh section to 'empty')."""
            async with _probe_sema:
                try:
                    rows = await db.query_section(agent_id, sec, limit=1)
                    return _has_real_data(rows[0]["data"]) if rows else False
                except Exception:
                    return None

        probe_results = await asyncio.gather(
            *(_probe(sec) for sec in present_sections)
        )
        has_data_by_section = dict(zip(present_sections, probe_results))

        sections, missing, stale, empty = [], [], [], []
        for sec, feeds in sorted(_EXPECTED_SECTIONS.items()):
            last    = last_times.get(sec)
            present = last is not None
            age     = (now - int(last)) if present else None
            has_data = has_data_by_section.get(sec) if present else None
            status   = "missing"
            if present:
                fresh = age is not None and age <= stale_sec
                if not fresh:
                    status = "stale"
                elif has_data is False:
                    status = "empty"
                else:
                    status = "ok"
            if status == "missing":
                missing.append(sec)
            elif status == "stale":
                stale.append(sec)
            elif status == "empty":
                empty.append(sec)
            sections.append({
                "section": sec, "feeds_detection": feeds, "present": present,
                "last_collected_at": last, "age_sec": age,
                "has_real_data": has_data, "status": status,
            })

        det_ok = all(s["status"] == "ok" for s in sections if s["feeds_detection"])
        return {
            "agent_id":       agent_id,
            "checked_at":     now,
            "stale_sec":      stale_sec,
            "ok":             det_ok,                 # all detection-feeding sections good
            "detection_ready": det_ok,
            "expected":       len(_EXPECTED_SECTIONS),
            "present":        sum(1 for s in sections if s["present"]),
            "missing":        missing,
            "stale":          stale,
            "empty":          empty,
            "sections":       sections,
        }

    return router


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_window(
    window: Optional[str],
    start:  Optional[int],
    end:    Optional[int],
    now:    int,
) -> tuple[int, int]:
    """Delegate to shared resolver; preserve lenient behavior for internal raw browser."""
    try:
        return _shared_resolve(window, start, end, now=now)
    except WindowError:
        # Raw endpoints are internal; fall back gracefully instead of 422.
        return (start or 0), (end or now)


# _DEVSEC_CAP_ITEMS (capability → record-key map) is imported at the top of this
# module from shared/schema.py — the single source of truth also used by the
# developer_security composite validator in validate_section().

# Short subset (with friendly labels) used for the compact list-row preview text.
_DEVSEC_PREVIEW: tuple[tuple[str, str], ...] = (
    ("editor_extensions", "ext"), ("mcp_servers", "mcp"),
    ("browser_extensions", "browser"), ("agent_cli_tools", "cli"),
    ("listening_ports", "listen"), ("native_messaging", "native"),
)


def _devsec_counts(caps: dict) -> dict[str, int]:
    """Record count per capability, keyed by capability name (all 17)."""
    counts: dict[str, int] = {}
    for cap_key, items_key in _DEVSEC_CAP_ITEMS.items():
        cap = caps.get(cap_key)
        if not isinstance(cap, dict):
            counts[cap_key] = 0
            continue
        if cap_key == "homebrew":
            counts[cap_key] = len(cap.get("formulae") or []) + len(cap.get("casks") or [])
        elif isinstance(cap.get("count"), int):
            counts[cap_key] = cap["count"]
        elif items_key and isinstance(cap.get(items_key), list):
            counts[cap_key] = len(cap[items_key])
        else:
            counts[cap_key] = 0
    return counts


def _devsec_summary(data: dict) -> Optional[dict]:
    """Compact capability counts + collection health for a developer_security
    snapshot, computed server-side so a metadata-only list row is still
    meaningful without shipping the ~300 KB payload."""
    caps = data.get("capabilities")
    if not isinstance(caps, dict):
        return None
    collection = data.get("collection") if isinstance(data.get("collection"), dict) else {}
    return {
        "counts":     _devsec_counts(caps),
        "capabilities_present": sum(1 for c in caps.values() if isinstance(c, dict) and "error" not in c),
        "partial":    bool(collection.get("partial")),
        "state":      collection.get("state") or ("partial" if collection.get("partial") else "complete"),
        "collector_version": data.get("collector_version"),
        "error_count": len(collection.get("errors", []) or []),
        "duration_ms": collection.get("duration_ms"),
    }


def _section_summary(data: object, section: str) -> Optional[dict]:
    """Section-aware structured summary for list rows (currently developer_security)."""
    if section == "developer_security" and isinstance(data, dict):
        return _devsec_summary(data)
    return None


def _record_count(data: object, section: str = "") -> int:
    """Number of records in this payload — list = len(list), dict = 1.

    For developer_security the top-level is a dict with no single record list, so
    count the total records across its capability lists instead of returning 1.
    """
    if section == "developer_security" and isinstance(data, dict):
        summary = _devsec_summary(data)
        if summary:
            return sum(summary["counts"].values())
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        # Some sections wrap a list under a key
        for v in data.values():
            if isinstance(v, list):
                return len(v)
        return 1
    return 0


def _data_preview(data: object, section: str = "", max_chars: int = 140) -> str:
    """Short human-readable preview of payload data.

    Dict-shaped nested sections (developer_security) get a purpose-built preview
    of capability counts + collection health — the generic "first 4 keys" preview
    would only show schema_version/platform/scope, which is useless in a list.
    """
    if section == "developer_security" and isinstance(data, dict):
        summary = _devsec_summary(data)
        if summary:
            counts = summary["counts"]
            parts = [f"{label}={counts[key]}" for key, label in _DEVSEC_PREVIEW if key in counts]
            if summary["partial"]:
                parts.append(f"partial({summary['error_count']} err)")
            preview = "  ·  ".join(parts)
            return preview[:max_chars] + ("…" if len(preview) > max_chars else "")

    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            # Show key=value pairs from first record
            parts = [f"{k}={v}" for k, v in list(first.items())[:4]]
            preview = "  ·  ".join(str(p) for p in parts)
        else:
            preview = str(first)
    elif isinstance(data, dict):
        parts = [f"{k}={v}" for k, v in list(data.items())[:4]]
        preview = "  ·  ".join(str(p) for p in parts)
    else:
        preview = str(data)
    return preview[:max_chars] + ("…" if len(preview) > max_chars else "")
