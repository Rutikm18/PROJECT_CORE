"""reports.py — server-side report assembly + streaming export endpoint.

Mirrors the client-side column set in the dashboard's `reportData.ts` so the
Phase A (browser) and Phase B (server) exports produce the identical workbook:
Summary, Incidents, Timeline, Deep Analysis, DeepMesh.

The pure row-assembly helpers below take plain dicts and have no I/O, so they
are unit-tested directly. `make_reports_router` wires them to the intel DB and
raw store and streams the file.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

# ── Column catalogs (key, header) — keys identical to reportData.ts ──────────
INCIDENT_COLUMNS: list[tuple[str, str]] = [
    ("finding_id", "Finding ID"), ("finding_uid", "Finding UID"), ("external_id", "External ID"),
    ("asset_agent_id", "Agent ID"), ("asset_hostname", "Hostname"),
    ("first_detected_at", "First Detected"), ("last_detected_at", "Last Detected"),
    ("incident_title", "Incident"), ("category", "Category"), ("terrain", "Terrain"),
    ("severity", "Severity"), ("status", "Status"), ("description", "Description"),
    ("business_impact", "Business Impact"), ("confidence_pct", "Confidence %"),
    ("validation_score_pct", "Validation Score %"), ("source", "Source"), ("rule_id", "Rule ID"),
    ("mitre_tactic", "MITRE Tactic"), ("mitre_technique", "MITRE Technique"),
    ("cve_ids", "CVE IDs"), ("cvss_score", "CVSS"), ("kev", "KEV"),
    ("exploit_available", "Exploit Available"), ("ai_verdict", "AI Verdict"),
    ("ai_confidence_pct", "AI Confidence %"), ("ai_reasoning", "AI Reasoning"),
    ("remediation", "Remediation"), ("actions_performed", "Actions"),
    ("scan_count", "Scan Count"), ("evidence", "Evidence (JSON)"),
]
TIMELINE_COLUMNS: list[tuple[str, str]] = [
    ("finding_id", "Finding ID"), ("finding_uid", "Finding UID"), ("incident_title", "Incident"),
    ("severity", "Severity"), ("terrain", "Terrain"), ("event_time", "Event Time"),
    ("elapsed", "Elapsed"), ("source", "Source"), ("actor", "Actor"), ("action", "Action"),
    ("from_status", "From Status"), ("to_status", "To Status"), ("note", "Note"),
    ("changed_fields", "Changed Fields"), ("metadata", "Metadata"),
]
TELEMETRY_COLUMNS: list[tuple[str, str]] = [
    ("timestamp", "Timestamp"), ("agent_id", "Agent ID"), ("agent_name", "Agent Name"),
    ("section", "Section"), ("record_count", "Records"), ("ingest_lag_s", "Ingest Lag (s)"),
    ("data", "Data (JSON)"),
]
SUMMARY_COLUMNS: list[tuple[str, str]] = [("field", "Field"), ("value", "Value")]


def _iso(v) -> str:
    if v in (None, ""):
        return ""
    try:
        n = float(v)
        if n > 1_000_000_000:
            return datetime.fromtimestamp(n, tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        pass
    return str(v)


def _yesno(b) -> str:
    return "Yes" if b else "No"


def _join(v, sep: str = "; ") -> str:
    if isinstance(v, list):
        return sep.join(json.dumps(x) if isinstance(x, (dict, list)) else str(x) for x in v)
    return "" if v is None else str(v)


def _maybe_json(v):
    """Raw DB rows store evidence/ai_verdict/action_plan as JSON *strings*; the
    enriched /detection/all response returns them parsed. Accept either so the
    backend export matches the client export field-for-field."""
    if isinstance(v, str) and v and v[0] in "[{":
        try:
            return json.loads(v)
        except (ValueError, TypeError):
            return v
    return v


def incident_row(f: dict) -> dict:
    f = {**f,
         "evidence": _maybe_json(f.get("evidence")),
         "ai_verdict": _maybe_json(f.get("ai_verdict")),
         "action_plan": _maybe_json(f.get("action_plan")),
         "available_actions": _maybe_json(f.get("available_actions")),
         "cve_ids": _maybe_json(f.get("cve_ids"))}
    ai = f.get("ai_verdict") or {}
    if not isinstance(ai, dict):
        ai = {}
    ps = f.get("precision_score")
    conf = ai.get("confidence")
    return {
        "finding_id": f.get("id"),
        "finding_uid": f.get("finding_uid", ""),
        "external_id": f.get("external_id", ""),
        "asset_agent_id": f.get("agent_id", ""),
        "asset_hostname": f.get("agent_hostname", ""),
        "first_detected_at": _iso(f.get("first_detected_at")),
        "last_detected_at": _iso(f.get("last_detected_at")),
        "incident_title": f.get("title", ""),
        "category": f.get("category", ""),
        "terrain": f.get("terrain", ""),
        "severity": f.get("severity", ""),
        "status": f.get("status", ""),
        "description": f.get("description", ""),
        "business_impact": f.get("impact", ""),
        "confidence_pct": f.get("confidence_pct", ""),
        "validation_score_pct": round(ps * 100) if isinstance(ps, (int, float)) else "",
        "source": f.get("source", ""),
        "rule_id": f.get("rule_id", ""),
        "mitre_tactic": f.get("mitre_tactic", ""),
        "mitre_technique": f.get("mitre_technique", ""),
        "cve_ids": _join(f.get("cve_ids"), ", "),
        "cvss_score": f.get("cvss_score", ""),
        "kev": _yesno(f.get("kev")),
        "exploit_available": _yesno(f.get("exploit_available")),
        "ai_verdict": ai.get("label", ""),
        "ai_confidence_pct": round(conf * 100) if isinstance(conf, (int, float)) else "",
        "ai_reasoning": ai.get("reasoning", ""),
        "remediation": _join(f.get("action_plan")),
        "actions_performed": _join(f.get("available_actions")),
        "scan_count": f.get("scan_count", ""),
        "evidence": json.dumps(f.get("evidence")) if f.get("evidence") else "",
    }


def timeline_row(ev: dict, f: dict) -> dict:
    return {
        "finding_id": f.get("id"),
        "finding_uid": f.get("finding_uid") or ev.get("finding_uid", ""),
        "incident_title": f.get("title", ""),
        "severity": f.get("severity", ""),
        "terrain": f.get("terrain", ""),
        "event_time": _iso(ev.get("created_at")),
        "elapsed": ev.get("elapsed", ""),
        "source": ev.get("source", ""),
        "actor": ev.get("actor", ""),
        "action": ev.get("action", ""),
        "from_status": ev.get("from_status", ""),
        "to_status": ev.get("to_status", ""),
        "note": ev.get("note", ""),
        "changed_fields": json.dumps(ev.get("changed_fields")) if ev.get("changed_fields") else "",
        "metadata": json.dumps(ev.get("metadata")) if ev.get("metadata") else "",
    }


def telemetry_row(r: dict, agent_name: dict | None = None) -> dict:
    names = agent_name or {}
    collected = float(r.get("collected_at") or 0)
    received = float(r.get("received_at") or 0)
    aid = r.get("agent_id", "")
    return {
        "timestamp": _iso(r.get("collected_at")),
        "agent_id": aid,
        "agent_name": names.get(aid, aid),
        "section": r.get("section", ""),
        "record_count": r.get("record_count", ""),
        "ingest_lag_s": max(0, round(received - collected)) if received and collected else "",
        "data": json.dumps(r.get("data")) if r.get("data") is not None else "",
    }


def summary_rows(incidents, timeline_count, deep, mesh, window, filters) -> list[dict]:
    def by(key: str) -> str:
        acc: dict[str, int] = {}
        for f in incidents:
            k = str(f.get(key) or "unknown")
            acc[k] = acc.get(k, 0) + 1
        return ", ".join(f"{k}: {v}" for k, v in acc.items())

    return [
        {"field": "Generated At", "value": datetime.now(timezone.utc).isoformat()},
        {"field": "Platform", "value": "AttackLens"},
        {"field": "Time Window", "value": window},
        {"field": "Filters Applied", "value": filters or "none"},
        {"field": "Total Incidents", "value": len(incidents)},
        {"field": "Incidents by Severity", "value": by("severity")},
        {"field": "Incidents by Terrain", "value": by("terrain")},
        {"field": "Incidents by Status", "value": by("status")},
        {"field": "Total Timeline Events", "value": timeline_count},
        {"field": "Deep Analysis Rows", "value": deep},
        {"field": "DeepMesh Rows", "value": mesh},
    ]


# ── File encoders ────────────────────────────────────────────────────────────
def _csv_bytes(columns: list[tuple[str, str]], rows: list[dict]) -> bytes:
    import csv
    from io import StringIO

    buf = StringIO()
    w = csv.writer(buf)
    w.writerow([h for _, h in columns])
    keys = [k for k, _ in columns]
    for r in rows:
        w.writerow([r.get(k, "") for k in keys])
    return buf.getvalue().encode("utf-8")


def _xlsx_bytes(sheets: list[tuple[str, list[tuple[str, str]], list[dict], str | None]]) -> bytes:
    import xlsxwriter
    from io import BytesIO

    bio = BytesIO()
    wb = xlsxwriter.Workbook(bio, {"in_memory": True})
    header_fmt = wb.add_format({"bold": True})
    fills = {
        "critical": wb.add_format({"bg_color": "#FEE2E2"}),
        "high": wb.add_format({"bg_color": "#FEF3C7"}),
        "medium": wb.add_format({"bg_color": "#DBEAFE"}),
    }
    for name, columns, rows, severity_key in sheets:
        ws = wb.add_worksheet(name[:31])
        ws.freeze_panes(1, 0)
        widths = [len(h) for _, h in columns]
        for c, (_, h) in enumerate(columns):
            ws.write(0, c, h, header_fmt)
        for ridx, r in enumerate(rows, start=1):
            fmt = fills.get(str(r.get(severity_key, "")).lower()) if severity_key else None
            for c, (k, _) in enumerate(columns):
                v = r.get(k, "")
                out = v if isinstance(v, (int, float, str)) else str(v)
                ws.write(ridx, c, out, fmt)
                widths[c] = min(60, max(widths[c], len(str(out))))
        for c, w in enumerate(widths):
            ws.set_column(c, c, w + 2)
    wb.close()
    return bio.getvalue()


def make_reports_router(intel_db, db=None):
    """Mount GET /export. Register with prefix='/api/v1/reports' + require_session."""
    from fastapi import APIRouter, Query
    from fastapi.responses import StreamingResponse

    router = APIRouter()

    async def _gather_incidents(filters: dict):
        findings = await intel_db.get_soc_findings(**filters)
        incidents = [incident_row(f) for f in findings]
        tl_rows: list[dict] = []
        for f in findings:
            fid = f.get("id")
            if fid is None:
                continue
            try:
                events = await intel_db.get_finding_timeline(fid)
            except Exception:
                events = []
            for ev in events:
                tl_rows.append(timeline_row(ev, f))
        return findings, incidents, tl_rows

    async def _gather_telemetry(section, start, end, agent):
        if db is None:
            return []
        try:
            rows = await db.query_payloads(
                agent_id=agent, section=section, start=start, end=end,
                search=None, limit=100_000, offset=0,
            )
        except Exception:
            return []
        return [telemetry_row(r) for r in rows]

    @router.get("/export")
    async def export(
        type: str = Query("all"),
        format: str = Query("xlsx"),
        window: str = Query("7d"),
        agent: str | None = Query(None),
        terrain: str | None = Query(None),
        severity: str | None = Query(None),
        status: str | None = Query(None),
    ):
        finding_filters = {
            k: v for k, v in {
                "agent_id": agent, "terrain_id": terrain, "severity": severity, "status": status,
            }.items() if v
        }

        findings: list = []
        incidents: list = []
        tl_rows: list = []
        deep: list = []
        mesh: list = []

        if type in ("all", "incident"):
            findings, incidents, tl_rows = await _gather_incidents(finding_filters)
        if type in ("all", "telemetry"):
            deep = await _gather_telemetry(None, None, None, agent)
            mesh = await _gather_telemetry("developer_security", None, None, agent)

        summary = summary_rows(findings, len(tl_rows), len(deep), len(mesh), window,
                               ", ".join(f"{k}={v}" for k, v in finding_filters.items()))

        catalog = {
            "Summary": (SUMMARY_COLUMNS, summary, None),
            "Incidents": (INCIDENT_COLUMNS, incidents, "severity"),
            "Timeline": (TIMELINE_COLUMNS, tl_rows, None),
            "Deep Analysis": (TELEMETRY_COLUMNS, deep, None),
            "DeepMesh (AI Security)": (TELEMETRY_COLUMNS, mesh, None),
        }
        if type == "incident":
            names = ["Summary", "Incidents", "Timeline"]
        elif type == "telemetry":
            names = ["Deep Analysis", "DeepMesh (AI Security)"]
        else:
            names = list(catalog.keys())

        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if format == "csv":
            import zipfile
            from io import BytesIO

            zbio = BytesIO()
            with zipfile.ZipFile(zbio, "w", zipfile.ZIP_DEFLATED) as zf:
                for n in names:
                    cols, rows, _ = catalog[n]
                    zf.writestr(f"{n.replace(' ', '_')}.csv", _csv_bytes(cols, rows))
            data = zbio.getvalue()
            mime, ext = "application/zip", "zip"
        else:
            sheets = [(n, *catalog[n]) for n in names]
            data = _xlsx_bytes(sheets)
            mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ext = "xlsx"

        return StreamingResponse(
            iter([data]),
            media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="attacklens-report-{ts}.{ext}"'},
        )

    return router
