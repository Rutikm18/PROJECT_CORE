from manager.manager.api.reports import (
    incident_row,
    timeline_row,
    telemetry_row,
    summary_rows,
    INCIDENT_COLUMNS,
    TIMELINE_COLUMNS,
    TELEMETRY_COLUMNS,
)


def test_incident_row_flattens_score_actions_and_evidence():
    row = incident_row({
        "id": 7, "finding_uid": "u7", "title": "Bad binary", "terrain": "citadels",
        "severity": "high", "status": "new", "precision_score": 0.9,
        "action_plan": ["isolate host"], "available_actions": ["quarantine", "notify"],
        "evidence": {"path": "/tmp/x"}, "ai_verdict": {"label": "tp", "confidence": 0.88},
        "cve_ids": ["CVE-2024-1"], "kev": True, "exploit_available": False,
    })
    assert row["finding_id"] == 7
    assert row["validation_score_pct"] == 90
    assert row["remediation"] == "isolate host"
    assert row["actions_performed"] == "quarantine; notify"
    assert row["ai_verdict"] == "tp"
    assert row["ai_confidence_pct"] == 88
    assert row["kev"] == "Yes"
    assert row["exploit_available"] == "No"
    assert "/tmp/x" in row["evidence"]
    for key, _ in INCIDENT_COLUMNS:
        assert key in row


def test_timeline_row_joins_incident_and_isoformats_epoch():
    row = timeline_row(
        {"source": "case", "actor": "alice", "action": "status_change",
         "from_status": "new", "to_status": "triaging", "note": "n", "created_at": 1700000000},
        {"id": 7, "finding_uid": "u7", "title": "T", "severity": "high", "terrain": "citadels"},
    )
    assert row["finding_id"] == 7
    assert row["actor"] == "alice"
    assert row["event_time"].startswith("2023-11-14T")
    for key, _ in TIMELINE_COLUMNS:
        assert key in row


def test_telemetry_row_computes_lag_and_resolves_name():
    row = telemetry_row(
        {"collected_at": 1700000000, "received_at": 1700000005, "agent_id": "a1",
         "section": "processes", "record_count": 12, "data": {"x": 1}},
        {"a1": "host-1"},
    )
    assert row["agent_name"] == "host-1"
    assert row["ingest_lag_s"] == 5
    assert '"x": 1' in row["data"] or '"x":1' in row["data"]
    for key, _ in TELEMETRY_COLUMNS:
        assert key in row


def test_summary_rows_count_by_dimension():
    rows = summary_rows(
        [{"severity": "high", "terrain": "citadels", "status": "new"},
         {"severity": "high", "terrain": "mesh", "status": "triaging"}],
        3, 100, 20, "24h", "none",
    )
    got = {r["field"]: r["value"] for r in rows}
    assert got["Total Incidents"] == 2
    assert got["Incidents by Severity"] == "high: 2"
    assert got["Total Timeline Events"] == 3
    assert got["Deep Analysis Rows"] == 100
    assert got["DeepMesh Rows"] == 20
