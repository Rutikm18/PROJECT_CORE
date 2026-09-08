import io
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from manager.manager.api.reports import make_reports_router


class FakeIntel:
    async def get_soc_findings(self, **_filters):
        return [{
            "id": 1, "finding_uid": "u1", "title": "T", "severity": "high",
            "terrain": "citadels", "status": "new", "evidence": {"a": 1},
            "action_plan": ["fix it"], "ai_verdict": {"label": "tp", "confidence": 0.9},
        }]

    async def get_finding_timeline(self, fid):
        return [{"source": "case", "actor": "sys", "action": "opened", "created_at": 1700000000}]


def _client():
    app = FastAPI()
    app.include_router(make_reports_router(FakeIntel(), db=None), prefix="/api/v1/reports")
    return TestClient(app)


def test_csv_export_incident_returns_incident_header_and_row():
    r = _client().get("/api/v1/reports/export?type=incident&format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert any("Incidents" in n for n in names)
    assert any("Timeline" in n for n in names)
    assert any("Summary" in n for n in names)
    incidents = z.read([n for n in names if "Incidents" in n][0]).decode()
    assert "Finding ID" in incidents           # header present
    assert "\r\n1," in incidents               # the one finding, id=1
    # evidence dict flattened into the cell (CSV doubles the inner quotes)
    assert '{""a"": 1}' in incidents or '{""a"":1}' in incidents
    timeline = z.read([n for n in names if "Timeline" in n][0]).decode()
    assert "opened" in timeline                # timeline event exported


def test_incident_export_maps_ai_verdict_and_remediation():
    r = _client().get("/api/v1/reports/export?type=incident&format=csv")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    incidents = z.read([n for n in z.namelist() if "Incidents" in n][0]).decode()
    assert "fix it" in incidents               # action_plan -> remediation
    assert "tp" in incidents                    # ai_verdict.label
