from __future__ import annotations

from fastapi.testclient import TestClient

from manager.manager.server import create_app


def test_dashboard_deep_links_return_spa_shell() -> None:
    client = TestClient(create_app())

    for path in ("/settings/platform", "/incidents/open", "/assets/agent-001"):
        response = client.get(path)

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert '<div id="root"></div>' in response.text
        assert response.headers["cache-control"] == "no-cache, no-store, must-revalidate"


def test_api_and_static_misses_stay_404() -> None:
    client = TestClient(create_app())

    api_response = client.get("/api/v1/does-not-exist")
    static_response = client.get("/static/does-not-exist.js")

    assert api_response.status_code == 404
    assert api_response.headers["content-type"].startswith("application/json")
    assert static_response.status_code == 404
    assert static_response.headers["content-type"].startswith("application/json")
