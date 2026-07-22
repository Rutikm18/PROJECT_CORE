"""tests/unit/test_version.py — version module and /api/v1/meta endpoint tests."""
from __future__ import annotations

import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from manager.manager.server import create_app
from manager.manager.version import get_version_info


def _fresh_info(**env: str) -> dict:
    """Call get_version_info with a clean cache and given env vars."""
    from manager.manager import version as v
    v.get_version_info.cache_clear()
    with patch.dict(os.environ, env, clear=False):
        result = v.get_version_info()
    v.get_version_info.cache_clear()
    return result


class TestVersionResolution:
    def test_env_var_takes_priority(self):
        info = _fresh_info(APP_VERSION="1.1.5", APP_COMMIT="abc1234", APP_BUILT_AT="2026-07-22T00:00:00Z")
        assert info["version"] == "1.1.5"
        assert info["commit"] == "abc1234"
        assert info["built_at"] == "2026-07-22T00:00:00Z"

    def test_version_file_fallback(self):
        # No env vars — should pick up VERSION file from repo root
        clean = {k: "" for k in ("APP_VERSION", "APP_COMMIT", "APP_BUILT_AT")}
        info = _fresh_info(**clean)
        parts = info["version"].split(".")
        assert len(parts) == 3, f"Expected 1.1.x format, got {info['version']!r}"
        assert parts[0] == "1" and parts[1] == "1"
        assert parts[2].split("-")[0].isdigit()

    def test_dev_fallback_when_no_version_file(self):
        clean = {k: "" for k in ("APP_VERSION", "APP_COMMIT", "APP_BUILT_AT")}
        with patch("manager.manager.version._read_version_file", return_value=None):
            info = _fresh_info(**clean)
        assert info["version"] == "1.1.0-dev"

    def test_get_version_string_matches_info(self):
        from manager.manager.version import get_version
        assert get_version() == get_version_info()["version"]


class TestMetaEndpoint:
    def setup_method(self):
        self.client = TestClient(create_app())

    def test_meta_returns_200(self):
        r = self.client.get("/api/v1/meta")
        assert r.status_code == 200

    def test_meta_returns_json_with_version(self):
        r = self.client.get("/api/v1/meta")
        data = r.json()
        assert "version" in data
        assert data["version"]  # non-empty string

    def test_meta_version_format(self):
        r = self.client.get("/api/v1/meta")
        version = r.json()["version"]
        parts = version.split(".")
        assert len(parts) == 3, f"Expected 1.1.x format, got: {version!r}"
        assert parts[0] == "1" and parts[1] == "1"

    def test_meta_is_not_intercepted_by_spa_catchall(self):
        # /api/v1/meta must return JSON, never the SPA shell
        r = self.client.get("/api/v1/meta")
        assert r.headers["content-type"].startswith("application/json")

    def test_health_includes_version(self):
        r = self.client.get("/health")
        data = r.json()
        assert "version" in data
        assert data["version"] == get_version_info()["version"]
