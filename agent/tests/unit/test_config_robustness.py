"""
agent/tests/unit/test_config_robustness.py — load_config edge cases.

A boot daemon that crashes on a bad config gets restart-looped by launchd every
ThrottleInterval. load_config turns the three real failure modes (missing file,
malformed TOML, missing/invalid required keys) into one clear ConfigError with an
operator-actionable message.
"""
from __future__ import annotations

import pytest

from agent.agent.core import load_config, ConfigError


_GOOD = 'ok'


def _write(tmp_path, text):
    p = tmp_path / "agent.toml"
    p.write_text(text)
    return str(p)


def test_missing_file_raises_configerror(tmp_path):
    with pytest.raises(ConfigError) as ei:
        load_config(str(tmp_path / "nope.toml"))
    assert "not found" in str(ei.value)


def test_malformed_toml_raises_configerror(tmp_path):
    path = _write(tmp_path, 'this is = = not valid toml [[[')
    with pytest.raises(ConfigError) as ei:
        load_config(path)
    assert "valid TOML" in str(ei.value)


def test_missing_manager_url_raises(tmp_path):
    path = _write(tmp_path, '[agent]\nid = "mac-001"\n[manager]\n')
    with pytest.raises(ConfigError) as ei:
        load_config(path)
    assert "url" in str(ei.value)


def test_empty_manager_url_raises(tmp_path):
    path = _write(tmp_path, '[manager]\nurl = "   "\n')
    with pytest.raises(ConfigError):
        load_config(path)


def test_non_http_url_scheme_raises(tmp_path):
    path = _write(tmp_path, '[manager]\nurl = "ftp://x"\n')
    with pytest.raises(ConfigError) as ei:
        load_config(path)
    assert "http" in str(ei.value)


def test_directory_as_config_raises(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    with pytest.raises(ConfigError):
        load_config(str(d))


def test_valid_config_loads(tmp_path):
    path = _write(tmp_path, '[agent]\nid = "mac-001"\n[manager]\nurl = "http://127.0.0.1:8080"\n')
    cfg = load_config(path)
    assert cfg["manager"]["url"] == "http://127.0.0.1:8080"
    assert cfg["agent"]["id"] == "mac-001"


def test_missing_agent_section_is_normalised(tmp_path):
    # [agent] absent is OK — id is auto-derived later; just don't crash.
    path = _write(tmp_path, '[manager]\nurl = "https://mgr.example:443"\n')
    cfg = load_config(path)
    assert isinstance(cfg["agent"], dict)
