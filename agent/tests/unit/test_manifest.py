"""
agent/tests/unit/test_manifest.py — install manifest + checksum validation (R1).
"""
from __future__ import annotations

import json

import pytest

from agent.agent import manifest as m


def _bin(tmp_path, name="attacklens-agent", data=b"MZ\x00binary-bytes" * 100):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _manifest_for(tmp_path, path, name="agent"):
    rec = m.build_component(path, version="1.1.0")
    assert rec is not None
    return {"version": "1.1.0", "components": {name: rec}}


def test_good_binary_verifies_ok(tmp_path):
    path = _bin(tmp_path)
    man = _manifest_for(tmp_path, path)
    r = m.verify_component("agent", man)
    assert r.ok and r.status == "ok"
    assert r.should_degrade is False


def test_tampered_binary_fails_checksum(tmp_path):
    path = _bin(tmp_path)
    man = _manifest_for(tmp_path, path)
    # Rewrite SAME size, different bytes → size passes, checksum fails.
    orig = (tmp_path / "attacklens-agent").read_bytes()
    (tmp_path / "attacklens-agent").write_bytes(b"X" * len(orig))
    r = m.verify_component("agent", man)
    assert r.status == "checksum_mismatch"
    assert r.should_degrade is True


def test_truncated_binary_fails_size_first(tmp_path):
    path = _bin(tmp_path)
    man = _manifest_for(tmp_path, path)
    (tmp_path / "attacklens-agent").write_bytes(b"short")
    r = m.verify_component("agent", man)
    assert r.status == "size_mismatch"      # short-circuits before hashing
    assert r.should_degrade is True


def test_missing_binary(tmp_path):
    path = _bin(tmp_path)
    man = _manifest_for(tmp_path, path)
    (tmp_path / "attacklens-agent").unlink()
    r = m.verify_component("agent", man)
    assert r.status == "file_missing"
    assert r.should_degrade is True


def test_unknown_component(tmp_path):
    path = _bin(tmp_path)
    man = _manifest_for(tmp_path, path)
    r = m.verify_component("watchdog", man)     # not in manifest
    assert r.status == "component_absent"
    assert r.should_degrade is True


def test_absent_manifest_does_not_degrade(tmp_path):
    # Rollout window: an install predating the manifest must NOT be degraded.
    r = m.verify_component("agent", None, manifest_path=str(tmp_path / "none.json"))
    assert r.status == "manifest_absent"
    assert r.should_degrade is False


def test_write_then_load_roundtrip(tmp_path):
    path = _bin(tmp_path)
    rec = m.build_component(path, version="2.0")
    out = tmp_path / "manifest.json"
    assert m.write_manifest({"agent": rec}, path=str(out), version="2.0") is True
    loaded = m.load_manifest(str(out))
    assert loaded["components"]["agent"]["sha256"] == rec["sha256"]
    # And it verifies against the on-disk binary.
    assert m.verify_component("agent", loaded).ok is True


def test_load_malformed_manifest_returns_none(tmp_path):
    bad = tmp_path / "manifest.json"
    bad.write_text("{not valid json")
    assert m.load_manifest(str(bad)) is None


def test_sha256_of_missing_file_is_none(tmp_path):
    assert m.sha256_file(str(tmp_path / "nope")) is None
