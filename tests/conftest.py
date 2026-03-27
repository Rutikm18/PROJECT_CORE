"""
tests/conftest.py — Shared pytest fixtures.

Available in all test files without explicit import.
"""
from __future__ import annotations

import os
import secrets
import sys

import pytest

# Make both packages importable from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def api_key() -> str:
    """Fresh 256-bit API key for each test."""
    return secrets.token_hex(32)


@pytest.fixture
def derived_keys(api_key: str) -> tuple[bytes, bytes]:
    """(enc_key, mac_key) pair derived from the test API key."""
    from agent.agent.crypto import derive_keys
    return derive_keys(api_key)


@pytest.fixture
def enc_key(derived_keys: tuple[bytes, bytes]) -> bytes:
    return derived_keys[0]


@pytest.fixture
def mac_key(derived_keys: tuple[bytes, bytes]) -> bytes:
    return derived_keys[1]
