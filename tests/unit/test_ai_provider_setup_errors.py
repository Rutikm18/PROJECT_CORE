"""
tests/unit/test_ai_provider_setup_errors.py — Setting up the AI provider key.

Reproduces the reported failure: saving an OpenRouter key produced

    Provider test failed: [ai:anthropic] HTTP 401 from
    https://api.anthropic.com/v1/messages: {"type":"error","error":
    {"type":"authentication_error","message":"invalid x-api-key"},...}

Three defects combined to cause it:
  • the dashboard did not offer OpenRouter at all, and defaulted to Anthropic
  • nothing noticed that an 'sk-or-' key cannot belong to Anthropic
  • the raw upstream error reached the operator, naming neither cause nor fix
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from manager.manager.api.ai_settings import (
    _explain_provider_failure,
    _key_shape_mismatch,
)


REPORTED_ERROR = (
    '[ai:anthropic] HTTP 401 from https://api.anthropic.com/v1/messages: '
    '{"type":"error","error":{"type":"authentication_error",'
    '"message":"invalid x-api-key"},"request_id":"req_011CeA1uAGFUkfrRqmdU5XRz"}'
)


# ── Key / provider mismatch ───────────────────────────────────────────────────

def test_openrouter_key_on_anthropic_is_caught_before_the_network_call():
    msg = _key_shape_mismatch("anthropic", "sk-or-v1-abcdef")
    assert msg is not None
    assert "OpenRouter" in msg and "Anthropic" in msg
    # It must say what to do, not merely that something is wrong.
    assert "switch the provider" in msg


def test_anthropic_key_on_openrouter_is_caught_too():
    msg = _key_shape_mismatch("openrouter", "sk-ant-api03-abc")
    assert msg is not None
    assert "Anthropic" in msg


@pytest.mark.parametrize("provider,key", [
    ("anthropic",  "sk-ant-api03-abc"),
    ("openrouter", "sk-or-v1-abc"),
    ("gemini",     "AIzaSyABC123"),
])
def test_matching_key_is_accepted(provider, key):
    assert _key_shape_mismatch(provider, key) is None


@pytest.mark.parametrize("provider,key", [
    ("openai", "sk-proj-abc"),      # unrecognised prefix — never guess
    ("openai", "sk-abc"),
    ("ollama", ""),                 # local, needs no key
    ("anthropic", ""),              # blank handled by the reuse path
])
def test_unrecognised_or_absent_keys_are_not_rejected(provider, key):
    """A false refusal is worse than one wasted round trip: providers change
    key formats, and rejecting a valid key blocks setup entirely."""
    assert _key_shape_mismatch(provider, key) is None


# ── Error message quality ─────────────────────────────────────────────────────

def test_the_reported_401_becomes_actionable():
    msg = _explain_provider_failure("anthropic", "claude-haiku-4-5-20251001", REPORTED_ERROR)
    assert "rejected this key as invalid" in msg
    assert "sk-ant-" in msg                      # tells them the right shape
    # None of the raw transport noise should survive.
    assert "request_id" not in msg
    assert "req_011CeA1uAGFUkfrRqmdU5XRz" not in msg
    assert "https://api.anthropic.com" not in msg
    assert "HTTP 401" not in msg


@pytest.mark.parametrize("raw,expected", [
    ("HTTP 402: insufficient credits",        "credit"),
    ("HTTP 404: model not found",             "does not recognise the model"),
    ("HTTP 429 rate limit exceeded",          "rate-limited"),
    ("HTTP 403 permission denied",            "refused the request"),
    ("Request timed out after 60s",           "timed out"),
    ("Cannot connect to host openrouter.ai",  "Could not reach"),
])
def test_common_failures_are_explained(raw, expected):
    assert expected in _explain_provider_failure("openrouter", "m", raw)


def test_unmapped_failure_is_passed_through_not_swallowed():
    """Hiding a cause we did not map would be worse than showing it raw."""
    msg = _explain_provider_failure("openrouter", "m", "something entirely novel")
    assert "something entirely novel" in msg


def test_explanations_are_bounded_in_length():
    msg = _explain_provider_failure("openrouter", "m", "x" * 5000)
    assert len(msg) < 600


# ── Dashboard wiring ──────────────────────────────────────────────────────────

SETTINGS_TSX = Path(
    "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/Settings.tsx"
)


def _settings_source() -> str:
    return SETTINGS_TSX.read_text()


def test_dashboard_offers_openrouter():
    """It was absent from the type, the selector, and every display map, so it
    could not be chosen at all."""
    src = _settings_source()
    selector = re.search(r'\(\[([^\]]*)\] as AIProvider\[\]\)', src)
    assert selector is not None
    assert "openrouter" in selector.group(1)
    assert '"openrouter"' in src.split("type AIProvider")[1].split("\n")[0]


@pytest.mark.parametrize("table", [
    "PROVIDER_LABELS", "PROVIDER_COLORS", "PROVIDER_DESCRIPTIONS",
])
def test_every_provider_display_map_covers_openrouter(table):
    src = _settings_source()
    block = src.split(f"const {table}")[1].split("};")[0]
    assert "openrouter" in block


def test_dashboard_default_provider_matches_the_backend_default():
    """A fresh install showed Anthropic while the system default was
    OpenRouter, so pasting the documented key produced a 401."""
    from manager.manager.ai.base import DEFAULT_MODELS

    src = _settings_source()
    match = re.search(r'useState<AIProvider>\("([a-z]+)"\)', src)
    assert match is not None
    assert match.group(1) == "openrouter"
    assert "openrouter" in DEFAULT_MODELS
