"""The first-run credential hint must survive a local install.

`env.sh` writes PUBLIC_IP on every install, including a laptop where the value
is `localhost`. The gate used to test whether the variable was *set*, so every
local developer was classified as an internet deployment: the click-to-autofill
hint disappeared and the login screen became unenterable without reading the
source. The gate now asks whether the address is actually reachable.
"""
from __future__ import annotations

import pytest

from manager.manager.api.auth_ui import _is_public_address

NOT_PUBLIC = [
    ("", "unset"),
    ("localhost", "what env.sh writes on a laptop"),
    ("  LocalHost  ", "whitespace and case are normalized"),
    ("127.0.0.1", "loopback"),
    ("::1", "IPv6 loopback"),
    ("[::1]", "bracketed IPv6"),
    ("10.0.0.5", "RFC1918"),
    ("172.16.4.9", "RFC1918"),
    ("192.168.1.50", "RFC1918"),
    ("169.254.1.1", "link-local"),
    ("100.64.0.1", "CGNAT"),
    ("box.local", "mDNS"),
    ("dev.internal", "internal suffix"),
]

PUBLIC = [
    ("8.8.8.8", "public IPv4"),
    ("93.184.216.34", "public IPv4"),
    ("2606:4700::1111", "public IPv6"),
    ("attacklens.example.com", "a real domain"),
    ("not an address", "unparseable input must fail closed"),
    # RFC 5737 documentation ranges. Python reports these as is_private and
    # not is_global, so a `not is_global` gate silently calls them safe — but
    # an operator who configures one means "a public address", and
    # test_default_credential_exposure.py relies on exactly that.
    ("203.0.113.10", "TEST-NET-3 must count as public"),
    ("198.51.100.5", "TEST-NET-2 must count as public"),
    ("192.0.2.1", "TEST-NET-1 must count as public"),
    ("0.0.0.0", "all-interfaces is exposure, not privacy"),
]


@pytest.mark.parametrize("value,why", NOT_PUBLIC)
def test_local_addresses_are_not_public(value, why):
    assert _is_public_address(value) is False, why


@pytest.mark.parametrize("value,why", PUBLIC)
def test_reachable_addresses_are_public(value, why):
    assert _is_public_address(value) is True, why


def test_empty_env_var_does_not_defeat_the_admin_email_default():
    """docker-compose sets DASHBOARD_EMAIL="" — always set, usually empty.

    `os.environ.get(name, default)` never fires its default for a variable that
    exists-but-is-empty, which left the expected login email as "" and made
    every human-typed credential a 401.
    """
    import os

    assert (os.environ.get("__NOT_SET_ANYWHERE__") or "fallback") == "fallback"
    os.environ["__EMPTY_PROBE__"] = ""
    try:
        assert os.environ.get("__EMPTY_PROBE__", "fallback") == "", "get() keeps the empty value"
        assert (os.environ.get("__EMPTY_PROBE__") or "fallback") == "fallback"
    finally:
        del os.environ["__EMPTY_PROBE__"]


# ── Lockout countdown ───────────────────────────────────────────────────────
# `ip_remaining` / `acct_remaining` were computed on every failed login and
# then dropped on the floor, so the attempt before a lockout looked identical
# to the first. Only the IP budget is surfaced: it belongs to the caller, so it
# cannot reveal whether an account exists the way the account budget would.

def _error_text(response) -> str:
    import json
    return json.loads(response.body)["error"]


def test_early_failures_do_not_leak_a_countdown():
    from manager.manager.api.auth_ui import _auth_error
    assert _error_text(_auth_error(attempts_remaining=4)) == "Invalid credentials."


def test_final_attempts_warn_before_lockout():
    from manager.manager.api.auth_ui import _auth_error
    assert "2 attempts remaining" in _error_text(_auth_error(attempts_remaining=2))
    assert "1 attempt remaining" in _error_text(_auth_error(attempts_remaining=1))


def test_countdown_is_singular_at_one():
    from manager.manager.api.auth_ui import _auth_error
    assert "1 attempts" not in _error_text(_auth_error(attempts_remaining=1))


def test_lockout_response_supersedes_the_countdown():
    from manager.manager.api.auth_ui import _auth_error
    response = _auth_error(locked_minutes=15, attempts_remaining=0)
    assert response.status_code == 429
    assert "15 minute" in _error_text(response)


def test_unknown_budget_falls_back_to_the_plain_message():
    from manager.manager.api.auth_ui import _auth_error
    assert _error_text(_auth_error()) == "Invalid credentials."
