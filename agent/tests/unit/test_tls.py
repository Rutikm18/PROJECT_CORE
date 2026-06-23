"""
agent/tests/unit/test_tls.py — shared outbound TLS context contract.

Regression coverage for the bug this module fixes: ssl.SSLContext(
PROTOCOL_TLS_CLIENT) starts with verify_mode/check_hostname secure by
default, but its trust store is EMPTY until load_default_certs() is called
explicitly. enrollment.py's old, independent context builder never called
it — under tls_verify=True (required for any real public/cloud endpoint),
every enrollment attempt would fail closed with "unable to get local issuer
certificate", invisible in local dev (tls_verify=false or plain http://).

Also covers: all three call sites (sender, enrollment, config_engine) build
an equivalent context via this one function, so they can't drift apart
again; and the loud warning when tls_verify=false targets a non-local host.
"""
from __future__ import annotations

import ssl

import pytest

from agent.agent.tls import build_client_ssl_context, is_local_or_private_host


def test_plain_http_returns_no_context():
    assert build_client_ssl_context("http://manager.internal:8080", tls_verify=True) is None


def test_https_verify_true_loads_a_trust_store(monkeypatch):
    """The actual bug: without calling load_default_certs(), the trust store
    stays empty and verification can never succeed against any real-world
    certificate. Spying on the call (not the resulting cert count) keeps this
    portable — whether THIS machine's Python has a CA bundle wired up is a
    local environment detail, not what the fix is responsible for."""
    calls = []
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs",
                        lambda self: calls.append(True))
    ctx = build_client_ssl_context("https://manager.example.com", tls_verify=True)
    assert ctx is not None
    assert calls, "load_default_certs() must be called — this is exactly the missing call that broke enrollment"
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_https_verify_false_disables_verification():
    ctx = build_client_ssl_context("https://127.0.0.1:8443", tls_verify=False)
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_minimum_tls_version_is_1_3():
    ctx = build_client_ssl_context("https://manager.example.com", tls_verify=True)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "10.0.0.5", "192.168.1.10", "::1"])
def test_local_and_private_hosts_recognised(host):
    assert is_local_or_private_host(host) is True


@pytest.mark.parametrize("host", ["manager.example.com", "8.8.8.8", "1.1.1.1"])
def test_public_hosts_not_misclassified_as_local(host):
    assert is_local_or_private_host(host) is False


def test_warns_loudly_when_verify_disabled_on_public_host(caplog):
    import logging
    with caplog.at_level(logging.ERROR, logger="agent.tls"):
        build_client_ssl_context("https://manager.example.com", tls_verify=False)
    assert any("SECURITY" in r.message for r in caplog.records)


def test_no_security_alarm_when_verify_disabled_on_local_host(caplog):
    import logging
    with caplog.at_level(logging.ERROR, logger="agent.tls"):
        build_client_ssl_context("https://127.0.0.1:8443", tls_verify=False)
    assert not any("SECURITY" in r.message for r in caplog.records)


# ── All three call sites build an equivalent context ────────────────────────

def test_sender_uses_shared_context_builder(tmp_path, monkeypatch):
    import queue
    from agent.agent.sender import Sender
    calls = []
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs",
                        lambda self: calls.append(True))
    s = Sender({
        "manager": {"url": "https://manager.example.com", "tls_verify": True},
        "paths": {"spool_dir": str(tmp_path)},
    }, queue.Queue())
    assert s._ctx is not None
    assert calls, "Sender must build its context via the shared, verified builder"


def test_config_engine_transport_uses_shared_context_builder(monkeypatch):
    from agent.agent.config_engine import HttpPolicyTransport
    calls = []
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs",
                        lambda self: calls.append(True))
    t = HttpPolicyTransport("https://manager.example.com", agent_id="a", tls_verify=True)
    assert t._ctx is not None
    assert calls, "HttpPolicyTransport must build its context via the shared, verified builder"


def test_post_enroll_builds_verified_context_for_https(monkeypatch):
    """Regression: _post_enroll must call load_default_certs() under
    tls_verify=True, not silently skip verification (the actual bug fixed
    here — it used to build a context with check_hostname/verify_mode left
    at their CERT_REQUIRED default but an EMPTY trust store)."""
    import agent.agent.enrollment as enrollment_mod

    calls = []
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs",
                        lambda self: calls.append(True))

    api_key = "a" * 64

    class _FakeResp:
        status = 200
        def read(self):
            return ('{"api_key": "%s"}' % api_key).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        enrollment_mod.urllib.request, "urlopen", lambda *a, **k: _FakeResp()
    )

    result = enrollment_mod._post_enroll("https://manager.example.com/enroll", "", {}, True)

    assert calls, "_post_enroll must build its context via the shared, verified builder"
    assert result == {"api_key": api_key}
