"""
agent/agent/tls.py — single source of truth for the agent's outbound TLS posture.

Every HTTPS call the agent makes (telemetry send, enrollment, policy fetch)
needs an identically-configured ssl.SSLContext. These used to be three
independent, hand-copied implementations (sender.py, enrollment.py,
config_engine.py) — and they drifted: enrollment.py's never called
load_default_certs(), so with tls_verify=True (required for any real, public
cloud endpoint) it built a context with ZERO trusted CAs loaded. Every
enrollment attempt against a properly-signed cert would fail closed with
"unable to get local issuer certificate" — invisible in local dev, which uses
tls_verify=false or plain http://, guaranteed to surface the moment the
manager moves behind a real TLS-terminated cloud endpoint.

One implementation, used everywhere, is the only way to keep this from
drifting again.
"""
from __future__ import annotations

import ipaddress
import logging
import ssl

log = logging.getLogger("agent.tls")


def build_client_ssl_context(url: str, tls_verify: bool = True) -> ssl.SSLContext | None:
    """Build the TLS client context for an outbound HTTPS request to `url`.

    Returns None for a plain http:// URL (urllib sends it unencrypted, no
    context needed). For https://, verify_mode/check_hostname default to
    CERT_REQUIRED/True on PROTOCOL_TLS_CLIENT — but the trust store is empty
    until load_default_certs() is called explicitly; skipping it means
    verification can never succeed against any real-world certificate.
    """
    if url.startswith("http://"):
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if tls_verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
        _warn_if_verify_disabled_on_public_host(url, tls_verify)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _warn_if_verify_disabled_on_public_host(url, tls_verify)
    return ctx


def _warn_if_verify_disabled_on_public_host(url: str, tls_verify: bool) -> None:
    """Loud, hard-to-miss warning when tls_verify=false is pointed at what
    looks like a real public host — the exact local-dev setting that becomes
    a MITM vulnerability if it ships unchanged to a cloud deployment."""
    if tls_verify:
        return
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if is_local_or_private_host(host):
        log.warning("TLS verification disabled — dev/self-signed cert mode (host=%s)", host)
        return
    log.error(
        "SECURITY: tls_verify=false against a NON-local host (%s) — this accepts "
        "ANY certificate, including an attacker's. This is a dev-only setting; "
        "set tls_verify=true with a real (e.g. Let's Encrypt) certificate before "
        "this agent talks to a manager outside your own machine/network.",
        host,
    )


def is_local_or_private_host(host: str) -> bool:
    """True for localhost, loopback, and RFC1918/RFC4193 private addresses —
    the hosts where skipping cert verification is a reasonable dev shortcut
    rather than a live MITM exposure."""
    if host in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False   # a real hostname, not a literal IP — treat as public
