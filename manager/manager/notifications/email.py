"""
manager/manager/notifications/email.py — Email notification system.

Supports:
  • SMTP (generic — works with Gmail, Outlook.com, Exchange, any SMTP relay)
  • Microsoft Graph API (Office 365 / Outlook OAuth — set OUTLOOK_* env vars)

Configuration (via env vars):
  SMTP_HOST            SMTP server host (e.g. smtp.office365.com)
  SMTP_PORT            587 (STARTTLS) or 465 (SSL)
  SMTP_USER            Sender email address
  SMTP_PASS            SMTP password or app password
  SMTP_FROM            Display name + address (defaults to SMTP_USER)
  SMTP_TLS             "starttls" | "ssl" | "none"  (default: starttls)
  ALERT_RECIPIENTS     Comma-separated email list for critical alerts
  DIGEST_RECIPIENTS    Comma-separated email list for daily/weekly digests
  OUTLOOK_CLIENT_ID    Azure AD app client ID (Graph API mode)
  OUTLOOK_CLIENT_SECRET Azure AD client secret
  OUTLOOK_TENANT_ID    Azure AD tenant ID
  OUTLOOK_SENDER       Sender UPN (e.g. alerts@yourorg.com)
  EMAIL_ENABLED        "true" | "false"  (default: true if SMTP_HOST set)
"""
from __future__ import annotations

import html
import json
import logging
import os
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

log = logging.getLogger("manager.notifications.email")

_SEVERITY_COLOR = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f39c12",
    "low":      "#27ae60",
    "info":     "#3498db",
}
_SEVERITY_EMOJI = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _recipients(key: str) -> list[str]:
    raw = _env(key)
    return [r.strip() for r in raw.split(",") if r.strip()] if raw else []


class EmailNotifier:
    """
    Async email notifier. Use `send_critical_alert`, `send_digest`, or
    `send_soc_action` depending on the event type.
    """

    def __init__(self) -> None:
        self._smtp_host   = _env("SMTP_HOST")
        self._smtp_port   = int(_env("SMTP_PORT", "587"))
        self._smtp_user   = _env("SMTP_USER")
        self._smtp_pass   = _env("SMTP_PASS")
        self._smtp_from   = _env("SMTP_FROM") or self._smtp_user
        self._smtp_tls    = _env("SMTP_TLS", "starttls").lower()

        self._graph_client_id     = _env("OUTLOOK_CLIENT_ID")
        self._graph_client_secret = _env("OUTLOOK_CLIENT_SECRET")
        self._graph_tenant_id     = _env("OUTLOOK_TENANT_ID")
        self._graph_sender        = _env("OUTLOOK_SENDER")

        self._alert_recipients  = _recipients("ALERT_RECIPIENTS")
        self._digest_recipients = _recipients("DIGEST_RECIPIENTS") or self._alert_recipients

        self._use_graph = bool(self._graph_client_id and
                               self._graph_client_secret and
                               self._graph_tenant_id)
        self._enabled = _env("EMAIL_ENABLED", "true").lower() not in ("false", "0", "no")
        if not self._enabled:
            log.info("Email notifications disabled (EMAIL_ENABLED=false)")
        elif not self._smtp_host and not self._use_graph:
            log.info("Email notifications not configured (set SMTP_HOST or OUTLOOK_* vars)")

    @property
    def enabled(self) -> bool:
        return self._enabled and (bool(self._smtp_host) or self._use_graph)

    # ── Public API ────────────────────────────────────────────────────────────

    async def send_critical_alert(self, finding: dict,
                                  recipients: Optional[list[str]] = None) -> bool:
        """Send immediate alert for a critical/high finding."""
        to = recipients or self._alert_recipients
        if not to or not self.enabled:
            return False
        sev   = finding.get("severity", "high")
        title = finding.get("title", "Security Finding")
        agent = finding.get("agent_id", "unknown")
        subject = f"[AttackLens {_SEVERITY_EMOJI.get(sev, sev.upper())}] {title} — {agent}"
        body = self._render_critical_alert(finding)
        return await self._send(to, subject, body)

    async def send_digest(self, findings: list[dict], period: str = "daily",
                          recipients: Optional[list[str]] = None) -> bool:
        """Send daily or weekly findings digest."""
        to = recipients or self._digest_recipients
        if not to or not self.enabled:
            return False
        label = period.capitalize()
        subject = f"[AttackLens] {label} Security Digest — {len(findings)} Active Findings"
        body = self._render_digest(findings, period)
        return await self._send(to, subject, body)

    async def send_soc_action(self, finding: dict, action: str, analyst: str,
                              detail: str = "",
                              recipients: Optional[list[str]] = None) -> bool:
        """Notify when an analyst updates a finding (status change, comment, etc.)."""
        to = recipients or self._alert_recipients
        if not to or not self.enabled:
            return False
        title = finding.get("title", "Finding")
        ext_id = finding.get("external_id", f"#{finding.get('id','?')}")
        subject = f"[AttackLens SOC] {ext_id} — {action} by {analyst}"
        body = self._render_soc_action(finding, action, analyst, detail)
        return await self._send(to, subject, body)

    async def send_remediation_ready(self, finding: dict, os_type: str,
                                     recipients: Optional[list[str]] = None) -> bool:
        """Notify when AI remediation plan is ready for a finding."""
        to = recipients or self._alert_recipients
        if not to or not self.enabled:
            return False
        title  = finding.get("title", "Finding")
        ext_id = finding.get("external_id", f"#{finding.get('id','?')}")
        subject = f"[AttackLens] Remediation Plan Ready — {ext_id}: {title}"
        body = self._render_remediation_ready(finding, os_type)
        return await self._send(to, subject, body)

    # ── Send dispatch ─────────────────────────────────────────────────────────

    async def _send(self, to: list[str], subject: str, html_body: str) -> bool:
        try:
            if self._use_graph:
                return await self._send_graph(to, subject, html_body)
            elif self._smtp_host:
                return await self._send_smtp(to, subject, html_body)
            return False
        except Exception as exc:
            log.error("Email send failed (%s): %s", subject[:60], exc)
            return False

    async def _send_smtp(self, to: list[str], subject: str, html_body: str) -> bool:
        try:
            import aiosmtplib
        except ImportError:
            log.warning("aiosmtplib not installed — install with: pip install aiosmtplib")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self._smtp_from
        msg["To"]      = ", ".join(to)
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        kwargs: dict = {
            "hostname": self._smtp_host,
            "port":     self._smtp_port,
            "username": self._smtp_user,
            "password": self._smtp_pass,
        }
        if self._smtp_tls == "ssl":
            kwargs["use_tls"] = True
        elif self._smtp_tls == "starttls":
            kwargs["start_tls"] = True

        await aiosmtplib.send(msg, **kwargs)
        log.info("Email sent via SMTP: %s → %s", subject[:60], to)
        return True

    async def _send_graph(self, to: list[str], subject: str, html_body: str) -> bool:
        """Send via Microsoft Graph API (Office 365 app-only auth)."""
        try:
            import aiohttp
        except ImportError:
            log.warning("aiohttp not installed")
            return False

        token = await self._get_graph_token()
        if not token:
            return False

        payload = {
            "message": {
                "subject": subject,
                "body":    {"contentType": "HTML", "content": html_body},
                "toRecipients": [{"emailAddress": {"address": r}} for r in to],
            },
            "saveToSentItems": False,
        }
        url = f"https://graph.microsoft.com/v1.0/users/{self._graph_sender}/sendMail"
        import aiohttp
        async with aiohttp.ClientSession() as s:
            async with s.post(url, json=payload,
                              headers={"Authorization": f"Bearer {token}",
                                       "Content-Type": "application/json"}) as r:
                if r.status == 202:
                    log.info("Email sent via Graph API: %s → %s", subject[:60], to)
                    return True
                text = await r.text()
                log.error("Graph API send failed %d: %s", r.status, text[:200])
                return False

    _graph_token:    Optional[str]  = None
    _graph_token_exp: float         = 0.0

    async def _get_graph_token(self) -> Optional[str]:
        if self._graph_token and time.time() < self._graph_token_exp - 60:
            return self._graph_token
        try:
            import aiohttp
            url = f"https://login.microsoftonline.com/{self._graph_tenant_id}/oauth2/v2.0/token"
            data = {
                "grant_type":    "client_credentials",
                "client_id":     self._graph_client_id,
                "client_secret": self._graph_client_secret,
                "scope":         "https://graph.microsoft.com/.default",
            }
            async with aiohttp.ClientSession() as s:
                async with s.post(url, data=data) as r:
                    j = await r.json()
            self._graph_token     = j.get("access_token")
            self._graph_token_exp = time.time() + int(j.get("expires_in", 3600))
            return self._graph_token
        except Exception as exc:
            log.error("Graph token fetch failed: %s", exc)
            return None

    # ── HTML Templates ────────────────────────────────────────────────────────

    def _base_template(self, title: str, content: str) -> str:
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f5f5f5; margin: 0; padding: 20px; color: #333; }}
  .card {{ background: #fff; border-radius: 8px; padding: 24px 32px;
           max-width: 680px; margin: 0 auto; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
  .header {{ border-bottom: 1px solid #eee; padding-bottom: 16px; margin-bottom: 20px; }}
  .logo {{ font-size: 18px; font-weight: 700; color: #1a1a2e; }}
  .logo span {{ color: #e94560; }}
  h2 {{ margin: 0 0 4px; font-size: 20px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px;
            font-size: 12px; font-weight: 700; color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th {{ text-align: left; font-size: 12px; text-transform: uppercase;
        color: #888; font-weight: 600; padding: 6px 8px; }}
  td {{ padding: 8px; border-bottom: 1px solid #f0f0f0; font-size: 14px; }}
  .step {{ background: #f9f9f9; border-left: 3px solid #3498db;
           padding: 10px 14px; margin: 8px 0; border-radius: 0 6px 6px 0; }}
  .step h4 {{ margin: 0 0 4px; font-size: 14px; }}
  .step code {{ background: #e8e8e8; padding: 4px 8px; border-radius: 4px;
                font-family: monospace; font-size: 12px; display: block; margin-top: 6px; }}
  .footer {{ margin-top: 24px; padding-top: 16px; border-top: 1px solid #eee;
             font-size: 12px; color: #aaa; text-align: center; }}
  a {{ color: #3498db; text-decoration: none; }}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="logo">Attack<span>Lens</span> Security Platform</div>
  </div>
  <h2>{title}</h2>
  {content}
  <div class="footer">
    AttackLens &mdash; Automated Security Intelligence &mdash;
    <a href="#">View Dashboard</a>
  </div>
</div>
</body>
</html>"""

    def _render_critical_alert(self, f: dict) -> str:
        sev    = f.get("severity", "high")
        color  = _SEVERITY_COLOR.get(sev, "#888")
        title  = html.escape(f.get("title", "Security Finding"))
        ext_id = html.escape(f.get("external_id", f"#{f.get('id','?')}"))
        agent  = html.escape(f.get("agent_id", "unknown"))
        cat    = html.escape(f.get("category", "unknown"))
        desc   = html.escape(f.get("description", ""))
        score  = f.get("composite_score", 0)
        kev    = "YES — Active Exploitation Confirmed" if f.get("kev") else "No"
        epss   = f"{float(f.get('epss_score',0))*100:.1f}% exploit probability"
        mitre  = html.escape(f.get("mitre_technique","") or "N/A")
        rec    = html.escape(f.get("recommendation","") or "See dashboard for details")
        cves   = ", ".join(f.get("cve_ids") or []) or "None"
        ts     = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(f.get("last_detected_at", time.time())))

        content = f"""
<p><span class="badge" style="background:{color}">{sev.upper()}</span>
   &nbsp; Finding ID: <strong>{ext_id}</strong> &nbsp;|&nbsp; {ts}</p>

<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Agent</td><td><strong>{agent}</strong></td></tr>
  <tr><td>Category</td><td>{cat}</td></tr>
  <tr><td>Risk Score</td><td><strong>{score}/10</strong></td></tr>
  <tr><td>CVEs</td><td>{cves}</td></tr>
  <tr><td>CISA KEV</td><td>{kev}</td></tr>
  <tr><td>EPSS</td><td>{epss}</td></tr>
  <tr><td>MITRE ATT&CK</td><td>{mitre}</td></tr>
</table>

<p><strong>Description:</strong><br>{desc}</p>
<p><strong>Recommended Action:</strong><br>{rec}</p>
<p><a href="#">View Full Finding &rarr;</a> &nbsp;|&nbsp;
   <a href="#">Generate Remediation Plan &rarr;</a></p>"""
        return self._base_template(f"Security Alert: {title}", content)

    def _render_digest(self, findings: list[dict], period: str) -> str:
        from collections import Counter
        sev_count = Counter(f.get("severity","info") for f in findings)
        critical  = sev_count.get("critical", 0)
        high      = sev_count.get("high", 0)
        medium    = sev_count.get("medium", 0)
        total     = len(findings)
        kev_count = sum(1 for f in findings if f.get("kev"))
        ts        = time.strftime("%Y-%m-%d", time.gmtime())

        rows = ""
        for f in sorted(findings, key=lambda x: -float(x.get("composite_score",0)))[:20]:
            sev   = f.get("severity","info")
            color = _SEVERITY_COLOR.get(sev, "#888")
            rows += f"""<tr>
  <td><span class="badge" style="background:{color};font-size:10px">{sev[:4].upper()}</span></td>
  <td>{html.escape(f.get('external_id',''))}</td>
  <td>{html.escape(f.get('agent_id',''))}</td>
  <td>{html.escape(f.get('title','')[:60])}</td>
  <td>{f.get('composite_score',0):.1f}</td>
  <td>{'YES' if f.get('kev') else ''}</td>
</tr>"""

        content = f"""
<p>{period.capitalize()} security posture summary as of <strong>{ts}</strong>.</p>

<table>
  <tr>
    <td style="text-align:center;padding:12px">
      <div style="font-size:28px;font-weight:700;color:#c0392b">{critical}</div>
      <div style="font-size:12px;color:#888">CRITICAL</div>
    </td>
    <td style="text-align:center;padding:12px">
      <div style="font-size:28px;font-weight:700;color:#e67e22">{high}</div>
      <div style="font-size:12px;color:#888">HIGH</div>
    </td>
    <td style="text-align:center;padding:12px">
      <div style="font-size:28px;font-weight:700;color:#f39c12">{medium}</div>
      <div style="font-size:12px;color:#888">MEDIUM</div>
    </td>
    <td style="text-align:center;padding:12px">
      <div style="font-size:28px;font-weight:700;color:#e94560">{kev_count}</div>
      <div style="font-size:12px;color:#888">CISA KEV</div>
    </td>
    <td style="text-align:center;padding:12px">
      <div style="font-size:28px;font-weight:700">{total}</div>
      <div style="font-size:12px;color:#888">TOTAL ACTIVE</div>
    </td>
  </tr>
</table>

<h3 style="font-size:15px;margin-top:20px">Top Findings by Risk Score</h3>
<table>
  <tr>
    <th>Sev</th><th>ID</th><th>Agent</th><th>Title</th><th>Score</th><th>KEV</th>
  </tr>
  {rows}
</table>
<p><a href="#">Open Full Dashboard &rarr;</a></p>"""
        return self._base_template(f"{period.capitalize()} Security Digest", content)

    def _render_soc_action(self, f: dict, action: str, analyst: str, detail: str) -> str:
        ext_id = html.escape(f.get("external_id", f"#{f.get('id','?')}"))
        title  = html.escape(f.get("title", "Finding"))
        sev    = f.get("severity","info")
        color  = _SEVERITY_COLOR.get(sev, "#888")
        status = html.escape(f.get("status",""))
        ts     = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())

        content = f"""
<p>SOC analyst <strong>{html.escape(analyst)}</strong> performed action
   <strong>{html.escape(action)}</strong> on {ts}.</p>

<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Finding</td><td><strong>{ext_id}</strong> — {title}</td></tr>
  <tr><td>Severity</td>
      <td><span class="badge" style="background:{color}">{sev.upper()}</span></td></tr>
  <tr><td>Current Status</td><td>{status}</td></tr>
  <tr><td>Action</td><td>{html.escape(action)}</td></tr>
  <tr><td>Detail</td><td>{html.escape(detail or '—')}</td></tr>
</table>

<p><a href="#">View Finding &rarr;</a></p>"""
        return self._base_template(f"SOC Action: {ext_id}", content)

    def _render_remediation_ready(self, f: dict, os_type: str) -> str:
        ext_id = html.escape(f.get("external_id", f"#{f.get('id','?')}"))
        title  = html.escape(f.get("title", "Finding"))
        sev    = f.get("severity","info")
        color  = _SEVERITY_COLOR.get(sev, "#888")

        content = f"""
<p>An AI-generated remediation plan is ready for your review.</p>

<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Finding</td><td><strong>{ext_id}</strong> — {title}</td></tr>
  <tr><td>Severity</td>
      <td><span class="badge" style="background:{color}">{sev.upper()}</span></td></tr>
  <tr><td>Target OS</td><td>{html.escape(os_type)}</td></tr>
  <tr><td>Agent</td><td>{html.escape(f.get('agent_id',''))}</td></tr>
</table>

<p>The plan includes step-by-step commands, verification steps, and
   long-term recommendations.</p>
<p><a href="#">View Remediation Plan &rarr;</a></p>"""
        return self._base_template(f"Remediation Plan Ready: {ext_id}", content)
