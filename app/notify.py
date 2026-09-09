"""Outbound alert notifications for app/monitor.py.

Email only, sent via plain SMTP (smtplib, stdlib - no new dependency). Built
to point at Google Workspace's SMTP relay (smtp.gmail.com:587 with an app
password, or smtp-relay.gmail.com for a Workspace relay with no auth from a
known IP) once that's set up, but works against any SMTP provider.

Configuration is entirely environment variables, matching how MSP_API_KEY and
MSP_DATABASE_URL already work elsewhere in this app - nothing here changes
behavior for local dev unless you set them:

  MSP_ALERT_EMAIL_TO     comma-separated recipient list (your on-call inbox,
                          not a client's - this is Endpoint Shield Solutions'
                          own escalation, see app/monitor.py docstring)
  MSP_ALERT_EMAIL_FROM   From: address (defaults to MSP_SMTP_USER)
  MSP_SMTP_HOST
  MSP_SMTP_PORT          default 587
  MSP_SMTP_USER
  MSP_SMTP_PASSWORD
  MSP_SMTP_USE_TLS       default "1" (STARTTLS) - set "0" only for a relay
                          that doesn't support it

If MSP_ALERT_EMAIL_TO or MSP_SMTP_HOST is unset, send_alert_email() logs what
it would have sent and returns False instead of raising. That keeps the
monitor loop itself testable (detection, state tracking, and the audit trail
all work) before email is wired up, and means a mail-server outage degrades
to "no email went out" rather than crashing device monitoring.

Message bodies are deliberately limited to non-PHI fields: hostname, tenant
name, IP/CPU/RAM/OS, and timestamps. `notes` and `location` are free text a
technician types and may contain PHI - the same reasoning app/audit.py
applies to audit rows applies here, and an alert email is far less access-
controlled than the audit log.
"""

import os
import smtplib
import sys
from email.message import EmailMessage
from typing import Optional


def _bool_env(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip() not in ("0", "false", "False", "")


SMTP_HOST = os.environ.get("MSP_SMTP_HOST")
SMTP_PORT = int(os.environ.get("MSP_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("MSP_SMTP_USER")
SMTP_PASSWORD = os.environ.get("MSP_SMTP_PASSWORD")
SMTP_USE_TLS = _bool_env("MSP_SMTP_USE_TLS", "1")

ALERT_FROM = os.environ.get("MSP_ALERT_EMAIL_FROM") or SMTP_USER
_to_env = os.environ.get("MSP_ALERT_EMAIL_TO", "")
ALERT_TO = [addr.strip() for addr in _to_env.split(",") if addr.strip()]


def configured() -> bool:
    """True once there's somewhere to send and something to send from."""
    return bool(SMTP_HOST and ALERT_FROM and ALERT_TO)


def _send(to_addresses: list, subject: str, body: str, *, log_prefix: str) -> bool:
    """Shared plain-text send. Never raises - a notification failure must
    not take down the monitor loop or a request thread. Failures are logged
    to stderr so they show up in the same place AUDIT WRITE FAILED does
    (app/audit.py). `log_prefix` just distinguishes an alert-email skip/fail
    from a client-report skip/fail in the logs.
    """
    if not (SMTP_HOST and ALERT_FROM and to_addresses):
        print(
            f"{log_prefix} SKIPPED (not configured) - subject={subject!r}\n{body}",
            file=sys.stderr,
            flush=True,
        )
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = ALERT_FROM
    msg["To"] = ", ".join(to_addresses)
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        print(
            f"{log_prefix} FAILED - subject={subject!r} error={exc}",
            file=sys.stderr,
            flush=True,
        )
        return False


def send_alert_email(subject: str, body: str) -> bool:
    """Send to Endpoint Shield Solutions' own on-call inbox (MSP_ALERT_EMAIL_TO)."""
    return _send(ALERT_TO, subject, body, log_prefix="ALERT EMAIL")


def send_client_email(to_addresses: list, subject: str, body: str) -> bool:
    """Client Reporting Agent, subagent 5c. Send to a CLIENT's own contact
    address(es) - never ALERT_TO, which is the MSP's internal escalation
    list, not something a client should be cc'd on."""
    return _send([a for a in to_addresses if a], subject, body, log_prefix="CLIENT REPORT EMAIL")


def send_client_html_email(to_addresses: list, subject: str, *, text_body: str, html_body: str,
                            logo_bytes: Optional[bytes] = None, logo_cid: str = "") -> bool:
    """Client Reporting Agent, subagent 5c - the branded monthly report.
    Sends a proper multipart/alternative message: `text_body` is the MIME
    fallback every mail client can render, `html_body` is what a modern
    client actually shows. `logo_bytes`/`logo_cid` embed the brand mark as
    a related image the html_body references via `cid:<logo_cid>` - inline
    CID attachment, not a data: URI, because several major webmail clients
    (Outlook chief among them) strip data: URIs from HTML email but do
    render CID-attached images.
    """
    to_addresses = [a for a in to_addresses if a]
    if not (SMTP_HOST and ALERT_FROM and to_addresses):
        print(
            f"CLIENT REPORT EMAIL SKIPPED (not configured) - subject={subject!r}\n{text_body}",
            file=sys.stderr,
            flush=True,
        )
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = ALERT_FROM
    msg["To"] = ", ".join(to_addresses)
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    if logo_bytes and logo_cid:
        # The HTML alternative is always the last payload added above.
        html_part = msg.get_payload()[-1]
        html_part.add_related(logo_bytes, maintype="image", subtype="png", cid=f"<{logo_cid}>")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        print(f"CLIENT REPORT EMAIL FAILED - subject={subject!r} error={exc}", file=sys.stderr, flush=True)
        return False
