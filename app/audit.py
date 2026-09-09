"""Audit logging for the MSP backend - 45 CFR § 164.312(b).

The Security Rule's audit controls standard requires "hardware, software,
and/or procedural mechanisms that record and examine activity in information
systems that contain or use electronic protected health information." This
module is that mechanism.

Distinct from /api/v1/health-audit, which measures *device availability*.
That endpoint answers "are the endpoints reporting?"; this one answers "who
did what, and when?" - the question an OCR investigator asks. Both are
needed; neither substitutes for the other.

Two rules govern what goes in this table:

1. NEVER record credentials. A failed login records the username that was
   attempted and nothing else - never the password, not even hashed. A
   password typed into the username field by mistake is the classic way
   secrets end up in an audit log, so treat `actor_username` as
   potentially-sensitive text and never echo it outside an authenticated
   response.

2. NEVER record field VALUES from device records. `notes` and `location`
   are free text a technician types; either could contain PHI. Recording
   old/new values would put PHI into a table that has no PHI controls
   around it and a six-year retention requirement. So `detail` records
   which fields changed, never what they changed to. If you later need
   before/after values for forensics, that is a separate design with its
   own risk analysis - do not quietly widen this one.

Retention: HIPAA requires documentation retention of six years
(45 CFR § 164.316(b)(2)(i)). There is deliberately no purge routine here.
Do not add one without a written retention policy behind it.

Append-only by construction: nothing in this module updates or deletes an
AuditEvent, and no API route exposes a way to. The table should also be
protected at the database-permission level in production - the application
role wants INSERT and SELECT on audit_events, not UPDATE or DELETE.
"""

import os
import sys
from datetime import datetime
from typing import Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import AuditEvent

# Action vocabulary. Keep these stable - they are queried, and renaming one
# orphans the history that used the old name.
LOGIN_SUCCESS = "login.success"
LOGIN_FAILURE = "login.failure"
DEVICE_CREATE = "device.create"
DEVICE_UPDATE = "device.update"
DEVICE_DELETE = "device.delete"

# app/monitor.py - the silent-endpoint monitor. These are informational
# events (outcome is always SUCCESS: the alert pipeline did its job), not a
# judgment about the device itself.
ALERT_TRIGGERED = "alert.triggered"
ALERT_ESCALATED = "alert.escalated"
ALERT_RESOLVED = "alert.resolved"

# app/breach_clock.py / the breach-incident routes in app/main.py. Never put
# BreachIncident.description in `detail` alongside these - see that model's
# docstring on why it may contain PHI.
INCIDENT_CREATE = "incident.create"
INCIDENT_CONFIRM = "incident.confirm"
INCIDENT_NOTIFY = "incident.notify"
INCIDENT_CLOSE = "incident.close"

# Client Reporting Agent (5) / On-Call Escalation Router Agent (7).
TENANT_SETTINGS_UPDATE = "tenant.settings_update"
REPORT_SEND = "report.send"

SUCCESS = "success"
FAILURE = "failure"

# Behind Render (or any reverse proxy) request.client.host is the proxy, and
# the real client address is the first entry of X-Forwarded-For. That header
# is trivially spoofable when the app is reachable directly, so it is only
# honoured when explicitly enabled. Set MSP_TRUST_PROXY=1 on Render; leave it
# unset locally.
TRUST_PROXY = os.environ.get("MSP_TRUST_PROXY", "").strip() not in ("", "0", "false", "False")

# When set, a failed audit write aborts the operation it was recording
# instead of letting it proceed unlogged. Off by default: an audit-table
# problem should not take the whole service down for a dental office
# mid-appointment. On, it is the stricter reading of § 164.312(b). Device
# mutations are unaffected either way - those write their audit row inside
# the same transaction as the change, so they are atomic regardless.
STRICT = os.environ.get("MSP_AUDIT_STRICT", "").strip() not in ("", "0", "false", "False")

_MAX_UA = 400
_MAX_DETAIL = 500


def client_ip(request) -> Optional[str]:
    if request is None:
        return None
    if TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    client = getattr(request, "client", None)
    return client.host[:64] if client and client.host else None


def user_agent(request) -> Optional[str]:
    if request is None:
        return None
    ua = request.headers.get("user-agent")
    return ua[:_MAX_UA] if ua else None


def build(
    *,
    action: str,
    outcome: str,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    tenant_id: Optional[int] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    request=None,
    detail: Optional[str] = None,
) -> AuditEvent:
    """Construct an AuditEvent. Does not add it to a session."""
    return AuditEvent(
        timestamp=datetime.utcnow(),
        action=action,
        outcome=outcome,
        actor_user_id=actor_user_id,
        actor_username=(actor_username or None) and str(actor_username)[:255],
        tenant_id=tenant_id,
        target_type=target_type,
        target_id=(target_id or None) and str(target_id)[:255],
        source_ip=client_ip(request),
        user_agent=user_agent(request),
        detail=(detail or None) and str(detail)[:_MAX_DETAIL],
    )


def stage(db: Session, **kwargs) -> AuditEvent:
    """Add an audit row to the caller's session WITHOUT committing.

    Use this for anything that also changes data: the caller's commit then
    covers both the change and its audit record in one transaction, so a
    device can never be modified without a corresponding audit row, and a
    rolled-back change never leaves a phantom one behind.
    """
    event = build(**kwargs)
    db.add(event)
    return event


def record(db: Session, **kwargs) -> Optional[AuditEvent]:
    """Write an audit row in its own transaction.

    For events with nothing else to commit alongside them - logins, chiefly.
    Honours MSP_AUDIT_STRICT; see the note on STRICT above.
    """
    event = build(**kwargs)
    try:
        db.add(event)
        db.commit()
        return event
    except SQLAlchemyError as exc:
        db.rollback()
        print(
            f"AUDIT WRITE FAILED - action={kwargs.get('action')} "
            f"outcome={kwargs.get('outcome')} error={exc}",
            file=sys.stderr,
            flush=True,
        )
        if STRICT:
            raise
        return None


def changed_fields(changes: dict) -> str:
    """Render a device update as field NAMES only - never values.

    See rule 2 in the module docstring: `notes` and `location` are free text
    and may contain PHI.
    """
    if not changes:
        return "fields="
    return "fields=" + ",".join(sorted(changes))
