"""Silent-endpoint monitor - closes COMPLIANCE-GAPS.md item 4.

Before this module, the only "monitoring" was GET /api/v1/health-audit,
which is a pull: a technician has to have the dashboard tab open and looking
at it for a silent device to be noticed. There was no push - nothing woke a
human up. "24/7 monitoring" was not a supportable claim; see the item this
closes for the full finding.

This module is the push half. A background loop (started from app/main.py's
startup event) polls every MSP_ALERT_POLL_SECONDS and, for any device that
has gone silent past the offline threshold, sends an email via app/notify.py
and records the event in the audit trail (app/audit.py: alert.triggered /
alert.escalated / alert.resolved). It re-notifies on an escalation interval
for an outage that's still ongoing, and sends a resolved notice when the
device reports back in.

Scope, deliberately: this notifies Endpoint Shield Solutions' own on-call
inbox (MSP_ALERT_EMAIL_TO), not the client. Client-facing notification is a
separate, later decision - it touches the MSA/SMA's communication terms and
probably wants per-tenant contacts and quiet hours, none of which exist yet.
Getting a human on the MSP side notified quickly is the piece that unblocks
the SMA's response-time targets and the BAA's 72-hour breach-notification
clock; that's the gap this closes today.

Also deliberately out of scope: SMS/pager/on-call rotation, per-severity
routing, business-hours suppression. Email is the floor, not the ceiling -
see the "Suggested order" list in COMPLIANCE-GAPS.md for what's still ahead
of it (encryption at rest, admin safeguards, subcontractor BAA) before this
becomes the thing worth polishing.

Run standalone for testing without waiting for real silence:
    python -m app.monitor --once
"""

import asyncio
import os
import sys
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app import audit, notify
from app.database import SessionLocal
from app.models import Device, DeviceAlertState, Tenant

# Same default as app/main.py's fleet_status() "offline" boundary, so an
# alert fires exactly when the dashboard would also call the device
# offline - not sooner (noise) and not later (a silent gap between what a
# technician sees on screen and what the monitor is actually watching for).
SILENT_THRESHOLD_SECONDS = int(os.environ.get("MSP_ALERT_SILENT_SECONDS", "600"))

# How often an ongoing (already-alerted) outage gets a follow-up email, so an
# unresolved outage doesn't go seven hours between reminders, but also
# doesn't re-notify every single poll cycle.
RENOTIFY_MINUTES = int(os.environ.get("MSP_ALERT_RENOTIFY_MINUTES", "60"))

POLL_SECONDS = int(os.environ.get("MSP_ALERT_POLL_SECONDS", "60"))

ALERT_ENABLED = os.environ.get("MSP_ALERT_ENABLED", "1").strip() not in ("0", "false", "False", "")


def _humanize(seconds: float) -> str:
    # A device that has never sent a single heartbeat has no last_seen at
    # all, so check_once() passes float("inf") rather than a real duration -
    # int(inf // 60) raises ValueError (nan can't become an int), which is
    # exactly the case a brand-new, never-reporting device hits first.
    if seconds == float("inf"):
        return "an unknown time (never reported in)"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _tenant_name(db: Session, tenant_id: Optional[int]) -> str:
    if tenant_id is None:
        return "(no tenant)"
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    return tenant.name if tenant else f"(tenant #{tenant_id})"


def _get_or_create_state(db: Session, device: Device) -> DeviceAlertState:
    state = db.query(DeviceAlertState).filter(DeviceAlertState.hostname == device.hostname).first()
    if not state:
        state = DeviceAlertState(hostname=device.hostname, tenant_id=device.tenant_id, status="ok")
        db.add(state)
        db.flush()
    return state


def _device_summary(device: Device, tenant_name: str) -> str:
    # Non-PHI fields only - see app/notify.py's docstring for why `notes`
    # and `location` are excluded.
    last_seen = device.last_seen.isoformat() + "Z" if device.last_seen else "never"
    return (
        f"Hostname: {device.hostname}\n"
        f"Tenant:   {tenant_name}\n"
        f"IP:       {device.ip or '(unknown)'}\n"
        f"OS:       {device.os or '(unknown)'}\n"
        f"Last seen: {last_seen}"
    )


def check_once(db: Session) -> int:
    """Run one monitoring pass. Returns the number of notification emails
    sent (or attempted, if SMTP isn't configured yet - see app/notify.py).

    Synchronous and self-contained so it can be called directly from a test
    or a one-off script, independent of the asyncio loop below.
    """
    now = datetime.utcnow()
    sent = 0

    for device in db.query(Device).all():
        silent_for = (
            (now - device.last_seen).total_seconds()
            if device.last_seen
            else float("inf")  # never reported in = as silent as it gets
        )
        is_silent = silent_for >= SILENT_THRESHOLD_SECONDS
        state = _get_or_create_state(db, device)
        tenant_name = _tenant_name(db, device.tenant_id)

        if is_silent and state.status == "ok":
            state.status = "alerting"
            state.first_silent_at = now
            state.last_notified_at = now
            state.notify_count = 1
            body = (
                f"{device.hostname} has not checked in for over "
                f"{_humanize(silent_for)}.\n\n" + _device_summary(device, tenant_name)
            )
            if notify.send_alert_email(f"[Endpoint Shield] {device.hostname} is offline", body):
                sent += 1
            audit.record(
                db,
                action=audit.ALERT_TRIGGERED,
                outcome=audit.SUCCESS,
                tenant_id=device.tenant_id,
                target_type="device",
                target_id=device.hostname,
                detail=f"silent_for={_humanize(silent_for)}",
            )

        elif is_silent and state.status == "alerting":
            minutes_since_notify = (
                (now - state.last_notified_at).total_seconds() / 60 if state.last_notified_at else RENOTIFY_MINUTES
            )
            if minutes_since_notify >= RENOTIFY_MINUTES:
                state.last_notified_at = now
                state.notify_count += 1
                body = (
                    f"{device.hostname} is STILL offline "
                    f"(down {_humanize(silent_for)}, notification #{state.notify_count}).\n\n"
                    + _device_summary(device, tenant_name)
                )
                if notify.send_alert_email(f"[Endpoint Shield] {device.hostname} still offline", body):
                    sent += 1
                audit.record(
                    db,
                    action=audit.ALERT_ESCALATED,
                    outcome=audit.SUCCESS,
                    tenant_id=device.tenant_id,
                    target_type="device",
                    target_id=device.hostname,
                    detail=f"silent_for={_humanize(silent_for)} notify_count={state.notify_count}",
                )

        elif not is_silent and state.status == "alerting":
            outage_duration = (now - state.first_silent_at).total_seconds() if state.first_silent_at else None
            state.status = "ok"
            state.first_silent_at = None
            state.notify_count = 0
            body = (
                f"{device.hostname} is back online.\n\n" + _device_summary(device, tenant_name)
                + (f"\n\nOutage duration: {_humanize(outage_duration)}" if outage_duration is not None else "")
            )
            if notify.send_alert_email(f"[Endpoint Shield] {device.hostname} is back online", body):
                sent += 1
            audit.record(
                db,
                action=audit.ALERT_RESOLVED,
                outcome=audit.SUCCESS,
                tenant_id=device.tenant_id,
                target_type="device",
                target_id=device.hostname,
                detail=f"outage_duration={_humanize(outage_duration) if outage_duration is not None else 'unknown'}",
            )

        db.commit()

    return sent


async def monitor_loop() -> None:
    """Poll forever at POLL_SECONDS. Never exits on a single bad pass - one
    failed check should not stop future ones from running, the same
    reasoning app/audit.py's STRICT flag documents for audit writes."""
    print(
        f"monitor: started (threshold={SILENT_THRESHOLD_SECONDS}s, "
        f"poll={POLL_SECONDS}s, renotify={RENOTIFY_MINUTES}m, "
        f"email_configured={notify.configured()})",
        file=sys.stderr,
        flush=True,
    )
    while True:
        try:
            db = SessionLocal()
            try:
                await asyncio.to_thread(check_once, db)
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
            print(f"monitor: check pass failed - {exc}", file=sys.stderr, flush=True)
        await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    # Manual test path: `python -m app.monitor --once` runs a single pass
    # against the real configured database and exits - no need to wait for
    # POLL_SECONDS or fake a 10-minute-silent device by hand every time.
    from app.database import Base, engine

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        n = check_once(db)
        print(f"monitor: pass complete, {n} notification(s) sent/attempted")
    finally:
        db.close()
