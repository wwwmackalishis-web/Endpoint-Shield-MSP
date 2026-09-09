"""Incident Triage Agent (fleet position 2) - severity, root-cause, response.

All three subagents are deterministic rule engines over data this system
already has (app/monitor.py's DeviceAlertState, the audit trail) - none of
them call out to a model. That keeps triage explainable: a technician can
see exactly which fact produced which grade, the same way every other
"agent" in this fleet (the silent-endpoint monitor, the breach clock) is a
rule engine, not an LLM in the loop.

2a. classify_severity()   - grades a silent-device alert from its own
                             duration and escalation count.
2b. draft_root_cause()    - looks for a device.update audit event shortly
                             before the alert started; a config change right
                             before an outage is a real, checkable signal.
                             Absent that, it says so rather than guessing.
2c. recommend_response()  - maps (severity, root_cause) to one of a fixed
                             set of next actions. Always for human sign-off -
                             nothing here dispatches a technician or closes
                             an alert on its own.
"""

from datetime import datetime, timedelta
from typing import Iterable, Optional

# Mirrors app/monitor.py's own thresholds so triage's idea of "how bad is
# this" lines up with the same numbers that decided whether to alert and
# whether to escalate in the first place.
from app.monitor import RENOTIFY_MINUTES, SILENT_THRESHOLD_SECONDS

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# A change made in this window before an alert started is treated as a
# plausible trigger. Long enough to catch "technician made a change, walked
# away, it broke ten minutes later"; short enough not to blame something
# from three days ago.
ROOT_CAUSE_LOOKBACK_MINUTES = 120

# Free-text keyword triage for a manually-filed client report that has no
# device-silence signal behind it at all (e.g. "the front desk PC won't
# boot"). Deliberately small and literal - this is a first-pass filter for a
# human, not a classifier that should be trusted to catch everything.
CRITICAL_KEYWORDS = ("ransomware", "encrypted", "can't access", "cannot access", "breach", "down for everyone")
HIGH_KEYWORDS = ("down", "outage", "can't log in", "cannot log in", "virus", "malware")


def classify_severity(*, silent_seconds: Optional[int] = None, notify_count: int = 0,
                       report_text: Optional[str] = None) -> str:
    """Grade one signal. Pass EITHER a device-silence duration (from
    DeviceAlertState) OR free-text client-report wording, whichever this
    signal actually has - a manually-filed report has no silent_seconds,
    and an automated alert has no report_text.
    """
    if silent_seconds is not None:
        if notify_count >= 3 or silent_seconds >= RENOTIFY_MINUTES * 60 * 2:
            return SEVERITY_CRITICAL
        if notify_count >= 1 or silent_seconds >= SILENT_THRESHOLD_SECONDS * 2:
            return SEVERITY_HIGH
        return SEVERITY_MEDIUM

    if report_text:
        text = report_text.lower()
        if any(kw in text for kw in CRITICAL_KEYWORDS):
            return SEVERITY_CRITICAL
        if any(kw in text for kw in HIGH_KEYWORDS):
            return SEVERITY_HIGH
        return SEVERITY_LOW

    return SEVERITY_LOW


def draft_root_cause(*, alert_started_at: Optional[datetime], recent_events: Iterable,
                      now: Optional[datetime] = None) -> str:
    """`recent_events` is that device's own audit rows (target_type="device",
    matching target_id), newest-first or any order - this scans all of them.
    Only ever names WHICH fields changed (from audit.changed_fields' output,
    already PHI-safe) and WHEN, never the audit detail's raw text beyond
    that, since detail on a device.update row is already scrubbed to field
    names by app/audit.py.
    """
    if alert_started_at is None:
        return "No alert start time available - cannot correlate against recent changes."

    window_start = alert_started_at - timedelta(minutes=ROOT_CAUSE_LOOKBACK_MINUTES)
    candidates = [
        e for e in recent_events
        if e.action == "device.update" and e.timestamp and window_start <= e.timestamp <= alert_started_at
    ]
    if candidates:
        latest = max(candidates, key=lambda e: e.timestamp)
        minutes_before = round((alert_started_at - latest.timestamp).total_seconds() / 60)
        who = latest.actor_username or "an unknown user"
        return (
            f"Likely cause: {who} changed this device's record ({latest.detail or 'fields unspecified'}) "
            f"{minutes_before} minute(s) before the alert started. Review that change first."
        )
    return (
        "No configuration change found in the audit trail in the "
        f"{ROOT_CAUSE_LOOKBACK_MINUTES} minutes before this alert - likely a connectivity, "
        "power, or hardware issue rather than something changed in this system."
    )


def recommend_response(*, severity: str, root_cause: str) -> str:
    """One fixed recommendation per (severity, has-a-likely-config-cause)
    pair. This is a draft for a technician to accept or override, not an
    instruction the system acts on - nothing calls this and then does
    anything automatically.
    """
    change_implicated = root_cause.startswith("Likely cause:")

    if severity == SEVERITY_CRITICAL:
        if change_implicated:
            return "Roll back the implicated change immediately, then confirm the device reports back in."
        return "Escalate to on-call now and dispatch an on-site check - treat as hardware/power failure until ruled out."
    if severity == SEVERITY_HIGH:
        if change_implicated:
            return "Review the implicated change with whoever made it before rolling it back; confirm recovery within the hour."
        return "Contact the site to confirm power/network status; escalate to on-site if unconfirmed within the hour."
    if severity == SEVERITY_MEDIUM:
        return "Monitor - no action needed yet. Re-triage if this device is still silent at the next escalation."
    return "Log and monitor; no immediate action required."


def triage_alert(*, silent_seconds: Optional[int], notify_count: int, alert_started_at: Optional[datetime],
                  recent_events: Iterable, now: Optional[datetime] = None) -> dict:
    """The full 2a/2b/2c pipeline for one automated device alert."""
    severity = classify_severity(silent_seconds=silent_seconds, notify_count=notify_count)
    root_cause = draft_root_cause(alert_started_at=alert_started_at, recent_events=recent_events, now=now)
    response = recommend_response(severity=severity, root_cause=root_cause)
    return {"severity": severity, "root_cause": root_cause, "recommended_response": response}
