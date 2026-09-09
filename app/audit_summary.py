"""Audit Log Summarizer - Compliance Documentation Agent, subagent 4a.

Turns the append-only audit_events table (see app/audit.py) into the kind of
plain-English record a practice owner or an OCR investigator can actually
read, instead of a JSON table of actions and timestamps. This is a read-only
view over the same rows GET /api/v1/audit-log already exposes - it adds
narrative and counts, it does not add access to anything new.

Nothing here writes to audit_events, and nothing here should ever render a
device's `notes` or `location` value - see app/audit.py's rule 2. The
`detail` field on a device.update row is already restricted to field NAMES
("fields=location,notes"), never values, so summarizing it is safe by
construction as long as this module keeps rendering `detail` as opaque text
rather than trying to parse and reformat it into something more elaborate.
"""

from datetime import datetime
from typing import Iterable, List, Optional

from app.audit import (
    ALERT_ESCALATED,
    ALERT_RESOLVED,
    ALERT_TRIGGERED,
    DEVICE_CREATE,
    DEVICE_DELETE,
    DEVICE_UPDATE,
    LOGIN_FAILURE,
    LOGIN_SUCCESS,
)

# Caps how many individual narrative lines one summary response builds. A
# monthly compliance pull for a busy tenant can be thousands of rows; turning
# all of them into sentences is both slow and unreadable. The counts (by
# action / by outcome) still cover the full queried range regardless of this
# cap - only the line-by-line narrative is truncated.
MAX_NARRATIVE_LINES = 500


def _fields_from_detail(detail: Optional[str]) -> str:
    """Render audit.py's "fields=a,b,c" detail string as "a, b, c".

    Falls back to the raw detail unchanged if it isn't in that shape, so an
    unexpected detail string still shows up rather than disappearing.
    """
    if not detail:
        return ""
    if detail.startswith("fields="):
        names = detail[len("fields="):]
        return ", ".join(n for n in names.split(",") if n)
    return detail


def _narrate(event) -> str:
    ts = event.timestamp.strftime("%Y-%m-%d %H:%M UTC") if event.timestamp else "unknown time"
    actor = event.actor_username or "unknown user"

    if event.action == LOGIN_SUCCESS:
        return f"{ts} — {actor} logged in"
    if event.action == LOGIN_FAILURE:
        reason = f" ({event.detail})" if event.detail else ""
        return f"{ts} — failed login attempt for '{actor}'{reason}"
    if event.action == DEVICE_CREATE:
        return f"{ts} — {actor} added device {event.target_id}"
    if event.action == DEVICE_UPDATE:
        fields = _fields_from_detail(event.detail)
        changed = f" (changed: {fields})" if fields else ""
        return f"{ts} — {actor} updated device {event.target_id}{changed}"
    if event.action == DEVICE_DELETE:
        return f"{ts} — {actor} removed device {event.target_id}"
    if event.action == ALERT_TRIGGERED:
        return f"{ts} — ALERT: device {event.target_id} stopped reporting"
    if event.action == ALERT_ESCALATED:
        return f"{ts} — ALERT ESCALATED: device {event.target_id} still silent"
    if event.action == ALERT_RESOLVED:
        return f"{ts} — RESOLVED: device {event.target_id} back online"

    # Unknown action (future action type not yet given its own phrasing
    # above) - still produce a readable line instead of dropping the event.
    outcome = f" ({event.outcome})" if event.outcome else ""
    target = f" on {event.target_type} {event.target_id}" if event.target_id else ""
    return f"{ts} — {actor} {event.action}{target}{outcome}"


def _security_posture(by_action: dict) -> List[str]:
    """Factual, derived-from-counts statements only - never a boilerplate
    assurance. The failed-login count below is the one piece of "was there
    unauthorized access" evidence this table actually has; state the real
    number either way instead of asserting a clean result that wasn't
    checked. See app/audit.py's LOGIN_FAILURE - it's written on every failed
    login, known or unknown username, so a 0 here is a real 0, not an
    absence of data.
    """
    failures = by_action.get(LOGIN_FAILURE, 0)
    if failures == 0:
        return ["No failed login attempts were recorded in this period."]
    if failures == 1:
        return ["1 failed login attempt was recorded in this period - review the audit log for the account involved."]
    return [
        f"{failures} failed login attempts were recorded in this period - "
        "review the audit log for the account(s) involved."
    ]


def summarize_events(events: Iterable) -> dict:
    """Build counts and a plain-English narrative from AuditEvent rows.

    `events` should already be filtered to one tenant and one time window by
    the caller (see GET /api/v1/audit-log/summary in app/main.py) - this
    function does no scoping of its own, the same way app/audit.py does no
    scoping of its own for writes.
    """
    events = list(events)

    by_action: dict = {}
    by_outcome: dict = {}
    actors: set = set()
    earliest: Optional[datetime] = None
    latest: Optional[datetime] = None

    for event in events:
        by_action[event.action] = by_action.get(event.action, 0) + 1
        by_outcome[event.outcome] = by_outcome.get(event.outcome, 0) + 1
        if event.actor_username:
            actors.add(event.actor_username)
        if event.timestamp:
            if earliest is None or event.timestamp < earliest:
                earliest = event.timestamp
            if latest is None or event.timestamp > latest:
                latest = event.timestamp

    narrative: List[str] = [_narrate(event) for event in events[:MAX_NARRATIVE_LINES]]

    return {
        "total_events": len(events),
        "earliest": earliest.isoformat() if earliest else None,
        "latest": latest.isoformat() if latest else None,
        "distinct_actors": sorted(actors),
        "by_action": by_action,
        "by_outcome": by_outcome,
        "security_posture": _security_posture(by_action),
        "narrative": narrative,
        "narrative_truncated": len(events) > MAX_NARRATIVE_LINES,
    }
