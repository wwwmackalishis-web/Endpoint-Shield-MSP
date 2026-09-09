"""On-Call / Escalation Router Agent (fleet position 7).

7a. route_contacts()     - which of Endpoint Shield Solutions' own on-call
                           roster (app/models.py's OnCallContact - this is
                           the MSP's internal team, not a client's) should be
                           notified for an alert of a given severity.
7b. is_business_hours()  - the same routing depends on time of day; a
                           contact can opt out of business-hours or
                           after-hours notification independently.
7c. incident_sla_clock() - the live, per-incident version of the same idea
                           app/client_report.py's sla_scorecard() computes
                           retrospectively: given one alert's start time and
                           the tenant's contracted response-time target, how
                           much of that window is left right now. Mirrors
                           app/breach_clock.py's shape and thresholds on
                           purpose - a technician who already knows how to
                           read a breach clock reads this one for free.

Severity itself comes from app/incident_triage.py (fleet position 2) -
this module only decides who hears about it and how urgently, not how bad
it is.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional
from zoneinfo import ZoneInfo

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Business-hours window this MSP actually operates in. Configurable via
# environment variables, same pattern as every other MSP_* setting in this
# app (MSP_ALERT_*, MSP_SMTP_*) - nothing here changes for local dev unless
# you set them.
BUSINESS_TZ = os.environ.get("MSP_BUSINESS_TZ", "America/New_York")
BUSINESS_START_HOUR = int(os.environ.get("MSP_BUSINESS_START_HOUR", "9"))
BUSINESS_END_HOUR = int(os.environ.get("MSP_BUSINESS_END_HOUR", "17"))
BUSINESS_WEEKDAYS = {0, 1, 2, 3, 4}  # Monday=0 .. Friday=4, per datetime.weekday()

URGENT_FRACTION_REMAINING = 0.25

NOT_STARTED = "not_started"
ON_TRACK = "on_track"
URGENT = "urgent"
OVERDUE = "overdue"
MET = "met"


def is_business_hours(now_utc: Optional[datetime] = None) -> bool:
    """`now_utc` is naive UTC, matching every other timestamp in this
    schema (all set via datetime.utcnow()) - converted here to the
    configured business timezone for the actual comparison."""
    now_utc = now_utc or datetime.utcnow()
    local = now_utc.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(BUSINESS_TZ))
    return local.weekday() in BUSINESS_WEEKDAYS and BUSINESS_START_HOUR <= local.hour < BUSINESS_END_HOUR


def route_contacts(*, severity: str, contacts: Iterable, now_utc: Optional[datetime] = None) -> list:
    """7a + 7b combined: every active contact whose min_severity this alert
    meets or exceeds, and whose business/after-hours preference matches
    right now. `contacts` are OnCallContact rows or anything with the same
    attributes (see tests/test_escalation_router.py).
    """
    business = is_business_hours(now_utc)
    alert_rank = SEVERITY_RANK.get(severity, 0)
    routed = []
    for contact in contacts:
        if not getattr(contact, "active", True):
            continue
        if SEVERITY_RANK.get(getattr(contact, "min_severity", "low"), 0) > alert_rank:
            continue
        if business and not getattr(contact, "notify_business_hours", True):
            continue
        if not business and not getattr(contact, "notify_after_hours", True):
            continue
        routed.append(contact)
    return routed


def incident_sla_clock(*, triggered_at: Optional[datetime], sla_response_minutes: Optional[int],
                        resolved_at: Optional[datetime] = None, now: Optional[datetime] = None) -> dict:
    """7c: one incident's live standing against the contracted response
    target. Returns not_started when there's no SLA configured for this
    tenant at all - a technician should see "no target set", never a clock
    silently counting against a made-up number.
    """
    now = now or datetime.utcnow()
    if triggered_at is None or sla_response_minutes is None:
        return {"deadline": None, "met_at": None, "status": NOT_STARTED, "minutes_remaining": None}

    deadline = triggered_at + timedelta(minutes=sla_response_minutes)
    if resolved_at is not None:
        return {"deadline": deadline.isoformat(), "met_at": resolved_at.isoformat(), "status": MET,
                "minutes_remaining": None}

    remaining = (deadline - now).total_seconds() / 60
    if remaining <= 0:
        status = OVERDUE
    elif remaining <= sla_response_minutes * URGENT_FRACTION_REMAINING:
        status = URGENT
    else:
        status = ON_TRACK
    return {"deadline": deadline.isoformat(), "met_at": None, "status": status,
            "minutes_remaining": round(remaining, 1)}
