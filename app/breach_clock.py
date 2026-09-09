"""Breach-Notification Clock - Compliance Documentation Agent, subagent 4c.

Two deadlines start ticking the moment an incident is confirmed as a
reportable breach (BreachIncident.confirmed_at in app/models.py), and
app/monitor.py already names both of them:

1. The BAA's 72-hour clock: a business associate notifying the covered
   entity. This is a CONTRACT term, not a statute - the actual number lives
   in whatever BAA Endpoint Shield Solutions has signed, and 72 hours is the
   common figure such templates use. BA_NOTIFICATION_HOURS is a default, not
   a citation - if a real signed BAA specifies something else, that value
   should change to match the paper it is tracking, not the other way round.
2. HIPAA's own 60-day clock (45 CFR §164.404(b), §164.406, §164.408): notice
   to affected individuals, and (for 500+ individuals) to HHS and the media,
   "without unreasonable delay and in no case later than 60 days" after
   discovery. REGULATORY_NOTIFICATION_DAYS is the statute; unlike the 72-hour
   figure, this one is not configurable per client.

Deliberately computed live from timestamps rather than stored as a
status/deadline pair on the row: policy changes (a renegotiated BAA) or even
just the passage of time between a page load and a dashboard refresh would
otherwise leave a stored status stale. status_for() re-derives the truth
every time it's called, the same way app/main.py's fleet_status() re-derives
a device's online/stale/offline status from last_seen rather than storing it.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

BA_NOTIFICATION_HOURS = int(os.environ.get("MSP_BAA_NOTIFICATION_HOURS", "72"))
REGULATORY_NOTIFICATION_DAYS = 60

# A clock reading this fraction of its window or less is "urgent" - still
# achievable, but not something to discover on the last day. Same 25% figure
# for both clocks so "urgent" means the same thing everywhere in the API,
# even though the two windows are wildly different lengths.
URGENT_FRACTION_REMAINING = 0.25

NOT_STARTED = "not_started"
ON_TRACK = "on_track"
URGENT = "urgent"
OVERDUE = "overdue"
MET = "met"


@dataclass
class ClockStatus:
    name: str
    deadline: Optional[datetime]
    met_at: Optional[datetime]
    status: str
    # Negative once overdue. None while not_started (no deadline to measure
    # against yet).
    hours_remaining: Optional[float]


def _clock(
    name: str,
    confirmed_at: Optional[datetime],
    window: timedelta,
    met_at: Optional[datetime],
    now: datetime,
) -> ClockStatus:
    if confirmed_at is None:
        return ClockStatus(name=name, deadline=None, met_at=met_at, status=NOT_STARTED, hours_remaining=None)

    deadline = confirmed_at + window
    if met_at is not None:
        return ClockStatus(name=name, deadline=deadline, met_at=met_at, status=MET, hours_remaining=None)

    remaining = deadline - now
    hours_remaining = remaining.total_seconds() / 3600
    window_hours = window.total_seconds() / 3600
    if remaining.total_seconds() <= 0:
        status = OVERDUE
    elif hours_remaining <= window_hours * URGENT_FRACTION_REMAINING:
        status = URGENT
    else:
        status = ON_TRACK
    return ClockStatus(name=name, deadline=deadline, met_at=None, status=status, hours_remaining=hours_remaining)


def status_for(incident, now: Optional[datetime] = None) -> dict:
    """Both clocks for one BreachIncident, as of `now` (default: real time).

    `incident` needs only the attributes BreachIncident defines - a plain
    object works fine in tests, no database required (see
    tests/test_breach_clock.py).
    """
    now = now or datetime.utcnow()

    ba_clock = _clock(
        "ba_to_covered_entity",
        incident.confirmed_at,
        timedelta(hours=BA_NOTIFICATION_HOURS),
        incident.ba_notified_covered_entity_at,
        now,
    )
    regulatory_clock = _clock(
        "regulatory_60_day",
        incident.confirmed_at,
        timedelta(days=REGULATORY_NOTIFICATION_DAYS),
        # The regulatory clock covers individuals, HHS, and media notice
        # alike; individuals_notified_at is the one every reportable breach
        # has, so it's the one that stops this clock. A large breach with a
        # separate regulator_notified_at can still lag behind - that is a
        # real, distinct fact worth surfacing, not folded in here.
        incident.individuals_notified_at,
        now,
    )

    return {
        "ba_to_covered_entity": ba_clock,
        "regulatory_60_day": regulatory_clock,
    }


def clock_to_dict(clock: ClockStatus) -> dict:
    """JSON-safe rendering of one ClockStatus, for the API routes."""
    return {
        "deadline": clock.deadline.isoformat() if clock.deadline else None,
        "met_at": clock.met_at.isoformat() if clock.met_at else None,
        "status": clock.status,
        "hours_remaining": (
            round(clock.hours_remaining, 1) if clock.hours_remaining is not None else None
        ),
    }
