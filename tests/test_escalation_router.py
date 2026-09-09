from datetime import datetime, timedelta
from types import SimpleNamespace

from app.escalation_router import (
    MET,
    NOT_STARTED,
    ON_TRACK,
    OVERDUE,
    URGENT,
    incident_sla_clock,
    is_business_hours,
    route_contacts,
)


def make_contact(min_severity="low", notify_business_hours=True, notify_after_hours=True, active=True):
    return SimpleNamespace(
        min_severity=min_severity, notify_business_hours=notify_business_hours,
        notify_after_hours=notify_after_hours, active=active,
    )


# ---- 7b: business hours ----
# 2026-01-05 is a Monday. 15:00 UTC = 10:00 America/New_York (EST, UTC-5).

def test_weekday_daytime_is_business_hours():
    assert is_business_hours(datetime(2026, 1, 5, 15, 0)) is True


def test_weekday_night_is_after_hours():
    assert is_business_hours(datetime(2026, 1, 5, 22, 0)) is False


def test_weekend_daytime_is_after_hours():
    # 2026-01-10 is a Saturday.
    assert is_business_hours(datetime(2026, 1, 10, 15, 0)) is False


# ---- 7a: contact routing ----

def test_low_severity_only_reaches_low_tier_contacts():
    contacts = [make_contact(min_severity="low"), make_contact(min_severity="critical")]
    routed = route_contacts(severity="low", contacts=contacts, now_utc=datetime(2026, 1, 5, 15, 0))
    assert len(routed) == 1


def test_critical_severity_reaches_everyone():
    contacts = [make_contact(min_severity="low"), make_contact(min_severity="critical")]
    routed = route_contacts(severity="critical", contacts=contacts, now_utc=datetime(2026, 1, 5, 15, 0))
    assert len(routed) == 2


def test_inactive_contact_never_routed():
    contacts = [make_contact(min_severity="low", active=False)]
    routed = route_contacts(severity="critical", contacts=contacts, now_utc=datetime(2026, 1, 5, 15, 0))
    assert routed == []


def test_after_hours_opt_out_respected():
    contacts = [make_contact(min_severity="low", notify_after_hours=False)]
    business_time = datetime(2026, 1, 5, 15, 0)
    after_hours_time = datetime(2026, 1, 5, 22, 0)
    assert len(route_contacts(severity="high", contacts=contacts, now_utc=business_time)) == 1
    assert len(route_contacts(severity="high", contacts=contacts, now_utc=after_hours_time)) == 0


def test_business_hours_opt_out_respected():
    contacts = [make_contact(min_severity="low", notify_business_hours=False)]
    business_time = datetime(2026, 1, 5, 15, 0)
    after_hours_time = datetime(2026, 1, 5, 22, 0)
    assert len(route_contacts(severity="high", contacts=contacts, now_utc=business_time)) == 0
    assert len(route_contacts(severity="high", contacts=contacts, now_utc=after_hours_time)) == 1


# ---- 7c: SLA clock ----

def test_no_sla_configured_is_not_started():
    result = incident_sla_clock(triggered_at=datetime(2026, 1, 1), sla_response_minutes=None)
    assert result["status"] == NOT_STARTED


def test_no_trigger_time_is_not_started():
    result = incident_sla_clock(triggered_at=None, sla_response_minutes=30)
    assert result["status"] == NOT_STARTED


def test_on_track_shortly_after_trigger():
    start = datetime(2026, 1, 1, 12, 0)
    result = incident_sla_clock(triggered_at=start, sla_response_minutes=60, now=start + timedelta(minutes=5))
    assert result["status"] == ON_TRACK


def test_urgent_near_deadline():
    start = datetime(2026, 1, 1, 12, 0)
    result = incident_sla_clock(triggered_at=start, sla_response_minutes=60, now=start + timedelta(minutes=50))
    assert result["status"] == URGENT


def test_overdue_past_deadline():
    start = datetime(2026, 1, 1, 12, 0)
    result = incident_sla_clock(triggered_at=start, sla_response_minutes=60, now=start + timedelta(minutes=61))
    assert result["status"] == OVERDUE


def test_met_when_resolved():
    start = datetime(2026, 1, 1, 12, 0)
    resolved = start + timedelta(minutes=90)
    result = incident_sla_clock(triggered_at=start, sla_response_minutes=60, resolved_at=resolved,
                                 now=start + timedelta(minutes=120))
    assert result["status"] == MET
