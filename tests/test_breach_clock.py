from datetime import datetime, timedelta
from types import SimpleNamespace

from app.breach_clock import (
    BA_NOTIFICATION_HOURS,
    MET,
    NOT_STARTED,
    ON_TRACK,
    OVERDUE,
    REGULATORY_NOTIFICATION_DAYS,
    URGENT,
    status_for,
)


def make_incident(**overrides):
    defaults = dict(
        confirmed_at=None,
        ba_notified_covered_entity_at=None,
        individuals_notified_at=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_not_started_before_confirmation():
    incident = make_incident()
    result = status_for(incident, now=datetime(2026, 1, 1))
    assert result["ba_to_covered_entity"].status == NOT_STARTED
    assert result["regulatory_60_day"].status == NOT_STARTED
    assert result["ba_to_covered_entity"].deadline is None


def test_on_track_just_after_confirmation():
    confirmed = datetime(2026, 1, 1, 0, 0)
    incident = make_incident(confirmed_at=confirmed)
    result = status_for(incident, now=confirmed + timedelta(hours=1))
    assert result["ba_to_covered_entity"].status == ON_TRACK
    assert result["regulatory_60_day"].status == ON_TRACK
    assert result["ba_to_covered_entity"].deadline == confirmed + timedelta(hours=BA_NOTIFICATION_HOURS)


def test_urgent_inside_final_quarter_of_window():
    confirmed = datetime(2026, 1, 1, 0, 0)
    # 72-hour window; 25% remaining = 18 hours left.
    incident = make_incident(confirmed_at=confirmed)
    result = status_for(incident, now=confirmed + timedelta(hours=72 - 10))
    assert result["ba_to_covered_entity"].status == URGENT


def test_overdue_past_deadline():
    confirmed = datetime(2026, 1, 1, 0, 0)
    incident = make_incident(confirmed_at=confirmed)
    result = status_for(incident, now=confirmed + timedelta(hours=BA_NOTIFICATION_HOURS + 1))
    ba = result["ba_to_covered_entity"]
    assert ba.status == OVERDUE
    assert ba.hours_remaining < 0


def test_met_stops_the_clock_even_past_deadline():
    confirmed = datetime(2026, 1, 1, 0, 0)
    notified = confirmed + timedelta(hours=10)
    incident = make_incident(confirmed_at=confirmed, ba_notified_covered_entity_at=notified)
    result = status_for(incident, now=confirmed + timedelta(hours=BA_NOTIFICATION_HOURS + 1))
    ba = result["ba_to_covered_entity"]
    assert ba.status == MET
    assert ba.met_at == notified


def test_regulatory_clock_uses_individuals_notified_not_ba_notified():
    confirmed = datetime(2026, 1, 1, 0, 0)
    incident = make_incident(
        confirmed_at=confirmed,
        ba_notified_covered_entity_at=confirmed + timedelta(hours=10),
        individuals_notified_at=None,
    )
    result = status_for(incident, now=confirmed + timedelta(days=1))
    assert result["ba_to_covered_entity"].status == MET
    assert result["regulatory_60_day"].status == ON_TRACK


def test_regulatory_window_is_sixty_days():
    confirmed = datetime(2026, 1, 1, 0, 0)
    incident = make_incident(confirmed_at=confirmed)
    result = status_for(incident, now=confirmed + timedelta(hours=1))
    expected_deadline = confirmed + timedelta(days=REGULATORY_NOTIFICATION_DAYS)
    assert result["regulatory_60_day"].deadline == expected_deadline
