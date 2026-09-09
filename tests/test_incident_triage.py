from datetime import datetime, timedelta
from types import SimpleNamespace

from app.incident_triage import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    classify_severity,
    draft_root_cause,
    recommend_response,
    triage_alert,
)


def make_event(**overrides):
    defaults = dict(timestamp=None, action="device.update", actor_username="jsmith", detail="fields=location")
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---- 2a: severity ----

def test_fresh_alert_is_medium():
    assert classify_severity(silent_seconds=650, notify_count=0) == SEVERITY_MEDIUM


def test_repeated_notifications_are_critical():
    assert classify_severity(silent_seconds=650, notify_count=3) == SEVERITY_CRITICAL


def test_long_silence_without_notifies_is_high():
    assert classify_severity(silent_seconds=5000, notify_count=0) == SEVERITY_HIGH


def test_report_text_with_ransomware_is_critical():
    assert classify_severity(report_text="Front desk PC files got encrypted overnight") == SEVERITY_CRITICAL


def test_report_text_generic_is_low():
    assert classify_severity(report_text="Printer is being slow today") == SEVERITY_LOW


# ---- 2b: root cause ----

def test_root_cause_finds_recent_change():
    alert_start = datetime(2026, 1, 1, 12, 0)
    events = [make_event(timestamp=alert_start - timedelta(minutes=10), actor_username="jsmith", detail="fields=ip")]
    result = draft_root_cause(alert_started_at=alert_start, recent_events=events)
    assert "jsmith" in result
    assert "10 minute" in result


def test_root_cause_ignores_changes_outside_window():
    alert_start = datetime(2026, 1, 1, 12, 0)
    events = [make_event(timestamp=alert_start - timedelta(hours=5))]
    result = draft_root_cause(alert_started_at=alert_start, recent_events=events)
    assert "No configuration change found" in result


def test_root_cause_ignores_non_update_actions():
    alert_start = datetime(2026, 1, 1, 12, 0)
    events = [make_event(timestamp=alert_start - timedelta(minutes=5), action="login.success")]
    result = draft_root_cause(alert_started_at=alert_start, recent_events=events)
    assert "No configuration change found" in result


def test_root_cause_without_start_time():
    assert "No alert start time" in draft_root_cause(alert_started_at=None, recent_events=[])


# ---- 2c: response recommendation ----

def test_critical_with_change_recommends_rollback():
    rec = recommend_response(severity=SEVERITY_CRITICAL, root_cause="Likely cause: jsmith changed...")
    assert "Roll back" in rec


def test_critical_without_change_recommends_dispatch():
    rec = recommend_response(severity=SEVERITY_CRITICAL, root_cause="No configuration change found...")
    assert "dispatch" in rec.lower()


def test_medium_recommends_monitor():
    assert "Monitor" in recommend_response(severity=SEVERITY_MEDIUM, root_cause="No configuration change found...")


# ---- full pipeline ----

def test_triage_alert_end_to_end():
    alert_start = datetime(2026, 1, 1, 12, 0)
    events = [make_event(timestamp=alert_start - timedelta(minutes=15))]
    result = triage_alert(
        silent_seconds=5000, notify_count=2, alert_started_at=alert_start, recent_events=events,
    )
    assert result["severity"] == SEVERITY_HIGH
    assert "jsmith" in result["root_cause"]
    assert isinstance(result["recommended_response"], str) and result["recommended_response"]
