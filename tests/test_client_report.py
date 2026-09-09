from datetime import datetime, timedelta
from types import SimpleNamespace

from app import audit
from app.client_report import (
    EOL_WARNING_DAYS,
    build_html_report,
    build_report,
    sla_scorecard,
    translate_alerts,
    translate_maintenance_reminders,
    translate_patch_summary,
)


def make_eval(os_status="current", av_status="current", hostname="PC-1", eol_date=None, family="Windows 11"):
    return {
        "hostname": hostname,
        "os": {"status": os_status, "matched_family": family, "eol_date": eol_date},
        "antivirus": {"status": av_status},
    }


def make_event(action, target_id, timestamp):
    return SimpleNamespace(action=action, target_id=target_id, timestamp=timestamp)


EMPTY_SCORECARD = {"sla_response_minutes": None, "note": "No SLA response-time target is configured for this client."}


# ---- 5a: translation ----

def test_translate_patch_summary_all_clean():
    lines = translate_patch_summary([make_eval(), make_eval()])
    assert len(lines) == 1
    assert "up-to-date" in lines[0]


def test_translate_patch_summary_flags_eol_and_av():
    lines = translate_patch_summary([make_eval(os_status="end_of_life"), make_eval(av_status="disabled")])
    joined = " ".join(lines)
    assert "1 device" in joined
    assert "no longer" in joined.lower()
    assert "antivirus" in joined.lower()


def test_translate_patch_summary_no_technical_jargon():
    lines = translate_patch_summary([make_eval(os_status="end_of_life")])
    joined = " ".join(lines)
    assert "CVE" not in joined
    assert "164." not in joined


def test_translate_alerts_empty():
    assert "No devices" in translate_alerts([])[0]


def test_translate_alerts_formats_duration():
    lines = translate_alerts([{"hostname": "FRONT-DESK-01", "silent_seconds": 5400}])
    assert "FRONT-DESK-01" in lines[0]
    assert "hour" in lines[0]


# ---- 5a, continued: maintenance reminders ----

def test_no_reminders_when_everything_is_fine():
    lines = translate_maintenance_reminders(device_evaluations=[], backup_jobs=[], restore_test_jobs=[])
    assert "No maintenance items" in lines[0]


def test_upcoming_eol_within_window_is_flagged():
    now = datetime(2026, 1, 1)
    eol_date = (now + timedelta(days=30)).strftime("%Y-%m-%d")
    device = make_eval(os_status="current", hostname="FRONT-DESK-01", eol_date=eol_date, family="Windows 10")
    lines = translate_maintenance_reminders(
        device_evaluations=[device], backup_jobs=[], restore_test_jobs=[], now=now,
    )
    assert any("Windows 10" in line and "FRONT-DESK-01" in line for line in lines)


def test_eol_far_in_future_is_not_flagged():
    now = datetime(2026, 1, 1)
    eol_date = (now + timedelta(days=EOL_WARNING_DAYS + 10)).strftime("%Y-%m-%d")
    device = make_eval(os_status="current", eol_date=eol_date)
    lines = translate_maintenance_reminders(
        device_evaluations=[device], backup_jobs=[], restore_test_jobs=[], now=now,
    )
    assert "No maintenance items" in lines[0]


def test_already_eol_device_not_double_counted_here():
    # translate_patch_summary already covers an already-EOL device; the
    # maintenance-reminder EOL check only looks at status == "current".
    now = datetime(2026, 1, 1)
    device = make_eval(os_status="end_of_life", eol_date="2020-01-14")
    lines = translate_maintenance_reminders(
        device_evaluations=[device], backup_jobs=[], restore_test_jobs=[], now=now,
    )
    assert "No maintenance items" in lines[0]


def test_unhealthy_backup_job_is_flagged():
    lines = translate_maintenance_reminders(
        device_evaluations=[],
        backup_jobs=[{"job_name": "NAS-1", "status": "stale", "note": "Last successful backup was 40 hours ago"}],
        restore_test_jobs=[],
    )
    assert any("NAS-1" in line and "40 hours" in line for line in lines)


def test_unhealthy_restore_test_is_flagged():
    lines = translate_maintenance_reminders(
        device_evaluations=[],
        backup_jobs=[],
        restore_test_jobs=[{"job_name": "NAS-1", "status": "overdue", "note": "over the recommended interval"}],
    )
    assert any("NAS-1" in line for line in lines)


def test_healthy_backup_jobs_not_flagged():
    lines = translate_maintenance_reminders(
        device_evaluations=[],
        backup_jobs=[{"job_name": "NAS-1", "status": "ok", "note": None}],
        restore_test_jobs=[{"job_name": "NAS-1", "status": "ok", "note": None}],
    )
    assert "No maintenance items" in lines[0]


# ---- 5b: SLA scorecard ----

def test_scorecard_without_sla_target_configured():
    result = sla_scorecard([], sla_response_minutes=None)
    assert result["sla_response_minutes"] is None
    assert "is configured" in result["note"]


def test_scorecard_pairs_triggered_and_resolved():
    start = datetime(2026, 1, 1, 12, 0)
    events = [
        make_event(audit.ALERT_TRIGGERED, "PC-1", start),
        make_event(audit.ALERT_RESOLVED, "PC-1", start + timedelta(minutes=20)),
    ]
    result = sla_scorecard(events, sla_response_minutes=30)
    assert result["resolved_incidents"] == 1
    assert result["met_sla"] == 1
    assert result["missed_sla"] == 0
    assert result["percent_met"] == 100.0


def test_scorecard_flags_missed_sla():
    start = datetime(2026, 1, 1, 12, 0)
    events = [
        make_event(audit.ALERT_TRIGGERED, "PC-1", start),
        make_event(audit.ALERT_RESOLVED, "PC-1", start + timedelta(minutes=90)),
    ]
    result = sla_scorecard(events, sla_response_minutes=30)
    assert result["met_sla"] == 0
    assert result["missed_sla"] == 1


def test_scorecard_reports_still_open_incident():
    start = datetime(2026, 1, 1, 12, 0)
    now = start + timedelta(minutes=45)
    events = [make_event(audit.ALERT_TRIGGERED, "PC-1", start)]
    result = sla_scorecard(events, sla_response_minutes=30, now=now)
    assert result["resolved_incidents"] == 0
    assert len(result["still_open"]) == 1
    assert result["still_open"][0]["hostname"] == "PC-1"
    assert result["still_open"][0]["elapsed_minutes"] == 45.0


def test_scorecard_resolved_without_matching_trigger_is_ignored():
    events = [make_event(audit.ALERT_RESOLVED, "PC-1", datetime(2026, 1, 1))]
    result = sla_scorecard(events, sla_response_minutes=30)
    assert result["resolved_incidents"] == 0


# ---- 5c: report assembly ----

def test_build_report_includes_tenant_name_and_period():
    report = build_report(
        tenant_name="Riverside Dental",
        device_evaluations=[make_eval()],
        open_alerts=[],
        backup_jobs=[],
        restore_test_jobs=[],
        scorecard=EMPTY_SCORECARD,
        period_note="Covering the 30 days ending 2026-01-31.",
    )
    assert "Riverside Dental" in report["subject"]
    assert "Riverside Dental" in report["body"]
    assert "Covering the 30 days" in report["body"]
    assert "MAINTENANCE & REMINDERS" in report["body"]


def test_build_report_with_sla_scorecard():
    report = build_report(
        tenant_name="Riverside Dental",
        device_evaluations=[],
        open_alerts=[],
        backup_jobs=[],
        restore_test_jobs=[],
        scorecard={
            "sla_response_minutes": 30, "resolved_incidents": 2, "met_sla": 1,
            "missed_sla": 1, "percent_met": 50.0, "still_open": [],
        },
        period_note="Covering the 30 days ending 2026-01-31.",
    )
    assert "1 of 2 incidents" in report["body"]
    assert "50.0%" in report["body"]


def test_build_html_report_includes_logo_cid_and_sections():
    html = build_html_report(
        tenant_name="Riverside Dental",
        device_evaluations=[make_eval(os_status="end_of_life")],
        open_alerts=[{"hostname": "PC-1", "silent_seconds": 120}],
        backup_jobs=[],
        restore_test_jobs=[],
        scorecard=EMPTY_SCORECARD,
        period_note="Covering the 30 days ending 2026-01-31.",
    )
    assert "cid:endpoint-shield-logo" in html
    assert "Riverside Dental" in html
    assert "Fleet &amp; Security Status" in html or "Fleet & Security Status" in html
    assert "PC-1" in html


def test_build_html_report_escapes_tenant_name():
    html = build_html_report(
        tenant_name="<script>alert(1)</script>",
        device_evaluations=[],
        open_alerts=[],
        backup_jobs=[],
        restore_test_jobs=[],
        scorecard=EMPTY_SCORECARD,
        period_note="x",
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
