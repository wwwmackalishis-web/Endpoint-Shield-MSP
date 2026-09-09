from datetime import datetime, timedelta
from types import SimpleNamespace

from app.backup_compliance import (
    EXPECTED_BACKUP_INTERVAL_HOURS,
    RESTORE_TEST_INTERVAL_DAYS,
    STATUS_FAILED,
    STATUS_NEVER_RUN,
    STATUS_NEVER_TESTED,
    STATUS_OK,
    STATUS_OVERDUE,
    STATUS_STALE,
    backup_status,
    latest_by_job,
    restore_test_status,
)


def make_run(job_name="NAS-1", completed_at=None, success=True):
    return SimpleNamespace(job_name=job_name, completed_at=completed_at, success=success)


def make_test(job_name="NAS-1", tested_at=None, success=True):
    return SimpleNamespace(job_name=job_name, tested_at=tested_at, success=success)


# ---- 6a: backup status ----

def test_never_run_is_flagged():
    result = backup_status(None)
    assert result["status"] == STATUS_NEVER_RUN


def test_recent_success_is_ok():
    now = datetime(2026, 1, 2, 12, 0)
    run = make_run(completed_at=now - timedelta(hours=5))
    result = backup_status(run, now=now)
    assert result["status"] == STATUS_OK


def test_stale_backup_is_flagged():
    now = datetime(2026, 1, 2, 12, 0)
    run = make_run(completed_at=now - timedelta(hours=EXPECTED_BACKUP_INTERVAL_HOURS + 5))
    result = backup_status(run, now=now)
    assert result["status"] == STATUS_STALE


def test_failed_backup_is_flagged_even_if_recent():
    now = datetime(2026, 1, 2, 12, 0)
    run = make_run(completed_at=now - timedelta(hours=1), success=False)
    result = backup_status(run, now=now)
    assert result["status"] == STATUS_FAILED


# ---- 6b: restore test status ----

def test_never_tested_is_flagged():
    result = restore_test_status(None)
    assert result["status"] == STATUS_NEVER_TESTED


def test_recent_successful_test_is_ok():
    now = datetime(2026, 1, 2)
    test = make_test(tested_at=now - timedelta(days=10))
    result = restore_test_status(test, now=now)
    assert result["status"] == STATUS_OK


def test_overdue_restore_test_is_flagged():
    now = datetime(2026, 1, 2)
    test = make_test(tested_at=now - timedelta(days=RESTORE_TEST_INTERVAL_DAYS + 5))
    result = restore_test_status(test, now=now)
    assert result["status"] == STATUS_OVERDUE


def test_failed_restore_test_is_flagged_even_if_recent():
    now = datetime(2026, 1, 2)
    test = make_test(tested_at=now - timedelta(days=1), success=False)
    result = restore_test_status(test, now=now)
    assert result["status"] == STATUS_FAILED


# ---- grouping ----

def test_latest_by_job_picks_most_recent_per_job():
    rows = [
        make_run(job_name="NAS-1", completed_at=datetime(2026, 1, 1)),
        make_run(job_name="NAS-1", completed_at=datetime(2026, 1, 3)),
        make_run(job_name="NAS-2", completed_at=datetime(2026, 1, 2)),
    ]
    latest = latest_by_job(rows, "completed_at")
    assert latest["NAS-1"].completed_at == datetime(2026, 1, 3)
    assert latest["NAS-2"].completed_at == datetime(2026, 1, 2)


def test_latest_by_job_empty_list():
    assert latest_by_job([], "completed_at") == {}
