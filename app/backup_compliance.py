"""Backup & Continuity Verification Agent (fleet position 6).

6a. backup_status()       - is the most recent reported backup run for a job
                             both successful and recent enough.
6b. restore_test_status() - has anyone actually proven a backup from this
                             job is restorable, recently enough.

Both are honest about what they can and cannot see: this module only knows
what POST /agents/backup-report and POST /agents/restore-test-report have
been told (app/models.py's BackupRun / RestoreTest). A job that has never
reported in is "never_run"/"never_tested", not "failed" - the backup script
may simply not be wired up to report here yet, which is a different problem
than a backup that ran and failed.

The two thresholds below are intentionally different in spirit:
EXPECTED_BACKUP_INTERVAL_HOURS assumes a daily backup cadence, the common
case; RESTORE_TEST_INTERVAL_DAYS (90) is a best-practice recommendation for
this agent to flag proactively - tighter than the 12-month floor a HIPAA
risk analysis would treat as a compliance minimum. Flagging at 90 days here
does not mean waiting a year is itself a violation; it means this system
would rather surface it early.
"""

from datetime import datetime
from typing import Optional

STATUS_OK = "ok"
STATUS_STALE = "stale"
STATUS_FAILED = "failed"
STATUS_NEVER_RUN = "never_run"

STATUS_OVERDUE = "overdue"
STATUS_NEVER_TESTED = "never_tested"

# A daily backup with no margin would flag itself the moment the job runs a
# little late; 26 hours absorbs normal jitter without hiding a job that
# actually stopped running.
EXPECTED_BACKUP_INTERVAL_HOURS = 26

RESTORE_TEST_INTERVAL_DAYS = 90


def backup_status(latest_run, now: Optional[datetime] = None) -> dict:
    """`latest_run` is the most recent BackupRun for one job, or None if the
    job has never reported in."""
    now = now or datetime.utcnow()
    if latest_run is None:
        return {"status": STATUS_NEVER_RUN, "hours_since": None,
                "note": "No backup has ever been reported for this job."}

    hours_since = (now - latest_run.completed_at).total_seconds() / 3600
    if not latest_run.success:
        return {"status": STATUS_FAILED, "hours_since": round(hours_since, 1),
                "note": "The most recent backup run reported failure."}
    if hours_since > EXPECTED_BACKUP_INTERVAL_HOURS:
        return {"status": STATUS_STALE, "hours_since": round(hours_since, 1),
                "note": f"Last successful backup was {round(hours_since)} hours ago - over the "
                        f"{EXPECTED_BACKUP_INTERVAL_HOURS}-hour expected interval."}
    return {"status": STATUS_OK, "hours_since": round(hours_since, 1), "note": None}


def restore_test_status(latest_test, now: Optional[datetime] = None) -> dict:
    """`latest_test` is the most recent RestoreTest for one job, or None."""
    now = now or datetime.utcnow()
    if latest_test is None:
        return {"status": STATUS_NEVER_TESTED, "days_since": None,
                "note": "No restore test has ever been reported for this job."}

    days_since = (now - latest_test.tested_at).total_seconds() / 86400
    if not latest_test.success:
        return {"status": STATUS_FAILED, "days_since": round(days_since, 1),
                "note": "The most recent restore test reported failure - this backup has not been proven usable."}
    if days_since > RESTORE_TEST_INTERVAL_DAYS:
        return {"status": STATUS_OVERDUE, "days_since": round(days_since, 1),
                "note": f"Last successful restore test was {round(days_since)} days ago - over the "
                        f"{RESTORE_TEST_INTERVAL_DAYS}-day recommended interval."}
    return {"status": STATUS_OK, "days_since": round(days_since, 1), "note": None}


def latest_by_job(rows: list, timestamp_field: str) -> dict:
    """Reduce a flat list of BackupRun/RestoreTest rows to the single most
    recent row per job_name. Done in Python rather than a per-database
    DISTINCT ON so this works the same against SQLite (local dev) and
    Postgres (Render) without two query paths."""
    latest: dict = {}
    for row in rows:
        current = latest.get(row.job_name)
        if current is None or getattr(row, timestamp_field) > getattr(current, timestamp_field):
            latest[row.job_name] = row
    return latest
