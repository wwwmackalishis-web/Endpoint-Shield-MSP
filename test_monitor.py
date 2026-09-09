"""One-off verification script for the new alerting agent.

Run from the project root with the project's own venv:
    venv\\Scripts\\python.exe test_monitor.py

Uses a throwaway SQLite file (never devices.db) so this cannot touch real
device data. Prints PASS/FAIL lines; exits 1 on any failure.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta

# Point at a throwaway DB BEFORE importing anything that touches app.database.
test_db = os.path.join(tempfile.gettempdir(), "monitor_test.db")
if os.path.exists(test_db):
    os.remove(test_db)
os.environ["MSP_DB_PATH"] = test_db
os.environ["MSP_ALERT_ENABLED"] = "0"  # don't start the background loop for this test

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


# --- 1. Smoke-test that app.main still imports cleanly (main.py was edited) ---
try:
    import app.main  # noqa: F401
    check("app.main imports without error", True)
except Exception as exc:
    check(f"app.main imports without error (error: {exc})", False)
    raise

from app import monitor
from app.database import Base, SessionLocal, engine
from app.models import AuditEvent, Device, DeviceAlertState, Tenant

Base.metadata.create_all(bind=engine)

db = SessionLocal()
tenant = Tenant(name="Test Dental Office")
db.add(tenant)
db.flush()

device = Device(
    hostname="TEST-STALE-PC",
    ip="10.0.0.5",
    os="Windows 11",
    last_seen=datetime.utcnow() - timedelta(minutes=20),  # well past the 600s default threshold
    tenant_id=tenant.id,
)
db.add(device)
db.commit()

# --- 2. First pass: device is silent past threshold -> should trigger an alert ---
sent = monitor.check_once(db)
check("first pass ran without raising", True)

state = db.query(DeviceAlertState).filter(DeviceAlertState.hostname == "TEST-STALE-PC").first()
check("alert state created", state is not None)
check("alert state status == 'alerting'", state and state.status == "alerting")
check("notify_count == 1", state and state.notify_count == 1)
check("first_silent_at set", state and state.first_silent_at is not None)

triggered = (
    db.query(AuditEvent)
    .filter(AuditEvent.action == "alert.triggered", AuditEvent.target_id == "TEST-STALE-PC")
    .first()
)
check("audit row for alert.triggered written", triggered is not None)
check("audit row scoped to correct tenant", triggered and triggered.tenant_id == tenant.id)

# --- 3. Second pass immediately after: still silent, but inside the re-notify
#         window -> should NOT send another notification yet ---
sent2 = monitor.check_once(db)
db.refresh(state)
check("no re-notify inside the renotify window (notify_count still 1)", state.notify_count == 1)

escalated_count = (
    db.query(AuditEvent).filter(AuditEvent.action == "alert.escalated", AuditEvent.target_id == "TEST-STALE-PC").count()
)
check("no premature escalation audit row", escalated_count == 0)

# --- 4. Device reports back in -> should resolve and write alert.resolved ---
device.last_seen = datetime.utcnow()
db.commit()
monitor.check_once(db)
db.refresh(state)
check("alert state cleared back to 'ok'", state.status == "ok")
check("notify_count reset to 0", state.notify_count == 0)

resolved = (
    db.query(AuditEvent)
    .filter(AuditEvent.action == "alert.resolved", AuditEvent.target_id == "TEST-STALE-PC")
    .first()
)
check("audit row for alert.resolved written", resolved is not None)

# --- 5. Device that has NEVER reported in (last_seen is NULL) should also alert ---
never_reported = Device(hostname="TEST-NEVER-SEEN-PC", ip="10.0.0.9", tenant_id=tenant.id, last_seen=None)
db.add(never_reported)
db.commit()
monitor.check_once(db)
never_state = db.query(DeviceAlertState).filter(DeviceAlertState.hostname == "TEST-NEVER-SEEN-PC").first()
check("device with last_seen=NULL also alerts", never_state and never_state.status == "alerting")

# --- 6. /api/v1/alerts query logic (same filter the endpoint uses) ---
open_alerts = (
    db.query(DeviceAlertState)
    .filter(DeviceAlertState.tenant_id == tenant.id, DeviceAlertState.status == "alerting")
    .all()
)
check("open-alerts query returns exactly the still-silent device", len(open_alerts) == 1 and open_alerts[0].hostname == "TEST-NEVER-SEEN-PC")

db.close()
engine.dispose()  # release SQLite's file handle before deleting it (Windows locks open files)
try:
    os.remove(test_db)
    print(f"\ntest db removed: {test_db}")
except OSError as exc:
    print(f"\n(non-fatal: could not remove temp test db {test_db}: {exc})")

if failures:
    print(f"\n{len(failures)} CHECK(S) FAILED:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("\nALL CHECKS PASSED")
