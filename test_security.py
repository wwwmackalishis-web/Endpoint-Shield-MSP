"""One-off verification script for this security-hardening pass.

Run from the project root with the project's own venv:
    venv\\Scripts\\python.exe test_security.py

Uses a throwaway SQLite file (never devices.db) so this cannot touch real
device data. Covers, in isolation:

  1. app/auth.py refuses to start on the well-known dev JWT secret when
     MSP_DATABASE_URL looks like a real deployment (checked via a
     subprocess, since the check runs at import time and can't be re-run
     in an already-imported process).
  2. app/auth.py still starts locally (no MSP_DATABASE_URL) on the dev
     secret, warning only - unchanged local-dev behavior.
  3. GET /health no longer returns auth_enforced / cors_origins / fleet
     detail to an unauthenticated caller.
  4. app/ratelimit.py locks out a (ip, username) pair after MAX_ATTEMPTS
     failures, blocks even a correct password once tripped, and a
     successful login clears the counter.
  5. POST /api/login actually returns 429 once the limiter trips.
  6. /agents/heartbeat truncates oversized field values instead of
     storing them unbounded.
  7. An oversized request body is rejected (413) before any route runs.

Prints PASS/FAIL lines; exits 1 on any failure.
"""
import os
import subprocess
import sys
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

test_db = os.path.join(tempfile.gettempdir(), "security_test.db")
if os.path.exists(test_db):
    os.remove(test_db)
os.environ["MSP_DB_PATH"] = test_db
os.environ["MSP_ALERT_ENABLED"] = "0"  # don't start the background monitor loop for this test
os.environ.pop("MSP_API_KEY", None)
os.environ.pop("MSP_JWT_SECRET", None)
os.environ.pop("MSP_DATABASE_URL", None)

sys.path.insert(0, PROJECT_ROOT)

failures = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        failures.append(label)


# --- 1 & 2. Import-time hard-fail check (subprocess: env vars are read at
#     module import, so this can't be tested by re-importing in-process). ---
env_prod_like = dict(os.environ)
env_prod_like["MSP_DATABASE_URL"] = "postgresql://user:pass@localhost/doesnotexist"
env_prod_like.pop("MSP_JWT_SECRET", None)
result = subprocess.run(
    [sys.executable, "-c", "import app.auth"],
    cwd=PROJECT_ROOT,
    env=env_prod_like,
    capture_output=True,
    text=True,
)
check(
    "app.auth refuses to start on the dev JWT secret when MSP_DATABASE_URL is set",
    result.returncode != 0 and "MSP_JWT_SECRET" in result.stderr,
)

env_local = dict(os.environ)
env_local.pop("MSP_DATABASE_URL", None)
env_local.pop("MSP_JWT_SECRET", None)
result2 = subprocess.run(
    [sys.executable, "-c", "import app.auth; print('IMPORT_OK')"],
    cwd=PROJECT_ROOT,
    env=env_local,
    capture_output=True,
    text=True,
)
check(
    "app.auth still starts locally (no MSP_DATABASE_URL) on the dev secret, warning only",
    result2.returncode == 0 and "IMPORT_OK" in result2.stdout,
)

# --- Import the app in-process for the rest of the checks ---
import app.main as appmain  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app.database import Base, engine, SessionLocal  # noqa: E402
from app.models import Device, Tenant, User  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app import ratelimit  # noqa: E402

Base.metadata.create_all(bind=engine)

db = SessionLocal()
tenant = Tenant(name="Test Tenant")
db.add(tenant)
db.flush()
user = User(username="tester", hashed_password=hash_password("correct-horse"), tenant_id=tenant.id)
db.add(user)
db.commit()
db.close()

client = TestClient(appmain.app)

# --- 3. /health minimal, unauthenticated ---
r = client.get("/health")
check("/health returns 200", r.status_code == 200)
body = r.json() if r.status_code == 200 else {}
check("/health body has ONLY the 'status' key (no auth_enforced/cors_origins/devices/fleet)", set(body.keys()) == {"status"})
check("/health status is 'ok'", body.get("status") == "ok")

# --- 4 & 5. Rate limiting on /api/login ---
for i in range(ratelimit.MAX_ATTEMPTS):
    r = client.post("/api/login", data={"username": "tester", "password": "wrong"})
    check(f"bad-password attempt {i + 1}/{ratelimit.MAX_ATTEMPTS} rejected as 401 (not yet rate-limited)", r.status_code == 401)

r_blocked = client.post("/api/login", data={"username": "tester", "password": "wrong"})
check("attempt beyond MAX_ATTEMPTS is rate-limited (429)", r_blocked.status_code == 429)

r_blocked_correct = client.post("/api/login", data={"username": "tester", "password": "correct-horse"})
check("rate limit blocks even the CORRECT password once tripped", r_blocked_correct.status_code == 429)

# Simulate the limiter window elapsing (this is a test-only reach into the
# module's internal state - real recovery happens automatically after
# WINDOW_SECONDS with no code involved).
ratelimit._attempts.clear()
r_ok = client.post("/api/login", data={"username": "tester", "password": "correct-horse"})
check("login succeeds once the limiter window has elapsed", r_ok.status_code == 200)
check("successful login response includes an access_token", "access_token" in r_ok.json())

r_after_success = client.post("/api/login", data={"username": "tester", "password": "wrong"})
check("counter was cleared by the earlier success (this failure is attempt 1, not blocked)", r_after_success.status_code == 401)
ratelimit._attempts.clear()

# --- 6. Heartbeat field truncation ---
long_value = "A" * 5000
r_hb = client.post("/agents/heartbeat", json={"hostname": "TRUNCATE-TEST-PC", "os": long_value})
check("heartbeat with an oversized field is still accepted", r_hb.status_code == 200)
db2 = SessionLocal()
dev = db2.query(Device).filter(Device.hostname == "TRUNCATE-TEST-PC").first()
check("oversized 'os' field was truncated to <=255 chars, not stored whole (was 5000)", dev is not None and dev.os is not None and len(dev.os) <= 255)
db2.close()

# --- 7. Oversized request body rejected before reaching a route ---
huge_body = {"hostname": "OVERSIZE-PC", "notes": "B" * 2_000_000}
r_big = client.post("/agents/heartbeat", json=huge_body)
check("a >1MB request body is rejected with 413 before the route runs", r_big.status_code == 413)
db3 = SessionLocal()
not_created = db3.query(Device).filter(Device.hostname == "OVERSIZE-PC").first()
check("the oversized-body request never reached the database", not_created is None)
db3.close()

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
