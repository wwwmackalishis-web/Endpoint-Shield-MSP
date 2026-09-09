"""End-to-end check of the MSP device API.

Boots app.main on a spare port against a throwaway database (your real
devices.db is never touched), exercises every endpoint the dashboard and
agent.ps1 call - including login and tenant isolation now that /devices is
JWT-authenticated - then shuts the server down and reports PASS/FAIL.

Run from the project root:

    venv\\Scripts\\python verify_api.py         (Windows)
    ./venv/bin/python verify_api.py            (macOS / Linux)

Exit code 0 = everything passed. Requires the project's own dependencies
(passlib, python-jose) to be installed - no extra test-only packages.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PORT = 9010
BASE = f"http://127.0.0.1:{PORT}"
ROOT = Path(__file__).resolve().parent

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    mark = "PASS" if condition else "FAIL"
    line = f"[{mark}] {name}"
    if detail and not condition:
        line += f"\n       {detail}"
    print(line, flush=True)


def request(method, path, payload=None, headers=None, form=None):
    """Return (status, body, headers). Never raises on an HTTP error status.

    `payload` is sent as JSON; `form` (mutually exclusive) as
    application/x-www-form-urlencoded, which POST /api/login requires.
    """
    data = None
    hdrs = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode()
        hdrs["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(BASE + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            raw = res.read().decode()
            try:
                return res.status, json.loads(raw), dict(res.headers)
            except json.JSONDecodeError:
                return res.status, raw, dict(res.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw), dict(exc.headers)
        except json.JSONDecodeError:
            return exc.code, raw, dict(exc.headers)


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def start_server(db_path, extra_env=None):
    env = dict(os.environ, MSP_DB_PATH=str(db_path))
    env.pop("MSP_DATABASE_URL", None)  # never let a Postgres URL leak into tests
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for _ in range(480):  # up to ~2 minutes - this machine's disk I/O has
        # been the bottleneck for every slow step in this project so far
        # (npm builds, pip installs), not the app itself; give uvicorn room
        # to actually finish starting instead of failing on a fast timeout.
        if proc.poll() is not None:
            print("--- server failed to start ---")
            print(proc.stdout.read())
            sys.exit(1)
        try:
            status, body, _ = request("GET", "/health")
            if status == 200:
                return proc
        except Exception:
            pass
        time.sleep(0.25)
    proc.terminate()
    print("Server did not become ready in 120s.")
    sys.exit(1)


def stop_server(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_migration_script(db_path, username, password):
    """Runs the real migrate_to_tenants.py as a subprocess - this phase is
    the automated proof that script actually does what its docstring
    promises, not a reimplementation of its logic in the test."""
    env = dict(os.environ, MSP_DB_PATH=str(db_path))
    env.pop("MSP_DATABASE_URL", None)
    proc = subprocess.run(
        [sys.executable, "migrate_to_tenants.py", "--username", username, "--password", password],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Phase 1 - login + tenant isolation against a fresh database
# ---------------------------------------------------------------------------
def phase_auth(tmp):
    db = tmp / "auth.db"
    proc = start_server(db)
    try:
        # No users exist yet - migrate_to_tenants.py is what creates the
        # first one (see phase_migration for the upgrade-path version of
        # this). Seed two tenants + users directly here to test isolation
        # without conflating it with the migration script's own test.
        rc, out = run_migration_script(db, "alice", "alice-pw-123")
        check("migrate_to_tenants.py creates the first tenant/user (exit 0)", rc == 0, out)

        # A second, independent tenant/user pair, via the same script -
        # it should add a user without touching the first tenant.
        rc2, out2 = run_migration_script(db, "bob", "bob-pw-123")
        check("Re-running migrate_to_tenants.py is safe (exit 0)", rc2 == 0, out2)

        status, body, _ = request("POST", "/api/login", form={"username": "alice", "password": "alice-pw-123"})
        check("POST /api/login succeeds with the right password", status == 200 and "access_token" in body, f"{status} {body}")
        alice_token = body.get("access_token")

        status, body, _ = request("POST", "/api/login", form={"username": "alice", "password": "wrong-password"})
        check("POST /api/login rejects the wrong password (401)", status == 401, f"{status} {body}")

        status, body, _ = request("GET", "/devices")
        check("GET /devices without a token is rejected (401)", status == 401, f"{status} {body}")

        status, body, _ = request("GET", "/devices", headers=auth_header("not-a-real-token"))
        check("GET /devices with a garbage token is rejected (401)", status == 401, f"{status} {body}")

        # migrate_to_tenants.py's second run put bob in the *same* Default
        # tenant as alice (it only creates a tenant named "Default" once) -
        # that's correct behavior for the script, but it means isolation
        # has to be tested with a device manually assigned to a different
        # tenant, not just "a second user".
        status, body, _ = request(
            "POST", "/devices", payload={"hostname": "Alice-PC", "ip": "10.0.0.5"},
            headers=auth_header(alice_token),
        )
        check("POST /devices (authenticated) creates a device (201)", status == 201, f"{status} {body}")

        status, body, _ = request("GET", "/devices", headers=auth_header(alice_token))
        check("GET /devices returns the device its own tenant created",
              status == 200 and any(d["hostname"] == "Alice-PC" for d in body), f"{status} {body}")

        # Simulate a device belonging to a genuinely different tenant by
        # inserting one directly, then confirm bob's login - same tenant as
        # alice today, so this is really testing "a device with a
        # mismatched tenant_id is invisible", the actual filter the /devices
        # routes rely on.
        con = sqlite3.connect(db)
        con.execute("INSERT INTO tenants (name) VALUES ('OtherClinic')")
        other_tenant_id = con.execute("SELECT id FROM tenants WHERE name = 'OtherClinic'").fetchone()[0]
        con.execute(
            "INSERT INTO devices (hostname, ip, tenant_id) VALUES (?, ?, ?)",
            ("Other-Tenant-PC", "10.0.0.9", other_tenant_id),
        )
        con.commit()
        con.close()

        status, body, _ = request("GET", "/devices", headers=auth_header(alice_token))
        check("GET /devices does not leak another tenant's device",
              status == 200 and not any(d["hostname"] == "Other-Tenant-PC" for d in body), f"{status} {body}")

        status, body, _ = request("GET", "/devices/Other-Tenant-PC", headers=auth_header(alice_token))
        check("GET /devices/{hostname} 404s (not 403) for another tenant's device",
              status == 404, f"{status} {body}")

        status, body, _ = request(
            "PUT", "/devices/Other-Tenant-PC", payload={"notes": "hijacked"}, headers=auth_header(alice_token)
        )
        check("PUT /devices/{hostname} cannot edit another tenant's device",
              status == 404, f"{status} {body}")

        status, body, _ = request("DELETE", "/devices/Other-Tenant-PC", headers=auth_header(alice_token))
        check("DELETE /devices/{hostname} cannot delete another tenant's device",
              status == 404, f"{status} {body}")

        # Real health-audit, not the hardcoded string it replaced. Alice-PC
        # was hand-added and has never sent a heartbeat, so it's correctly
        # "silent" - test both real states rather than assume "Operational".
        status, body, _ = request("GET", "/api/v1/health-audit", headers=auth_header(alice_token))
        check("GET /api/v1/health-audit flags a never-checked-in device as Degraded",
              status == 200 and body.get("status") == "Degraded"
              and body.get("total_devices") == 1 and body.get("silent_over_5min") == 1,
              f"{status} {body}")

        request("POST", "/agents/heartbeat", {"hostname": "Alice-PC", "ip": "10.0.0.5"})
        status, body, _ = request("GET", "/api/v1/health-audit", headers=auth_header(alice_token))
        check("GET /api/v1/health-audit reports Operational once the device checks in",
              status == 200 and body.get("status") == "Operational" and body.get("reporting_last_5min") == 1,
              f"{status} {body}")

        status, body, _ = request("GET", "/api/v1/health-audit")
        check("GET /api/v1/health-audit rejects an unauthenticated request (401)", status == 401, f"{status} {body}")

        status, body, _ = request("DELETE", "/devices/Alice-PC", headers=auth_header(alice_token))
        check("DELETE /devices/{hostname} removes the device", status == 200, f"{status} {body}")
    finally:
        stop_server(proc)


# ---------------------------------------------------------------------------
# Phase 2 - full CRUD + heartbeat against a fresh database, authenticated
# ---------------------------------------------------------------------------
def phase_crud(tmp):
    db = tmp / "fresh.db"
    proc = start_server(db)
    try:
        rc, out = run_migration_script(db, "tech", "tech-pw-123")
        check("migrate_to_tenants.py sets up a fresh database (exit 0)", rc == 0, out)

        status, body, _ = request("POST", "/api/login", form={"username": "tech", "password": "tech-pw-123"})
        check("POST /api/login issues a usable token", status == 200 and "access_token" in body, f"{status} {body}")
        token = body.get("access_token")
        auth = auth_header(token)

        status, body, _ = request("GET", "/health")
        check("GET /health returns 200 with an empty database",
              status == 200 and body.get("devices") == 0, f"{status} {body}")

        status, body, _ = request("GET", "/devices", headers=auth)
        check("GET /devices returns an empty list", status == 200 and body == [], f"{status} {body}")

        new = {"hostname": "Test-PC1", "ip": "10.0.0.5", "cpu": "i7", "ram": "16384",
               "disk": "512", "os": "Windows 11", "location": "Op 2",
               "notes": "verify script"}
        status, body, _ = request("POST", "/devices", new, headers=auth)
        check("POST /devices creates a device (201)", status == 201, f"{status} {body}")
        check("POST /devices stores location and notes",
              isinstance(body, dict) and body.get("location") == "Op 2"
              and body.get("notes") == "verify script", str(body))
        check("POST /devices leaves last_seen null (shows as Never / Offline)",
              isinstance(body, dict) and body.get("last_seen") is None, str(body))
        check("POST /devices keeps a non-numeric CPU value",
              isinstance(body, dict) and body.get("cpu") == "i7", str(body))

        status, body, _ = request("POST", "/devices", new, headers=auth)
        check("POST /devices rejects a duplicate hostname (409)",
              status == 409, f"{status} {body}")

        status, body, _ = request("POST", "/devices", {"ip": "10.0.0.6"}, headers=auth)
        check("POST /devices rejects a missing hostname (422)",
              status == 422, f"{status} {body}")

        status, body, _ = request("POST", "/devices", {"hostname": "   ", "ip": "10.0.0.7"}, headers=auth)
        check("POST /devices rejects a blank hostname (422)",
              status == 422, f"{status} {body}")

        status, body, _ = request("GET", "/devices", headers=auth)
        check("GET /devices lists the new device",
              status == 200 and len(body) == 1 and body[0]["hostname"] == "Test-PC1",
              f"{status} {body}")
        check("GET /devices returns strings, never null",
              all(body[0][f] is not None for f in
                  ("ip", "cpu", "ram", "disk", "os", "location", "notes")), str(body))

        status, body, _ = request("GET", "/devices/Test-PC1", headers=auth)
        check("GET /devices/{hostname} returns the device", status == 200, f"{status} {body}")

        status, body, _ = request("GET", "/devices/Nope-PC", headers=auth)
        check("GET /devices/{hostname} 404s for an unknown host",
              status == 404, f"{status} {body}")

        # The Edit form posts the whole row back, including read-only fields.
        edit = {"hostname": "Test-PC1", "ip": "10.0.0.99", "cpu": "i9", "ram": "32768",
                "disk": "1024", "os": "Windows 11 Pro", "location": "Front Desk",
                "notes": "edited", "last_seen": None}
        status, body, _ = request("PUT", "/devices/Test-PC1", edit, headers=auth)
        check("PUT /devices/{hostname} accepts the Edit form payload",
              status == 200, f"{status} {body}")
        check("PUT /devices/{hostname} applies the changes",
              isinstance(body, dict) and body.get("ip") == "10.0.0.99"
              and body.get("location") == "Front Desk" and body.get("notes") == "edited",
              str(body))

        status, body, _ = request("PUT", "/devices/Nope-PC", {"ip": "1.1.1.1"}, headers=auth)
        check("PUT /devices/{hostname} 404s for an unknown host",
              status == 404, f"{status} {body}")

        # Heartbeat uses MSP_API_KEY (unset here, same as production until
        # you opt in), not the JWT dashboard users log in with - these two
        # auth schemes are intentionally independent.
        status, body, _ = request("GET", "/agents/heartbeat")
        check("GET /agents/heartbeat reports online", status == 200, f"{status} {body}")

        status, body, _ = request("POST", "/agents/heartbeat", {"hostname": "Test-PC1", "ip": "10.0.0.99"})
        check("POST /agents/heartbeat updates an existing device",
              status == 200, f"{status} {body}")
        status, body, _ = request("GET", "/devices/Test-PC1", headers=auth)
        check("Heartbeat sets last_seen",
              isinstance(body, dict) and body.get("last_seen") is not None, str(body))
        check("Heartbeat does not blank fields it did not report",
              isinstance(body, dict) and body.get("location") == "Front Desk"
              and body.get("notes") == "edited", str(body))

        status, body, _ = request("POST", "/agents/heartbeat",
                                  {"hostname": "Agent-PC2", "ip": "10.0.0.20",
                                   "cpu": 8, "ram": 16384, "disk": 512, "os": "Windows 10"})
        check("POST /agents/heartbeat registers an unknown device (no tenant given -> Default)",
              status == 200, f"{status} {body}")
        status, body, _ = request("GET", "/devices", headers=auth)
        check("Heartbeat-registered device (Default tenant) appears for the Default-tenant user",
              status == 200 and len(body) == 2, f"{status} {body}")

        status, body, _ = request("POST", "/agents/heartbeat", {"ip": "10.0.0.30"})
        check("POST /agents/heartbeat rejects a missing hostname (422)",
              status == 422, f"{status} {body}")

        status, body, headers = request(
            "OPTIONS", "/devices",
            headers={"Origin": "http://localhost:3000",
                     "Access-Control-Request-Method": "POST"})
        allow = headers.get("access-control-allow-origin") or \
            headers.get("Access-Control-Allow-Origin")
        check("CORS preflight allows the dashboard origin",
              status in (200, 204) and allow is not None, f"{status} allow-origin={allow}")

        status, body, _ = request("DELETE", "/devices/Test-PC1", headers=auth)
        check("DELETE /devices/{hostname} removes the device",
              status == 200, f"{status} {body}")

        status, body, _ = request("DELETE", "/devices/Test-PC1", headers=auth)
        check("DELETE /devices/{hostname} 404s the second time",
              status == 404, f"{status} {body}")

        status, body, _ = request("GET", "/devices", headers=auth)
        check("Device list reflects the deletion",
              status == 200 and len(body) == 1, f"{status} {body}")
    finally:
        stop_server(proc)


# ---------------------------------------------------------------------------
# Phase 3 - the real upgrade path: a legacy pre-tenant database run through
# migrate_to_tenants.py, exactly as a real deployment would do it.
# ---------------------------------------------------------------------------
def phase_migration(tmp):
    db = tmp / "legacy.db"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE devices (id INTEGER PRIMARY KEY, hostname VARCHAR UNIQUE, "
        "ip VARCHAR, cpu INTEGER, ram INTEGER, disk INTEGER, os VARCHAR, "
        "last_seen DATETIME)"
    )
    con.execute(
        "INSERT INTO devices (hostname, ip, cpu, ram, disk, os, last_seen) "
        "VALUES ('Dental-PC1','192.168.1.10',14,8192,256,'Windows 11','2026-03-14 23:39:01')"
    )
    con.commit()
    con.close()

    rc, out = run_migration_script(db, "admin", "admin-pw-123")
    check("migrate_to_tenants.py runs against a pre-tenant database (exit 0)", rc == 0, out)

    cols = {r[1] for r in sqlite3.connect(db).execute("pragma table_info(devices)")}
    check("Migration adds the tenant_id column (plus location/notes)",
          {"location", "notes", "tenant_id"} <= cols, str(sorted(cols)))

    row = sqlite3.connect(db).execute(
        "SELECT tenant_id FROM devices WHERE hostname = 'Dental-PC1'"
    ).fetchone()
    check("The pre-existing device is backfilled into a real tenant, not left NULL",
          row is not None and row[0] is not None, str(row))

    proc = start_server(db)
    try:
        status, body, _ = request("POST", "/api/login", form={"username": "admin", "password": "admin-pw-123"})
        check("The migration script's admin user can log in", status == 200 and "access_token" in body, f"{status} {body}")
        auth = auth_header(body.get("access_token"))

        status, body, _ = request("GET", "/devices", headers=auth)
        check("Existing row survives the migration and is visible to the admin",
              status == 200 and len(body) == 1 and body[0]["hostname"] == "Dental-PC1",
              f"{status} {body}")
        check("Migrated row exposes location/notes as empty strings",
              body and body[0]["location"] == "" and body[0]["notes"] == "", str(body))
        check("Legacy integer CPU still reads back",
              body and str(body[0]["cpu"]) == "14", str(body))

        status, body, _ = request("PUT", "/devices/Dental-PC1", {"location": "Op 1", "notes": "migrated"}, headers=auth)
        check("Migrated row is editable",
              status == 200 and body.get("location") == "Op 1", f"{status} {body}")
    finally:
        stop_server(proc)

    # Second boot + a second migration-script run must both be no-ops, not errors.
    rc2, out2 = run_migration_script(db, "admin", "admin-pw-123")
    check("Re-running migrate_to_tenants.py on an already-migrated DB is a no-op (exit 0)", rc2 == 0, out2)

    proc = start_server(db)
    try:
        status, body, _ = request("POST", "/api/login", form={"username": "admin", "password": "admin-pw-123"})
        auth = auth_header(body.get("access_token"))
        status, body, _ = request("GET", "/devices", headers=auth)
        check("Migration is idempotent on a second start",
              status == 200 and body[0]["location"] == "Op 1", f"{status} {body}")
    finally:
        stop_server(proc)


# ---------------------------------------------------------------------------
# Phase 4 - audit logging (45 CFR 164.312(b))
# ---------------------------------------------------------------------------
def phase_audit(tmp):
    db = tmp / "audit.db"
    proc = start_server(db)
    try:
        rc, out = run_migration_script(db, "auditor", "auditor-pw-123")
        check("migrate_to_tenants.py sets up the audit-phase database (exit 0)", rc == 0, out)

        cols = {r[1] for r in sqlite3.connect(db).execute("pragma table_info(audit_events)")}
        check("Startup creates the audit_events table",
              {"timestamp", "action", "outcome", "actor_username", "tenant_id",
               "target_type", "target_id", "source_ip", "detail"} <= cols,
              str(sorted(cols)))

        # --- login events -------------------------------------------------
        status, body, _ = request("POST", "/api/login",
                                  form={"username": "auditor", "password": "wrong-pw"})
        check("Failed login is rejected (401)", status == 401, f"{status} {body}")

        status, body, _ = request("POST", "/api/login",
                                  form={"username": "auditor", "password": "auditor-pw-123"})
        check("Login succeeds", status == 200 and "access_token" in body, f"{status} {body}")
        token = body.get("access_token")
        hdr = auth_header(token)

        con = sqlite3.connect(db)
        actions = [r[0] for r in con.execute("SELECT action FROM audit_events ORDER BY id")]
        check("Failed login is recorded as login.failure",
              "login.failure" in actions, str(actions))
        check("Successful login is recorded as login.success",
              "login.success" in actions, str(actions))

        # The single most important negative test in this file.
        blob = " ".join(
            " ".join(str(c) for c in row)
            for row in con.execute("SELECT * FROM audit_events")
        )
        check("No password text is ever written to the audit table",
              "wrong-pw" not in blob and "auditor-pw-123" not in blob,
              "a credential leaked into audit_events")
        con.close()

        # --- device mutations ---------------------------------------------
        SECRET_NOTE = "patient-chart-reference-do-not-log"
        status, body, _ = request("POST", "/devices", headers=hdr, payload={
            "hostname": "Audit-PC", "ip": "10.0.0.42", "location": "Operatory 3",
            "notes": SECRET_NOTE,
        })
        check("POST /devices succeeds (audited)", status == 201, f"{status} {body}")

        status, body, _ = request("PUT", "/devices/Audit-PC", headers=hdr,
                                  payload={"location": "Front Desk", "notes": SECRET_NOTE + "-v2"})
        check("PUT /devices succeeds (audited)", status == 200, f"{status} {body}")

        con = sqlite3.connect(db)
        rows = con.execute(
            "SELECT action, outcome, actor_username, target_type, target_id, detail "
            "FROM audit_events WHERE action LIKE 'device.%' ORDER BY id"
        ).fetchall()
        check("device.create is recorded with actor and target",
              any(r[0] == "device.create" and r[2] == "auditor"
                  and r[3] == "device" and r[4] == "Audit-PC" for r in rows), str(rows))
        check("device.update is recorded",
              any(r[0] == "device.update" for r in rows), str(rows))
        upd = next((r for r in rows if r[0] == "device.update"), None)
        check("device.update records changed field NAMES",
              upd is not None and upd[5] is not None
              and "location" in upd[5] and "notes" in upd[5], str(upd))

        # Free-text device fields may contain PHI; they must never reach the
        # audit table. This is the rule app/audit.py exists to enforce.
        blob = " ".join(
            " ".join(str(c) for c in row)
            for row in con.execute("SELECT * FROM audit_events")
        )
        check("Device field VALUES never reach the audit table",
              SECRET_NOTE not in blob, "free-text device content leaked into audit_events")
        check("Audit rows carry a source IP",
              any(r[0] is not None for r in
                  con.execute("SELECT source_ip FROM audit_events")), "source_ip is always NULL")
        con.close()

        # --- the read API --------------------------------------------------
        status, body, _ = request("GET", "/api/v1/audit-log")
        check("GET /api/v1/audit-log rejects an unauthenticated request (401)",
              status == 401, f"{status} {body}")

        status, body, _ = request("GET", "/api/v1/audit-log", headers=hdr)
        check("GET /api/v1/audit-log returns the trail",
              status == 200 and body.get("total", 0) >= 4, f"{status} {body}")
        check("Audit log is newest-first",
              status == 200 and len(body["events"]) >= 2
              and body["events"][0]["timestamp"] >= body["events"][1]["timestamp"],
              str(body.get("events", [])[:2]))

        status, body, _ = request("GET", "/api/v1/audit-log?action=device.create", headers=hdr)
        check("Audit log filters by action",
              status == 200 and body["total"] == 1
              and body["events"][0]["action"] == "device.create", f"{status} {body}")

        status, body, _ = request("GET", "/api/v1/audit-log?limit=1&offset=0", headers=hdr)
        check("Audit log paginates",
              status == 200 and len(body["events"]) == 1 and body["total"] > 1, f"{status} {body}")

        status, body, _ = request("GET", "/api/v1/audit-log?since=2999-01-01T00:00:00", headers=hdr)
        check("Audit log filters by since",
              status == 200 and body["total"] == 0, f"{status} {body}")

        status, body, _ = request("GET", "/api/v1/audit-log?limit=0", headers=hdr)
        check("Audit log rejects an out-of-range limit (422)", status == 422, f"{status} {body}")

        # Append-only over the API: no write verbs exist on this path.
        status, body, _ = request("DELETE", "/api/v1/audit-log", headers=hdr)
        check("Audit log has no DELETE route (405)", status == 405, f"{status} {body}")
        status, body, _ = request("POST", "/api/v1/audit-log", headers=hdr, payload={"action": "x"})
        check("Audit log has no POST route (405)", status == 405, f"{status} {body}")

        # --- tenant scoping and failed mutations ---------------------------
        con = sqlite3.connect(db)
        con.execute("INSERT INTO tenants (name) VALUES ('OtherClinic')")
        other = con.execute("SELECT id FROM tenants WHERE name='OtherClinic'").fetchone()[0]
        con.execute("INSERT INTO devices (hostname, ip, tenant_id) VALUES (?,?,?)",
                    ("Other-PC", "10.0.0.99", other))
        con.execute(
            "INSERT INTO audit_events (timestamp, action, outcome, actor_username, tenant_id) "
            "VALUES (datetime('now'), 'device.delete', 'success', 'someone-else', ?)", (other,))
        con.commit()
        con.close()

        status, body, _ = request("GET", "/api/v1/audit-log", headers=hdr)
        check("Audit log does not leak another tenant's events",
              status == 200 and all(e["actor"] != "someone-else" for e in body["events"]),
              str(body.get("events")))

        before = sqlite3.connect(db).execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        status, body, _ = request("PUT", "/devices/Other-PC", headers=hdr, payload={"notes": "nope"})
        check("Cross-tenant edit is refused (404)", status == 404, f"{status} {body}")
        after = sqlite3.connect(db).execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        check("A refused mutation writes no audit row", before == after, f"{before} -> {after}")

        # --- delete -------------------------------------------------------
        status, body, _ = request("DELETE", "/devices/Audit-PC", headers=hdr)
        check("DELETE /devices succeeds (audited)", status == 200, f"{status} {body}")
        con = sqlite3.connect(db)
        check("device.delete is recorded",
              con.execute("SELECT COUNT(*) FROM audit_events WHERE action='device.delete' "
                          "AND target_id='Audit-PC'").fetchone()[0] == 1, "")
        check("The audit trail outlives the device it describes",
              con.execute("SELECT COUNT(*) FROM devices WHERE hostname='Audit-PC'").fetchone()[0] == 0
              and con.execute("SELECT COUNT(*) FROM audit_events WHERE target_id='Audit-PC'"
                              ).fetchone()[0] >= 3, "")
        con.close()
    finally:
        stop_server(proc)


def main():
    if not (ROOT / "app" / "main.py").exists():
        print("Run this from the antivirus-orchestrator project root.")
        sys.exit(1)

    tmp = Path(tempfile.mkdtemp(prefix="msp-verify-"))
    try:
        phase_auth(tmp)
        phase_crud(tmp)
        phase_migration(tmp)
        phase_audit(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("\n" + "=" * 60)
    print(f"{passed}/{total} checks passed")
    if passed != total:
        print("\nFailures:")
        for name, ok, detail in results:
            if not ok:
                print(f"  - {name}: {detail}")
        sys.exit(1)
    print("All endpoints operational.")


if __name__ == "__main__":
    main()
