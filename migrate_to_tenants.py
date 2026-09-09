"""One-time migration: adds the tenant/user schema to an existing devices.db
without losing data, and gets you a working login on the first try.

What it does, in order:
  1. Creates the `tenants` and `users` tables (via Base.metadata.create_all -
     a no-op for anything that already exists).
  2. Adds any of `location`/`notes`/`tenant_id` missing from `devices`, via
     the same ensure_device_columns() app/main.py runs on every startup -
     shared, not duplicated, so the two can't drift on which columns they
     know about. This script doesn't depend on the server having run first.
  3. Creates a "Default" tenant if none exists.
  4. Backfills every device whose tenant_id is NULL into that Default
     tenant - otherwise those devices become invisible to every user,
     since GET /devices filters by Device.tenant_id == current_user.tenant_id
     and NULL matches nothing. This is the "without losing data" step.
  5. Creates one admin user in the Default tenant, IF no users exist yet -
     without this step, the migration would ship a login-only API with
     nobody able to log in.

Safe to re-run: every step is idempotent.

Usage:
    python migrate_to_tenants.py --username admin --password "change-me-now"

Respects MSP_DATABASE_URL / MSP_DB_PATH exactly like app/main.py, so it
targets whichever database the server actually runs against.
"""

import argparse
import sys

from app.auth import hash_password
from app.database import Base, SessionLocal, engine, ensure_device_columns
from app.models import Device, Tenant, User


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", default="admin", help="Initial admin username (default: admin)")
    parser.add_argument("--password", required=True, help="Initial admin password")
    args = parser.parse_args()

    print("Creating tenants/users tables if missing...")
    Base.metadata.create_all(bind=engine)

    print("Checking devices columns (location, notes, tenant_id)...")
    ensure_device_columns()

    db = SessionLocal()
    try:
        default_tenant = db.query(Tenant).filter(Tenant.name == "Default").first()
        if not default_tenant:
            default_tenant = Tenant(name="Default")
            db.add(default_tenant)
            db.flush()
            print(f"Created 'Default' tenant (id={default_tenant.id}).")
        else:
            print(f"'Default' tenant already exists (id={default_tenant.id}).")

        orphaned = db.query(Device).filter(Device.tenant_id.is_(None)).all()
        for device in orphaned:
            device.tenant_id = default_tenant.id
        if orphaned:
            print(f"Backfilled {len(orphaned)} pre-existing device(s) into 'Default'.")
        else:
            print("No orphaned devices to backfill.")

        if db.query(User).count() == 0:
            admin = User(
                username=args.username,
                hashed_password=hash_password(args.password),
                tenant_id=default_tenant.id,
            )
            db.add(admin)
            print(f"Created initial user '{args.username}' in tenant 'Default'.")
        else:
            print("Users already exist - not creating another admin.")

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    print("\nMigration complete. Nothing was deleted; existing device rows are intact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
