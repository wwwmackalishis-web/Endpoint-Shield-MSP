"""Shared SQLAlchemy engine/session setup for the MSP backend.

Split out of app/main.py so app/models.py can import Base without a circular
import. MSP_DATABASE_URL takes over entirely when set (e.g. a Postgres URL
from a Render add-on) - SQLite on Render's default disk is ephemeral and
loses every row on redeploy, so this is the real escape hatch out of that.
Falls back to file-based SQLite for local dev, anchored to the project root
so the same file is used no matter which directory the server is launched
from. MSP_DB_PATH (SQLite path only) lets verify_api.py and
migrate_to_tenants.py point at a throwaway database without touching
MSP_DATABASE_URL.
"""

import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_URL = os.environ.get("MSP_DATABASE_URL")
if DATABASE_URL:
    DB_PATH = None  # not file-based - / reports the driver name instead
    connect_args = {}
else:
    DB_PATH = Path(os.environ.get("MSP_DB_PATH") or (BASE_DIR / "devices.db")).resolve()
    DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Column name -> SQL type, for every column app/models.py's Device has
# added since the table was first created. Shared by app/main.py (runs on
# every startup) and migrate_to_tenants.py (runs once, deliberately, against
# a legacy database) so the two can't drift apart on which columns they know
# about - the bug that broke migrate_to_tenants.py against a genuinely old
# database missing all three of the original three, not just tenant_id.
DEVICE_COLUMN_TYPES = {
    "location": "VARCHAR",
    "notes": "VARCHAR",
    "tenant_id": "INTEGER",
    # Patch & Vulnerability Compliance Agent, subagent 3b.
    "av_enabled": "BOOLEAN",
    "av_signature_updated_at": "TIMESTAMP",
}


# Client Reporting Agent (5) / On-Call Escalation Router Agent (7) /
# Billing & Renewal Agent (8).
TENANT_COLUMN_TYPES = {
    "contact_email": "VARCHAR",
    "sla_response_minutes": "INTEGER",
    "monthly_base_fee_cents": "INTEGER",
    "per_device_fee_cents": "INTEGER",
    "msa_renewal_date": "TIMESTAMP",
    "sma_renewal_date": "TIMESTAMP",
    "baa_renewal_date": "TIMESTAMP",
}


def _ensure_columns(table_name: str, column_types: dict) -> None:
    existing = {col["name"] for col in inspect(engine).get_columns(table_name)}
    missing = [name for name in column_types if name not in existing]
    if not missing:
        return
    with engine.begin() as conn:
        for name in missing:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {name} {column_types[name]}"))


def ensure_device_columns() -> None:
    """Add columns to `devices` that create_all() cannot add to a table that
    already exists."""
    _ensure_columns("devices", DEVICE_COLUMN_TYPES)


def ensure_tenant_columns() -> None:
    """Same as ensure_device_columns(), for `tenants`."""
    _ensure_columns("tenants", TENANT_COLUMN_TYPES)
