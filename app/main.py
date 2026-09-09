"""Mackalishis MSP device API.

Serves the msp-dashboard React app (default: http://127.0.0.1:9000).

Run from anywhere:
    python app/main.py
or:
    uvicorn app.main:app --host 127.0.0.1 --port 9000 --reload

Two separate auth schemes on purpose:
  - /devices/* requires a JWT (POST /api/login) - a human technician's
    dashboard session, scoped to their tenant.
  - /agents/heartbeat requires MSP_API_KEY (opt-in, unchanged from before) -
    an unattended background script can't practically do an interactive
    login/refresh cycle the way a browser session can.

Every login attempt and every change to a device record is written to the
append-only audit_events table (45 CFR 164.312(b)); see app/audit.py for
what may and may not be recorded, and GET /api/v1/audit-log to read it back.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, Query, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

import asyncio

from app import ai_vendor_compliance, audit, audit_summary, backup_compliance, billing, breach_clock, client_report, escalation_router, incident_triage, monitor, notify, patch_compliance, ratelimit, referral, risk_worksheet
from app.auth import authenticate_user, create_access_token, get_current_user
from app.database import Base, SessionLocal, DB_PATH, engine, ensure_device_columns, ensure_tenant_columns, get_db
from app.models import (
    AIVendor, AuditEvent, BackupRun, BreachIncident, Device, DeviceAlertState, Lead,
    OnCallContact, ReferralPartner, RestoreTest, Tenant, User,
)

# ---------------------------------------------------------------------------
# 0. Agent API key (opt-in) and CORS origins - both driven by environment
# variables so nothing here changes for local dev unless you set them.
# ---------------------------------------------------------------------------
# Unset: heartbeat stays open, exactly like today. Set MSP_API_KEY once you
# have a real deployment, and agent.ps1 needs the matching env var to match.
API_KEY = os.environ.get("MSP_API_KEY")


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if API_KEY is None:
        return  # auth disabled - see /health for a visible reminder
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# Comma-separated list, e.g. "https://dashboard.example.com,https://admin.example.com".
# Falls back to "*" for local development - set MSP_CORS_ORIGINS to your real
# production domain before deploying anywhere the wildcard would be unsafe.
_origins_env = os.environ.get("MSP_CORS_ORIGINS")
CORS_ORIGINS = [o.strip() for o in _origins_env.split(",") if o.strip()] if _origins_env else ["*"]

# ---------------------------------------------------------------------------
# 1. Database - tables + startup migration for columns create_all() can't add
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=engine)
ensure_device_columns()
ensure_tenant_columns()


def get_or_create_default_tenant(db: Session) -> Tenant:
    """Devices reported by agent.ps1 aren't tied to a logged-in user, so they
    need somewhere to land. Agents can opt into a real tenant by sending
    "tenant" in the heartbeat payload; anything else falls in here."""
    tenant = db.query(Tenant).filter(Tenant.name == "Default").first()
    if not tenant:
        tenant = Tenant(name="Default")
        db.add(tenant)
        db.flush()
    return tenant


def resolve_or_create_tenant(db: Session, tenant_name: Optional[str]) -> Tenant:
    """Shared by /agents/heartbeat and the backup/restore-test report routes
    below - every unattended, API-key-authenticated ingestion endpoint
    resolves its tenant the same way, so they can't drift into different
    behavior for an unrecognized tenant name."""
    if not tenant_name:
        return get_or_create_default_tenant(db)
    tenant_name = str(tenant_name)[:255]
    tenant = db.query(Tenant).filter(Tenant.name == tenant_name).first()
    if not tenant:
        tenant = Tenant(name=tenant_name)
        db.add(tenant)
        db.flush()
    return tenant


# ---------------------------------------------------------------------------
# 2. Schemas
# ---------------------------------------------------------------------------
class DeviceIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip: str = Field(min_length=1, max_length=255)
    cpu: Optional[str] = ""
    ram: Optional[str] = ""
    disk: Optional[str] = ""
    os: Optional[str] = ""
    location: Optional[str] = ""
    notes: Optional[str] = ""

    @field_validator("hostname", "ip")
    @classmethod
    def not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value


class DeviceUpdate(BaseModel):
    """Every field optional - the dashboard sends the whole row on save.

    Unknown keys (`hostname`, `last_seen`) are ignored by Pydantic's default
    `extra='ignore'`, so the payload the Edit form sends is accepted as-is.
    """

    ip: Optional[str] = None
    cpu: Optional[str] = None
    ram: Optional[str] = None
    disk: Optional[str] = None
    os: Optional[str] = None
    location: Optional[str] = None
    notes: Optional[str] = None


class OnCallContactIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    email: str = Field(min_length=1, max_length=255)
    min_severity: str = Field(default="low")
    notify_business_hours: bool = True
    notify_after_hours: bool = True

    @field_validator("min_severity")
    @classmethod
    def known_severity(cls, value: str) -> str:
        if value not in escalation_router.SEVERITY_RANK:
            raise ValueError(f"must be one of {sorted(escalation_router.SEVERITY_RANK)}")
        return value


def serialize_contact(contact: OnCallContact) -> dict:
    return {
        "id": contact.id,
        "name": contact.name,
        "email": contact.email,
        "min_severity": contact.min_severity,
        "notify_business_hours": contact.notify_business_hours,
        "notify_after_hours": contact.notify_after_hours,
        "active": contact.active,
    }


class AIVendorIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    purpose: str = Field(min_length=1, max_length=255)
    has_baa: bool = False
    baa_signed_date: Optional[datetime] = None
    data_retention_opted_out: bool = False
    notes: Optional[str] = Field(default=None, max_length=1000)


def serialize_ai_vendor(vendor: AIVendor) -> dict:
    return {
        "id": vendor.id,
        "name": vendor.name,
        "purpose": vendor.purpose,
        "has_baa": vendor.has_baa,
        "baa_signed_date": vendor.baa_signed_date.isoformat() if vendor.baa_signed_date else None,
        "data_retention_opted_out": vendor.data_retention_opted_out,
        "notes": vendor.notes,
    }


class ReferralPartnerIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    contact_email: str = Field(min_length=1, max_length=255)
    partner_type: str = Field(min_length=1, max_length=100)


def serialize_referral_partner(partner: ReferralPartner) -> dict:
    return {
        "id": partner.id,
        "name": partner.name,
        "contact_email": partner.contact_email,
        "partner_type": partner.partner_type,
        "last_contacted_at": partner.last_contacted_at.isoformat() if partner.last_contacted_at else None,
    }


class LeadIn(BaseModel):
    practice_name: str = Field(min_length=1, max_length=255)
    contact_email: str = Field(min_length=1, max_length=255)
    practice_type: Optional[str] = Field(default=None, max_length=100)
    device_count_estimate: Optional[int] = Field(default=None, ge=0, le=100000)
    has_existing_it_support: Optional[bool] = None
    notes: Optional[str] = Field(default=None, max_length=2000)


def serialize_lead(lead: Lead) -> dict:
    qualification = referral.qualify_lead(
        device_count_estimate=lead.device_count_estimate,
        has_existing_it_support=lead.has_existing_it_support,
        practice_type=lead.practice_type,
    )
    return {
        "id": lead.id,
        "practice_name": lead.practice_name,
        "contact_email": lead.contact_email,
        "practice_type": lead.practice_type,
        "device_count_estimate": lead.device_count_estimate,
        "has_existing_it_support": lead.has_existing_it_support,
        "submitted_at": lead.submitted_at.isoformat() if lead.submitted_at else None,
        "qualification": qualification,
    }


class BackupReportIn(BaseModel):
    job_name: str = Field(min_length=1, max_length=255)
    completed_at: datetime
    success: bool
    size_bytes: Optional[int] = Field(default=None, ge=0)
    detail: Optional[str] = Field(default=None, max_length=500)
    tenant: Optional[str] = Field(default=None, max_length=255)


class RestoreTestReportIn(BaseModel):
    job_name: str = Field(min_length=1, max_length=255)
    tested_at: datetime
    success: bool
    notes: Optional[str] = Field(default=None, max_length=500)
    tenant: Optional[str] = Field(default=None, max_length=255)


class BreachIncidentIn(BaseModel):
    description: str = Field(min_length=1, max_length=2000)
    discovered_at: datetime


NOTIFY_FIELDS = {
    "ba_notified_covered_entity",
    "individuals_notified",
    "regulator_notified",
}


class BreachIncidentNotifyIn(BaseModel):
    # One of NOTIFY_FIELDS, without the "_at" suffix the column carries -
    # the suffix is a storage detail, not something a caller should have to
    # know to type correctly.
    which: str

    @field_validator("which")
    @classmethod
    def known_field(cls, value: str) -> str:
        if value not in NOTIFY_FIELDS:
            raise ValueError(f"must be one of {sorted(NOTIFY_FIELDS)}")
        return value


class TenantSettingsIn(BaseModel):
    contact_email: Optional[str] = Field(default=None, max_length=255)
    sla_response_minutes: Optional[int] = Field(default=None, ge=1, le=100000)
    monthly_base_fee_cents: Optional[int] = Field(default=None, ge=0)
    per_device_fee_cents: Optional[int] = Field(default=None, ge=0)
    msa_renewal_date: Optional[datetime] = None
    sma_renewal_date: Optional[datetime] = None
    baa_renewal_date: Optional[datetime] = None


def serialize_tenant_settings(tenant: Tenant) -> dict:
    return {
        "tenant_name": tenant.name,
        "contact_email": tenant.contact_email,
        "sla_response_minutes": tenant.sla_response_minutes,
        "monthly_base_fee_cents": tenant.monthly_base_fee_cents,
        "per_device_fee_cents": tenant.per_device_fee_cents,
        "msa_renewal_date": tenant.msa_renewal_date.isoformat() if tenant.msa_renewal_date else None,
        "sma_renewal_date": tenant.sma_renewal_date.isoformat() if tenant.sma_renewal_date else None,
        "baa_renewal_date": tenant.baa_renewal_date.isoformat() if tenant.baa_renewal_date else None,
    }


def serialize_incident(incident: BreachIncident) -> dict:
    clocks = breach_clock.status_for(incident)
    return {
        "id": incident.id,
        "description": incident.description,
        "status": incident.status,
        "discovered_at": incident.discovered_at.isoformat() if incident.discovered_at else None,
        "confirmed_at": incident.confirmed_at.isoformat() if incident.confirmed_at else None,
        "ba_notified_covered_entity_at": (
            incident.ba_notified_covered_entity_at.isoformat()
            if incident.ba_notified_covered_entity_at else None
        ),
        "individuals_notified_at": (
            incident.individuals_notified_at.isoformat() if incident.individuals_notified_at else None
        ),
        "regulator_notified_at": (
            incident.regulator_notified_at.isoformat() if incident.regulator_notified_at else None
        ),
        "clocks": {
            "ba_to_covered_entity": breach_clock.clock_to_dict(clocks["ba_to_covered_entity"]),
            "regulatory_60_day": breach_clock.clock_to_dict(clocks["regulatory_60_day"]),
        },
    }


def serialize(device: Device) -> dict:
    """Shape a row the way the dashboard expects it (never null strings)."""
    return {
        "hostname": device.hostname,
        "ip": device.ip or "",
        "cpu": device.cpu if device.cpu is not None else "",
        "ram": device.ram if device.ram is not None else "",
        "disk": device.disk if device.disk is not None else "",
        "os": device.os or "",
        "location": device.location or "",
        "notes": device.notes or "",
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "av_enabled": device.av_enabled,
        "av_signature_updated_at": (
            device.av_signature_updated_at.isoformat() if device.av_signature_updated_at else None
        ),
    }


# ---------------------------------------------------------------------------
# 3. App
# ---------------------------------------------------------------------------
app = FastAPI(title="Mackalishis MSP", version="1.0.0")

# allow_credentials must stay False while allow_origins can be "*" - browsers
# reject the wildcard when credentials are allowed. Auth rides in a header
# (Bearer token / X-API-Key), never a cookie, so this pairing is correct even
# after MSP_CORS_ORIGINS narrows the list down to a real production domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Every route here reads a small JSON body (a login form, a device record, a
# heartbeat payload) - none legitimately needs more than a few KB. Without a
# cap, /agents/heartbeat in particular (unauthenticated whenever MSP_API_KEY
# is unset - see require_api_key above) would read an attacker-supplied body
# of any size fully into memory via request.json() before any field-level
# validation gets a chance to reject it. Checked against Content-Length
# up front so an oversized body is rejected before it is read, not after.
MAX_BODY_BYTES = int(os.environ.get("MSP_MAX_BODY_BYTES", 1_000_000))  # 1 MB


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            too_large = int(content_length) > MAX_BODY_BYTES
        except ValueError:
            too_large = False
        if too_large:
            return JSONResponse(status_code=413, content={"detail": "request body too large"})
    return await call_next(request)


@app.on_event("startup")
async def start_monitor() -> None:
    """Launch the silent-endpoint monitor (app/monitor.py) as a background
    task alongside the API. MSP_ALERT_ENABLED=0 turns it off entirely (e.g.
    for a test run that doesn't want email attempts in its output); nothing
    else here changes for local dev unless the MSP_ALERT_* / MSP_SMTP_*
    env vars are set - see app/monitor.py and app/notify.py."""
    if monitor.ALERT_ENABLED:
        asyncio.create_task(monitor.monitor_loop())


@app.get("/")
def root():
    # Never echo the raw URL here - a Postgres MSP_DATABASE_URL carries a
    # password in it. The file path is safe to show; the driver name is the
    # most a Postgres deployment gets.
    database = str(DB_PATH) if DB_PATH else f"{engine.url.get_backend_name()} (external)"
    return {"service": "Mackalishis MSP", "database": database}


def fleet_status(last_seen: Optional[datetime]) -> str:
    """Same thresholds as the dashboard's getStatus() (App.js) - the backend
    and frontend must agree on what "online" means, or the numbers here and
    what a technician sees on screen will silently drift apart."""
    if last_seen is None:
        return "offline"
    delta = (datetime.utcnow() - last_seen).total_seconds()
    if delta < 120:
        return "online"
    if delta < 600:
        return "stale"
    return "offline"


@app.get("/health")
def health():
    """Unauthenticated liveness check only: proves the process is up and the
    database answers. Deliberately minimal - this endpoint has no auth in
    front of it, so anything it returns is available to anyone who can reach
    the server at all, including someone probing before they've tried
    anything else. It used to also return device counts, a fleet status
    breakdown, whether MSP_API_KEY was set, and the CORS origin list; that
    handed an unauthenticated caller a map of exactly which protections are
    off (e.g. "auth_enforced": false) before they'd made a single real
    request, plus how many endpoints/clients this deployment has. All of
    that moved to GET /api/v1/health-audit, which needs a technician's JWT
    and is scoped to their own tenant - see that endpoint for fleet detail.
    """
    db = SessionLocal()
    try:
        db.query(Device).limit(1).all()
        # "ok" means the API and database answered - not a claim about fleet
        # health. A dental office with every PC off overnight is not an API
        # outage; conflating the two would either hide a real outage behind
        # fleet noise or cry wolf over normal downtime.
        return {"status": "ok"}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"database error: {exc}")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 4. Login
# ---------------------------------------------------------------------------
@app.post("/api/login")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    # Rate-limited per (source IP, username) before touching the database or
    # the password hasher at all - see app/ratelimit.py. Nothing else in this
    # app throttled repeated attempts against a technician's password, which
    # made /api/login an unlimited-guess oracle protected only by bcrypt's
    # own cost factor.
    source_ip = audit.client_ip(request)
    if not ratelimit.check(source_ip, form_data.username):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again in a few minutes.",
        )
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        ratelimit.record_failure(source_ip, form_data.username)
        # Record the attempt, never the password. A failed login for an
        # unknown username has no tenant to attribute it to, so tenant_id
        # stays NULL - deliberately, see GET /api/v1/audit-log.
        attempted = db.query(User).filter(User.username == form_data.username).first()
        audit.record(
            db,
            action=audit.LOGIN_FAILURE,
            outcome=audit.FAILURE,
            actor_user_id=attempted.id if attempted else None,
            actor_username=form_data.username,
            tenant_id=attempted.tenant_id if attempted else None,
            request=request,
            detail="bad credentials",
        )
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    ratelimit.record_success(source_ip, form_data.username)
    audit.record(
        db,
        action=audit.LOGIN_SUCCESS,
        outcome=audit.SUCCESS,
        actor_user_id=user.id,
        actor_username=user.username,
        tenant_id=user.tenant_id,
        request=request,
    )
    token = create_access_token(user.username, user.tenant_id)
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# 5. Real health audit - per-tenant, queried live, not a hardcoded string
# ---------------------------------------------------------------------------
@app.get("/api/v1/health-audit")
def health_audit(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Device).filter(Device.tenant_id == current_user.tenant_id).all()
    total = len(rows)
    cutoff = datetime.utcnow().timestamp() - 5 * 60  # 5-minute window, as specified
    reporting, silent = 0, 0
    for row in rows:
        if row.last_seen and row.last_seen.timestamp() >= cutoff:
            reporting += 1
        else:
            silent += 1
    offline_pct = (silent / total * 100) if total else 0
    return {
        "status": "Degraded" if offline_pct > 10 else "Operational",
        "total_devices": total,
        "reporting_last_5min": reporting,
        "silent_over_5min": silent,
        "offline_percent": round(offline_pct, 1),
    }


# ---------------------------------------------------------------------------
# 5a. Open alerts - live state from app/monitor.py, tenant-scoped like
# everything else a technician sees. Distinct from /api/v1/audit-log: that is
# the permanent record of every alert event, ever; this is just "what's
# alerting right now", the way the dashboard's device list is "what's here
# now" rather than a history of every device that ever existed.
# ---------------------------------------------------------------------------
@app.get("/api/v1/alerts")
def open_alerts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    triage: bool = Query(False, description="Include Incident Triage Agent output per alert"),
):
    rows = (
        db.query(DeviceAlertState)
        .filter(DeviceAlertState.tenant_id == current_user.tenant_id, DeviceAlertState.status == "alerting")
        .order_by(DeviceAlertState.first_silent_at)
        .all()
    )
    now = datetime.utcnow()
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    result = []
    for row in rows:
        silent_seconds = int((now - row.first_silent_at).total_seconds()) if row.first_silent_at else None
        entry = {
            "hostname": row.hostname,
            "since": row.first_silent_at.isoformat() if row.first_silent_at else None,
            "silent_seconds": silent_seconds,
            "notify_count": row.notify_count,
            "sla_clock": escalation_router.incident_sla_clock(
                triggered_at=row.first_silent_at,
                sla_response_minutes=tenant.sla_response_minutes if tenant else None,
                now=now,
            ),
        }
        if triage:
            recent_events = (
                db.query(AuditEvent)
                .filter(
                    AuditEvent.tenant_id == current_user.tenant_id,
                    AuditEvent.target_type == "device",
                    AuditEvent.target_id == row.hostname,
                )
                .order_by(AuditEvent.timestamp.desc())
                .limit(50)
                .all()
            )
            entry["triage"] = incident_triage.triage_alert(
                silent_seconds=silent_seconds,
                notify_count=row.notify_count,
                alert_started_at=row.first_silent_at,
                recent_events=recent_events,
                now=now,
            )
        result.append(entry)
    return result


# ---------------------------------------------------------------------------
# 5b. Audit log - 45 CFR 164.312(b). Append-only; read-only over the API.
# ---------------------------------------------------------------------------
@app.get("/api/v1/audit-log")
def audit_log(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None, description="Exact action, e.g. device.delete"),
    since: Optional[datetime] = Query(None, description="ISO-8601; events at or after this time"),
):
    """Tenant-scoped, newest first.

    Deliberately scoped to the caller's tenant, which means failed logins for
    an *unrecognised* username - which have no tenant to attribute them to -
    are not returned here to anyone. They are still written, and are visible
    with direct database access. Surfacing them properly needs an
    administrator role that does not exist yet; that is the follow-up, not a
    reason to withhold the rest of the trail.

    There is no POST, PUT or DELETE counterpart, by design.
    """
    query = db.query(AuditEvent).filter(AuditEvent.tenant_id == current_user.tenant_id)
    if action:
        query = query.filter(AuditEvent.action == action)
    if since:
        query = query.filter(AuditEvent.timestamp >= since)

    total = query.count()
    rows = (
        query.order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [
            {
                "id": row.id,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "action": row.action,
                "outcome": row.outcome,
                "actor": row.actor_username,
                "target_type": row.target_type,
                "target_id": row.target_id,
                "source_ip": row.source_ip,
                "detail": row.detail,
            }
            for row in rows
        ],
    }


# ---------------------------------------------------------------------------
# 5c. Audit log summary - Compliance Documentation Agent, subagent 4a.
#
# Same tenant scope and filters as GET /api/v1/audit-log; the difference is
# the response is meant to be read directly (by a practice owner, or handed
# to an auditor) rather than parsed. See app/audit_summary.py for the
# no-PHI-in-detail invariant this relies on.
# ---------------------------------------------------------------------------
@app.get("/api/v1/audit-log/summary")
def audit_log_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    since: Optional[datetime] = Query(None, description="ISO-8601; events at or after this time"),
    until: Optional[datetime] = Query(None, description="ISO-8601; events at or before this time"),
    action: Optional[str] = Query(None, description="Exact action, e.g. device.delete"),
):
    query = db.query(AuditEvent).filter(AuditEvent.tenant_id == current_user.tenant_id)
    if action:
        query = query.filter(AuditEvent.action == action)
    if since:
        query = query.filter(AuditEvent.timestamp >= since)
    if until:
        query = query.filter(AuditEvent.timestamp <= until)

    rows = query.order_by(AuditEvent.timestamp.asc(), AuditEvent.id.asc()).all()
    return audit_summary.summarize_events(rows)


# ---------------------------------------------------------------------------
# 5d. Breach incidents & notification clocks - Compliance Documentation
# Agent, subagent 4c. See app/breach_clock.py for what the two clocks mean
# and app/models.py's BreachIncident for why `description` may hold PHI and
# must never reach the audit trail's `detail` column.
# ---------------------------------------------------------------------------
def _get_incident_or_404(incident_id: int, current_user: User, db: Session) -> BreachIncident:
    incident = (
        db.query(BreachIncident)
        .filter(BreachIncident.id == incident_id, BreachIncident.tenant_id == current_user.tenant_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/v1/breach-incidents", status_code=201)
def create_incident(
    payload: BreachIncidentIn,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        incident = BreachIncident(
            tenant_id=current_user.tenant_id,
            description=payload.description,
            discovered_at=payload.discovered_at,
            status="open",
        )
        db.add(incident)
        db.flush()
        audit.stage(
            db,
            action=audit.INCIDENT_CREATE,
            outcome=audit.SUCCESS,
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            tenant_id=current_user.tenant_id,
            target_type="breach_incident",
            target_id=str(incident.id),
            request=request,
        )
        db.commit()
        db.refresh(incident)
        return serialize_incident(incident)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")


@app.get("/api/v1/breach-incidents")
def list_incidents(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(BreachIncident)
        .filter(BreachIncident.tenant_id == current_user.tenant_id)
        .order_by(BreachIncident.discovered_at.desc())
        .all()
    )
    return [serialize_incident(row) for row in rows]


@app.get("/api/v1/breach-incidents/{incident_id}")
def get_incident(
    incident_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return serialize_incident(_get_incident_or_404(incident_id, current_user, db))


@app.post("/api/v1/breach-incidents/{incident_id}/confirm")
def confirm_incident(
    incident_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Starts both notification clocks. Idempotent: confirming an
    already-confirmed incident again does not push its deadlines out."""
    incident = _get_incident_or_404(incident_id, current_user, db)
    if incident.confirmed_at is None:
        try:
            incident.confirmed_at = datetime.utcnow()
            audit.stage(
                db,
                action=audit.INCIDENT_CONFIRM,
                outcome=audit.SUCCESS,
                actor_user_id=current_user.id,
                actor_username=current_user.username,
                tenant_id=current_user.tenant_id,
                target_type="breach_incident",
                target_id=str(incident.id),
                request=request,
            )
            db.commit()
            db.refresh(incident)
        except SQLAlchemyError as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"database error: {exc}")
    return serialize_incident(incident)


@app.post("/api/v1/breach-incidents/{incident_id}/notify")
def notify_incident(
    incident_id: int,
    payload: BreachIncidentNotifyIn,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Marks one of the three notification steps as actually sent. This
    never fires a real notification (see app/notify.py for the one channel
    that does exist, the on-call alert email) - it records that a human
    already sent one, which is the only source of truth for whether HIPAA's
    notice requirement has in fact been met."""
    incident = _get_incident_or_404(incident_id, current_user, db)
    if incident.confirmed_at is None:
        raise HTTPException(status_code=409, detail="Incident is not confirmed yet - nothing to stop the clock on")
    column = f"{payload.which}_at"
    try:
        setattr(incident, column, datetime.utcnow())
        audit.stage(
            db,
            action=audit.INCIDENT_NOTIFY,
            outcome=audit.SUCCESS,
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            tenant_id=current_user.tenant_id,
            target_type="breach_incident",
            target_id=str(incident.id),
            request=request,
            detail=f"which={payload.which}",
        )
        db.commit()
        db.refresh(incident)
        return serialize_incident(incident)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")


@app.post("/api/v1/breach-incidents/{incident_id}/close")
def close_incident(
    incident_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incident = _get_incident_or_404(incident_id, current_user, db)
    try:
        incident.status = "closed"
        audit.stage(
            db,
            action=audit.INCIDENT_CLOSE,
            outcome=audit.SUCCESS,
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            tenant_id=current_user.tenant_id,
            target_type="breach_incident",
            target_id=str(incident.id),
            request=request,
        )
        db.commit()
        db.refresh(incident)
        return serialize_incident(incident)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")


# ---------------------------------------------------------------------------
# 5e. Risk analysis worksheet - Compliance Documentation Agent, subagent 4b.
# See app/risk_worksheet.py for what is and is not auto-filled, and why.
# ---------------------------------------------------------------------------
@app.get("/api/v1/risk-analysis/worksheet")
def risk_analysis_worksheet(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    devices = db.query(Device).filter(Device.tenant_id == current_user.tenant_id).all()
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.tenant_id == current_user.tenant_id)
        .order_by(AuditEvent.timestamp.asc())
        .all()
    )
    return risk_worksheet.build_worksheet(
        tenant_name=tenant.name if tenant else "Unknown tenant",
        devices=devices,
        audit_result=audit_summary.summarize_events(events),
        monitoring_enabled=monitor.ALERT_ENABLED,
    )


# ---------------------------------------------------------------------------
# 5f. Patch & vulnerability compliance - fleet position 3. See
# app/patch_compliance.py for what "known_vulnerabilities" does and does not
# mean (a static EOL-driven table, not a live CVE feed).
# ---------------------------------------------------------------------------
@app.get("/api/v1/compliance/patch-status")
def patch_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    devices = (
        db.query(Device)
        .filter(Device.tenant_id == current_user.tenant_id)
        .order_by(Device.hostname)
        .all()
    )
    evaluations = [patch_compliance.evaluate_device(d) for d in devices]
    return {
        "total_devices": len(evaluations),
        "at_risk_count": sum(1 for e in evaluations if e["at_risk"]),
        "devices": evaluations,
    }


# ---------------------------------------------------------------------------
# 5g. Tenant settings - contact email + SLA target, used by the Client
# Reporting Agent (5) and the On-Call Escalation Router Agent (7). Never
# guessed or defaulted to something plausible-looking - see app/models.py's
# Tenant docstring on why both stay NULL until a technician sets them.
# ---------------------------------------------------------------------------
@app.get("/api/v1/tenant/settings")
def get_tenant_settings(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return serialize_tenant_settings(tenant)


@app.put("/api/v1/tenant/settings")
def update_tenant_settings(
    payload: TenantSettingsIn,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        changes = payload.model_dump(exclude_unset=True)
        for field, value in changes.items():
            setattr(tenant, field, value)
        audit.stage(
            db,
            action=audit.TENANT_SETTINGS_UPDATE,
            outcome=audit.SUCCESS,
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            tenant_id=current_user.tenant_id,
            target_type="tenant",
            target_id=tenant.name,
            request=request,
            detail=audit.changed_fields(changes),
        )
        db.commit()
        db.refresh(tenant)
        return serialize_tenant_settings(tenant)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")


# ---------------------------------------------------------------------------
# 5h. Client reports - Client Reporting Agent, subagents 5a/5b/5c. See
# app/client_report.py for how findings get translated to plain English and
# how the SLA scorecard is computed.
# ---------------------------------------------------------------------------
def _assemble_report(current_user: User, db: Session) -> dict:
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    devices = db.query(Device).filter(Device.tenant_id == current_user.tenant_id).all()
    device_evaluations = [patch_compliance.evaluate_device(d) for d in devices]

    now = datetime.utcnow()
    alert_rows = (
        db.query(DeviceAlertState)
        .filter(DeviceAlertState.tenant_id == current_user.tenant_id, DeviceAlertState.status == "alerting")
        .all()
    )
    open_alerts = [
        {
            "hostname": row.hostname,
            "silent_seconds": int((now - row.first_silent_at).total_seconds()) if row.first_silent_at else 0,
        }
        for row in alert_rows
    ]

    backup_rows = db.query(BackupRun).filter(BackupRun.tenant_id == current_user.tenant_id).all()
    backup_jobs = [
        {"job_name": job_name, **backup_compliance.backup_status(run, now=now)}
        for job_name, run in sorted(backup_compliance.latest_by_job(backup_rows, "completed_at").items())
    ]
    restore_rows = db.query(RestoreTest).filter(RestoreTest.tenant_id == current_user.tenant_id).all()
    restore_test_jobs = [
        {"job_name": job_name, **backup_compliance.restore_test_status(test, now=now)}
        for job_name, test in sorted(backup_compliance.latest_by_job(restore_rows, "tested_at").items())
    ]

    period_start = now - timedelta(days=30)
    events = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.tenant_id == current_user.tenant_id,
            AuditEvent.action.in_([audit.ALERT_TRIGGERED, audit.ALERT_RESOLVED]),
            AuditEvent.timestamp >= period_start,
        )
        .all()
    )
    scorecard = client_report.sla_scorecard(events, tenant.sla_response_minutes if tenant else None, now=now)

    tenant_name = tenant.name if tenant else "Unknown tenant"
    period_note = f"Covering the 30 days ending {now.date().isoformat()}."
    report_kwargs = dict(
        tenant_name=tenant_name,
        device_evaluations=device_evaluations,
        open_alerts=open_alerts,
        backup_jobs=backup_jobs,
        restore_test_jobs=restore_test_jobs,
        scorecard=scorecard,
        period_note=period_note,
    )
    report = client_report.build_report(**report_kwargs)
    html_body = client_report.build_html_report(**report_kwargs)
    return {"tenant": tenant, "report": report, "html_body": html_body}


@app.get("/api/v1/reports/preview")
def preview_report(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _assemble_report(current_user, db)["report"]


@app.get("/api/v1/reports/preview.html")
def preview_report_html(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Same report, rendered as the actual branded HTML - for a technician
    to eyeball in a browser before it goes to a client. The logo won't
    render here (cid: references only resolve inside an email client that
    received the related attachment) - that's expected for a preview."""
    return HTMLResponse(_assemble_report(current_user, db)["html_body"])


@app.post("/api/v1/reports/send")
def send_report(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    assembled = _assemble_report(current_user, db)
    tenant = assembled["tenant"]
    if not tenant or not tenant.contact_email:
        raise HTTPException(
            status_code=409,
            detail="No contact_email is configured for this tenant - set one via PUT /api/v1/tenant/settings first.",
        )
    report = assembled["report"]
    sent = notify.send_client_html_email(
        [tenant.contact_email],
        report["subject"],
        text_body=report["body"],
        html_body=assembled["html_body"],
        logo_bytes=client_report.load_logo_bytes(),
        logo_cid=client_report.LOGO_CID,
    )
    audit.record(
        db,
        action=audit.REPORT_SEND,
        outcome=audit.SUCCESS if sent else audit.FAILURE,
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        tenant_id=current_user.tenant_id,
        target_type="tenant",
        target_id=tenant.name,
        request=request,
        detail=f"to={tenant.contact_email}",
    )
    if not sent:
        raise HTTPException(status_code=502, detail="Report was assembled but the email did not send - see server logs.")
    return {"status": "sent", "to": tenant.contact_email, "subject": report["subject"]}


# ---------------------------------------------------------------------------
# 6. Agent heartbeat - API-key auth, not JWT (see module docstring)
# ---------------------------------------------------------------------------
@app.api_route("/agents/heartbeat", methods=["GET", "POST"], dependencies=[Depends(require_api_key)])
async def heartbeat(request: Request):
    if request.method == "GET":
        return {"status": "heartbeat endpoint online"}

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="body must be JSON")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    hostname = (data.get("hostname") or "").strip()[:255]
    if not hostname:
        raise HTTPException(status_code=422, detail="hostname is required")

    # Caps how much text an unauthenticated-by-default endpoint (MSP_API_KEY
    # is opt-in, see require_api_key above) can make this process write to
    # disk per field. Nothing enforced a limit here before, so a heartbeat
    # sender - malicious, or just a bug - could store megabytes per field per
    # request with no server-side backstop.
    _MAX_FIELD = 255

    def as_text(value):
        return None if value is None else str(value)[:_MAX_FIELD]

    def as_datetime(value):
        # agent.ps1 sends .NET's round-trip ("o") format, which can carry 7
        # fractional-second digits and a trailing "Z" - Python's fromisoformat
        # caps fractional seconds at 6 digits. Stored as naive UTC, matching
        # every other timestamp in this schema (all set via datetime.utcnow()).
        # Never let a malformed or unparseable timestamp fail the whole
        # heartbeat over one optional field.
        if not value:
            return None
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        if "." in text:
            base, _, tail = text.partition(".")
            frac_digits = ""
            i = 0
            while i < len(tail) and tail[i].isdigit():
                frac_digits += tail[i]
                i += 1
            text = f"{base}.{frac_digits[:6]}{tail[i:]}"
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            return None

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.hostname == hostname).first()
        if device:
            # Only overwrite fields the agent actually reported, so a sparse
            # heartbeat can't blank out details entered in the dashboard.
            for field in ("ip", "cpu", "ram", "disk", "os"):
                if data.get(field) is not None:
                    setattr(device, field, as_text(data.get(field)))
            if "av_enabled" in data:
                device.av_enabled = bool(data.get("av_enabled")) if data.get("av_enabled") is not None else None
            if "av_signature_updated_at" in data:
                device.av_signature_updated_at = as_datetime(data.get("av_signature_updated_at"))
            device.last_seen = datetime.utcnow()
        else:
            tenant = resolve_or_create_tenant(db, data.get("tenant"))
            device = Device(
                hostname=hostname,
                ip=as_text(data.get("ip")),
                cpu=as_text(data.get("cpu")),
                ram=as_text(data.get("ram")),
                disk=as_text(data.get("disk")),
                os=as_text(data.get("os")),
                location="",
                notes="",
                last_seen=datetime.utcnow(),
                tenant_id=tenant.id,
                av_enabled=bool(data.get("av_enabled")) if data.get("av_enabled") is not None else None,
                av_signature_updated_at=as_datetime(data.get("av_signature_updated_at")),
            )
            db.add(device)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")
    finally:
        db.close()

    return {"message": "heartbeat received", "hostname": hostname}


# ---------------------------------------------------------------------------
# 6a/6b. Backup & Continuity Verification Agent (fleet position 6) - report
# ingestion. Same API-key auth as /agents/heartbeat, for the same reason: an
# unattended backup/restore-test script can't do an interactive login.
# ---------------------------------------------------------------------------
@app.post("/agents/backup-report", status_code=201, dependencies=[Depends(require_api_key)])
def backup_report(payload: BackupReportIn):
    db = SessionLocal()
    try:
        tenant = resolve_or_create_tenant(db, payload.tenant)
        run = BackupRun(
            tenant_id=tenant.id,
            job_name=payload.job_name,
            completed_at=payload.completed_at,
            success=payload.success,
            size_bytes=payload.size_bytes,
            detail=payload.detail,
        )
        db.add(run)
        db.commit()
        return {"message": "backup report received", "job_name": payload.job_name}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")
    finally:
        db.close()


@app.post("/agents/restore-test-report", status_code=201, dependencies=[Depends(require_api_key)])
def restore_test_report(payload: RestoreTestReportIn):
    db = SessionLocal()
    try:
        tenant = resolve_or_create_tenant(db, payload.tenant)
        test = RestoreTest(
            tenant_id=tenant.id,
            job_name=payload.job_name,
            tested_at=payload.tested_at,
            success=payload.success,
            notes=payload.notes,
        )
        db.add(test)
        db.commit()
        return {"message": "restore test report received", "job_name": payload.job_name}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")
    finally:
        db.close()


@app.post("/api/v1/oncall/contacts", status_code=201)
def create_oncall_contact(payload: OnCallContactIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    contact = OnCallContact(**payload.model_dump())
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return serialize_contact(contact)


@app.get("/api/v1/oncall/contacts")
def list_oncall_contacts(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(OnCallContact).order_by(OnCallContact.name).all()
    return [serialize_contact(row) for row in rows]


@app.delete("/api/v1/oncall/contacts/{contact_id}")
def delete_oncall_contact(contact_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    contact = db.query(OnCallContact).filter(OnCallContact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(contact)
    db.commit()
    return {"status": "deleted", "id": contact_id}


@app.get("/api/v1/oncall/route")
def route_oncall(
    severity: str = Query(..., description="low, medium, high, or critical"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """7a + 7b: who gets notified for an alert of this severity, right now."""
    if severity not in escalation_router.SEVERITY_RANK:
        raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(escalation_router.SEVERITY_RANK)}")
    contacts = db.query(OnCallContact).filter(OnCallContact.active == True).all()  # noqa: E712
    routed = escalation_router.route_contacts(severity=severity, contacts=contacts)
    return {
        "severity": severity,
        "business_hours": escalation_router.is_business_hours(),
        "contacts": [serialize_contact(c) for c in routed],
    }


@app.get("/api/v1/backups/status")
def backups_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(BackupRun).filter(BackupRun.tenant_id == current_user.tenant_id).all()
    latest = backup_compliance.latest_by_job(rows, "completed_at")
    jobs = [
        {
            "job_name": job_name,
            "last_completed_at": run.completed_at.isoformat(),
            **backup_compliance.backup_status(run),
        }
        for job_name, run in sorted(latest.items())
    ]
    return {"jobs": jobs, "at_risk_count": sum(1 for j in jobs if j["status"] != backup_compliance.STATUS_OK)}


@app.get("/api/v1/backups/restore-tests")
def backups_restore_tests(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(RestoreTest).filter(RestoreTest.tenant_id == current_user.tenant_id).all()
    latest = backup_compliance.latest_by_job(rows, "tested_at")
    jobs = [
        {
            "job_name": job_name,
            "last_tested_at": test.tested_at.isoformat(),
            **backup_compliance.restore_test_status(test),
        }
        for job_name, test in sorted(latest.items())
    ]
    return {"jobs": jobs, "at_risk_count": sum(1 for j in jobs if j["status"] != backup_compliance.STATUS_OK)}


# ---------------------------------------------------------------------------
# 8a/8b/8c. Billing & Renewal Agent (fleet position 8). See app/billing.py -
# every figure here comes from Tenant fields a technician entered via
# PUT /api/v1/tenant/settings; nothing is estimated or defaulted.
# ---------------------------------------------------------------------------
@app.get("/api/v1/billing/invoice/preview")
def invoice_preview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    period_start: Optional[datetime] = Query(None),
    period_end: Optional[datetime] = Query(None),
):
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    device_count = db.query(Device).filter(Device.tenant_id == current_user.tenant_id).count()
    now = datetime.utcnow()
    start = period_start or now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = period_end or now
    return billing.generate_invoice(
        tenant_name=tenant.name if tenant else "Unknown tenant",
        monthly_base_fee_cents=tenant.monthly_base_fee_cents if tenant else None,
        per_device_fee_cents=tenant.per_device_fee_cents if tenant else None,
        device_count=device_count,
        period_start=start,
        period_end=end,
    )


@app.get("/api/v1/billing/renewals")
def billing_renewals(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    within_days: int = Query(billing.DEFAULT_RENEWAL_WINDOW_DAYS, ge=1, le=3650),
):
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    due = billing.renewals_due(
        msa_renewal_date=tenant.msa_renewal_date,
        sma_renewal_date=tenant.sma_renewal_date,
        baa_renewal_date=tenant.baa_renewal_date,
        within_days=within_days,
    )
    return {"within_days": within_days, "contracts_due": due}


@app.get("/api/v1/billing/churn-risk")
def billing_churn_risk(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    current_window_start = now - timedelta(days=30)
    prior_window_start = now - timedelta(days=60)

    def login_count(start, end):
        return (
            db.query(AuditEvent)
            .filter(
                AuditEvent.tenant_id == current_user.tenant_id,
                AuditEvent.action == audit.LOGIN_SUCCESS,
                AuditEvent.timestamp >= start,
                AuditEvent.timestamp < end,
            )
            .count()
        )

    current_logins = login_count(current_window_start, now)
    prior_logins = login_count(prior_window_start, current_window_start)
    result = billing.churn_risk(current_period_logins=current_logins, prior_period_logins=prior_logins)
    return {"current_period_logins": current_logins, "prior_period_logins": prior_logins, **result}


# ---------------------------------------------------------------------------
# 9. AI-Vendor Compliance Agent - oversight only, not tenant-scoped. See
# app/ai_vendor_compliance.py: this is Endpoint Shield Solutions checking
# its OWN AI/ML vendor supply chain, never shown to a client.
# ---------------------------------------------------------------------------
@app.post("/api/v1/ai-vendors", status_code=201)
def create_ai_vendor(payload: AIVendorIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    vendor = AIVendor(**payload.model_dump())
    db.add(vendor)
    db.commit()
    db.refresh(vendor)
    return serialize_ai_vendor(vendor)


@app.get("/api/v1/ai-vendors")
def list_ai_vendors(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(AIVendor).order_by(AIVendor.name).all()
    return [serialize_ai_vendor(row) for row in rows]


@app.delete("/api/v1/ai-vendors/{vendor_id}")
def delete_ai_vendor(vendor_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    vendor = db.query(AIVendor).filter(AIVendor.id == vendor_id).first()
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    db.delete(vendor)
    db.commit()
    return {"status": "deleted", "id": vendor_id}


@app.get("/api/v1/ai-vendors/compliance-status")
def ai_vendor_compliance_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(AIVendor).order_by(AIVendor.name).all()
    return ai_vendor_compliance.evaluate_all(rows)


# ---------------------------------------------------------------------------
# 10. Client Acquisition / Referral Agent. Referral-partner management is
# technician-only (JWT); POST /api/v1/leads is deliberately public - a
# prospect who has never logged in needs to be able to submit one. That is
# a known, accepted surface: it carries the same body-size cap as every
# other route (see limit_body_size above) but no CAPTCHA or extra rate
# limiting yet - add one before pointing real ad spend at this endpoint.
# ---------------------------------------------------------------------------
@app.post("/api/v1/referral-partners", status_code=201)
def create_referral_partner(payload: ReferralPartnerIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    partner = ReferralPartner(**payload.model_dump())
    db.add(partner)
    db.commit()
    db.refresh(partner)
    return serialize_referral_partner(partner)


@app.get("/api/v1/referral-partners")
def list_referral_partners(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(ReferralPartner).order_by(ReferralPartner.name).all()
    return [serialize_referral_partner(row) for row in rows]


@app.get("/api/v1/referral-partners/{partner_id}/draft-outreach")
def draft_referral_outreach(partner_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    partner = db.query(ReferralPartner).filter(ReferralPartner.id == partner_id).first()
    if not partner:
        raise HTTPException(status_code=404, detail="Referral partner not found")
    return referral.draft_referral_outreach(partner_name=partner.name, partner_type=partner.partner_type)


@app.post("/api/v1/leads", status_code=201)
def submit_lead(payload: LeadIn, db: Session = Depends(get_db)):
    lead = Lead(**payload.model_dump(), submitted_at=datetime.utcnow())
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return serialize_lead(lead)


@app.get("/api/v1/leads")
def list_leads(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Lead).order_by(Lead.submitted_at.desc()).all()
    return [serialize_lead(row) for row in rows]


# ---------------------------------------------------------------------------
# 7. Device CRUD (consumed by msp-dashboard) - JWT-authenticated, tenant-scoped
# ---------------------------------------------------------------------------
@app.get("/devices")
def list_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(Device)
        .filter(Device.tenant_id == current_user.tenant_id)
        .order_by(Device.hostname)
        .all()
    )
    return [serialize(row) for row in rows]


@app.get("/devices/{hostname}")
def get_device(hostname: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    device = (
        db.query(Device)
        .filter(Device.hostname == hostname, Device.tenant_id == current_user.tenant_id)
        .first()
    )
    if not device:
        # 404, not 403 - confirming a hostname exists under another tenant
        # is itself a cross-tenant information leak.
        raise HTTPException(status_code=404, detail="Device not found")
    return serialize(device)


@app.post("/devices", status_code=201)
def create_device(
    payload: DeviceIn,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    exists = db.query(Device).filter(Device.hostname == payload.hostname).first()
    if exists:
        raise HTTPException(status_code=409, detail=f"Device '{payload.hostname}' already exists")
    try:
        # last_seen stays NULL: a hand-added device has never checked in, so
        # the dashboard shows it as "Never" / Offline until an agent reports.
        device = Device(**payload.model_dump(), last_seen=None, tenant_id=current_user.tenant_id)
        db.add(device)
        # Staged, not committed: the audit row rides the same transaction as
        # the change, so a device can never be created without one.
        audit.stage(
            db,
            action=audit.DEVICE_CREATE,
            outcome=audit.SUCCESS,
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            tenant_id=current_user.tenant_id,
            target_type="device",
            target_id=payload.hostname,
            request=request,
        )
        db.commit()
        db.refresh(device)
        return serialize(device)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")


@app.put("/devices/{hostname}")
def update_device(
    hostname: str,
    payload: DeviceUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = (
        db.query(Device)
        .filter(Device.hostname == hostname, Device.tenant_id == current_user.tenant_id)
        .first()
    )
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    try:
        changes = {
            field: value
            for field, value in payload.model_dump(exclude_unset=True).items()
            if value is not None
        }
        for field, value in changes.items():
            setattr(device, field, value)
        audit.stage(
            db,
            action=audit.DEVICE_UPDATE,
            outcome=audit.SUCCESS,
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            tenant_id=current_user.tenant_id,
            target_type="device",
            target_id=hostname,
            request=request,
            # Field names only - `notes` and `location` are free text and
            # could contain PHI. See app/audit.py, rule 2.
            detail=audit.changed_fields(changes),
        )
        db.commit()
        db.refresh(device)
        return serialize(device)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")


@app.delete("/devices/{hostname}")
def delete_device(
    hostname: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = (
        db.query(Device)
        .filter(Device.hostname == hostname, Device.tenant_id == current_user.tenant_id)
        .first()
    )
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    try:
        db.delete(device)
        audit.stage(
            db,
            action=audit.DEVICE_DELETE,
            outcome=audit.SUCCESS,
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            tenant_id=current_user.tenant_id,
            target_type="device",
            target_id=hostname,
            request=request,
        )
        db.commit()
        return {"status": "deleted", "hostname": hostname}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"database error: {exc}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9000)
