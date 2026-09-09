"""SQLAlchemy models for the MSP backend.

This file used to be a PowerShell heredoc (`@"..."@ | Set-Content`) saved
with a .py extension - not valid Python, never importable. This is the real
schema replacing it.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String

from app.database import Base


class Tenant(Base):
    """One row per MSP client (e.g. one dental office). Devices and users
    both belong to exactly one tenant; a logged-in user only ever sees
    devices in their own tenant - see app/main.py's device routes."""

    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    # Client Reporting Agent (fleet position 5) / On-Call Escalation Router
    # Agent (fleet position 7). Both NULL until a technician sets them via
    # PUT /api/v1/tenants/{id}/settings - there is no sensible default
    # response-time commitment or client contact to guess, and guessing one
    # would be exactly the mistake COMPLIANCE-GAPS.md warns against: a number
    # that sounds authoritative but was never actually agreed with the client.
    contact_email = Column(String, nullable=True)
    sla_response_minutes = Column(Integer, nullable=True)

    # Billing & Renewal Agent (fleet position 8). All NULL until a
    # technician enters the client's actual contracted rate and dates via
    # PUT /api/v1/tenant/settings - same reasoning as contact_email/
    # sla_response_minutes above: no default is honest here, only "not set
    # yet". Money amounts are stored in cents (Integer) to avoid float
    # rounding in anything that later sums or compares them.
    monthly_base_fee_cents = Column(Integer, nullable=True)
    per_device_fee_cents = Column(Integer, nullable=True)
    msa_renewal_date = Column(DateTime, nullable=True)
    sma_renewal_date = Column(DateTime, nullable=True)
    baa_renewal_date = Column(DateTime, nullable=True)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    # Unique across ALL tenants, not just within one - a known limitation,
    # not an oversight: two different clients could plausibly both name a
    # machine "Front-Desk-PC". Changing this to unique-per-tenant also means
    # changing how agent.ps1 identifies itself in a heartbeat, and how a
    # tenant-scoped id is threaded back through /agents/heartbeat, which is
    # its own real design task - not folded in silently here.
    hostname = Column(String, unique=True, index=True, nullable=False)
    ip = Column(String)
    cpu = Column(String)
    ram = Column(String)
    disk = Column(String)
    os = Column(String)
    location = Column(String, default="")
    notes = Column(String, default="")
    # No column-level default: see app/main.py's create_device for why
    # (a SQLAlchemy Python-side default fires even when None is explicit).
    last_seen = Column(DateTime)
    # Nullable at the DB level only so ALTER TABLE ADD COLUMN works against
    # an existing SQLite table with rows in it (SQLite can't add a NOT NULL
    # column with no default to a non-empty table). Every code path that
    # creates a Device sets this explicitly - see migrate_to_tenants.py for
    # backfilling rows that predate this column.
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)

    # Patch & Vulnerability Compliance Agent, subagent 3b (AV/Endpoint
    # Protection Currency). Populated by agent.ps1's Get-MpComputerStatus
    # call, same as every other heartbeat field - NULL means "this agent
    # build predates AV reporting or Defender status couldn't be read", not
    # "AV is off". app/patch_compliance.py treats NULL as unknown, never as
    # a pass or a fail.
    av_enabled = Column(Boolean, nullable=True)
    av_signature_updated_at = Column(DateTime, nullable=True)


class DeviceAlertState(Base):
    """Working state for the silent-endpoint monitor (app/monitor.py).

    One row per device, kept in sync with whether that device is currently
    past the offline threshold. This is mutable and disposable - it exists so
    the monitor knows "have I already notified about this outage" and "how
    long has it been down", not as a record of what happened. The durable,
    append-only record of alert activity is in audit_events (action=
    alert.triggered / alert.escalated / alert.resolved), written alongside
    every state change here. If this table were dropped and recreated, the
    worst case is one duplicate notification on the next poll - never lost
    history, because the history lives in the audit trail, not here.
    """

    __tablename__ = "device_alert_state"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, unique=True, index=True, nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)

    # "ok" - last check saw the device online/stale (not alertable).
    # "alerting" - device has been silent past the offline threshold and at
    # least one notification has gone out.
    status = Column(String, nullable=False, default="ok")

    first_silent_at = Column(DateTime, nullable=True)
    last_notified_at = Column(DateTime, nullable=True)
    notify_count = Column(Integer, nullable=False, default=0)


class BreachIncident(Base):
    """A tracked security incident, from discovery through notification.

    Compliance Documentation Agent, subagent 4c ("Breach-Notification Clock").
    Existing prose in app/monitor.py already names the two clocks this model
    exists to make visible: the BAA's 72-hour business-associate-to-covered-
    entity clock, and HIPAA's own 60-day clock to individuals/HHS/media
    (45 CFR §164.404, §164.406, §164.408). Both clocks start at the same
    instant - `confirmed_at` - and are computed live in app/breach_clock.py,
    not stored, so changing BREACH_*_HOURS/DAYS there re-derives every
    incident's status instead of leaving old rows stamped with an old policy.

    `description` is free text a technician writes about what happened and,
    like Device.notes/location (see app/audit.py's module docstring), may
    contain PHI. It is application data returned to the tenant's own
    authenticated users - same as a device's notes - but it must never be
    copied into the audit trail's `detail` column; see the audit.stage calls
    in app/main.py's breach-incident routes.
    """

    __tablename__ = "breach_incidents"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)

    description = Column(String, nullable=False)

    discovered_at = Column(DateTime, nullable=False)
    # NULL until someone confirms this is a reportable breach rather than a
    # false alarm - the clocks below have no meaning before that judgment
    # call is made, so both routines in app/breach_clock.py treat a NULL
    # confirmed_at as "not yet started", not as "overdue since the epoch".
    confirmed_at = Column(DateTime, nullable=True)

    # Each set once, by a technician marking that notification actually went
    # out - never computed or defaulted, because only a human knows whether
    # the notification was actually sent.
    ba_notified_covered_entity_at = Column(DateTime, nullable=True)
    individuals_notified_at = Column(DateTime, nullable=True)
    regulator_notified_at = Column(DateTime, nullable=True)

    # "open" until a technician closes it out - not inferred from the three
    # notification timestamps above, because closing an incident is its own
    # decision (e.g. post-incident review is also done) that shouldn't be
    # backed into automatically just because every clock reads "met".
    status = Column(String, nullable=False, default="open")


class BackupRun(Base):
    """One reported backup job completion - Backup & Continuity Verification
    Agent, subagent 6a. Rows arrive via POST /agents/backup-report, the same
    API-key auth as /agents/heartbeat (see app/main.py's module docstring) -
    an unattended backup script can't do an interactive login any more than
    the device agent can. `job_name` is technician-assigned (e.g. a NAS
    name, or a hostname if the backup is per-device) and is how
    app/backup_compliance.py groups runs into "the latest run of this job".
    """

    __tablename__ = "backup_runs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    job_name = Column(String, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=False)
    success = Column(Boolean, nullable=False)
    size_bytes = Column(Integer, nullable=True)
    detail = Column(String, nullable=True)


class RestoreTest(Base):
    """One reported restore-test attempt - subagent 6b. A completed backup
    is not evidence the backup is usable; this is the separate record that
    someone (or some script) actually tried restoring from it. Same
    ingestion pattern as BackupRun - see POST /agents/restore-test-report.
    """

    __tablename__ = "restore_tests"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    job_name = Column(String, nullable=False, index=True)
    tested_at = Column(DateTime, nullable=False)
    success = Column(Boolean, nullable=False)
    notes = Column(String, nullable=True)


class OnCallContact(Base):
    """One member of Endpoint Shield Solutions' OWN on-call roster - On-Call
    / Escalation Router Agent, subagents 7a/7b. Deliberately NOT tenant-
    scoped: this is the MSP's internal team, the same roster regardless of
    which client's dashboard a technician happens to be looking at, unlike
    every tenant-scoped table elsewhere in this schema.
    """

    __tablename__ = "oncall_contacts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    # "low" / "medium" / "high" / "critical" - see
    # app/escalation_router.py's SEVERITY_RANK. A contact is routed an alert
    # whose severity meets or exceeds this floor, so "low" hears everything
    # and "critical" hears only the worst.
    min_severity = Column(String, nullable=False, default="low")
    notify_business_hours = Column(Boolean, nullable=False, default=True)
    notify_after_hours = Column(Boolean, nullable=False, default=True)
    active = Column(Boolean, nullable=False, default=True)


class AIVendor(Base):
    """One AI/ML vendor used anywhere in Endpoint Shield Solutions' OWN
    pipeline - AI-Vendor Compliance Agent (fleet position 9, oversight only:
    this is never shown to a client, it is this MSP checking its own
    supply chain). Not tenant-scoped, same reasoning as OnCallContact: one
    vendor list for the whole business, not per client.
    """

    __tablename__ = "ai_vendors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    purpose = Column(String, nullable=False)  # e.g. "threat classification", "support chatbot"
    has_baa = Column(Boolean, nullable=False, default=False)
    baa_signed_date = Column(DateTime, nullable=True)
    data_retention_opted_out = Column(Boolean, nullable=False, default=False)
    notes = Column(String, nullable=True)


class ReferralPartner(Base):
    """Client Acquisition / Referral Agent (fleet position 10), subagent
    10a's target list - practice consultants, accountants, generalist IT
    providers who might refer a client this MSP's way. Not tenant-scoped:
    these are Endpoint Shield Solutions' own contacts, not a client's.
    """

    __tablename__ = "referral_partners"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    contact_email = Column(String, nullable=False)
    partner_type = Column(String, nullable=False)  # e.g. "IT provider", "consultant", "accountant"
    last_contacted_at = Column(DateTime, nullable=True)


class Lead(Base):
    """One inbound prospect - subagent 10b. Not tenant-scoped: a lead isn't
    a client yet."""

    __tablename__ = "leads"

    id = Column(Integer, primary_key=True, index=True)
    practice_name = Column(String, nullable=False)
    contact_email = Column(String, nullable=False)
    practice_type = Column(String, nullable=True)  # e.g. "dental", "medical", "hospital"
    device_count_estimate = Column(Integer, nullable=True)
    has_existing_it_support = Column(Boolean, nullable=True)
    notes = Column(String, nullable=True)
    submitted_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class AuditEvent(Base):
    """Append-only record of who did what, for 45 CFR § 164.312(b).

    Nothing in the application updates or deletes a row here, and no route
    exposes a way to. See app/audit.py for what may and may not be written -
    in particular: never credentials, and never field values from device
    records, which are free text and may contain PHI.
    """

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    # e.g. "login.success", "device.update" - see the constants in app/audit.py.
    action = Column(String, nullable=False, index=True)
    # "success" or "failure".
    outcome = Column(String, nullable=False)

    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    # Denormalised on purpose: an audit trail has to stay readable after the
    # user row is gone, and a failed login for an unknown username has no
    # user row to point at in the first place.
    actor_username = Column(String, nullable=True, index=True)

    # NULL for a failed login with an unrecognised username - there is no
    # tenant to attribute it to. Those rows are therefore not returned by the
    # tenant-scoped API; see the note on GET /api/v1/audit-log in app/main.py.
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)

    target_type = Column(String, nullable=True)   # e.g. "device"
    target_id = Column(String, nullable=True)     # e.g. the hostname

    source_ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    # Field NAMES only, never values. See app/audit.py, rule 2.
    detail = Column(String, nullable=True)
