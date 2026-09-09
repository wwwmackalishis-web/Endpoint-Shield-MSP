# Endpoint Shield Solutions

Multi-tenant endpoint monitoring and antivirus orchestration for dental and medical practices.

FastAPI backend · React dashboard · PowerShell agent

---

## Contents

- [What this is](#what-this-is)
- [System Architecture](#system-architecture)
- [Data Model & Tenant Isolation](#data-model--tenant-isolation)
- [HIPAA Compliance Posture](#hipaa-compliance-posture)
- [Deployment Guide (Render)](#deployment-guide-render)
- [Local Development](#local-development)
- [Operations Runbook](#operations-runbook)
- [Known Limitations](#known-limitations)

---

## What this is

Endpoint Shield Solutions inventories the workstations at a client practice, tracks whether each one is reporting in, and surfaces silent endpoints to a technician. A PowerShell agent on each machine posts a heartbeat; the backend records it; the dashboard shows fleet state and lets a technician manage the inventory.

**Scope boundary, stated up front:** the platform monitors *endpoint availability and inventory*. It does not read, store, transmit, or process patient records. This distinction governs everything in the compliance section below, and it is the single most important sentence to get right in front of a client.

---

## System Architecture

```
┌──────────────────┐        JWT (Bearer)         ┌──────────────────┐
│  React Dashboard │ ──────────────────────────► │                  │
│  (msp-dashboard) │ ◄────────────────────────── │  FastAPI backend │
└──────────────────┘      tenant-scoped JSON     │   (app/main.py)  │
                                                 │                  │
┌──────────────────┐      X-API-Key header       │                  │
│  agent.ps1       │ ──────────────────────────► │                  │
│  (per endpoint)  │        heartbeat            └────────┬─────────┘
└──────────────────┘                                      │
                                                 ┌────────▼─────────┐
                                                 │ SQLite (dev)     │
                                                 │ Postgres (prod)  │
                                                 └──────────────────┘
```

### Hybrid authentication: JWT for humans, API key for agents

Two credential types, deliberately separate, because the two callers have genuinely different constraints.

**JWT — technician dashboard sessions** (`app/auth.py`)

| Property | Value |
|---|---|
| Algorithm | HS256 |
| Issued by | `POST /api/login` (OAuth2 password form) |
| Lifetime | 8 hours (one technician workday) |
| Claims | `sub` (username), `tenant_id`, `exp` |
| Password storage | bcrypt via passlib |
| Signing secret | `MSP_JWT_SECRET` environment variable |

Every `/devices/*` route depends on `get_current_user`, which decodes the bearer token and loads the user. There is no unauthenticated path to device data.

**API key — unattended agent heartbeats** (`app/main.py`)

An unattended background script cannot perform an interactive login/refresh cycle the way a browser session can. `POST /agents/heartbeat` therefore authenticates with a shared secret in the `X-API-Key` header, compared using `secrets.compare_digest` to avoid timing leaks.

> **Operational warning:** API-key enforcement is **opt-in**. If `MSP_API_KEY` is unset, the heartbeat endpoint accepts anonymous posts — and because an unknown `tenant` value in a heartbeat payload creates a new tenant row, an unauthenticated caller can create tenants. `GET /health` reports `auth_enforced: true|false` so you can confirm at a glance. **`MSP_API_KEY` must be set in every environment that is not localhost.**

### Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/` | none | Service identity |
| `GET` | `/health` | none | Liveness + cross-tenant fleet counts |
| `POST` | `/api/login` | none | Exchange credentials for a JWT |
| `GET` | `/api/v1/health-audit` | JWT | Per-tenant endpoint reporting summary |
| `GET` | `/api/v1/audit-log` | JWT | Per-tenant access/change audit trail (§164.312(b)) |
| `GET`/`POST` | `/agents/heartbeat` | API key | Agent check-in |
| `GET` | `/devices` | JWT | List devices in caller's tenant |
| `GET` | `/devices/{hostname}` | JWT | Single device |
| `POST` | `/devices` | JWT | Create device |
| `PUT` | `/devices/{hostname}` | JWT | Update device |
| `DELETE` | `/devices/{hostname}` | JWT | Remove device |

### Status thresholds

Backend (`fleet_status`) and frontend (`getStatus` in `App.js`) intentionally use identical windows. If you change one, change both, or the dashboard and the API will silently disagree about what "online" means.

| Status | Condition |
|---|---|
| Online | last heartbeat < 2 minutes ago |
| Stale | 2–10 minutes ago |
| Offline | > 10 minutes ago, or never |

`/api/v1/health-audit` uses a separate 5-minute window and flags a tenant **Degraded** above 10% silent endpoints.

---

## Data Model & Tenant Isolation

```
Tenant ──┬── User       (username, bcrypt hash, tenant_id)
         ├── Device     (hostname, ip, cpu, ram, disk, os, location, notes, last_seen, tenant_id)
         └── AuditEvent (timestamp, action, outcome, actor, target, source_ip, detail, tenant_id)
```

Tenant isolation is enforced in the query layer: every device route filters on `Device.tenant_id == current_user.tenant_id`. A device belonging to another tenant returns **404, not 403** — confirming that a hostname exists under a different client is itself a cross-tenant information leak.

**Isolation is logical, not physical.** All clients share one database and one application process. This is a defensible architecture and it is what most MSP platforms do, but describe it accurately to clients and auditors — do not imply physically separated instances.

---

## HIPAA Compliance Posture

Read this section before signing anything. It separates what the platform enforces today from what the business must supply around it.

### Why this matters at all

If Endpoint Shield Solutions administers workstations at a covered entity and could encounter ePHI in the course of that work, it is a **Business Associate** under 45 CFR Part 160/164. Business Associates carry direct liability under the HITECH Act — not merely contractual exposure to the practice.

### Implemented in code

| Safeguard | Status | Where |
|---|---|---|
| Unique user identification (§164.312(a)(2)(i)) | ✅ Per-user accounts, no shared logins | `app/models.py` |
| Authentication (§164.312(d)) | ✅ bcrypt + signed JWT | `app/auth.py` |
| Access control / least privilege by tenant (§164.312(a)(1)) | ✅ Tenant-scoped queries | `app/main.py` |
| Automatic logoff (§164.312(a)(2)(iii)) | ⚠️ Partial — 8h token expiry, no idle timeout | `app/auth.py` |
| Audit controls (§164.312(b)) | ✅ Append-only log of logins and device changes | `app/audit.py` |
| Transmission security (§164.312(e)(1)) | ⚠️ Depends on deployment — TLS terminated by Render, not by the app | — |

### Not implemented — required before any BAA is signed

| Gap | Why it matters |
|---|---|
| **No encryption at rest** | SQLite/Postgres content is stored unencrypted by the application. Addressable rather than required under §164.312(a)(2)(iv) — but if a BAA asserts encryption at rest, it must actually exist. |
| **No idle session timeout** | An 8-hour token on an unattended workstation in an operatory is a real exposure. |
| **No MFA** | Not strictly required by the Security Rule; expected by most practice-side security questionnaires and by cyber-liability underwriters. |
| **No alerting or on-call** | The dashboard shows status while a browser has it open. There is no paging, escalation, or after-hours coverage. "24/7 monitoring" cannot be claimed without it. |
| **No breach notification procedure** | §164.410 obliges a Business Associate to notify the covered entity of a breach. This is a documented process, not code. |
| **No risk analysis, workforce training, sanction policy, contingency plan** | §164.308 administrative safeguards. No software supplies these. |

### Audit logging

`app/audit.py` writes an append-only row to `audit_events` for every login attempt (success and failure) and every device create, update, and delete — with actor, tenant, target, source IP, and timestamp. Read it back with `GET /api/v1/audit-log` (JWT, tenant-scoped, newest first, filterable by `action` and `since`). There is no write route, by design.

Two rules the module enforces, both worth understanding before extending it:

- **Credentials are never recorded.** A failed login stores the attempted username and nothing else.
- **Device field values are never recorded** — only the field *names* that changed. `notes` and `location` are free text a technician types, either could contain PHI, and this table has a six-year retention requirement and no PHI controls around it.

Device mutations stage their audit row in the *same transaction* as the change, so a device cannot be modified without a corresponding record, and a rolled-back change leaves no phantom one. Login events commit separately; set `MSP_AUDIT_STRICT=1` to make a failed audit write abort the login rather than proceed unlogged.

Known limitation: the read API is tenant-scoped, so failed logins for an *unrecognised* username — which have no tenant to attribute them to — are written but not returned to anyone over HTTP. Surfacing those needs an administrator role that does not exist yet.

Retention: there is deliberately no purge routine. §164.316(b)(2)(i) requires six years. Do not add one without a written retention policy behind it.

### The honest summary

The technical access controls and the audit trail are real. **Encryption at rest, alerting, and the administrative-safeguard layer are not there yet.** Sell what runs; build the rest before the language in a BAA depends on it.

---

## Deployment Guide (Render)

### 1. Provision Postgres first

**Do not deploy on SQLite.** Render's default filesystem is ephemeral — every device row is lost on each redeploy. Create a Render PostgreSQL instance and use its internal connection string.

### 2. Web service

| Setting | Value |
|---|---|
| Environment | Python 3 |
| Build command | `pip install -r requirements.txt` |
| Start command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| Health check path | `/health` |

### 3. Environment variables

| Variable | Required | Notes |
|---|---|---|
| `MSP_DATABASE_URL` | **Yes** | Render Postgres internal URL. Overrides SQLite entirely. |
| `MSP_JWT_SECRET` | **Yes** | 32+ random bytes: `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Without it the app falls back to a publicly-known dev string and every token it issues is forgeable. It logs a warning; treat that warning as a production outage. |
| `MSP_API_KEY` | **Yes** | Shared secret for agent heartbeats. Must match `agent.ps1`. Unset means the heartbeat endpoint is open. |
| `MSP_CORS_ORIGINS` | **Yes** | Comma-separated dashboard origins, e.g. `https://dashboard.endpointshield.com`. Defaults to `*`, which is unacceptable in production. |
| `MSP_TRUST_PROXY` | **Yes on Render** | Set to `1` so audit rows record the real client IP from `X-Forwarded-For` rather than the proxy's. Leave unset locally — the header is spoofable when the app is reachable directly. |
| `MSP_AUDIT_STRICT` | Optional | `1` makes a failed audit write abort the login it was recording. Stricter reading of §164.312(b); off by default so an audit-table problem can't take the service down mid-appointment. |

### 4. Post-deploy verification

```bash
curl https://<service>.onrender.com/health
```

Confirm in the response:

- `"auth_enforced": true` — if `false`, `MSP_API_KEY` did not take effect. Stop and fix before onboarding a client.
- `"cors_origins"` lists your real domain, not `["*"]`.
- `"database"` reports `postgresql (external)`, not a file path.

Then confirm `/devices` returns **401** without a token. If it returns data, do not proceed.

### 5. Frontend

Build `msp-dashboard` with `REACT_APP_API_URL` pointed at the deployed API and publish as a Render Static Site. The dashboard must attach the JWT as `Authorization: Bearer <token>` — verify this is wired before go-live.

---

## Local Development

```bash
python -m venv venv
venv\Scripts\activate                 # Windows
pip install -r requirements.txt

python app/main.py                     # http://127.0.0.1:9000

cd msp-dashboard && npm install && npm start   # http://localhost:3000
```

Run the endpoint suite from the project root:

```bash
venv\Scripts\python verify_api.py
```

It boots the API on a spare port against a throwaway database, exercises every route, and reports pass/fail. Your real `devices.db` is never touched.

---

## Operations Runbook

| Situation | Response |
|---|---|
| Dashboard shows "Could not reach the device API" | Check the service is up and `MSP_CORS_ORIGINS` includes the dashboard's exact origin including scheme. |
| All devices suddenly Offline | Check `MSP_API_KEY` matches on both sides — a rotated key silently stops every agent. |
| `401` on every dashboard action | Token expired (8h). Log in again. |
| Login fails for everyone after a deploy | `MSP_JWT_SECRET` changed; all existing tokens are invalid. Expected on rotation. |
| Devices vanished after a redeploy | Running on SQLite on ephemeral disk. Migrate to Postgres. |

---

## Known Limitations

1. **Hostnames are globally unique, not per-tenant.** Two client practices cannot both have a `FRONT-DESK-PC`. Additionally, `POST /devices` checks uniqueness *without* a tenant filter, so a `409` reveals that a hostname exists under another tenant. Fixing this properly means changing how the agent identifies itself in a heartbeat.
2. **`GET /health` is unauthenticated and reports cross-tenant device counts.** Low sensitivity, but it is a public disclosure of total fleet size.
3. **Failed logins for unknown usernames are not readable over the API.** Written, but tenant-scoped filtering excludes them. Needs an admin role.
4. **Agent heartbeat auth is opt-in and off by default.**
5. **JWT secret has an insecure default.** It warns rather than refusing to start.
6. **No rate limiting** on `/api/login` — brute-force is unthrottled.
