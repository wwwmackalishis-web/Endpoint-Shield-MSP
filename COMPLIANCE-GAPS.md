# Pre-BAA Compliance Gap List

**Internal. Do not distribute to clients or prospects.**

Derived from a read of `app/auth.py`, `app/main.py`, `app/models.py`, `app/database.py`, `app/monitor.py`, `app/notify.py`, `app/ratelimit.py`, `requirements.txt`, `agent.ps1`, `test_upload.py`, and the archived `archive/track-b-defender/` and `archive/legacy-backend/` subsystems. Last updated 9 September 2026.

The technical access-control layer and the audit trail are real. What is still missing is the encryption, alerting, and administrative-safeguard layer that a signed BAA depends on. Each item below maps to a representation in the BAA template that cannot be supported until it is done.

Item 1 (audit logging) was closed on 7 September 2026; item 4 (monitoring/alerting) on 8 September 2026; and the JWT-secret hard-fail half of item 2, all of item 8, item 9, and the new item 12 on 9 September 2026, as part of a full security-and-HIPAA review of the codebase. All are kept here with their resolution rather than deleted, so the record shows what was found and what was done about it.

---

## Blocking — must be true before any BAA is signed

### 1. Audit logging (45 CFR § 164.312(b)) — ✅ DONE

**Status:** Implemented in `app/audit.py`, `app/models.py` (`AuditEvent`), and `GET /api/v1/audit-log`. Logins (success and failure) and every device create/update/delete are recorded with actor, tenant, target, source IP, and timestamp. Device mutations write their audit row in the same transaction as the change. Credentials and device field *values* are never recorded — only changed field names, because `notes` and `location` are free text that could contain PHI.

**Remaining:** failed logins for an unrecognised username have no tenant and are therefore written but not returned by the tenant-scoped read API — needs an administrator role. Retention is policy, not code: §164.316(b)(2)(i) requires six years and there is deliberately no purge routine.

Original finding, for the record: nothing recorded who logged in, who created, edited, or deleted a device, or when.

Note the naming hazard that remains: `GET /api/v1/health-audit` is a device-availability summary, not an access audit trail. Consider renaming it `/api/v1/fleet-status` so the two are never confused in front of an auditor.

### 2. Production secrets discipline — ⚠️ PARTIALLY DONE (JWT secret closed 9 September 2026)

**Status:**

- `MSP_JWT_SECRET` — ✅ closed. `app/auth.py` now refuses to import (raises, process won't start) if `MSP_JWT_SECRET` is unset **and** `MSP_DATABASE_URL` is set — the same signal `app/database.py` already uses to tell local SQLite dev apart from a real (e.g. Render/Postgres) deployment. Local dev with no `MSP_DATABASE_URL` still gets the old warning-only behavior, unchanged. Verified in `test_security.py`: importing `app.auth` with `MSP_DATABASE_URL` set and no `MSP_JWT_SECRET` now exits non-zero instead of silently issuing forgeable tokens.
- `MSP_API_KEY` enforcement is still **opt-in** by design (unchanged). Unset, `/agents/heartbeat` accepts anonymous posts — and an unrecognised `tenant` value in a heartbeat payload *creates a new tenant row*, so an unauthenticated caller can write to the tenant table. This was left alone rather than silently hard-failed: flipping it to required breaks every already-deployed `agent.ps1` that doesn't have a matching key configured, which is a coordinated-rollout decision, not a safe unattended code change.
- `MSP_CORS_ORIGINS` still defaults to `*`. Same reasoning — narrowing it is a real production domain you have to supply, not something code can infer.

**What's still needed:** the same "refuse to start in a production-like config" treatment for `MSP_API_KEY` and `MSP_CORS_ORIGINS`, once you're ready to require them — that's a deployment-config decision (which domain, which key), not a code gap anymore.

### 3. Encryption at rest (§ 164.312(a)(2)(iv))

**Status:** Not implemented.

Addressable rather than required — but if the BAA asserts it, it must exist. Either implement it (Render Postgres encryption at rest, plus documented key management) or strike § 4.3 of the BAA and record the documented rationale § 164.306(d)(3) requires. Do not leave the language in and hope.

### 4. Monitoring coverage claims — ✅ CODE DONE, needs SMTP configured to go live

**Status:** Implemented in `app/monitor.py` (background poll loop, started from `app/main.py`'s startup event), `app/notify.py` (email delivery), and `DeviceAlertState` in `app/models.py` (per-device alert state, separate from the append-only audit trail). Every 60 seconds by default, any device silent past the same 10-minute "offline" threshold the dashboard already uses fires an email to Endpoint Shield Solutions' own on-call inbox, escalates hourly while the outage continues, and sends a resolved notice when the device reports back in. Every trigger/escalation/resolution is also written to `audit_events` (`alert.triggered` / `alert.escalated` / `alert.resolved`), so there's a permanent record independent of whether any email actually arrived. `GET /api/v1/alerts` surfaces currently-open alerts to the dashboard, tenant-scoped like everything else a technician sees.

Tested against the real dependency set (not just syntax-checked): a device that goes silent triggers exactly one notification and one audit row, does not re-notify inside the escalation window, resolves and records outage duration when it reports back in, and a device that has *never* reported in (no `last_seen` at all) also alerts rather than being silently ignored — that last case surfaced a real bug (`_humanize()` crashing on an infinite silence duration), which was fixed and reverified before this was marked done.

**Remaining:** the code is live but toothless until `MSP_SMTP_HOST` / `MSP_SMTP_USER` / `MSP_SMTP_PASSWORD` / `MSP_ALERT_EMAIL_TO` are set — without them it logs what it would have sent instead of sending it (visible in stderr as `ALERT EMAIL SKIPPED`), so the app never crashes for lack of mail config but also never actually pages anyone. This is a natural pairing with the Google Workspace business email being set up separately: once that mailbox exists, point `MSP_SMTP_HOST` at it (`smtp.gmail.com`, an app password) and the alert becomes real. Also still open: this notifies Endpoint Shield Solutions' own inbox only, not the client — client-facing notification is a separate decision that touches the MSA/SMA's communication terms and wants per-tenant contacts, and email is the floor here, not a full on-call/pager rotation.

### 5. Administrative safeguards (§ 164.308)

**Status:** None documented. No code supplies these.

- Written security risk analysis, reviewed annually
- Workforce HIPAA and security-awareness training, documented
- Written sanction policy
- Incident response plan and breach notification runbook (§ 164.410 gives you a hard clock)
- Contingency plan: backup, disaster recovery, emergency mode operation

The most common OCR finding against small entities is the absence of a current risk analysis. Yours does not exist yet.

### 6. Subcontractor BAAs (§ 164.308(b)(2))

**Status:** Not executed.

Render is a subcontractor handling systems in scope. You need a signed BAA with them — confirm they will sign one on your plan tier before you promise anything to a client — plus any other infrastructure provider in the path.

---

## Important — should be closed before a medical client at scale

### 7. Cross-tenant hostname collision and information leak

`POST /devices` (app/main.py, ~line 327) checks hostname uniqueness **without** a tenant filter. Two consequences:

- Two client practices cannot both have a `FRONT-DESK-PC`. This will happen almost immediately.
- The resulting `409` tells tenant A that a hostname exists under tenant B — a cross-tenant information leak, in a codebase that is otherwise careful about exactly this (`GET /devices/{hostname}` correctly returns 404 rather than 403 for the same reason).

Fixing it properly means making hostname unique per tenant and changing how `agent.ps1` identifies itself in a heartbeat. `app/models.py` already documents this as a known limitation — good — but multi-tenancy is now a compliance boundary, not a convenience.

### 8. `GET /health` is unauthenticated and cross-tenant — ✅ DONE (9 September 2026)

**Was:** returned total device count across all tenants, a fleet-status breakdown, plus `auth_enforced` and `cors_origins` — to anyone, no login required. Individually low-sensitivity, but together it handed an unauthenticated caller a map of exactly which protections were off (`"auth_enforced": false`) before they'd tried a single real request, plus fleet size.

**Now:** `/health` returns only `{"status": "ok"}` — a bare liveness probe (process up, database answers), matching what an uptime monitor or Render health check actually needs. The fleet detail and auth/CORS posture it used to leak are already available at `GET /api/v1/health-audit`, which requires a technician's JWT and is scoped to their own tenant — nothing was lost, it just now needs a login. Verified in `test_security.py`.

### 9. No rate limiting on `/api/login` — ✅ DONE (9 September 2026)

**Was:** brute force was unthrottled — any number of password guesses per second, limited only by bcrypt's own cost factor.

**Now:** `app/ratelimit.py` adds an in-memory limiter keyed by (source IP, username): 5 failed attempts locks that pair out for 5 minutes, returning `429` — checked *before* the password hasher runs, so a lockout doesn't even cost a bcrypt verify. A successful login clears the counter, so a technician who mistyped their password twice isn't left one attempt away from a lockout next time. Failed attempts still write to the audit table exactly as before (item 1). Verified in `test_security.py`, including that a *correct* password is still blocked once the limiter has tripped.

**Known limitation, accepted for now:** in-memory and single-process — resets on restart, not shared across multiple worker processes. Fine for the current single-process deployment; a multi-worker/multi-instance production deployment should move this to a shared store (Redis, or a DB-backed table) instead.

### 10. No idle session timeout, no MFA

An 8-hour token on an unattended workstation in an operatory is a real exposure. MFA is not strictly required by the Security Rule but is expected by practice-side security questionnaires and by cyber-liability underwriters, and you will be asked.

### 11. `server.crt` / `server.key` in the repository

There are TLS key files at the project root. If that repo is or ever becomes remote-hosted, those are burned. Rotate them, remove them from history, and add them to `.gitignore`.

### 12. Unbounded request bodies and field lengths on `/agents/heartbeat` — ✅ DONE (9 September 2026)

**Was:** `/agents/heartbeat` is unauthenticated whenever `MSP_API_KEY` is unset (item 2), and had no size limit anywhere in the request path — a sender could post an arbitrarily large JSON body (read fully into memory before any validation ran) and store an arbitrarily long string in any device field (`ip`, `cpu`, `ram`, `disk`, `os`, `hostname`, `tenant`), unlike `POST /devices`, whose Pydantic schema already caps fields at 255 characters.

**Now:** a global body-size limit (1 MB, `MSP_MAX_BODY_BYTES`) rejects an oversized request with `413` before it's read into memory, and every heartbeat field is truncated to 255 characters to match the authenticated route's own limit. Verified in `test_security.py`: a >1 MB body never reaches the database, and an oversized field is stored truncated rather than in full.

### 13. Archived file-scan subsystem (`archive/track-b-defender/`) and leftover scan artifacts — reviewed, not live, cleanup recommended

`test_upload.py` at the project root posts to `http://127.0.0.1:8000/scan/file` with no auth header, which read at first like a live, unauthenticated upload endpoint separate from the main app (port 9000). On inspection: it is not live. The router in `archive/track-b-defender/app/api/scan.py` is never mounted anywhere (no `app.include_router(...)` call exists in `app/main.py` or anywhere else in the live tree), and there is no `main.py`/launcher inside `archive/track-b-defender/` that would start a service on port 8000 — so nothing serves that route today. The archive's own `README.md` independently confirms it was archived, not deleted, because `app/core/policy_engine.py` matches only one demo hash and `app/ai/analyzer.py` is a hardcoded stub — it was never a working detector.

Two follow-ups, neither urgent:

- **Cleanup.** `uploads/` at the project root still holds a live 12.6 MB `.exe` and several GUID-named dummy files, and `scan_history.json` / `scan_logs.json` at the project root are leftover output from when this pipeline was last run manually. None of this is reachable by any live route, but it's dead weight sitting in the repo — worth deleting as basic data-minimization housekeeping, not because it's exposed.
- **If Track B is ever revived,** `archive/track-b-defender/app/defender/quarantine.py` builds a PowerShell `Start-MpScan` command by interpolating the file path directly into a `-Command` string with no escaping — a command-injection pattern if an attacker ever controlled the filename. Fix this as part of reviving the feature (replace the demo hash list and stub classifier per the archive's own README), not before — there is no live path to it today.

### 14. Dependency / known-CVE review (9 September 2026)

Checked the pinned versions in `requirements.txt` against public CVE databases:

- **`python-jose==3.3.0`** — the version pinned is the one named in CVE-2024-33663 (algorithm-confusion with OpenSSH ECDSA/other key formats). Not exploitable here: `app/auth.py` only ever encodes and decodes with `algorithms=["HS256"]` (symmetric), never accepts a token claiming `RS256`/`ES256`, and never uses an asymmetric public key as a verification key — the precondition for that CVE. No code change made. Worth noting anyway: python-jose is not under active maintenance; a future migration to `PyJWT` would remove the dependency rather than just work around it, at some point when there's room for it — not urgent.
- **`python-multipart`** — pinned with no version in `requirements.txt` (unlike every other dependency), and is the package affected by CVE-2024-24762 and CVE-2024-53981 (both denial-of-service). The version actually installed in the project's venv is 0.0.22, well past both fixes — so this deployment is not exposed today. The gap is reproducibility: an unpinned line means a different machine or a future clean install could resolve an older, vulnerable version. Recommend pinning it explicitly (e.g. `python-multipart>=0.0.18`) the next time `requirements.txt` is touched.
- Everything else pinned (`fastapi`, `uvicorn`, `pydantic`, `sqlalchemy`, `httpx`, `requests`, `psycopg2-binary`, `passlib`, `bcrypt`, `starlette` as fastapi's dependency) is recent enough that the CVEs found in research all predate the pinned version by a wide margin. No action needed beyond normal periodic re-checking.

---

## Business-side, before quoting at scale

- **Cyber liability and technology E&O coverage.** Bind it before the first BAA. Underwriters will ask about MFA, backups, and endpoint monitoring — items 1, 2, and 10 affect what you can answer and what you pay.
- **Healthcare counsel.** The BAA template is a drafting starting point, not a signable document. Indemnification and liability allocation in particular should not come from a template.
- **Business Associate liability is direct.** Under HITECH, OCR can act against you, not only against the practice. The gap between what a BAA says and what actually runs is precisely where that liability sits.

---

## Suggested order

1. ~~Audit logging (item 1)~~ — done
2. ~~Alerting and escalation (item 4)~~ — code done; set SMTP env vars against the new Workspace mailbox to make it live
3. ~~JWT-secret hard-fail, `/health` info disclosure, `/api/login` rate limiting, heartbeat body/field size caps (items 2's JWT half, 8, 9, 12)~~ — done and tested against the real dependency set
4. Idle session timeout + MFA (item 10) — remaining half of what "no rate limiting" used to cover; a technician-workflow/UX decision as much as a technical one
5. Risk analysis and the written policy set (item 5) — slow, start early, non-technical
6. Encryption-at-rest decision, documented either way (item 3)
7. Per-tenant hostname uniqueness (item 7)
8. Cleanup: delete the dead `uploads/`, `scan_history.json`, `scan_logs.json` artifacts from the archived scan pipeline (item 13) — low effort, no urgency
