"""Client Reporting Agent (fleet position 5).

5a. translate_patch_summary() / translate_alerts() / translate_maintenance_reminders()
    - turn technical findings (app/patch_compliance.py's per-device
    evaluation, app/backup_compliance.py's job status, an open alert from
    app/monitor.py's DeviceAlertState) into plain-English sentences. A
    client report names consequences ("no longer receives security
    updates"), never mechanisms (an OS Caption string, a CVE number, a CFR
    citation) - those stay in the technician-facing views this module
    never touches directly.
5b. sla_scorecard() - pairs alert.triggered/alert.resolved audit rows per
    device (app/audit.py already writes both) and scores how many were
    resolved inside Tenant.sla_response_minutes.
5c. build_report() / build_html_report() assemble all of the above into one
    email (plain-text and a branded HTML version respectively);
    app/main.py's POST /api/v1/reports/send hands both to
    app.notify.send_client_email(), the actual delivery mechanism. The HTML
    version exists because this report is the tangible, recurring proof of
    value a client actually sees for what they're paying - the plain-text
    body stays as the required MIME fallback for mail clients that don't
    render HTML.

Nothing here invents a number a human didn't configure. A tenant with no
sla_response_minutes set gets an explicit "not configured" note, never a
score against a target nobody agreed to.
"""

import html as html_escape
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from app import audit

# The one brand asset every client-facing document should carry - see
# app/models.py's Tenant docstring neighbors for the same "real data, not
# guessed" standard applied to a logo instead of a number. Resolved once at
# import time; a missing file degrades to a logo-less report rather than a
# crashed one, since a report that's late because an image moved is a worse
# outcome than one without a picture in the corner.
LOGO_PATH = Path(__file__).resolve().parent.parent / "msp-dashboard" / "src" / "endpoint-shield-solutions-logo.png"
LOGO_CID = "endpoint-shield-logo"

# Brand colors sampled from the shield logo itself (deep navy + violet),
# not a palette invented for this one document - every client-facing piece
# should read as the same company.
BRAND_NAVY = "#12213D"
BRAND_VIOLET = "#6C3CE0"
BRAND_PAPER = "#F4F5F8"
BRAND_RULE = "#E1E4EA"

# How far ahead of an OS's actual end-of-life date this agent starts
# mentioning it as a reminder, not yet an alert. translate_patch_summary()
# already covers a device that IS end-of-life; this covers "will be soon,"
# which is the more useful lead time for a client to actually budget for a
# replacement.
EOL_WARNING_DAYS = 90


def _human_duration(seconds: float) -> str:
    seconds = max(0, seconds)
    minutes = seconds / 60
    if minutes < 60:
        return f"{round(minutes)} minute(s)"
    hours = minutes / 60
    if hours < 24:
        return f"{round(hours, 1)} hour(s)"
    return f"{round(hours / 24, 1)} day(s)"


def translate_patch_summary(device_evaluations: Iterable[dict]) -> list:
    """`device_evaluations` is a list of app/patch_compliance.py's
    evaluate_device() output, one per device in the tenant's fleet."""
    device_evaluations = list(device_evaluations)
    eol_count = sum(1 for d in device_evaluations if d["os"]["status"] == "end_of_life")
    av_issue_count = sum(1 for d in device_evaluations if d["antivirus"]["status"] in ("stale", "disabled"))

    lines = []
    if eol_count:
        plural = "s" if eol_count != 1 else ""
        lines.append(
            f"{eol_count} device{plural} on your network are running an operating system the "
            "manufacturer no longer issues security updates for. We recommend planning a "
            "replacement or upgrade for these soon."
        )
    if av_issue_count:
        plural = "s" if av_issue_count != 1 else ""
        lines.append(
            f"{av_issue_count} device{plural} have antivirus protection that is either turned off "
            "or has not updated recently. We're following up on these directly."
        )
    if not lines and device_evaluations:
        lines.append(
            "All monitored devices are running supported software with active, up-to-date "
            "antivirus protection."
        )
    return lines


def translate_alerts(open_alerts: Iterable[dict]) -> list:
    """`open_alerts` matches GET /api/v1/alerts' shape: hostname, silent_seconds."""
    open_alerts = list(open_alerts)
    if not open_alerts:
        return ["No devices are currently reporting an outage."]
    return [
        f"{a['hostname']} has not checked in for {_human_duration(a['silent_seconds'] or 0)}. "
        "We are already on this."
        for a in open_alerts
    ]


def translate_maintenance_reminders(*, device_evaluations: Iterable[dict], backup_jobs: Iterable[dict],
                                     restore_test_jobs: Iterable[dict], now: Optional[datetime] = None) -> list:
    """5a, continued: proactive "handle this before it's a problem" items -
    distinct from translate_patch_summary()'s already-a-problem findings.
    `backup_jobs` / `restore_test_jobs` match GET /api/v1/backups/status and
    .../restore-tests' shapes: job_name, status, note (app/backup_compliance.py).
    """
    now = now or datetime.utcnow()
    reminders = []

    upcoming_eol: dict = {}
    for device in device_evaluations:
        os_info = device["os"]
        eol_date = os_info.get("eol_date")
        if os_info["status"] == "current" and eol_date:
            days_left = (datetime.strptime(eol_date, "%Y-%m-%d") - now).days
            if 0 <= days_left <= EOL_WARNING_DAYS:
                upcoming_eol.setdefault(os_info["matched_family"], []).append(device["hostname"])
    for family, hostnames in sorted(upcoming_eol.items()):
        shown = ", ".join(hostnames[:5]) + ("..." if len(hostnames) > 5 else "")
        plural = "s" if len(hostnames) != 1 else ""
        reminders.append(
            f"{len(hostnames)} device{plural} running {family} ({shown}) will lose manufacturer "
            f"security support within {EOL_WARNING_DAYS} days - worth budgeting a replacement now."
        )

    for job in backup_jobs:
        if job.get("status") != "ok":
            reminders.append(f"Backup job '{job['job_name']}': {job.get('note') or job['status']}")

    for job in restore_test_jobs:
        if job.get("status") != "ok":
            reminders.append(f"Restore test '{job['job_name']}': {job.get('note') or job['status']}")

    if not reminders:
        reminders.append("No maintenance items need attention this period.")
    return reminders


def sla_scorecard(events: Iterable, sla_response_minutes: Optional[int], now: Optional[datetime] = None) -> dict:
    """Pairs each device's alert.triggered with its next alert.resolved (both
    written by app/monitor.py via app/audit.py) to measure real response
    time, then compares against the contracted target.
    """
    now = now or datetime.utcnow()
    pending: dict = {}
    completed = []  # list of (hostname, minutes)

    for event in sorted(events, key=lambda e: e.timestamp):
        if event.action == audit.ALERT_TRIGGERED:
            pending[event.target_id] = event.timestamp
        elif event.action == audit.ALERT_RESOLVED:
            started_at = pending.pop(event.target_id, None)
            if started_at is not None:
                completed.append((event.target_id, (event.timestamp - started_at).total_seconds() / 60))

    still_open = [
        {"hostname": hostname, "elapsed_minutes": round((now - started_at).total_seconds() / 60, 1)}
        for hostname, started_at in pending.items()
    ]

    result = {
        "resolved_incidents": len(completed),
        "still_open": still_open,
        "sla_response_minutes": sla_response_minutes,
    }
    if sla_response_minutes is None:
        result["note"] = "No SLA response-time target is configured for this client."
        return result

    met = sum(1 for _, minutes in completed if minutes <= sla_response_minutes)
    result["met_sla"] = met
    result["missed_sla"] = len(completed) - met
    result["percent_met"] = round(met / len(completed) * 100, 1) if completed else None
    return result


def _response_time_lines(scorecard: dict) -> list:
    if scorecard.get("sla_response_minutes") is None:
        return [scorecard.get("note", "No SLA response-time target is configured for this client.")]
    lines = []
    target = scorecard["sla_response_minutes"]
    if scorecard["resolved_incidents"] == 0:
        lines.append(f"No incidents to report against the {target}-minute response target this period.")
    else:
        lines.append(
            f"{scorecard['met_sla']} of {scorecard['resolved_incidents']} incidents "
            f"({scorecard['percent_met']}%) were resolved within the {target}-minute response target."
        )
    if scorecard["still_open"]:
        lines.append(f"{len(scorecard['still_open'])} incident(s) are still open as of this report.")
    return lines


def build_report(*, tenant_name: str, device_evaluations: Iterable[dict], open_alerts: Iterable[dict],
                  backup_jobs: Iterable[dict], restore_test_jobs: Iterable[dict],
                  scorecard: dict, period_note: str) -> dict:
    """Assembles the plain-text email body app/main.py's report routes send.
    Returns {"subject": str, "body": str} - nothing here sends anything."""
    device_evaluations = list(device_evaluations)
    backup_jobs = list(backup_jobs)
    restore_test_jobs = list(restore_test_jobs)

    lines = [
        f"Endpoint Shield Solutions - Service Report for {tenant_name}",
        period_note,
        "",
        "FLEET & SECURITY STATUS",
        "-----------------------",
    ]
    lines.extend(translate_patch_summary(device_evaluations))
    lines.append("")
    lines.append("MAINTENANCE & REMINDERS")
    lines.append("------------------------")
    lines.extend(translate_maintenance_reminders(
        device_evaluations=device_evaluations, backup_jobs=backup_jobs, restore_test_jobs=restore_test_jobs,
    ))
    lines.append("")
    lines.append("CURRENT ALERTS")
    lines.append("--------------")
    lines.extend(translate_alerts(open_alerts))
    lines.append("")
    lines.append("RESPONSE-TIME PERFORMANCE")
    lines.append("-------------------------")
    lines.extend(_response_time_lines(scorecard))

    return {
        "subject": f"Endpoint Shield Solutions - Service Report for {tenant_name}",
        "body": "\n".join(lines),
    }


def load_logo_bytes() -> Optional[bytes]:
    try:
        return LOGO_PATH.read_bytes()
    except OSError:
        return None


def _html_section(title: str, items: list) -> str:
    rows = "".join(
        f'<li style="margin:0 0 8px;line-height:1.5;">{html_escape.escape(item)}</li>' for item in items
    )
    return f"""
    <tr><td style="padding:24px 28px 8px;">
      <h2 style="margin:0 0 12px;font:600 15px/1.3 Arial,Helvetica,sans-serif;color:{BRAND_NAVY};
                 text-transform:uppercase;letter-spacing:0.04em;border-bottom:2px solid {BRAND_RULE};
                 padding-bottom:8px;">{html_escape.escape(title)}</h2>
      <ul style="margin:0;padding-left:20px;font:14px/1.5 Arial,Helvetica,sans-serif;color:#2A2E35;">
        {rows}
      </ul>
    </td></tr>
    """


def build_html_report(*, tenant_name: str, device_evaluations: Iterable[dict], open_alerts: Iterable[dict],
                       backup_jobs: Iterable[dict], restore_test_jobs: Iterable[dict],
                       scorecard: dict, period_note: str) -> str:
    """The branded version of build_report() - a self-contained HTML email
    body, logo included via a cid: reference (app/notify.py attaches the
    actual image bytes as a related MIME part; see load_logo_bytes()).
    Inline styles and table-based layout throughout - deliberately not the
    CSS an Artifact page would use, because this renders inside mail
    clients (Outlook chief among them), most of which ignore <style> blocks
    and modern layout CSS entirely.
    """
    device_evaluations = list(device_evaluations)
    backup_jobs = list(backup_jobs)
    restore_test_jobs = list(restore_test_jobs)
    tenant_name_safe = html_escape.escape(tenant_name)
    period_note_safe = html_escape.escape(period_note)

    sections = "".join([
        _html_section("Fleet & Security Status", translate_patch_summary(device_evaluations)),
        _html_section("Maintenance & Reminders", translate_maintenance_reminders(
            device_evaluations=device_evaluations, backup_jobs=backup_jobs, restore_test_jobs=restore_test_jobs,
        )),
        _html_section("Current Alerts", translate_alerts(open_alerts)),
        _html_section("Response-Time Performance", _response_time_lines(scorecard)),
    ])

    return f"""<!doctype html>
<html>
<body style="margin:0;padding:24px;background:{BRAND_PAPER};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border:1px solid {BRAND_RULE};border-radius:6px;overflow:hidden;">
        <tr>
          <td style="background:{BRAND_NAVY};padding:20px 28px;">
            <table role="presentation" cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:14px;"><img src="cid:{LOGO_CID}" width="44" height="44"
                  alt="Endpoint Shield Solutions" style="display:block;"></td>
              <td>
                <div style="font:700 17px/1.2 Arial,Helvetica,sans-serif;color:#ffffff;">Endpoint Shield Solutions</div>
                <div style="font:400 13px/1.4 Arial,Helvetica,sans-serif;color:{BRAND_VIOLET};margin-top:2px;">
                  Service Report - {tenant_name_safe}</div>
              </td>
            </tr></table>
          </td>
        </tr>
        <tr><td style="padding:16px 28px 0;">
          <p style="margin:0;font:italic 13px/1.4 Arial,Helvetica,sans-serif;color:#6B7280;">{period_note_safe}</p>
        </td></tr>
        {sections}
        <tr><td style="padding:20px 28px 26px;border-top:1px solid {BRAND_RULE};">
          <p style="margin:0;font:12px/1.5 Arial,Helvetica,sans-serif;color:#9AA1AC;">
            Endpoint Shield Solutions - Secure - Advanced - Connected</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
