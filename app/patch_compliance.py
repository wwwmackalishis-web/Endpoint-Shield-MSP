"""Patch & Vulnerability Compliance Agent (fleet position 3).

3a. os_status()            - is this OS version still receiving security
                             patches at all, from Microsoft/Apple/the
                             distro's own published end-of-life dates.
3b. av_status()            - is Windows Defender actually on and current,
                             from the fields agent.ps1's Get-MpComputerStatus
                             call adds to the heartbeat (see app/models.py's
                             Device.av_enabled / av_signature_updated_at).
3c. known_vulnerabilities()- names specific, real CVEs that are permanently
                             unpatched on an EOL OS, because no more patches
                             are coming for that OS ever - not a live feed.

None of this calls out to NVD, MSRC, or any other external feed - see the
module-level EOL_TABLE and KNOWN_EOL_VULNERABILITIES for the honesty
tradeoff that implies: these are dates and CVE numbers that were correct
when written and need a human to refresh periodically (an OS's EOL date
does not move, but new ones get added to the industry every year). A
currently-supported OS reports no known vulnerabilities here - this module
has no way to know whether THIS PARTICULAR device is missing a specific
patch, only whether its OS family can still receive one at all. Treat an
empty vulnerabilities list as "nothing this static table catches", never as
"this device has no vulnerabilities."
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

STATUS_CURRENT = "current"
STATUS_EOL = "end_of_life"
STATUS_UNKNOWN = "unknown"

STATUS_STALE = "stale"
STATUS_DISABLED = "disabled"

# End-of-life dates as published by the vendor. Matched by substring against
# Device.os (agent.ps1 sends Win32_OperatingSystem.Caption, e.g. "Microsoft
# Windows 11 Pro" / "Microsoft Windows Server 2019 Standard"). Order matters:
# checked longest/most-specific substring first so "Windows Server 2012 R2"
# doesn't get matched by a bare "Windows Server 2012" entry.
OS_EOL_TABLE = [
    ("Windows Server 2008 R2", "2020-01-14"),
    ("Windows Server 2008", "2020-01-14"),
    ("Windows Server 2012 R2", "2023-10-10"),
    ("Windows Server 2012", "2023-10-10"),
    ("Windows Server 2016", "2027-01-12"),
    ("Windows Server 2019", "2029-01-09"),
    ("Windows Server 2022", "2031-10-14"),
    ("Windows 7", "2020-01-14"),
    ("Windows 8.1", "2023-01-10"),
    ("Windows 8", "2016-01-12"),
    ("Windows 10", "2025-10-14"),
    ("Windows 11", "2031-10-14"),  # earliest edition's EOL; fine as a floor
]

# Specific CVEs permanently unpatched on an EOL OS family - real, named,
# widely documented vulnerabilities, not a guess about any one device.
KNOWN_EOL_VULNERABILITIES = {
    "Windows 7": [
        {"cve": "CVE-2017-0144", "name": "EternalBlue / SMBv1 RCE", "note": "No patch will ever ship for this OS."},
        {"cve": "CVE-2019-0708", "name": "BlueKeep / RDP RCE", "note": "No patch will ever ship for this OS."},
    ],
    "Windows Server 2008": [
        {"cve": "CVE-2017-0144", "name": "EternalBlue / SMBv1 RCE", "note": "No patch will ever ship for this OS."},
        {"cve": "CVE-2019-0708", "name": "BlueKeep / RDP RCE", "note": "No patch will ever ship for this OS."},
    ],
    "Windows Server 2008 R2": [
        {"cve": "CVE-2017-0144", "name": "EternalBlue / SMBv1 RCE", "note": "No patch will ever ship for this OS."},
        {"cve": "CVE-2019-0708", "name": "BlueKeep / RDP RCE", "note": "No patch will ever ship for this OS."},
    ],
}

# How stale a Defender signature can be before it's flagged. Definitions
# ship roughly daily; two days of slack absorbs a device that was simply
# off overnight without flagging every workstation that skipped one cycle.
MAX_SIGNATURE_AGE_HOURS = 48


def _match_eol(os_name: str) -> Optional[tuple]:
    if not os_name:
        return None
    for needle, eol_date in OS_EOL_TABLE:
        if needle.lower() in os_name.lower():
            return needle, eol_date
    return None


def os_status(os_name: Optional[str], today: Optional[datetime] = None) -> dict:
    """3a: is this OS family still inside its vendor support window."""
    today = today or datetime.utcnow()
    match = _match_eol(os_name or "")
    if not match:
        return {
            "status": STATUS_UNKNOWN,
            "matched_family": None,
            "eol_date": None,
            "note": f"'{os_name}' does not match any entry in the end-of-life reference table - "
                    "update OS_EOL_TABLE, or confirm this OS is actually current.",
        }
    family, eol_date_str = match
    eol_date = datetime.strptime(eol_date_str, "%Y-%m-%d")
    if today >= eol_date:
        return {
            "status": STATUS_EOL,
            "matched_family": family,
            "eol_date": eol_date_str,
            "note": f"{family} reached end of life on {eol_date_str} - it no longer receives "
                    "security patches from the vendor, regardless of update settings.",
        }
    return {"status": STATUS_CURRENT, "matched_family": family, "eol_date": eol_date_str, "note": None}


def av_status(av_enabled: Optional[bool], av_signature_updated_at: Optional[datetime],
              now: Optional[datetime] = None) -> dict:
    """3b: is real-time protection on and its signatures fresh."""
    now = now or datetime.utcnow()
    if av_enabled is None and av_signature_updated_at is None:
        return {"status": STATUS_UNKNOWN, "signature_age_hours": None,
                "note": "No AV data reported yet - this device's agent may predate AV reporting."}
    if av_enabled is False:
        return {"status": STATUS_DISABLED, "signature_age_hours": None,
                "note": "Real-time protection is off or antivirus is disabled."}
    if av_signature_updated_at is None:
        return {"status": STATUS_UNKNOWN, "signature_age_hours": None,
                "note": "Antivirus reports enabled but signature update time was not reported."}
    age_hours = (now - av_signature_updated_at).total_seconds() / 3600
    if age_hours > MAX_SIGNATURE_AGE_HOURS:
        return {"status": STATUS_STALE, "signature_age_hours": round(age_hours, 1),
                "note": f"Signatures are {round(age_hours)} hours old - over the "
                        f"{MAX_SIGNATURE_AGE_HOURS}-hour freshness threshold."}
    return {"status": STATUS_CURRENT, "signature_age_hours": round(age_hours, 1), "note": None}


def known_vulnerabilities(os_name: Optional[str]) -> list:
    """3c: named CVEs that are permanently unpatched for an EOL OS family."""
    match = _match_eol(os_name or "")
    if not match:
        return []
    family, _ = match
    return list(KNOWN_EOL_VULNERABILITIES.get(family, []))


def evaluate_device(device) -> dict:
    """The full 3a/3b/3c picture for one device. `device` needs hostname,
    os, av_enabled, av_signature_updated_at - a Device row or any object
    with those attributes (see tests/test_patch_compliance.py)."""
    os_result = os_status(getattr(device, "os", None))
    av_result = av_status(getattr(device, "av_enabled", None), getattr(device, "av_signature_updated_at", None))
    vulnerabilities = known_vulnerabilities(getattr(device, "os", None))
    at_risk = os_result["status"] == STATUS_EOL or av_result["status"] in (STATUS_STALE, STATUS_DISABLED)
    return {
        "hostname": getattr(device, "hostname", None),
        "os": os_result,
        "antivirus": av_result,
        "known_vulnerabilities": vulnerabilities,
        "at_risk": at_risk,
    }
