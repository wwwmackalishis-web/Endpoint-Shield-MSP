from datetime import datetime, timedelta
from types import SimpleNamespace

from app.patch_compliance import (
    MAX_SIGNATURE_AGE_HOURS,
    STATUS_CURRENT,
    STATUS_DISABLED,
    STATUS_EOL,
    STATUS_STALE,
    STATUS_UNKNOWN,
    av_status,
    evaluate_device,
    known_vulnerabilities,
    os_status,
)


def make_device(os="Microsoft Windows 11 Pro", av_enabled=True, av_signature_updated_at=None, hostname="PC-1"):
    return SimpleNamespace(hostname=hostname, os=os, av_enabled=av_enabled, av_signature_updated_at=av_signature_updated_at)


# ---- 3a: OS status ----

def test_current_os_is_current():
    result = os_status("Microsoft Windows 11 Pro", today=datetime(2026, 1, 1))
    assert result["status"] == STATUS_CURRENT
    assert result["matched_family"] == "Windows 11"


def test_eol_os_is_flagged():
    result = os_status("Microsoft Windows 7 Professional", today=datetime(2026, 1, 1))
    assert result["status"] == STATUS_EOL
    assert result["eol_date"] == "2020-01-14"


def test_windows_10_is_current_before_its_eol_date():
    result = os_status("Microsoft Windows 10 Pro", today=datetime(2024, 1, 1))
    assert result["status"] == STATUS_CURRENT


def test_windows_10_is_eol_after_its_eol_date():
    result = os_status("Microsoft Windows 10 Pro", today=datetime(2026, 1, 1))
    assert result["status"] == STATUS_EOL


def test_server_2012_r2_not_shadowed_by_2012_entry():
    result = os_status("Microsoft Windows Server 2012 R2 Standard", today=datetime(2026, 1, 1))
    assert result["matched_family"] == "Windows Server 2012 R2"


def test_unrecognized_os_is_unknown():
    result = os_status("FreeBSD 14.0")
    assert result["status"] == STATUS_UNKNOWN


def test_missing_os_is_unknown():
    result = os_status(None)
    assert result["status"] == STATUS_UNKNOWN


# ---- 3b: AV status ----

def test_no_av_data_is_unknown():
    result = av_status(None, None)
    assert result["status"] == STATUS_UNKNOWN


def test_av_disabled_is_flagged():
    result = av_status(False, None)
    assert result["status"] == STATUS_DISABLED


def test_fresh_signature_is_current():
    now = datetime(2026, 1, 2, 12, 0)
    result = av_status(True, now - timedelta(hours=2), now=now)
    assert result["status"] == STATUS_CURRENT
    assert result["signature_age_hours"] == 2.0


def test_stale_signature_is_flagged():
    now = datetime(2026, 1, 2, 12, 0)
    result = av_status(True, now - timedelta(hours=MAX_SIGNATURE_AGE_HOURS + 1), now=now)
    assert result["status"] == STATUS_STALE


def test_enabled_without_signature_timestamp_is_unknown():
    result = av_status(True, None)
    assert result["status"] == STATUS_UNKNOWN


# ---- 3c: known vulnerabilities ----

def test_eol_os_has_named_cves():
    vulns = known_vulnerabilities("Microsoft Windows 7 Professional")
    cve_ids = {v["cve"] for v in vulns}
    assert "CVE-2017-0144" in cve_ids
    assert "CVE-2019-0708" in cve_ids


def test_current_os_has_no_static_vulnerabilities():
    assert known_vulnerabilities("Microsoft Windows 11 Pro") == []


def test_unrecognized_os_has_no_vulnerabilities():
    assert known_vulnerabilities("Some Unknown OS") == []


# ---- full evaluation ----

def test_evaluate_device_flags_eol_os_as_at_risk():
    device = make_device(os="Microsoft Windows 7 Professional")
    result = evaluate_device(device)
    assert result["at_risk"] is True
    assert result["os"]["status"] == STATUS_EOL
    assert len(result["known_vulnerabilities"]) > 0


def test_evaluate_device_current_and_protected_is_not_at_risk():
    now = datetime.utcnow()
    device = make_device(os="Microsoft Windows 11 Pro", av_enabled=True, av_signature_updated_at=now)
    result = evaluate_device(device)
    assert result["at_risk"] is False


def test_evaluate_device_flags_disabled_av_even_on_current_os():
    device = make_device(os="Microsoft Windows 11 Pro", av_enabled=False)
    result = evaluate_device(device)
    assert result["at_risk"] is True
