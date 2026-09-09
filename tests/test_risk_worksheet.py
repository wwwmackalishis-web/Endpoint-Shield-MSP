from types import SimpleNamespace

from app.risk_worksheet import COMMON_THREATS, build_worksheet


def make_device(os="Windows 11", hostname="PC-1"):
    return SimpleNamespace(os=os, hostname=hostname)


def test_scope_counts_assets_by_os():
    devices = [make_device(os="Windows 11"), make_device(os="Windows 11"), make_device(os="macOS")]
    worksheet = build_worksheet(tenant_name="Riverside Dental", devices=devices)
    scope = worksheet["sections"]["1_scope"]
    assert scope["asset_count"] == 3
    assert scope["assets_by_os"] == {"Windows 11": 2, "macOS": 1}


def test_missing_os_falls_back_to_unreported():
    devices = [make_device(os=None), make_device(os="")]
    worksheet = build_worksheet(tenant_name="Riverside Dental", devices=devices)
    assert worksheet["sections"]["1_scope"]["assets_by_os"] == {"Unreported": 2}


def test_no_audit_events_flags_it_explicitly():
    worksheet = build_worksheet(tenant_name="Riverside Dental", devices=[], audit_result={
        "total_events": 0, "distinct_actors": [], "earliest": None,
    })
    measures = worksheet["sections"]["4_current_security_measures"]["measures"]
    audit_measure = next(m for m in measures if m["safeguard"] == "Audit controls")
    assert "No audit events recorded" in audit_measure["evidence"]


def test_audit_events_produce_evidence_with_counts():
    worksheet = build_worksheet(
        tenant_name="Riverside Dental",
        devices=[],
        audit_result={
            "total_events": 42,
            "distinct_actors": ["jsmith", "admin"],
            "earliest": "2026-01-01T00:00:00",
        },
    )
    measures = worksheet["sections"]["4_current_security_measures"]["measures"]
    audit_measure = next(m for m in measures if m["safeguard"] == "Audit controls")
    assert "42 recorded events" in audit_measure["evidence"]
    assert "2 distinct user account" in audit_measure["evidence"]


def test_monitoring_flag_changes_evidence_text():
    on = build_worksheet(tenant_name="X", devices=[], monitoring_enabled=True)
    off = build_worksheet(tenant_name="X", devices=[], monitoring_enabled=False)
    on_evidence = next(
        m for m in on["sections"]["4_current_security_measures"]["measures"]
        if m["safeguard"] == "Endpoint monitoring / alerting"
    )["evidence"]
    off_evidence = next(
        m for m in off["sections"]["4_current_security_measures"]["measures"]
        if m["safeguard"] == "Endpoint monitoring / alerting"
    )["evidence"]
    assert "enabled" in on_evidence
    assert "NOT currently enabled" in off_evidence


def test_risk_scoring_rows_start_blank_not_guessed():
    worksheet = build_worksheet(tenant_name="X", devices=[])
    rows = worksheet["sections"]["5_6_7_risk_scoring"]["rows"]
    assert len(rows) == len(COMMON_THREATS)
    for row in rows:
        assert row["likelihood"] is None
        assert row["impact"] is None
        assert row["risk_level"] is None


def test_disclaimer_present_and_not_empty():
    worksheet = build_worksheet(tenant_name="X", devices=[])
    assert "not a completed risk analysis" in worksheet["disclaimer"]
