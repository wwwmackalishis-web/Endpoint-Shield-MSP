from datetime import datetime, timedelta

from app.billing import (
    CHURN_DROP_THRESHOLD_PERCENT,
    churn_risk,
    generate_invoice,
    renewals_due,
)


# ---- 8a: invoice generation ----

def test_no_billing_plan_configured():
    result = generate_invoice(
        tenant_name="Riverside Dental", monthly_base_fee_cents=None, per_device_fee_cents=None,
        device_count=10, period_start=datetime(2026, 1, 1), period_end=datetime(2026, 1, 31),
    )
    assert result["configured"] is False


def test_invoice_totals_base_plus_per_device():
    result = generate_invoice(
        tenant_name="Riverside Dental", monthly_base_fee_cents=10000, per_device_fee_cents=500,
        device_count=12, period_start=datetime(2026, 1, 1), period_end=datetime(2026, 1, 31),
    )
    assert result["configured"] is True
    assert result["total_cents"] == 10000 + 12 * 500


def test_invoice_with_only_per_device_fee():
    result = generate_invoice(
        tenant_name="X", monthly_base_fee_cents=None, per_device_fee_cents=1000,
        device_count=5, period_start=datetime(2026, 1, 1), period_end=datetime(2026, 1, 31),
    )
    assert result["configured"] is True
    assert result["total_cents"] == 5000


# ---- 8b: renewal tracker ----

def test_no_dates_recorded_returns_nothing():
    result = renewals_due(msa_renewal_date=None, sma_renewal_date=None, baa_renewal_date=None,
                           today=datetime(2026, 1, 1))
    assert result == []


def test_renewal_within_window_is_flagged():
    today = datetime(2026, 1, 1)
    result = renewals_due(msa_renewal_date=today + timedelta(days=30), sma_renewal_date=None,
                           baa_renewal_date=None, within_days=60, today=today)
    assert len(result) == 1
    assert result[0]["contract_type"] == "MSA"
    assert result[0]["days_until"] == 30
    assert result[0]["overdue"] is False


def test_renewal_outside_window_is_not_flagged():
    today = datetime(2026, 1, 1)
    result = renewals_due(msa_renewal_date=today + timedelta(days=200), sma_renewal_date=None,
                           baa_renewal_date=None, within_days=60, today=today)
    assert result == []


def test_overdue_renewal_is_flagged_as_overdue():
    today = datetime(2026, 1, 1)
    result = renewals_due(msa_renewal_date=None, sma_renewal_date=today - timedelta(days=5),
                           baa_renewal_date=None, within_days=60, today=today)
    assert result[0]["overdue"] is True
    assert result[0]["days_until"] == -5


def test_multiple_renewals_sorted_by_urgency():
    today = datetime(2026, 1, 1)
    result = renewals_due(
        msa_renewal_date=today + timedelta(days=50),
        sma_renewal_date=today + timedelta(days=10),
        baa_renewal_date=today + timedelta(days=30),
        within_days=60, today=today,
    )
    assert [r["contract_type"] for r in result] == ["SMA", "BAA", "MSA"]


# ---- 8c: churn risk ----

def test_no_activity_either_period_is_not_at_risk():
    result = churn_risk(current_period_logins=0, prior_period_logins=0)
    assert result["at_risk"] is False


def test_stable_login_activity_is_not_at_risk():
    result = churn_risk(current_period_logins=18, prior_period_logins=20)
    assert result["at_risk"] is False


def test_sharp_drop_is_flagged():
    result = churn_risk(current_period_logins=2, prior_period_logins=20)
    assert result["at_risk"] is True
    assert result["percent_change"] <= -CHURN_DROP_THRESHOLD_PERCENT


def test_increase_in_logins_is_not_at_risk():
    result = churn_risk(current_period_logins=40, prior_period_logins=20)
    assert result["at_risk"] is False
    assert result["percent_change"] == 100.0
