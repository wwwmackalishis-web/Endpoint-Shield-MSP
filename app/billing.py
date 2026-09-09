"""Billing & Renewal Agent (fleet position 8).

8a. generate_invoice()  - computes one billing period's line items from the
                          tenant's own configured rate. Returns an explicit
                          "not configured" result rather than a $0 invoice
                          when no rate has been entered - a silently-zero
                          invoice is a worse bug than a loud error.
8b. renewals_due()      - flags MSA/SMA/BAA renewal dates approaching within
                          a window. Real dates in, real flags out - this
                          does not guess a renewal date for a contract that
                          was never recorded.
8c. churn_risk()        - a login-frequency heuristic: this tenant's own
                          staff logging into the dashboard measurably less
                          than they used to is a real, checkable signal that
                          something changed, not proof of anything by
                          itself. Named a "flag for a human to look at", not
                          a verdict, on purpose - see the `note` field
                          route consumers should surface, not just the bool.

All money is handled in integer cents throughout, per Tenant.monthly_base_fee_cents
/ per_device_fee_cents in app/models.py - never floats, so nothing here can
accumulate a rounding error across a year of invoices.
"""

from datetime import datetime, timedelta
from typing import Optional

# How far out a renewal has to be before this agent stops mentioning it.
# 60 days gives enough runway to renegotiate or re-sign before the old
# paper lapses.
DEFAULT_RENEWAL_WINDOW_DAYS = 60

# A drop this large between two equal-length windows is treated as a churn
# signal. Deliberately blunt (a plain percentage, not a statistical model) -
# this is meant to catch a client that used to log in daily and now hasn't
# in weeks, not to be precise about borderline cases.
CHURN_DROP_THRESHOLD_PERCENT = 50.0


def generate_invoice(*, tenant_name: str, monthly_base_fee_cents: Optional[int],
                      per_device_fee_cents: Optional[int], device_count: int,
                      period_start: datetime, period_end: datetime) -> dict:
    """8a. Both fee fields NULL means no billing plan has been configured
    for this tenant at all - a genuinely different case from a $0 plan,
    which this function has no way to distinguish from "not set up yet" if
    it silently produced one."""
    if monthly_base_fee_cents is None and per_device_fee_cents is None:
        return {
            "configured": False,
            "tenant_name": tenant_name,
            "note": "No billing plan is configured for this client - set monthly_base_fee_cents "
                    "and/or per_device_fee_cents via PUT /api/v1/tenant/settings first.",
        }

    base = monthly_base_fee_cents or 0
    per_device = per_device_fee_cents or 0
    device_line_total = per_device * device_count
    total = base + device_line_total

    return {
        "configured": True,
        "tenant_name": tenant_name,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "line_items": [
            {"description": "Base service fee", "amount_cents": base},
            {"description": f"Per-device fee ({device_count} device(s) x {per_device}c)",
             "amount_cents": device_line_total},
        ],
        "total_cents": total,
    }


def renewals_due(*, msa_renewal_date: Optional[datetime], sma_renewal_date: Optional[datetime],
                  baa_renewal_date: Optional[datetime], within_days: int = DEFAULT_RENEWAL_WINDOW_DAYS,
                  today: Optional[datetime] = None) -> list:
    """8b. Returns only the contracts that are (a) on file and (b) due
    within the window - a contract type with no date recorded is silently
    skipped, not reported as overdue against a date nobody entered."""
    today = today or datetime.utcnow()
    horizon = today + timedelta(days=within_days)
    candidates = [
        ("MSA", msa_renewal_date),
        ("SMA", sma_renewal_date),
        ("BAA", baa_renewal_date),
    ]
    due = []
    for contract_type, renewal_date in candidates:
        if renewal_date is None:
            continue
        days_until = (renewal_date - today).days
        if renewal_date <= horizon:
            due.append({
                "contract_type": contract_type,
                "renewal_date": renewal_date.isoformat(),
                "days_until": days_until,
                "overdue": days_until < 0,
            })
    return sorted(due, key=lambda d: d["days_until"])


def churn_risk(*, current_period_logins: int, prior_period_logins: int) -> dict:
    """8c. Compares two equal-length windows of login.success events
    (app/audit.py) for one tenant - the caller picks the windows (see
    GET /api/v1/billing/churn-risk in app/main.py, which uses trailing and
    preceding 30-day periods)."""
    if prior_period_logins == 0:
        if current_period_logins == 0:
            return {"at_risk": False, "percent_change": None,
                    "note": "No login activity in either period - insufficient data to flag churn risk."}
        return {"at_risk": False, "percent_change": None,
                "note": "No prior-period logins to compare against."}

    percent_change = ((current_period_logins - prior_period_logins) / prior_period_logins) * 100
    at_risk = percent_change <= -CHURN_DROP_THRESHOLD_PERCENT
    note = (
        f"Dashboard logins are down {abs(round(percent_change))}% versus the prior period - "
        "worth a check-in call."
        if at_risk else
        "Login activity is within normal range."
    )
    return {"at_risk": at_risk, "percent_change": round(percent_change, 1), "note": note}
