from app.referral import (
    FIT_GOOD,
    FIT_MARGINAL,
    FIT_POOR,
    draft_referral_outreach,
    qualify_lead,
)


# ---- 10a: outreach drafting ----

def test_draft_includes_partner_name():
    draft = draft_referral_outreach(partner_name="Jane Doe", partner_type="consultant")
    assert "Jane Doe" in draft["body"]
    assert "subject" in draft


def test_draft_angle_varies_by_partner_type():
    consultant = draft_referral_outreach(partner_name="X", partner_type="consultant")
    accountant = draft_referral_outreach(partner_name="X", partner_type="accountant")
    assert consultant["body"] != accountant["body"]


def test_draft_handles_unknown_partner_type():
    draft = draft_referral_outreach(partner_name="X", partner_type="something else")
    assert "X" in draft["body"]


# ---- 10b: lead qualification ----

def test_good_fit_lead():
    result = qualify_lead(device_count_estimate=20, has_existing_it_support=False, practice_type="dental")
    assert result["fit"] == FIT_GOOD


def test_poor_fit_too_small():
    result = qualify_lead(device_count_estimate=1, has_existing_it_support=True, practice_type="retail")
    assert result["fit"] == FIT_POOR


def test_marginal_fit_has_incumbent_it():
    result = qualify_lead(device_count_estimate=20, has_existing_it_support=True, practice_type="dental")
    assert result["fit"] in (FIT_MARGINAL, FIT_GOOD)


def test_missing_fields_still_produces_a_result_with_reasons():
    result = qualify_lead(device_count_estimate=None, has_existing_it_support=None, practice_type=None)
    assert result["fit"] == FIT_POOR
    assert len(result["reasons"]) == 3


def test_too_large_practice_flagged():
    result = qualify_lead(device_count_estimate=500, has_existing_it_support=False, practice_type="hospital")
    assert any("larger provider" in r for r in result["reasons"])
