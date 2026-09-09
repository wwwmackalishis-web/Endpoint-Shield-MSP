"""Client Acquisition / Referral Agent (fleet position 10).

10a. draft_referral_outreach() - produces a ready-to-review email body for
     one referral partner. A draft for a human to read and send, like every
     other "for human sign-off" output in this fleet (app/incident_triage.py's
     recommend_response, app/risk_worksheet.py's worksheet) - nothing here
     calls app/notify.py itself.
10b. qualify_lead()            - scores an inbound lead against this MSP's
     actual service fit, using the same target-customer profile the HIPAA
     Risk Check quiz was built around: small healthcare-adjacent practices
     without dedicated in-house IT. A poor-fit score is not a rejection,
     it is "read this one more carefully before promising a timeline."
"""

from typing import Optional

# This MSP's serviceable range - grounded in what a single technician /
# small team can realistically support well, not an arbitrary number.
# Below MIN: probably not worth a dedicated MSP relationship yet. Above
# MAX: probably needs a bigger provider or an in-house hire.
MIN_DEVICE_COUNT = 3
MAX_DEVICE_COUNT = 75

# Practice types this MSP is actually built for - matches the HIPAA Risk
# Check's own audience line (medical, dental, hospitals, behavioral health,
# etc.) and their business associates.
TARGET_PRACTICE_TYPES = {
    "medical", "dental", "hospital", "urgent care", "behavioral health",
    "chiropractic", "physical therapy", "optometry", "pharmacy",
    "home health", "hospice", "billing company", "it provider",
}

FIT_GOOD = "good"
FIT_MARGINAL = "marginal"
FIT_POOR = "poor"


def draft_referral_outreach(*, partner_name: str, partner_type: str) -> dict:
    """10a. `partner_type` shapes which angle the draft leads with - a
    practice consultant cares about client outcomes, an accountant cares
    about avoiding liability exposure, a generalist IT provider cares about
    a referral fee/partnership rather than being replaced.
    """
    angle = {
        "consultant": "the compliance gaps we keep finding when a practice you've advised gets audited",
        "accountant": "the liability exposure a HIPAA-covered client carries if their IT isn't handled correctly",
        "it provider": "a referral partnership for the HIPAA-specific work outside your usual scope, not a competing pitch",
    }.get(partner_type.lower(), "how we help small healthcare practices stay HIPAA-compliant")

    body = (
        f"Hi {partner_name},\n\n"
        f"I wanted to reach out about {angle}. Endpoint Shield Solutions specializes in HIPAA-aware "
        "IT and endpoint security for small medical, dental, and behavioral health practices - the "
        "clients you already work with.\n\n"
        "If you ever run into a practice whose IT situation looks shaky - no real backups, no audit "
        "trail, an antivirus setup nobody's checked on in years - we'd welcome the introduction, and "
        "we're happy to return the favor.\n\n"
        "Would you be open to a short call?\n\n"
        "Best,\nEndpoint Shield Solutions"
    )
    return {"subject": f"Partnering on HIPAA-compliant IT for your clients", "body": body}


def qualify_lead(*, device_count_estimate: Optional[int], has_existing_it_support: Optional[bool],
                  practice_type: Optional[str]) -> dict:
    """10b. Every reason is stated explicitly in `reasons` so a human reviewing
    the lead sees exactly what drove the score, not just a label."""
    reasons = []
    score = 0

    if device_count_estimate is None:
        reasons.append("Device count not provided - ask before quoting.")
    elif device_count_estimate < MIN_DEVICE_COUNT:
        reasons.append(f"Only ~{device_count_estimate} devices - likely too small for a dedicated MSP relationship.")
    elif device_count_estimate > MAX_DEVICE_COUNT:
        reasons.append(f"~{device_count_estimate} devices - likely needs a larger provider or in-house IT.")
        score += 1
    else:
        reasons.append(f"~{device_count_estimate} devices is squarely in our serviceable range.")
        score += 2

    if practice_type and practice_type.lower() in TARGET_PRACTICE_TYPES:
        reasons.append(f"'{practice_type}' matches our target practice profile.")
        score += 2
    elif practice_type:
        reasons.append(f"'{practice_type}' is outside our usual target profile - confirm HIPAA exposure before quoting.")
    else:
        reasons.append("Practice type not provided.")

    if has_existing_it_support is False:
        reasons.append("No existing IT support - clean opportunity, no incumbent to displace.")
        score += 2
    elif has_existing_it_support is True:
        reasons.append("Already has IT support - a sale here means displacing an incumbent.")
        score += 1
    else:
        reasons.append("Existing IT situation not provided.")

    if score >= 5:
        fit = FIT_GOOD
    elif score >= 3:
        fit = FIT_MARGINAL
    else:
        fit = FIT_POOR

    return {"fit": fit, "score": score, "reasons": reasons}
