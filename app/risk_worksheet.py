"""Risk Analysis Worksheet - Compliance Documentation Agent, subagent 4b.

45 CFR §164.308(a)(1)(ii)(A) requires "an accurate and thorough assessment
of the potential risks and vulnerabilities to the confidentiality,
integrity, and availability of electronic protected health information."
OCR's audit protocol breaks that into a standard sequence of elements
(scope, data flow, threat identification, current-measures assessment,
likelihood, impact, risk level, documentation, periodic review).

This module drafts the PAPERWORK, not the ANALYSIS. Two elements below
(scope, current security measures) are assembled from data this application
actually has - a real device inventory, a real audit trail - and are
therefore factual, not judgment calls. The three elements that require a
human decision - likelihood, impact, and the resulting risk level for each
threat - are deliberately left blank, one row per threat, for that human to
fill in. Auto-filling those would be exactly the mistake COMPLIANCE-GAPS.md
warns against for the BAA template: putting confidence-sounding language
into a document before the substance behind it exists. See that file's
framing ("a drafting starting point, not a signable document") - this
worksheet is the same idea applied to the risk analysis instead of the BAA.

Nothing here is legal advice, and the worksheet says so - see `disclaimer`
in build_worksheet()'s return value, which the API route surfaces unedited.
"""

from datetime import datetime
from typing import Iterable, Optional

DISCLAIMER = (
    "This worksheet assembles factual inputs for a HIPAA Security Rule risk "
    "analysis (45 CFR 164.308(a)(1)) from data this system already has - an "
    "asset inventory and audit-trail evidence. It is not a completed risk "
    "analysis and does not by itself demonstrate compliance. The likelihood, "
    "impact, and risk-level columns below require a human reviewer - "
    "ideally with input from counsel or a qualified security assessor - and "
    "are intentionally left blank."
)

# A starting checklist of threat categories common to a small healthcare
# practice's IT environment, drawn from the kind of threat catalogue HHS's
# own guidance and NIST SP 800-30 use as a baseline. This is reference
# material, not a claim about any specific practice - the worksheet asks the
# reviewer to confirm, add, or remove rows before scoring them.
COMMON_THREATS = [
    "Theft or loss of a laptop, phone, or portable drive containing ePHI",
    "Ransomware or other malware affecting a device or the network",
    "Unauthorized access via a compromised or shared login",
    "Workforce member accessing or disclosing ePHI without authorization (insider misuse)",
    "Loss of ePHI availability due to hardware failure with no tested backup",
    "A vendor or business associate accessing more data than their role requires",
    "Improper disposal of a device or drive that still holds ePHI",
    "Natural disaster or extended power/network outage affecting the primary site",
]

RISK_LEVEL_GUIDE = (
    "Suggested scale (fill in per threat, do not default to Medium): "
    "Risk = Likelihood (Low/Medium/High) x Impact (Low/Medium/High). "
    "Low x Low = Low. High x High = High. Any High-likelihood/High-impact "
    "pairing should be prioritized regardless of what else is on this list."
)


def _os_breakdown(devices: Iterable) -> dict:
    counts: dict = {}
    for device in devices:
        os_name = (getattr(device, "os", None) or "Unreported").strip() or "Unreported"
        counts[os_name] = counts.get(os_name, 0) + 1
    return counts


def _assess_current_measures(audit_result: Optional[dict], monitoring_enabled: bool) -> list:
    measures = []

    measures.append({
        "safeguard": "Access control - unique user authentication",
        "evidence": "Every dashboard session requires a per-user JWT issued at login; "
                    "there is no shared or anonymous access path to device or audit data.",
        "citation": "45 CFR 164.312(a)(2)(i)",
    })

    if audit_result and audit_result.get("total_events", 0) > 0:
        earliest = audit_result.get("earliest")
        distinct_actors = len(audit_result.get("distinct_actors", []))
        measures.append({
            "safeguard": "Audit controls",
            "evidence": (
                f"Audit trail active since {earliest or 'unknown'}: "
                f"{audit_result['total_events']} recorded events across "
                f"{distinct_actors} distinct user account(s)."
            ),
            "citation": "45 CFR 164.312(b)",
        })
    else:
        measures.append({
            "safeguard": "Audit controls",
            "evidence": "No audit events recorded in the queried period - confirm the "
                        "audit trail has actually been running, not just installed.",
            "citation": "45 CFR 164.312(b)",
        })

    measures.append({
        "safeguard": "Endpoint monitoring / alerting",
        "evidence": (
            "Automated silent-endpoint monitoring is enabled and pushes alerts on "
            "outage." if monitoring_enabled else
            "Automated monitoring is NOT currently enabled - fleet status is only "
            "as current as the last time a technician opened the dashboard."
        ),
        "citation": "45 CFR 164.308(a)(1)(ii)(D)",
    })

    return measures


def build_worksheet(
    *,
    tenant_name: str,
    devices: Iterable,
    audit_result: Optional[dict] = None,
    monitoring_enabled: bool = False,
    generated_at: Optional[datetime] = None,
) -> dict:
    devices = list(devices)
    generated_at = generated_at or datetime.utcnow()

    return {
        "disclaimer": DISCLAIMER,
        "tenant_name": tenant_name,
        "generated_at": generated_at.isoformat(),
        "sections": {
            "1_scope": {
                "title": "Scope of the analysis",
                "asset_count": len(devices),
                "assets_by_os": _os_breakdown(devices),
                "note": "Scope covers the devices tracked in this system as of the date "
                        "above. Confirm this matches every system that creates, receives, "
                        "maintains, or transmits ePHI - paper records, third-party SaaS, "
                        "and personal devices used for work are common gaps this list "
                        "cannot see.",
            },
            "2_data_flow": {
                "title": "Where and how ePHI moves",
                "note": "Not derivable from device inventory alone. Document: which "
                        "systems store ePHI, which staff roles can access it, and which "
                        "outside parties (billing, EHR vendor, cloud host) receive it.",
                "fields": ["storage_locations", "access_roles", "external_recipients"],
            },
            "3_threats_and_vulnerabilities": {
                "title": "Identify and document potential threats and vulnerabilities",
                "starting_checklist": list(COMMON_THREATS),
                "note": "Add or remove rows to match this practice's actual environment "
                        "before scoring them in section 5.",
            },
            "4_current_security_measures": {
                "title": "Assess current security measures",
                "measures": _assess_current_measures(audit_result, monitoring_enabled),
            },
            "5_6_7_risk_scoring": {
                "title": "Likelihood, impact, and level of risk per threat",
                "guide": RISK_LEVEL_GUIDE,
                "rows": [
                    {"threat": threat, "likelihood": None, "impact": None, "risk_level": None}
                    for threat in COMMON_THREATS
                ],
            },
            "8_finalize_documentation": {
                "title": "Finalize documentation",
                "note": "Retain this worksheet and its completed version for at least six "
                        "years (45 CFR 164.316(b)(2)(i)). A risk analysis with blank "
                        "scoring columns is a draft, not a finding - do not file this "
                        "version as the completed analysis.",
            },
            "9_periodic_review": {
                "title": "Periodic review",
                "note": "Re-run this analysis at least annually and after any material "
                        "change - a new vendor, a new location, a system migration, or a "
                        "confirmed incident (see the breach-notification clocks).",
            },
        },
    }
