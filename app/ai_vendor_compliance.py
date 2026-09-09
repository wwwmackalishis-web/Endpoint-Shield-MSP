"""AI-Vendor Compliance Agent (fleet position 9) - oversight only.

Endpoint Shield Solutions' own supply chain, not a client-facing report:
if this MSP's product pipeline calls out to any AI/ML vendor (a threat-
classification API, a support chatbot, anything that could see a client's
data even in passing), that vendor is itself a business associate under
HIPAA the moment client data reaches it - see COMPLIANCE-GAPS.md's own
framing of "Business Associate liability is direct." This module checks
Endpoint Shield Solutions' own vendor registry (app/models.py's AIVendor)
against that requirement, the same way app/patch_compliance.py checks a
client's fleet.

9a. BAA coverage    - does every vendor have a signed BAA on file.
9b. Retention/training opt-out - has each vendor confirmed client data is
    not retained or used for model training.
"""

STATUS_COVERED = "covered"
STATUS_NOT_COVERED = "not_covered"


def evaluate_vendor(vendor) -> dict:
    """`vendor` needs name, purpose, has_baa, data_retention_opted_out -
    an AIVendor row or anything with the same attributes."""
    issues = []
    if not vendor.has_baa:
        issues.append("No signed BAA on file for this vendor.")
    if not vendor.data_retention_opted_out:
        issues.append("Data retention/training opt-out has not been confirmed for this vendor.")

    return {
        "name": vendor.name,
        "purpose": vendor.purpose,
        "has_baa": vendor.has_baa,
        "data_retention_opted_out": vendor.data_retention_opted_out,
        "status": STATUS_COVERED if not issues else STATUS_NOT_COVERED,
        "issues": issues,
    }


def evaluate_all(vendors) -> dict:
    evaluations = [evaluate_vendor(v) for v in vendors]
    return {
        "total_vendors": len(evaluations),
        "not_covered_count": sum(1 for e in evaluations if e["status"] == STATUS_NOT_COVERED),
        "vendors": evaluations,
    }
