from types import SimpleNamespace

from app.ai_vendor_compliance import STATUS_COVERED, STATUS_NOT_COVERED, evaluate_all, evaluate_vendor


def make_vendor(name="Acme AI", purpose="threat scoring", has_baa=True, data_retention_opted_out=True):
    return SimpleNamespace(name=name, purpose=purpose, has_baa=has_baa, data_retention_opted_out=data_retention_opted_out)


def test_fully_covered_vendor_has_no_issues():
    result = evaluate_vendor(make_vendor())
    assert result["status"] == STATUS_COVERED
    assert result["issues"] == []


def test_missing_baa_is_flagged():
    result = evaluate_vendor(make_vendor(has_baa=False))
    assert result["status"] == STATUS_NOT_COVERED
    assert any("BAA" in issue for issue in result["issues"])


def test_missing_retention_optout_is_flagged():
    result = evaluate_vendor(make_vendor(data_retention_opted_out=False))
    assert result["status"] == STATUS_NOT_COVERED
    assert any("retention" in issue.lower() for issue in result["issues"])


def test_both_issues_reported_together():
    result = evaluate_vendor(make_vendor(has_baa=False, data_retention_opted_out=False))
    assert len(result["issues"]) == 2


def test_evaluate_all_counts_not_covered():
    vendors = [make_vendor(), make_vendor(has_baa=False), make_vendor(data_retention_opted_out=False)]
    result = evaluate_all(vendors)
    assert result["total_vendors"] == 3
    assert result["not_covered_count"] == 2
