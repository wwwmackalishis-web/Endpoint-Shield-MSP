from datetime import datetime
from types import SimpleNamespace

from app import audit
from app.audit_summary import MAX_NARRATIVE_LINES, summarize_events


def make_event(**overrides):
    defaults = dict(
        timestamp=datetime(2026, 1, 1, 12, 0),
        action=audit.LOGIN_SUCCESS,
        outcome=audit.SUCCESS,
        actor_username="jsmith",
        target_type=None,
        target_id=None,
        detail=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_empty_events():
    result = summarize_events([])
    assert result["total_events"] == 0
    assert result["narrative"] == []
    assert result["by_action"] == {}
    assert result["distinct_actors"] == []


def test_counts_and_actors():
    events = [
        make_event(action=audit.LOGIN_SUCCESS, outcome=audit.SUCCESS, actor_username="jsmith"),
        make_event(action=audit.LOGIN_FAILURE, outcome=audit.FAILURE, actor_username="admin", detail="bad credentials"),
        make_event(action=audit.DEVICE_UPDATE, outcome=audit.SUCCESS, actor_username="jsmith",
                   target_id="FRONT-DESK-01", detail="fields=location,notes"),
    ]
    result = summarize_events(events)
    assert result["total_events"] == 3
    assert result["by_action"] == {
        audit.LOGIN_SUCCESS: 1,
        audit.LOGIN_FAILURE: 1,
        audit.DEVICE_UPDATE: 1,
    }
    assert result["by_outcome"] == {audit.SUCCESS: 2, audit.FAILURE: 1}
    assert result["distinct_actors"] == ["admin", "jsmith"]


def test_narrative_is_readable_and_never_leaks_field_values():
    events = [
        make_event(action=audit.DEVICE_UPDATE, actor_username="jsmith",
                   target_id="FRONT-DESK-01", detail="fields=location,notes"),
        make_event(action=audit.LOGIN_FAILURE, outcome=audit.FAILURE,
                   actor_username="baduser", detail="bad credentials"),
    ]
    result = summarize_events(events)
    assert "jsmith updated device FRONT-DESK-01 (changed: location, notes)" in result["narrative"][0]
    assert "failed login attempt for 'baduser' (bad credentials)" in result["narrative"][1]
    # The detail column only ever carries field names (see app/audit.py rule
    # 2) - this just guards that the summarizer doesn't invent a place to
    # print a value even if one ever leaked into `detail` upstream.
    for line in result["narrative"]:
        assert "notes=" not in line and "location=" not in line


def test_narrative_truncates_but_counts_do_not():
    events = [make_event(action=audit.LOGIN_SUCCESS) for _ in range(MAX_NARRATIVE_LINES + 10)]
    result = summarize_events(events)
    assert result["total_events"] == MAX_NARRATIVE_LINES + 10
    assert result["by_action"][audit.LOGIN_SUCCESS] == MAX_NARRATIVE_LINES + 10
    assert len(result["narrative"]) == MAX_NARRATIVE_LINES
    assert result["narrative_truncated"] is True


def test_unknown_action_still_produces_a_line():
    event = make_event(action="future.action", outcome=audit.SUCCESS,
                        target_type="widget", target_id="w1")
    result = summarize_events([event])
    assert "future.action" in result["narrative"][0]
    assert "w1" in result["narrative"][0]


# ---- security posture: derived from real counts, never a boilerplate claim ----

def test_no_failed_logins_states_a_real_zero():
    result = summarize_events([make_event(action=audit.LOGIN_SUCCESS)])
    assert result["security_posture"] == ["No failed login attempts were recorded in this period."]


def test_no_events_at_all_still_states_the_real_zero():
    # An empty period is not "unknown" - zero failed logins is still a
    # real, checked fact, not an assurance nobody looked for.
    result = summarize_events([])
    assert result["security_posture"] == ["No failed login attempts were recorded in this period."]


def test_failed_logins_are_reported_not_hidden():
    events = [make_event(action=audit.LOGIN_FAILURE, outcome=audit.FAILURE, actor_username="baduser")
              for _ in range(3)]
    result = summarize_events(events)
    assert result["security_posture"] == [
        "3 failed login attempts were recorded in this period - review the audit log for the account(s) involved."
    ]


def test_single_failed_login_uses_singular_wording():
    events = [make_event(action=audit.LOGIN_FAILURE, outcome=audit.FAILURE)]
    result = summarize_events(events)
    assert result["security_posture"][0].startswith("1 failed login attempt ")
