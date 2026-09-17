"""Reconciliation between the audit log and the Okta System Log."""

import json

import pytest
from conftest import CLIENT_ID, GROUP_ID, USER_ID, call_request, call_result, okta_event, run_audit

from reconcile import load_audit, reconcile

OTHER_GROUP = "00gOTHERgroup00000000"
ADMIN_ID = "00uADMIN000000000000"


def codes(findings):
    return [f[0] for f in findings]


def audited_call(log_dir, tool, arguments, result_text='{"message": "ok"}'):
    run_audit("before", call_request(tool, arguments), log_dir)
    run_audit("after", call_result(result_text), log_dir)


def audit_calls(log_dir):
    return load_audit(sorted(log_dir.glob("audit-*.jsonl")))


@pytest.fixture
def membership_args():
    return {"group_id": GROUP_ID, "user_id": USER_ID}


def test_change_through_the_gateway_matches(log_dir, membership_args):
    audited_call(log_dir, "add_user_to_group", membership_args)
    calls = audit_calls(log_dir)
    published = calls[0]["ts"].strftime("%Y-%m-%dT%H:%M:%S.000Z")
    events = [okta_event("group.user_membership.add", published, CLIENT_ID, "Okta MCP Gateway")]

    findings = reconcile(events, calls, CLIENT_ID)

    assert codes(findings) == ["MATCHED"]


def test_okta_change_with_no_audit_record_is_high(log_dir):
    events = [okta_event("group.user_membership.add", "2026-09-17T12:00:00.000Z",
                         CLIENT_ID, "Okta MCP Gateway")]

    findings = reconcile(events, [], CLIENT_ID)

    assert codes(findings) == ["UNAUDITED_GATEWAY_CHANGE"]
    assert findings[0][1] == "high"


def test_audited_change_with_no_okta_event_is_medium(log_dir, membership_args):
    audited_call(log_dir, "add_user_to_group", membership_args)

    findings = reconcile([], audit_calls(log_dir), CLIENT_ID)

    assert codes(findings) == ["MISSING_OKTA_EVENT"]
    assert findings[0][1] == "medium"


def test_refused_change_is_reported_from_the_audit_log(log_dir):
    """Okta logs nothing for a 403, so the audit log is the only record."""
    body = json.dumps({"error": "Okta HTTP 403 E0000006 You do not have permission"})
    audited_call(log_dir, "add_user_to_group",
                 {"group_id": OTHER_GROUP, "user_id": USER_ID}, result_text=body)

    findings = reconcile([], audit_calls(log_dir), CLIENT_ID)

    assert codes(findings) == ["BLOCKED_CHANGE"]
    assert "E0000006" in findings[0][3]


def test_admin_change_is_listed_as_outside_the_gateway():
    events = [okta_event("group.user_membership.remove", "2026-09-17T12:00:00.000Z",
                         ADMIN_ID, "Admin User", actor_type="User")]

    findings = reconcile(events, [], CLIENT_ID)

    assert codes(findings) == ["CHANGE_OUTSIDE_GATEWAY"]
    assert findings[0][1] == "info"


def test_sign_ins_and_token_grants_are_not_treated_as_changes():
    events = [
        okta_event("app.oauth2.token.grant.access_token", "2026-09-17T12:00:00.000Z",
                   CLIENT_ID, "Okta MCP Gateway"),
        okta_event("user.authentication.sso", "2026-09-17T12:00:01.000Z",
                   ADMIN_ID, "Admin User", actor_type="User"),
        okta_event("policy.evaluate_sign_on", "2026-09-17T12:00:02.000Z",
                   ADMIN_ID, "Admin User", actor_type="User"),
    ]

    assert reconcile(events, [], CLIENT_ID) == []


def test_reads_are_not_expected_to_produce_events(log_dir):
    audited_call(log_dir, "list_groups", {}, result_text='{"items": []}')

    assert reconcile([], audit_calls(log_dir), CLIENT_ID) == []


def test_event_for_a_different_target_does_not_match(log_dir, membership_args):
    """A change to another group at the same moment must not be paired with this call."""
    audited_call(log_dir, "add_user_to_group", membership_args)
    calls = audit_calls(log_dir)
    published = calls[0]["ts"].strftime("%Y-%m-%dT%H:%M:%S.000Z")
    events = [okta_event("group.user_membership.add", published, CLIENT_ID, "Okta MCP Gateway",
                         targets=(USER_ID, OTHER_GROUP))]

    findings = reconcile(events, calls, CLIENT_ID)

    assert set(codes(findings)) == {"MISSING_OKTA_EVENT", "UNAUDITED_GATEWAY_CHANGE"}


def test_event_long_after_the_call_does_not_match(log_dir, membership_args):
    audited_call(log_dir, "add_user_to_group", membership_args)
    calls = audit_calls(log_dir)
    late = calls[0]["ts"].replace(year=2027).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    events = [okta_event("group.user_membership.add", late, CLIENT_ID, "Okta MCP Gateway")]

    assert "MATCHED" not in codes(reconcile(events, calls, CLIENT_ID))


def test_one_event_matches_only_one_call(log_dir, membership_args):
    """Two identical calls and a single event: one matches, the other is reported."""
    audited_call(log_dir, "add_user_to_group", membership_args)
    audited_call(log_dir, "add_user_to_group", membership_args)
    calls = audit_calls(log_dir)
    published = calls[0]["ts"].strftime("%Y-%m-%dT%H:%M:%S.000Z")
    events = [okta_event("group.user_membership.add", published, CLIENT_ID, "Okta MCP Gateway")]

    findings = reconcile(events, calls, CLIENT_ID)

    assert sorted(codes(findings)) == ["MATCHED", "MISSING_OKTA_EVENT"]


def test_calls_are_paired_in_order(log_dir):
    """The 'after' record belongs to the call that opened before it."""
    run_audit("before", call_request("list_groups", {}), log_dir)
    run_audit("after", call_result('{"items": []}'), log_dir)
    run_audit("before", call_request("add_user_to_group", {"group_id": GROUP_ID, "user_id": USER_ID}), log_dir)
    run_audit("after", call_result(json.dumps({"error": "boom"})), log_dir)

    calls = audit_calls(log_dir)

    assert [c["tool"] for c in calls] == ["list_groups", "add_user_to_group"]
    assert calls[0]["result"]["is_error"] is False
    assert calls[1]["result"]["is_error"] is True


def test_same_change_by_an_admin_does_not_match_a_gateway_call(log_dir, membership_args):
    """An admin making the same change at the same moment must not be credited to the gateway."""
    audited_call(log_dir, "add_user_to_group", membership_args)
    calls = audit_calls(log_dir)
    published = calls[0]["ts"].strftime("%Y-%m-%dT%H:%M:%S.000Z")
    events = [okta_event("group.user_membership.add", published, ADMIN_ID, "Admin User",
                         actor_type="User")]

    findings = reconcile(events, calls, CLIENT_ID)

    assert sorted(codes(findings)) == ["CHANGE_OUTSIDE_GATEWAY", "MISSING_OKTA_EVENT"]
