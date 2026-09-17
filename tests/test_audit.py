"""The audit interceptor: what it records, and the contract it has with the gateway."""

import json

from conftest import GROUP_ID, USER_ID, audit_file, call_request, call_result, read_audit, run_audit


def test_before_record_captures_tool_and_arguments(log_dir):
    args = {"group_id": GROUP_ID, "user_id": USER_ID}
    proc = run_audit("before", call_request("add_user_to_group", args), log_dir)

    assert proc.returncode == 0
    # Anything on stdout would replace the real tool call.
    assert proc.stdout == ""
    rec = read_audit(log_dir)[0]
    assert rec["phase"] == "before"
    assert rec["tool"] == "add_user_to_group"
    assert rec["arguments"] == args
    assert rec["ts"].endswith("Z")


def test_after_record_summarizes_result(log_dir):
    run_audit("after", call_result('{"items": []}'), log_dir)

    result = read_audit(log_dir)[0]["result"]
    assert result == {"is_error": False, "content_items": 1, "text_chars": 13}


def test_error_body_counts_as_an_error(log_dir):
    """okta-mcp-server reports failures as isError=false with an {"error": ...} body."""
    body = json.dumps({"error": "Okta HTTP 403 E0000006 You do not have permission"})
    run_audit("after", call_result(body, is_error=False), log_dir)

    result = read_audit(log_dir)[0]["result"]
    assert result["is_error"] is True
    assert "E0000006" in result["error"]


def test_records_chain_and_are_numbered(log_dir):
    run_audit("before", call_request("list_groups", {}), log_dir)
    run_audit("after", call_result("{}"), log_dir)
    run_audit("before", call_request("list_users", {}), log_dir)

    records = read_audit(log_dir)
    assert [r["seq"] for r in records] == [1, 2, 3]
    assert records[0]["prev_sha256"] is None
    from verify_chain import verify
    assert verify(audit_file(log_dir)) == []


def test_unparsable_input_is_still_recorded(log_dir):
    """A call is never silently unlogged, even if the payload isn't what we expect."""
    proc = run_audit("before", "not json at all", log_dir)

    assert proc.returncode == 0
    assert len(read_audit(log_dir)) == 1


def test_bad_phase_fails_so_the_call_fails(log_dir):
    proc = run_audit("sideways", call_result("{}"), log_dir)

    assert proc.returncode != 0
    assert not log_dir.exists() or read_audit(log_dir) == []
