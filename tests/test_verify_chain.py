"""The hash chain should survive nothing being changed, and catch everything else."""

import json

import pytest
from conftest import audit_file, call_request, call_result, run_audit

from verify_chain import verify


@pytest.fixture
def chain(log_dir):
    """Three calls' worth of records written by the real interceptor."""
    for tool in ("list_groups", "list_users", "get_group"):
        run_audit("before", call_request(tool, {}), log_dir)
        run_audit("after", call_result("{}"), log_dir)
    return audit_file(log_dir)


def test_untouched_log_verifies(chain):
    assert verify(chain) == []


def test_edited_record_is_caught(chain):
    lines = chain.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["tool"] = "list_applications"
    lines[0] = json.dumps(rec, separators=(",", ":"))
    chain.write_text("\n".join(lines) + "\n")

    assert any("prev_sha256" in p for p in verify(chain))


def test_deleted_record_is_caught(chain):
    lines = chain.read_text().splitlines()
    del lines[2]
    chain.write_text("\n".join(lines) + "\n")

    problems = verify(chain)
    assert any("seq jumps" in p for p in problems)
    # One gap, not an error on every line after it.
    assert len([p for p in problems if "seq jumps" in p]) == 1


def test_reordered_records_are_caught(chain):
    lines = chain.read_text().splitlines()
    lines[2], lines[3] = lines[3], lines[2]
    chain.write_text("\n".join(lines) + "\n")

    assert verify(chain)


def test_appended_record_is_caught(chain):
    """A record forged onto the end can't carry the right previous hash."""
    forged = {"ts": "2026-09-17T23:59:59.000Z", "phase": "before", "tool": "delete_group",
              "arguments": {}, "prev_sha256": "0" * 64, "seq": 7}
    with chain.open("a") as f:
        f.write(json.dumps(forged, separators=(",", ":")) + "\n")

    assert any("prev_sha256" in p for p in verify(chain))
