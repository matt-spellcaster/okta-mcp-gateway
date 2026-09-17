"""The committed demo fixtures: anyone can run these without an Okta org."""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
CLIENT_ID = "0oaDEMOgateway0000000"


def run_reconcile(scenario: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "reconcile.py"),
         str(FIXTURES / f"{scenario}-system-log.json"),
         "--audit", str(FIXTURES / f"{scenario}-audit.jsonl"),
         "--client-id", CLIENT_ID, "--json"],
        text=True, capture_output=True,
    )


def codes(proc) -> list[str]:
    return [json.loads(line)["code"] for line in proc.stdout.splitlines()]


def test_clean_day_has_nothing_to_answer_for():
    proc = run_reconcile("demo")

    assert proc.returncode == 0, proc.stderr
    assert sorted(codes(proc)) == ["BLOCKED_CHANGE", "CHANGE_OUTSIDE_GATEWAY", "MATCHED"]


def test_incident_day_reports_both_problems():
    proc = run_reconcile("incident")

    assert proc.returncode == 1
    assert sorted(codes(proc)) == ["MISSING_OKTA_EVENT", "UNAUDITED_GATEWAY_CHANGE"]


def test_scope_widened_day_shows_both_logs_covering_each_other():
    """Refused change (only the audit log has it), admin widening scope (only Okta has it), then success."""
    proc = run_reconcile("scope-widened")

    assert proc.returncode == 0
    findings = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [f["code"] for f in findings] == ["BLOCKED_CHANGE", "CHANGE_OUTSIDE_GATEWAY", "MATCHED"]
    assert "Director of IT" in findings[0]["detail"]
    # The successful change is matched to the event type Okta actually emits.
    assert "user.account.update_profile" in findings[2]["detail"]


def test_fixture_audit_logs_verify():
    from verify_chain import verify
    for name in ("demo-audit.jsonl", "incident-audit.jsonl", "scope-widened-audit.jsonl"):
        assert verify(FIXTURES / name) == [], name


def test_fixtures_are_up_to_date(tmp_path):
    """Regenerating must reproduce the committed files byte for byte."""
    before = {f.name: f.read_bytes() for f in sorted(FIXTURES.iterdir())}
    subprocess.run([sys.executable, str(ROOT / "scripts" / "make_fixtures.py")],
                   capture_output=True, check=True)
    after = {f.name: f.read_bytes() for f in sorted(FIXTURES.iterdir())}

    assert before == after, "fixtures differ from make_fixtures.py output; commit the regenerated files"
