"""Shared helpers: run the audit interceptor, and build fake Okta events."""

import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

CLIENT_ID = "0oaTESTclient000000"
USER_ID = "00uTESTuser000000000"
GROUP_ID = "00gTESTgroup00000000"


@pytest.fixture
def log_dir(tmp_path):
    return tmp_path / "logs"


def run_audit(phase: str, payload, log_dir: pathlib.Path) -> subprocess.CompletedProcess:
    """Run scripts/audit.py the way the gateway does: JSON on stdin, nothing expected on stdout.

    A str payload is sent as-is, so a test can feed it something that isn't JSON.
    """
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "audit.py"), phase],
        input=payload if isinstance(payload, str) else json.dumps(payload), text=True, capture_output=True,
        env={"AUDIT_LOG_DIR": str(log_dir), "PATH": "/usr/bin:/bin"},
    )


def read_audit(log_dir: pathlib.Path) -> list[dict]:
    files = sorted(log_dir.glob("audit-*.jsonl"))
    return [json.loads(line) for f in files for line in f.read_text().splitlines()]


def audit_file(log_dir: pathlib.Path) -> pathlib.Path:
    return next(iter(sorted(log_dir.glob("audit-*.jsonl"))))


def call_request(tool: str, arguments: dict) -> dict:
    """Shaped like the gateway's marshalled CallToolRequest."""
    return {"Session": {}, "Params": {"name": tool, "arguments": arguments}}


def call_result(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def okta_event(event_type: str, published: str, actor_id: str, actor_name: str,
               actor_type: str = "PublicClientAppEntity", targets=(USER_ID, GROUP_ID)) -> dict:
    return {
        "eventType": event_type,
        "published": published,
        "actor": {"id": actor_id, "displayName": actor_name, "type": actor_type},
        "target": [{"id": t, "alternateId": "unknown", "displayName": t} for t in targets],
        "transaction": {"id": "txn-" + published},
        "outcome": {"result": "SUCCESS"},
    }
