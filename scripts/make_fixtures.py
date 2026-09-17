#!/usr/bin/env python3
"""Regenerate the demo fixtures in fixtures/.

Two scenarios, both invented: a clean day, and a day with something wrong.
Run: uv run scripts/make_fixtures.py
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

ORG = "https://acme.okta.com"
CLIENT_ID = "0oaDEMOgateway0000000"  # the gateway's Okta app
ADMIN = {"id": "00uDEMOadmin00000000", "displayName": "Robin Reyes",
         "alternateId": "robin.reyes@acme.example", "type": "User"}
GATEWAY = {"id": CLIENT_ID, "displayName": "Okta MCP Gateway",
           "alternateId": "unknown", "detailEntry": {"subjectProfile": "service"},
           "type": "PublicClientAppEntity"}

USERS = {"dana": ("00uDEMOdana000000000", "dana.okoye@acme.example"),
         "sam": ("00uDEMOsam0000000000", "sam.iqbal@acme.example")}
GROUPS = {"support-tier1": "00gDEMOsupport000000", "finance-admins": "00gDEMOfinance000000"}


def ts(day: str, hhmmss: str, ms: int = 0) -> dt.datetime:
    return dt.datetime.fromisoformat(f"{day}T{hhmmss}+00:00") + dt.timedelta(milliseconds=ms)


def audit_line(record: dict, prev: bytes | None, seq: int) -> bytes:
    record["prev_sha256"] = hashlib.sha256(prev).hexdigest() if prev else None
    record["seq"] = seq
    return json.dumps(record, separators=(",", ":")).encode()


def write_audit(path: pathlib.Path, calls: list[tuple]) -> None:
    """calls: (when, tool, arguments, result) -> before/after pair per call."""
    lines: list[bytes] = []
    prev = None
    for when, tool, arguments, result in calls:
        for record in (
            {"ts": when.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
             "phase": "before", "gateway_pid": 4242, "tool": tool, "arguments": arguments},
            {"ts": (when + dt.timedelta(seconds=3)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
             "phase": "after", "gateway_pid": 4242, "result": result},
        ):
            line = audit_line(record, prev, len(lines) + 1)
            lines.append(line)
            prev = line
    path.write_bytes(b"\n".join(lines) + b"\n")


def ok(chars: int = 120) -> dict:
    return {"is_error": False, "content_items": 1, "text_chars": chars}


def denied() -> dict:
    return {"is_error": True, "content_items": 1, "text_chars": 100,
            "error": "Okta HTTP 403 E0000006 You do not have permission to perform the requested action"}


def event(event_type: str, when: dt.datetime, actor: dict, targets: list[dict], outcome="SUCCESS") -> dict:
    return {
        "uuid": hashlib.sha1(f"{event_type}{when}".encode()).hexdigest(),
        "published": when.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "eventType": event_type,
        "displayMessage": event_type.replace(".", " "),
        "severity": "INFO",
        "actor": actor,
        "target": targets,
        "client": {"ipAddress": "198.51.100.24", "userAgent": {"rawUserAgent": "OpenAPI-Generator/1.0.0/python"}},
        "outcome": {"result": outcome},
        "transaction": {"id": hashlib.md5(f"{event_type}{when}".encode()).hexdigest(), "type": "WEB"},
        "debugContext": {"debugData": {"requestUri": "/api/v1/groups"}},
    }


def user_target(key: str) -> dict:
    uid, login = USERS[key]
    return {"id": uid, "alternateId": login, "displayName": login.split("@")[0], "type": "User"}


def group_target(name: str) -> dict:
    return {"id": GROUPS[name], "alternateId": "unknown", "displayName": name, "type": "UserGroup"}


def token_grant(when: dt.datetime) -> dict:
    return event("app.oauth2.token.grant.access_token", when, GATEWAY,
                 [{"id": "AT.demo", "alternateId": "unknown", "displayName": "Access Token", "type": "access_token"}])


def write_log(path: pathlib.Path, events: list[dict], window: tuple[str, str]) -> None:
    events = sorted(events, key=lambda e: e["published"])
    path.write_text(json.dumps({"window": {"since": window[0], "until": window[1]},
                                "items": events, "total_fetched": len(events), "has_more": False,
                                "next_cursor": None, "fetch_all_used": True,
                                "pagination_info": {"pages_fetched": 1, "stopped_early": False}}, indent=2) + "\n")


def clean_day() -> None:
    """A normal morning: reads, one change through the gateway, one refused, one admin change."""
    day = "2026-03-04"
    calls = [
        (ts(day, "09:14:02"), "list_group_users", {"group_id": GROUPS["support-tier1"]}, ok(2400)),
        (ts(day, "09:14:20"), "add_user_to_group",
         {"group_id": GROUPS["support-tier1"], "user_id": USERS["dana"][0]}, ok(93)),
        # Out of the gateway's resource set: Okta refuses it and logs nothing.
        (ts(day, "09:15:05"), "add_user_to_group",
         {"group_id": GROUPS["finance-admins"], "user_id": USERS["dana"][0]}, denied()),
        (ts(day, "09:16:40"), "list_user_groups", {"user_id": USERS["dana"][0]}, ok(1310)),
    ]
    write_audit(FIXTURES / "demo-audit.jsonl", calls)
    write_log(FIXTURES / "demo-system-log.json", [
        token_grant(ts(day, "09:14:01")),
        token_grant(ts(day, "09:14:19")),
        event("group.user_membership.add", ts(day, "09:14:23", 400), GATEWAY,
              [user_target("dana"), group_target("support-tier1")]),
        token_grant(ts(day, "09:15:04")),
        token_grant(ts(day, "09:16:39")),
        # An admin doing the same kind of work in the console.
        event("group.user_membership.remove", ts(day, "09:22:11"), ADMIN,
              [user_target("sam"), group_target("finance-admins")]),
        event("user.session.start", ts(day, "09:21:02"), ADMIN, [ADMIN]),
    ], (f"{day}T09:00:00Z", f"{day}T09:30:00Z"))


def incident_day() -> None:
    """The gateway's key used somewhere else, and a change the gateway made that Okta never recorded."""
    day = "2026-03-05"
    calls = [
        (ts(day, "11:02:10"), "list_groups", {}, ok(3154)),
        (ts(day, "11:03:00"), "remove_user_from_group",
         {"group_id": GROUPS["support-tier1"], "user_id": USERS["sam"][0]}, ok(97)),
    ]
    write_audit(FIXTURES / "incident-audit.jsonl", calls)
    write_log(FIXTURES / "incident-system-log.json", [
        token_grant(ts(day, "11:02:09")),
        token_grant(ts(day, "11:02:59")),
        # 11:03 change is missing from Okta: the audit log says it succeeded.
        # 02:47, with the gateway's credentials, while no session was running.
        token_grant(ts(day, "02:47:30")),
        event("group.user_membership.add", ts(day, "02:47:33"), GATEWAY,
              [user_target("sam"), group_target("finance-admins")]),
    ], (f"{day}T00:00:00Z", f"{day}T11:10:00Z"))


def main() -> None:
    FIXTURES.mkdir(exist_ok=True)
    clean_day()
    incident_day()
    for f in sorted(FIXTURES.iterdir()):
        print(f"wrote {f.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
