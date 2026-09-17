#!/usr/bin/env python3
"""Reconcile the gateway audit log with the Okta System Log.

Usage: scripts/reconcile.py SYSTEM_LOG_JSON [--audit logs/audit-*.jsonl ...] [--client-id ID] [--json]

SYSTEM_LOG_JSON comes from scripts/fetch_logs.py. The time window is the span of
that file. Findings:

  UNAUDITED_GATEWAY_CHANGE  high    Okta change made with the gateway app's
                                    credentials that no audit record accounts for.
                                    The key was used outside the gateway, or the
                                    audit log was altered.
  MISSING_OKTA_EVENT        medium  An audited write call that succeeded, with no
                                    matching Okta event.
  AUDIT_CHAIN_BROKEN        high    The audit log hash chain doesn't verify.
  CHANGE_OUTSIDE_GATEWAY    info    A change by another actor (an admin in the
                                    console, another integration). Expected, but
                                    listed so a reviewer can account for it.
  MATCHED                   ok      Audited write call with its Okta event.

Exit status: 1 if any high or medium finding, else 0.
"""

import argparse
import datetime as dt
import json
import os
import pathlib
import sys

from verify_chain import verify

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Gateway write tools -> the Okta event they should produce, and which argument
# holds the target IDs. Only the group membership mapping has been observed in a
# live org; the others follow Okta's documented event types.
WRITE_TOOLS = {
    "add_user_to_group": ("group.user_membership.add", ["user_id", "group_id"]),
    "remove_user_from_group": ("group.user_membership.remove", ["user_id", "group_id"]),
    "create_user": ("user.lifecycle.create", []),
    "update_user": ("user.account.update_profile", ["user_id"]),
    "deactivate_user": ("user.lifecycle.deactivate", ["user_id"]),
    "delete_deactivated_user": ("user.lifecycle.delete.initiated", ["user_id"]),
    "create_group": ("group.lifecycle.create", []),
    "update_group": ("group.profile.update", ["group_id"]),
    "delete_group": ("group.lifecycle.delete", ["group_id"]),
    "confirm_delete_group": ("group.lifecycle.delete", ["group_id"]),
}

# Okta event types that represent a change (as opposed to sign-ins, token
# grants and policy evaluations).
CHANGE_PREFIXES = (
    "group.user_membership.", "group.lifecycle.", "group.profile.",
    "user.lifecycle.", "user.account.update", "user.account.privilege",
    "application.lifecycle.", "application.user_membership.", "app.oauth2.client.",
    "app.oauth2.credentials.", "app.oauth2.admin.consent.", "iam.", "policy.lifecycle.",
    "policy.rule.", "zone.",
)

MATCH_WINDOW = dt.timedelta(seconds=120)


def parse_ts(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_audit(paths):
    """Pair 'before' and 'after' records into calls (FIFO per gateway process)."""
    calls, pending = [], {}
    for path in paths:
        for line in path.read_text().splitlines():
            rec = json.loads(line)
            key = (path.name, rec.get("gateway_pid"))
            if rec["phase"] == "before":
                call = {"ts": parse_ts(rec["ts"]), "tool": rec.get("tool"),
                        "arguments": rec.get("arguments") or {}, "result": None,
                        "ref": f"{path.name}#{rec['seq']}"}
                calls.append(call)
                pending.setdefault(key, []).append(call)
            elif pending.get(key):
                pending[key].pop(0)["result"] = rec.get("result")
    return calls


def is_change(event) -> bool:
    return str(event.get("eventType", "")).startswith(CHANGE_PREFIXES)


def target_ids(event) -> set:
    return {t.get("id") for t in event.get("target") or []}


def reconcile(events, calls, client_id):
    findings = []
    used = set()
    writes = [c for c in calls if c["tool"] in WRITE_TOOLS]

    for call in writes:
        ok = call["result"] is not None and not call["result"].get("is_error")
        if not ok:
            continue  # failed calls aren't expected to change anything
        etype, id_args = WRITE_TOOLS[call["tool"]]
        want_ids = {call["arguments"].get(a) for a in id_args}
        match = next((
            i for i, e in enumerate(events)
            if i not in used
            and e.get("eventType") == etype
            and (e.get("actor") or {}).get("id") == client_id
            and want_ids <= target_ids(e)
            and call["ts"] - dt.timedelta(seconds=5) <= parse_ts(e["published"]) <= call["ts"] + MATCH_WINDOW
        ), None)
        if match is None:
            findings.append(("MISSING_OKTA_EVENT", "medium", call["ts"],
                             f"{call['tool']} {json.dumps(call['arguments'])} ({call['ref']}) has no {etype} event from the gateway app"))
        else:
            used.add(match)
            e = events[match]
            findings.append(("MATCHED", "ok", call["ts"],
                             f"{call['tool']} ({call['ref']}) -> {etype} at {e['published']} (request {e.get('transaction', {}).get('id')})"))

    for i, e in enumerate(events):
        if i in used or not is_change(e):
            continue
        actor = e.get("actor") or {}
        targets = ", ".join(t.get("alternateId") if t.get("alternateId") not in (None, "unknown") else t.get("displayName", "?")
                            for t in e.get("target") or [])
        desc = f"{e['eventType']} by {actor.get('displayName')} ({actor.get('type')}) on {targets}"
        if actor.get("id") == client_id:
            findings.append(("UNAUDITED_GATEWAY_CHANGE", "high", parse_ts(e["published"]), desc))
        else:
            findings.append(("CHANGE_OUTSIDE_GATEWAY", "info", parse_ts(e["published"]), desc))

    return sorted(findings, key=lambda f: f[2])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("system_log", type=pathlib.Path)
    ap.add_argument("--audit", type=pathlib.Path, nargs="*")
    ap.add_argument("--client-id", default=os.environ.get("OKTA_CLIENT_ID"))
    ap.add_argument("--json", action="store_true", help="print findings as JSON lines")
    a = ap.parse_args()

    if not a.client_id:
        env = ROOT / "env"
        for line in env.read_text().splitlines() if env.exists() else []:
            if line.startswith("OKTA_CLIENT_ID="):
                a.client_id = line.split("=", 1)[1].split("#")[0].strip().strip('"')
    if not a.client_id:
        ap.error("gateway client ID not found; pass --client-id or set OKTA_CLIENT_ID in env")

    events = json.loads(a.system_log.read_text()).get("items", [])
    if not events:
        print("reconcile: the System Log file has no events", file=sys.stderr)
        return 1
    start = min(parse_ts(e["published"]) for e in events)
    end = max(parse_ts(e["published"]) for e in events)

    audit_paths = a.audit or sorted((ROOT / "logs").glob("audit-*.jsonl"))
    findings = []
    for p in audit_paths:
        for problem in verify(p):
            findings.append(("AUDIT_CHAIN_BROKEN", "high", start, problem))
    calls = [c for c in load_audit(audit_paths) if start - MATCH_WINDOW <= c["ts"] <= end]
    findings += reconcile(events, calls, a.client_id)

    tokens = sum(1 for e in events if e.get("eventType") == "app.oauth2.token.grant.access_token"
                 and (e.get("actor") or {}).get("id") == a.client_id)
    reads = sum(1 for c in calls if c["tool"] not in WRITE_TOOLS)

    if a.json:
        for code, sev, ts, msg in findings:
            print(json.dumps({"code": code, "severity": sev, "time": ts.isoformat(), "detail": msg}))
    else:
        print(f"Window {start:%Y-%m-%d %H:%M:%S} to {end:%H:%M:%S} UTC: {len(events)} Okta events, "
              f"{len(calls)} audited calls ({reads} reads), {tokens} gateway token grants\n")
        for code, sev, ts, msg in findings:
            print(f"{ts:%H:%M:%S}  {sev:<6}  {code:<25} {msg}")
        counts = {}
        for f in findings:
            counts[f[0]] = counts.get(f[0], 0) + 1
        print("\n" + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    return 1 if any(f[1] in ("high", "medium") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
