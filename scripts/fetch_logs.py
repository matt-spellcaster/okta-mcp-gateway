#!/usr/bin/env python3
"""Fetch Okta System Log events through the gateway and save them as JSON.

Usage: scripts/fetch_logs.py SINCE [UNTIL] [-o FILE]
  SINCE/UNTIL: ISO 8601 UTC, e.g. 2026-09-17T16:00:00Z (UNTIL defaults to now)
The fetch itself goes through the gateway, so it is audited like any other call.
"""

import argparse
import datetime as dt
import json
import pathlib
import sys

from gateway_client import ROOT, GatewayClient


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("since")
    ap.add_argument("until", nargs="?")
    ap.add_argument("-o", "--output", type=pathlib.Path)
    a = ap.parse_args()
    until = a.until or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = a.output or ROOT / "logs" / f"okta-system-log-{a.since}-{until}.json".replace(":", "")

    with GatewayClient("okta-mcp-gateway-fetch-logs") as gw:
        is_error, text = gw.call("get_logs", {"since": a.since, "until": until, "fetch_all": True})
    if is_error:
        print(f"fetch_logs: {text[:500]}", file=sys.stderr)
        return 1
    body = json.loads(text)
    # reconcile.py uses this window, so a call made after the last event is still
    # judged (a change Okta never recorded is exactly what we want to catch).
    body["window"] = {"since": a.since, "until": until}
    out.parent.mkdir(mode=0o700, exist_ok=True)
    out.write_text(json.dumps(body, indent=2))
    out.chmod(0o600)
    items = body.get("items", [])
    print(f"{len(items)} events -> {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    if body.get("pagination_info", {}).get("stopped_early"):
        print("fetch_logs: warning: result was capped; narrow the time window", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
