#!/usr/bin/env python3
"""End-to-end check: start the gateway over stdio, list tools, and call one or more.

Usage: scripts/smoke.py [TOOL [JSON_ARGS]] ...
Default: list_groups {}. Prints a one-line summary per call; exits non-zero on any error.
"""

import json
import sys

from gateway_client import GatewayClient


def main(argv: list[str]) -> int:
    calls = []
    while argv:
        name = argv.pop(0)
        args = json.loads(argv.pop(0)) if argv and argv[0].startswith("{") else {}
        calls.append((name, args))
    calls = calls or [("list_groups", {})]

    failed = False
    with GatewayClient("okta-mcp-gateway-smoke") as gw:
        print(f"tools: {len(gw.list_tools())}")
        for name, args in calls:
            is_error, text = gw.call(name, args)
            failed |= is_error
            print(f"{name}: {'ERROR' if is_error else 'ok'} {text[:300]!r}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
