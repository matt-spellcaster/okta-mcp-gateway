#!/usr/bin/env python3
"""Gateway interceptor that writes an audit record for every tool call.

The gateway runs this on the host for each `tools/call`:
  --interceptor 'before:exec:scripts/audit.py before'   (stdin: the request)
  --interceptor 'after:exec:scripts/audit.py after'     (stdin: the result)

Records go to logs/audit-YYYY-MM-DD.jsonl (UTC). Each record carries the
SHA-256 of the previous line, so edits or deletions break the chain
(scripts/verify_chain.py checks it).

Contract with the gateway: print nothing to stdout, because any output
replaces the real call or result. A non-zero exit fails the call, so a call
that can't be logged doesn't run.
"""

import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import sys

LOG_DIR = pathlib.Path(os.environ.get("AUDIT_LOG_DIR", pathlib.Path(__file__).resolve().parent.parent / "logs"))


def find(obj, *names):
    """Find the first value under any of `names` (case-insensitive), searching nested dicts."""
    wanted = {n.lower() for n in names}
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.lower() in wanted:
                    return v
            stack.extend(v for v in cur.values() if isinstance(v, dict))
    return None


def summarize_result(payload):
    content = find(payload, "content") or []
    texts = [c.get("text", "") for c in content if isinstance(c, dict)]
    summary = {
        "is_error": bool(find(payload, "isError", "is_error")),
        "content_items": len(content),
        "text_chars": sum(len(t) for t in texts),
    }
    # okta-mcp-server reports many failures as isError=false with a body of
    # {"error": "..."}, so record those as errors too.
    for t in texts:
        try:
            body = json.loads(t)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(body, dict) and "error" in body:
            summary["is_error"] = True
            summary["error"] = str(body["error"])[:300]
            break
    return summary


def main() -> int:
    phase = sys.argv[1] if len(sys.argv) > 1 else ""
    if phase not in ("before", "after"):
        print("audit: expected 'before' or 'after'", file=sys.stderr)
        return 2

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {"unparsed": raw[:2000]}

    now = dt.datetime.now(dt.timezone.utc)
    record = {"ts": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"), "phase": phase, "gateway_pid": os.getppid()}
    if phase == "before":
        params = find(payload, "params") or payload
        record["tool"] = find(params, "name")
        record["arguments"] = find(params, "arguments") or {}
    else:
        record["result"] = summarize_result(payload)

    LOG_DIR.mkdir(mode=0o700, exist_ok=True)
    path = LOG_DIR / f"audit-{now:%Y-%m-%d}.jsonl"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "r+b") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        lines = f.read().splitlines()
        record["prev_sha256"] = hashlib.sha256(lines[-1]).hexdigest() if lines else None
        record["seq"] = len(lines) + 1
        f.write(json.dumps(record, separators=(",", ":"), default=str).encode() + b"\n")
        f.flush()
        os.fsync(f.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())
