#!/usr/bin/env python3
"""Check the hash chain in audit log files. Exits non-zero if any file is broken.

Usage: scripts/verify_chain.py [logs/audit-*.jsonl ...]   (default: all files in logs/)
"""

import hashlib
import json
import pathlib
import sys


def verify(path: pathlib.Path) -> list[str]:
    problems = []
    prev = None
    prev_seq = 0
    for n, line in enumerate(path.read_bytes().splitlines(), start=1):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"{path.name}:{n}: not valid JSON")
            prev = hashlib.sha256(line).hexdigest()
            continue
        if rec.get("seq") != prev_seq + 1:
            problems.append(f"{path.name}:{n}: seq jumps from {prev_seq} to {rec.get('seq')} (records missing or reordered)")
        prev_seq = rec.get("seq") if isinstance(rec.get("seq"), int) else prev_seq + 1
        if rec.get("prev_sha256") != prev:
            problems.append(f"{path.name}:{n}: prev_sha256 does not match line {n - 1}")
        prev = hashlib.sha256(line).hexdigest()
    return problems


def main(argv: list[str]) -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    files = [pathlib.Path(a) for a in argv] or sorted((root / "logs").glob("audit-*.jsonl"))
    if not files:
        print("verify_chain: no audit files found", file=sys.stderr)
        return 1
    failed = False
    for f in files:
        problems = verify(f)
        failed |= bool(problems)
        print(f"{f.name}: {'OK' if not problems else 'BROKEN'}")
        for p in problems:
            print(f"  {p}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
