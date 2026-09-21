"""Scrub a JSON-lines file (e.g. an OTLP/JSON dump) and print a summary.

python -m telemetry_scrubber dump.jsonl > clean.jsonl
"""

import argparse
import json
import sys

from .scrubber import Scrubber
from .tokens import Tokenizer


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="telemetry_scrubber")
    p.add_argument("path", help="JSON-lines file, '-' for stdin")
    p.add_argument("--tokenize", action="store_true", help="tokenize PII using SCRUBBER_TOKEN_KEY")
    p.add_argument("--summary-only", action="store_true")
    args = p.parse_args(argv)

    scrubber = Scrubber(tokenizer=Tokenizer.from_env() if args.tokenize else None)
    src = sys.stdin if args.path == "-" else open(args.path, encoding="utf-8")
    lines = 0
    with src:
        for line in src:
            line = line.strip()
            if not line:
                continue
            lines += 1
            clean, _ = scrubber.scrub_value(json.loads(line))
            if not args.summary_only:
                sys.stdout.write(json.dumps(clean) + "\n")

    print(f"lines={lines}", file=sys.stderr)
    for (detector, action), n in scrubber.stats.most_common():
        print(f"{detector:<20} {action:<9} {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
