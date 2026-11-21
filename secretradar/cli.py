"""
Command line entry point.

    python -m secretradar scan <path>            scan a file or folder
    python -m secretradar scan <path> --json     machine readable output
    python -m secretradar scan <path> --fail-on high   exit 1 if any high finding

Designed to drop into a pre commit hook or a CI job: a non zero exit stops a
commit or a build that would leak a secret.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import summarise, to_console, to_json
from .scanner import scan_json_values, scan_path

ORDER = {"high": 0, "medium": 1, "low": 2}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secretradar", description="Find exposed secrets in files, repos and API exports.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or folder")
    scan.add_argument("path", help="file or folder to scan")
    scan.add_argument("--json", action="store_true", help="output JSON")
    scan.add_argument("--json-aware", action="store_true",
                      help="walk JSON structure (for Postman and SwaggerHub exports)")
    scan.add_argument("--fail-on", choices=["high", "medium", "low"],
                      help="exit 1 if a finding at this level or higher is present")

    args = parser.parse_args(argv)

    target = Path(args.path)
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 2

    if args.json_aware and target.is_file():
        fr = scan_json_values(target)
        results = [fr] if fr.findings else []
    else:
        results = scan_path(target)

    print(to_json(results) if args.json else to_console(results))

    if args.fail_on:
        threshold = ORDER[args.fail_on]
        worst = min((ORDER[f.confidence] for r in results for f in r.findings), default=99)
        if worst <= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
