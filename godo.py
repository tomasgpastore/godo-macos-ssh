#!/usr/bin/env python3
"""godo: guarded natural-language automation for macOS over SSH."""

from __future__ import annotations

import argparse
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="godo",
        description="Plan shell/app actions from natural language and require approval before running.",
    )
    parser.add_argument("request", help="Natural language request")
    parser.add_argument("--dry-run", action="store_true", help="Print plan only; never execute")
    parser.add_argument("--json", action="store_true", help="Print debug JSON output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # Initial scaffold behavior; model integration added in later commits.
    print(f"Intent: {args.request}")
    print("Risk: HIGH")
    print("Proposed script:")
    print("```bash")
    print("echo 'godo scaffold: model integration not yet implemented.'")
    print("```")
    if args.json:
        print('{"status":"scaffold","note":"model integration pending"}')
    if args.dry_run:
        print("Dry run mode: not executing.")
        return 0

    answer = input("Run this now? (y/N): ").strip().lower()
    if answer in {"y", "yes"}:
        print("Scaffold mode: no command execution yet.")
    else:
        print("Cancelled.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
