#!/usr/bin/env python3
"""Extract one Omega release section from CHANGELOG.md for GitHub Releases."""
from __future__ import annotations
import argparse
import re
from pathlib import Path


def extract(text: str, version: str) -> str:
    pattern = re.compile(rf"^##\s+\[{re.escape(version)}\](?:\s+-\s+[^\n]+)?\s*$", re.M)
    match = pattern.search(text)
    if not match:
        raise ValueError(f"CHANGELOG.md has no release section for {version}")
    start = match.end()
    next_heading = re.search(r"^##\s+", text[start:], re.M)
    end = start + next_heading.start() if next_heading else len(text)
    body = text[start:end].strip()
    if not body:
        raise ValueError(f"CHANGELOG.md release section for {version} is empty")
    return body + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--input", default="CHANGELOG.md")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    notes = extract(Path(args.input).read_text(encoding="utf-8"), args.version)
    Path(args.output).write_text(notes, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
