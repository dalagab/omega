#!/usr/bin/env python3
"""Roll Omega's Unreleased changelog work into a tagged release section.

The GitHub release workflow calls this only when the tagged commit is still the
default-branch tip. That avoids accidentally folding post-tag work into an older
release. The operation is idempotent for an already-finalized version.
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
from pathlib import Path

from extract_changelog import HEADING, extract_section


def finalize(text: str, version: str, release_date: str) -> str:
    if any(match.group(1).strip().casefold() == version.strip().casefold() for match in HEADING.finditer(text)):
        return text

    matches = list(HEADING.finditer(text))
    unreleased_index = next(
        (index for index, match in enumerate(matches) if match.group(1).strip().casefold() == "unreleased"),
        None,
    )
    if unreleased_index is None:
        raise ValueError("CHANGELOG.md has no Unreleased section to finalize")

    unreleased = matches[unreleased_index]
    next_start = matches[unreleased_index + 1].start() if unreleased_index + 1 < len(matches) else len(text)
    body = extract_section(text, "Unreleased").strip()
    replacement = (
        "## [Unreleased]\n\n"
        f"## [{version}] - {release_date}\n\n"
        f"{body}\n\n"
    )
    return text[:unreleased.start()] + replacement + text[next_start:].lstrip("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--date", default=dt.date.today().isoformat())
    parser.add_argument("--input", default="CHANGELOG.md")
    parser.add_argument("--output", default="CHANGELOG.md")
    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    text = input_path.read_text(encoding="utf-8")
    output_path.write_text(finalize(text, args.version, args.date), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
