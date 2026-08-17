#!/usr/bin/env python3
"""Extract Omega release notes from CHANGELOG.md.

Development work is accumulated under ``## [Unreleased]``. When a GitHub tag is
cut, the release workflow asks for that tag's version. If the changelog already
contains an explicit section for the version it wins; otherwise the pending
Unreleased section becomes the release notes for that tag.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


HEADING = re.compile(r"^##\s+\[([^\]]+)\](?:\s+-\s+[^\n]+)?\s*$", re.M | re.I)


def extract_section(text: str, name: str) -> str:
    wanted = name.strip().casefold()
    matches = list(HEADING.finditer(text))
    for index, match in enumerate(matches):
        if match.group(1).strip().casefold() != wanted:
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        if not body:
            raise ValueError(f"CHANGELOG.md section for {name} is empty")
        return body + "\n"
    raise ValueError(f"CHANGELOG.md has no section for {name}")


def extract(text: str, version: str) -> str:
    try:
        return extract_section(text, version)
    except ValueError as version_error:
        try:
            return extract_section(text, "Unreleased")
        except ValueError:
            raise ValueError(
                f"CHANGELOG.md has no release section for {version} and no Unreleased work"
            ) from version_error


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
