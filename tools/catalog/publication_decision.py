#!/usr/bin/env python3
"""Expose a tested fail-closed catalog publication decision to GitHub Actions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def decision(report_path: Path) -> dict[str, str]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    publication = report.get("publication")
    revisions = report.get("revisions")
    if not isinstance(publication, dict) or not isinstance(revisions, dict):
        raise ValueError("compaction report is missing publication/revision metadata")
    required = publication.get("required")
    if not isinstance(required, bool):
        raise ValueError("compaction report publication.required must be boolean")
    catalog_revision = str(revisions.get("catalogRevision") or "")
    security_revision = str(revisions.get("securityRevision") or "")
    if not catalog_revision.startswith("cat-v1-") or not security_revision.startswith("sec-"):
        raise ValueError("compaction report contains invalid semantic revision IDs")
    return {
        "publish": "true" if required else "false",
        "catalog_revision": catalog_revision,
        "security_revision": security_revision,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read Omega catalog publication decision")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    values = decision(args.report)
    lines = "".join(f"{key}={value}\n" for key, value in values.items())
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(lines)
    else:
        print(lines, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
