#!/usr/bin/env python3
"""Expose a tested fail-closed catalog publication decision to GitHub Actions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from catalog_revisions import is_valid_evidence_revision


def decision(report_path: Path, projection_report_path: Path | None = None) -> dict[str, str]:
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
    evidence_revision = str(revisions.get("evidenceRevision") or "")
    if not catalog_revision.startswith("cat-v1-") or not security_revision.startswith("sec-") or not is_valid_evidence_revision(evidence_revision):
        raise ValueError("compaction report contains invalid semantic revision IDs")
    marketplace_required = required
    if projection_report_path is not None:
        projection = json.loads(projection_report_path.read_text(encoding="utf-8"))
        projection_publication = projection.get("publication")
        if not isinstance(projection_publication, dict) or not isinstance(projection_publication.get("marketplaceRequired"), bool):
            raise ValueError("projection report publication.marketplaceRequired must be boolean")
        marketplace_required = bool(projection_publication["marketplaceRequired"])
    return {
        "publish": "true" if marketplace_required else "false",
        "publish_marketplace": "true" if marketplace_required else "false",
        "publish_evidence": "true" if required else "false",
        "catalog_revision": catalog_revision,
        "security_revision": security_revision,
        "evidence_revision": evidence_revision,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read Omega catalog publication decision")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--projection-report", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    values = decision(args.report, args.projection_report)
    lines = "".join(f"{key}={value}\n" for key, value in values.items())
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(lines)
    else:
        print(lines, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
