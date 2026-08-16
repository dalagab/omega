#!/usr/bin/env python3
"""Project scanner source-coverage gaps into bounded, actionable follow-ups.

The security evidence database stays server-side.  This helper reads only the
current scanner rows and emits a small workflow artifact describing plugin/source
pairs whose public source could not be inspected.

A pure HTTP 404 is omitted: the scanner already established that the attempted
repository is absent.  Retryable network/service failures are retained in the JSON
for diagnostics but marked non-actionable so a transient outage cannot flood the
issue tracker.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from source_resolution import source_override_key


SCHEMA = "omega.source-scan-followups.v2"
_RETRYABLE = re.compile(
    r"(?:HTTP(?: Error)?\s+(?:408|425|429|500|502|503|504)\b|"
    r"timed?\s*out|timeout|temporar(?:y|ily)|connection reset|"
    r"connection aborted|rate.?limit|service unavailable|bad gateway|gateway timeout)",
    re.IGNORECASE,
)


def _attempts(error: str) -> list[str]:
    return [item.strip() for item in str(error or "").split(";") if item.strip()]


def is_not_found(error: str) -> bool:
    attempts = _attempts(error)
    return bool(attempts) and all(re.search(r"\b404\b", item) for item in attempts)


def is_retryable(error: str) -> bool:
    return bool(_RETRYABLE.search(str(error or "")))


def followups(database: Path) -> dict:
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT p.internal_name,v.variant_id,v.name,s.name AS source_name,s.url AS source_url,
                      sc.artifact_url,sc.report_json
                   FROM plugin_security_current sc
                   JOIN plugin_variants v ON v.variant_id=sc.variant_id
                   JOIN plugins p ON p.plugin_id=v.plugin_id
                   JOIN sources s ON s.source_id=v.source_id
                  WHERE sc.status='complete' AND sc.source_available=0
                  ORDER BY p.internal_name COLLATE NOCASE,s.name COLLATE NOCASE,v.variant_id"""
        ).fetchall()

    # One follow-up per stable plugin/feed pair. Multiple historical/current package
    # variants in the same feed should not create duplicate human work.
    projected: dict[str, dict] = {}
    for row in rows:
        try:
            report = json.loads(str(row["report_json"] or "{}"))
        except json.JSONDecodeError:
            report = {}
        source = report.get("source") if isinstance(report.get("source"), dict) else {}
        error = str(source.get("error") or "")
        if is_not_found(error):
            continue

        internal_name = str(row["internal_name"] or "")
        source_url = str(row["source_url"] or "")
        override_key = source_override_key(internal_name, source_url)
        retryable = is_retryable(error)
        item = {
            "key": f"omega-source-followup:{override_key}",
            "overrideKey": override_key,
            "variantId": int(row["variant_id"]),
            "internalName": internal_name,
            "pluginName": str(row["name"] or ""),
            "catalogSource": str(row["source_name"] or ""),
            "catalogSourceUrl": source_url,
            "artifactUrl": str(row["artifact_url"] or ""),
            "attemptedRepository": str(source.get("repository") or ""),
            "sourceCandidates": [str(item) for item in source.get("candidates") or [] if str(item)],
            "reason": error or "No public GitHub source repository could be resolved for scanning",
            "reasonCategory": "transient" if retryable else "source-missing",
            "actionable": not retryable,
        }
        current = projected.get(override_key)
        if current is None or (not current.get("actionable", True) and item["actionable"]):
            projected[override_key] = item

    items = sorted(projected.values(), key=lambda item: (item["internalName"].lower(), item["catalogSource"].lower()))
    return {
        "schema": SCHEMA,
        "count": len(items),
        "actionableCount": sum(1 for item in items if item["actionable"]),
        "followups": items,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Write bounded public-source scan follow-ups")
    parser.add_argument("--database", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = followups(Path(args.database))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output}: {result['count']} gap(s), {result['actionableCount']} actionable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
