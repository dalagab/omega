#!/usr/bin/env python3
"""Plan or explicitly apply bounded cleanup of duplicate source-followup issues."""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path

from create_source_followup_issues import _close_issue, _open_followup_issues, issue_internal_name

CONFIRMATION = "CLOSE-DUPLICATES"


def cleanup_plan(issues: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for issue in issues:
        internal = issue_internal_name(str(issue.get("body") or ""))
        if internal:
            grouped[internal.casefold()].append(issue)
    duplicates = []
    for rows in grouped.values():
        rows.sort(key=lambda row: int(row.get("number") or 0))
        if len(rows) > 1:
            duplicates.append({
                "internalName": issue_internal_name(str(rows[0].get("body") or "")),
                "keepIssue": int(rows[0].get("number") or 0),
                "closeIssues": [int(row.get("number") or 0) for row in rows[1:]],
            })
    duplicates.sort(key=lambda row: str(row["internalName"]).casefold())
    return {
        "schema": "omega.source-followup-cleanup.v1",
        "managedOpenIssues": len(issues),
        "duplicatePlugins": len(duplicates),
        "duplicateIssues": sum(len(row["closeIssues"]) for row in duplicates),
        "groups": duplicates,
    }


def apply_cleanup(plan: dict, repository: str, maximum: int) -> int:
    close_targets = {
        number: keep
        for group in plan.get("groups") or []
        for number in group.get("closeIssues") or []
        for keep in [int(group.get("keepIssue") or 0)]
    }
    closed = 0
    for number in close_targets:
        if closed >= max(0, maximum):
            break
        if _close_issue(repository, {"number": number}):
            closed += 1
    return closed


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan or apply bounded duplicate source-followup cleanup")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-close", type=int, default=100)
    parser.add_argument("--apply", default="", help=f"Pass {CONFIRMATION} to close duplicates")
    args = parser.parse_args()
    if not args.repository:
        parser.error("--repository or GITHUB_REPOSITORY is required")
    plan = cleanup_plan(_open_followup_issues(args.repository))
    if args.output:
        args.output.write_text(json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in plan.items() if key != "groups"}, sort_keys=True))
    if args.apply != CONFIRMATION:
        print(f"Dry run only. Pass --apply {CONFIRMATION} to close at most {max(0, args.max_close)} duplicates.")
        return 0
    closed = apply_cleanup(plan, args.repository, args.max_close)
    print(f"Closed {closed} duplicate source-followup issue(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
