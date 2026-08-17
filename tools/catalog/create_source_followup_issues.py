#!/usr/bin/env python3
"""Reconcile bounded GitHub issues for actionable public-source coverage gaps."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


LABEL = "omega-source-followup"
DEFAULT_MAX_NEW = 25
FOLLOWUP_KEY_RE = re.compile(r"omega-source-followup:([A-Za-z0-9_-]+)")


def gh(*args: str) -> str:
    completed = subprocess.run(["gh", *args], check=True, text=True, capture_output=True)
    return completed.stdout


def issue_body(item: dict) -> str:
    candidates = "\n".join(f"- {url}" for url in item.get("sourceCandidates") or []) or "- No GitHub repository candidate was derived."
    return f"""<!-- {item['key']} -->
<!-- omega-source-submission -->
<!-- omega-source-internal:{item['internalName']} -->
## Public source needed for scanner coverage

Omega downloaded and statically scanned this plugin artifact, but could not inspect a public source repository for the same plugin/source pair. This is not a claim that the plugin is unsafe.

- **Plugin:** `{item['pluginName']}` (`{item['internalName']}`)
- **Catalog source:** {item['catalogSource']}
- **PluginMaster feed:** {item['catalogSourceUrl']}
- **Artifact:** {item['artifactUrl']}
- **Scanner reason:** {item['reason']}

### Attempted repository candidates
{candidates}

### Provide the source repository
Reply with the public GitHub repository URL containing this plugin's source. Omega will validate the repository identity, persist the plugin/source override, and queue a targeted security rescan.
"""


def followup_key(body: str) -> str:
    match = FOLLOWUP_KEY_RE.search(str(body or ""))
    return f"omega-source-followup:{match.group(1)}" if match else ""


def _open_followup_issues(repository: str) -> list[dict]:
    raw = gh(
        "issue", "list", "--repo", repository, "--label", LABEL, "--state", "open",
        "--limit", "1000", "--json", "number,body,title",
    )
    data = json.loads(raw)
    return data if isinstance(data, list) else []


def reconcile_issues(document: dict, repository: str, max_new: int = DEFAULT_MAX_NEW) -> tuple[int, int]:
    gh("label", "create", LABEL, "--color", "D4C5F9", "--description", "Public source needed for an Omega scan", "--force", "--repo", repository)
    existing = _open_followup_issues(repository)
    open_by_key: dict[str, dict] = {}
    for issue in existing:
        key = followup_key(str(issue.get("body") or ""))
        if key:
            open_by_key[key] = issue

    actionable = {
        str(item.get("key") or ""): item
        for item in document.get("followups") or []
        if item.get("actionable", True) and str(item.get("key") or "")
    }

    # A missing row can mean a transient scanner/API failure, a 404, or a source
    # gap that was intentionally made non-actionable. Close only when current
    # evidence explicitly confirms the public source was scanned successfully.
    resolved_keys = {
        str(key) for key in document.get("resolvedKeys") or []
        if str(key).startswith("omega-source-followup:")
    }
    closed = 0
    for key, issue in list(open_by_key.items()):
        if key not in resolved_keys:
            continue
        number = str(issue.get("number") or "")
        if not number:
            continue
        gh("issue", "close", number, "--repo", repository, "--comment", "Omega's current scanner evidence successfully inspected a public source repository for this plugin/source pair.")
        closed += 1

    created = 0
    for key, item in actionable.items():
        if key in open_by_key or created >= max(0, max_new):
            continue
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as stream:
            stream.write(issue_body(item))
            body_file = stream.name
        try:
            gh(
                "issue", "create", "--repo", repository,
                "--title", f"Source needed: {item['internalName']} ({item['catalogSource']})",
                "--label", LABEL, "--body-file", body_file,
            )
            created += 1
        finally:
            Path(body_file).unlink(missing_ok=True)
    return created, closed


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile deduplicated source-scan follow-up issues")
    parser.add_argument("--input", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--max-new", type=int, default=DEFAULT_MAX_NEW)
    args = parser.parse_args()
    if not args.repository:
        parser.error("--repository or GITHUB_REPOSITORY is required")
    document = json.loads(Path(args.input).read_text(encoding="utf-8"))
    created, closed = reconcile_issues(document, args.repository, args.max_new)
    print(f"Created {created} and closed {closed} source follow-up issue(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
