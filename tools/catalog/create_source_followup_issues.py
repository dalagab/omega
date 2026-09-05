#!/usr/bin/env python3
"""Reconcile bounded GitHub issues for actionable public-source coverage gaps.

Human follow-up is plugin-scoped even though source attribution remains variant/feed
scoped.  Multiple mirrors of the same Dalamud ``InternalName`` therefore share one
issue.  Resolving source discovery for that plugin closes redundant mirror issues;
it does *not* claim that every mirror artifact is byte-for-byte produced by that
source repository.  Artifact↔source correspondence stays per-variant evidence.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
import urllib.parse


LABEL = "omega-source-followup"
DEFAULT_MAX_NEW = 25
DEFAULT_MAX_CLOSE = 100
MAX_MANAGED_OPEN_ISSUES = 10_000
FOLLOWUP_KEY_RE = re.compile(r"omega-source-followup:([A-Za-z0-9_-]+)")
OVERRIDE_KEY_RE = re.compile(r"omega-source-override:([A-Za-z0-9_-]+)")
INTERNAL_RE = re.compile(r"omega-source-internal:([^\s<>]+)")


def gh(*args: str) -> str:
    completed = subprocess.run(["gh", *args], check=True, text=True, capture_output=True)
    return completed.stdout


def followup_key(body: str) -> str:
    match = FOLLOWUP_KEY_RE.search(str(body or ""))
    return f"omega-source-followup:{match.group(1)}" if match else ""


def issue_internal_name(body: str) -> str:
    match = INTERNAL_RE.search(str(body or ""))
    return match.group(1) if match else ""


def issue_override_keys(body: str) -> list[str]:
    """Return all feed-scoped source override keys carried by one managed issue."""
    body = str(body or "")
    keys: list[str] = []
    primary = FOLLOWUP_KEY_RE.search(body)
    if primary:
        keys.append(primary.group(1))
    for match in OVERRIDE_KEY_RE.finditer(body):
        key = match.group(1)
        if key not in keys:
            keys.append(key)
    return keys


def _group_actionable(document: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in document.get("followups") or []:
        if not isinstance(item, dict) or not item.get("actionable", True):
            continue
        internal = str(item.get("internalName") or "").strip()
        key = str(item.get("key") or "")
        if not internal or not key.startswith("omega-source-followup:"):
            continue
        grouped[internal.casefold()].append(item)
    for items in grouped.values():
        items.sort(key=lambda item: (
            str(item.get("catalogSource") or "").casefold(),
            str(item.get("assemblyVersion") or ""),
            int(item.get("variantId") or 0),
        ))
    return dict(grouped)


def _resolved_by_internal(document: dict) -> dict[str, dict]:
    resolved: dict[str, dict] = {}
    for item in document.get("resolved") or []:
        if not isinstance(item, dict):
            continue
        internal = str(item.get("internalName") or "").strip()
        if not internal:
            continue
        current = resolved.get(internal.casefold())
        # Prefer a version-correlated source when more than one mirror resolved.
        if current is None or (not current.get("versionMatched") and item.get("versionMatched")):
            resolved[internal.casefold()] = item
    return resolved


def issue_body(items: list[dict]) -> str:
    if not items:
        raise ValueError("issue_body requires at least one source-gap item")
    primary = items[0]
    internal_name = str(primary.get("internalName") or "")
    plugin_name = str(primary.get("pluginName") or internal_name)
    keys: list[str] = []
    versions: list[str] = []
    candidates: list[str] = []
    affected: list[str] = []
    for item in items:
        raw_key = str(item.get("key") or "")
        key = raw_key.split(":", 1)[1] if raw_key.startswith("omega-source-followup:") else str(item.get("overrideKey") or "")
        if key and key not in keys:
            keys.append(key)
        version = str(item.get("assemblyVersion") or "")
        if version and version not in versions:
            versions.append(version)
        for url in item.get("sourceCandidates") or []:
            url = str(url or "")
            if url and url not in candidates:
                candidates.append(url)
        source_name = str(item.get("catalogSource") or "unknown source")
        source_url = str(item.get("catalogSourceUrl") or "")
        artifact_url = str(item.get("artifactUrl") or "")
        reason = str(item.get("reason") or "Source unavailable")
        affected.append(
            f"- **{source_name}** — version `{version or 'unknown'}`\n"
            f"  - Feed: {source_url or 'unknown'}\n"
            f"  - Artifact: {artifact_url or 'unknown'}\n"
            f"  - Reason: {reason}"
        )
    if not keys:
        raise ValueError("source-gap group has no stable override keys")
    markers = [f"<!-- omega-source-followup:{keys[0]} -->"]
    markers.extend(f"<!-- omega-source-override:{key} -->" for key in keys)
    markers.extend((
        "<!-- omega-source-submission -->",
        f"<!-- omega-source-internal:{internal_name} -->",
        f"<!-- omega-source-version:{versions[0] if len(versions) == 1 else ''} -->",
    ))
    candidate_text = "\n".join(f"- {url}" for url in candidates) or "- No public repository candidate was derived."
    affected_text = "\n".join(affected)
    version_text = ", ".join(f"`{version}`" for version in versions) or "unknown"
    return "\n".join(markers) + f"""
## Public source needed for Sigmascope coverage

Omega downloaded and statically scanned one or more artifacts for **{plugin_name}** (`{internal_name}`), but could not inspect public source for every catalog mirror. This is a plugin-level source-discovery request and is not a claim that any artifact is unsafe.

- **Plugin identity:** `{internal_name}`
- **Observed version(s):** {version_text}
- **Affected catalog mirrors:** {len(items)}

### Affected catalog mirrors
{affected_text}

### Attempted repository candidates
{candidate_text}

### Provide the source repository
Reply with the public GitHub repository URL containing this plugin's source. Omega validates the Dalamud plugin identity and applies the validated repository to the affected feed-scoped source mappings above. The issue closes after current Sigmascope evidence successfully inspects public source for this plugin.

Finding source for the plugin resolves this human source-discovery request across mirrors. It does **not** prove that every mirror artifact was built from that source; artifact-to-source verification remains separate per-variant evidence.
"""


def _open_followup_issues(repository: str) -> list[dict]:
    owner_repo = "/".join(urllib.parse.quote(part, safe="") for part in repository.split("/"))
    label = urllib.parse.quote(LABEL, safe="")
    raw = gh(
        "api", "--paginate", "--slurp",
        "--jq", "map(map({number,body,title,pull_request}))",
        f"repos/{owner_repo}/issues?state=open&labels={label}&per_page=100",
    )
    pages = json.loads(raw)
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise RuntimeError("GitHub returned an incomplete or malformed source-followup issue listing")
    issues: list[dict] = []
    for page in pages:
        for issue in page:
            if not isinstance(issue, dict):
                raise RuntimeError("GitHub returned a malformed source-followup issue")
            if issue.get("pull_request"):
                continue
            issues.append({key: issue.get(key) for key in ("number", "body", "title")})
            if len(issues) > MAX_MANAGED_OPEN_ISSUES:
                raise RuntimeError(f"managed source-followup issue count exceeds {MAX_MANAGED_OPEN_ISSUES}")
    return issues


def _close_issue(repository: str, issue: dict, comment: str) -> bool:
    number = str(issue.get("number") or "")
    if not number:
        return False
    gh("issue", "close", number, "--repo", repository, "--comment", comment)
    return True


def _update_issue(repository: str, issue: dict, title: str, body: str) -> None:
    number = str(issue.get("number") or "")
    if not number:
        return
    if str(issue.get("title") or "") == title and str(issue.get("body") or "") == body:
        return
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as stream:
        stream.write(body)
        body_file = stream.name
    try:
        gh("issue", "edit", number, "--repo", repository, "--title", title, "--body-file", body_file)
    finally:
        Path(body_file).unlink(missing_ok=True)


def reconcile_issues(
    document: dict,
    repository: str,
    max_new: int = DEFAULT_MAX_NEW,
    max_close: int = DEFAULT_MAX_CLOSE,
) -> tuple[int, int]:
    gh("label", "create", LABEL, "--color", "D4C5F9", "--description", "Public source needed for an Omega scan", "--force", "--repo", repository)
    existing = _open_followup_issues(repository)
    actionable_by_internal = _group_actionable(document)
    resolved_by_internal = _resolved_by_internal(document)
    resolved_keys = {
        str(key) for key in document.get("resolvedKeys") or []
        if str(key).startswith("omega-source-followup:")
    }

    open_by_internal: dict[str, list[dict]] = defaultdict(list)
    unscoped: list[dict] = []
    for issue in existing:
        internal = issue_internal_name(str(issue.get("body") or ""))
        if internal:
            open_by_internal[internal.casefold()].append(issue)
        else:
            unscoped.append(issue)
    for issues in open_by_internal.values():
        issues.sort(key=lambda issue: int(issue.get("number") or 0))

    closed = 0

    def close(issue: dict, comment: str) -> bool:
        nonlocal closed
        if closed >= max(0, max_close):
            return False
        if not _close_issue(repository, issue, comment):
            return False
        closed += 1
        return True

    # Compatibility for historical managed issues that somehow lack the InternalName marker.
    for issue in unscoped:
        if followup_key(str(issue.get("body") or "")) not in resolved_keys:
            continue
        close(
            issue,
            "Omega's current Sigmascope evidence successfully inspected public source for this source-discovery request.",
        )

    # Source discovery is plugin-scoped: once current evidence successfully inspects
    # public source for an InternalName, close every mirror-specific legacy issue.
    for internal_key, issues in list(open_by_internal.items()):
        resolution = resolved_by_internal.get(internal_key)
        if resolution is None:
            # Retain exact-key compatibility for legacy projection documents.
            exact = next((issue for issue in issues if followup_key(str(issue.get("body") or "")) in resolved_keys), None)
            if exact is None:
                continue
            resolution = {}
        repository_url = str(resolution.get("repository") or "")
        commit = str(resolution.get("commit") or "")
        confidence = str(resolution.get("confidence") or "")
        detail = ""
        if repository_url:
            detail += f" Repository: {repository_url}."
        if commit:
            detail += f" Commit: {commit[:12]}."
        if confidence:
            detail += f" Provenance confidence: {confidence}."
        comment = (
            "Omega's current Sigmascope evidence successfully inspected a public source repository for this plugin. "
            "This resolves the source-discovery request across catalog mirrors; individual artifact-to-source verification remains per variant."
            + detail
        )
        for issue in issues:
            close(issue, comment)
        open_by_internal.pop(internal_key, None)

    # Consolidate still-unresolved legacy mirror issues to one canonical issue and
    # refresh that issue with all currently affected feed-scoped override keys.
    for internal_key, issues in list(open_by_internal.items()):
        if not issues:
            continue
        canonical = issues[0]
        canonical_number = str(canonical.get("number") or "")
        for duplicate in issues[1:]:
            close(
                duplicate,
                f"Consolidated into #{canonical_number}. Source discovery is tracked once per plugin InternalName; mirror-specific artifact provenance remains separate.",
            )
        current_items = actionable_by_internal.get(internal_key) or []
        if current_items:
            internal_name = str(current_items[0].get("internalName") or "")
            _update_issue(repository, canonical, f"Source needed: {internal_name}", issue_body(current_items))
        open_by_internal[internal_key] = [canonical]

    created = 0
    for internal_key, items in sorted(
        actionable_by_internal.items(),
        key=lambda pair: str(pair[1][0].get("internalName") or "").casefold(),
    ):
        if internal_key in resolved_by_internal or internal_key in open_by_internal or created >= max(0, max_new):
            continue
        internal_name = str(items[0].get("internalName") or "")
        body = issue_body(items)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as stream:
            stream.write(body)
            body_file = stream.name
        try:
            gh(
                "issue", "create", "--repo", repository,
                "--title", f"Source needed: {internal_name}",
                "--label", LABEL, "--body-file", body_file,
            )
            created += 1
        finally:
            Path(body_file).unlink(missing_ok=True)
    return created, closed


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile plugin-scoped source-scan follow-up issues")
    parser.add_argument("--input", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--max-new", type=int, default=DEFAULT_MAX_NEW)
    parser.add_argument("--max-close", type=int, default=DEFAULT_MAX_CLOSE)
    args = parser.parse_args()
    if not args.repository:
        parser.error("--repository or GITHUB_REPOSITORY is required")
    document = json.loads(Path(args.input).read_text(encoding="utf-8"))
    created, closed = reconcile_issues(document, args.repository, args.max_new, args.max_close)
    print(f"Created {created} and closed {closed} source follow-up issue(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
