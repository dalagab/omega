#!/usr/bin/env python3
"""Report or delete bounded GitHub Actions artifacts from one workflow run.

Deletion is deliberately scoped to the current repository/run and requires explicit
artifact names and/or prefixes. It is operational cleanup only; Evidence authority
never depends on this script succeeding.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable
import urllib.error
import urllib.request

SCHEMA = "omega.github-actions-artifact-lifecycle.v1"
API_VERSION = "2022-11-28"
USER_AGENT = "Omega-SigmaScope-artifact-lifecycle/1"
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _request_json(url: str, token: str, *, method: str = "GET") -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
    if not payload:
        return {}
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("GitHub API returned a non-object response")
    return value


def list_run_artifacts(
    repository: str,
    run_id: int,
    token: str,
    *,
    request_json: Callable[..., dict[str, Any]] = _request_json,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100&page={page}"
        payload = request_json(url, token, method="GET")
        rows = [row for row in (payload.get("artifacts") or []) if isinstance(row, dict)]
        artifacts.extend(rows)
        if len(rows) < 100:
            break
        page += 1
    return artifacts


def select_artifacts(
    artifacts: list[dict[str, Any]],
    *,
    names: set[str] | None = None,
    prefixes: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    names = names or set()
    selected: list[dict[str, Any]] = []
    seen: set[int] = set()
    for artifact in artifacts:
        artifact_id = int(artifact.get("id") or 0)
        name = str(artifact.get("name") or "")
        if artifact_id <= 0 or not name or bool(artifact.get("expired")):
            continue
        if name not in names and not any(name.startswith(prefix) for prefix in prefixes):
            continue
        if artifact_id in seen:
            continue
        seen.add(artifact_id)
        selected.append(artifact)
    return selected


def artifact_summary(command: str, repository: str, run_id: int, selected: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for artifact in selected:
        rows.append({
            "id": int(artifact.get("id") or 0),
            "name": str(artifact.get("name") or ""),
            "sizeInBytes": int(artifact.get("size_in_bytes") or 0),
        })
    return {
        "schema": SCHEMA,
        "command": command,
        "repository": repository,
        "runId": run_id,
        "matchedCount": len(rows),
        "matchedBytes": sum(int(row["sizeInBytes"]) for row in rows),
        "artifacts": rows,
    }


def delete_selected(
    repository: str,
    token: str,
    selected: list[dict[str, Any]],
    *,
    request_json: Callable[..., dict[str, Any]] = _request_json,
) -> tuple[int, int, list[dict[str, Any]]]:
    deleted_count = 0
    deleted_bytes = 0
    failures: list[dict[str, Any]] = []
    for artifact in selected:
        artifact_id = int(artifact.get("id") or 0)
        name = str(artifact.get("name") or "")
        size = int(artifact.get("size_in_bytes") or 0)
        try:
            request_json(
                f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}",
                token,
                method="DELETE",
            )
        except Exception as exc:  # noqa: BLE001 - cleanup must attempt the remaining artifacts
            failures.append({"id": artifact_id, "name": name, "error": f"{type(exc).__name__}: {exc}"[:500]})
            continue
        deleted_count += 1
        deleted_bytes += size
    return deleted_count, deleted_bytes, failures


def _write(path: Path | None, value: dict[str, Any]) -> None:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path is None:
        print(text, end="")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("report", "delete"))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    parser.add_argument("--name", action="append", default=[])
    parser.add_argument("--prefix", action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    repository = str(args.repository or "").strip()
    if not REPOSITORY_RE.fullmatch(repository):
        parser.error("--repository must be owner/name")
    try:
        run_id = int(str(args.run_id or ""))
    except ValueError:
        parser.error("--run-id must be an integer")
    if run_id <= 0:
        parser.error("--run-id must be positive")
    token = str(os.environ.get(args.token_env) or "").strip()
    if not token:
        parser.error(f"environment variable {args.token_env} is required")

    names = {str(name).strip() for name in args.name if str(name).strip()}
    prefixes = tuple(str(prefix).strip() for prefix in args.prefix if str(prefix).strip())
    if args.command == "delete" and not names and not prefixes:
        parser.error("delete requires at least one --name or --prefix selector")

    try:
        artifacts = list_run_artifacts(repository, run_id, token)
        selected = select_artifacts(artifacts, names=names, prefixes=prefixes) if (names or prefixes) else [
            row for row in artifacts if isinstance(row, dict) and not bool(row.get("expired"))
        ]
        result = artifact_summary(args.command, repository, run_id, selected)
        if args.command == "delete":
            deleted_count, deleted_bytes, failures = delete_selected(repository, token, selected)
            result.update({
                "deletedCount": deleted_count,
                "deletedBytes": deleted_bytes,
                "failedCount": len(failures),
                "failures": failures,
            })
        _write(args.output, result)
        if args.command == "delete" and int(result.get("failedCount") or 0) > 0:
            for failure in result.get("failures") or []:
                print(f"artifact cleanup failed: {failure['name']}: {failure['error']}", file=sys.stderr)
            return 1
        return 0
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError) as exc:
        print(f"artifact lifecycle failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
