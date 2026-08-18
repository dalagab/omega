#!/usr/bin/env python3
"""Stage a validated Omega base-catalog bootstrap from GitHub Actions.

The authoritative full base catalog is the ``omega-sqlite-catalog`` artifact produced by
``catalog-builder.yml``.  The public ``catalog-latest`` release intentionally contains the
small client marketplace projection, so release/regression jobs must not try to recover the
full base catalog from that release.

This helper selects the newest successful catalog-builder run whose retained artifact still
contains a valid base catalog, validates the database/descriptor/bundle triplet, and copies
only the runtime bootstrap bundle to the requested output path.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Sequence

import validate_base_catalog


BUILDER_WORKFLOW = "catalog-builder.yml"
ARTIFACT_NAME = "omega-sqlite-catalog"
BUNDLE_NAME = "omega-catalog.sqlite.zip"
DATABASE_NAME = "omega-catalog.sqlite"
DESCRIPTOR_NAME = "catalog.json"
DEFAULT_MAX_RUNS = 10


class HandoffError(RuntimeError):
    pass


class CommandRunner:
    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(list(argv), text=True, capture_output=True, check=False)


def _detail(completed: subprocess.CompletedProcess[str]) -> str:
    text = (completed.stderr or completed.stdout or "").strip()
    return text[:1200]


def _successful_builder_runs(runner: CommandRunner, repository: str, branch: str, max_runs: int) -> list[dict[str, Any]]:
    completed = runner.run([
        "gh", "run", "list",
        "--repo", repository,
        "--workflow", BUILDER_WORKFLOW,
        "--branch", branch,
        "--status", "success",
        "--limit", str(max_runs),
        "--json", "databaseId,createdAt,headSha,event,status,conclusion",
    ])
    if completed.returncode != 0:
        suffix = f" GitHub CLI: {_detail(completed)}" if _detail(completed) else ""
        raise HandoffError("Could not list successful Omega SQLite catalog builder runs." + suffix)
    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise HandoffError(f"GitHub CLI returned invalid catalog-builder run JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise HandoffError("GitHub CLI returned an unexpected catalog-builder run list.")
    return [item for item in payload if isinstance(item, dict)]


def _artifact_root(download_root: Path) -> Path:
    candidates: list[Path] = []
    for bundle in download_root.rglob(BUNDLE_NAME):
        parent = bundle.parent
        if (parent / DATABASE_NAME).is_file() and (parent / DESCRIPTOR_NAME).is_file():
            candidates.append(parent)
    if not candidates:
        raise HandoffError(
            f"Downloaded {ARTIFACT_NAME} artifact does not contain {DATABASE_NAME}, "
            f"{BUNDLE_NAME}, and {DESCRIPTOR_NAME} together."
        )
    # The upload contract should yield exactly one catalog triplet. Fail closed if an artifact
    # somehow contains multiple competing roots instead of guessing which one is authoritative.
    unique = sorted({path.resolve() for path in candidates}, key=lambda p: str(p))
    if len(unique) != 1:
        raise HandoffError(f"Downloaded {ARTIFACT_NAME} artifact contains multiple catalog roots.")
    return unique[0]


def stage_catalog_bootstrap(
    *,
    repository: str,
    output: Path,
    branch: str = "main",
    max_runs: int = DEFAULT_MAX_RUNS,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    if not repository or "/" not in repository:
        raise HandoffError("GitHub repository must be supplied as owner/name.")
    if not branch.strip():
        raise HandoffError("Catalog builder branch must be supplied.")
    if max_runs <= 0:
        raise HandoffError("max_runs must be positive.")

    runner = runner or CommandRunner()
    runs = _successful_builder_runs(runner, repository, branch.strip(), max_runs)
    if not runs:
        raise HandoffError("No successful Omega SQLite catalog builder run is available.")

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="omega-bootstrap-handoff-") as td:
        temp_root = Path(td)
        for item in runs[:max_runs]:
            try:
                run_id = int(item.get("databaseId") or 0)
            except (TypeError, ValueError):
                continue
            if run_id <= 0:
                continue

            destination = temp_root / str(run_id)
            destination.mkdir(parents=True, exist_ok=True)
            completed = runner.run([
                "gh", "run", "download", str(run_id),
                "--repo", repository,
                "--name", ARTIFACT_NAME,
                "--dir", str(destination),
            ])
            if completed.returncode != 0:
                failures.append(f"run {run_id}: artifact download failed: {_detail(completed)}")
                continue

            try:
                root = _artifact_root(destination)
                validation = validate_base_catalog.validate_local(root)
            except Exception as exc:
                failures.append(f"run {run_id}: {type(exc).__name__}: {exc}")
                continue

            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / BUNDLE_NAME, output)
            return {
                "artifact": ARTIFACT_NAME,
                "workflow": BUILDER_WORKFLOW,
                "branch": branch.strip(),
                "runId": run_id,
                "headSha": str(item.get("headSha") or ""),
                "createdAt": str(item.get("createdAt") or ""),
                "output": str(output),
                "variantCount": int(validation["database"]["variantCount"]),
                "catalogBaseRevision": str(validation["database"]["metadata"].get("catalog_base_revision") or ""),
            }

    detail = "; ".join(failures[:max_runs])
    suffix = f" Attempts: {detail}" if detail else ""
    raise HandoffError("No retained successful catalog-builder artifact passed bootstrap validation." + suffix)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--branch", default="main")
    parser.add_argument("--output", type=Path, default=Path("catalog/bootstrap") / BUNDLE_NAME)
    parser.add_argument("--max-runs", type=int, default=DEFAULT_MAX_RUNS)
    args = parser.parse_args()
    result = stage_catalog_bootstrap(
        repository=args.repository,
        branch=args.branch,
        output=args.output,
        max_runs=args.max_runs,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
