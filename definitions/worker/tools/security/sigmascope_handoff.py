#!/usr/bin/env python3
"""Resolve the authoritative catalog handoff for the Omega Sigmascope workflow.

The catalog builder artifact is the source of truth for every Sigmascope run. Workflow-run
invocations prefer the triggering builder run; scheduled/manual runs (and failed upstream
artifact lookups) fall back to the newest successful catalog-builder run that still exposes
the expected ``omega-sqlite-catalog`` artifact.

A bounded JSON diagnostic is always written before returning, including failed ``gh``
commands. This makes early handoff failures downloadable from GitHub Actions instead of
leaving only an opaque shell exit code.
"""
from __future__ import annotations

import argparse
import datetime as dt
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Sequence


MAX_CAPTURE_CHARS = 32_768
MAX_RUN_CANDIDATES = 10
ARTIFACT_NAME = "omega-sqlite-catalog"
BUILDER_WORKFLOW = "catalog-builder.yml"
REQUIRED_ARTIFACT_FILES = ("omega-catalog.sqlite", "catalog.json")
REQUIRED_EVIDENCE_FILES = ("index.json", "validation-report.json")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _bounded(text: str) -> str:
    text = text or ""
    if len(text) <= MAX_CAPTURE_CHARS:
        return text
    omitted = len(text) - MAX_CAPTURE_CHARS
    return text[:MAX_CAPTURE_CHARS] + f"\n...[truncated {omitted} characters]"


@dataclass
class CommandRecord:
    argv: list[str]
    returnCode: int
    stdout: str
    stderr: str


class CommandRunner:
    def __init__(self) -> None:
        self.records: list[CommandRecord] = []

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(list(argv), text=True, capture_output=True, check=False)
        self.records.append(CommandRecord(
            argv=list(argv),
            returnCode=int(completed.returncode),
            stdout=_bounded(completed.stdout),
            stderr=_bounded(completed.stderr),
        ))
        return completed


class HandoffError(RuntimeError):
    pass


def _parse_run_id(value: str | None) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    if not value.isdigit():
        raise HandoffError(f"Invalid upstream workflow run id: {value!r}")
    parsed = int(value)
    if parsed <= 0:
        raise HandoffError(f"Invalid upstream workflow run id: {value!r}")
    return parsed


def _latest_successful_builder_runs(runner: CommandRunner, repository: str) -> list[dict[str, Any]]:
    completed = runner.run([
        "gh", "run", "list",
        "--repo", repository,
        "--workflow", BUILDER_WORKFLOW,
        "--status", "success",
        "--limit", str(MAX_RUN_CANDIDATES),
        "--json", "databaseId,createdAt,headSha,event,status,conclusion",
    ])
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        suffix = f" GitHub CLI: {_bounded(detail)[:800]}" if detail else ""
        raise HandoffError("Could not list successful Omega SQLite catalog builder runs." + suffix)
    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise HandoffError(f"GitHub CLI returned invalid catalog-builder run JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise HandoffError("GitHub CLI returned an unexpected catalog-builder run list.")
    return [item for item in payload if isinstance(item, dict)]


def _artifact_files_ok(directory: Path) -> tuple[bool, list[str]]:
    missing = [name for name in REQUIRED_ARTIFACT_FILES if not (directory / name).is_file()]
    return not missing, missing


def _download_run_artifact(
    runner: CommandRunner,
    repository: str,
    run_id: int,
    destination: Path,
) -> tuple[bool, str]:
    staging = destination.parent / f".{destination.name}-run-{run_id}"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    completed = runner.run([
        "gh", "run", "download", str(run_id),
        "--repo", repository,
        "--name", ARTIFACT_NAME,
        "--dir", str(staging),
    ])
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        shutil.rmtree(staging, ignore_errors=True)
        suffix = f": {_bounded(detail)[:800]}" if detail else ""
        return False, f"artifact download failed for run {run_id}{suffix}"
    ok, missing = _artifact_files_ok(staging)
    if not ok:
        shutil.rmtree(staging, ignore_errors=True)
        return False, f"run {run_id} artifact is missing: {', '.join(missing)}"

    shutil.rmtree(destination, ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging.replace(destination)
    return True, ""


def _download_previous_marketplace_descriptor(
    runner: CommandRunner,
    repository: str,
    destination: Path,
) -> bool:
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / "catalog.json"
    target.unlink(missing_ok=True)
    completed = runner.run([
        "gh", "release", "download", "catalog-latest",
        "--repo", repository,
        "--pattern", "catalog.json",
        "--dir", str(destination),
        "--clobber",
    ])
    return completed.returncode == 0 and target.is_file()


def _files_snapshot(*roots: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            items.append({"path": str(root), "bytes": root.stat().st_size})
            continue
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            try:
                rel = path.relative_to(root)
                display = f"{root.name}/{rel.as_posix()}"
            except ValueError:
                display = str(path)
            items.append({"path": display, "bytes": path.stat().st_size})
    return items[:200]


def resolve_handoff(
    *,
    event_name: str,
    repository: str,
    upstream_run_id: str | None,
    output_dir: Path,
    previous_marketplace_dir: Path,
    current_evidence_dir: Path,
    diagnostics_path: Path,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    runner = runner or CommandRunner()
    diagnostics: dict[str, Any] = {
        "schema": "omega.sigmascope.handoff-diagnostics.v1",
        "generatedAtUtc": utc_now(),
        "eventName": event_name,
        "repository": repository,
        "requestedUpstreamRunId": (upstream_run_id or "").strip(),
        "artifactName": ARTIFACT_NAME,
        "builderWorkflow": BUILDER_WORKFLOW,
        "selectedCatalogRunId": None,
        "selectedCatalogHeadSha": "",
        "selectedCatalogEvent": "",
        "sourceMode": "",
        "previousMarketplaceDescriptorAvailable": False,
        "success": False,
        "error": "",
        "commands": [],
        "files": [],
    }

    diagnostics_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if not repository or "/" not in repository:
            raise HandoffError("GitHub repository must be supplied as owner/name.")

        requested_id = _parse_run_id(upstream_run_id)
        diagnostics["previousMarketplaceDescriptorAvailable"] = _download_previous_marketplace_descriptor(
            runner, repository, previous_marketplace_dir
        )

        candidates: list[tuple[int, str, dict[str, Any]]] = []
        if event_name == "workflow_run" and requested_id is not None:
            candidates.append((requested_id, "triggering-builder-run", {}))

        latest_runs = _latest_successful_builder_runs(runner, repository)
        for item in latest_runs:
            try:
                run_id = int(item.get("databaseId") or 0)
            except (TypeError, ValueError):
                continue
            if run_id <= 0 or any(existing[0] == run_id for existing in candidates):
                continue
            candidates.append((run_id, "latest-successful-builder-run", item))

        if not candidates:
            raise HandoffError("No successful Omega SQLite catalog builder run is available for Sigmascope.")

        failures: list[str] = []
        for run_id, mode, metadata in candidates[:MAX_RUN_CANDIDATES]:
            ok, reason = _download_run_artifact(runner, repository, run_id, output_dir)
            if not ok:
                failures.append(reason)
                continue
            diagnostics["selectedCatalogRunId"] = run_id
            diagnostics["sourceMode"] = mode
            diagnostics["selectedCatalogHeadSha"] = str(metadata.get("headSha") or "")
            diagnostics["selectedCatalogEvent"] = str(metadata.get("event") or "")
            break

        if diagnostics["selectedCatalogRunId"] is None:
            raise HandoffError(
                "Could not download a valid omega-sqlite-catalog artifact from any candidate builder run. "
                + "; ".join(failures[:MAX_RUN_CANDIDATES])
            )

        ok, missing = _artifact_files_ok(output_dir)
        if not ok:
            raise HandoffError("Resolved catalog artifact is missing required files: " + ", ".join(missing))

        missing_evidence = [name for name in REQUIRED_EVIDENCE_FILES if not (current_evidence_dir / name).is_file()]
        if missing_evidence:
            raise HandoffError("Checked-out Security Evidence v2 snapshot is missing: " + ", ".join(missing_evidence))

        diagnostics["success"] = True
        return diagnostics
    except Exception as exc:
        diagnostics["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        diagnostics["generatedAtUtc"] = utc_now()
        diagnostics["commands"] = [asdict(record) for record in runner.records]
        diagnostics["files"] = _files_snapshot(output_dir, previous_marketplace_dir, current_evidence_dir)
        diagnostics_path.write_text(json.dumps(diagnostics, indent=2) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--upstream-run-id", default="")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--previous-marketplace-dir", type=Path, required=True)
    parser.add_argument("--current-evidence-dir", type=Path, required=True)
    parser.add_argument("--diagnostics", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = resolve_handoff(
            event_name=args.event_name,
            repository=args.repository,
            upstream_run_id=args.upstream_run_id,
            output_dir=args.output_dir,
            previous_marketplace_dir=args.previous_marketplace_dir,
            current_evidence_dir=args.current_evidence_dir,
            diagnostics_path=args.diagnostics,
        )
    except Exception as exc:
        print(f"Sigmascope catalog handoff failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"Handoff diagnostics: {args.diagnostics}", file=sys.stderr)
        return 1

    print(
        "Sigmascope catalog handoff ready: "
        f"run={result['selectedCatalogRunId']} mode={result['sourceMode']} "
        f"previousMarketplaceDescriptor={result['previousMarketplaceDescriptorAvailable']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
