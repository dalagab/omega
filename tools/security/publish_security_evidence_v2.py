#!/usr/bin/env python3
"""Publish a validated Omega security-evidence v2 tree to a dedicated Git branch.

The publisher is intentionally local/operator driven. It never touches the source
working tree: a temporary Git repository is created, the evidence snapshot is copied
into it, and an orphan snapshot commit is force-with-lease pushed to the target branch.
This keeps evidence history from growing without bound while preserving atomicity:
index.json already references only files in the same validated snapshot.

By default this command performs preflight only. Pass --push to modify the remote.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from security_evidence_v2 import MAX_PUBLISH_FILE_BYTES, SCHEMA, sha256_file  # noqa: E402

EXCLUDED_NAMES = {".omega-security-evidence-v2-migration.json"}


def run(cmd: list[str], *, cwd: Path | None = None, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=capture,
        check=check,
    )


def git_root(path: Path) -> Path:
    result = run(["git", "rev-parse", "--show-toplevel"], cwd=path, capture=True)
    return Path(result.stdout.strip()).resolve()


def remote_url(repo: Path, remote: str) -> str:
    result = run(["git", "remote", "get-url", remote], cwd=repo, capture=True)
    url = result.stdout.strip()
    if not url:
        raise RuntimeError(f"Git remote {remote!r} has no URL")
    return url


def remote_branch_sha(repo: Path, remote: str, branch: str) -> str:
    result = run(["git", "ls-remote", "--heads", remote, f"refs/heads/{branch}"], cwd=repo, capture=True)
    line = result.stdout.strip()
    return line.split()[0] if line else ""


def validate_report(evidence: Path, report_path: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema") != "omega.security-evidence.validation.v2":
        raise RuntimeError(f"unsupported validation report: {report.get('schema')!r}")
    if report.get("ok") is not True:
        raise RuntimeError("validation report is not successful")
    if report.get("mode") != "full":
        raise RuntimeError("publication requires a full parity validation report; quick mode is not sufficient")
    actual_index = sha256_file(evidence / "index.json")
    if str(report.get("indexSha256") or "") != actual_index:
        raise RuntimeError("validation report does not match the current index.json SHA-256")
    return report




def validate_snapshot_report(evidence: Path, report_path: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema") != "omega.security-evidence.snapshot-validation.v2":
        raise RuntimeError(f"unsupported snapshot validation report: {report.get('schema')!r}")
    if report.get("ok") is not True:
        raise RuntimeError("snapshot validation report is not successful")
    actual_index = sha256_file(evidence / "index.json")
    if str(report.get("indexSha256") or "") != actual_index:
        raise RuntimeError("snapshot validation report does not match the current index.json SHA-256")
    return report


def validate_audit_report(report_path: Path, *, strict_warnings: bool = False) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    counts = report.get("counts") or {}
    if int(counts.get("fail") or 0) > 0:
        raise RuntimeError(f"developer audit has {counts.get('fail')} failing checks")
    if strict_warnings and int(counts.get("warn") or 0) > 0:
        raise RuntimeError(f"developer audit has {counts.get('warn')} warnings under strict publication mode")
    return report

def preflight(evidence: Path) -> dict[str, Any]:
    evidence = evidence.resolve()
    index_path = evidence / "index.json"
    if not index_path.is_file():
        raise RuntimeError("index.json is missing; migrate and validate the evidence before publishing")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index.get("schema") != SCHEMA:
        raise RuntimeError(f"unsupported evidence schema: {index.get('schema')!r}")
    files = []
    total = 0
    for path in sorted(evidence.rglob("*")):
        if not path.is_file() or path.name in EXCLUDED_NAMES:
            continue
        rel = path.relative_to(evidence).as_posix()
        if rel.startswith(".staging/"):
            continue
        size = path.stat().st_size
        if size > MAX_PUBLISH_FILE_BYTES:
            raise RuntimeError(
                f"{rel} is {size:,} bytes; v2 branch files must stay <= {MAX_PUBLISH_FILE_BYTES:,} bytes"
            )
        files.append({"path": rel, "bytes": size, "sha256": sha256_file(path)})
        total += size
    if not files:
        raise RuntimeError("evidence tree is empty")
    if files[-1]["path"] == "index.json":
        pass
    return {
        "schema": index.get("schema"),
        "evidenceRevision": (index.get("revisions") or {}).get("evidenceRevision", ""),
        "files": len(files),
        "bytes": total,
        "indexSha256": sha256_file(index_path),
    }


def copy_snapshot(evidence: Path, target: Path) -> None:
    for path in evidence.rglob("*"):
        if not path.is_file() or path.name in EXCLUDED_NAMES:
            continue
        rel = path.relative_to(evidence)
        if rel.parts and rel.parts[0] == ".staging":
            continue
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)


def publish(
    evidence: Path,
    *,
    repo: Path,
    remote: str,
    branch: str,
    push: bool,
    validation_report: Path | None = None,
    snapshot_validation_report: Path | None = None,
    audit_report: Path | None = None,
    strict_audit_warnings: bool = False,
    commit_message: str | None = None,
) -> dict[str, Any]:
    info = preflight(evidence)
    if validation_report is not None and snapshot_validation_report is not None:
        raise RuntimeError("choose either --validation-report or --snapshot-validation-report, not both")
    if validation_report is not None:
        report = validate_report(evidence.resolve(), validation_report.resolve())
        info["validation"] = {"ok": True, "mode": report.get("mode"), "checkedVariants": report.get("checkedVariants")}
    elif snapshot_validation_report is not None:
        report = validate_snapshot_report(evidence.resolve(), snapshot_validation_report.resolve())
        info["validation"] = {"ok": True, "mode": report.get("mode"), "checkedVariants": report.get("checkedVariants")}
    elif push:
        raise RuntimeError("--push requires a successful full migration parity report or production snapshot validation report")
    if audit_report is not None:
        audit = validate_audit_report(audit_report.resolve(), strict_warnings=strict_audit_warnings)
        counts = audit.get("counts") or {}
        info["audit"] = {"fail": int(counts.get("fail") or 0), "warn": int(counts.get("warn") or 0)}
    elif push and snapshot_validation_report is not None:
        raise RuntimeError("incremental production --push requires --audit-report")
    repo = git_root(repo.resolve())
    url = remote_url(repo, remote)
    old_sha = remote_branch_sha(repo, remote, branch)
    info.update({"repository": str(repo), "remote": remote, "remoteUrl": url, "branch": branch, "previousHead": old_sha})
    if not push:
        info["pushed"] = False
        return info

    with tempfile.TemporaryDirectory(prefix="omega-security-evidence-v2-publish-") as temp_name:
        work = Path(temp_name)
        run(["git", "init", "-q"], cwd=work)
        run(["git", "checkout", "--orphan", branch], cwd=work)
        run(["git", "config", "user.name", "Omega Evidence Publisher"], cwd=work)
        run(["git", "config", "user.email", "omega-evidence@users.noreply.github.com"], cwd=work)
        run(["git", "config", "core.autocrlf", "false"], cwd=work)
        run(["git", "remote", "add", remote, url], cwd=work)
        copy_snapshot(evidence.resolve(), work)
        run(["git", "add", "--all"], cwd=work)
        message = commit_message or f"Security evidence v2 snapshot {info['evidenceRevision'] or info['indexSha256'][:12]}"
        run(["git", "commit", "-q", "-m", message], cwd=work)
        new_sha = run(["git", "rev-parse", "HEAD"], cwd=work, capture=True).stdout.strip()
        refspec = f"HEAD:refs/heads/{branch}"
        if old_sha:
            run(["git", "push", f"--force-with-lease=refs/heads/{branch}:{old_sha}", remote, refspec], cwd=work)
        else:
            run(["git", "push", remote, refspec], cwd=work)
        info.update({"pushed": True, "newHead": new_sha})
        return info


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish Omega security-evidence v2 to a dedicated snapshot branch")
    parser.add_argument("--input", required=True, type=Path, help="Validated security-evidence-v2 directory")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Omega source Git working tree (default: cwd)")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--branch", default="security-evidence-v2")
    parser.add_argument("--push", action="store_true", help="Actually push; without this flag only preflight is performed")
    parser.add_argument("--validation-report", type=Path, help="Successful full v1↔v2 parity report (one-time migration publication)")
    parser.add_argument("--snapshot-validation-report", type=Path, help="Successful intrinsic v2 snapshot validation report (incremental production publication)")
    parser.add_argument("--audit-report", type=Path, help="Successful independent developer audit report; required for incremental production --push")
    parser.add_argument("--strict-audit-warnings", action="store_true", help="Treat developer-audit warnings as publication failures")
    parser.add_argument("--message", help="Commit message override")
    args = parser.parse_args()
    info = publish(
        args.input,
        repo=args.repo,
        remote=args.remote,
        branch=args.branch,
        push=args.push,
        validation_report=args.validation_report,
        snapshot_validation_report=args.snapshot_validation_report,
        audit_report=args.audit_report,
        strict_audit_warnings=args.strict_audit_warnings,
        commit_message=args.message,
    )
    print(json.dumps(info, indent=2, ensure_ascii=False))
    if not args.push:
        print("Preflight only. Re-run with --push after the applicable validation and audit gates pass.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
