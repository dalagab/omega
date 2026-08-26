#!/usr/bin/env python3
"""Publish a validated Omega security-evidence v2 tree to a dedicated Git branch.

The publisher is intentionally local/operator driven. It never touches the source
working tree: publication is prepared in a temporary Git repository. Authoritative
publication defaults to a controlled fast-forward history: the exact current remote head
is fetched and becomes the parent of the next accepted Evidence snapshot. A concurrent
remote advance therefore fails closed instead of rewriting history.

The former orphan/force-with-lease publisher remains available only as an explicit
``--history-mode legacy-orphan`` emergency fallback. By default this command performs
preflight only. Pass --push to modify the remote.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from security_evidence_v2 import MAX_PUBLISH_FILE_BYTES, SCHEMA, sha256_file  # noqa: E402

ORCHESTRATION_DIR = SCRIPT_DIR.parent / "orchestration"
if str(ORCHESTRATION_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATION_DIR))
from git_snapshot_history import HISTORY_FAST_FORWARD, HISTORY_MODES, publish_snapshot_tree  # noqa: E402
from sigmascope_parallel_publish_gate import read_json as read_parallel_authorization, verify_authorization as verify_parallel_authorization  # noqa: E402

EXCLUDED_NAMES = {".omega-security-evidence-v2-migration.json"}


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



def validate_parallel_authorization(
    evidence: Path, report_path: Path, *, expected_parent_sha: str | None
) -> dict[str, Any]:
    authorization = read_parallel_authorization(report_path.resolve())
    verify_parallel_authorization(authorization)
    if sha256_file(evidence.resolve() / "index.json") != str(authorization.get("candidateIndexSha256") or ""):
        raise RuntimeError("parallel publication authorization does not match candidate index.json")
    bound_parent = str(authorization.get("expectedParentHead") or "")
    if not expected_parent_sha:
        raise RuntimeError("parallel publication authorization requires --expected-parent-sha")
    if str(expected_parent_sha).lower() != bound_parent.lower():
        raise RuntimeError("--expected-parent-sha differs from the parallel publication authorization")
    return authorization

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
    history_mode: str = HISTORY_FAST_FORWARD,
    expected_parent_sha: str | None = None,
    parallel_authorization_report: Path | None = None,
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
    if parallel_authorization_report is not None:
        authorization = validate_parallel_authorization(
            evidence.resolve(), parallel_authorization_report, expected_parent_sha=expected_parent_sha
        )
        info["parallelAuthorization"] = {
            "authorizationRevision": str(authorization.get("authorizationRevision") or ""),
            "preflightRevision": str(authorization.get("preflightRevision") or ""),
        }
    message = commit_message or f"Security evidence v2 snapshot {info['evidenceRevision'] or info['indexSha256'][:12]}"
    publication = publish_snapshot_tree(
        evidence.resolve(),
        repo=repo.resolve(),
        remote=remote,
        branch=branch,
        push=push,
        author_name="Omega Evidence Publisher",
        author_email="omega-evidence@users.noreply.github.com",
        commit_message=message,
        history_mode=history_mode,
        excluded_names=EXCLUDED_NAMES,
        excluded_prefixes=(".staging",),
        expected_previous_head=expected_parent_sha,
    )
    info.update(publication.as_dict())
    info.update({"repository": str(repo.resolve()), "remote": remote, "branch": branch})
    return info


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish Omega security-evidence v2 to a dedicated snapshot branch")
    parser.add_argument("--input", required=True, type=Path, help="Validated security-evidence-v2 directory")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Omega source Git working tree (default: cwd)")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--branch", default="security-evidence-v2")
    parser.add_argument("--history-mode", choices=HISTORY_MODES, default=HISTORY_FAST_FORWARD,
                        help="Authoritative publication history mode (default: controlled fast-forward)")
    parser.add_argument("--expected-parent-sha",
                        help="Require the current remote branch head to equal this exact Git SHA before publication")
    parser.add_argument("--parallel-authorization-report", type=Path,
                        help="Phase-4C one-writer authorization bound to this candidate and expected parent")
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
        history_mode=args.history_mode,
        expected_parent_sha=args.expected_parent_sha,
        parallel_authorization_report=args.parallel_authorization_report,
    )
    print(json.dumps(info, indent=2, ensure_ascii=False))
    if not args.push:
        print("Preflight only. Re-run with --push after the applicable validation and audit gates pass.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
