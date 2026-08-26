#!/usr/bin/env python3
"""Authorize and re-check Phase-4C one-writer parallel Evidence publication.

This module is the bridge between the read-only Phase-4B preflight and the tiny writer
job.  It does not push Git refs or publish side effects.  Authorization is granted only
when the original shadow reports still hash to the values frozen into the preflight, the
reconstructed candidate has the exact preflight index digest, and the current Evidence
Git head is the exact base head observed by the shadow run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

PREFLIGHT_SCHEMA = "omega.sigmascope-parallel-preflight.v1"
AUTH_SCHEMA = "omega.sigmascope-parallel-publication-authorization.v1"
AUTHORITY = "serialized-one-writer-evidence-publication"
STATE_SCHEMA = "omega.sigmascope-parallel-publication-state.v1"


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def exact_git_sha(value: str, *, label: str) -> str:
    value = str(value or "").strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{label} must be an exact 40-character Git SHA-1")
    return value


def _verify_revision(document: dict[str, Any], key: str, prefix: str) -> None:
    actual = str(document.get(key) or "")
    semantic = {k: v for k, v in document.items() if k != key}
    expected = f"{prefix}{digest(semantic)[:20]}"
    if actual != expected:
        raise ValueError(f"{key} mismatch: expected {expected}, observed {actual or '<missing>'}")


def verify_preflight(preflight: dict[str, Any]) -> None:
    if preflight.get("schema") != PREFLIGHT_SCHEMA:
        raise ValueError(f"unsupported preflight schema: {preflight.get('schema')!r}")
    if preflight.get("authority") != "preflight-only-no-evidence-publication":
        raise ValueError("preflight authority boundary is invalid")
    if preflight.get("publishable") is not True:
        raise ValueError("preflight is not publishable")
    gates = preflight.get("gates") or []
    if not gates or any(not bool(gate.get("passed")) for gate in gates if isinstance(gate, dict)):
        raise ValueError("not every Phase-4B preflight gate passed")
    _verify_revision(preflight, "preflightRevision", "sigmascope-parallel-preflight-v1-")
    exact_git_sha(str(preflight.get("baseEvidenceGitHead") or ""), label="baseEvidenceGitHead")


def verify_authorization(authorization: dict[str, Any]) -> None:
    if authorization.get("schema") != AUTH_SCHEMA:
        raise ValueError(f"unsupported authorization schema: {authorization.get('schema')!r}")
    if authorization.get("authority") != AUTHORITY or authorization.get("authorized") is not True:
        raise ValueError("publication authorization is not active")
    exact_git_sha(str(authorization.get("expectedParentHead") or ""), label="expectedParentHead")
    _verify_revision(authorization, "authorizationRevision", "sigmascope-parallel-publish-v1-")


def _verify_report_hashes(preflight: dict[str, Any], reports: dict[str, Path]) -> None:
    expected = preflight.get("inputReports") or {}
    for key, path in reports.items():
        row = expected.get(key) if isinstance(expected, dict) else None
        if not isinstance(row, dict):
            raise ValueError(f"preflight does not bind input report {key!r}")
        observed = sha256_file(path)
        if observed != str(row.get("sha256") or ""):
            raise ValueError(f"shadow report hash mismatch for {key}: expected {row.get('sha256')}, observed {observed}")


def authorize(
    *,
    preflight_path: Path,
    shadow_reports: dict[str, Path],
    current_evidence: Path,
    current_evidence_git_head: str,
    candidate: Path,
    reconstructed_merge_report: Path,
    deep_scan_index: Path,
    source_followups: Path,
    output: Path,
) -> dict[str, Any]:
    preflight = read_json(preflight_path)
    verify_preflight(preflight)
    _verify_report_hashes(preflight, shadow_reports)

    base_head = exact_git_sha(str(preflight.get("baseEvidenceGitHead") or ""), label="baseEvidenceGitHead")
    current_head = exact_git_sha(current_evidence_git_head, label="current Evidence Git head")
    if current_head != base_head:
        raise ValueError(f"stale Evidence Git base: shadow={base_head}, current={current_head}")

    current_index = sha256_file(current_evidence / "index.json")
    if current_index != str(preflight.get("baseIndexSha256") or ""):
        raise ValueError("current Evidence index does not match the exact Phase-4B base index")
    candidate_index = sha256_file(candidate / "index.json")
    if candidate_index != str(preflight.get("candidateIndexSha256") or ""):
        raise ValueError("reconstructed candidate index does not match the Phase-4B preflight")

    reconstructed = read_json(reconstructed_merge_report)
    if reconstructed.get("authority") != "candidate-only-no-evidence-publication":
        raise ValueError("reconstructed merger has an invalid authority boundary")
    if str(reconstructed.get("baseIndexSha256") or "") != current_index:
        raise ValueError("reconstructed merger did not start from the authorized Evidence base")
    if str(reconstructed.get("candidateIndexSha256") or "") != candidate_index:
        raise ValueError("reconstructed merge report does not describe the authorized candidate")
    if sorted(reconstructed.get("bundleRevisions") or []) != sorted(preflight.get("bundleRevisions") or []):
        raise ValueError("reconstructed bundle revision set differs from Phase-4B preflight")
    if sorted(int(v) for v in (reconstructed.get("variantIds") or [])) != sorted(int(v) for v in (preflight.get("variantIds") or [])):
        raise ValueError("reconstructed variant set differs from Phase-4B preflight")

    validation = read_json(candidate / "validation-report.json")
    if validation.get("ok") is not True:
        raise ValueError("reconstructed candidate intrinsic validation did not pass")

    side_effects = {
        "deepScan": {"path": deep_scan_index.name, "sha256": sha256_file(deep_scan_index)},
        "sourceFollowups": {"path": source_followups.name, "sha256": sha256_file(source_followups)},
    }
    document: dict[str, Any] = {
        "schema": AUTH_SCHEMA,
        "authority": AUTHORITY,
        "authorized": True,
        "preflightRevision": str(preflight.get("preflightRevision") or ""),
        "sourceRun": dict(preflight.get("sourceRun") or {}),
        "expectedParentHead": base_head,
        "baseIndexSha256": current_index,
        "candidateIndexSha256": candidate_index,
        "mergeRevision": str(reconstructed.get("mergeRevision") or ""),
        "bundleRevisions": sorted(str(v) for v in (reconstructed.get("bundleRevisions") or [])),
        "variantIds": sorted(int(v) for v in (reconstructed.get("variantIds") or [])),
        "sideEffects": side_effects,
        "publicationOrder": ["security-evidence-v2", "deep-scan-state", "source-followup-issues"],
    }
    document["authorizationRevision"] = f"sigmascope-parallel-publish-v1-{digest(document)[:20]}"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return document


def check_current(
    *, authorization_path: Path, candidate: Path, current_evidence: Path,
    current_head: str, current_parent: str, output: Path,
    deep_scan_index: Path | None = None, source_followups: Path | None = None,
) -> dict[str, Any]:
    authorization = read_json(authorization_path)
    verify_authorization(authorization)
    expected_parent = exact_git_sha(str(authorization.get("expectedParentHead") or ""), label="expectedParentHead")
    current_head = exact_git_sha(current_head, label="current head")
    current_parent = str(current_parent or "").strip().lower()
    candidate_index = sha256_file(candidate / "index.json")
    if candidate_index != str(authorization.get("candidateIndexSha256") or ""):
        raise ValueError("candidate no longer matches publication authorization")
    current_index = sha256_file(current_evidence / "index.json")
    side_effects = authorization.get("sideEffects") or {}
    if deep_scan_index is not None:
        expected = ((side_effects.get("deepScan") or {}) if isinstance(side_effects, dict) else {}).get("sha256")
        if sha256_file(deep_scan_index) != str(expected or ""):
            raise ValueError("Deep Scan side-effect payload no longer matches publication authorization")
    if source_followups is not None:
        expected = ((side_effects.get("sourceFollowups") or {}) if isinstance(side_effects, dict) else {}).get("sha256")
        if sha256_file(source_followups) != str(expected or ""):
            raise ValueError("source-followup payload no longer matches publication authorization")

    if current_head == expected_parent:
        if current_index != str(authorization.get("baseIndexSha256") or ""):
            raise ValueError("current Evidence tree changed without the Git head changing")
        state = "ready-to-publish"
    elif current_index == candidate_index and current_parent == expected_parent:
        state = "already-published-immediate-child"
    else:
        raise ValueError(
            f"authorized publication is stale: expected parent {expected_parent}, current head {current_head}, current parent {current_parent or '<none>'}"
        )

    document = {
        "schema": STATE_SCHEMA,
        "authorizationRevision": str(authorization.get("authorizationRevision") or ""),
        "state": state,
        "expectedParentHead": expected_parent,
        "currentHead": current_head,
        "currentParent": current_parent,
        "candidateIndexSha256": candidate_index,
        "currentIndexSha256": current_index,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return document


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    auth = sub.add_parser("authorize")
    auth.add_argument("--preflight", required=True, type=Path)
    auth.add_argument("--shadow-merge", required=True, type=Path)
    auth.add_argument("--shadow-equivalence", required=True, type=Path)
    auth.add_argument("--shadow-candidate-validation", required=True, type=Path)
    auth.add_argument("--shadow-developer-audit", required=True, type=Path)
    auth.add_argument("--shadow-storage-audit", required=True, type=Path)
    auth.add_argument("--current-evidence", required=True, type=Path)
    auth.add_argument("--current-evidence-git-head", required=True)
    auth.add_argument("--candidate", required=True, type=Path)
    auth.add_argument("--reconstructed-merge", required=True, type=Path)
    auth.add_argument("--deep-scan-index", required=True, type=Path)
    auth.add_argument("--source-followups", required=True, type=Path)
    auth.add_argument("--output", required=True, type=Path)

    current = sub.add_parser("check-current")
    current.add_argument("--authorization", required=True, type=Path)
    current.add_argument("--candidate", required=True, type=Path)
    current.add_argument("--current-evidence", required=True, type=Path)
    current.add_argument("--current-head", required=True)
    current.add_argument("--current-parent", default="")
    current.add_argument("--deep-scan-index", type=Path)
    current.add_argument("--source-followups", type=Path)
    current.add_argument("--output", required=True, type=Path)

    args = ap.parse_args()
    if args.command == "authorize":
        result = authorize(
            preflight_path=args.preflight,
            shadow_reports={
                "merge": args.shadow_merge,
                "equivalence": args.shadow_equivalence,
                "candidateValidation": args.shadow_candidate_validation,
                "developerAudit": args.shadow_developer_audit,
                "storageAudit": args.shadow_storage_audit,
            },
            current_evidence=args.current_evidence,
            current_evidence_git_head=args.current_evidence_git_head,
            candidate=args.candidate,
            reconstructed_merge_report=args.reconstructed_merge,
            deep_scan_index=args.deep_scan_index,
            source_followups=args.source_followups,
            output=args.output,
        )
    else:
        result = check_current(
            authorization_path=args.authorization,
            candidate=args.candidate,
            current_evidence=args.current_evidence,
            current_head=args.current_head,
            current_parent=args.current_parent,
            output=args.output,
            deep_scan_index=args.deep_scan_index,
            source_followups=args.source_followups,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
