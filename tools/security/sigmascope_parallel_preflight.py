#!/usr/bin/env python3
"""Assemble the Phase-4B shadow publication-readiness gate without publishing Evidence.

The preflight consumes only already-produced validation artifacts.  It cannot create or
publish Security Evidence v2.  A passing report means the serialized parallel candidate
has passed intrinsic Evidence validation, semantic equivalence against a serialized
reference, independent developer audit, and storage-accounting checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "omega.sigmascope-parallel-preflight.v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def build(*, merge_report: Path, equivalence_report: Path, candidate_validation: Path,
          developer_audit: Path, storage_audit: Path, base_evidence_git_head: str,
          source_run_id: str = "", source_run_attempt: str = "", output: Path) -> dict[str, Any]:
    merge = _read(merge_report)
    equivalence = _read(equivalence_report)
    validation = _read(candidate_validation)
    audit = _read(developer_audit)
    storage = _read(storage_audit)
    base_evidence_git_head = str(base_evidence_git_head or "").strip().lower()
    if len(base_evidence_git_head) != 40 or any(ch not in "0123456789abcdef" for ch in base_evidence_git_head):
        raise ValueError("base Evidence Git head must be an exact 40-character SHA-1")

    gates = [
        {
            "id": "merger.authority",
            "passed": str(merge.get("authority") or "") == "candidate-only-no-evidence-publication",
            "detail": str(merge.get("authority") or ""),
        },
        {
            "id": "candidate.validation",
            "passed": bool(validation.get("ok")) and bool((merge.get("validation") or {}).get("ok")),
            "detail": f"errors={len(validation.get('errors') or [])}",
        },
        {
            "id": "serialized.equivalence",
            "passed": bool(equivalence.get("equivalent")) and not (equivalence.get("mismatches") or []),
            "detail": f"mismatches={len(equivalence.get('mismatches') or [])}",
        },
        {
            "id": "developer.audit",
            "passed": int((audit.get("counts") or {}).get("fail") or 0) == 0,
            "detail": f"fail={int((audit.get('counts') or {}).get('fail') or 0)},warn={int((audit.get('counts') or {}).get('warn') or 0)}",
        },
        {
            "id": "storage.audit",
            "passed": str(storage.get("schema") or "") == "omega.security-evidence.storage-audit.v1" and int(storage.get("files") or 0) > 0,
            "detail": f"files={int(storage.get('files') or 0)},bytes={int(storage.get('bytes') or 0)}",
        },
    ]
    passed = all(bool(gate["passed"]) for gate in gates)
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "authority": "preflight-only-no-evidence-publication",
        "publishable": passed,
        "mergeRevision": str(merge.get("mergeRevision") or ""),
        "equivalenceRevision": str(equivalence.get("equivalenceRevision") or ""),
        "baseIndexSha256": str(merge.get("baseIndexSha256") or ""),
        "baseEvidenceGitHead": base_evidence_git_head,
        "candidateIndexSha256": str(merge.get("candidateIndexSha256") or ""),
        "sourceRun": {"id": str(source_run_id or ""), "attempt": str(source_run_attempt or "")},
        "inputReports": {
            "merge": {"sha256": _file_sha256(merge_report), "schema": str(merge.get("schema") or "")},
            "equivalence": {"sha256": _file_sha256(equivalence_report), "schema": str(equivalence.get("schema") or "")},
            "candidateValidation": {"sha256": _file_sha256(candidate_validation), "schema": str(validation.get("schema") or "")},
            "developerAudit": {"sha256": _file_sha256(developer_audit), "schema": str(audit.get("schema") or "")},
            "storageAudit": {"sha256": _file_sha256(storage_audit), "schema": str(storage.get("schema") or "")},
        },
        "bundleRevisions": list(merge.get("bundleRevisions") or []),
        "variantIds": list(merge.get("variantIds") or []),
        "gates": gates,
        "deferredSideEffects": list(merge.get("deferredSideEffects") or []),
    }
    document["preflightRevision"] = f"sigmascope-parallel-preflight-v1-{_digest(document)[:20]}"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return document


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--merge-report", required=True, type=Path)
    ap.add_argument("--equivalence-report", required=True, type=Path)
    ap.add_argument("--candidate-validation", required=True, type=Path)
    ap.add_argument("--developer-audit", required=True, type=Path)
    ap.add_argument("--storage-audit", required=True, type=Path)
    ap.add_argument("--base-evidence-git-head", required=True)
    ap.add_argument("--source-run-id", default="")
    ap.add_argument("--source-run-attempt", default="")
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    result = build(
        merge_report=args.merge_report, equivalence_report=args.equivalence_report,
        candidate_validation=args.candidate_validation, developer_audit=args.developer_audit,
        storage_audit=args.storage_audit, base_evidence_git_head=args.base_evidence_git_head,
        source_run_id=args.source_run_id, source_run_attempt=args.source_run_attempt, output=args.output,
    )
    print(json.dumps({"publishable": result["publishable"], "preflightRevision": result["preflightRevision"]}, sort_keys=True))
    return 0 if result["publishable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
