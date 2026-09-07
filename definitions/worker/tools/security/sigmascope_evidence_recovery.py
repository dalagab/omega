#!/usr/bin/env python3
"""Rebuild one full Security Evidence v2 candidate by retaining last-known-good payloads.

This is a one-shot forward-recovery tool for the sparse-authority regression.  It never
publishes Git refs.  The caller supplies the exact current authoritative Evidence tree,
a previously validated full retained snapshot from the same catalog identity epoch, the
current catalog database/Definitions, and the current immutable queue seed.

Recovery is current-wins: retained current payloads are used only where today's full
Evidence tree has no replacement.  When today's current variant replaces a retained
artifact, the normal production merge helper archives the retained descriptor before
overwrite.  Global indexes, SRL projections, security-system state, validation and queue
state are regenerated from the merged tree; the retained scanner queue is never reused.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
CATALOG_DIR = SCRIPT_DIR.parent / "catalog"
for path in (SCRIPT_DIR, CATALOG_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import scan_queue  # noqa: E402
import sigmascope_result_merger  # noqa: E402
from production_sigmascope_v2_pipeline import (  # noqa: E402
    _build_plugins_artifacts_indexes,
    _merge_successful_subset,
    materialize_current_state,
    materialize_definition_provenance_index,
    materialize_srl_reprojection_sidecar,
    materialize_threat_intelligence_index,
    rebuild_candidate_indexes,
    synchronize_candidate,
    write_json,
)
from security_evidence_v2 import SCHEMA, sha256_file, validate_snapshot  # noqa: E402

RECOVERY_SCHEMA = "omega.sigmascope-evidence-recovery.v1"
SPARSE_MARKER = ".sigmascope-sparse-evidence.json"
RETAINED_ROOTS = ("artifacts", "derived", "history", "terminal", "variants")
CURRENT_OVERLAY_ROOTS = ("derived", "history", "terminal")
SNAPSHOT_ROOTS = ("variants", "terminal/variants", "history/variants")


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _identity_epoch(index: dict[str, Any]) -> str:
    revisions = index.get("revisions") if isinstance(index.get("revisions"), dict) else {}
    return str(revisions.get("catalogIdentityEpoch") or "")


def _copy_tree(source: Path, target: Path) -> None:
    if not source.is_dir():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target, dirs_exist_ok=True)


def _snapshot_identity_keys(root: Path) -> set[tuple[int, str, str]]:
    """Return semantic snapshot identities independent of transport path/lifecycle state."""
    identities: set[tuple[int, str, str]] = set()
    for relative in SNAPSHOT_ROOTS:
        directory = root / relative
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.json")):
            payload = _read(path)
            analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
            current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
            identities.add((
                int(payload.get("variantId") or 0),
                str(analysis.get("analysisId") or ""),
                str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower(),
            ))
    return identities


def _bootstrap_payload_index(candidate: Path, current_index: dict[str, Any]) -> dict[str, int]:
    plugins, artifacts, current_count, terminal_count, history_count, analysis_count, artifact_count = (
        _build_plugins_artifacts_indexes(candidate)
    )
    bootstrap = {
        "schema": SCHEMA,
        "formatVersion": int(current_index.get("formatVersion") or 2),
        "migrationMode": "incremental-v2",
        "engine": dict(current_index.get("engine") or {}),
        "revisions": dict(current_index.get("revisions") or {}),
        "counts": {
            "currentVariants": current_count,
            "terminalVariants": terminal_count,
            "historicalSnapshots": history_count,
            "analyses": analysis_count,
            "artifactGroups": artifact_count,
        },
        "indexes": {"plugins": plugins, "artifacts": artifacts},
    }
    write_json(candidate / "index.json", bootstrap)
    return dict(bootstrap["counts"])


def stage_retained_union(current_evidence: Path, retained_evidence: Path, candidate: Path) -> dict[str, Any]:
    """Create a current-wins retained payload union without importing old global state."""
    current_evidence = current_evidence.resolve()
    retained_evidence = retained_evidence.resolve()
    candidate = candidate.resolve()
    current_index = _read(current_evidence / "index.json")

    if candidate.exists():
        shutil.rmtree(candidate)
    candidate.mkdir(parents=True, exist_ok=True)

    for root_name in RETAINED_ROOTS:
        _copy_tree(retained_evidence / root_name, candidate / root_name)

    # Merge today's active payloads through the production archival helper.  This is
    # intentionally not shutil.copytree: an artifact replacement must retain the old
    # current descriptor as a superseded history snapshot before overwrite.
    merged = _merge_successful_subset(candidate, current_evidence)
    for root_name in CURRENT_OVERLAY_ROOTS:
        _copy_tree(current_evidence / root_name, candidate / root_name)

    sparse_marker_removed = (current_evidence / SPARSE_MARKER).is_file() or (candidate / SPARSE_MARKER).is_file()
    (candidate / SPARSE_MARKER).unlink(missing_ok=True)
    bootstrap_counts = _bootstrap_payload_index(candidate, current_index)
    return {
        "bootstrapCounts": bootstrap_counts,
        "currentMerge": merged,
        "sparseAuthorityMarkerRemoved": sparse_marker_removed,
    }


def _validate_inputs(
    current_evidence: Path,
    retained_evidence: Path,
    definitions: Path,
    queue_seed_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    current_validation = validate_snapshot(current_evidence, require_no_orphans=False)
    retained_validation = validate_snapshot(retained_evidence, require_no_orphans=False)
    if current_validation.get("ok") is not True:
        raise RuntimeError("current authoritative Evidence is intrinsically invalid: " + "; ".join(current_validation.get("errors") or []))
    if retained_validation.get("ok") is not True:
        raise RuntimeError("retained full Evidence is intrinsically invalid: " + "; ".join(retained_validation.get("errors") or []))

    current_index = _read(current_evidence / "index.json")
    retained_index = _read(retained_evidence / "index.json")
    definitions_index = _read(definitions / "index.json")
    queue_seed = _read(queue_seed_path)
    if queue_seed.get("schema") != scan_queue.SEED_SCHEMA:
        raise RuntimeError("recovery requires the current immutable SigmaScope queue seed")

    current_epoch = _identity_epoch(current_index)
    retained_epoch = _identity_epoch(retained_index)
    seed_epoch = str(queue_seed.get("catalogIdentityEpoch") or "")
    if not current_epoch or current_epoch != retained_epoch or current_epoch != seed_epoch:
        raise RuntimeError(
            "Evidence recovery cannot cross catalog identity epochs: "
            f"current={current_epoch or '<missing>'} retained={retained_epoch or '<missing>'} seed={seed_epoch or '<missing>'}"
        )

    expected_identity = {
        "definitionsRevision": str(definitions_index.get("definitionsRevision") or ""),
        "scannerRevision": str(definitions_index.get("scannerRevision") or ""),
        "scannerBundleSha256": str((definitions_index.get("scannerBundle") or {}).get("sha256") or ""),
        "artifactAnalysisRevision": str(definitions_index.get("artifactAnalysisRevision") or ""),
        "sourceAnalysisRevision": str(definitions_index.get("sourceAnalysisRevision") or ""),
        "ruleSetRevision": str(definitions_index.get("ruleSetRevision") or ""),
        "advisoryRevision": str(definitions_index.get("advisoryRevision") or ""),
    }
    for key, expected in expected_identity.items():
        observed = str(queue_seed.get(key) or "")
        if expected and observed != expected:
            raise RuntimeError(f"queue seed {key} differs from current frozen Definitions: {observed!r} != {expected!r}")
    return current_index, retained_index, definitions_index, queue_seed


def recover(
    *,
    current_evidence: Path,
    retained_evidence: Path,
    base_database: Path,
    definitions: Path,
    queue_seed_path: Path,
    candidate: Path,
    work_dir: Path,
    report_path: Path,
) -> dict[str, Any]:
    current_evidence = current_evidence.resolve()
    retained_evidence = retained_evidence.resolve()
    base_database = base_database.resolve()
    definitions = definitions.resolve()
    queue_seed_path = queue_seed_path.resolve()
    candidate = candidate.resolve()
    work_dir = work_dir.resolve()
    report_path = report_path.resolve()

    current_index, retained_index, definitions_index, queue_seed = _validate_inputs(
        current_evidence, retained_evidence, definitions, queue_seed_path
    )
    work_dir.mkdir(parents=True, exist_ok=True)

    staged = stage_retained_union(current_evidence, retained_evidence, candidate)
    work_database = work_dir / "omega-security-evidence-recovery.sqlite"
    materialized = materialize_current_state(base_database, candidate, work_database, include_evidence=True)
    osv_coverage = sigmascope_result_merger._refresh_frozen_advisories(  # noqa: SLF001 - shared serialized authority primitive
        work_database, work_dir, definitions, definitions_index
    )
    synchronized = synchronize_candidate(candidate, work_database, set())

    scan_context = {
        "previousIndexSha256": sha256_file(current_evidence / "index.json"),
        "selected": 0,
        "successful": 0,
        "failedRetained": 0,
        "failedVariantIds": [],
        "maxScans": 0,
        "catalogDataRevision": str(queue_seed.get("catalogRevision") or ""),
        "catalogIdentityEpoch": str(queue_seed.get("catalogIdentityEpoch") or ""),
        "baselineSecurityRebuild": False,
        "definitionsRevision": str(definitions_index.get("definitionsRevision") or ""),
        "advisoryRevision": str(definitions_index.get("advisoryRevision") or ""),
        "scannerRevision": str(definitions_index.get("scannerRevision") or ""),
        "scannerBundleSha256": str((definitions_index.get("scannerBundle") or {}).get("sha256") or ""),
        "artifactAnalysisRevision": str(definitions_index.get("artifactAnalysisRevision") or ""),
        "sourceAnalysisRevision": str(definitions_index.get("sourceAnalysisRevision") or ""),
        "ruleSetRevision": str(definitions_index.get("ruleSetRevision") or ""),
        "queueSeedRevision": str(queue_seed.get("queueSeedRevision") or ""),
        "recovery": {
            "schema": RECOVERY_SCHEMA,
            "mode": "forward-retained-current-wins",
            "retainedEvidenceRevision": str((retained_index.get("revisions") or {}).get("evidenceRevision") or ""),
            "retainedIndexSha256": sha256_file(retained_evidence / "index.json"),
            "newScans": 0,
        },
    }
    provenance = materialize_definition_provenance_index(candidate, definitions)
    threat_intelligence = materialize_threat_intelligence_index(candidate, definitions)
    root_index = rebuild_candidate_indexes(
        candidate, work_database, current_index, scan_context, osv_coverage, provenance or None
    )
    if threat_intelligence:
        root_index.setdefault("indexes", {})["threatIntelligence"] = threat_intelligence
        root_index.setdefault("revisions", {})["reputationRevision"] = str(threat_intelligence.get("reputationRevision") or "")
        root_index.setdefault("source", {})["reputationRevision"] = str(threat_intelligence.get("reputationRevision") or "")
        write_json(candidate / "index.json", root_index)

    # Mutable queue authority comes only from the current head plus today's seed.  The
    # retained snapshot's queue is deliberately ignored even though its payloads are
    # used as last-known-good evidence.
    previous_queue = scan_queue.load_state(current_evidence / "scanner-queue.json")
    queue_state = scan_queue.sync_state(queue_seed, previous_queue)
    queue_path = candidate / "scanner-queue.json"
    scan_queue.write_json(queue_path, queue_state)
    root_index["scannerQueue"] = {
        "schema": scan_queue.STATE_SCHEMA,
        "path": "scanner-queue.json",
        "bytes": queue_path.stat().st_size,
        "sha256": sha256_file(queue_path),
        "summary": scan_queue.state_summary(queue_state),
    }
    write_json(candidate / "index.json", root_index)

    srl = materialize_srl_reprojection_sidecar(candidate, definitions)
    if srl.get("enabled"):
        root_index["srlRuleProjections"] = {key: value for key, value in srl.items() if key != "validation"}
        write_json(candidate / "index.json", root_index)

    (candidate / SPARSE_MARKER).unlink(missing_ok=True)
    validation = validate_snapshot(candidate, require_no_orphans=True)
    write_json(candidate / "validation-report.json", validation)
    if validation.get("ok") is not True:
        raise RuntimeError("recovered Evidence candidate failed full intrinsic validation: " + "; ".join(validation.get("errors") or []))

    current_counts = dict(current_index.get("counts") or {})
    retained_counts = dict(retained_index.get("counts") or {})
    candidate_counts = dict(root_index.get("counts") or {})
    current_snapshots = sum(int(current_counts.get(key) or 0) for key in ("currentVariants", "terminalVariants", "historicalSnapshots"))
    retained_snapshots = sum(int(retained_counts.get(key) or 0) for key in ("currentVariants", "terminalVariants", "historicalSnapshots"))
    candidate_snapshots = sum(int(candidate_counts.get(key) or 0) for key in ("currentVariants", "terminalVariants", "historicalSnapshots"))
    if candidate_snapshots < max(current_snapshots, retained_snapshots):
        raise RuntimeError("recovery reduced retained variant-snapshot coverage")
    if int(candidate_counts.get("analyses") or 0) < max(int(current_counts.get("analyses") or 0), int(retained_counts.get("analyses") or 0)):
        raise RuntimeError("recovery reduced immutable analysis coverage")

    retained_snapshot_identities = _snapshot_identity_keys(retained_evidence)
    candidate_snapshot_identities = _snapshot_identity_keys(candidate)
    missing_retained = retained_snapshot_identities - candidate_snapshot_identities
    if missing_retained:
        sample = sorted(missing_retained)[:10]
        raise RuntimeError(
            f"recovery lost {len(missing_retained)} retained snapshot identities; sample={sample!r}"
        )

    report: dict[str, Any] = {
        "schema": RECOVERY_SCHEMA,
        "authority": "candidate-only-no-evidence-publication",
        "mode": "forward-retained-current-wins",
        "catalogIdentityEpoch": _identity_epoch(current_index),
        "current": {
            "indexSha256": sha256_file(current_evidence / "index.json"),
            "evidenceRevision": str((current_index.get("revisions") or {}).get("evidenceRevision") or ""),
            "counts": current_counts,
        },
        "retained": {
            "indexSha256": sha256_file(retained_evidence / "index.json"),
            "evidenceRevision": str((retained_index.get("revisions") or {}).get("evidenceRevision") or ""),
            "counts": retained_counts,
        },
        "candidate": {
            "indexSha256": sha256_file(candidate / "index.json"),
            "evidenceRevision": str((root_index.get("revisions") or {}).get("evidenceRevision") or ""),
            "counts": candidate_counts,
            "path": str(candidate),
        },
        "staging": staged,
        "materialized": materialized,
        "synchronize": synchronized,
        "retention": {
            "retainedSnapshotIdentities": len(retained_snapshot_identities),
            "candidateSnapshotIdentities": len(candidate_snapshot_identities),
            "missingRetainedSnapshotIdentities": 0,
        },
        "queueSummary": scan_queue.state_summary(queue_state),
        "srlReprojection": {key: value for key, value in srl.items() if key != "validation"},
        "validation": {"ok": True, "indexSha256": validation.get("indexSha256")},
        "workDatabase": str(work_database),
        "deferredSideEffects": ["Evidence-v2-publication", "deep-scan-state-publication", "source-followup-issue-reconciliation"],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-evidence", required=True, type=Path)
    parser.add_argument("--retained-evidence", required=True, type=Path)
    parser.add_argument("--base-database", required=True, type=Path)
    parser.add_argument("--definitions-root", required=True, type=Path)
    parser.add_argument("--queue-seed", required=True, type=Path)
    parser.add_argument("--candidate-evidence", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    result = recover(
        current_evidence=args.current_evidence,
        retained_evidence=args.retained_evidence,
        base_database=args.base_database,
        definitions=args.definitions_root,
        queue_seed_path=args.queue_seed,
        candidate=args.candidate_evidence,
        work_dir=args.work_dir,
        report_path=args.report,
    )
    print(json.dumps({
        "schema": result["schema"],
        "authority": result["authority"],
        "currentCounts": result["current"]["counts"],
        "retainedCounts": result["retained"]["counts"],
        "candidateCounts": result["candidate"]["counts"],
        "candidateIndexSha256": result["candidate"]["indexSha256"],
    }, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
