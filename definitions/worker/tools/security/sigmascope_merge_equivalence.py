#!/usr/bin/env python3
"""Compare a parallel-merge Evidence-v2 candidate with serialized reference output.

This is a Phase-4B shadow cutover gate.  It intentionally compares security semantics,
not incidental execution identities such as scan row IDs, timestamps, queue attempt IDs,
or root snapshot hashes.  Both candidates must independently pass full intrinsic
Evidence-v2 validation before their affected variants, scanner queue, SRL projections,
Deep Scan requests, and source-followup projection are compared.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from security_evidence_v2 import validate_snapshot

SCHEMA = "omega.sigmascope-parallel-equivalence.v1"
MAX_MISMATCHES = 100
MAX_DIFFERENCE_PATHS = 64

_VOLATILE_KEYS = {
    "generatedAtUtc", "updatedAtUtc", "scannedAtUtc", "scanned_at_utc", "scan_id", "scanId",
    "currentScanId", "current_scan_id", "comparison_id", "comparisonId",
    "selectedAtUtc", "startedAtUtc", "completedAtUtc", "lastAttemptAtUtc", "requestedAtUtc",
    "attemptId", "artifactAnalysisRepresentativeScanId", "sourceAnalysisRepresentativeScanId",
    "previousIndexSha256", "evidenceRevision", "securityRevision",
}

_ROOT_REVISION_KEYS = (
    "catalogRevision", "catalogDataRevision", "catalogIdentityEpoch", "definitionsRevision",
    "scannerRevision", "scannerBundleSha256", "artifactAnalysisRevision", "sourceAnalysisRevision",
    "sourceObservationRevision", "ruleSetRevision", "srlRuleSetRevision", "advisoryRevision",
    "reputationRevision", "capabilityRegistryRevision", "componentRegistryRevision",
    "collectorRegistryRevision", "executionTopologyRevision",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(value):
            if key in _VOLATILE_KEYS:
                continue
            result[key] = _normalize(value[key])
        return result
    if isinstance(value, list):
        # Evidence arrays are generally already canonical.  Preserve order to avoid
        # hiding a meaningful precedence change, but normalize volatile children.
        return [_normalize(item) for item in value]
    return value


def _variant_path(root: Path, variant_id: int) -> Path:
    return root / "variants" / f"{variant_id // 1000:04d}" / f"{variant_id}.json"


def _variant_semantic(root: Path, variant_id: int) -> dict[str, Any]:
    payload = _read(_variant_path(root, variant_id))
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    observations = payload.get("observations") if isinstance(payload.get("observations"), dict) else {}
    collections = observations.get("collections") if isinstance(observations.get("collections"), dict) else {}
    collection_semantic = {
        name: {
            key: value for key, value in _normalize(row).items()
            if key in {"schema", "collectionSchema", "semanticClass", "srlEligible", "completeness", "records", "recordDigest", "backingDataset"}
        }
        for name, row in sorted(collections.items()) if isinstance(row, dict)
    }
    derived_evidence = payload.get("derivedEvidence") if isinstance(payload.get("derivedEvidence"), dict) else {}
    derived_semantic = {
        name: {
            "records": int(row.get("records") or 0),
            "recordDigest": str(row.get("recordDigest") or ""),
        }
        for name, row in sorted(derived_evidence.items()) if isinstance(row, dict)
    }
    return {
        "variantId": variant_id,
        "artifactSha256": str(analysis.get("artifactSha256") or current.get("artifact_sha256") or ""),
        "analysisRecordCount": int(analysis.get("recordCount") or 0),
        "current": _normalize(current),
        "observations": collection_semantic,
        "derived": _normalize(payload.get("derived") or {}),
        "derivedEvidence": derived_semantic,
        "collectorResults": _normalize(payload.get("collectorResults") or {}),
    }


def _queue_semantic(root: Path) -> dict[str, Any]:
    path = root / "scanner-queue.json"
    if not path.is_file():
        return {}
    queue = _read(path)
    keep_context = {
        key: _normalize(queue.get(key)) for key in (
            "schema", "queueSeedRevision", "catalogRevision", "catalogIdentityEpoch",
            "baselineSecurityRebuild", "definitionsRevision", "scannerRevision", "scannerBundleSha256",
            "artifactAnalysisRevision", "sourceAnalysisRevision", "sourceObservationRevision",
            "ruleSetRevision", "srlRuleSetRevision", "advisoryRevision", "selectionPolicy", "reasonContracts",
            "srlReprojection",
        ) if key in queue
    }
    items = queue.get("items") if isinstance(queue.get("items"), dict) else {}
    keep_context["items"] = {key: _normalize(row) for key, row in sorted(items.items()) if isinstance(row, dict)}
    # recentCompleted is a presentation cache of item transitions; the item map itself is
    # authoritative for this equivalence gate and avoids order/timestamp-only drift.
    return keep_context


def _root_semantic(root: Path) -> dict[str, Any]:
    index = _read(root / "index.json")
    revisions = index.get("revisions") if isinstance(index.get("revisions"), dict) else {}
    return {
        "schema": str(index.get("schema") or ""),
        "revisions": {key: revisions.get(key) for key in _ROOT_REVISION_KEYS if key in revisions},
    }


def _tree_json_semantic(root: Path, rel: str) -> dict[str, Any]:
    base = root / rel
    if not base.is_dir():
        return {}
    result: dict[str, Any] = {}
    for path in sorted(base.rglob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        result[path.relative_to(base).as_posix()] = _normalize(value)
    return result


def _optional_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {}
    return _normalize(_read(path))


def _difference_paths(expected: Any, actual: Any, *, prefix: str = "") -> list[dict[str, Any]]:
    """Return bounded structural diagnostics without weakening semantic comparison."""
    result: list[dict[str, Any]] = []

    def visit(left: Any, right: Any, path: str) -> None:
        if len(result) >= MAX_DIFFERENCE_PATHS or _canonical(left) == _canonical(right):
            return
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                if len(result) >= MAX_DIFFERENCE_PATHS:
                    return
                child = f"{path}.{key}" if path else str(key)
                if key not in left:
                    result.append({"path": child, "kind": "parallel-only"})
                elif key not in right:
                    result.append({"path": child, "kind": "serial-only"})
                else:
                    visit(left[key], right[key], child)
            return
        if isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                result.append({
                    "path": path or "$",
                    "kind": "list-length",
                    "serial": len(left),
                    "parallel": len(right),
                })
                return
            for index, (left_item, right_item) in enumerate(zip(left, right)):
                visit(left_item, right_item, f"{path}[{index}]")
                if len(result) >= MAX_DIFFERENCE_PATHS:
                    return
            return
        item: dict[str, Any] = {
            "path": path or "$",
            "kind": "value",
            "serialDigest": _digest(left),
            "parallelDigest": _digest(right),
        }
        if isinstance(left, (str, int, float, bool, type(None))) and isinstance(
            right, (str, int, float, bool, type(None))
        ):
            item["serial"] = left if not isinstance(left, str) or len(left) <= 256 else left[:253] + "..."
            item["parallel"] = right if not isinstance(right, str) or len(right) <= 256 else right[:253] + "..."
        result.append(item)

    visit(expected, actual, prefix)
    return result


def _append_mismatch(mismatches: list[dict[str, Any]], area: str, expected: Any, actual: Any) -> None:
    if len(mismatches) >= MAX_MISMATCHES:
        return
    mismatches.append({
        "area": area,
        "serialDigest": _digest(expected),
        "parallelDigest": _digest(actual),
        "differences": _difference_paths(expected, actual),
    })


def compare(*, parallel_evidence: Path, serial_evidence: Path, variant_ids: Iterable[int], output: Path,
            parallel_deep_scan: Path | None = None, serial_deep_scan: Path | None = None,
            parallel_source_followups: Path | None = None, serial_source_followups: Path | None = None) -> dict[str, Any]:
    parallel = parallel_evidence.resolve(); serial = serial_evidence.resolve()
    p_validation = validate_snapshot(parallel, require_no_orphans=True)
    s_validation = validate_snapshot(serial, require_no_orphans=True)
    if not p_validation.get("ok"):
        raise ValueError("parallel merged candidate is not intrinsically valid")
    if not s_validation.get("ok"):
        raise ValueError("serialized reference candidate is not intrinsically valid")

    variants = sorted({int(v) for v in variant_ids if int(v) > 0})
    mismatches: list[dict[str, Any]] = []
    for variant_id in variants:
        expected = _variant_semantic(serial, variant_id)
        actual = _variant_semantic(parallel, variant_id)
        if _canonical(expected) != _canonical(actual):
            _append_mismatch(mismatches, f"variant:{variant_id}", expected, actual)

    pairs = (
        ("root-revisions", _root_semantic(serial), _root_semantic(parallel)),
        ("scanner-queue", _queue_semantic(serial), _queue_semantic(parallel)),
        ("rule-projections", _tree_json_semantic(serial, "rule-projections"), _tree_json_semantic(parallel, "rule-projections")),
        ("deep-scan", _optional_json(serial_deep_scan), _optional_json(parallel_deep_scan)),
        ("source-followups", _optional_json(serial_source_followups), _optional_json(parallel_source_followups)),
    )
    for area, expected, actual in pairs:
        if _canonical(expected) != _canonical(actual):
            _append_mismatch(mismatches, area, expected, actual)

    semantic = {
        "schema": SCHEMA,
        "authority": "shadow-equivalence-gate-only",
        "variantIds": variants,
        "parallelIndexSha256": hashlib.sha256((parallel / "index.json").read_bytes()).hexdigest(),
        "serialIndexSha256": hashlib.sha256((serial / "index.json").read_bytes()).hexdigest(),
        "areasChecked": ["affected-variants", "root-revisions", "scanner-queue", "rule-projections", "deep-scan", "source-followups"],
        "mismatches": mismatches,
        "equivalent": not mismatches,
    }
    semantic["equivalenceRevision"] = f"sigmascope-equivalence-v1-{_digest(semantic)[:20]}"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(semantic, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return semantic


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--parallel-evidence", required=True, type=Path)
    ap.add_argument("--serial-evidence", required=True, type=Path)
    ap.add_argument("--variant-ids", required=True, help="Comma-separated affected variant IDs")
    ap.add_argument("--parallel-deep-scan", type=Path)
    ap.add_argument("--serial-deep-scan", type=Path)
    ap.add_argument("--parallel-source-followups", type=Path)
    ap.add_argument("--serial-source-followups", type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    variants = [int(v.strip()) for v in str(args.variant_ids).split(",") if v.strip()]
    report = compare(
        parallel_evidence=args.parallel_evidence, serial_evidence=args.serial_evidence, variant_ids=variants, output=args.output,
        parallel_deep_scan=args.parallel_deep_scan, serial_deep_scan=args.serial_deep_scan,
        parallel_source_followups=args.parallel_source_followups, serial_source_followups=args.serial_source_followups,
    )
    print(json.dumps({
        "equivalent": report["equivalent"],
        "mismatchCount": len(report["mismatches"]),
        "mismatchAreas": [item["area"] for item in report["mismatches"]],
        "differencePaths": {
            item["area"]: [entry["path"] for entry in item.get("differences") or []]
            for item in report["mismatches"]
        },
        "equivalenceRevision": report["equivalenceRevision"],
    }, sort_keys=True))
    return 0 if report["equivalent"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
