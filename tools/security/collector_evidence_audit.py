#!/usr/bin/env python3
"""Independent fail-closed audit for generic collector-only Evidence-v2 updates."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any, Mapping

import collector_results
import security_evidence_v2

SCHEMA = "omega.collector-evidence-audit.v1"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return value


def _variant_map(root: Path) -> dict[int, dict[str, Any]]:
    return {int(payload.get("variantId") or 0): payload for _entry, payload in security_evidence_v2.iter_variant_entries(root)}


def _without_collector_lane(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(payload))
    value.pop("collectorResults", None)
    derived = value.get("derivedEvidence") if isinstance(value.get("derivedEvidence"), dict) else {}
    derived.pop("collectorResults", None)
    if derived:
        value["derivedEvidence"] = derived
    else:
        value.pop("derivedEvidence", None)
    observations = value.get("observations") if isinstance(value.get("observations"), dict) else {}
    collections = observations.get("collections") if isinstance(observations.get("collections"), dict) else {}
    collections = {
        name: item for name, item in collections.items()
        if not (isinstance(item, Mapping) and str(item.get("backingDataset") or "") == "collector-result")
    }
    if observations:
        observations["collections"] = collections
        observations.pop("collectorRegistryRevision", None)
        # observationDigest legitimately changes when collector collections are attached.
        observations.pop("observationDigest", None)
        value["observations"] = observations
    return value


def audit(current: Path, candidate: Path, result_path: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "status": "pass" if ok else "fail", "detail": detail[:2000]})

    result = collector_results.validate_result(_load(result_path))
    subject = result.get("subject") if isinstance(result.get("subject"), Mapping) else {}
    variant_id = int(subject.get("variantId") or 0)
    validation = security_evidence_v2.validate_snapshot(candidate)
    check("candidate-intrinsic-validation", bool(validation.get("ok")), "; ".join(validation.get("errors") or []))

    current_index = security_evidence_v2.read_json_file(current, "index.json")
    candidate_index = security_evidence_v2.read_json_file(candidate, "index.json")
    check("catalog-revision-unchanged", str((current_index.get("revisions") or {}).get("catalogRevision") or "") == str((candidate_index.get("revisions") or {}).get("catalogRevision") or ""))
    check("security-revision-unchanged", str((current_index.get("revisions") or {}).get("securityRevision") or "") == str((candidate_index.get("revisions") or {}).get("securityRevision") or ""))
    current_counts = {str(k): int(v or 0) for k, v in dict(current_index.get("counts") or {}).items()}
    candidate_counts = {str(k): int(v or 0) for k, v in dict(candidate_index.get("counts") or {}).items()}
    count_keys = set(current_counts) | set(candidate_counts)
    check(
        "variant-counts-unchanged",
        all(current_counts.get(key, 0) == candidate_counts.get(key, 0) for key in count_keys),
    )

    current_variants = _variant_map(current)
    candidate_variants = _variant_map(candidate)
    check("variant-identity-set-unchanged", set(current_variants) == set(candidate_variants))
    changed: list[int] = []
    for vid in sorted(set(current_variants) & set(candidate_variants)):
        if security_evidence_v2.canonical_json_bytes(current_variants[vid]) != security_evidence_v2.canonical_json_bytes(candidate_variants[vid]):
            changed.append(vid)
    check("exactly-target-variant-changed", changed == [variant_id], f"changed={changed}, target={variant_id}")
    if variant_id in current_variants and variant_id in candidate_variants:
        check(
            "target-static-evidence-unchanged",
            _without_collector_lane(current_variants[variant_id]) == _without_collector_lane(candidate_variants[variant_id]),
        )
    else:
        check("target-static-evidence-unchanged", False, "target variant missing")

    result_revision = str(result.get("resultRevision") or "")
    candidate_target = candidate_variants.get(variant_id) or {}
    latest = candidate_target.get("collectorResults") if isinstance(candidate_target.get("collectorResults"), Mapping) else {}
    metadata = latest.get(str(result.get("observation") or "")) if isinstance(latest.get(str(result.get("observation") or "")), Mapping) else {}
    check("result-revision-retained", str((metadata or {}).get("resultRevision") or "") == result_revision)
    retained_rel = str((metadata or {}).get("resultPath") or "")
    retained_ok = False
    if retained_rel:
        try:
            retained = collector_results.validate_result(security_evidence_v2.read_json_file(candidate, retained_rel))
            retained_ok = str(retained.get("resultRevision") or "") == result_revision
        except Exception:
            retained_ok = False
    check("retained-result-valid", retained_ok)

    fail = sum(1 for item in checks if item["status"] == "fail")
    report = {
        "schema": SCHEMA,
        "ok": fail == 0,
        "counts": {"pass": len(checks) - fail, "fail": fail, "warn": 0},
        "variantId": variant_id,
        "resultRevision": result_revision,
        "checks": checks,
    }
    return report


def main() -> int:
    p = argparse.ArgumentParser(description="Audit a collector-only Security Evidence v2 candidate")
    p.add_argument("--current-evidence", type=Path, required=True)
    p.add_argument("--candidate-evidence", type=Path, required=True)
    p.add_argument("--result", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    report = audit(args.current_evidence.resolve(), args.candidate_evidence.resolve(), args.result.resolve())
    text = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
