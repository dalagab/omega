#!/usr/bin/env python3
"""Retain one generic collector result in Security Evidence v2.

This is the shared producer-side ingress for non-core collectors.  It validates the
content-addressed collector result, binds it to the exact current variant/artifact, stores
it as bounded derived evidence, extends the variant observation contract, refreshes the
root indexes/revision, and runs intrinsic Evidence-v2 validation.  It never creates
findings or evaluates SRL.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import collector_contracts  # noqa: E402
import collector_results  # noqa: E402
import observation_projection  # noqa: E402
import production_sigmascope_v2_pipeline as production  # noqa: E402
from security_evidence_v2 import (  # noqa: E402
    SCHEMA as EVIDENCE_SCHEMA,
    canonical_json_bytes,
    dataset_record_digest,
    file_entry,
    read_json_file,
    sha256_bytes,
    validate_snapshot,
    write_json,
)

ADAPTER_SCHEMA = "omega.collector-evidence-ingestion.v1"
ADAPTER_VERSION = "1.0.0"
MAX_RESULTS_PER_COLLECTOR_VARIANT = 8
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return value


def _variant_path(root: Path, variant_id: int) -> Path:
    matches = []
    if (root / "variants").exists():
        for path in (root / "variants").rglob(f"{variant_id}.json"):
            try:
                if int(_load(path).get("variantId") or 0) == variant_id:
                    matches.append(path)
            except Exception:
                continue
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one active Evidence-v2 descriptor for variant {variant_id}, found {len(matches)}")
    return matches[0]


def _artifact_sha(payload: Mapping[str, Any]) -> str:
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
    current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
    return str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()


def _dataset_from_files(root: Path, files: list[Path]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    for path in sorted(files):
        value = _load(path)
        rows.append(value)
        count, digest = dataset_record_digest([value])
        entries.append(file_entry(root, path, records=count, record_digest=digest, encoding="json"))
    count, digest = dataset_record_digest(rows)
    return {"records": count, "recordDigest": digest, "files": entries}


def _refresh_observation_contract(payload: dict[str, Any], result: Mapping[str, Any], result_rel: str) -> None:
    contract = copy.deepcopy(payload.get("observations") or {}) if isinstance(payload.get("observations"), Mapping) else {}
    collections = copy.deepcopy(contract.get("collections") or {}) if isinstance(contract.get("collections"), Mapping) else {}
    collector_id = str((result.get("collector") or {}).get("id") or "") if isinstance(result.get("collector"), Mapping) else ""
    result_revision = str(result.get("resultRevision") or "")
    for observation, descriptor in sorted((result.get("collections") or {}).items()):
        if not isinstance(descriptor, Mapping):
            continue
        spec = collector_contracts.OBSERVATION_TYPES.get(str(observation)) or {}
        collections[str(observation)] = {
            "schema": observation_projection.OBSERVATION_COLLECTION_SCHEMA,
            "collectionSchema": str(spec.get("schema") or descriptor.get("observationSchema") or ""),
            "backingDataset": "collector-result",
            "records": int(descriptor.get("records") or 0),
            "recordDigest": str(descriptor.get("recordDigest") or ""),
            "semanticClass": str(spec.get("semanticClass") or descriptor.get("semanticClass") or "observation"),
            "srlEligible": bool(spec.get("ruleEligible")),
            "completeness": "retained-snapshot" if str(result.get("status") or "") == "complete" else "partial",
            "collectorId": collector_id,
            "resultRevision": result_revision,
            "resultPath": result_rel,
        }
    digest_payload = [
        {
            "collection": name,
            "records": int(item.get("records") or 0),
            "recordDigest": str(item.get("recordDigest") or ""),
            "schema": str(item.get("collectionSchema") or ""),
            "completeness": str(item.get("completeness") or ""),
        }
        for name, item in sorted(collections.items()) if isinstance(item, Mapping)
    ]
    contract.update({
        "schema": observation_projection.OBSERVATION_CONTRACT_SCHEMA,
        "contractRevision": observation_projection.contract_revision(),
        "collectorRegistryRevision": collector_contracts.registry_revision(),
        "observationDigest": "obs-" + sha256_bytes(canonical_json_bytes(digest_payload)),
        "collections": collections,
    })
    payload["observations"] = contract


def _collector_revision(candidate: Path) -> str:
    rows: list[dict[str, Any]] = []
    for path in sorted((candidate / "variants").rglob("*.json")) if (candidate / "variants").exists() else []:
        payload = _load(path)
        derived = payload.get("derivedEvidence") if isinstance(payload.get("derivedEvidence"), Mapping) else {}
        descriptor = derived.get("collectorResults") if isinstance(derived.get("collectorResults"), Mapping) else {}
        if descriptor:
            rows.append({
                "variantId": int(payload.get("variantId") or 0),
                "records": int(descriptor.get("records") or 0),
                "recordDigest": str(descriptor.get("recordDigest") or ""),
            })
    return "collector-observations-v1-" + sha256_bytes(canonical_json_bytes(rows))[:16]


def _refresh_indexes(candidate: Path, previous_root: Mapping[str, Any], ingestion: Mapping[str, Any]) -> dict[str, Any]:
    plugins_path = str(((previous_root.get("indexes") or {}).get("plugins") or {}).get("path") or "indexes/plugins.json")
    previous_plugins = read_json_file(candidate, plugins_path)
    lifecycle = int(previous_plugins.get("lifecycleContractVersion") or 0)
    plugins_entry, artifacts_entry, current_count, terminal_count, history_count, analysis_count, artifact_count = production._build_plugins_artifacts_indexes(
        candidate, lifecycle_contract_version=lifecycle
    )
    root = copy.deepcopy(dict(previous_root))
    indexes = dict(root.get("indexes") or {})
    indexes["plugins"] = plugins_entry
    indexes["artifacts"] = artifacts_entry
    root["indexes"] = indexes
    counts = dict(root.get("counts") or {})
    counts.update({
        "currentVariants": current_count,
        "terminalVariants": terminal_count,
        "historicalSnapshots": history_count,
        "analyses": analysis_count,
        "artifactGroups": artifact_count,
    })
    root["counts"] = counts
    source = dict(root.get("source") or {})
    source["lastCollectorIngestion"] = dict(ingestion)
    root["source"] = source
    revisions = dict(root.get("revisions") or {})
    previous_evidence = str(revisions.get("evidenceRevision") or "")
    collector_revision = _collector_revision(candidate)
    revisions["previousEvidenceRevision"] = previous_evidence
    revisions["collectorObservationRevision"] = collector_revision
    revisions["evidenceRevision"] = "ev-v2-" + sha256_bytes(canonical_json_bytes({
        "schema": "omega.security-evidence.collector-revision.v1",
        "baseEvidenceRevision": previous_evidence,
        "pluginsIndexSha256": str(plugins_entry.get("sha256") or ""),
        "collectorObservationRevision": collector_revision,
    }))[:16]
    root["revisions"] = revisions
    root["generatedAtUtc"] = collector_contracts.utc_now()
    root.setdefault("publication", {})["rootWrittenLast"] = True
    write_json(candidate / "index.json", root)
    return root


def ingest(current_evidence: Path, candidate_evidence: Path, result_path: Path) -> dict[str, Any]:
    current_evidence = current_evidence.resolve()
    candidate_evidence = candidate_evidence.resolve()
    previous_root = read_json_file(current_evidence, "index.json")
    if str(previous_root.get("schema") or "") != EVIDENCE_SCHEMA:
        raise RuntimeError("current evidence root is not Security Evidence v2")
    result = collector_results.validate_result(_load(result_path))
    subject = result.get("subject") if isinstance(result.get("subject"), Mapping) else {}
    variant_id = int(subject.get("variantId") or 0)
    expected_artifact = str(subject.get("artifactSha256") or "").strip().lower()
    if variant_id <= 0 or len(expected_artifact) != 64:
        raise RuntimeError("collector Evidence-v2 ingestion requires an exact variantId + artifactSha256 subject")

    if candidate_evidence.exists():
        shutil.rmtree(candidate_evidence)
    shutil.copytree(current_evidence, candidate_evidence, ignore=shutil.ignore_patterns(".git", ".staging"))
    variant_file = _variant_path(candidate_evidence, variant_id)
    payload = _load(variant_file)
    current_artifact = _artifact_sha(payload)
    if current_artifact != expected_artifact:
        raise RuntimeError(f"collector result artifact does not match current Evidence-v2 variant: result={expected_artifact}, evidence={current_artifact}")

    collector_id = str((result.get("collector") or {}).get("id") or "")
    safe_collector = _SAFE_ID.sub("_", collector_id).strip("._")[:160] or "collector"
    result_revision = str(result.get("resultRevision") or "")
    lane_root = candidate_evidence / "derived" / "variants" / f"{variant_id // 1000:04d}" / str(variant_id) / "collectors" / safe_collector
    result_dir = lane_root / result_revision
    result_dir.mkdir(parents=True, exist_ok=True)
    retained_result = result_dir / "result.json"
    write_json(retained_result, result)

    # Keep a small immutable history per collector/variant. Snapshot publication already
    # provides branch-level atomicity; this bound prevents a high-frequency provider from
    # becoming an unbounded storage lane.
    result_dirs = sorted([item for item in lane_root.iterdir() if item.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
    for old in result_dirs[MAX_RESULTS_PER_COLLECTOR_VARIANT:]:
        shutil.rmtree(old)

    collector_root = candidate_evidence / "derived" / "variants" / f"{variant_id // 1000:04d}" / str(variant_id) / "collectors"
    retained_files = sorted(path for path in collector_root.rglob("result.json") if path.is_file())
    derived = dict(payload.get("derivedEvidence") or {})
    derived["collectorResults"] = _dataset_from_files(candidate_evidence, retained_files)
    payload["derivedEvidence"] = derived
    result_rel = retained_result.relative_to(candidate_evidence).as_posix()
    _refresh_observation_contract(payload, result, result_rel)
    latest = dict(payload.get("collectorResults") or {}) if isinstance(payload.get("collectorResults"), Mapping) else {}
    for observation in sorted((result.get("collections") or {})):
        latest[str(observation)] = {
            "collectorId": collector_id,
            "resultRevision": result_revision,
            "resultPath": result_rel,
            "status": str(result.get("status") or ""),
            "generatedAtUtc": str(result.get("generatedAtUtc") or ""),
            "artifactSha256": expected_artifact,
        }
    payload["collectorResults"] = latest
    write_json(variant_file, payload)

    ingestion = {
        "schema": ADAPTER_SCHEMA,
        "adapterVersion": ADAPTER_VERSION,
        "variantId": variant_id,
        "artifactSha256": expected_artifact,
        "requestId": str(result.get("requestId") or ""),
        "workItemId": str(result.get("workItemId") or ""),
        "collectorId": collector_id,
        "resultRevision": result_revision,
        "observations": sorted((result.get("collections") or {}).keys()),
        "resultPath": result_rel,
    }
    root = _refresh_indexes(candidate_evidence, previous_root, ingestion)
    validation = validate_snapshot(candidate_evidence)
    if not validation.get("ok"):
        raise RuntimeError("collector candidate Evidence-v2 failed intrinsic validation: " + "; ".join(validation.get("errors") or []))
    return {
        **ingestion,
        "evidenceRevision": str((root.get("revisions") or {}).get("evidenceRevision") or ""),
        "collectorObservationRevision": str((root.get("revisions") or {}).get("collectorObservationRevision") or ""),
        "validation": {"ok": True, "checkedVariants": validation.get("checkedVariants"), "checkedAnalyses": validation.get("checkedAnalyses")},
        "candidate": str(candidate_evidence),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Retain a generic Omega collector result in Security Evidence v2")
    parser.add_argument("--current-evidence", required=True, type=Path)
    parser.add_argument("--candidate-evidence", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validation-output", type=Path)
    args = parser.parse_args()
    result = ingest(args.current_evidence, args.candidate_evidence, args.result)
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    if args.validation_output:
        validation = validate_snapshot(args.candidate_evidence.resolve())
        args.validation_output.parent.mkdir(parents=True, exist_ok=True)
        args.validation_output.write_text(json.dumps(validation, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
