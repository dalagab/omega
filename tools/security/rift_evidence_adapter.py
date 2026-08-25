#!/usr/bin/env python3
"""Import a broker-bound Interdimensional Rift run into Security Evidence v2.

The adapter is deliberately transport/observation-only.  It validates the broker request,
trusted supervisor attestation and current Evidence-v2 variant identity, then retains the exact
Rift report bytes plus a typed collector observation bundle.  It does not invent findings,
change severity, enqueue scans, or execute hostile code.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import collector_contracts
import production_sigmascope_v2_pipeline as production
import rift_runtime_contract as rift_contract
from security_evidence_v2 import (
    SCHEMA as EVIDENCE_SCHEMA,
    canonical_json_bytes,
    dataset_record_digest,
    file_entry,
    read_json_file,
    sha256_bytes,
    sha256_file,
    validate_snapshot,
    write_json,
)

ADAPTER_VERSION = "1.0.0"
MAX_RETAINED_RUNS_PER_VARIANT = 16


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return value


def _variant_path(root: Path, variant_id: int) -> Path:
    matches = list((root / "variants").rglob(f"{variant_id}.json")) if (root / "variants").exists() else []
    matches = [path for path in matches if int(_load_json(path).get("variantId") or 0) == variant_id]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one active Evidence-v2 descriptor for variant {variant_id}, found {len(matches)}")
    return matches[0]


def _current_artifact_sha(payload: Mapping[str, Any]) -> str:
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
    current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
    return str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()


def _dataset_from_files(root: Path, files: list[Path]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    for path in sorted(files):
        value = _load_json(path)
        rows.append(value)
        count, digest = dataset_record_digest([value])
        entries.append(file_entry(root, path, records=count, record_digest=digest, encoding="json"))
    count, digest = dataset_record_digest(rows)
    return {"records": count, "recordDigest": digest, "files": entries}


def _runtime_revision(candidate: Path) -> str:
    rows: list[dict[str, Any]] = []
    for path in sorted((candidate / "variants").rglob("*.json")) if (candidate / "variants").exists() else []:
        payload = _load_json(path)
        derived = payload.get("derivedEvidence") if isinstance(payload.get("derivedEvidence"), Mapping) else {}
        descriptor = derived.get("riftRuntimeEvidence") if isinstance(derived.get("riftRuntimeEvidence"), Mapping) else {}
        if descriptor:
            rows.append({
                "variantId": int(payload.get("variantId") or 0),
                "recordDigest": str(descriptor.get("recordDigest") or ""),
                "records": int(descriptor.get("records") or 0),
            })
    return "rift-runtime-v1-" + sha256_bytes(canonical_json_bytes(rows))[:16]


def _refresh_indexes_and_root(candidate: Path, previous_root: Mapping[str, Any], ingestion: Mapping[str, Any]) -> dict[str, Any]:
    previous_plugins = read_json_file(candidate, str(((previous_root.get("indexes") or {}).get("plugins") or {}).get("path") or "indexes/plugins.json"))
    lifecycle_contract_version = int(previous_plugins.get("lifecycleContractVersion") or 0)
    plugins_entry, artifacts_entry, current_count, terminal_count, history_count, analysis_count, artifact_count = production._build_plugins_artifacts_indexes(
        candidate, lifecycle_contract_version=lifecycle_contract_version
    )
    root = dict(previous_root)
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
    source["lastRiftIngestion"] = dict(ingestion)
    root["source"] = source
    revisions = dict(root.get("revisions") or {})
    previous_evidence = str(revisions.get("evidenceRevision") or "")
    runtime_revision = _runtime_revision(candidate)
    revisions["previousEvidenceRevision"] = previous_evidence
    revisions["runtimeObservationRevision"] = runtime_revision
    # Evidence revision incorporates the new plugins index hash and runtime revision while leaving
    # the semantic static-security revision untouched.
    evidence_payload = {
        "schema": "omega.security-evidence.rift-revision.v1",
        "baseEvidenceRevision": previous_evidence,
        "pluginsIndexSha256": str(plugins_entry.get("sha256") or ""),
        "runtimeObservationRevision": runtime_revision,
    }
    revisions["evidenceRevision"] = "ev-v2-" + sha256_bytes(canonical_json_bytes(evidence_payload))[:16]
    root["revisions"] = revisions
    root["generatedAtUtc"] = collector_contracts.utc_now()
    root.setdefault("publication", {})["rootWrittenLast"] = True
    write_json(candidate / "index.json", root)
    return root


def ingest(
    current_evidence: Path,
    candidate_evidence: Path,
    request_path: Path,
    runtime_report_path: Path,
    attestation_path: Path,
    *,
    component_security_path: Path | None = None,
    allow_unbound_local: bool = False,
) -> dict[str, Any]:
    current_evidence = current_evidence.resolve()
    candidate_evidence = candidate_evidence.resolve()
    previous_root = read_json_file(current_evidence, "index.json")
    if str(previous_root.get("schema") or "") != EVIDENCE_SCHEMA:
        raise RuntimeError("current evidence root is not Security Evidence v2")

    request = _load_json(request_path)
    report_bytes = runtime_report_path.read_bytes()
    report = json.loads(report_bytes.decode("utf-8"))
    if not isinstance(report, dict):
        raise RuntimeError("Rift runtime report must be a JSON object")
    attestation = _load_json(attestation_path)
    component_security = _load_json(component_security_path) if component_security_path else None

    errors = []
    errors.extend(rift_contract.validate_request(request))
    errors.extend(rift_contract.validate_runtime_report(report))
    errors.extend(rift_contract.validate_attestation(attestation, report_bytes, request, production=not allow_unbound_local))
    errors.extend(rift_contract.validate_report_attestation_correlation(report, attestation))
    if component_security is not None:
        errors.extend(rift_contract.validate_component_security(component_security))
    if errors:
        raise RuntimeError("Rift evidence validation failed: " + "; ".join(errors))

    variant_id = int(request["variantId"])
    if candidate_evidence.exists():
        shutil.rmtree(candidate_evidence)
    shutil.copytree(current_evidence, candidate_evidence, ignore=shutil.ignore_patterns(".git", ".staging"))
    variant_file = _variant_path(candidate_evidence, variant_id)
    payload = _load_json(variant_file)
    expected_artifact = str(request["artifactSha256"]).strip().lower()
    current_artifact = _current_artifact_sha(payload)
    if current_artifact != expected_artifact:
        raise RuntimeError(f"Rift request artifact does not match current Evidence-v2 variant: request={expected_artifact}, evidence={current_artifact}")

    bundle = rift_contract.build_observation_bundle(request, report, attestation, component_security)
    report_sha = rift_contract.sha256_bytes(report_bytes)
    run_id = sha256_bytes(f"{request['requestId']}\n{report_sha}".encode("utf-8"))[:20]
    run_dir = candidate_evidence / "derived" / "variants" / f"{variant_id // 1000:04d}" / str(variant_id) / "rift" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Preserve the exact managed report bytes so the supervisor's SHA-256 remains independently verifiable.
    (run_dir / "runtime-report.json").write_bytes(report_bytes)
    shutil.copy2(request_path, run_dir / "request.json")
    shutil.copy2(attestation_path, run_dir / "supervisor-attestation.json")
    write_json(run_dir / "collector-observations.json", bundle)
    if component_security is not None:
        shutil.copy2(component_security_path, run_dir / "component-security.json")

    # Bound snapshot retention per current variant. Evidence-v2 itself is snapshot-published, so
    # this prevents a noisy runtime lane from growing forever while preserving useful recent history.
    rift_root = run_dir.parent
    run_dirs = sorted([item for item in rift_root.iterdir() if item.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
    for old in run_dirs[MAX_RETAINED_RUNS_PER_VARIANT:]:
        shutil.rmtree(old)

    retained_files = sorted(path for path in rift_root.rglob("*.json") if path.is_file())
    derived = dict(payload.get("derivedEvidence") or {})
    derived["riftRuntimeEvidence"] = _dataset_from_files(candidate_evidence, retained_files)
    payload["derivedEvidence"] = derived
    runtime = dict(payload.get("runtime") or {})
    runtime.update({
        "schema": rift_contract.INGESTION_SCHEMA,
        "collectorRegistryRevision": collector_contracts.registry_revision(),
        "collectorId": "omega.collector.rift.runtime",
        "requestId": str(request["requestId"]),
        "runId": run_id,
        "artifactSha256": expected_artifact,
        "artifactTreeSha256": str(attestation.get("artifact_tree_sha256") or ""),
        "entrySha256": str(attestation.get("entry_sha256") or ""),
        "runtimeReportSha256": report_sha,
        "observedAtUtc": str(report.get("ran_at") or ""),
        "productionBound": not allow_unbound_local,
        "bundleRecordDigest": sha256_bytes(canonical_json_bytes(bundle)),
        "bundleCollections": sorted(bundle.get("collections") or {}),
    })
    payload["runtime"] = runtime
    write_json(variant_file, payload)

    ingestion = {
        "schema": rift_contract.INGESTION_SCHEMA,
        "adapterVersion": ADAPTER_VERSION,
        "variantId": variant_id,
        "requestId": str(request["requestId"]),
        "runId": run_id,
        "artifactSha256": expected_artifact,
        "runtimeReportSha256": report_sha,
        "collectorRegistryRevision": collector_contracts.registry_revision(),
        "productionBound": not allow_unbound_local,
    }
    root = _refresh_indexes_and_root(candidate_evidence, previous_root, ingestion)
    validation = validate_snapshot(candidate_evidence)
    if not validation.get("ok"):
        raise RuntimeError("candidate Evidence-v2 failed intrinsic validation: " + "; ".join(validation.get("errors") or []))
    return {
        **ingestion,
        "evidenceRevision": str((root.get("revisions") or {}).get("evidenceRevision") or ""),
        "runtimeObservationRevision": str((root.get("revisions") or {}).get("runtimeObservationRevision") or ""),
        "observationRecords": int(bundle.get("records") or 0),
        "observationCollections": sorted(bundle.get("collections") or {}),
        "candidate": str(candidate_evidence),
        "validation": {"ok": True, "files": validation.get("files"), "variants": validation.get("variants")},
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Import a broker-bound Rift runtime report into Security Evidence v2")
    p.add_argument("--current-evidence", required=True, type=Path)
    p.add_argument("--candidate-evidence", required=True, type=Path)
    p.add_argument("--request", required=True, type=Path)
    p.add_argument("--runtime-report", required=True, type=Path)
    p.add_argument("--attestation", required=True, type=Path)
    p.add_argument("--component-security-report", type=Path)
    p.add_argument("--allow-unbound-local", action="store_true", help="Allow attestation v1 for local inspection only; output is marked non-production-bound")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = ingest(
        args.current_evidence, args.candidate_evidence, args.request, args.runtime_report, args.attestation,
        component_security_path=args.component_security_report, allow_unbound_local=args.allow_unbound_local,
    )
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
