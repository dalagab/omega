#!/usr/bin/env python3
"""Build one validated Security Evidence v2 candidate from parallel SigmaScope bundles.

This is the serialized Phase-4B merge boundary.  Parallel workers remain result-only:
they may contribute bounded variant-local transport data and an exact scanner-queue
settlement, but never root/global indexes or an Evidence-v2 publication.  The merger
starts from one exact published Evidence-v2 head, applies disjoint bundles, reconstructs
the compact security database from the merged transport, rebuilds global projections
centrally, performs SRL reprojection, and validates the resulting candidate.

The first implementation is deliberately *candidate-only*.  It does not call the
Evidence-v2 publisher and it refuses stale-base bundles instead of attempting a rebase.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
CATALOG_DIR = SCRIPT_DIR.parent / "catalog"
for path in (SCRIPT_DIR, CATALOG_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import scan_queue  # noqa: E402
import sigmascope  # noqa: E402
import sigmascope_result_bundle  # noqa: E402
import sigmascope_source_followups  # noqa: E402
import deep_scan_queue  # noqa: E402
from local_sigmascope_v2_test import summarize as summarize_database  # noqa: E402
from production_sigmascope_v2_pipeline import (  # noqa: E402
    _copy_evidence_tree,
    _export_nuget_index,
    _merge_successful_subset,
    _sigmascope_args,
    materialize_current_state,
    materialize_definition_provenance_index,
    materialize_srl_reprojection_sidecar,
    materialize_threat_intelligence_index,
    rebuild_candidate_indexes,
    synchronize_candidate,
    write_json,
)
from security_evidence_v2 import sha256_file, validate_snapshot  # noqa: E402

SCHEMA = "omega.sigmascope-result-merge.v1"
MAX_BUNDLES = 8
MAX_VARIANTS = 8


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _variant_path(root: Path, variant_id: int) -> Path:
    return root / "variants" / f"{variant_id // 1000:04d}" / f"{variant_id}.json"


def _copy_derived_payload(payload_root: Path, candidate: Path) -> int:
    source = payload_root / "derived"
    if not source.is_dir():
        return 0
    copied = 0
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(payload_root)
        destination = candidate / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        copied += 1
    return copied


def _prepare_transport_plugins_index(candidate: Path, bundle_docs: list[dict[str, Any]]) -> None:
    """Make the temporary merged tree materializable before global indexes are rebuilt.

    ``materialize_current_state`` only needs ``variantId`` and ``variantPath`` from the
    plugins transport index.  The file is deliberately temporary/stale with respect to
    the root descriptor and is replaced by ``rebuild_candidate_indexes`` before any
    validation or publication can occur.
    """
    path = candidate / "indexes" / "plugins.json"
    payload = _read(path) if path.is_file() else {"schema": "omega.security-evidence.plugins-index.v2", "currentVariants": []}
    rows = [dict(row) for row in payload.get("currentVariants") or [] if isinstance(row, dict)]
    by_variant = {int(row.get("variantId") or 0): row for row in rows if int(row.get("variantId") or 0) > 0}
    for doc in bundle_docs:
        outcome = doc.get("outcome") if isinstance(doc.get("outcome"), dict) else {}
        if str(outcome.get("status") or "") != "complete":
            continue
        work = doc["work"]
        variant_id = int(work["variantId"])
        variant_file = _variant_path(candidate, variant_id)
        if not variant_file.is_file():
            raise ValueError(f"successful bundle did not materialize variant payload {variant_id}")
        variant = _read(variant_file)
        current = variant.get("current") if isinstance(variant.get("current"), dict) else {}
        analysis = variant.get("analysis") if isinstance(variant.get("analysis"), dict) else {}
        by_variant[variant_id] = {
            **by_variant.get(variant_id, {}),
            "variantId": variant_id,
            "scanId": int(current.get("scan_id") or 0),
            "artifactSha256": str(analysis.get("artifactSha256") or current.get("artifact_sha256") or ""),
            "analysisId": str(analysis.get("analysisId") or ""),
            "variantPath": variant_file.relative_to(candidate).as_posix(),
        }
    payload["currentVariants"] = [by_variant[key] for key in sorted(by_variant)]
    write_json(path, payload)


def _completion_entry(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "variantId": int(item.get("variantId") or 0),
        "workType": str(item.get("workType") or "artifact"),
        "internalName": str(item.get("internalName") or ""),
        "targetFingerprint": str(item.get("targetFingerprint") or ""),
        "primaryReason": str(item.get("primaryReason") or ""),
        "completedAtUtc": str(item.get("completedAtUtc") or ""),
        "attemptCount": int(item.get("attemptCount") or 0),
    }


def _parse_utc(value: str) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _current_rows(database: Path) -> dict[int, dict[str, Any]]:
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        return {int(row["variant_id"]): dict(row) for row in db.execute("SELECT * FROM plugin_security_current")}


def _merge_queue(current_evidence: Path, bundle_docs: list[dict[str, Any]], current_rows: dict[int, dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    path = current_evidence / "scanner-queue.json"
    state = _read(path) if path.is_file() else {"schema": scan_queue.STATE_SCHEMA, "items": {}, "recentCompleted": []}
    contexts = [doc["work"].get("queueContextAfter") or {} for doc in bundle_docs]
    if contexts:
        first = contexts[0]
        for context in contexts[1:]:
            if _canonical(context) != _canonical(first):
                raise ValueError("parallel merge queue contexts differ")
        for key, value in first.items():
            state[key] = value
    items = state.get("items") if isinstance(state.get("items"), dict) else {}
    recent = [dict(row) for row in state.get("recentCompleted") or [] if isinstance(row, dict)]
    source_followup_keys: list[str] = []
    for doc in bundle_docs:
        work = doc["work"]
        key = str(work.get("queueKey") or "")
        after = work.get("after") if isinstance(work.get("after"), dict) else {}
        if not key or str(after.get("queueKey") or key) != key:
            raise ValueError("parallel bundle has inconsistent queue settlement key")
        items[key] = dict(after)
        if str(after.get("state") or "") == "complete":
            entry = _completion_entry(after)
            identity = (entry["variantId"], entry["workType"], entry["targetFingerprint"], entry["completedAtUtc"])
            existing = {
                (int(row.get("variantId") or 0), str(row.get("workType") or "artifact"), str(row.get("targetFingerprint") or ""), str(row.get("completedAtUtc") or ""))
                for row in recent
            }
            if identity not in existing:
                recent.append(entry)
            # The parallel worker deliberately cannot mutate global queue state beyond
            # its exact leased key. Reproduce the production artifact -> source-followup
            # transition once, centrally, from the merged current database row.
            if str(after.get("workType") or "") == "artifact" and str((doc.get("outcome") or {}).get("status") or "") == "complete":
                followup = scan_queue.enqueue_source_followup(
                    state, after, current_rows.get(int(after.get("variantId") or 0)),
                    now=_parse_utc(str(after.get("completedAtUtc") or "")),
                )
                if isinstance(followup, dict) and str(followup.get("queueKey") or ""):
                    source_followup_keys.append(str(followup["queueKey"]))
    state["items"] = items
    state["recentCompleted"] = recent[-64:]
    completed_times = [str((doc["work"].get("after") or {}).get("completedAtUtc") or "") for doc in bundle_docs]
    state["updatedAtUtc"] = max([str(state.get("updatedAtUtc") or "")] + completed_times)
    return state, sorted(set(source_followup_keys))


def _project_source_followups(database: Path, output: Path) -> dict[str, Any]:
    projection = sigmascope_source_followups.followups(database)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, projection)
    return {
        "schema": str(projection.get("schema") or ""),
        "path": str(output),
        "count": int(projection.get("count") or 0),
        "actionableCount": int(projection.get("actionableCount") or 0),
        "pluginCount": int(projection.get("pluginCount") or 0),
        "actionablePluginCount": int(projection.get("actionablePluginCount") or 0),
        "sha256": sha256_file(output),
        "publicationAuthority": False,
    }


def _project_deep_scan_queue(candidate: Path, srl: dict[str, Any], previous_state: Path | None, output: Path) -> dict[str, Any]:
    if not srl.get("enabled"):
        return {"enabled": False, "publicationAuthority": False, "pending": 0, "blocked": 0, "complete": 0, "queueRevision": ""}
    projection_root = candidate / "rule-projections"
    request_path = projection_root / "analysis-requests.json"
    requests: list[dict[str, Any]] = []
    if request_path.is_file():
        request_doc = _read(request_path)
        requests = [dict(item) for item in request_doc.get("requests") or [] if isinstance(item, dict)]
    previous: dict[str, Any] = {}
    if previous_state is not None and previous_state.is_file():
        try:
            previous = _read(previous_state)
        except (OSError, ValueError, json.JSONDecodeError):
            previous = {}
    queue_doc = deep_scan_queue.build_queue(candidate, requests, previous)
    output.mkdir(parents=True, exist_ok=True)
    if previous_state is not None and previous_state.is_file():
        results = previous_state.parent / "results"
        if results.is_dir():
            shutil.copytree(results, output / "results", dirs_exist_ok=True)
    deep_scan_queue.write_queue(output / "index.json", queue_doc)
    counts = queue_doc.get("counts") if isinstance(queue_doc.get("counts"), dict) else {}
    return {
        "enabled": True,
        "publicationAuthority": False,
        "changed": str(queue_doc.get("queueRevision") or "") != str(previous.get("queueRevision") or ""),
        "pending": int(counts.get("pending") or 0),
        "blocked": int(counts.get("blocked") or 0),
        "complete": int(counts.get("complete") or 0),
        "queueRevision": str(queue_doc.get("queueRevision") or ""),
        "path": str(output / "index.json"),
        "sha256": sha256_file(output / "index.json"),
    }


def _frozen_advisory_path(definitions: Path, definitions_index: dict[str, Any]) -> Path:
    osv = definitions_index.get("osv") if isinstance(definitions_index.get("osv"), dict) else {}
    rel = str(osv.get("path") or "osv-advisories.json")
    path = definitions / rel
    if not path.is_file():
        raise ValueError(f"frozen advisory payload is missing: {rel}")
    return path


def _refresh_frozen_advisories(database: Path, work_dir: Path, definitions: Path, definitions_index: dict[str, Any]) -> dict[str, Any]:
    advisory_path = _frozen_advisory_path(definitions, definitions_index)
    advisory = _read(advisory_path)
    source_overrides = definitions / "worker" / "sources" / "source-overrides.json"
    args = _sigmascope_args(
        database, work_dir, report_name="sigmascope-merge-advisory-refresh.json",
        max_scans=0, max_batch_seconds=0, internal_names="", variant_ids="",
        advisories=advisory_path, source_overrides=source_overrides, skip_source=True,
    )
    sigmascope.run(args)
    index_root = work_dir / "osv-index"
    if index_root.exists():
        shutil.rmtree(index_root)
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        _entry, current_count = _export_nuget_index(db, index_root)
    nuget = _read(index_root / "indexes" / "nuget.json")
    current_pairs = {
        (str(item.get("name") or "").casefold(), str(item.get("version") or ""))
        for item in nuget.get("packages") or [] if isinstance(item, dict) and str(item.get("name") or "").strip() and str(item.get("version") or "").strip()
    }
    frozen_pairs = {
        (str(item.get("name") or "").casefold(), str(item.get("version") or ""))
        for item in advisory.get("queriedPackageVersionPairs") or [] if isinstance(item, dict) and str(item.get("name") or "").strip() and str(item.get("version") or "").strip()
    }
    queried = int(advisory.get("queriedPackages") or 0)
    if queried < len(frozen_pairs):
        raise ValueError("frozen OSV advisory payload is internally incomplete")
    covered = current_pairs & frozen_pairs
    uncovered = current_pairs - frozen_pairs
    summary = summarize_database(database)
    if int(summary.get("nugetPackageVersionPairs") or 0) != current_count:
        raise ValueError("merged NuGet projection does not match its exported exact package/version index")
    return {
        "generatedAtUtc": str(advisory.get("generatedAtUtc") or ""),
        "inputPackageVersionPairs": current_count,
        "expectedQueryPackageVersionPairs": len(covered),
        "queriedPackageVersionPairs": queried,
        "matchedPackageVersionPairs": int(advisory.get("matchedPackages") or 0),
        "advisoryRecords": len(advisory.get("advisories") or []),
        "notQueriedByLimit": 0,
        "notCoveredByFrozenDefinitions": len(uncovered),
        "definitionsRevision": str(definitions_index.get("definitionsRevision") or ""),
        "advisoryRevision": str(definitions_index.get("advisoryRevision") or ""),
        "mode": "frozen-definitions-serialized-merge",
        "queryGate": "pass",
    }


def merge(*, current_evidence: Path, base_database: Path, definitions: Path, bundle_roots: list[Path],
          candidate: Path, work_dir: Path, report: Path, previous_deep_scan_state: Path | None = None,
          deep_scan_output: Path | None = None, source_followup_output: Path | None = None) -> dict[str, Any]:
    current_evidence = current_evidence.resolve(); base_database = base_database.resolve(); definitions = definitions.resolve()
    candidate = candidate.resolve(); work_dir = work_dir.resolve(); report = report.resolve()
    if not bundle_roots or len(bundle_roots) > MAX_BUNDLES:
        raise ValueError(f"serialized SigmaScope merge requires 1..{MAX_BUNDLES} result bundles")
    plan_path = work_dir / "merge-plan.json"
    work_dir.mkdir(parents=True, exist_ok=True)
    plan = sigmascope_result_bundle.build_plan(bundle_roots, current_evidence=current_evidence, output=plan_path)
    docs = [sigmascope_result_bundle.validate(root, current_evidence=current_evidence) for root in bundle_roots]
    if len({int(doc["work"]["variantId"]) for doc in docs}) > MAX_VARIANTS:
        raise ValueError(f"serialized SigmaScope merge exceeds {MAX_VARIANTS} variants")
    definitions_index = _read(definitions / "index.json")
    expected_frozen = plan.get("frozen") if isinstance(plan.get("frozen"), dict) else {}
    actual_frozen = {
        "definitionsRevision": str(definitions_index.get("definitionsRevision") or ""),
        "scannerRevision": str(definitions_index.get("scannerRevision") or ""),
        "scannerBundleSha256": str((definitions_index.get("scannerBundle") or {}).get("sha256") or ""),
        "artifactAnalysisRevision": str(definitions_index.get("artifactAnalysisRevision") or ""),
        "sourceAnalysisRevision": str(definitions_index.get("sourceAnalysisRevision") or ""),
        "ruleSetRevision": str(definitions_index.get("ruleSetRevision") or ""),
        "advisoryRevision": str(definitions_index.get("advisoryRevision") or ""),
    }
    if _canonical(expected_frozen) != _canonical(actual_frozen):
        raise ValueError("serialized merger Definitions identity differs from result bundles")

    previous_index = _read(current_evidence / "index.json")
    _copy_evidence_tree(current_evidence, candidate)
    successful: set[int] = set()
    copied_derived = 0
    archive_count = 0
    for root, doc in zip(bundle_roots, docs):
        if str((doc.get("outcome") or {}).get("status") or "") != "complete":
            continue
        payload_root = root.resolve() / "payload"
        merged = _merge_successful_subset(candidate, payload_root)
        archive_count += int(merged.get("historicalSnapshotsArchived") or 0)
        copied_derived += _copy_derived_payload(payload_root, candidate)
        successful.add(int(doc["work"]["variantId"]))
    _prepare_transport_plugins_index(candidate, docs)

    work_database = work_dir / "omega-security-parallel-merge.sqlite"
    materialized = materialize_current_state(base_database, candidate, work_database, include_evidence=True)
    osv_coverage = _refresh_frozen_advisories(work_database, work_dir, definitions, definitions_index)
    sync_report = synchronize_candidate(candidate, work_database, successful)

    base_revisions = previous_index.get("revisions") if isinstance(previous_index.get("revisions"), dict) else {}
    queue_context = plan.get("queueContext") if isinstance(plan.get("queueContext"), dict) else {}
    scan_context = {
        "previousIndexSha256": sha256_file(current_evidence / "index.json"),
        "selected": len(docs),
        "successful": len(successful),
        "failedRetained": sum(1 for doc in docs if str((doc.get("outcome") or {}).get("status") or "") != "complete"),
        "failedVariantIds": sorted(int(doc["work"]["variantId"]) for doc in docs if str((doc.get("outcome") or {}).get("status") or "") != "complete"),
        "maxScans": len(docs),
        "catalogDataRevision": str(queue_context.get("catalogRevision") or base_revisions.get("catalogDataRevision") or ""),
        "catalogIdentityEpoch": str(queue_context.get("catalogIdentityEpoch") or base_revisions.get("catalogIdentityEpoch") or ""),
        "baselineSecurityRebuild": False,
        "definitionsRevision": str(definitions_index.get("definitionsRevision") or ""),
        "advisoryRevision": str(definitions_index.get("advisoryRevision") or ""),
        "scannerRevision": str(definitions_index.get("scannerRevision") or ""),
        "scannerBundleSha256": str((definitions_index.get("scannerBundle") or {}).get("sha256") or ""),
        "artifactAnalysisRevision": str(definitions_index.get("artifactAnalysisRevision") or ""),
        "sourceAnalysisRevision": str(definitions_index.get("sourceAnalysisRevision") or ""),
        "ruleSetRevision": str(definitions_index.get("ruleSetRevision") or ""),
        "parallelResultMerge": True,
        "bundleRevisions": sorted(str(doc.get("bundleRevision") or "") for doc in docs),
    }
    definition_provenance = materialize_definition_provenance_index(candidate, definitions)
    threat_intelligence = materialize_threat_intelligence_index(candidate, definitions)
    root_index = rebuild_candidate_indexes(candidate, work_database, previous_index, scan_context, osv_coverage, definition_provenance or None)
    if threat_intelligence:
        root_index.setdefault("indexes", {})["threatIntelligence"] = threat_intelligence
        root_index.setdefault("revisions", {})["reputationRevision"] = str(threat_intelligence.get("reputationRevision") or "")
        root_index.setdefault("source", {})["reputationRevision"] = str(threat_intelligence.get("reputationRevision") or "")
        write_json(candidate / "index.json", root_index)

    queue_state, dynamic_source_followups = _merge_queue(current_evidence, docs, _current_rows(work_database))
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

    source_followups = _project_source_followups(
        work_database, (source_followup_output or (work_dir / "sigmascope-source-followups.json")).resolve()
    )
    deep_scan = _project_deep_scan_queue(
        candidate, srl, previous_deep_scan_state.resolve() if previous_deep_scan_state else None,
        (deep_scan_output or (work_dir / "deep-scan-state")).resolve(),
    )

    validation = validate_snapshot(candidate, require_no_orphans=True)
    write_json(candidate / "validation-report.json", validation)
    if not validation.get("ok"):
        raise ValueError("serialized parallel merge candidate failed Evidence-v2 validation: " + "; ".join(validation.get("errors") or []))

    result: dict[str, Any] = {
        "schema": SCHEMA,
        "generatedAtUtc": _utc_now(),
        "authority": "candidate-only-no-evidence-publication",
        "baseIndexSha256": sha256_file(current_evidence / "index.json"),
        "mergePlanRevision": str(plan.get("planRevision") or ""),
        "bundleRevisions": sorted(str(doc.get("bundleRevision") or "") for doc in docs),
        "variantIds": sorted(int(doc["work"]["variantId"]) for doc in docs),
        "successfulVariantIds": sorted(successful),
        "candidateIndexSha256": sha256_file(candidate / "index.json"),
        "candidateRevisions": dict(root_index.get("revisions") or {}),
        "queueSummary": scan_queue.state_summary(queue_state),
        "materialized": materialized,
        "synchronize": {**sync_report, "historicalSnapshotsArchivedByBundleApply": archive_count, "derivedFilesCopiedBeforeMaterialization": copied_derived},
        "osvCoverage": osv_coverage,
        "srlReprojection": {key: value for key, value in srl.items() if key != "validation"},
        "sideEffects": {
            "dynamicSourceQueueKeys": dynamic_source_followups,
            "sourceFollowups": source_followups,
            "deepScan": deep_scan,
        },
        "validation": {"ok": True, "errors": []},
        "deferredSideEffects": ["deep-scan-queue-publication", "source-followup-issue-reconciliation", "Evidence-v2-publication"],
    }
    semantic = {key: value for key, value in result.items() if key not in {"generatedAtUtc", "mergeRevision"}}
    result["mergeRevision"] = f"sigmascope-merge-v1-{_digest(semantic)[:20]}"
    report.parent.mkdir(parents=True, exist_ok=True)
    write_json(report, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-evidence", required=True, type=Path)
    parser.add_argument("--base-database", required=True, type=Path)
    parser.add_argument("--definitions-root", required=True, type=Path)
    parser.add_argument("--candidate-evidence", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--previous-deep-scan-state", type=Path)
    parser.add_argument("--deep-scan-output", type=Path)
    parser.add_argument("--source-followup-output", type=Path)
    parser.add_argument("bundles", nargs="+", type=Path)
    args = parser.parse_args()
    result = merge(
        current_evidence=args.current_evidence, base_database=args.base_database, definitions=args.definitions_root,
        bundle_roots=args.bundles, candidate=args.candidate_evidence, work_dir=args.work_dir, report=args.report,
        previous_deep_scan_state=args.previous_deep_scan_state, deep_scan_output=args.deep_scan_output,
        source_followup_output=args.source_followup_output,
    )
    print(json.dumps({
        "schema": result["schema"], "mergeRevision": result["mergeRevision"],
        "variantIds": result["variantIds"], "candidateIndexSha256": result["candidateIndexSha256"],
        "authority": result["authority"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
