"""Deterministic rule-only SRL reprojection over retained Security Evidence v2.

Phase 10 separates a pure rule/Definition change from artifact/source analysis.  The
planner reads only immutable SRL-eligible observation collections plus their retained
observation contract.  It never opens plugin artifacts, never treats legacy findings as
inputs, and never mutates the production Security Evidence v2 tree.

Compatible variants can be materialized as a deterministic SRL projection set.  A
variant whose retained observations cannot satisfy the new ruleset is returned as a
precise re-analysis request naming the missing/bounded collection(s).  The requests are
queue-ready data only: this module intentionally does not mutate the production queue
while ``productionRuleEvaluationEnabled`` remains false.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Iterable, Mapping

try:
    from . import definition_packs, observation_projection, reputation_intelligence, security_evidence_v2, srl
except ImportError:  # direct script/import from tools/security
    import definition_packs  # type: ignore
    import observation_projection  # type: ignore
    import reputation_intelligence  # type: ignore
    import security_evidence_v2  # type: ignore
    import srl  # type: ignore

PLAN_SCHEMA = "omega.sigmascope.rule-reprojection-plan.v1"
PROJECTION_SCHEMA = "omega.sigmascope.srl-rule-projection.v1"
PROJECTION_SET_SCHEMA = "omega.sigmascope.srl-rule-projection-set.v1"
REANALYSIS_SCHEMA = "omega.sigmascope.srl-reanalysis-request.v1"
ENGINE_REVISION = "rule-reprojection-v1"
MAX_VARIANTS = 100_000


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _required_collections(compiled_ruleset: Mapping[str, Any]) -> list[str]:
    return sorted({
        str(name)
        for rule in compiled_ruleset.get("rules") or []
        if isinstance(rule, Mapping)
        for name in rule.get("requires") or []
        if str(name)
    })


def _report(payload: Mapping[str, Any]) -> dict[str, Any]:
    for key in ("current", "scan"):
        row = payload.get(key) if isinstance(payload.get(key), Mapping) else {}
        raw = row.get("report_json") if isinstance(row, Mapping) else None
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        if isinstance(raw, dict) and raw:
            return raw
    return {}


def _analysis_manifest(evidence_root: Path, analysis_path: str) -> dict[str, Any]:
    if not analysis_path:
        return {}
    return security_evidence_v2.read_json_file(
        evidence_root, f"{security_evidence_v2.safe_relpath(analysis_path)}/manifest.json"
    )


def _observation_contract(payload: Mapping[str, Any], manifest: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    report = _report(payload)
    declared = payload.get("observations") if isinstance(payload.get("observations"), Mapping) else None
    if declared is None:
        # Historical v2 can be adapted from immutable datasets plus bounded compact
        # report inputs.  The builder never consumes legacy findings/projections.
        return observation_projection.build_variant_observation_contract(dict(manifest), report), []
    errors = observation_projection.validation_errors(dict(payload), dict(manifest))
    return dict(declared), [str(item) for item in errors]


def _load_required_observations(
    evidence_root: Path,
    analysis_path: str,
    payload: Mapping[str, Any],
    contract: Mapping[str, Any],
    required: Iterable[str],
) -> dict[str, list[dict[str, Any]]]:
    manifest = _analysis_manifest(evidence_root, analysis_path)
    datasets = manifest.get("datasets") if isinstance(manifest.get("datasets"), Mapping) else {}
    report_rows = observation_projection.report_observation_rows(_report(payload))
    declared = contract.get("collections") if isinstance(contract.get("collections"), Mapping) else {}
    result: dict[str, list[dict[str, Any]]] = {}
    for collection in sorted({str(item) for item in required if str(item)}):
        item = declared.get(collection) if isinstance(declared.get(collection), Mapping) else None
        if item is None:
            continue
        backing = str(item.get("backingDataset") or "")
        spec = observation_projection.COLLECTIONS.get(collection) or {}
        dataset = str(spec.get("backingDataset") or backing or collection)
        if isinstance(datasets.get(dataset), Mapping):
            result[collection] = security_evidence_v2.read_dataset_rows(evidence_root, analysis_path, dataset)
            continue
        # Retained-summary compatibility inputs are carried inside the bounded variant
        # descriptor.  Exact replay deliberately refuses bounded-transport collections
        # in observation_projection.replay_audit before these rows are evaluated.
        if backing in {"compact-report", ""} and collection in report_rows:
            result[collection] = [dict(row) for row in report_rows.get(collection) or []]
    return result


def projection_revision(
    compiled_ruleset: Mapping[str, Any],
    observation_contract: Mapping[str, Any],
    required_collections: Iterable[str],
    reputation_revision: str = "",
) -> str:
    semantic = {
        "schema": PROJECTION_SCHEMA,
        "engineRevision": ENGINE_REVISION,
        "ruleSetRevision": str(compiled_ruleset.get("ruleSetRevision") or ""),
        "observationContractRevision": str(observation_contract.get("contractRevision") or ""),
        "observationDigest": str(observation_contract.get("observationDigest") or ""),
        "requiredCollections": sorted({str(item) for item in required_collections if str(item)}),
        "reputationRevision": str(reputation_revision or ""),
    }
    return f"srl-projection-v1-{_sha(semantic)[:24]}"


def _reanalysis_request(
    *,
    variant_id: int,
    analysis_id: str,
    analysis_path: str,
    rule_set_revision: str,
    audit: Mapping[str, Any] | None = None,
    reason: str,
) -> dict[str, Any]:
    replay = dict(audit or {})
    missing = sorted({str(item) for item in replay.get("missingCollections") or [] if str(item)})
    bounded = sorted({str(item) for item in replay.get("boundedCompatibilityCollections") or [] if str(item)})
    forbidden = sorted({str(item) for item in replay.get("forbiddenDerivedInputs") or [] if str(item)})
    precise: list[str] = []
    precise.extend(f"missing observation collection {item}" for item in missing)
    precise.extend(f"observation collection {item} is only available as bounded historical transport" for item in bounded)
    precise.extend(f"rule requires forbidden derived input {item}" for item in forbidden)
    if not precise and reason:
        precise.append(reason)
    affected = missing + bounded
    origins = {str((observation_projection.COLLECTIONS.get(name) or {}).get("origin") or "") for name in affected}
    work_type = "source" if affected and origins and all(origin == "source" for origin in origins) else "artifact"
    return {
        "schema": REANALYSIS_SCHEMA,
        "variantId": int(variant_id),
        "analysisId": analysis_id,
        "analysisPath": analysis_path,
        "ruleSetRevision": rule_set_revision,
        "workType": work_type,
        "reason": precise[0] if precise else "retained observations are not replay-compatible",
        "reasons": precise,
        "missingCollections": missing,
        "boundedCompatibilityCollections": bounded,
        "forbiddenDerivedInputs": forbidden,
        "queueMutationAuthorized": False,
    }


def reproject_variant(
    evidence_root: Path,
    entry: Mapping[str, Any],
    payload: Mapping[str, Any],
    compiled_ruleset: Mapping[str, Any],
    reputation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    variant_id = int(payload.get("variantId") or entry.get("variantId") or 0)
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
    analysis_id = str(analysis.get("analysisId") or entry.get("analysisId") or "")
    analysis_path = str(analysis.get("path") or "")
    rule_set_revision = str(compiled_ruleset.get("ruleSetRevision") or "")
    required = _required_collections(compiled_ruleset)
    base = {
        "variantId": variant_id,
        "analysisId": analysis_id,
        "analysisPath": analysis_path,
        "ruleSetRevision": rule_set_revision,
        "requiredCollections": required,
        "reprojected": False,
        "reanalysisRequired": False,
        "auditError": False,
        "reason": "",
    }
    if not analysis_path:
        request = _reanalysis_request(
            variant_id=variant_id, analysis_id=analysis_id, analysis_path=analysis_path,
            rule_set_revision=rule_set_revision, reason="variant has no retained immutable analysis",
        )
        return {**base, "reanalysisRequired": True, "reason": request["reason"], "reanalysisRequest": request}

    try:
        manifest = _analysis_manifest(evidence_root, analysis_path)
        contract, contract_errors = _observation_contract(payload, manifest)
        if contract_errors:
            return {
                **base,
                "auditError": True,
                "reason": "retained observation contract failed validation: " + "; ".join(contract_errors)[:1500],
            }
        audit = observation_projection.replay_audit(contract, required)
        if not audit.get("reusableWithoutRescan"):
            request = _reanalysis_request(
                variant_id=variant_id, analysis_id=analysis_id, analysis_path=analysis_path,
                rule_set_revision=rule_set_revision, audit=audit, reason=str(audit.get("reason") or ""),
            )
            return {
                **base,
                "reanalysisRequired": True,
                "reason": request["reason"],
                "replayAudit": audit,
                "reanalysisRequest": request,
            }
        observations = _load_required_observations(evidence_root, analysis_path, payload, contract, required)
        if "networkEndpoints" in observations:
            observations["networkEndpoints"] = reputation_intelligence.enrich_network_endpoints(
                observations["networkEndpoints"], reputation
            )
        evaluation = srl.evaluate_ruleset(compiled_ruleset, observations, observation_contract=contract)
    except Exception as exc:
        return {
            **base,
            "auditError": True,
            "reason": f"retained evidence could not be verified/read: {type(exc).__name__}: {exc}"[:1500],
        }

    replay = evaluation.get("replayAudit") if isinstance(evaluation.get("replayAudit"), Mapping) else {}
    if not evaluation.get("evaluated"):
        request = _reanalysis_request(
            variant_id=variant_id, analysis_id=analysis_id, analysis_path=analysis_path,
            rule_set_revision=rule_set_revision, audit=replay, reason=str(replay.get("reason") or ""),
        )
        return {
            **base,
            "reanalysisRequired": True,
            "reason": request["reason"],
            "replayAudit": dict(replay),
            "reanalysisRequest": request,
        }

    reputation_rev = reputation_intelligence.reputation_revision(reputation)
    revision = projection_revision(compiled_ruleset, contract, required, reputation_rev)
    findings = [dict(item) for item in evaluation.get("findings") or [] if isinstance(item, Mapping)]
    analysis_requests = [dict(item) for item in evaluation.get("analysisRequests") or [] if isinstance(item, Mapping)]
    for request in analysis_requests:
        request["variantId"] = variant_id
        request["analysisId"] = analysis_id
        request["ruleSetRevision"] = rule_set_revision
        request["queueMutationScope"] = "deep-scan-evidence-acquisition"
    analysis_requests.sort(key=lambda item: (str(item.get("ruleId") or ""), str(item.get("profile") or "")))
    findings.sort(key=lambda item: (str(item.get("ruleId") or ""), str(item.get("findingId") or "")))
    facts = sorted({str(item) for item in evaluation.get("facts") or [] if str(item)})
    matched_rules = sorted({
        str(item.get("ruleId") or "")
        for item in evaluation.get("rules") or []
        if isinstance(item, Mapping) and bool(item.get("matched")) and str(item.get("ruleId") or "")
    })
    semantic_outputs = {"facts": facts, "findings": findings, "matchedRuleIds": matched_rules, "analysisRequests": analysis_requests}
    projection = {
        "schema": PROJECTION_SCHEMA,
        "engineRevision": ENGINE_REVISION,
        "variantId": variant_id,
        "analysisId": analysis_id,
        "analysisPath": analysis_path,
        "ruleSetRevision": rule_set_revision,
        "observationContractRevision": str(contract.get("contractRevision") or ""),
        "observationDigest": str(contract.get("observationDigest") or ""),
        "requiredCollections": required,
        "reputationRevision": reputation_rev,
        "projectionRevision": revision,
        "projectionDigest": f"srl-output-{_sha(semantic_outputs)}",
        "facts": facts,
        "findings": findings,
        "analysisRequests": analysis_requests,
        "matchedRuleIds": matched_rules,
        "productionWriteBack": False,
    }
    return {
        **base,
        "reprojected": True,
        "reason": "compatible retained observations",
        "replayAudit": dict(replay),
        "projection": projection,
    }


def plan_reprojection(
    evidence_root: Path,
    compiled_ruleset: Mapping[str, Any],
    *,
    reputation: Mapping[str, Any] | None = None,
    variant_ids: Iterable[int] | None = None,
    limit: int = 0,
) -> dict[str, Any]:
    evidence_root = evidence_root.resolve()
    index_path = evidence_root / "index.json"
    index = security_evidence_v2.read_json_file(evidence_root, "index.json")
    if str(index.get("schema") or "") != security_evidence_v2.SCHEMA:
        raise ValueError(f"unsupported evidence schema: {index.get('schema')!r}")
    selected = {int(item) for item in variant_ids or [] if int(item) > 0}
    required = _required_collections(compiled_ruleset)
    results: list[dict[str, Any]] = []
    projections: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    deep_requests: list[dict[str, Any]] = []
    max_count = min(MAX_VARIANTS, max(0, int(limit))) if limit else MAX_VARIANTS
    for entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        variant_id = int(payload.get("variantId") or entry.get("variantId") or 0)
        if selected and variant_id not in selected:
            continue
        result = reproject_variant(evidence_root, entry, payload, compiled_ruleset, reputation)
        results.append(result)
        if isinstance(result.get("projection"), Mapping):
            projections.append(dict(result["projection"]))
        if isinstance(result.get("reanalysisRequest"), Mapping):
            requests.append(dict(result["reanalysisRequest"]))
        projection = result.get("projection") if isinstance(result.get("projection"), Mapping) else {}
        deep_requests.extend(dict(item) for item in projection.get("analysisRequests") or [] if isinstance(item, Mapping))
        if len(results) >= max_count:
            break
    projected = len(projections)
    reanalysis = len(requests)
    errors = sum(1 for item in results if item.get("auditError"))
    revisions = index.get("revisions") if isinstance(index.get("revisions"), Mapping) else {}
    semantic = {
        "schema": PROJECTION_SET_SCHEMA,
        "engineRevision": ENGINE_REVISION,
        "ruleSetRevision": str(compiled_ruleset.get("ruleSetRevision") or ""),
        "reputationRevision": reputation_intelligence.reputation_revision(reputation),
        "observationContractRevision": observation_projection.contract_revision(),
        "sourceEvidenceIndexSha256": _sha_file(index_path),
        "requiredCollections": required,
        "projectionRevisions": sorted(str(item.get("projectionRevision") or "") for item in projections),
        "reanalysisRequests": requests,
        "analysisRequests": deep_requests,
    }
    set_revision = f"srl-projection-set-v1-{_sha(semantic)[:24]}"
    return {
        "schema": PLAN_SCHEMA,
        "engineRevision": ENGINE_REVISION,
        "ruleSetRevision": str(compiled_ruleset.get("ruleSetRevision") or ""),
        "reputationRevision": reputation_intelligence.reputation_revision(reputation),
        "observationContractRevision": observation_projection.contract_revision(),
        "sourceEvidenceIndexSha256": _sha_file(index_path),
        "sourceEvidenceRevision": str(revisions.get("evidenceRevision") or ""),
        "requiredCollections": required,
        "projectionSetRevision": set_revision,
        "productionRuleEvaluationEnabled": False,
        "productionWriteBack": False,
        "queueMutationAuthorized": False,
        "deepScanQueueMutationAuthorized": True,
        "checkedVariants": len(results),
        "reprojectedVariants": projected,
        "reanalysisRequiredVariants": reanalysis,
        "auditErrorVariants": errors,
        "auditOk": errors == 0,
        "allVariantsReprojectable": bool(results) and projected == len(results) and not reanalysis and not errors,
        "variants": results,
        "projections": projections,
        "reanalysisRequests": requests,
        "analysisRequests": deep_requests,
    }


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def materialize_projection_set(output: Path, plan: Mapping[str, Any]) -> dict[str, Any]:
    """Write a deterministic, non-production SRL projection set atomically."""
    if str(plan.get("schema") or "") != PLAN_SCHEMA:
        raise ValueError("unsupported reprojection plan schema")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=output.name + ".", dir=output.parent))
    try:
        variant_entries: list[dict[str, Any]] = []
        for projection in sorted(
            (dict(item) for item in plan.get("projections") or [] if isinstance(item, Mapping)),
            key=lambda item: int(item.get("variantId") or 0),
        ):
            variant_id = int(projection.get("variantId") or 0)
            rel = Path("variants") / f"{variant_id}.json"
            path = staging / rel
            _write_json(path, projection)
            variant_entries.append({
                "variantId": variant_id,
                "path": rel.as_posix(),
                "bytes": path.stat().st_size,
                "sha256": _sha_file(path),
                "projectionRevision": str(projection.get("projectionRevision") or ""),
            })
        requests = [dict(item) for item in plan.get("reanalysisRequests") or [] if isinstance(item, Mapping)]
        _write_json(staging / "reanalysis-requests.json", {
            "schema": "omega.sigmascope.srl-reanalysis-requests.v1",
            "ruleSetRevision": str(plan.get("ruleSetRevision") or ""),
            "requests": requests,
            "queueMutationAuthorized": False,
        })
        request_entry = {
            "path": "reanalysis-requests.json",
            "bytes": (staging / "reanalysis-requests.json").stat().st_size,
            "sha256": _sha_file(staging / "reanalysis-requests.json"),
            "records": len(requests),
        }
        deep_requests = [dict(item) for item in plan.get("analysisRequests") or [] if isinstance(item, Mapping)]
        _write_json(staging / "analysis-requests.json", {
            "schema": "omega.stigma-1.analysis-requests.v1",
            "ruleSetRevision": str(plan.get("ruleSetRevision") or ""),
            "requests": deep_requests,
            "queueMutationScope": "deep-scan-evidence-acquisition-only",
            "productionFindingsWriteBack": False,
        })
        deep_request_entry = {
            "path": "analysis-requests.json",
            "bytes": (staging / "analysis-requests.json").stat().st_size,
            "sha256": _sha_file(staging / "analysis-requests.json"),
            "records": len(deep_requests),
        }
        index = {
            "schema": PROJECTION_SET_SCHEMA,
            "engineRevision": ENGINE_REVISION,
            "projectionSetRevision": str(plan.get("projectionSetRevision") or ""),
            "ruleSetRevision": str(plan.get("ruleSetRevision") or ""),
            "reputationRevision": str(plan.get("reputationRevision") or ""),
            "observationContractRevision": str(plan.get("observationContractRevision") or ""),
            "sourceEvidenceIndexSha256": str(plan.get("sourceEvidenceIndexSha256") or ""),
            "sourceEvidenceRevision": str(plan.get("sourceEvidenceRevision") or ""),
            "requiredCollections": list(plan.get("requiredCollections") or []),
            "productionRuleEvaluationEnabled": False,
            "productionWriteBack": False,
            "queueMutationAuthorized": False,
            "deepScanQueueMutationAuthorized": True,
            "counts": {
                "checkedVariants": int(plan.get("checkedVariants") or 0),
                "reprojectedVariants": int(plan.get("reprojectedVariants") or 0),
                "reanalysisRequiredVariants": int(plan.get("reanalysisRequiredVariants") or 0),
                "auditErrorVariants": int(plan.get("auditErrorVariants") or 0),
            },
            "variants": variant_entries,
            "reanalysisRequests": request_entry,
            "analysisRequests": deep_request_entry,
        }
        _write_json(staging / "index.json", index)
        if output.exists():
            shutil.rmtree(output)
        staging.replace(output)
        return index
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def verify_projection_set(root: Path) -> dict[str, Any]:
    root = root.resolve()
    errors: list[str] = []
    try:
        index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    except Exception as exc:
        return {"schema": "omega.sigmascope.srl-rule-projection-validation.v1", "ok": False, "errors": [f"index could not be read: {exc}"]}
    if str(index.get("schema") or "") != PROJECTION_SET_SCHEMA:
        errors.append("projection set schema is invalid")
    if bool(index.get("productionRuleEvaluationEnabled")) or bool(index.get("productionWriteBack")) or bool(index.get("queueMutationAuthorized")):
        errors.append("projection set crosses the non-production Phase-10 boundary")
    seen: set[int] = set()
    for entry in index.get("variants") or []:
        if not isinstance(entry, Mapping):
            errors.append("variant projection descriptor is malformed")
            continue
        variant_id = int(entry.get("variantId") or 0)
        if variant_id <= 0 or variant_id in seen:
            errors.append(f"invalid/duplicate projected variant id {variant_id}")
            continue
        seen.add(variant_id)
        try:
            rel = security_evidence_v2.safe_relpath(str(entry.get("path") or ""))
            path = root / rel
            if not path.is_file():
                raise FileNotFoundError(rel)
            if path.stat().st_size != int(entry.get("bytes") or -1):
                errors.append(f"size mismatch for {rel}")
            if _sha_file(path) != str(entry.get("sha256") or ""):
                errors.append(f"sha256 mismatch for {rel}")
            projection = json.loads(path.read_text(encoding="utf-8"))
            if str(projection.get("schema") or "") != PROJECTION_SCHEMA:
                errors.append(f"invalid projection schema for {rel}")
            if str(projection.get("ruleSetRevision") or "") != str(index.get("ruleSetRevision") or ""):
                errors.append(f"ruleset mismatch for {rel}")
            if bool(projection.get("productionWriteBack")):
                errors.append(f"production write-back flag set in {rel}")
        except Exception as exc:
            errors.append(f"projection {variant_id} could not be verified: {type(exc).__name__}: {exc}")
    request = index.get("reanalysisRequests") if isinstance(index.get("reanalysisRequests"), Mapping) else {}
    try:
        rel = security_evidence_v2.safe_relpath(str(request.get("path") or ""))
        path = root / rel
        if not path.is_file():
            raise FileNotFoundError(rel)
        if path.stat().st_size != int(request.get("bytes") or -1):
            errors.append(f"size mismatch for {rel}")
        if _sha_file(path) != str(request.get("sha256") or ""):
            errors.append(f"sha256 mismatch for {rel}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if bool(payload.get("queueMutationAuthorized")):
            errors.append("reanalysis request set authorizes queue mutation")
    except Exception as exc:
        errors.append(f"reanalysis request set could not be verified: {type(exc).__name__}: {exc}")

    raw_deep_request = index.get("analysisRequests")
    if raw_deep_request is not None:
        if not isinstance(raw_deep_request, Mapping):
            errors.append("analysis request set descriptor is malformed")
        else:
            deep_request = dict(raw_deep_request)
            try:
                rel = security_evidence_v2.safe_relpath(str(deep_request.get("path") or ""))
                path = root / rel
                if not path.is_file():
                    raise FileNotFoundError(rel)
                if path.stat().st_size != int(deep_request.get("bytes") or -1):
                    errors.append(f"size mismatch for {rel}")
                if _sha_file(path) != str(deep_request.get("sha256") or ""):
                    errors.append(f"sha256 mismatch for {rel}")
                payload = json.loads(path.read_text(encoding="utf-8"))
                if str(payload.get("schema") or "") != "omega.stigma-1.analysis-requests.v1":
                    errors.append("analysis request set schema is invalid")
                if str(payload.get("queueMutationScope") or "") != "deep-scan-evidence-acquisition-only":
                    errors.append("analysis request set has an invalid queue mutation scope")
                if bool(payload.get("productionFindingsWriteBack")):
                    errors.append("analysis request set enables production findings write-back")
                expected = int(deep_request.get("records") or 0)
                actual = len(payload.get("requests") or []) if isinstance(payload.get("requests"), list) else -1
                if expected != actual:
                    errors.append(f"analysis request count mismatch: index={expected}, actual={actual}")
            except Exception as exc:
                errors.append(f"analysis request set could not be verified: {type(exc).__name__}: {exc}")
    return {
        "schema": "omega.sigmascope.srl-rule-projection-validation.v1",
        "ok": not errors,
        "projectionSetRevision": str(index.get("projectionSetRevision") or ""),
        "ruleSetRevision": str(index.get("ruleSetRevision") or ""),
        "projectedVariants": len(seen),
        "errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan/materialize rule-only SRL reprojection over retained Evidence-v2")
    parser.add_argument("--evidence-v2", type=Path, required=True)
    parser.add_argument("--packs-root", type=Path, default=Path(__file__).resolve().parents[2] / "security-definitions" / "packs")
    parser.add_argument("--variant-id", type=int, action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strict", action="store_true", help="exit 3 when targeted re-analysis is required")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    compiled = definition_packs.compile_pack_root(args.packs_root.resolve())["compiledRuleSet"]
    plan = plan_reprojection(args.evidence_v2.resolve(), compiled, variant_ids=args.variant_id, limit=args.limit)
    result: dict[str, Any] = dict(plan)
    if args.output:
        index = materialize_projection_set(args.output.resolve(), plan)
        result["materialized"] = {"path": str(args.output.resolve()), "index": index, "validation": verify_projection_set(args.output.resolve())}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    if not plan.get("auditOk"):
        return 2
    if args.strict and int(plan.get("reanalysisRequiredVariants") or 0) > 0:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
