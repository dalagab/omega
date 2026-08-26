"""Replay reviewed Phase-7 SRL migration rules against retained Security Evidence v2.

The replay consumes only collections declared SRL-eligible by the observation contract.
Legacy ``findings`` rows are read solely as a comparison baseline; they are never passed
into the SRL evaluator.  A variant that lacks a required retained collection is marked
``rescanRequired`` rather than being reconstructed from a current projection.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    from . import collector_results, definition_packs, observation_projection, security_evidence_v2, srl, srl_migration_parity
except ImportError:  # direct script/import from tools/security
    import collector_results  # type: ignore
    import definition_packs  # type: ignore
    import observation_projection  # type: ignore
    import security_evidence_v2  # type: ignore
    import srl  # type: ignore
    import srl_migration_parity  # type: ignore

REPLAY_SCHEMA = "omega.sigmascope.srl-evidence-replay.v1"


def _finding_rule_id(row: Mapping[str, Any]) -> str:
    return str(row.get("ruleId") or row.get("rule_id") or row.get("findingId") or "")


def _normalized_compound(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        rule_id = _finding_rule_id(row)
        if rule_id not in srl_migration_parity.MIGRATED_FINDING_IDS:
            continue
        evidence = row.get("evidence")
        if evidence is None:
            evidence = row.get("evidence_json")
        if not isinstance(evidence, list):
            evidence = []
        result.append({
            "ruleId": rule_id,
            "severity": str(row.get("severity") or ""),
            "category": str(row.get("category") or ""),
            "title": str(row.get("title") or ""),
            "description": str(row.get("description") or ""),
            "evidence": list(evidence),
        })
    result.sort(key=lambda item: item["ruleId"])
    return result


def _required_collections(compiled_ruleset: Mapping[str, Any]) -> list[str]:
    return sorted({
        str(name)
        for rule in compiled_ruleset.get("rules") or []
        if isinstance(rule, Mapping)
        for name in rule.get("requires") or []
        if str(name)
    })


def _load_observations(
    evidence_root: Path,
    analysis_path: str,
    required: Iterable[str],
    *,
    variant_payload: Mapping[str, Any] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    manifest = security_evidence_v2.read_json_file(evidence_root, f"{security_evidence_v2.safe_relpath(analysis_path)}/manifest.json")
    datasets = manifest.get("datasets") if isinstance(manifest.get("datasets"), dict) else {}
    observations: dict[str, list[dict[str, Any]]] = {}
    variant_contract = (variant_payload or {}).get("observations") if isinstance((variant_payload or {}).get("observations"), Mapping) else {}
    variant_collections = variant_contract.get("collections") if isinstance(variant_contract.get("collections"), Mapping) else {}
    for collection in required:
        spec = observation_projection.COLLECTIONS.get(collection) or {}
        if spec:
            dataset = str(spec.get("backingDataset") or collection)
            descriptor = datasets.get(dataset) if isinstance(datasets.get(dataset), dict) else None
            if descriptor is not None:
                observations[collection] = security_evidence_v2.read_dataset_rows(evidence_root, analysis_path, dataset)
                continue
        external = variant_collections.get(collection) if isinstance(variant_collections.get(collection), Mapping) else None
        result_path = str((external or {}).get("resultPath") or "")
        if result_path:
            result = security_evidence_v2.read_json_file(evidence_root, security_evidence_v2.safe_relpath(result_path))
            observations[collection] = collector_results.rows_from_result(result, collection)  # type: ignore[assignment]
    return observations


def replay_variant(
    evidence_root: Path,
    entry: Mapping[str, Any],
    payload: Mapping[str, Any],
    compiled_ruleset: Mapping[str, Any],
) -> dict[str, Any]:
    variant_id = int(payload.get("variantId") or entry.get("variantId") or 0)
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
    analysis_path = str(analysis.get("path") or "")
    analysis_id = str(analysis.get("analysisId") or "")
    base = {
        "variantId": variant_id,
        "analysisId": analysis_id,
        "analysisPath": analysis_path,
        "matched": False,
        "evaluated": False,
        "rescanRequired": False,
        "auditError": False,
        "reason": "",
    }
    if not analysis_path:
        return {**base, "rescanRequired": True, "reason": "variant has no retained immutable analysis"}

    required = _required_collections(compiled_ruleset)
    try:
        observations = _load_observations(evidence_root, analysis_path, required, variant_payload=payload)
        contract = payload.get("observations") if isinstance(payload.get("observations"), Mapping) else {}
        evaluation = srl.evaluate_ruleset(compiled_ruleset, observations, observation_contract=contract)
    except Exception as exc:
        return {
            **base,
            "auditError": True,
            "reason": f"retained evidence could not be verified/read: {type(exc).__name__}: {exc}"[:1000],
        }

    replay_audit = evaluation.get("replayAudit") if isinstance(evaluation.get("replayAudit"), Mapping) else {}
    if not evaluation.get("evaluated"):
        reason = str(replay_audit.get("reason") or "required observations are not replay-compatible")
        return {
            **base,
            "rescanRequired": bool(replay_audit.get("rescanRequired", True)),
            "reason": reason,
            "replayAudit": dict(replay_audit),
        }

    try:
        manifest = security_evidence_v2.read_json_file(
            evidence_root, f"{security_evidence_v2.safe_relpath(analysis_path)}/manifest.json"
        )
        datasets = manifest.get("datasets") if isinstance(manifest.get("datasets"), Mapping) else {}
        if not isinstance(datasets.get("findings"), Mapping):
            raise RuntimeError("baseline findings dataset is not retained")
        baseline_rows = security_evidence_v2.read_dataset_rows(evidence_root, analysis_path, "findings")
    except Exception as exc:
        return {
            **base,
            "auditError": True,
            "reason": f"baseline findings could not be verified/read: {type(exc).__name__}: {exc}"[:1000],
        }

    baseline_rule_ids = {_finding_rule_id(row) for row in baseline_rows}
    baseline_facts = sorted(rule_id for rule_id in srl_migration_parity.PRIMITIVE_FACT_IDS if rule_id in baseline_rule_ids)
    srl_facts = sorted(str(fact) for fact in evaluation.get("facts") or [] if str(fact) in srl_migration_parity.PRIMITIVE_FACT_IDS)
    baseline_compound = _normalized_compound(baseline_rows)
    srl_compound = _normalized_compound(item for item in evaluation.get("findings") or [] if isinstance(item, Mapping))
    primitive_match = baseline_facts == srl_facts
    compound_match = baseline_compound == srl_compound
    return {
        **base,
        "evaluated": True,
        "rescanRequired": False,
        "matched": primitive_match and compound_match,
        "reason": "" if primitive_match and compound_match else "retained observation replay differs from legacy projection baseline",
        "baselinePrimitiveFacts": baseline_facts,
        "srlPrimitiveFacts": srl_facts,
        "baselineCompoundFindings": baseline_compound,
        "srlCompoundFindings": srl_compound,
        "primitiveMatched": primitive_match,
        "compoundMatched": compound_match,
        "replayAudit": dict(replay_audit),
    }


def replay_evidence_root(
    evidence_root: Path,
    compiled_ruleset: Mapping[str, Any],
    *,
    variant_ids: Iterable[int] | None = None,
    limit: int = 0,
) -> dict[str, Any]:
    evidence_root = evidence_root.resolve()
    selected = {int(item) for item in variant_ids or [] if int(item) > 0}
    results: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()
    for entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        variant_id = int(payload.get("variantId") or entry.get("variantId") or 0)
        if selected and variant_id not in selected:
            continue
        result = replay_variant(evidence_root, entry, payload, compiled_ruleset)
        results.append(result)
        if result.get("reason"):
            reasons[str(result["reason"])] += 1
        if limit > 0 and len(results) >= limit:
            break

    evaluated = sum(1 for item in results if item.get("evaluated"))
    matched = sum(1 for item in results if item.get("matched"))
    mismatched = sum(1 for item in results if item.get("evaluated") and not item.get("matched"))
    rescan = sum(1 for item in results if item.get("rescanRequired"))
    audit_errors = sum(1 for item in results if item.get("auditError"))
    audit_ok = mismatched == 0 and audit_errors == 0
    return {
        "schema": REPLAY_SCHEMA,
        "ruleSetRevision": str(compiled_ruleset.get("ruleSetRevision") or ""),
        "requiredCollections": _required_collections(compiled_ruleset),
        "variantsChecked": len(results),
        "evaluatedVariants": evaluated,
        "matchedVariants": matched,
        "mismatchedVariants": mismatched,
        "rescanRequiredVariants": rescan,
        "auditErrorVariants": audit_errors,
        "auditOk": audit_ok,
        "cutoverReady": bool(results) and audit_ok and rescan == 0 and matched == len(results),
        "reasonCounts": dict(sorted(reasons.items())),
        "productionRuleEvaluationEnabled": False,
        "variants": results,
        "note": "Legacy findings are comparison baselines only and are never supplied to SRL as observations or facts.",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay Phase-7 reviewed SRL rules against retained Security Evidence v2.")
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument(
        "--packs-root", type=Path,
        default=Path(__file__).resolve().parents[2] / "security-definitions" / "packs",
    )
    parser.add_argument("--variant-id", type=int, action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--require-cutover-ready", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        compiled = definition_packs.compile_pack_root(args.packs_root.resolve())["compiledRuleSet"]
        # Fail immediately if a caller supplied a partial migration pack set.
        srl_migration_parity._assert_migrated_rules(compiled)
        report = replay_evidence_root(
            args.evidence_root,
            compiled,
            variant_ids=args.variant_id,
            limit=max(0, int(args.limit)),
        )
        if args.summary:
            report = {key: report[key] for key in (
                "schema", "ruleSetRevision", "requiredCollections", "variantsChecked", "evaluatedVariants",
                "matchedVariants", "mismatchedVariants", "rescanRequiredVariants", "auditErrorVariants", "auditOk", "cutoverReady",
                "reasonCounts", "productionRuleEvaluationEnabled", "note",
            )}
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
        if not report.get("auditOk"):
            return 2
        if args.require_cutover_ready and not report.get("cutoverReady"):
            return 3
        return 0
    except (OSError, ValueError, RuntimeError, srl.SRLError) as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
