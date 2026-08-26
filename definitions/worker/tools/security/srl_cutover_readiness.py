#!/usr/bin/env python3
"""Read-only corpus cutover-readiness audit for the reviewed SRL migration path.

The audit combines three independently useful gates over the *exact* published inputs:

* intrinsic Security Evidence v2 integrity;
* exact frozen Daily Definitions / Definition-Pack integrity;
* legacy-baseline replay plus retained-observation rule-only reprojection.

It never enables production SRL evaluation, never mutates queue/evidence/catalog state,
and never authorizes removal of the hard-coded baseline.  A clean full-corpus result means
only "ready for explicit human cutover review".
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

SECURITY_DIR = Path(__file__).resolve().parent
CATALOG_DIR = SECURITY_DIR.parent / "catalog"
if str(CATALOG_DIR) not in sys.path:
    sys.path.insert(0, str(CATALOG_DIR))

try:
    from . import definition_packs, rule_reprojection, security_evidence_v2, srl_evidence_replay
except ImportError:  # direct script / frozen worker execution
    import definition_packs  # type: ignore
    import rule_reprojection  # type: ignore
    import security_evidence_v2  # type: ignore
    import srl_evidence_replay  # type: ignore

import definitions_snapshot  # type: ignore  # tools/catalog import path above

SCHEMA = "omega.sigmascope.srl-cutover-readiness.v1"
ENGINE_REVISION = "srl-cutover-readiness-v1"
MAX_REASON_SAMPLES = 25


def _implementation_sha256() -> str:
    return hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _current_variant_ids(evidence_root: Path) -> list[int]:
    root = security_evidence_v2.read_json_file(evidence_root, "index.json")
    plugins_descriptor = ((root.get("indexes") or {}).get("plugins") or {}) if isinstance(root, Mapping) else {}
    plugins = security_evidence_v2.read_json_file(evidence_root, str(plugins_descriptor.get("path") or "indexes/plugins.json"))
    ids = {
        int(item.get("variantId") or 0)
        for item in plugins.get("currentVariants") or []
        if isinstance(item, Mapping) and int(item.get("variantId") or 0) > 0
    }
    return sorted(ids)


def _gate(gate_id: str, title: str, passed: bool, detail: str) -> dict[str, Any]:
    return {
        "id": gate_id,
        "title": title,
        "status": "pass" if passed else "fail",
        "passed": bool(passed),
        "detail": str(detail)[:2000],
    }


def _reason_summary(replay: Mapping[str, Any], reprojection: Mapping[str, Any]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    variant_samples: dict[str, list[int]] = {}
    seen: set[tuple[int, str]] = set()

    def record(variant_id: int, reason: str) -> None:
        reason = reason.strip()
        if not reason:
            return
        key = (variant_id, reason)
        if key in seen:
            return
        seen.add(key)
        counts[reason] += 1
        samples = variant_samples.setdefault(reason, [])
        if variant_id > 0 and len(samples) < MAX_REASON_SAMPLES:
            samples.append(variant_id)

    for row in replay.get("variants") or []:
        if not isinstance(row, Mapping):
            continue
        record(int(row.get("variantId") or 0), str(row.get("reason") or ""))
    for row in reprojection.get("reanalysisRequests") or []:
        if not isinstance(row, Mapping):
            continue
        reasons = [str(item).strip() for item in row.get("reasons") or [] if str(item).strip()]
        if not reasons and str(row.get("reason") or "").strip():
            reasons = [str(row.get("reason")).strip()]
        variant_id = int(row.get("variantId") or 0)
        for reason in reasons:
            record(variant_id, reason)
    return [
        {"reason": reason, "count": int(count), "sampleVariantIds": sorted(set(variant_samples.get(reason) or []))}
        for reason, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _agreement(replay: Mapping[str, Any], reprojection: Mapping[str, Any]) -> dict[str, Any]:
    replay_by_id = {
        int(item.get("variantId") or 0): item
        for item in replay.get("variants") or []
        if isinstance(item, Mapping) and int(item.get("variantId") or 0) > 0
    }
    reproj_by_id = {
        int(item.get("variantId") or 0): item
        for item in reprojection.get("variants") or []
        if isinstance(item, Mapping) and int(item.get("variantId") or 0) > 0
    }
    ids = sorted(set(replay_by_id) | set(reproj_by_id))
    disagreements: list[dict[str, Any]] = []
    compatible = 0
    needs_reanalysis = 0
    audit_errors = 0
    mismatches = 0
    for variant_id in ids:
        replay_row = replay_by_id.get(variant_id) or {}
        reproj_row = reproj_by_id.get(variant_id) or {}
        replay_audit = bool(replay_row.get("auditError"))
        reproj_audit = bool(reproj_row.get("auditError"))
        replay_rescan = bool(replay_row.get("rescanRequired"))
        reproj_rescan = bool(reproj_row.get("reanalysisRequired"))
        replay_evaluated = bool(replay_row.get("evaluated"))
        replay_matched = bool(replay_row.get("matched"))
        reproj_ok = bool(reproj_row.get("reprojected"))
        if replay_audit or reproj_audit:
            audit_errors += 1
        elif replay_evaluated and not replay_matched:
            mismatches += 1
        elif replay_rescan or reproj_rescan:
            needs_reanalysis += 1
        elif replay_matched and reproj_ok:
            compatible += 1

        coherent = (
            variant_id in replay_by_id
            and variant_id in reproj_by_id
            and replay_audit == reproj_audit
            and replay_rescan == reproj_rescan
            and ((replay_matched and reproj_ok) or replay_rescan or replay_audit or (replay_evaluated and not replay_matched))
        )
        if not coherent and len(disagreements) < MAX_REASON_SAMPLES:
            disagreements.append({
                "variantId": variant_id,
                "legacyReplay": {
                    "evaluated": replay_evaluated,
                    "matched": replay_matched,
                    "rescanRequired": replay_rescan,
                    "auditError": replay_audit,
                    "reason": str(replay_row.get("reason") or ""),
                },
                "reprojection": {
                    "reprojected": reproj_ok,
                    "reanalysisRequired": reproj_rescan,
                    "auditError": reproj_audit,
                    "reason": str(reproj_row.get("reason") or ""),
                },
            })
    return {
        "variantsCompared": len(ids),
        "compatibleExactVariants": compatible,
        "reanalysisRequiredVariants": needs_reanalysis,
        "mismatchedVariants": mismatches,
        "auditErrorVariants": audit_errors,
        "disagreementCount": sum(
            1
            for variant_id in ids
            if not (
                variant_id in replay_by_id
                and variant_id in reproj_by_id
                and bool(replay_by_id[variant_id].get("auditError")) == bool(reproj_by_id[variant_id].get("auditError"))
                and bool(replay_by_id[variant_id].get("rescanRequired")) == bool(reproj_by_id[variant_id].get("reanalysisRequired"))
                and (
                    (bool(replay_by_id[variant_id].get("matched")) and bool(reproj_by_id[variant_id].get("reprojected")))
                    or bool(replay_by_id[variant_id].get("rescanRequired"))
                    or bool(replay_by_id[variant_id].get("auditError"))
                    or (bool(replay_by_id[variant_id].get("evaluated")) and not bool(replay_by_id[variant_id].get("matched")))
                )
            )
        ),
        "disagreementSamples": disagreements,
    }


def build_report(
    definitions_root: Path,
    evidence_root: Path,
    *,
    variant_ids: Iterable[int] | None = None,
    limit: int = 0,
) -> dict[str, Any]:
    definitions_root = definitions_root.resolve()
    evidence_root = evidence_root.resolve()
    selected_ids = sorted({int(item) for item in variant_ids or [] if int(item) > 0})
    limited = int(limit) > 0

    defs_validation = definitions_snapshot.verify_snapshot(definitions_root=definitions_root)
    evidence_validation = security_evidence_v2.validate_snapshot(evidence_root)
    errors: list[str] = []
    if not defs_validation.get("ok"):
        errors.extend(f"Definitions: {item}" for item in defs_validation.get("errors") or [])
    if not evidence_validation.get("ok"):
        errors.extend(f"Evidence-v2: {item}" for item in evidence_validation.get("errors") or [])

    parent = _read_json(definitions_root / "index.json") if (definitions_root / "index.json").is_file() else {}
    descriptor = parent.get("srlDefinitionPacks") if isinstance(parent.get("srlDefinitionPacks"), Mapping) else {}
    compiled: dict[str, Any] = {}
    if not errors:
        try:
            compiled = definition_packs.load_frozen_ruleset(definitions_root, descriptor)
        except Exception as exc:
            errors.append(f"Frozen SRL: {type(exc).__name__}: {exc}")

    evidence_index = _read_json(evidence_root / "index.json") if (evidence_root / "index.json").is_file() else {}
    evidence_revisions = evidence_index.get("revisions") if isinstance(evidence_index.get("revisions"), Mapping) else {}
    current_ids: list[int] = []
    try:
        current_ids = _current_variant_ids(evidence_root) if evidence_validation.get("ok") else []
    except Exception as exc:
        errors.append(f"Evidence-v2 current variant index: {type(exc).__name__}: {exc}")

    replay: dict[str, Any] = {}
    reprojection: dict[str, Any] = {}
    if not errors and compiled:
        replay = srl_evidence_replay.replay_evidence_root(
            evidence_root, compiled, variant_ids=selected_ids, limit=max(0, int(limit))
        )
        reprojection = rule_reprojection.plan_reprojection(
            evidence_root, compiled, variant_ids=selected_ids, limit=max(0, int(limit))
        )

    full_corpus_requested = not selected_ids and not limited
    expected_checked = len(current_ids) if full_corpus_requested else None
    agreement = _agreement(replay, reprojection) if replay and reprojection else {
        "variantsCompared": 0,
        "compatibleExactVariants": 0,
        "reanalysisRequiredVariants": 0,
        "mismatchedVariants": 0,
        "auditErrorVariants": 0,
        "disagreementCount": 0,
        "disagreementSamples": [],
    }

    definitions_prod_enabled = bool(compiled.get("productionRuleEvaluationEnabled")) if compiled else bool(descriptor.get("productionRuleEvaluationEnabled"))
    replay_checked = int(replay.get("variantsChecked") or 0)
    reproj_checked = int(reprojection.get("checkedVariants") or 0)
    all_current_checked = bool(full_corpus_requested and expected_checked is not None and replay_checked == expected_checked and reproj_checked == expected_checked)
    coherent_revision = bool(
        compiled
        and str(compiled.get("ruleSetRevision") or "")
        and str(compiled.get("ruleSetRevision") or "") == str(replay.get("ruleSetRevision") or "")
        and str(compiled.get("ruleSetRevision") or "") == str(reprojection.get("ruleSetRevision") or "")
        and str(compiled.get("ruleSetRevision") or "") == str(descriptor.get("ruleSetRevision") or "")
    )
    no_audit_errors = int(replay.get("auditErrorVariants") or 0) == 0 and int(reprojection.get("auditErrorVariants") or 0) == 0
    no_mismatches = int(replay.get("mismatchedVariants") or 0) == 0
    no_reanalysis = int(replay.get("rescanRequiredVariants") or 0) == 0 and int(reprojection.get("reanalysisRequiredVariants") or 0) == 0
    all_projected = bool(reprojection.get("allVariantsReprojectable")) and reproj_checked > 0
    agreement_ok = int(agreement.get("disagreementCount") or 0) == 0 and int(agreement.get("variantsCompared") or 0) == replay_checked == reproj_checked

    gates = [
        _gate("definitions.integrity", "Frozen Definitions integrity", bool(defs_validation.get("ok")), "exact Daily Definitions snapshot verifies fail-closed" if defs_validation.get("ok") else "; ".join(defs_validation.get("errors") or [])[:1500]),
        _gate("evidence.integrity", "Security Evidence v2 integrity", bool(evidence_validation.get("ok")), "published Evidence-v2 snapshot verifies intrinsically" if evidence_validation.get("ok") else "; ".join(evidence_validation.get("errors") or [])[:1500]),
        _gate("srl.frozen", "Frozen reviewed SRL ruleset", bool(compiled), str(compiled.get("ruleSetRevision") or "not loadable")),
        _gate("srl.production-gated", "Production SRL remains gated during readiness audit", not definitions_prod_enabled, "productionRuleEvaluationEnabled=false" if not definitions_prod_enabled else "productionRuleEvaluationEnabled unexpectedly true"),
        _gate("corpus.full", "Full current corpus requested", full_corpus_requested, "all current variants" if full_corpus_requested else "variant filter/limit makes this diagnostic-only"),
        _gate("corpus.coverage", "Every current variant checked", all_current_checked, f"checked replay={replay_checked}, reprojection={reproj_checked}, current={len(current_ids)}"),
        _gate("ruleset.coherent", "Rule-set identity coherent", coherent_revision, str(compiled.get("ruleSetRevision") or "") if compiled else "unavailable"),
        _gate("replay.audit", "No retained-evidence audit errors", no_audit_errors, f"legacy-replay={int(replay.get('auditErrorVariants') or 0)}, reprojection={int(reprojection.get('auditErrorVariants') or 0)}"),
        _gate("replay.parity", "No hard-coded vs SRL mismatches", no_mismatches, f"mismatchedVariants={int(replay.get('mismatchedVariants') or 0)}"),
        _gate("replay.compatibility", "No targeted observation re-analysis remains", no_reanalysis, f"legacy-rescan={int(replay.get('rescanRequiredVariants') or 0)}, reprojection-reanalysis={int(reprojection.get('reanalysisRequiredVariants') or 0)}"),
        _gate("reprojection.complete", "All variants reproject from retained observations", all_projected and all_current_checked, f"reprojectedVariants={int(reprojection.get('reprojectedVariants') or 0)}"),
        _gate("replay.reprojection-agreement", "Replay and reprojection classifications agree", agreement_ok, f"disagreementCount={int(agreement.get('disagreementCount') or 0)}"),
    ]
    mechanically_ready = bool(gates) and all(bool(item.get("passed")) for item in gates) and not errors

    summary = {
        "currentVariants": len(current_ids),
        "variantsChecked": replay_checked,
        "compatibleExactVariants": int(agreement.get("compatibleExactVariants") or 0),
        "mismatchedVariants": int(replay.get("mismatchedVariants") or 0),
        "reanalysisRequiredVariants": int(reprojection.get("reanalysisRequiredVariants") or 0),
        "auditErrorVariants": max(int(replay.get("auditErrorVariants") or 0), int(reprojection.get("auditErrorVariants") or 0)),
        "reprojectedVariants": int(reprojection.get("reprojectedVariants") or 0),
        "classificationDisagreements": int(agreement.get("disagreementCount") or 0),
    }
    semantic = {
        "schema": SCHEMA,
        "engineRevision": ENGINE_REVISION,
        "auditImplementationSha256": _implementation_sha256(),
        "definitionsRevision": str(parent.get("definitionsRevision") or ""),
        "legacyRuleSetRevision": str(parent.get("ruleSetRevision") or ""),
        "srlRuleSetRevision": str(compiled.get("ruleSetRevision") or "") if compiled else "",
        "definitionPackRevision": str(descriptor.get("definitionPackRevision") or ""),
        "evidenceRevision": str(evidence_revisions.get("evidenceRevision") or ""),
        "fullCorpusRequested": full_corpus_requested,
        "selectedVariantIds": selected_ids,
        "limit": max(0, int(limit)),
        "summary": summary,
        "gates": gates,
        "mechanicallyReady": mechanically_ready,
    }
    readiness_revision = f"srl-cutover-readiness-v1-{_sha(semantic)[:24]}"
    return {
        **semantic,
        "readinessRevision": readiness_revision,
        "cutoverReadyForReview": mechanically_ready,
        "readinessState": "ready-for-human-review" if mechanically_ready else "blocked",
        "manualApprovalRequired": True,
        "activationAuthorized": False,
        "hardCodedBaselineRemovalAuthorized": False,
        "productionWriteBack": False,
        "queueMutationAuthorized": False,
        "reasonSummary": _reason_summary(replay, reprojection) if replay or reprojection else [],
        "agreement": agreement,
        "legacyReplay": {
            key: replay.get(key)
            for key in (
                "schema", "ruleSetRevision", "requiredCollections", "variantsChecked", "evaluatedVariants",
                "matchedVariants", "mismatchedVariants", "rescanRequiredVariants", "auditErrorVariants", "auditOk", "cutoverReady"
            )
            if key in replay
        },
        "reprojection": {
            key: reprojection.get(key)
            for key in (
                "schema", "ruleSetRevision", "observationContractRevision", "sourceEvidenceIndexSha256",
                "sourceEvidenceRevision", "requiredCollections", "projectionSetRevision", "checkedVariants",
                "reprojectedVariants", "reanalysisRequiredVariants", "auditErrorVariants", "auditOk", "allVariantsReprojectable"
            )
            if key in reprojection
        },
        "reanalysisRequests": [dict(item) for item in reprojection.get("reanalysisRequests") or [] if isinstance(item, Mapping)],
        "errors": errors,
        "note": "A clean report authorizes only explicit human cutover review. This tool cannot enable production SRL, mutate the queue/evidence, or remove the hard-coded baseline.",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit retained Evidence-v2 for SRL production cutover readiness without activating anything.")
    parser.add_argument("--definitions-root", type=Path, required=True)
    parser.add_argument("--evidence-v2", type=Path, required=True)
    parser.add_argument("--variant-id", type=int, action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--require-ready", action="store_true", help="Exit 3 unless the complete current corpus is mechanically ready for explicit human cutover review.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = build_report(
            args.definitions_root,
            args.evidence_v2,
            variant_ids=args.variant_id,
            limit=max(0, int(args.limit)),
        )
    except Exception as exc:
        print(json.dumps({"schema": SCHEMA, "ok": False, "error": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if args.summary:
        print(json.dumps({
            key: report.get(key)
            for key in (
                "schema", "readinessRevision", "readinessState", "cutoverReadyForReview",
                "manualApprovalRequired", "activationAuthorized", "hardCodedBaselineRemovalAuthorized",
                "summary", "reasonSummary", "errors",
            )
        }, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    if args.require_ready and not report.get("cutoverReadyForReview"):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
