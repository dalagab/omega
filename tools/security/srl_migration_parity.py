"""Deterministic Phase-7 parity checks for migrated SigmaScope SRL rules.

This module is migration tooling only.  It does not scan/download plugins and it never
uses current finding/permission/automation projections as SRL inputs.

Phase 7b introduces ``staticPatternMatches`` as the retained low-level observation seam
for every literal-backed legacy static primitive except the separately-derived external-path
case. The checker proves two boundaries:

* every legacy literal pattern for those primitive rules produces the same fact through
  the reviewed observation rules; and
* the two reviewed compound correlations still match the current hard-coded finding
  payload across the complete 32-case boolean space of the five facts they consume.

Production SRL projection remains disabled until the later cutover phase.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import itertools
import json
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

try:
    from . import definition_packs, srl
except ImportError:  # direct script/import from tools/security
    import definition_packs  # type: ignore
    import srl  # type: ignore

CATALOG_DIR = Path(__file__).resolve().parents[1] / "catalog"
if str(CATALOG_DIR) not in sys.path:
    sys.path.insert(0, str(CATALOG_DIR))

PARITY_SCHEMA = "omega.sigmascope.srl-migration-parity.v1"
MIGRATED_FINDING_IDS = (
    "compound.credential-network",
    "compound.network-execute",
)
PRIMITIVE_FACT_IDS = (
    "clipboard",
    "credential.api",
    "dynamic.assembly",
    "filesystem.write",
    "game.hooking",
    "local.listener",
    "memory.process",
    "memory.remote-thread",
    "native.pinvoke",
    "network.http",
    "network.socket",
    "process.launch",
    "registry.access",
    "shell.powershell",
)
COMPOUND_PRIMITIVE_FACT_IDS = (
    "credential.api",
    "network.http",
    "network.socket",
    "process.launch",
    "shell.powershell",
)
PRIMITIVE_RULE_IDS = {
    "clipboard": "primitive.clipboard",
    "credential.api": "primitive.credential.api",
    "dynamic.assembly": "primitive.dynamic.assembly",
    "filesystem.write": "primitive.filesystem.write",
    "game.hooking": "primitive.game.hooking",
    "local.listener": "primitive.local.listener",
    "memory.process": "primitive.memory.process",
    "memory.remote-thread": "primitive.memory.remote-thread",
    "native.pinvoke": "primitive.native.pinvoke",
    "network.http": "primitive.network.http",
    "network.socket": "primitive.network.socket",
    "process.launch": "primitive.process.launch",
    "registry.access": "primitive.registry.access",
    "shell.powershell": "primitive.shell.powershell",
}
MIGRATED_PRIMITIVE_RULE_IDS = tuple(sorted(PRIMITIVE_RULE_IDS.values()))


def _sigmascope() -> Any:
    import sigmascope  # type: ignore
    return sigmascope


def _legacy_rules() -> dict[str, Any]:
    return {str(rule.rule_id): rule for rule in _sigmascope().RULES}


def _legacy_findings(primitive_ids: Iterable[str]) -> list[dict[str, Any]]:
    sigma = _sigmascope()
    hits = {rule_id: [f"phase7-parity:{rule_id}"] for rule_id in primitive_ids}
    findings, _capabilities = sigma.finding_payload(hits, {})
    return [dict(item) for item in findings if str(item.get("ruleId") or "") in MIGRATED_FINDING_IDS]


def _representative_observations(primitive_ids: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
    rules = _legacy_rules()
    rows: list[dict[str, Any]] = []
    for fact in primitive_ids:
        rule = rules.get(str(fact))
        if rule is None or not tuple(rule.patterns):
            raise RuntimeError(f"legacy primitive rule {fact} has no literal pattern vocabulary")
        pattern = str(rule.patterns[0])
        rows.append({
            "origin": "artifact",
            "pattern": pattern,
            "evidenceLabel": f"phase7-parity:{fact}",
            "evidence": [f"phase7-parity:{fact}: {pattern}"],
        })
    return {"staticPatternMatches": rows}


def _evaluate(compiled_ruleset: Mapping[str, Any], observations: Mapping[str, Any]) -> dict[str, Any]:
    evaluation = srl.evaluate_ruleset(compiled_ruleset, observations)
    if not evaluation.get("evaluated"):
        raise RuntimeError(f"SRL migration parity evaluation was replay-gated: {evaluation.get('replayAudit')}")
    return evaluation


def _srl_findings(compiled_ruleset: Mapping[str, Any], primitive_ids: Iterable[str]) -> list[dict[str, Any]]:
    evaluation = _evaluate(compiled_ruleset, _representative_observations(primitive_ids))
    return [
        dict(item)
        for item in evaluation.get("findings") or []
        if isinstance(item, Mapping) and str(item.get("ruleId") or item.get("findingId") or "") in MIGRATED_FINDING_IDS
    ]


def _normalized_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in findings:
        result.append({
            "ruleId": str(item.get("ruleId") or item.get("findingId") or ""),
            "severity": str(item.get("severity") or ""),
            "category": str(item.get("category") or ""),
            "title": str(item.get("title") or ""),
            "description": str(item.get("description") or ""),
            "evidence": list(item.get("evidence") or []),
        })
    result.sort(key=lambda item: item["ruleId"])
    return result


def _assert_migrated_rules(compiled_ruleset: Mapping[str, Any]) -> None:
    by_id = {
        str(rule.get("id") or ""): rule
        for rule in compiled_ruleset.get("rules") or []
        if isinstance(rule, Mapping)
    }
    expected = [*MIGRATED_FINDING_IDS, *MIGRATED_PRIMITIVE_RULE_IDS]
    missing = [rule_id for rule_id in expected if rule_id not in by_id]
    if missing:
        raise RuntimeError(f"active frozen SRL ruleset is missing migrated rule(s): {', '.join(missing)}")
    for rule_id in MIGRATED_FINDING_IDS:
        rule = by_id[rule_id]
        if str(rule.get("kind") or "") != "correlation":
            raise RuntimeError(f"migrated rule {rule_id} must remain a correlation rule")
        if str(rule.get("status") or "") != "reviewed":
            raise RuntimeError(f"migrated rule {rule_id} must remain reviewed")
    for fact, rule_id in PRIMITIVE_RULE_IDS.items():
        rule = by_id[rule_id]
        if str(rule.get("kind") or "") not in {"observation", "classification"}:
            raise RuntimeError(f"primitive migration rule {rule_id} must remain an observation/classification rule")
        if str(rule.get("status") or "") != "reviewed":
            raise RuntimeError(f"primitive migration rule {rule_id} must remain reviewed")
        if str((rule.get("emit") or {}).get("fact") or "") != fact:
            raise RuntimeError(f"primitive migration rule {rule_id} must emit fact {fact}")
        if list(rule.get("requires") or []) != ["staticPatternMatches"]:
            raise RuntimeError(f"primitive migration rule {rule_id} must consume only staticPatternMatches")


def run_primitive_pattern_parity(compiled_ruleset: Mapping[str, Any]) -> dict[str, Any]:
    """Prove every legacy primitive literal reaches the same reviewed fact."""
    _assert_migrated_rules(compiled_ruleset)
    sigma = _sigmascope()
    legacy_rules = _legacy_rules()
    mismatches: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []

    # Test both original and case-perturbed source text because the legacy matcher is
    # explicitly case-insensitive. The observation stores the canonical reviewed
    # literal, so SRL does not inherit attacker/source casing as rule semantics.
    for fact in PRIMITIVE_FACT_IDS:
        rule = legacy_rules.get(fact)
        if rule is None:
            raise RuntimeError(f"legacy primitive rule disappeared: {fact}")
        for pattern in tuple(rule.patterns):
            for variant_name, text in (("canonical", str(pattern)), ("casefold", str(pattern).swapcase())):
                hits: dict[str, list[str]] = defaultdict(list)
                intel = sigma.empty_dependency_intelligence("artifact")
                sigma.add_rule_hits(text, f"phase7-primitive:{fact}:{variant_name}", hits, intel)
                legacy_active = sorted(rule_id for rule_id in PRIMITIVE_FACT_IDS if hits.get(rule_id))
                evaluation = _evaluate(compiled_ruleset, {"staticPatternMatches": list(intel.get("staticPatternMatches") or [])})
                srl_active = sorted(f for f in evaluation.get("facts") or [] if f in PRIMITIVE_FACT_IDS)
                matched = legacy_active == srl_active and fact in srl_active
                case = {
                    "fact": fact,
                    "pattern": str(pattern),
                    "textVariant": variant_name,
                    "legacyPrimitiveIds": legacy_active,
                    "srlPrimitiveFacts": srl_active,
                    "observationCount": len(intel.get("staticPatternMatches") or []),
                    "matched": matched,
                }
                cases.append(case)
                if not matched:
                    mismatches.append(case)

    # Explicit non-match guards catch an accidentally broad selector vocabulary.
    for text in ("System.Net.Http", "Process.Kill", "CredentialCache", "power shell", "SocketAddress"):
        hits = defaultdict(list)
        intel = sigma.empty_dependency_intelligence("artifact")
        sigma.add_rule_hits(text, "phase7-primitive:near-miss", hits, intel)
        legacy_active = sorted(rule_id for rule_id in PRIMITIVE_FACT_IDS if hits.get(rule_id))
        evaluation = _evaluate(compiled_ruleset, {"staticPatternMatches": list(intel.get("staticPatternMatches") or [])})
        srl_active = sorted(f for f in evaluation.get("facts") or [] if f in PRIMITIVE_FACT_IDS)
        matched = legacy_active == srl_active
        case = {
            "fact": "",
            "pattern": text,
            "textVariant": "near-miss",
            "legacyPrimitiveIds": legacy_active,
            "srlPrimitiveFacts": srl_active,
            "observationCount": len(intel.get("staticPatternMatches") or []),
            "matched": matched,
        }
        cases.append(case)
        if not matched:
            mismatches.append(case)

    return {
        "casesChecked": len(cases),
        "mismatchCount": len(mismatches),
        "ok": not mismatches,
        "mismatches": mismatches,
        "cases": cases,
    }


def run_compound_parity(compiled_ruleset: Mapping[str, Any]) -> dict[str, Any]:
    """Compare current hard-coded and reviewed SRL compound semantics exhaustively."""
    _assert_migrated_rules(compiled_ruleset)
    primitive = run_primitive_pattern_parity(compiled_ruleset)
    mismatches: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    for mask in itertools.product((False, True), repeat=len(COMPOUND_PRIMITIVE_FACT_IDS)):
        facts = [fact for fact, enabled in zip(COMPOUND_PRIMITIVE_FACT_IDS, mask) if enabled]
        legacy = _normalized_findings(_legacy_findings(facts))
        migrated = _normalized_findings(_srl_findings(compiled_ruleset, facts))
        case = {
            "primitiveFacts": facts,
            "legacyFindingIds": [item["ruleId"] for item in legacy],
            "srlFindingIds": [item["ruleId"] for item in migrated],
            "matched": legacy == migrated,
        }
        cases.append(case)
        if legacy != migrated:
            mismatches.append({**case, "legacy": legacy, "srl": migrated})

    all_mismatches = [
        *({"stage": "primitive", **item} for item in primitive["mismatches"]),
        *({"stage": "compound", **item} for item in mismatches),
    ]
    return {
        "schema": PARITY_SCHEMA,
        "scope": "phase7-static-primitives-and-core-compound-correlations",
        "ruleSetRevision": str(compiled_ruleset.get("ruleSetRevision") or ""),
        "migratedFindingIds": list(MIGRATED_FINDING_IDS),
        "migratedPrimitiveRuleIds": list(MIGRATED_PRIMITIVE_RULE_IDS),
        "primitiveFactIds": list(PRIMITIVE_FACT_IDS),
        "compoundPrimitiveFactIds": list(COMPOUND_PRIMITIVE_FACT_IDS),
        "primitiveCasesChecked": int(primitive["casesChecked"]),
        "primitiveMismatchCount": int(primitive["mismatchCount"]),
        "casesChecked": len(cases),
        "compoundCasesChecked": len(cases),
        "compoundMismatchCount": len(mismatches),
        "mismatchCount": len(all_mismatches),
        "ok": not all_mismatches,
        "mismatches": all_mismatches,
        "cases": cases,
        "primitiveCases": primitive["cases"],
        "productionRuleEvaluationEnabled": False,
        "note": (
            "Primitive facts are derived only from retained staticPatternMatches observations. "
            "Current findings/permissions/automation rows remain forbidden SRL observation inputs."
        ),
    }


def run_pack_root_parity(packs_root: Path) -> dict[str, Any]:
    compiled = definition_packs.compile_pack_root(packs_root)
    report = run_compound_parity(compiled["compiledRuleSet"])
    report["definitionPackRevision"] = compiled["definitionPackRevision"]
    report["activeRuleCount"] = int(compiled["activeRuleCount"])
    report["totalRuleCount"] = int(compiled["totalRuleCount"])
    report["productionRuleEvaluationEnabled"] = bool(compiled.get("productionRuleEvaluationEnabled", False))
    if report["productionRuleEvaluationEnabled"]:
        report["ok"] = False
        report["mismatchCount"] = int(report["mismatchCount"]) + 1
        report["mismatches"].append({"error": "production SRL evaluation must remain disabled during Phase 7 parity migration"})
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Phase-7 old-vs-SRL primitive + compound migration parity checks.")
    parser.add_argument(
        "--packs-root",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "security-definitions" / "packs",
        help="Source-controlled Definition Pack root. Default: repository security-definitions/packs.",
    )
    parser.add_argument("--summary", action="store_true", help="Emit only parity summary fields instead of detailed cases.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_pack_root_parity(args.packs_root.resolve())
        if args.summary:
            report = {key: report[key] for key in (
                "schema", "scope", "definitionPackRevision", "ruleSetRevision", "activeRuleCount",
                "migratedFindingIds", "migratedPrimitiveRuleIds", "primitiveFactIds", "compoundPrimitiveFactIds",
                "primitiveCasesChecked", "primitiveMismatchCount", "casesChecked", "compoundMismatchCount",
                "mismatchCount", "ok", "productionRuleEvaluationEnabled", "note",
            )}
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
        return 0 if report.get("ok") else 2
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
