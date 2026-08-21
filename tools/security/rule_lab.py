"""DeltaScope Rule Lab backend for local/experimental SRL authoring.

The Rule Lab is deliberately read-only with respect to production/catalog/evidence state.
It compiles inert SRL YAML with the production compiler, evaluates only retained
SRL-eligible observations, compares candidate findings with retained baseline findings,
and can build deterministic local candidate/fixture export bundles.  It has no network,
repository, workflow, publication, or production write-back surface.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import difflib
import io
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping
import zipfile

import yaml

try:
    from . import observation_projection, srl, rule_candidate
except ImportError:  # direct script/import from tools/security
    import observation_projection  # type: ignore
    import srl  # type: ignore
    import rule_candidate  # type: ignore

RULE_LAB_SCHEMA = "omega.deltascope.rule-lab.v1"
COMPILE_SCHEMA = "omega.deltascope.rule-lab.compile.v1"
VARIANT_EVALUATION_SCHEMA = "omega.deltascope.rule-lab.variant-evaluation.v1"
REPLAY_SCHEMA = "omega.deltascope.rule-lab.replay.v1"
DIFF_SCHEMA = "omega.deltascope.rule-lab.finding-diff.v1"
EDITOR_INTELLIGENCE_SCHEMA = "omega.deltascope.rule-editor-intelligence.v1"
FORMAT_SCHEMA = "omega.deltascope.rule-editor-format.v1"
EXPORT_SCHEMA = "omega.sigmascope.rule-candidate-bundle.v1"
MAX_REPLAY_VARIANTS = 1000
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_EXPORT_NOTES = 16 * 1024

DEFAULT_EXAMPLE = """schema: omega.sigmascope.rule.v1
id: candidate.network-http-literal
kind: observation
status: experimental
requires: [staticPatternMatches]
selectors:
  http_literal:
    collection: staticPatternMatches
    where:
      pattern:
        starts-with-ci: http
condition: http_literal
emit:
  fact: candidate.network.http
  confidence: medium
  title: Candidate HTTP literal observation
"""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _diag(stage: str, message: str, *, severity: str = "error") -> dict[str, Any]:
    return {"severity": severity, "stage": stage, "message": str(message)[:4000]}


def required_collections(compiled_ruleset: Mapping[str, Any]) -> list[str]:
    return sorted({
        str(name)
        for rule in compiled_ruleset.get("rules") or []
        if isinstance(rule, Mapping)
        for name in rule.get("requires") or []
        if str(name)
    })


def candidate_finding_ids(compiled_ruleset: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    for rule in compiled_ruleset.get("rules") or []:
        if not isinstance(rule, Mapping) or str(rule.get("kind") or "") != "correlation":
            continue
        emit = rule.get("emit") if isinstance(rule.get("emit"), Mapping) else {}
        finding_id = str(emit.get("findingId") or rule.get("id") or "")
        if finding_id:
            result.append(finding_id)
    return sorted(set(result))


def compile_candidate_text(text: str) -> dict[str, Any]:
    try:
        compiled = srl.compile_yaml_text(text)
    except srl.SRLParseError as exc:
        return {
            "schema": COMPILE_SCHEMA, "ok": False, "diagnostics": [_diag("parse", str(exc))],
            "productionWriteBack": False,
        }
    except srl.SRLCompileError as exc:
        return {
            "schema": COMPILE_SCHEMA, "ok": False, "diagnostics": [_diag("compile", str(exc))],
            "productionWriteBack": False,
        }
    rules = compiled.get("rules") or []
    diagnostics: list[dict[str, Any]] = []
    experimental = [str(rule.get("id") or "") for rule in rules if str(rule.get("status") or "") == "experimental"]
    if experimental:
        diagnostics.append(_diag("review", f"{len(experimental)} experimental rule(s); candidate evaluation remains local only", severity="info"))
    return {
        "schema": COMPILE_SCHEMA,
        "ok": True,
        "diagnostics": diagnostics,
        "ruleSetRevision": str(compiled.get("ruleSetRevision") or ""),
        "ruleIds": [str(rule.get("id") or "") for rule in rules],
        "requiredCollections": required_collections(compiled),
        "findingIds": candidate_finding_ids(compiled),
        "compiledRuleSet": compiled,
        "productionWriteBack": False,
    }


def _parse_evidence(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return list(parsed) if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _finding_identity(row: Mapping[str, Any]) -> tuple[str, str]:
    rule_id = str(row.get("ruleId") or row.get("rule_id") or row.get("findingId") or row.get("finding_id") or "")
    finding_id = str(row.get("findingId") or row.get("finding_id") or rule_id)
    return rule_id, finding_id


def normalize_findings(rows: Iterable[Mapping[str, Any]], *, include_ids: Iterable[str] | None = None) -> list[dict[str, Any]]:
    allowed = None if include_ids is None else {str(item) for item in include_ids if str(item)}
    result: list[dict[str, Any]] = []
    for raw in rows:
        rule_id, finding_id = _finding_identity(raw)
        if allowed is not None and finding_id not in allowed and rule_id not in allowed:
            continue
        evidence = raw.get("evidence")
        if evidence is None:
            evidence = raw.get("evidence_json")
        result.append({
            "ruleId": rule_id,
            "findingId": finding_id,
            "severity": str(raw.get("severity") or ""),
            "category": str(raw.get("category") or ""),
            "title": str(raw.get("title") or ""),
            "description": str(raw.get("description") or ""),
            "evidence": _parse_evidence(evidence),
        })
    result.sort(key=lambda item: (item["findingId"], item["ruleId"], _sha(item)))
    return result


def diff_findings(baseline_rows: Iterable[Mapping[str, Any]], candidate_rows: Iterable[Mapping[str, Any]], *, include_ids: Iterable[str] | None = None) -> dict[str, Any]:
    baseline = normalize_findings(baseline_rows, include_ids=include_ids)
    candidate = normalize_findings(candidate_rows, include_ids=include_ids)
    before = {(item["ruleId"], item["findingId"]): item for item in baseline}
    after = {(item["ruleId"], item["findingId"]): item for item in candidate}
    added = [after[key] for key in sorted(after.keys() - before.keys())]
    removed = [before[key] for key in sorted(before.keys() - after.keys())]
    changed: list[dict[str, Any]] = []
    unchanged = 0
    for key in sorted(before.keys() & after.keys()):
        left, right = before[key], after[key]
        fields = [name for name in ("severity", "category", "title", "description") if left.get(name) != right.get(name)]
        evidence_changed = _canonical(left.get("evidence") or []) != _canonical(right.get("evidence") or [])
        if fields or evidence_changed:
            changed.append({
                "ruleId": key[0], "findingId": key[1], "changedFields": fields,
                "evidenceChanged": evidence_changed, "baseline": left, "candidate": right,
            })
        else:
            unchanged += 1
    return {
        "schema": DIFF_SCHEMA,
        "clean": not added and not removed and not changed,
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchangedCount": unchanged,
        "baselineCount": len(baseline),
        "candidateCount": len(candidate),
    }


def deterministic_explanation(compiled_ruleset: Mapping[str, Any], evaluation: Mapping[str, Any]) -> dict[str, Any]:
    compiled_by_id = {
        str(rule.get("id") or ""): rule
        for rule in compiled_ruleset.get("rules") or []
        if isinstance(rule, Mapping)
    }
    rules: list[dict[str, Any]] = []
    for result in evaluation.get("rules") or []:
        if not isinstance(result, Mapping):
            continue
        rule_id = str(result.get("ruleId") or "")
        compiled = compiled_by_id.get(rule_id) or {}
        selectors: list[dict[str, Any]] = []
        for selector in result.get("selectors") or []:
            if not isinstance(selector, Mapping):
                continue
            selectors.append({
                "name": str(selector.get("name") or ""),
                "type": str(selector.get("type") or ""),
                "collection": str(selector.get("collection") or ""),
                "matched": bool(selector.get("matched")),
                "matchCount": int(selector.get("matchCount") or 0),
                "matchedFacts": sorted(str(item) for item in selector.get("matchedFacts") or []),
                "evidenceRows": list(selector.get("evidenceRows") or []),
                "truncated": bool(selector.get("truncated")),
            })
        rules.append({
            "ruleId": rule_id,
            "kind": str(result.get("kind") or ""),
            "status": str(result.get("status") or ""),
            "matched": bool(result.get("matched")),
            "condition": compiled.get("condition") or {},
            "emittedFact": str(result.get("emittedFact") or ""),
            "findingId": str(((result.get("finding") or {}).get("findingId") if isinstance(result.get("finding"), Mapping) else "") or ""),
            "selectors": selectors,
        })
    return {
        "schema": RULE_LAB_SCHEMA,
        "evaluated": bool(evaluation.get("evaluated")),
        "ruleSetRevision": str(evaluation.get("ruleSetRevision") or compiled_ruleset.get("ruleSetRevision") or ""),
        "replayAudit": dict(evaluation.get("replayAudit") or {}),
        "rules": rules,
        "facts": sorted(str(item) for item in evaluation.get("facts") or []),
        "findingIds": sorted(str(item.get("findingId") or item.get("ruleId") or "") for item in evaluation.get("findings") or [] if isinstance(item, Mapping)),
        "productionWriteBack": False,
    }


def _load_variant_inputs(inspector: Any, compiled_ruleset: Mapping[str, Any], variant_id: int) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, Any], list[dict[str, Any]]]:
    if not hasattr(inspector, "plugin_dataset"):
        raise ValueError("Rule Lab variant evaluation requires Security Evidence v2 retained datasets")
    detail = inspector.plugin_detail(int(variant_id))
    required = required_collections(compiled_ruleset)
    observations: dict[str, list[dict[str, Any]]] = {}
    for collection in required:
        spec = observation_projection.COLLECTIONS.get(collection) or {}
        dataset = str(spec.get("backingDataset") or collection)
        try:
            rows = inspector.plugin_dataset(int(variant_id), dataset)
        except (KeyError, ValueError):
            continue
        observations[collection] = [dict(row) for row in rows if isinstance(row, Mapping)]
    contract = detail.get("observations") if isinstance(detail.get("observations"), Mapping) else {}
    try:
        baseline = inspector.plugin_dataset(int(variant_id), "findings")
    except (KeyError, ValueError):
        baseline = detail.get("findings") if isinstance(detail.get("findings"), list) else []
    return detail, observations, dict(contract), [dict(row) for row in baseline if isinstance(row, Mapping)]


def evaluate_variant(inspector: Any, text: str, variant_id: int) -> dict[str, Any]:
    compiled_result = compile_candidate_text(text)
    if not compiled_result.get("ok"):
        return {
            "schema": VARIANT_EVALUATION_SCHEMA, "ok": False, "variantId": int(variant_id),
            "compile": compiled_result, "productionWriteBack": False,
        }
    compiled = compiled_result["compiledRuleSet"]
    try:
        detail, observations, contract, baseline = _load_variant_inputs(inspector, compiled, int(variant_id))
        evaluation = srl.evaluate_ruleset(compiled, observations, observation_contract=contract)
    except (OSError, ValueError, RuntimeError, srl.SRLError) as exc:
        return {
            "schema": VARIANT_EVALUATION_SCHEMA, "ok": False, "variantId": int(variant_id),
            "compile": compiled_result, "diagnostics": [_diag("evidence", str(exc))], "productionWriteBack": False,
        }
    identity = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
    finding_ids = compiled_result.get("findingIds") or []
    diff = diff_findings(baseline, evaluation.get("findings") or [], include_ids=finding_ids)
    return {
        "schema": VARIANT_EVALUATION_SCHEMA,
        "ok": True,
        "variantId": int(variant_id),
        "plugin": {
            "internalName": str(identity.get("internal_name") or identity.get("internalName") or ""),
            "name": str(identity.get("canonical_name") or identity.get("name") or ""),
            "version": str(identity.get("assembly_version") or identity.get("assemblyVersion") or ""),
            "source": str(identity.get("source_name") or identity.get("sourceName") or ""),
        },
        "compile": {key: value for key, value in compiled_result.items() if key != "compiledRuleSet"},
        "observationRows": {name: len(rows) for name, rows in sorted(observations.items())},
        "evaluation": evaluation,
        "explanation": deterministic_explanation(compiled, evaluation),
        "baselineDiff": diff,
        "productionWriteBack": False,
    }


def replay_inspector(inspector: Any, text: str, *, variant_ids: Iterable[int] | None = None, limit: int = MAX_REPLAY_VARIANTS) -> dict[str, Any]:
    compiled_result = compile_candidate_text(text)
    if not compiled_result.get("ok"):
        return {"schema": REPLAY_SCHEMA, "ok": False, "compile": compiled_result, "productionWriteBack": False}
    selected = sorted({int(item) for item in variant_ids or [] if int(item) > 0})
    bounded_limit = min(MAX_REPLAY_VARIANTS, max(1, int(limit or MAX_REPLAY_VARIANTS)))
    if selected:
        ids = selected[:bounded_limit]
    else:
        rows = inspector.list_plugins(limit=bounded_limit, offset=0)
        ids = [int(row.get("variant_id") or row.get("variantId") or 0) for row in rows]
        ids = [item for item in ids if item > 0]
    results = [evaluate_variant(inspector, text, variant_id) for variant_id in ids]
    evaluated = 0
    clean = 0
    rescan = 0
    errors = 0
    diff_counts: Counter[str] = Counter()
    for item in results:
        if not item.get("ok"):
            errors += 1
            continue
        evaluation = item.get("evaluation") if isinstance(item.get("evaluation"), Mapping) else {}
        if not evaluation.get("evaluated"):
            replay = evaluation.get("replayAudit") if isinstance(evaluation.get("replayAudit"), Mapping) else {}
            if replay.get("rescanRequired", True):
                rescan += 1
            continue
        evaluated += 1
        diff = item.get("baselineDiff") if isinstance(item.get("baselineDiff"), Mapping) else {}
        diff_counts["added"] += len(diff.get("added") or [])
        diff_counts["removed"] += len(diff.get("removed") or [])
        diff_counts["changed"] += len(diff.get("changed") or [])
        if diff.get("clean"):
            clean += 1
    return {
        "schema": REPLAY_SCHEMA,
        "ok": errors == 0,
        "ruleSetRevision": compiled_result.get("ruleSetRevision", ""),
        "variantsChecked": len(results),
        "evaluatedVariants": evaluated,
        "cleanBaselineVariants": clean,
        "rescanRequiredVariants": rescan,
        "errorVariants": errors,
        "diffCounts": dict(diff_counts),
        "baselineParity": bool(results) and errors == 0 and rescan == 0 and evaluated == len(results) and clean == len(results),
        "compile": {key: value for key, value in compiled_result.items() if key != "compiledRuleSet"},
        "variants": results,
        "productionWriteBack": False,
        "note": "Candidate YAML is inert local data. Retained findings are comparison baselines only and are never supplied as SRL observations or facts.",
    }


def build_fixture(inspector: Any, text: str, variant_id: int, *, name: str = "Rule Lab retained-evidence fixture") -> dict[str, Any]:
    compiled_result = compile_candidate_text(text)
    if not compiled_result.get("ok"):
        return {"ok": False, "compile": compiled_result, "productionWriteBack": False}
    compiled = compiled_result["compiledRuleSet"]
    detail, observations, contract, _baseline = _load_variant_inputs(inspector, compiled, int(variant_id))
    evaluation = srl.evaluate_ruleset(compiled, observations, observation_contract=contract)
    if not evaluation.get("evaluated"):
        return {
            "ok": False,
            "compile": {key: value for key, value in compiled_result.items() if key != "compiledRuleSet"},
            "diagnostics": [_diag("fixture", str((evaluation.get("replayAudit") or {}).get("reason") or "required observations are not replay-compatible"))],
            "productionWriteBack": False,
        }
    fixture = {
        "schema": srl.FIXTURE_SCHEMA,
        "name": str(name or "Rule Lab retained-evidence fixture")[:160],
        "observations": observations,
        "expected": {
            "facts": sorted(str(item) for item in evaluation.get("facts") or []),
            "matchedRules": sorted(str(item.get("ruleId") or "") for item in evaluation.get("rules") or [] if isinstance(item, Mapping) and item.get("matched")),
            "findingIds": sorted(str(item.get("findingId") or item.get("ruleId") or "") for item in evaluation.get("findings") or [] if isinstance(item, Mapping)),
        },
    }
    text_out = yaml.safe_dump(fixture, sort_keys=False, allow_unicode=True)
    if len(text_out.encode("utf-8")) > MAX_FIXTURE_BYTES:
        return {
            "ok": False,
            "diagnostics": [_diag("fixture", f"exact retained-evidence fixture exceeds {MAX_FIXTURE_BYTES} bytes; reduce the candidate collections or create a focused fixture manually")],
            "productionWriteBack": False,
        }
    identity = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
    return {
        "ok": True,
        "fixture": fixture,
        "fixtureYaml": text_out,
        "variantId": int(variant_id),
        "plugin": str(identity.get("canonical_name") or identity.get("name") or identity.get("internal_name") or ""),
        "productionWriteBack": False,
    }


def test_fixture_text(text: str, fixture_text: str) -> dict[str, Any]:
    compiled_result = compile_candidate_text(text)
    if not compiled_result.get("ok"):
        return {"ok": False, "compile": compiled_result, "productionWriteBack": False}
    try:
        fixture = srl.parse_yaml_text(fixture_text)
        if not isinstance(fixture, Mapping):
            raise srl.SRLCompileError("fixture YAML must contain a mapping")
        result = srl.run_fixture(compiled_result["compiledRuleSet"], fixture)
    except (srl.SRLError, ValueError) as exc:
        return {"ok": False, "diagnostics": [_diag("fixture", str(exc))], "productionWriteBack": False}
    return {
        "ok": bool(result.get("passed")),
        "result": result,
        "compile": {key: value for key, value in compiled_result.items() if key != "compiledRuleSet"},
        "productionWriteBack": False,
    }


def _zip_bytes(files: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name])
    return output.getvalue()


def _proposal_fixture_validation(text: str, positive_fixture_text: str, negative_fixture_text: str) -> dict[str, Any]:
    return rule_candidate.validate_candidate({
        "issueNumber": 1,
        "issueUrl": "",
        "issueBodySha256": "0" * 64,
        "packId": "rule-lab-export",
        "packTitle": "DeltaScope Rule Lab export",
        "candidateYaml": text,
        "positiveFixtureYaml": positive_fixture_text,
        "negativeFixtureYaml": negative_fixture_text,
        "rationale": "Local Rule Lab export validation",
        "falsePositiveExpectations": "Supplied separately when proposed on GitHub",
        "provenance": "DeltaScope Rule Lab",
        "license": "UNSPECIFIED",
    })


def build_export_bundle(
    text: str, *, fixture_text: str = "", positive_fixture_text: str = "",
    negative_fixture_text: str = "", notes: str = ""
) -> tuple[bytes, dict[str, Any]]:
    compiled_result = compile_candidate_text(text)
    if not compiled_result.get("ok"):
        raise ValueError(str((compiled_result.get("diagnostics") or [{"message": "candidate compilation failed"}])[0].get("message")))
    if len(notes.encode("utf-8")) > MAX_EXPORT_NOTES:
        raise ValueError(f"candidate notes exceed {MAX_EXPORT_NOTES} bytes")
    if fixture_text.strip() and (positive_fixture_text.strip() or negative_fixture_text.strip()):
        raise ValueError("legacy fixture_text cannot be combined with positive/negative proposal fixtures")

    files: dict[str, bytes] = {"candidate.yaml": text.encode("utf-8")}
    proposal_ready = False
    if positive_fixture_text.strip() or negative_fixture_text.strip():
        if not positive_fixture_text.strip() or not negative_fixture_text.strip():
            raise ValueError("GitHub-ready candidate export requires both positive and negative fixtures")
        try:
            _proposal_fixture_validation(text, positive_fixture_text, negative_fixture_text)
        except (rule_candidate.RuleCandidateError, srl.SRLError) as exc:
            raise ValueError(f"proposal fixtures cannot be exported: {exc}") from exc
        files["positive-fixture.yaml"] = positive_fixture_text.encode("utf-8")
        files["negative-fixture.yaml"] = negative_fixture_text.encode("utf-8")
        proposal_ready = True
    elif fixture_text.strip():
        tested = test_fixture_text(text, fixture_text)
        if not tested.get("ok"):
            diagnostics = tested.get("diagnostics") or []
            failures = ((tested.get("result") or {}).get("failures") if isinstance(tested.get("result"), Mapping) else []) or []
            message = (diagnostics[0].get("message") if diagnostics else "; ".join(str(x) for x in failures)) or "fixture did not pass"
            raise ValueError(f"fixture cannot be exported: {message}")
        files["fixture.yaml"] = fixture_text.encode("utf-8")

    descriptor = {
        "schema": EXPORT_SCHEMA,
        "ruleSetRevision": compiled_result.get("ruleSetRevision", ""),
        "ruleIds": compiled_result.get("ruleIds") or [],
        "requiredCollections": compiled_result.get("requiredCollections") or [],
        "findingIds": compiled_result.get("findingIds") or [],
        "notes": notes,
        "githubProposalReady": proposal_ready,
        "productionWriteBack": False,
        "promotionAuthority": "none; normal repository review/authorization is required outside Rule Lab",
    }
    files["candidate.json"] = json.dumps(descriptor, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    files["README.md"] = (
        "# SigmaScope Rule Lab candidate\n\n"
        "This bundle was exported from DeltaScope Rule Lab. Candidate YAML is inert data. "
        "The bundle has no production write-back authority and must enter the normal reviewed Definition Pack workflow before it can ever be frozen into Daily Definitions.\n"
    ).encode("utf-8")
    manifest_files = {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        for name, data in sorted(files.items())
    }
    manifest_core = {"schema": EXPORT_SCHEMA, "files": manifest_files}
    manifest_core["bundleRevision"] = f"rule-candidate-v1-{_sha(manifest_core)[:24]}"
    files["MANIFEST.json"] = json.dumps(manifest_core, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    return _zip_bytes(files), manifest_core



EDITOR_KEY_DOCS: dict[str, str] = {
    "schema": "SRL document schema. A single rule uses omega.sigmascope.rule.v1; a multi-rule document uses omega.sigmascope.ruleset.v1.",
    "id": "Stable rule identity. Use a durable namespaced identifier; changing this creates a new logical rule.",
    "kind": "Rule role: observation/classification emits a fact; correlation consumes selectors/facts and emits a review finding.",
    "status": "Lifecycle state. Rule Lab normally authors experimental rules; GitHub review is the authority boundary for reviewed state.",
    "requires": "Exact retained observation collections required by this rule. Collection selectors must be mirrored here.",
    "selectors": "Named, same-record selectors over retained observations, or fact selectors in correlation rules.",
    "collection": "An SRL-eligible retained observation collection. Only frozen typed collections are legal inputs.",
    "where": "Typed predicates that must match the same retained observation row.",
    "facts": "Correlation-only selector over previously emitted/stable fact identifiers using any/all semantics.",
    "condition": "Boolean composition of selector names using all/any/not/count. Every declared selector must be referenced.",
    "emit": "Typed output. Observation/classification rules emit a fact; correlation rules emit a finding.",
    "fact": "Stable fact identifier emitted by an observation or classification rule.",
    "findingId": "Stable finding identifier emitted by a correlation rule.",
    "confidence": "Human-facing confidence metadata for an emitted fact.",
    "severity": "Human-facing finding severity; SRL does not grant mutation authority or activation semantics.",
    "title": "Short human-readable title.",
    "description": "Human-readable explanation of the rule or emitted result.",
    "category": "Human-facing category metadata.",
    "license": "Rule/source licensing provenance.",
    "source": "External/source provenance metadata; it does not grant authority.",
}

CONDITION_DOCS = {
    "all": "All child conditions must match.",
    "any": "At least one child condition must match.",
    "not": "Negates one child condition.",
    "count": "Compares a selector match count using gt/gte/lt/lte/equals.",
}


def _line_for_key(text: str, key: str, *, after_line: int = 0) -> int:
    pattern = re.compile(rf"^\s*(?:-\s*)?{re.escape(key)}\s*:", re.MULTILINE)
    for match in pattern.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if line >= after_line:
            return line
    return max(1, after_line or 1)


def _location_for_diagnostic(text: str, message: str) -> tuple[int, int]:
    mark = re.search(r"line\s+(\d+),\s*column\s+(\d+)", message, re.IGNORECASE)
    if mark:
        return max(1, int(mark.group(1))), max(1, int(mark.group(2)))
    for pattern in (
        r"unknown operator ([A-Za-z0-9-]+)",
        r"unknown field [^.]+\.([A-Za-z0-9_.\[\]-]+)",
        r"selector ([A-Za-z0-9_.:/-]+)",
        r"collection ([A-Za-z0-9_.:/-]+)",
    ):
        found = re.search(pattern, message)
        if found:
            return _line_for_key(text, found.group(1)), 1
    if "requires" in message:
        return _line_for_key(text, "requires"), 1
    if "condition" in message:
        return _line_for_key(text, "condition"), 1
    if "emit" in message:
        return _line_for_key(text, "emit"), 1
    if "rule id" in message:
        return _line_for_key(text, "id"), 1
    return 1, 1


def _rules_from_document(document: Any) -> list[Mapping[str, Any]]:
    if isinstance(document, Mapping) and document.get("schema") == srl.RULE_SCHEMA:
        return [document]
    if isinstance(document, Mapping) and document.get("schema") == srl.RULESET_SCHEMA and isinstance(document.get("rules"), list):
        return [item for item in document["rules"] if isinstance(item, Mapping)]
    if isinstance(document, list):
        return [item for item in document if isinstance(item, Mapping)]
    return []


def _line_of_value(text: str, key: str, value: str, *, after_line: int = 0) -> int:
    escaped = re.escape(str(value))
    pattern = re.compile(rf"^\s*(?:-\s*)?{re.escape(key)}\s*:\s*['\"]?{escaped}(?:['\"]?\s*(?:#.*)?$)", re.MULTILINE)
    for match in pattern.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if line >= after_line:
            return line
    return _line_for_key(text, key, after_line=after_line)


def _editor_symbols(text: str, document: Any) -> dict[str, Any]:
    rules_out: list[dict[str, Any]] = []
    selectors_out: list[dict[str, Any]] = []
    facts_out: list[dict[str, Any]] = []
    finding_out: list[dict[str, Any]] = []
    last_rule_line = 1
    for raw in _rules_from_document(document):
        rule_id = str(raw.get("id") or "")
        rule_line = _line_of_value(text, "id", rule_id, after_line=last_rule_line) if rule_id else last_rule_line
        last_rule_line = rule_line
        kind = str(raw.get("kind") or "")
        rules_out.append({"name": rule_id or "<unnamed>", "kind": kind or "rule", "line": rule_line, "status": str(raw.get("status") or "experimental")})
        selectors = raw.get("selectors") if isinstance(raw.get("selectors"), Mapping) else {}
        for name, selector in selectors.items():
            selector_line = _line_for_key(text, str(name), after_line=rule_line)
            collection = str(selector.get("collection") or "") if isinstance(selector, Mapping) else ""
            selectors_out.append({"name": str(name), "rule": rule_id, "line": selector_line, "collection": collection, "type": "facts" if isinstance(selector, Mapping) and "facts" in selector else "collection"})
        emit = raw.get("emit") if isinstance(raw.get("emit"), Mapping) else {}
        fact = str(emit.get("fact") or "")
        if fact:
            facts_out.append({"name": fact, "rule": rule_id, "line": _line_of_value(text, "fact", fact, after_line=rule_line)})
        finding_id = str(emit.get("findingId") or "")
        if finding_id:
            finding_out.append({"name": finding_id, "rule": rule_id, "line": _line_of_value(text, "findingId", finding_id, after_line=rule_line)})
    return {"rules": rules_out, "selectors": selectors_out, "facts": facts_out, "findings": finding_out}


def _cursor_token(line: str, column: int) -> tuple[str, int, int]:
    index = max(0, min(len(line), int(column) - 1))
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.[]/-")
    start = index
    while start > 0 and line[start - 1] in allowed:
        start -= 1
    end = index
    while end < len(line) and line[end] in allowed:
        end += 1
    return line[start:end], start + 1, end + 1


def _nearest_selector(symbols: Mapping[str, Any], line: int) -> Mapping[str, Any] | None:
    eligible = [item for item in symbols.get("selectors") or [] if int(item.get("line") or 0) <= line]
    return max(eligible, key=lambda item: int(item.get("line") or 0), default=None)


def _lexical_editor_context(lines: list[str], line_no: int) -> dict[str, Any]:
    upto = lines[:line_no]
    selectors: list[dict[str, Any]] = []
    facts: list[dict[str, Any]] = []
    in_selectors = False
    selectors_indent = -1
    current_selector = ""
    current_selector_indent = -1
    current_collection = ""
    where_indent = -1
    current_field = ""
    for index, raw in enumerate(upto, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if re.match(r"selectors\s*:\s*(?:#.*)?$", stripped):
            in_selectors = True
            selectors_indent = indent
            current_selector = ""
            current_collection = ""
            where_indent = -1
            current_field = ""
            continue
        if in_selectors and indent <= selectors_indent and not stripped.startswith("-"):
            in_selectors = False
            current_selector = ""
            current_collection = ""
            where_indent = -1
            current_field = ""
        if in_selectors:
            key_match = re.match(r"(?:-\s*)?([A-Za-z0-9_.:/-]+)\s*:\s*(.*)$", stripped)
            if key_match:
                key, value = key_match.group(1), key_match.group(2).split("#", 1)[0].strip().strip("'\"")
                if indent == selectors_indent + 2:
                    current_selector = key
                    current_selector_indent = indent
                    current_collection = ""
                    where_indent = -1
                    current_field = ""
                    selectors.append({"name": key, "line": index, "collection": "", "type": "collection"})
                elif current_selector and key == "collection" and indent > current_selector_indent:
                    current_collection = value
                    selectors[-1]["collection"] = value
                elif current_selector and key == "facts" and indent > current_selector_indent:
                    selectors[-1]["type"] = "facts"
                elif current_selector and key == "where" and indent > current_selector_indent:
                    where_indent = indent
                    current_field = ""
                elif current_selector and where_indent >= 0 and indent == where_indent + 2:
                    current_field = key
        fact_match = re.match(r"fact\s*:\s*([^#]+)", stripped)
        if fact_match:
            facts.append({"name": fact_match.group(1).strip().strip("'\""), "line": index})
    return {
        "selectors": selectors, "facts": facts, "currentSelector": current_selector,
        "currentCollection": current_collection, "currentField": current_field, "whereIndent": where_indent,
    }


def _completion(label: str, *, insert: str | None = None, kind: str = "keyword", detail: str = "", documentation: str = "") -> dict[str, str]:
    return {"label": label, "insertText": insert if insert is not None else label, "kind": kind, "detail": detail, "documentation": documentation}


def _diagnostic_suggestion(message: str, typed: Mapping[str, Mapping[str, str]]) -> str:
    match = re.search(r"unknown operator ([A-Za-z0-9-]+)", message)
    if match:
        found = difflib.get_close_matches(match.group(1), sorted(srl.OPERATORS), n=1, cutoff=0.55)
        return found[0] if found else ""
    match = re.search(r"unknown field ([A-Za-z0-9_.:/-]+)\.([A-Za-z0-9_.\[\]-]+)", message)
    if match:
        fields = sorted((typed.get(match.group(1)) or {}).keys())
        found = difflib.get_close_matches(match.group(2), fields, n=1, cutoff=0.5)
        return found[0] if found else ""
    match = re.search(r"unknown/non-SRL collection ([A-Za-z0-9_.:/-]+)", message)
    if match:
        found = difflib.get_close_matches(match.group(1), sorted(typed), n=1, cutoff=0.5)
        return found[0] if found else ""
    return ""


def _operator_names(field_type: str) -> list[str]:
    if field_type == "integer":
        return ["equals", "gt", "gte", "lt", "lte", "exists", "missing"]
    if field_type == "boolean":
        return ["equals", "exists", "missing"]
    if field_type == "object[]":
        return ["exists", "missing"]
    return ["equals", "equals-ci", "contains", "contains-ci", "starts-with", "starts-with-ci", "ends-with", "ends-with-ci", "in", "in-ci", "exists", "missing"]


def editor_intelligence(text: str, *, cursor_line: int = 1, cursor_column: int = 1) -> dict[str, Any]:
    lines = text.splitlines() or [""]
    line_no = max(1, min(len(lines), int(cursor_line or 1)))
    column = max(1, min(len(lines[line_no - 1]) + 1, int(cursor_column or 1)))
    current_line = lines[line_no - 1]
    token, replace_start, replace_end = _cursor_token(current_line, column)
    compile_result = compile_candidate_text(text)
    diagnostics: list[dict[str, Any]] = []
    for raw in compile_result.get("diagnostics") or []:
        item = dict(raw)
        item["line"], item["column"] = _location_for_diagnostic(text, str(item.get("message") or ""))
        diagnostics.append(item)
    document: Any = None
    try:
        document = srl.parse_yaml_text(text)
    except srl.SRLError:
        pass
    symbols = _editor_symbols(text, document) if document is not None else {"rules": [], "selectors": [], "facts": [], "findings": []}
    lexical = _lexical_editor_context(lines, line_no)
    if not symbols.get("selectors"):
        symbols["selectors"] = lexical.get("selectors") or []
    if not symbols.get("facts"):
        symbols["facts"] = lexical.get("facts") or []
    typed = srl.engine_reference().get("typedCollections") or {}
    for item in diagnostics:
        suggestion = _diagnostic_suggestion(str(item.get("message") or ""), typed)
        if suggestion:
            item["suggestion"] = suggestion
    selector = _nearest_selector(symbols, line_no)
    selector_collection = str((selector or {}).get("collection") or lexical.get("currentCollection") or "")
    collection_fields = typed.get(selector_collection) if isinstance(typed.get(selector_collection), Mapping) else {}

    stripped_before = current_line[: column - 1]
    key_match = re.match(r"^\s*(?:-\s*)?([A-Za-z0-9_.\[\]-]+)\s*:\s*(.*)$", stripped_before)
    key = key_match.group(1) if key_match else ""
    value_prefix = key_match.group(2) if key_match else token
    indent = len(current_line) - len(current_line.lstrip(" "))
    completions: list[dict[str, str]] = []

    def add_values(values: Iterable[str], *, kind: str = "value", detail: str = "", docs: Mapping[str, str] | None = None) -> None:
        for value in values:
            completions.append(_completion(str(value), kind=kind, detail=detail, documentation=(docs or {}).get(str(value), "")))

    if key == "schema":
        add_values([srl.RULE_SCHEMA, srl.RULESET_SCHEMA], detail="SRL schema")
    elif key == "kind":
        add_values(["observation", "classification", "correlation"], detail="rule kind")
    elif key == "status":
        add_values(["experimental", "reviewed", "deprecated", "disabled"], detail="rule lifecycle")
    elif key == "collection":
        add_values(sorted(typed), kind="collection", detail="retained SRL collection")
    elif key in {"condition", "selector"}:
        add_values([str(item.get("name")) for item in symbols.get("selectors") or []], kind="selector", detail="named selector")
        if key == "condition":
            add_values(["all", "any", "not", "count"], kind="function", detail="condition operator", docs=CONDITION_DOCS)
    elif key in {"any", "all"} and "facts" in "\n".join(lines[max(0, line_no - 5):line_no]).lower():
        add_values([str(item.get("name")) for item in symbols.get("facts") or []], kind="fact", detail="fact symbol")
    elif key == "severity":
        add_values(["critical", "high", "caution", "informational"], detail="finding severity")
    elif key == "confidence":
        add_values(["high", "medium", "low"], detail="confidence metadata")
    elif key in typed:
        add_values(sorted(typed), kind="collection", detail="retained SRL collection")

    # Collection/field/operator awareness based on indentation and the nearest selector.
    recent = "\n".join(lines[max(0, line_no - 8):line_no + 1])
    if (key == "requires" or ("requires:" in recent and current_line.lstrip().startswith("-"))) and not completions:
        add_values(sorted(typed), kind="collection", detail="required retained collection")
    where_line = _line_for_key(text, "where", after_line=int(selector.get("line") or 1)) if selector else 0
    if selector_collection and line_no >= where_line:
        field_key = key if key in collection_fields else str(lexical.get("currentField") or "")
        if not field_key:
            # The nearest typed field line in this selector determines operator suggestions.
            candidates = [(name, _line_for_key(text, str(name), after_line=where_line)) for name in collection_fields]
            candidates = [(name, ln) for name, ln in candidates if where_line <= ln <= line_no]
            if candidates:
                field_key = max(candidates, key=lambda item: item[1])[0]
        field_indent = int(lexical.get("whereIndent") or 4) + 2
        if key == "" and indent >= field_indent and not lexical.get("currentField"):
            for name, field_type in sorted(collection_fields.items()):
                completions.append(_completion(str(name), insert=f"{name}: ", kind="field", detail=str(field_type), documentation=f"{selector_collection}.{name} · {field_type}"))
        elif field_key and (key == field_key or indent >= field_indent + 2):
            add_values(_operator_names(str(collection_fields.get(field_key) or "string")), kind="operator", detail=f"operator for {collection_fields.get(field_key)}")

    if not completions and (not stripped_before.strip() or stripped_before.rstrip().endswith("-")):
        if indent <= 2:
            for name in ("schema", "id", "kind", "status", "requires", "selectors", "condition", "emit", "title", "description", "category", "severity", "license", "source"):
                completions.append(_completion(name, insert=f"{name}: ", kind="keyword", documentation=EDITOR_KEY_DOCS.get(name, "")))
        elif "emit:" in recent:
            for name in ("fact", "findingId", "confidence", "title", "description", "severity", "category"):
                completions.append(_completion(name, insert=f"{name}: ", kind="keyword", documentation=EDITOR_KEY_DOCS.get(name, "")))
        elif "selectors:" in recent:
            completions.append(_completion("collection", insert="collection: ", kind="keyword", documentation=EDITOR_KEY_DOCS["collection"]))
            completions.append(_completion("facts", insert="facts:\n  any: []", kind="keyword", documentation=EDITOR_KEY_DOCS["facts"]))

    # Filter duplicate/prefix-insensitive suggestions and cap the payload.
    unique: dict[tuple[str, str], dict[str, str]] = {}
    prefix = (value_prefix or token or "").strip().strip("[],'\"")
    for item in completions:
        if prefix and not item["label"].lower().startswith(prefix.lower()) and prefix.lower() not in item["label"].lower():
            continue
        unique[(item["label"], item["kind"])] = item
    completions = list(unique.values())[:80]

    hover = {"token": token, "documentation": "", "kind": ""}
    if token in EDITOR_KEY_DOCS:
        hover.update({"documentation": EDITOR_KEY_DOCS[token], "kind": "keyword"})
    elif token in CONDITION_DOCS:
        hover.update({"documentation": CONDITION_DOCS[token], "kind": "function"})
    elif token in srl.OPERATORS:
        hover.update({"documentation": f"Typed SRL predicate operator `{token}`. Validity depends on the selected field type.", "kind": "operator"})
    elif token in typed:
        fields = typed[token]
        hover.update({"documentation": f"Retained observation collection `{token}` with {len(fields)} typed SRL field(s).", "kind": "collection"})
    elif selector_collection and token in collection_fields:
        hover.update({"documentation": f"Field `{selector_collection}.{token}` · type `{collection_fields[token]}` · same-record selector semantics.", "kind": "field"})
    else:
        for group, kind in ((symbols.get("rules") or [], "rule"), (symbols.get("selectors") or [], "selector"), (symbols.get("facts") or [], "fact"), (symbols.get("findings") or [], "finding")):
            match = next((item for item in group if item.get("name") == token), None)
            if match:
                hover.update({"documentation": f"{kind.title()} `{token}` defined on line {match.get('line')}.", "kind": kind})
                break

    if compile_result.get("ok") and not diagnostics:
        diagnostics.append({"severity": "info", "stage": "compile", "message": "SRL candidate compiles cleanly with the frozen typed engine.", "line": 1, "column": 1})

    graph_edges: list[dict[str, str]] = []
    for item in symbols.get("selectors") or []:
        if item.get("collection"):
            graph_edges.append({"from": str(item.get("collection")), "to": str(item.get("name")), "kind": "collection→selector"})
    for item in symbols.get("facts") or []:
        graph_edges.append({"from": str(item.get("rule")), "to": str(item.get("name")), "kind": "rule→fact"})
    for item in symbols.get("findings") or []:
        graph_edges.append({"from": str(item.get("rule")), "to": str(item.get("name")), "kind": "rule→finding"})

    return {
        "schema": EDITOR_INTELLIGENCE_SCHEMA,
        "ok": bool(compile_result.get("ok")),
        "productionWriteBack": False,
        "mutationAuthority": "none",
        "cursor": {"line": line_no, "column": column, "token": token, "replaceStartColumn": replace_start, "replaceEndColumn": replace_end},
        "diagnostics": diagnostics,
        "completions": completions,
        "hover": hover,
        "symbols": symbols,
        "graph": {"edges": graph_edges},
        "metrics": {
            "bytes": len(text.encode("utf-8")),
            "lines": len(lines),
            "rules": len(symbols.get("rules") or []),
            "selectors": len(symbols.get("selectors") or []),
            "requiredCollections": len(compile_result.get("requiredCollections") or []),
        },
        "compile": {key: compile_result.get(key) for key in ("ok", "ruleSetRevision", "ruleIds", "requiredCollections", "findingIds")},
    }


class _NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:  # noqa: ANN401
        return True


def format_candidate_text(text: str) -> dict[str, Any]:
    try:
        document = srl.parse_yaml_text(text)
    except srl.SRLError as exc:
        line, column = _location_for_diagnostic(text, str(exc))
        return {
            "schema": FORMAT_SCHEMA, "ok": False, "productionWriteBack": False, "mutationAuthority": "none",
            "diagnostics": [{"severity": "error", "stage": "parse", "message": str(exc), "line": line, "column": column}],
        }
    rendered = yaml.dump(document, Dumper=_NoAliasDumper, allow_unicode=True, sort_keys=False, default_flow_style=False, width=120).rstrip() + "\n"
    compiled = compile_candidate_text(rendered)
    return {
        "schema": FORMAT_SCHEMA, "ok": bool(compiled.get("ok")), "yaml": rendered,
        "diagnostics": compiled.get("diagnostics") or [], "productionWriteBack": False, "mutationAuthority": "none",
    }

def build_github_issue_proposal(
    text: str, *, pack_id: str, pack_title: str, positive_fixture_text: str,
    negative_fixture_text: str, rationale: str, false_positive_expectations: str,
    provenance: str, license_text: str, repository: str = rule_candidate.DEFAULT_REPOSITORY,
    max_url_bytes: int = rule_candidate.MAX_GITHUB_PREFILL_URL_BYTES,
) -> dict[str, Any]:
    compiled = compile_candidate_text(text)
    if not compiled.get("ok"):
        return {
            "schema": rule_candidate.ISSUE_PREFILL_SCHEMA, "ok": False,
            "diagnostics": compiled.get("diagnostics") or [_diag("compile", "candidate compilation failed")],
            "productionWriteBack": False, "mutationAuthority": "none",
        }
    try:
        result = rule_candidate.build_issue_prefill(
            pack_id=pack_id, pack_title=pack_title, candidate_yaml=text,
            positive_fixture_yaml=positive_fixture_text, negative_fixture_yaml=negative_fixture_text,
            rationale=rationale, false_positive_expectations=false_positive_expectations,
            provenance=provenance, license_text=license_text, repository=repository,
            max_url_bytes=max_url_bytes,
        )
    except (rule_candidate.RuleCandidateError, srl.SRLError) as exc:
        return {
            "schema": rule_candidate.ISSUE_PREFILL_SCHEMA, "ok": False,
            "diagnostics": [_diag("proposal", str(exc))],
            "productionWriteBack": False, "mutationAuthority": "none",
        }
    result["candidateBundleAvailable"] = True
    result["note"] = (
        "Opening this URL only pre-fills GitHub's normal issue form. DeltaScope never submits the issue, "
        "uses no GitHub write API/token, and GitHub CI re-fetches/revalidates the submitted issue from scratch."
    )
    return result


def reference() -> dict[str, Any]:
    return {
        "schema": RULE_LAB_SCHEMA,
        "status": "local-experimental-no-production-writeback",
        "productionRuleEvaluationEnabled": False,
        "productionWriteBack": False,
        "engine": srl.engine_reference(),
        "observationContractRevision": observation_projection.contract_revision(),
        "collections": observation_projection.build_schema_reference().get("collections") or [],
        "exampleYaml": DEFAULT_EXAMPLE,
        "editor": {
            "schema": EDITOR_INTELLIGENCE_SCHEMA,
            "liveLint": True,
            "contextAwareCompletion": True,
            "typedCollections": srl.engine_reference().get("typedCollections") or {},
            "keyDocumentation": EDITOR_KEY_DOCS,
            "conditionDocumentation": CONDITION_DOCS,
            "keyboard": {"compile": "Ctrl/Cmd+Enter", "complete": "Ctrl/Cmd+Space", "format": "Shift+Alt+F"},
            "productionWriteBack": False,
            "mutationAuthority": "none",
        },
        "limits": {
            "candidateBytes": srl.MAX_DOCUMENT_BYTES,
            "corpusVariants": MAX_REPLAY_VARIANTS,
            "fixtureBytes": MAX_FIXTURE_BYTES,
            "exportNotesBytes": MAX_EXPORT_NOTES,
            "githubPrefillUrlBytes": rule_candidate.MAX_GITHUB_PREFILL_URL_BYTES,
        },
    }
