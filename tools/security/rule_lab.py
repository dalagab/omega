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
import io
import json
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
        "limits": {
            "candidateBytes": srl.MAX_DOCUMENT_BYTES,
            "corpusVariants": MAX_REPLAY_VARIANTS,
            "fixtureBytes": MAX_FIXTURE_BYTES,
            "exportNotesBytes": MAX_EXPORT_NOTES,
            "githubPrefillUrlBytes": rule_candidate.MAX_GITHUB_PREFILL_URL_BYTES,
        },
    }
