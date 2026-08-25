#!/usr/bin/env python3
"""Authorization-independent validation/materialization for SigmaScope rule candidates.

GitHub workflows remain responsible for *who* is allowed to promote. This module only
handles inert issue data: bounded parsing, SRL compilation, fixture checks, reviewed-pack
materialization, and fail-closed Definition Pack validation. It performs no network
requests, repository permission checks, git operations, PR creation, or production writes.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Iterable, Mapping
import urllib.parse

import yaml

from deltascope_sdk import definition_packs, srl

CANDIDATE_ISSUE_SCHEMA = "omega.sigmascope.rule-candidate-issue.v1"
VALIDATION_SCHEMA = "omega.sigmascope.rule-candidate-validation.v1"
PROMOTION_SCHEMA = "omega.sigmascope.rule-candidate-promotion.v1"
ISSUE_PREFILL_SCHEMA = "omega.deltascope.github-rule-candidate-prefill.v1"
DEFAULT_REPOSITORY = "dalagab/omega"
DEFAULT_ISSUE_TEMPLATE = "sigmascope-rule-candidate.yml"
MAX_GITHUB_PREFILL_URL_BYTES = 7500
ISSUE_FORM_FIELD_IDS = {
    "packId": "candidate-pack-id",
    "packTitle": "candidate-pack-title",
    "candidateYaml": "candidate-rule-yaml",
    "positiveFixtureYaml": "positive-fixture-yaml",
    "negativeFixtureYaml": "negative-fixture-yaml",
    "rationale": "rationale",
    "falsePositiveExpectations": "false-positive-expectations",
    "provenance": "external-provenance-source",
    "license": "license",
}
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

MAX_ISSUE_BODY_BYTES = 768 * 1024
MAX_SECTION_BYTES = 512 * 1024
MAX_FIXTURES_PER_POLARITY = 32
PACK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,79}$")
HEADING_RE = re.compile(r"^###\s+(.+?)\s*$", re.MULTILINE)

SECTION_ALIASES = {
    "packId": ("Candidate pack ID", "Pack ID"),
    "packTitle": ("Candidate pack title", "Pack title"),
    "candidateYaml": ("Candidate rule YAML", "Candidate YAML"),
    "positiveFixtures": ("Positive fixture YAML", "Positive fixtures"),
    "negativeFixtures": ("Negative fixture YAML", "Negative fixtures"),
    "rationale": ("Rationale", "Rule rationale"),
    "falsePositiveExpectations": ("False-positive expectations", "False positive expectations"),
    "provenance": ("External provenance / source", "External provenance", "Provenance / source"),
    "license": ("License", "Rule license"),
}


class RuleCandidateError(ValueError):
    pass


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha(value: Any) -> str:
    return _sha_bytes(_canonical(value))


def _bounded_text(value: Any, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleCandidateError(f"{label} is required")
    text = value.strip()
    if len(text.encode("utf-8")) > maximum:
        raise RuleCandidateError(f"{label} exceeds {maximum} bytes")
    return text


def _extract_sections(body: str) -> dict[str, str]:
    raw = body.encode("utf-8")
    if len(raw) > MAX_ISSUE_BODY_BYTES:
        raise RuleCandidateError(f"issue body exceeds {MAX_ISSUE_BODY_BYTES} bytes")
    matches = list(HEADING_RE.finditer(body))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        heading = match.group(1).strip()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        value = body[start:end].strip()
        if heading in sections:
            raise RuleCandidateError(f"duplicate issue section: {heading}")
        sections[heading] = value
    return sections


def _strip_fence(text: str, label: str) -> str:
    value = text.strip()
    if not value.startswith("```"):
        return value
    lines = value.splitlines()
    if len(lines) < 3 or not lines[-1].strip().startswith("```"):
        raise RuleCandidateError(f"{label} has an unterminated Markdown code fence")
    if any(line.strip().startswith("```") for line in lines[1:-1]):
        raise RuleCandidateError(f"{label} must contain exactly one fenced YAML block")
    return "\n".join(lines[1:-1]).strip()


def _section(sections: Mapping[str, str], key: str, *, maximum: int, fence: bool = False) -> str:
    aliases = SECTION_ALIASES[key]
    found = [(name, sections[name]) for name in aliases if name in sections]
    if not found:
        raise RuleCandidateError(f"missing issue section: {aliases[0]}")
    if len(found) > 1:
        raise RuleCandidateError(f"issue contains multiple aliases for {aliases[0]}")
    value = _bounded_text(found[0][1], aliases[0], maximum=maximum)
    return _strip_fence(value, aliases[0]) if fence else value


def parse_issue(issue: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(issue, Mapping):
        raise RuleCandidateError("issue JSON must be an object")
    if issue.get("pull_request"):
        raise RuleCandidateError("rule candidates must originate from a normal issue, not a pull request")
    try:
        issue_number = int(issue.get("number") or 0)
    except (TypeError, ValueError) as exc:
        raise RuleCandidateError("issue number is missing or invalid") from exc
    if issue_number <= 0:
        raise RuleCandidateError("issue number is missing or invalid")
    body = _bounded_text(issue.get("body"), "issue body", maximum=MAX_ISSUE_BODY_BYTES)
    sections = _extract_sections(body)
    pack_id = _section(sections, "packId", maximum=80)
    if not PACK_ID_RE.fullmatch(pack_id):
        raise RuleCandidateError("Candidate pack ID must be 3-80 lowercase letters/numbers/dot/underscore/hyphen and may not contain paths")
    pack_title = _section(sections, "packTitle", maximum=200)
    candidate_yaml = _section(sections, "candidateYaml", maximum=srl.MAX_DOCUMENT_BYTES, fence=True)
    positive = _section(sections, "positiveFixtures", maximum=MAX_SECTION_BYTES, fence=True)
    negative = _section(sections, "negativeFixtures", maximum=MAX_SECTION_BYTES, fence=True)
    rationale = _section(sections, "rationale", maximum=8000)
    false_positive = _section(sections, "falsePositiveExpectations", maximum=8000)
    provenance = _section(sections, "provenance", maximum=4000)
    license_text = _section(sections, "license", maximum=160)
    author = issue.get("user") if isinstance(issue.get("user"), Mapping) else {}
    issue_url = str(issue.get("html_url") or "").strip()
    updated_at = str(issue.get("updated_at") or "").strip()
    issue_body_sha256 = _sha_bytes(body.encode("utf-8"))
    return {
        "schema": CANDIDATE_ISSUE_SCHEMA,
        "issueNumber": issue_number,
        "issueUrl": issue_url,
        "issueUpdatedAt": updated_at,
        "issueAuthor": str(author.get("login") or ""),
        "issueBodySha256": issue_body_sha256,
        "packId": pack_id,
        "packTitle": pack_title,
        "candidateYaml": candidate_yaml,
        "positiveFixtureYaml": positive,
        "negativeFixtureYaml": negative,
        "rationale": rationale,
        "falsePositiveExpectations": false_positive,
        "provenance": provenance,
        "license": license_text,
    }


def _candidate_rules_document(text: str) -> Any:
    document = srl.parse_yaml_text(text)
    compiled = srl.compile_ruleset(document)
    if not compiled.get("rules"):
        raise RuleCandidateError("candidate must contain at least one SRL rule")
    return document


def _rules_from_document(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, Mapping) and document.get("schema") == srl.RULE_SCHEMA:
        return [dict(document)]
    if isinstance(document, Mapping) and document.get("schema") == srl.RULESET_SCHEMA:
        rules = document.get("rules")
        if not isinstance(rules, list) or not rules:
            raise RuleCandidateError("candidate ruleset requires a non-empty rules list")
        if any(not isinstance(rule, Mapping) for rule in rules):
            raise RuleCandidateError("candidate ruleset contains a non-mapping rule")
        return [dict(rule) for rule in rules]
    if isinstance(document, list):
        if not document or any(not isinstance(rule, Mapping) for rule in document):
            raise RuleCandidateError("candidate rule list must contain rule mappings")
        return [dict(rule) for rule in document]
    raise RuleCandidateError("candidate must contain an SRL rule or ruleset")


def reviewed_document(candidate_text: str) -> dict[str, Any]:
    document = _candidate_rules_document(candidate_text)
    rules = _rules_from_document(document)
    reviewed_rules: list[dict[str, Any]] = []
    for raw in rules:
        rule = copy.deepcopy(raw)
        candidate_status = str(rule.get("status") or "experimental")
        if candidate_status not in {"experimental", "reviewed"}:
            raise RuleCandidateError(
                f"candidate rule {rule.get('id') or '<unknown>'} status must be experimental or reviewed before promotion"
            )
        # Candidate status is never authority. Promotion is an explicit repository-
        # authorized act, so the materialized source-controlled copy is stamped reviewed.
        rule["status"] = "reviewed"
        reviewed_rules.append(rule)
    reviewed = {"schema": srl.RULESET_SCHEMA, "rules": reviewed_rules}
    srl.compile_ruleset(reviewed)
    return reviewed


def _parse_fixture_set(text: str, label: str) -> list[dict[str, Any]]:
    value = srl.parse_yaml_text(text)
    if isinstance(value, Mapping):
        fixtures = [dict(value)]
    elif isinstance(value, list) and value and all(isinstance(item, Mapping) for item in value):
        fixtures = [dict(item) for item in value]
    else:
        raise RuleCandidateError(f"{label} must be one fixture mapping or a YAML list of fixture mappings")
    if len(fixtures) > MAX_FIXTURES_PER_POLARITY:
        raise RuleCandidateError(f"{label} exceeds {MAX_FIXTURES_PER_POLARITY} fixtures")
    return fixtures


def _fixture_summary(compiled: Mapping[str, Any], fixtures: Iterable[Mapping[str, Any]], polarity: str) -> tuple[list[dict[str, Any]], set[str]]:
    rows: list[dict[str, Any]] = []
    covered_rules: set[str] = set()
    candidate_rule_ids = {str(rule.get("id") or "") for rule in compiled.get("rules") or []}
    for index, fixture in enumerate(fixtures, 1):
        try:
            result = srl.run_fixture(compiled, fixture)
        except (srl.SRLError, ValueError) as exc:
            raise RuleCandidateError(f"{polarity} fixture {index} is invalid: {exc}") from exc
        if not result.get("passed"):
            raise RuleCandidateError(f"{polarity} fixture {index} failed: {'; '.join(result.get('failures') or [])}")
        evaluation = result.get("evaluation") if isinstance(result.get("evaluation"), Mapping) else {}
        matched = {str(item.get("ruleId") or "") for item in evaluation.get("rules") or [] if isinstance(item, Mapping) and item.get("matched")}
        findings = {str(item.get("findingId") or item.get("ruleId") or "") for item in evaluation.get("findings") or [] if isinstance(item, Mapping)}
        facts = {str(item) for item in evaluation.get("facts") or [] if str(item)}
        if polarity == "positive":
            if not (matched & candidate_rule_ids):
                raise RuleCandidateError(f"positive fixture {index} does not match any candidate rule")
            covered_rules.update(matched & candidate_rule_ids)
        elif matched & candidate_rule_ids:
            raise RuleCandidateError(f"negative fixture {index} unexpectedly matches candidate rule(s): {sorted(matched & candidate_rule_ids)}")
        rows.append({
            "name": str(result.get("name") or f"{polarity}-{index}"),
            "matchedRules": sorted(matched),
            "findingIds": sorted(findings),
            "facts": sorted(facts),
        })
    return rows, covered_rules


def validate_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    reviewed = reviewed_document(str(candidate["candidateYaml"]))
    compiled = srl.compile_ruleset(reviewed)
    positive_fixtures = _parse_fixture_set(str(candidate["positiveFixtureYaml"]), "Positive fixture YAML")
    negative_fixtures = _parse_fixture_set(str(candidate["negativeFixtureYaml"]), "Negative fixture YAML")
    positive_rows, covered = _fixture_summary(compiled, positive_fixtures, "positive")
    negative_rows, _ = _fixture_summary(compiled, negative_fixtures, "negative")
    rule_ids = sorted(str(rule.get("id") or "") for rule in compiled.get("rules") or [])
    missing = sorted(set(rule_ids) - covered)
    if missing:
        raise RuleCandidateError(f"positive fixtures do not exercise every candidate rule: {missing}")
    emitted_facts = sorted(str(name) for name in (compiled.get("emittedFacts") or {}).keys())
    finding_ids = sorted({
        str((rule.get("emit") or {}).get("findingId") or rule.get("id") or "")
        for rule in compiled.get("rules") or []
        if isinstance(rule, Mapping) and str(rule.get("kind") or "") == "correlation"
    })
    return {
        "schema": VALIDATION_SCHEMA,
        "ok": True,
        "issueNumber": int(candidate["issueNumber"]),
        "issueUrl": str(candidate.get("issueUrl") or ""),
        "issueBodySha256": str(candidate["issueBodySha256"]),
        "packId": str(candidate["packId"]),
        "packTitle": str(candidate["packTitle"]),
        "ruleSetRevision": str(compiled.get("ruleSetRevision") or ""),
        "ruleIds": rule_ids,
        "emittedFacts": emitted_facts,
        "findingIds": finding_ids,
        "positiveFixtures": positive_rows,
        "negativeFixtures": negative_rows,
        "requiredCollections": sorted({str(req) for rule in compiled.get("rules") or [] for req in (rule.get("requires") or []) if str(req)}),
        "reviewStatusSource": "repository-authorized-promotion-only; candidate status is ignored",
        "candidateAuthorIsAuthorization": False,
        "productionWriteBack": False,
        "reviewedDocument": reviewed,
        "positiveFixtureDocuments": positive_fixtures,
        "negativeFixtureDocuments": negative_fixtures,
    }


class _NoAliasSafeDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:  # noqa: ANN001 - PyYAML hook
        return True


def _dump_yaml(value: Any) -> bytes:
    return yaml.dump(value, Dumper=_NoAliasSafeDumper, sort_keys=False, allow_unicode=True).encode("utf-8")


def _write_candidate_pack(pack_root: Path, candidate: Mapping[str, Any], validation: Mapping[str, Any], *, reviewer: str, reviewed_at: str) -> None:
    rules_dir = pack_root / "rules"
    fixtures_dir = pack_root / "fixtures"
    rules_dir.mkdir(parents=True, exist_ok=False)
    fixtures_dir.mkdir(parents=True, exist_ok=False)

    rules_rel = "rules/candidate.yaml"
    (pack_root / rules_rel).write_bytes(_dump_yaml(validation["reviewedDocument"]))
    fixture_entries: list[dict[str, str]] = []
    for polarity, documents in (
        ("positive", validation["positiveFixtureDocuments"]),
        ("negative", validation["negativeFixtureDocuments"]),
    ):
        for index, fixture in enumerate(documents, 1):
            rel = f"fixtures/{polarity}-{index:02d}.fixture.yaml"
            (pack_root / rel).write_bytes(_dump_yaml(fixture))
            fixture_entries.append({"path": rel})

    source = str(candidate.get("issueUrl") or f"GitHub issue #{candidate['issueNumber']}")
    provenance_source = (
        f"{source}; issueBodySha256={candidate['issueBodySha256']}; "
        f"submittedBy={candidate.get('issueAuthor') or 'unknown'}; external={candidate['provenance']}"
    )
    rule_ids = list(validation["ruleIds"])
    metadata = {
        "license": str(candidate["license"]),
        "provenance": {"kind": "github-rule-candidate", "source": provenance_source[:1024]},
        "review": {"reviewer": reviewer, "reviewedAtUtc": reviewed_at},
    }
    manifest = {
        "schema": definition_packs.PACK_SCHEMA,
        "id": str(candidate["packId"]),
        "title": str(candidate["packTitle"]),
        "description": (
            f"Promoted from SigmaScope rule candidate issue #{candidate['issueNumber']}. "
            f"Rationale: {candidate['rationale']} False-positive expectations: {candidate['falsePositiveExpectations']}"
        )[:4000],
        "trustTier": "reviewed",
        **metadata,
        "compatibility": {
            "minimumSrlEngineVersion": definition_packs.ENGINE_VERSION,
            "minimumObservationContractVersion": definition_packs.OBSERVATION_CONTRACT_VERSION,
            "ruleSchema": srl.RULE_SCHEMA,
            "fixtureSchema": srl.FIXTURE_SCHEMA,
            "observationContractSchema": definition_packs.observation_projection.OBSERVATION_CONTRACT_SCHEMA,
        },
        "rules": [{"path": rules_rel, "ids": rule_ids, **metadata}],
        "fixtures": fixture_entries,
    }
    (pack_root / "pack.yaml").write_bytes(_dump_yaml(manifest))


def _validate_against_root(packs_root: Path, candidate: Mapping[str, Any], validation: Mapping[str, Any], *, reviewer: str, reviewed_at: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="omega-rule-candidate-") as tmp:
        temp_root = Path(tmp) / "packs"
        if packs_root.exists():
            shutil.copytree(packs_root, temp_root, symlinks=False)
        else:
            temp_root.mkdir(parents=True)
        target = temp_root / str(candidate["packId"])
        if target.exists():
            raise RuleCandidateError(f"Definition Pack already exists: {candidate['packId']}")
        target.mkdir()
        _write_candidate_pack(target, candidate, validation, reviewer=reviewer, reviewed_at=reviewed_at)
        try:
            compiled_root = definition_packs.compile_pack_root(temp_root)
        except (definition_packs.DefinitionPackError, srl.SRLError) as exc:
            raise RuleCandidateError(f"candidate fails Definition Pack root validation: {exc}") from exc
        pack = next((item for item in compiled_root.get("packs") or [] if item.get("id") == candidate["packId"]), None)
        if not isinstance(pack, Mapping):
            raise RuleCandidateError("candidate did not materialize into the Definition Pack root")
        return {
            "definitionPackRevisionPreview": str(compiled_root.get("definitionPackRevision") or ""),
            "ruleSetRevisionPreview": str(compiled_root.get("ruleSetRevision") or ""),
            "packRevision": str(pack.get("packRevision") or ""),
        }


def validate_issue(issue: Mapping[str, Any], packs_root: Path) -> dict[str, Any]:
    try:
        candidate = parse_issue(issue)
        validation = validate_candidate(candidate)
        preview = _validate_against_root(
            packs_root,
            candidate,
            validation,
            reviewer="candidate-validation-only",
            reviewed_at="2000-01-01T00:00:00Z",
        )
        public = {key: value for key, value in validation.items() if key not in {"reviewedDocument", "positiveFixtureDocuments", "negativeFixtureDocuments"}}
        return {**public, **preview, "ok": True}
    except (RuleCandidateError, srl.SRLError, definition_packs.DefinitionPackError) as exc:
        return {"schema": VALIDATION_SCHEMA, "ok": False, "errors": [str(exc)[:4000]], "productionWriteBack": False}



def build_issue_prefill(
    *,
    pack_id: str,
    pack_title: str,
    candidate_yaml: str,
    positive_fixture_yaml: str,
    negative_fixture_yaml: str,
    rationale: str,
    false_positive_expectations: str,
    provenance: str,
    license_text: str,
    repository: str = DEFAULT_REPOSITORY,
    template: str = DEFAULT_ISSUE_TEMPLATE,
    max_url_bytes: int = MAX_GITHUB_PREFILL_URL_BYTES,
) -> dict[str, Any]:
    """Build a browser-only GitHub Issue Form prefill URL.

    This performs no network request and grants no GitHub/repository authority.  It
    validates the candidate/fixtures with the same authorization-independent logic
    used by the Phase-9 workflow, then URL-encodes the canonical Issue Form field IDs.
    GitHub remains responsible for showing the form, the operator must submit it, and
    the workflow re-fetches/revalidates the resulting issue from scratch.
    """
    repository = _bounded_text(repository, "repository", maximum=200)
    if not REPOSITORY_RE.fullmatch(repository):
        raise RuleCandidateError("repository must be in owner/name form")
    template = _bounded_text(template, "issue template", maximum=160)
    if "/" in template or "\\" in template or not template.endswith((".yml", ".yaml")):
        raise RuleCandidateError("issue template must be a YAML filename")

    pack_id = _bounded_text(pack_id, "Candidate pack ID", maximum=80)
    if not PACK_ID_RE.fullmatch(pack_id):
        raise RuleCandidateError("Candidate pack ID must be 3-80 lowercase letters/numbers/dot/underscore/hyphen and may not contain paths")
    pack_title = _bounded_text(pack_title, "Candidate pack title", maximum=200)
    candidate_yaml = _bounded_text(candidate_yaml, "Candidate rule YAML", maximum=srl.MAX_DOCUMENT_BYTES)
    positive_fixture_yaml = _bounded_text(positive_fixture_yaml, "Positive fixture YAML", maximum=MAX_SECTION_BYTES)
    negative_fixture_yaml = _bounded_text(negative_fixture_yaml, "Negative fixture YAML", maximum=MAX_SECTION_BYTES)
    rationale = _bounded_text(rationale, "Rationale", maximum=8000)
    false_positive_expectations = _bounded_text(false_positive_expectations, "False-positive expectations", maximum=8000)
    provenance = _bounded_text(provenance, "External provenance / source", maximum=4000)
    license_text = _bounded_text(license_text, "License", maximum=160)

    # Reuse the exact candidate/fixture semantic validator.  Placeholder issue
    # metadata is intentionally non-authoritative and never leaves this function.
    validation = validate_candidate({
        "issueNumber": 1,
        "issueUrl": "",
        "issueBodySha256": "0" * 64,
        "packId": pack_id,
        "packTitle": pack_title,
        "candidateYaml": candidate_yaml,
        "positiveFixtureYaml": positive_fixture_yaml,
        "negativeFixtureYaml": negative_fixture_yaml,
        "rationale": rationale,
        "falsePositiveExpectations": false_positive_expectations,
        "provenance": provenance,
        "license": license_text,
    })

    title = f"SigmaScope rule candidate: {pack_id}"
    fields = [
        ("template", template),
        ("title", title),
        (ISSUE_FORM_FIELD_IDS["packId"], pack_id),
        (ISSUE_FORM_FIELD_IDS["packTitle"], pack_title),
        (ISSUE_FORM_FIELD_IDS["candidateYaml"], candidate_yaml),
        (ISSUE_FORM_FIELD_IDS["positiveFixtureYaml"], positive_fixture_yaml),
        (ISSUE_FORM_FIELD_IDS["negativeFixtureYaml"], negative_fixture_yaml),
        (ISSUE_FORM_FIELD_IDS["rationale"], rationale),
        (ISSUE_FORM_FIELD_IDS["falsePositiveExpectations"], false_positive_expectations),
        (ISSUE_FORM_FIELD_IDS["provenance"], provenance),
        (ISSUE_FORM_FIELD_IDS["license"], license_text),
    ]
    base = f"https://github.com/{repository}/issues/new"
    full_url = base + "?" + urllib.parse.urlencode(fields, quote_via=urllib.parse.quote)
    full_bytes = len(full_url.encode("utf-8"))

    # If the complete URL would be risky, open the same Issue Form with the small
    # metadata fields prefilled and require explicit paste of the three potentially
    # large YAML fields.  DeltaScope still never submits anything itself.
    metadata_fields = [
        ("template", template),
        ("title", title),
        (ISSUE_FORM_FIELD_IDS["packId"], pack_id),
        (ISSUE_FORM_FIELD_IDS["packTitle"], pack_title),
        (ISSUE_FORM_FIELD_IDS["rationale"], rationale),
        (ISSUE_FORM_FIELD_IDS["falsePositiveExpectations"], false_positive_expectations),
        (ISSUE_FORM_FIELD_IDS["provenance"], provenance),
        (ISSUE_FORM_FIELD_IDS["license"], license_text),
    ]
    identity_fields = [
        ("template", template),
        ("title", title),
        (ISSUE_FORM_FIELD_IDS["packId"], pack_id),
        (ISSUE_FORM_FIELD_IDS["packTitle"], pack_title),
        (ISSUE_FORM_FIELD_IDS["license"], license_text),
    ]
    template_fields = [("template", template), ("title", title)]
    maximum = max(512, int(max_url_bytes))
    candidates = [
        ("complete-prefill", fields, []),
        ("metadata-prefill", metadata_fields, [ISSUE_FORM_FIELD_IDS["candidateYaml"], ISSUE_FORM_FIELD_IDS["positiveFixtureYaml"], ISSUE_FORM_FIELD_IDS["negativeFixtureYaml"]]),
        ("identity-prefill", identity_fields, [ISSUE_FORM_FIELD_IDS["candidateYaml"], ISSUE_FORM_FIELD_IDS["positiveFixtureYaml"], ISSUE_FORM_FIELD_IDS["negativeFixtureYaml"], ISSUE_FORM_FIELD_IDS["rationale"], ISSUE_FORM_FIELD_IDS["falsePositiveExpectations"], ISSUE_FORM_FIELD_IDS["provenance"]]),
        ("template-only", template_fields, list(ISSUE_FORM_FIELD_IDS.values())),
    ]
    chosen_mode, chosen_url, omitted = "template-only", base, [item[0] for item in fields if item[0] not in {"template", "title"}]
    for mode, option_fields, option_omitted in candidates:
        option_url = base + "?" + urllib.parse.urlencode(option_fields, quote_via=urllib.parse.quote)
        if len(option_url.encode("utf-8")) <= maximum or mode == "template-only":
            chosen_mode, chosen_url, omitted = mode, option_url, option_omitted
            break
    direct = chosen_mode == "complete-prefill"
    return {
        "schema": ISSUE_PREFILL_SCHEMA,
        "ok": True,
        "repository": repository,
        "template": template,
        "mode": chosen_mode,
        "openUrl": chosen_url,
        "completePrefillUrlBytes": full_bytes,
        "openUrlBytes": len(chosen_url.encode("utf-8")),
        "maxUrlBytes": maximum,
        "manualPasteRequired": not direct,
        "omittedFieldIds": omitted,
        "ruleIds": list(validation.get("ruleIds") or []),
        "ruleSetRevision": str(validation.get("ruleSetRevision") or ""),
        "githubSubmissionRequired": True,
        "githubWillRevalidate": True,
        "repositoryCollisionChecked": False,
        "githubWillCheckPackCollision": True,
        "githubApiWrite": False,
        "repositoryCredentialsRequired": False,
        "productionWriteBack": False,
        "mutationAuthority": "none",
    }

def _normalize_timestamp(value: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuleCandidateError("reviewed-at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RuleCandidateError("reviewed-at must include a timezone")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def materialize_issue(issue: Mapping[str, Any], packs_root: Path, *, reviewer: str, reviewed_at: str) -> dict[str, Any]:
    reviewer = _bounded_text(reviewer, "reviewer", maximum=160)
    reviewed_at = _normalize_timestamp(reviewed_at)
    candidate = parse_issue(issue)
    validation = validate_candidate(candidate)
    preview = _validate_against_root(packs_root, candidate, validation, reviewer=reviewer, reviewed_at=reviewed_at)
    target = packs_root / str(candidate["packId"])
    if target.exists():
        raise RuleCandidateError(f"Definition Pack already exists: {candidate['packId']}")
    packs_root.mkdir(parents=True, exist_ok=True)
    target.mkdir()
    try:
        _write_candidate_pack(target, candidate, validation, reviewer=reviewer, reviewed_at=reviewed_at)
        compiled_root = definition_packs.compile_pack_root(packs_root)
        pack = next((item for item in compiled_root.get("packs") or [] if item.get("id") == candidate["packId"]), None)
        if not isinstance(pack, Mapping):
            raise RuleCandidateError("materialized candidate is missing from Definition Pack root")
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise
    return {
        "schema": PROMOTION_SCHEMA,
        "ok": True,
        "issueNumber": int(candidate["issueNumber"]),
        "issueUrl": str(candidate.get("issueUrl") or ""),
        "issueBodySha256": str(candidate["issueBodySha256"]),
        "packId": str(candidate["packId"]),
        "packPath": target.relative_to(packs_root.parent.parent).as_posix() if len(target.parents) >= 2 else target.as_posix(),
        "reviewer": reviewer,
        "reviewedAtUtc": reviewed_at,
        "ruleIds": list(validation["ruleIds"]),
        "packRevision": str(pack.get("packRevision") or preview.get("packRevision") or ""),
        "definitionPackRevisionPreview": str(compiled_root.get("definitionPackRevision") or ""),
        "ruleSetRevisionPreview": str(compiled_root.get("ruleSetRevision") or ""),
        "candidateAuthorIsAuthorization": False,
        "productionWriteBack": False,
        "normalPullRequestReviewRequired": True,
    }


def validation_comment(result: Mapping[str, Any]) -> str:
    if not result.get("ok"):
        errors = result.get("errors") or ["candidate validation failed"]
        detail = "\n".join(f"- {str(error)}" for error in errors)
        return (
            "SigmaScope candidate validation **failed**. The submitted YAML was treated as inert data; no repository content was changed.\n\n"
            f"{detail}\n\n"
            "Fix the issue fields and edit/reopen the candidate. A passing validation is not promotion authority."
        )
    rules = ", ".join(f"`{item}`" for item in result.get("ruleIds") or []) or "none"
    return (
        "SigmaScope candidate validation **passed**. The candidate and positive/negative fixtures compile with the current SRL/Definition Pack contracts.\n\n"
        f"- Pack: `{result.get('packId')}`\n"
        f"- Rules: {rules}\n"
        f"- Candidate ruleset: `{result.get('ruleSetRevision')}`\n"
        f"- Preview pack revision: `{result.get('packRevision')}`\n"
        f"- Issue body SHA-256: `{result.get('issueBodySha256')}`\n\n"
        "This validation does **not** authorize promotion. Only a separately permission-checked repository actor may trigger the promotion workflow, which re-fetches and revalidates the issue from scratch before opening a normal PR."
    )


def promotion_comment(result: Mapping[str, Any], pr_url: str = "") -> str:
    suffix = f" PR: {pr_url}" if pr_url else ""
    return (
        f"Authorized candidate materialization completed for `{result.get('packId')}` and requires normal pull-request review.{suffix}\n\n"
        f"Issue body SHA-256: `{result.get('issueBodySha256')}`. Production SRL projection remains disabled; merging a reviewed pack only makes it eligible for the later Daily Definitions freeze."
    )


def _load_issue(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuleCandidateError("issue JSON must be an object")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate or materialize inert SigmaScope rule-candidate issue data")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "promote"):
        child = sub.add_parser(command)
        child.add_argument("--issue-json", required=True, type=Path)
        child.add_argument("--packs-root", required=True, type=Path)
        child.add_argument("--result", required=True, type=Path)
        child.add_argument("--comment", type=Path)
        if command == "promote":
            child.add_argument("--reviewer", required=True)
            child.add_argument("--reviewed-at", required=True)
    args = parser.parse_args()
    try:
        issue = _load_issue(args.issue_json)
        if args.command == "validate":
            result = validate_issue(issue, args.packs_root)
            comment = validation_comment(result)
            rc = 0 if result.get("ok") else 2
        else:
            try:
                result = materialize_issue(
                    issue,
                    args.packs_root,
                    reviewer=args.reviewer,
                    reviewed_at=args.reviewed_at,
                )
                comment = promotion_comment(result)
                rc = 0
            except (RuleCandidateError, srl.SRLError, definition_packs.DefinitionPackError) as exc:
                result = {"schema": PROMOTION_SCHEMA, "ok": False, "errors": [str(exc)[:4000]], "productionWriteBack": False}
                comment = validation_comment(result)
                rc = 2
        _write_json(args.result, result)
        if args.comment:
            args.comment.write_text(comment + "\n", encoding="utf-8")
        return rc
    except (RuleCandidateError, OSError, json.JSONDecodeError) as exc:
        result = {"schema": VALIDATION_SCHEMA, "ok": False, "errors": [str(exc)[:4000]], "productionWriteBack": False}
        _write_json(args.result, result)
        if args.comment:
            args.comment.write_text(validation_comment(result) + "\n", encoding="utf-8")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
