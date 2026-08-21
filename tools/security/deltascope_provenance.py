#!/usr/bin/env python3
"""Read-only Definition/Rule provenance projection for DeltaScope.

The provenance sidecar is derived from the exact frozen Daily Definitions snapshot that
SigmaScope already validated.  It is navigation/audit metadata only: it is never a rule
input, observation, finding, queue instruction, or writable Definition surface.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from . import definition_packs
except ImportError:  # direct execution / worker-style import path
    import definition_packs  # type: ignore

DEFINITION_PROVENANCE_SCHEMA = "omega.security-evidence.definition-provenance.v1"
MAX_PROVENANCE_BYTES = 8 * 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value




def _semantic_core(value: Mapping[str, Any]) -> dict[str, Any]:
    definitions = value.get("definitions") if isinstance(value.get("definitions"), Mapping) else {}
    semantic_definitions = {
        key: definitions.get(key)
        for key in (
            "definitionsRevision", "scannerVersion", "scannerRevision",
            "artifactAnalysisRevision", "sourceAnalysisRevision", "sourceObservationRevision",
            "legacyRuleSetRevision", "advisoryRevision",
        )
        if definitions.get(key) is not None
    }
    return {
        "definitions": semantic_definitions,
        "srl": dict(value.get("srl") or {}) if isinstance(value.get("srl"), Mapping) else {},
        "packs": [dict(item) for item in value.get("packs") or [] if isinstance(item, Mapping)],
        "activeRules": [dict(item) for item in value.get("activeRules") or [] if isinstance(item, Mapping)],
    }

def _safe_pack_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for name in ("license", "provenance", "review"):
        item = value.get(name)
        if isinstance(item, Mapping):
            result[name] = {str(k): v for k, v in item.items() if isinstance(v, (str, int, float, bool)) or v is None}
        elif isinstance(item, str):
            result[name] = item
    return result


def build_definition_provenance(definitions_root: Path) -> dict[str, Any]:
    """Build deterministic read-only provenance from a verified frozen Definitions root."""
    definitions_root = definitions_root.resolve()
    parent = _read_json(definitions_root / "index.json")
    descriptor = parent.get("srlDefinitionPacks") if isinstance(parent.get("srlDefinitionPacks"), Mapping) else {}
    if not descriptor:
        raise ValueError("frozen Definitions contain no SRL Definition Pack descriptor")
    validation = definition_packs.verify_frozen(definitions_root, descriptor)
    if not validation.get("ok"):
        raise ValueError("frozen Definition Packs failed verification: " + "; ".join(validation.get("errors") or []))

    srl_index = _read_json(definitions_root / str(descriptor.get("path") or ""))
    compiled = definition_packs.load_frozen_ruleset(definitions_root, descriptor)
    compiled_rules = {
        str(rule.get("id") or ""): dict(rule)
        for rule in compiled.get("rules") or []
        if isinstance(rule, Mapping) and str(rule.get("id") or "")
    }

    packs: list[dict[str, Any]] = []
    active_rules: list[dict[str, Any]] = []
    for raw_pack in srl_index.get("packs") or []:
        if not isinstance(raw_pack, Mapping):
            continue
        pack_id = str(raw_pack.get("id") or "")
        pack_rule_rows: list[dict[str, Any]] = []
        for source in raw_pack.get("rules") or []:
            if not isinstance(source, Mapping):
                continue
            source_meta = _safe_pack_metadata(source)
            for rule_id in source.get("ruleIds") or []:
                rule_id = str(rule_id or "")
                rule = compiled_rules.get(rule_id)
                if rule is None:
                    # Experimental/non-production pack rules are not present in the active
                    # compiled ruleset. Keep their source identity visible without inventing
                    # executable semantics.
                    pack_rule_rows.append({
                        "ruleId": rule_id,
                        "active": False,
                        "ruleRevision": str((source.get("ruleRevisions") or {}).get(rule_id) or ""),
                        "sourcePath": str(source.get("path") or ""),
                        "sourceSha256": str(source.get("sha256") or ""),
                        "sourceBytes": int(source.get("bytes") or 0),
                        **source_meta,
                    })
                    continue
                emit = rule.get("emit") if isinstance(rule.get("emit"), Mapping) else {}
                row = {
                    "ruleId": rule_id,
                    "active": True,
                    "kind": str(rule.get("kind") or ""),
                    "status": str(rule.get("status") or ""),
                    "ruleRevision": str(rule.get("ruleRevision") or ""),
                    "requires": list(rule.get("requires") or []),
                    "selectors": rule.get("selectors") or [],
                    "condition": rule.get("condition") or {},
                    "emit": dict(emit),
                    "sourcePath": str(source.get("path") or ""),
                    "sourceSha256": str(source.get("sha256") or ""),
                    "sourceBytes": int(source.get("bytes") or 0),
                    **source_meta,
                }
                pack_rule_rows.append(row)
                active_rules.append({**row, "packId": pack_id})
        fixtures = []
        for fixture in raw_pack.get("fixtures") or []:
            if isinstance(fixture, Mapping):
                fixtures.append({
                    "path": str(fixture.get("path") or ""),
                    "sha256": str(fixture.get("sha256") or ""),
                    "bytes": int(fixture.get("bytes") or 0),
                    "name": str(fixture.get("name") or ""),
                    "passed": bool(fixture.get("passed")),
                })
        fixtures.sort(key=lambda item: item["path"].casefold())
        pack_rule_rows.sort(key=lambda item: item["ruleId"])
        packs.append({
            "packId": pack_id,
            "title": str(raw_pack.get("title") or pack_id),
            "description": str(raw_pack.get("description") or ""),
            "trustTier": str(raw_pack.get("trustTier") or ""),
            "productionEligible": bool(raw_pack.get("productionEligible")),
            "packRevision": str(raw_pack.get("packRevision") or ""),
            "compiledRuleSetRevision": str(raw_pack.get("compiledRuleSetRevision") or ""),
            "manifest": dict(raw_pack.get("manifest") or {}),
            "compatibility": dict(raw_pack.get("compatibility") or {}),
            "metadata": _safe_pack_metadata(raw_pack.get("metadata")),
            "rules": pack_rule_rows,
            "fixtures": fixtures,
        })
    packs.sort(key=lambda item: item["packId"])
    active_rules.sort(key=lambda item: item["ruleId"])

    parity_descriptor = descriptor.get("migrationParity") if isinstance(descriptor.get("migrationParity"), Mapping) else {}
    parity: dict[str, Any] = {}
    if parity_descriptor:
        parity_path = definitions_root / str(parity_descriptor.get("path") or "")
        if not parity_path.is_file():
            raise ValueError("frozen SRL migration parity report is missing")
        data = parity_path.read_bytes()
        expected = str(parity_descriptor.get("sha256") or "")
        if expected and _sha(data) != expected:
            raise ValueError("frozen SRL migration parity SHA-256 mismatch")
        raw = json.loads(data.decode("utf-8"))
        if isinstance(raw, Mapping):
            parity = {
                "schema": str(raw.get("schema") or ""),
                "status": str(parity_descriptor.get("status") or raw.get("status") or ""),
                "ok": bool(raw.get("ok")),
                "ruleSetRevision": str(raw.get("ruleSetRevision") or ""),
                "primitiveCasesChecked": int(raw.get("primitiveCasesChecked") or 0),
                "primitiveMismatchCount": int(raw.get("primitiveMismatchCount") or 0),
                "compoundCasesChecked": int(raw.get("casesChecked") or 0),
                "compoundMismatchCount": int(raw.get("mismatchCount") or 0),
                "sha256": expected,
            }

    core = {
        "definitions": {
            "definitionsRevision": str(parent.get("definitionsRevision") or ""),
            "generatedAtUtc": str(parent.get("generatedAtUtc") or ""),
            "builtFromDevCommit": str(parent.get("builtFromDevCommit") or ""),
            "scannerVersion": str(parent.get("scannerVersion") or ""),
            "scannerRevision": str(parent.get("scannerRevision") or ""),
            "artifactAnalysisRevision": str(parent.get("artifactAnalysisRevision") or ""),
            "sourceAnalysisRevision": str(parent.get("sourceAnalysisRevision") or ""),
            "sourceObservationRevision": str(parent.get("sourceObservationRevision") or ""),
            "legacyRuleSetRevision": str(parent.get("ruleSetRevision") or ""),
            "advisoryRevision": str(parent.get("advisoryRevision") or ""),
        },
        "srl": {
            "definitionPackRevision": str(srl_index.get("definitionPackRevision") or descriptor.get("definitionPackRevision") or ""),
            "ruleSetRevision": str(srl_index.get("ruleSetRevision") or descriptor.get("ruleSetRevision") or ""),
            "packCount": len(packs),
            "activeRuleCount": len(active_rules),
            "totalRuleCount": int(srl_index.get("totalRuleCount") or len(active_rules)),
            "productionRuleEvaluationEnabled": bool(srl_index.get("productionRuleEvaluationEnabled")),
            "productionRuleEvaluationNote": str(srl_index.get("productionRuleEvaluationNote") or ""),
            "migrationParity": parity,
        },
        "packs": packs,
        "activeRules": active_rules,
    }
    payload = {
        "schema": DEFINITION_PROVENANCE_SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        **core,
    }
    payload["provenanceRevision"] = f"definition-provenance-v1-{_sha(_canonical(_semantic_core(payload)))[:20]}"
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if len(data) > MAX_PROVENANCE_BYTES:
        raise ValueError(f"Definition provenance sidecar exceeds {MAX_PROVENANCE_BYTES} bytes")
    return payload


def write_definition_provenance(definitions_root: Path, output_path: Path) -> dict[str, Any]:
    payload = build_definition_provenance(definitions_root)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    output_path.write_bytes(data)
    return {
        "schema": DEFINITION_PROVENANCE_SCHEMA,
        "path": output_path.name if output_path.parent.name != "indexes" else f"indexes/{output_path.name}",
        "bytes": len(data),
        "sha256": _sha(data),
        "provenanceRevision": str(payload.get("provenanceRevision") or ""),
        "definitionsRevision": str((payload.get("definitions") or {}).get("definitionsRevision") or ""),
        "ruleSetRevision": str((payload.get("srl") or {}).get("ruleSetRevision") or ""),
        "activeRuleCount": int((payload.get("srl") or {}).get("activeRuleCount") or 0),
        "packCount": int((payload.get("srl") or {}).get("packCount") or 0),
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
    }


def validate_definition_provenance(value: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(value.get("schema") or "") != DEFINITION_PROVENANCE_SCHEMA:
        errors.append("definition provenance has an unsupported schema")
    if value.get("readOnly") is not True or str(value.get("mutationAuthority") or "") != "none":
        errors.append("definition provenance is not explicitly read-only")
    if bool(value.get("policyInput")):
        errors.append("definition provenance incorrectly declares itself a policy input")
    srl = value.get("srl") if isinstance(value.get("srl"), Mapping) else {}
    packs = value.get("packs") if isinstance(value.get("packs"), list) else []
    active_rules = value.get("activeRules") if isinstance(value.get("activeRules"), list) else []
    if int(srl.get("packCount") or 0) != len(packs):
        errors.append("definition provenance pack count mismatch")
    if int(srl.get("activeRuleCount") or 0) != len(active_rules):
        errors.append("definition provenance active rule count mismatch")
    if bool(srl.get("productionRuleEvaluationEnabled")):
        # Current 2.15 migration line intentionally keeps production projection off.
        errors.append("definition provenance unexpectedly reports production SRL evaluation enabled")
    expected_revision = f"definition-provenance-v1-{_sha(_canonical(_semantic_core(value)))[:20]}"
    if str(value.get("provenanceRevision") or "") != expected_revision:
        errors.append("definition provenance semantic revision mismatch")
    ids = [str(item.get("ruleId") or "") for item in active_rules if isinstance(item, Mapping)]
    if not all(ids) or len(ids) != len(set(ids)):
        errors.append("definition provenance active rule IDs are missing or duplicated")
    return errors
