"""SigmaScope Definition Pack v1 compiler/freezer.

Definition Packs are inert, source-controlled SRL data.  This module validates pack
metadata, compiles the exact SRL v1 rules with :mod:`srl`, executes declared fixtures,
prevents duplicate rule/fact identities across packs, and can freeze a deterministic
manifest plus compiled ruleset into a Daily Definitions snapshot.

It does not evaluate plugins, fetch network content, execute candidate code, or mutate
published evidence.  Production scan code must consume only the frozen output produced
at the Daily Catalog boundary; source pack YAML is never a live worker input.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Mapping

try:
    from . import observation_projection, srl
except ImportError:  # direct import from frozen worker / tools/security
    from . import observation_projection, srl

PACK_SCHEMA = "omega.sigmascope.definition-pack.v1"
PACK_INDEX_SCHEMA = "omega.sigmascope.definition-packs.v1"
FROZEN_PACK_SCHEMA = "omega.sigmascope.frozen-definition-pack.v1"
VALIDATION_SCHEMA = "omega.sigmascope.definition-pack-validation.v1"

ENGINE_VERSION = 1
OBSERVATION_CONTRACT_VERSION = 1
TRUST_TIERS = {"core", "reviewed", "experimental", "local"}
PRODUCTION_TIERS = {"core", "reviewed"}
MAX_PACKS = 64
MAX_RULE_FILES_PER_PACK = 128
MAX_FIXTURES_PER_PACK = 256
MAX_FILE_BYTES = srl.MAX_DOCUMENT_BYTES
MAX_TOTAL_RULES = srl.MAX_RULES
MAX_TOTAL_PACK_SOURCE_BYTES = 32 * 1024 * 1024


class DefinitionPackError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha(value: Any) -> str:
    return _sha_bytes(_canonical(value))


def _require_text(value: Any, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DefinitionPackError(f"{label} must be a non-empty string")
    text = value.strip()
    if len(text) > maximum:
        raise DefinitionPackError(f"{label} exceeds {maximum} characters")
    return text



def _require_timestamp(value: Any, label: str) -> str:
    parsed: dt.datetime
    if isinstance(value, dt.datetime):
        parsed = value
    elif isinstance(value, str):
        text = _require_text(value, label, 64)
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise DefinitionPackError(f"{label} must be an ISO-8601 timestamp") from exc
    else:
        raise DefinitionPackError(f"{label} must be an ISO-8601 timestamp")
    if parsed.tzinfo is None:
        raise DefinitionPackError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _require_id(value: Any, label: str) -> str:
    text = _require_text(value, label, 160)
    if not all(ch.isalnum() or ch in "._:-/" for ch in text):
        raise DefinitionPackError(f"{label} contains unsupported characters")
    return text


def _safe_relative_path(pack_root: Path, raw: Any, label: str) -> tuple[str, Path]:
    rel = _require_text(raw, label, 260).replace("\\", "/")
    candidate = Path(rel)
    if candidate.is_absolute() or ".." in candidate.parts or rel.startswith("/"):
        raise DefinitionPackError(f"{label} must stay inside the pack directory")
    path = pack_root / candidate
    if path.is_symlink():
        raise DefinitionPackError(f"{label} may not be a symlink: {rel}")
    try:
        resolved = path.resolve(strict=True)
        root_resolved = pack_root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise DefinitionPackError(f"{label} does not exist: {rel}") from exc
    if root_resolved not in resolved.parents:
        raise DefinitionPackError(f"{label} escapes the pack directory: {rel}")
    if not resolved.is_file():
        raise DefinitionPackError(f"{label} is not a regular file: {rel}")
    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise DefinitionPackError(f"{label} exceeds {MAX_FILE_BYTES} bytes: {rel}")
    return candidate.as_posix(), resolved


def _metadata(raw: Any, label: str, *, require_review: bool) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise DefinitionPackError(f"{label} must be a mapping")
    provenance = raw.get("provenance")
    if not isinstance(provenance, Mapping):
        raise DefinitionPackError(f"{label}.provenance must be a mapping")
    result = {
        "license": _require_text(raw.get("license"), f"{label}.license", 160),
        "provenance": {
            "kind": _require_text(provenance.get("kind"), f"{label}.provenance.kind", 80),
            "source": _require_text(provenance.get("source"), f"{label}.provenance.source", 1024),
        },
    }
    review = raw.get("review")
    if require_review:
        if not isinstance(review, Mapping):
            raise DefinitionPackError(f"{label}.review is required for production-tier packs")
        result["review"] = {
            "reviewer": _require_text(review.get("reviewer"), f"{label}.review.reviewer", 160),
            "reviewedAtUtc": _require_timestamp(review.get("reviewedAtUtc"), f"{label}.review.reviewedAtUtc"),
        }
    elif isinstance(review, Mapping):
        reviewer = str(review.get("reviewer") or "").strip()
        reviewed_value = review.get("reviewedAtUtc")
        has_reviewed_at = reviewed_value not in (None, "")
        if reviewer or has_reviewed_at:
            if not reviewer or not has_reviewed_at:
                raise DefinitionPackError(f"{label}.review must contain both reviewer and reviewedAtUtc")
            result["review"] = {"reviewer": reviewer, "reviewedAtUtc": _require_timestamp(reviewed_value, f"{label}.review.reviewedAtUtc")}
    return result


def _compatibility(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise DefinitionPackError(f"{label} must be a mapping")
    try:
        engine = int(raw.get("minimumSrlEngineVersion") or 0)
        observations = int(raw.get("minimumObservationContractVersion") or 0)
    except (TypeError, ValueError) as exc:
        raise DefinitionPackError(f"{label} engine/observation versions must be integers") from exc
    rule_schema = str(raw.get("ruleSchema") or "")
    fixture_schema = str(raw.get("fixtureSchema") or "")
    observation_schema = str(raw.get("observationContractSchema") or "")
    if engine < 1 or engine > ENGINE_VERSION:
        raise DefinitionPackError(f"{label}.minimumSrlEngineVersion={engine} is not supported by engine v{ENGINE_VERSION}")
    if observations < 1 or observations > OBSERVATION_CONTRACT_VERSION:
        raise DefinitionPackError(
            f"{label}.minimumObservationContractVersion={observations} is not supported by observation contract v{OBSERVATION_CONTRACT_VERSION}"
        )
    if rule_schema != srl.RULE_SCHEMA:
        raise DefinitionPackError(f"{label}.ruleSchema must be {srl.RULE_SCHEMA}")
    if fixture_schema != srl.FIXTURE_SCHEMA:
        raise DefinitionPackError(f"{label}.fixtureSchema must be {srl.FIXTURE_SCHEMA}")
    if observation_schema != observation_projection.OBSERVATION_CONTRACT_SCHEMA:
        raise DefinitionPackError(
            f"{label}.observationContractSchema must be {observation_projection.OBSERVATION_CONTRACT_SCHEMA}"
        )
    return {
        "minimumSrlEngineVersion": engine,
        "minimumObservationContractVersion": observations,
        "ruleSchema": rule_schema,
        "fixtureSchema": fixture_schema,
        "observationContractSchema": observation_schema,
    }


def discover_pack_manifests(packs_root: Path, *, include_local: bool = False) -> list[Path]:
    if not packs_root.exists():
        return []
    if not packs_root.is_dir():
        raise DefinitionPackError(f"Definition Pack root is not a directory: {packs_root}")
    manifests = sorted(packs_root.glob("*/pack.yaml"), key=lambda p: p.parent.name.casefold())
    if len(manifests) > MAX_PACKS:
        raise DefinitionPackError(f"Definition Pack root exceeds {MAX_PACKS} packs")
    # include_local is applied after parsing because trust tier is manifest data.
    return manifests


def _rules_from_document(document: Any) -> list[Mapping[str, Any]]:
    # Keep this small wrapper here rather than depending on SRL's private helper.
    if isinstance(document, Mapping) and document.get("schema") == srl.RULE_SCHEMA:
        return [document]
    if isinstance(document, Mapping) and document.get("schema") == srl.RULESET_SCHEMA:
        rules = document.get("rules")
        if not isinstance(rules, list) or not rules:
            raise DefinitionPackError("SRL ruleset file requires a non-empty rules list")
        return [rule for rule in rules if isinstance(rule, Mapping)]
    if isinstance(document, list):
        return [rule for rule in document if isinstance(rule, Mapping)]
    raise DefinitionPackError(f"rule file must contain {srl.RULE_SCHEMA} or {srl.RULESET_SCHEMA}")


def compile_pack(manifest_path: Path, *, include_local: bool = False) -> dict[str, Any] | None:
    if manifest_path.name != "pack.yaml":
        raise DefinitionPackError("Definition Pack manifest must be named pack.yaml")
    if manifest_path.is_symlink():
        raise DefinitionPackError("Definition Pack manifest may not be a symlink")
    if manifest_path.parent.is_symlink():
        raise DefinitionPackError("Definition Pack directory may not be a symlink")
    pack_root = manifest_path.parent.resolve()
    manifest = srl.load_yaml(manifest_path)
    if not isinstance(manifest, Mapping):
        raise DefinitionPackError("pack.yaml must be a mapping")
    if str(manifest.get("schema") or "") != PACK_SCHEMA:
        raise DefinitionPackError(f"pack schema must be {PACK_SCHEMA}")
    pack_id = _require_id(manifest.get("id"), "pack.id")
    if pack_id != manifest_path.parent.name:
        raise DefinitionPackError(f"pack.id must match its directory name ({manifest_path.parent.name})")
    trust_tier = str(manifest.get("trustTier") or "")
    if trust_tier not in TRUST_TIERS:
        raise DefinitionPackError(f"pack.trustTier must be one of {sorted(TRUST_TIERS)}")
    if trust_tier == "local" and not include_local:
        return None
    production_tier = trust_tier in PRODUCTION_TIERS
    pack_meta = _metadata(manifest, "pack", require_review=production_tier)
    compatibility = _compatibility(manifest.get("compatibility"), "pack.compatibility")
    title = _require_text(manifest.get("title"), "pack.title", 200)
    description = str(manifest.get("description") or "").strip()
    if len(description) > 4000:
        raise DefinitionPackError("pack.description exceeds 4000 characters")

    raw_rule_entries = manifest.get("rules")
    if not isinstance(raw_rule_entries, list) or not raw_rule_entries:
        raise DefinitionPackError("pack.rules must contain at least one rule-file descriptor")
    if len(raw_rule_entries) > MAX_RULE_FILES_PER_PACK:
        raise DefinitionPackError(f"pack.rules exceeds {MAX_RULE_FILES_PER_PACK} files")

    compiled_rules: list[dict[str, Any]] = []
    frozen_rule_files: list[dict[str, Any]] = []
    source_rules: list[Mapping[str, Any]] = []
    seen_paths: set[str] = set()
    for index, entry in enumerate(raw_rule_entries):
        if not isinstance(entry, Mapping):
            raise DefinitionPackError(f"pack.rules[{index}] must be a mapping")
        rel, path = _safe_relative_path(pack_root, entry.get("path"), f"pack.rules[{index}].path")
        if rel in seen_paths:
            raise DefinitionPackError(f"duplicate rule source path in pack {pack_id}: {rel}")
        seen_paths.add(rel)
        metadata = _metadata(entry, f"pack.rules[{index}]", require_review=production_tier)
        document = srl.load_yaml(path)
        raw_rules = _rules_from_document(document)
        compiled_file = srl.compile_ruleset(document)
        declared_ids = entry.get("ids")
        if not isinstance(declared_ids, list) or not declared_ids:
            raise DefinitionPackError(f"pack.rules[{index}].ids must list the exact rule IDs in {rel}")
        expected_ids = sorted(_require_id(value, f"pack.rules[{index}].ids") for value in declared_ids)
        actual_ids = sorted(str(rule.get("id") or "") for rule in compiled_file.get("rules") or [])
        if expected_ids != actual_ids:
            raise DefinitionPackError(f"declared rule IDs for {rel} do not match compiled rules: expected {expected_ids}, got {actual_ids}")
        if production_tier:
            non_reviewed = [rule["id"] for rule in compiled_file["rules"] if rule.get("status") != "reviewed"]
            if non_reviewed:
                raise DefinitionPackError(f"production-tier pack {pack_id} contains non-reviewed rules: {non_reviewed}")
        source_rules.extend(raw_rules)
        compiled_rules.extend(compiled_file["rules"])
        frozen_rule_files.append({
            "path": rel,
            "sha256": _sha_bytes(path.read_bytes()),
            "bytes": path.stat().st_size,
            "ruleSetRevision": compiled_file["ruleSetRevision"],
            "ruleIds": actual_ids,
            "ruleRevisions": {rule["id"]: rule["ruleRevision"] for rule in compiled_file["rules"]},
            **metadata,
        })

    # Compile the pack as one unit to catch duplicate IDs/facts across its files.
    pack_ruleset = srl.compile_ruleset({"schema": srl.RULESET_SCHEMA, "rules": list(source_rules)})

    raw_fixture_entries = manifest.get("fixtures") or []
    if not isinstance(raw_fixture_entries, list):
        raise DefinitionPackError("pack.fixtures must be a list")
    if len(raw_fixture_entries) > MAX_FIXTURES_PER_PACK:
        raise DefinitionPackError(f"pack.fixtures exceeds {MAX_FIXTURES_PER_PACK} files")
    if production_tier and not raw_fixture_entries:
        raise DefinitionPackError(f"production-tier pack {pack_id} must declare at least one fixture")
    frozen_fixtures: list[dict[str, Any]] = []
    fixture_failures: list[str] = []
    positive_fixture_rule_ids: set[str] = set()
    seen_fixture_paths: set[str] = set()
    for index, entry in enumerate(raw_fixture_entries):
        if isinstance(entry, str):
            entry = {"path": entry}
        if not isinstance(entry, Mapping):
            raise DefinitionPackError(f"pack.fixtures[{index}] must be a path or mapping")
        rel, path = _safe_relative_path(pack_root, entry.get("path"), f"pack.fixtures[{index}].path")
        if rel in seen_fixture_paths:
            raise DefinitionPackError(f"duplicate fixture path in pack {pack_id}: {rel}")
        seen_fixture_paths.add(rel)
        fixture = srl.load_yaml(path)
        result = srl.run_fixture(pack_ruleset, fixture)
        expected = fixture.get("expected") if isinstance(fixture, Mapping) and isinstance(fixture.get("expected"), Mapping) else {}
        positive_fixture_rule_ids.update(str(item) for item in expected.get("matchedRules") or [] if str(item))
        if not result.get("passed"):
            fixture_failures.extend(f"{rel}: {failure}" for failure in result.get("failures") or [])
        frozen_fixtures.append({
            "path": rel,
            "sha256": _sha_bytes(path.read_bytes()),
            "bytes": path.stat().st_size,
            "name": str(result.get("name") or ""),
            "passed": bool(result.get("passed")),
        })
    if fixture_failures:
        raise DefinitionPackError(f"Definition Pack fixtures failed for {pack_id}: " + "; ".join(fixture_failures))
    if production_tier:
        rule_ids = {str(rule["id"]) for rule in pack_ruleset.get("rules") or []}
        missing_positive = sorted(rule_ids - positive_fixture_rule_ids)
        if missing_positive:
            raise DefinitionPackError(
                f"production-tier pack {pack_id} lacks a positive matchedRules fixture for: {missing_positive}"
            )

    semantic = {
        "schema": FROZEN_PACK_SCHEMA,
        "packSchema": PACK_SCHEMA,
        "manifest": {
            "path": "pack.yaml",
            "sha256": _sha_bytes(manifest_path.read_bytes()),
            "bytes": manifest_path.stat().st_size,
        },
        "id": pack_id,
        "title": title,
        "description": description,
        "trustTier": trust_tier,
        "productionEligible": production_tier,
        "compatibility": compatibility,
        "metadata": pack_meta,
        "rules": frozen_rule_files,
        "fixtures": frozen_fixtures,
        "compiledRuleSetRevision": pack_ruleset["ruleSetRevision"],
    }
    pack_revision = f"definition-pack-v1-{_sha(semantic)[:24]}"
    return {
        **semantic,
        "packRevision": pack_revision,
        "compiledRuleSet": pack_ruleset,
        "sourceRoot": str(pack_root),
    }


def compile_pack_root(packs_root: Path, *, include_local: bool = False) -> dict[str, Any]:
    compiled_packs: list[dict[str, Any]] = []
    for manifest in discover_pack_manifests(packs_root, include_local=include_local):
        pack = compile_pack(manifest, include_local=include_local)
        if pack is not None:
            compiled_packs.append(pack)
    ids = [pack["id"] for pack in compiled_packs]
    if len(ids) != len(set(ids)):
        duplicates = sorted({pack_id for pack_id in ids if ids.count(pack_id) > 1})
        raise DefinitionPackError(f"duplicate Definition Pack IDs: {duplicates}")

    all_rules: list[dict[str, Any]] = []
    active_rules: list[dict[str, Any]] = []
    raw_active_rules: list[Mapping[str, Any]] = []
    rule_owners: dict[str, str] = {}
    fact_owners: dict[str, str] = {}
    total_source_bytes = sum(
        int(pack.get("manifest", {}).get("bytes") or 0)
        + sum(int(item.get("bytes") or 0) for item in pack.get("rules") or [])
        + sum(int(item.get("bytes") or 0) for item in pack.get("fixtures") or [])
        for pack in compiled_packs
    )
    if total_source_bytes > MAX_TOTAL_PACK_SOURCE_BYTES:
        raise DefinitionPackError(
            f"Definition Pack source exceeds the {MAX_TOTAL_PACK_SOURCE_BYTES}-byte aggregate limit"
        )
    for pack in compiled_packs:
        for rule in pack["compiledRuleSet"]["rules"]:
            rule_id = str(rule["id"])
            if rule_id in rule_owners:
                raise DefinitionPackError(f"duplicate rule ID across packs: {rule_id} ({rule_owners[rule_id]}, {pack['id']})")
            rule_owners[rule_id] = pack["id"]
            if rule["kind"] in {"observation", "classification"}:
                fact = str(rule["emit"]["fact"])
                if fact in fact_owners:
                    raise DefinitionPackError(f"duplicate emitted fact across packs: {fact} ({fact_owners[fact]}, {pack['id']})")
                fact_owners[fact] = pack["id"]
            all_rules.append(rule)
            if len(all_rules) > MAX_TOTAL_RULES:
                raise DefinitionPackError(f"Definition Pack set exceeds {MAX_TOTAL_RULES} total rules")
            if pack["productionEligible"]:
                active_rules.append(rule)
        if pack["productionEligible"]:
            # Re-read source documents only to build an aggregate ruleset through the
            # public SRL compiler, ensuring closure/duplicates use exact engine logic.
            pack_root = Path(pack["sourceRoot"])
            for rule_file in pack["rules"]:
                document = srl.load_yaml(pack_root / rule_file["path"])
                raw_active_rules.extend(_rules_from_document(document))

    if raw_active_rules:
        active_ruleset = srl.compile_ruleset({"schema": srl.RULESET_SCHEMA, "rules": list(raw_active_rules)})
    else:
        # SRL itself deliberately rejects empty authoring rulesets. Definitions need a
        # deterministic zero-rule frozen state before the first reviewed migration.
        empty_core = {
            "schema": srl.COMPILED_RULESET_SCHEMA,
            "engineSchema": srl.ENGINE_SCHEMA,
            "rules": [],
            "emittedFacts": {},
        }
        empty_core["ruleSetRevision"] = f"srl-ruleset-v1-{_sha(empty_core)[:24]}"
        active_ruleset = empty_core

    pack_summaries = []
    for pack in compiled_packs:
        pack_summaries.append({
            key: pack[key] for key in (
                "schema", "packSchema", "manifest", "id", "title", "description", "trustTier",
                "productionEligible", "compatibility", "metadata", "rules", "fixtures",
                "compiledRuleSetRevision", "packRevision",
            )
        })
    semantic = {
        "schema": PACK_INDEX_SCHEMA,
        "engine": {
            "schema": srl.ENGINE_SCHEMA,
            "version": ENGINE_VERSION,
            "ruleSchema": srl.RULE_SCHEMA,
            "fixtureSchema": srl.FIXTURE_SCHEMA,
        },
        "observationContract": {
            "schema": observation_projection.OBSERVATION_CONTRACT_SCHEMA,
            "version": OBSERVATION_CONTRACT_VERSION,
            "revision": observation_projection.contract_revision(),
        },
        "trustTiers": sorted(TRUST_TIERS),
        "productionTrustTiers": sorted(PRODUCTION_TIERS),
        "packs": pack_summaries,
        "ruleSetRevision": active_ruleset["ruleSetRevision"],
        "activeRuleCount": len(active_ruleset["rules"]),
        "totalRuleCount": len(all_rules),
        "productionRuleEvaluationEnabled": False,
        "productionRuleEvaluationNote": "Reviewed SRL packs may be frozen for Phase-7 migration, but production projection remains disabled until a compatible 2.15 retained corpus replays cleanly and cutover is explicitly reviewed.",
    }
    semantic["definitionPackRevision"] = f"definition-packs-v1-{_sha(semantic)[:24]}"
    return {
        **semantic,
        "compiledRuleSet": active_ruleset,
        "sourceRoot": str(packs_root.resolve()),
    }


def freeze_pack_root(packs_root: Path, output_root: Path, *, include_local: bool = False) -> dict[str, Any]:
    compiled = compile_pack_root(packs_root, include_local=include_local)
    destination = output_root / "srl"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    source_root = Path(compiled["sourceRoot"])
    for pack in compiled["packs"]:
        pack_source = source_root / pack["id"]
        pack_destination = destination / "packs" / pack["id"]
        pack_destination.mkdir(parents=True, exist_ok=True)
        manifest_source = pack_source / "pack.yaml"
        shutil.copy2(manifest_source, pack_destination / "pack.yaml")
        for file_descriptor in [*pack["rules"], *pack["fixtures"]]:
            rel = file_descriptor["path"]
            target = pack_destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pack_source / rel, target)

    ruleset_path = destination / "compiled-ruleset.json"
    ruleset_path.write_text(json.dumps(compiled["compiledRuleSet"], ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    index = {key: value for key, value in compiled.items() if key not in {"compiledRuleSet", "sourceRoot"}}
    index["compiledRuleSet"] = {
        "path": "srl/compiled-ruleset.json",
        "sha256": _sha_bytes(ruleset_path.read_bytes()),
        "schema": str(compiled["compiledRuleSet"].get("schema") or ""),
        "ruleSetRevision": str(compiled["compiledRuleSet"].get("ruleSetRevision") or ""),
        "ruleCount": len(compiled["compiledRuleSet"].get("rules") or []),
    }
    index_path = destination / "index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {
        "schema": PACK_INDEX_SCHEMA,
        "path": "srl/index.json",
        "sha256": _sha_bytes(index_path.read_bytes()),
        "definitionPackRevision": index["definitionPackRevision"],
        "ruleSetRevision": index["ruleSetRevision"],
        "packCount": len(index["packs"]),
        "activeRuleCount": int(index["activeRuleCount"]),
        "totalRuleCount": int(index["totalRuleCount"]),
        "productionRuleEvaluationEnabled": False,
    }


def _verify_copied_file(root: Path, relative: str, expected_sha: str, errors: list[str]) -> None:
    path = root / relative
    if not path.is_file():
        errors.append(f"frozen Definition Pack file missing: {relative}")
        return
    actual = _sha_bytes(path.read_bytes())
    if actual != expected_sha:
        errors.append(f"frozen Definition Pack file SHA-256 mismatch: {relative}")


def verify_frozen(output_root: Path, descriptor: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    rel = str(descriptor.get("path") or "")
    index_path = output_root / rel
    if not rel or not index_path.is_file():
        return {"schema": VALIDATION_SCHEMA, "ok": False, "errors": ["frozen Definition Pack index is missing"]}
    if _sha_bytes(index_path.read_bytes()) != str(descriptor.get("sha256") or ""):
        errors.append("frozen Definition Pack index SHA-256 mismatch")
        return {"schema": VALIDATION_SCHEMA, "ok": False, "errors": errors}
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"schema": VALIDATION_SCHEMA, "ok": False, "errors": [f"frozen Definition Pack index unreadable: {type(exc).__name__}: {exc}"]}
    if index.get("schema") != PACK_INDEX_SCHEMA:
        errors.append(f"unsupported frozen Definition Pack schema: {index.get('schema')!r}")
    ruleset_descriptor = index.get("compiledRuleSet") if isinstance(index.get("compiledRuleSet"), Mapping) else {}
    ruleset_rel = str(ruleset_descriptor.get("path") or "")
    _verify_copied_file(output_root, ruleset_rel, str(ruleset_descriptor.get("sha256") or ""), errors)
    ruleset: dict[str, Any] = {}
    if ruleset_rel and (output_root / ruleset_rel).is_file():
        try:
            value = json.loads((output_root / ruleset_rel).read_text(encoding="utf-8"))
            ruleset = value if isinstance(value, dict) else {}
        except Exception as exc:
            errors.append(f"frozen compiled SRL ruleset unreadable: {type(exc).__name__}: {exc}")
    if ruleset:
        if ruleset.get("schema") != srl.COMPILED_RULESET_SCHEMA:
            errors.append("frozen compiled SRL ruleset uses an unsupported schema")
        if str(ruleset.get("ruleSetRevision") or "") != str(index.get("ruleSetRevision") or ""):
            errors.append("frozen SRL ruleSetRevision mismatch")
        if len(ruleset.get("rules") or []) != int(index.get("activeRuleCount") or 0):
            errors.append("frozen SRL active rule count mismatch")
    for pack in index.get("packs") or []:
        if not isinstance(pack, Mapping):
            errors.append("frozen Definition Pack entry is malformed")
            continue
        pack_id = str(pack.get("id") or "")
        base = f"srl/packs/{pack_id}"
        manifest = pack.get("manifest") if isinstance(pack.get("manifest"), Mapping) else {}
        _verify_copied_file(output_root, f"{base}/{manifest.get('path') or 'pack.yaml'}", str(manifest.get("sha256") or ""), errors)
        for item in [*(pack.get("rules") or []), *(pack.get("fixtures") or [])]:
            if isinstance(item, Mapping):
                _verify_copied_file(output_root, f"{base}/{item.get('path')}", str(item.get("sha256") or ""), errors)
    if str(index.get("definitionPackRevision") or "") != str(descriptor.get("definitionPackRevision") or ""):
        errors.append("frozen Definition Pack revision descriptor mismatch")
    if str(index.get("ruleSetRevision") or "") != str(descriptor.get("ruleSetRevision") or ""):
        errors.append("frozen Definition Pack rule-set descriptor mismatch")
    return {
        "schema": VALIDATION_SCHEMA,
        "ok": not errors,
        "definitionPackRevision": str(index.get("definitionPackRevision") or ""),
        "ruleSetRevision": str(index.get("ruleSetRevision") or ""),
        "packCount": len(index.get("packs") or []),
        "activeRuleCount": int(index.get("activeRuleCount") or 0),
        "errors": errors,
    }


def load_frozen_ruleset(output_root: Path, descriptor: Mapping[str, Any]) -> dict[str, Any]:
    """Load only a verified Daily-Definitions compiled SRL ruleset.

    This is the sole production-facing loader contract. It never reads
    ``security-definitions/packs`` and therefore cannot float with a development branch.
    """
    validation = verify_frozen(output_root, descriptor)
    if not validation.get("ok"):
        raise DefinitionPackError("invalid frozen Definition Packs: " + "; ".join(validation.get("errors") or []))
    index = json.loads((output_root / str(descriptor["path"])).read_text(encoding="utf-8"))
    ruleset_path = output_root / str(index["compiledRuleSet"]["path"])
    return json.loads(ruleset_path.read_text(encoding="utf-8"))
