"""SigmaScope Rule Language (SRL) v1 compiler and deterministic evaluator.

SRL is deliberately non-executable. Rules may inspect only registered retained
observation collections (plus facts emitted by observation rules), use a small typed
operator set, and emit typed facts or review findings. This module performs no file,
network, process, SQL, environment, plugin or dynamic-code actions while evaluating a
rule. File loading helpers only read the explicitly supplied rule/fixture path.

Production rule loading is intentionally *not* enabled by this phase. DeltaScope and
unit tests use this exact compiler/evaluator so Definition Pack promotion can later
freeze the same semantics without inventing a second implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

try:
    from . import observation_projection, rule_author_reference
except ImportError:  # direct script/import from tools/security
    import observation_projection  # type: ignore
    import rule_author_reference  # type: ignore

RULE_SCHEMA = "omega.sigmascope.rule.v1"
RULESET_SCHEMA = "omega.sigmascope.ruleset.v1"
COMPILED_SCHEMA = "omega.sigmascope.compiled-rule.v1"
COMPILED_RULESET_SCHEMA = "omega.sigmascope.compiled-ruleset.v1"
EVALUATION_SCHEMA = "omega.sigmascope.rule-evaluation.v1"
RULESET_EVALUATION_SCHEMA = "omega.sigmascope.ruleset-evaluation.v1"
FIXTURE_SCHEMA = "omega.sigmascope.rule-fixture.v1"
FIXTURE_RESULT_SCHEMA = "omega.sigmascope.rule-fixture-result.v1"
ENGINE_SCHEMA = "omega.sigmascope.srl-engine.v1"

MAX_DOCUMENT_BYTES = 128 * 1024
MAX_RULES = 256
MAX_SELECTORS = 32
MAX_VALUES_PER_OPERATOR = 64
MAX_CONDITION_DEPTH = 8
MAX_NODES = 4096
MAX_TOKENS = 8192
MAX_ROWS_PER_COLLECTION = 100_000
MAX_MATCH_ROWS_PER_SELECTOR = 256
MAX_EVIDENCE_ROWS_PER_RULE = 512
MAX_STRING_OPERAND = 4096
MAX_FACTS = 4096
MAX_FINDINGS = 1024

STRING_TYPES = {"string", "capability-id", "https-url"}
INTEGER_TYPES = {"integer"}
BOOLEAN_TYPES = {"boolean"}
ARRAY_TYPES = {"string[]", "object[]"}
KNOWN_TYPES = STRING_TYPES | INTEGER_TYPES | BOOLEAN_TYPES | ARRAY_TYPES

OPERATORS = {
    "equals", "equals-ci", "in", "in-ci", "contains", "contains-ci",
    "starts-with", "starts-with-ci", "ends-with", "ends-with-ci",
    "exists", "missing", "gt", "gte", "lt", "lte",
}
NUMERIC_OPERATORS = {"gt", "gte", "lt", "lte"}
BOOLEAN_OPERATORS = {"exists", "missing"}
LIST_OPERATORS = {"in", "in-ci"}
STRING_OPERATORS = {
    "equals-ci", "contains", "contains-ci", "starts-with",
    "starts-with-ci", "ends-with", "ends-with-ci", "in", "in-ci",
}


class SRLError(ValueError):
    """Base deterministic SRL validation/evaluation error."""


class SRLParseError(SRLError):
    pass


class SRLCompileError(SRLError):
    pass


class SRLEvaluationError(SRLError):
    pass


class _NoDuplicateSafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: yaml.Loader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise SRLParseError(f"duplicate YAML mapping key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_NoDuplicateSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bounded_structure(value: Any) -> None:
    count = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_NODES:
            raise SRLParseError(f"SRL document exceeds {MAX_NODES} structural nodes")
        if depth > MAX_CONDITION_DEPTH + 8:
            raise SRLParseError("SRL document nesting is too deep")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise SRLParseError("SRL mapping keys must be strings")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str) and len(item) > MAX_STRING_OPERAND * 4:
            raise SRLParseError("SRL string value is unreasonably large")

    visit(value, 0)


def parse_yaml_text(text: str) -> Any:
    raw = text.encode("utf-8")
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise SRLParseError(f"SRL document exceeds {MAX_DOCUMENT_BYTES} bytes")
    token_count = 0
    try:
        for token in yaml.scan(text):
            token_count += 1
            if token_count > MAX_TOKENS:
                raise SRLParseError(f"SRL document exceeds {MAX_TOKENS} YAML tokens")
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken)):
                raise SRLParseError("YAML anchors, aliases and explicit tags are not allowed in SRL")
        value = yaml.load(text, Loader=_NoDuplicateSafeLoader)
    except SRLError:
        raise
    except Exception as exc:
        raise SRLParseError(f"invalid SRL YAML: {exc}") from exc
    if value is None:
        raise SRLParseError("SRL document is empty")
    _bounded_structure(value)
    return value


def load_yaml(path: str | Path) -> Any:
    p = Path(path)
    data = p.read_bytes()
    if len(data) > MAX_DOCUMENT_BYTES:
        raise SRLParseError(f"SRL document exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SRLParseError("SRL document must be UTF-8") from exc
    return parse_yaml_text(text)


def _observation_field_registry() -> dict[str, dict[str, str]]:
    legal = {
        name for name, spec in observation_projection.COLLECTIONS.items()
        if bool(spec.get("srlEligible"))
    }
    result: dict[str, dict[str, str]] = {}
    for name, spec in rule_author_reference.COLLECTIONS.items():
        if name not in legal:
            continue
        fields = spec.get("fields") if isinstance(spec.get("fields"), dict) else {}
        result[name] = {str(k): str(v) for k, v in fields.items() if str(v) in KNOWN_TYPES}
    return result


FIELD_REGISTRY = _observation_field_registry()


def engine_reference() -> dict[str, Any]:
    return {
        "schema": ENGINE_SCHEMA,
        "ruleSchema": RULE_SCHEMA,
        "rulesetSchema": RULESET_SCHEMA,
        "fixtureSchema": FIXTURE_SCHEMA,
        "productionRuleEvaluationEnabled": False,
        "compilerAvailable": True,
        "evaluatorAvailable": True,
        "operators": sorted(OPERATORS),
        "conditionOperators": ["all", "any", "not", "count"],
        "limits": {
            "maxDocumentBytes": MAX_DOCUMENT_BYTES,
            "maxRules": MAX_RULES,
            "maxSelectorsPerRule": MAX_SELECTORS,
            "maxValuesPerOperator": MAX_VALUES_PER_OPERATOR,
            "maxConditionDepth": MAX_CONDITION_DEPTH,
            "maxRowsPerCollection": MAX_ROWS_PER_COLLECTION,
            "maxMatchRowsPerSelector": MAX_MATCH_ROWS_PER_SELECTOR,
            "maxEvidenceRowsPerRule": MAX_EVIDENCE_ROWS_PER_RULE,
            "maxFacts": MAX_FACTS,
            "maxFindings": MAX_FINDINGS,
        },
        "typedCollections": FIELD_REGISTRY,
        "forbiddenInputs": sorted(observation_projection.PROJECTION_DATASETS) + ["behaviorConsistency", "permissionCandidates", "automationCapabilities"],
        "deterministic": True,
        "nonExecutable": True,
    }


def _require_id(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise SRLCompileError(f"{label} is required")
    if len(text) > 160 or not all(ch.isalnum() or ch in "._:-/" for ch in text):
        raise SRLCompileError(f"{label} contains unsupported characters")
    return text


def _require_string(value: Any, label: str, maximum: int = MAX_STRING_OPERAND) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SRLCompileError(f"{label} must be a non-empty string")
    text = value.strip()
    if len(text) > maximum:
        raise SRLCompileError(f"{label} exceeds {maximum} characters")
    return text


def _normalize_scalar(value: Any, field_type: str, label: str) -> Any:
    if field_type in STRING_TYPES:
        if not isinstance(value, str):
            raise SRLCompileError(f"{label} must be a string")
        if len(value) > MAX_STRING_OPERAND:
            raise SRLCompileError(f"{label} string operand is too long")
        return value
    if field_type in INTEGER_TYPES:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise SRLCompileError(f"{label} must be numeric")
        return value
    if field_type in BOOLEAN_TYPES:
        if not isinstance(value, bool):
            raise SRLCompileError(f"{label} must be boolean")
        return value
    if field_type in ARRAY_TYPES:
        # Array fields are matched element-wise by scalar operators. The operand type is
        # the element type rather than another list, except membership operators below.
        if field_type == "string[]":
            if not isinstance(value, str):
                raise SRLCompileError(f"{label} must be a string element")
            return value
        raise SRLCompileError(f"{label} object-array operands are not supported directly in SRL v1")
    raise SRLCompileError(f"{label} has unsupported field type {field_type}")


def _compile_predicate(field: str, field_type: str, raw: Any, selector_name: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or len(raw) != 1:
        raise SRLCompileError(f"selector {selector_name} field {field} must contain exactly one operator")
    operator, operand = next(iter(raw.items()))
    operator = str(operator)
    if operator not in OPERATORS:
        raise SRLCompileError(f"selector {selector_name} field {field} uses unknown operator {operator}")
    label = f"selector {selector_name} field {field} operator {operator}"
    base_type = "string" if field_type == "string[]" else field_type
    if operator in BOOLEAN_OPERATORS:
        if operand not in (True, None):
            raise SRLCompileError(f"{label} must use true (or null)")
        compiled_operand: Any = True
    elif operator in LIST_OPERATORS:
        if base_type not in STRING_TYPES:
            raise SRLCompileError(f"{label} is only valid for string-like fields")
        if not isinstance(operand, list) or not operand:
            raise SRLCompileError(f"{label} requires a non-empty list")
        if len(operand) > MAX_VALUES_PER_OPERATOR:
            raise SRLCompileError(f"{label} exceeds {MAX_VALUES_PER_OPERATOR} values")
        compiled_operand = [_normalize_scalar(item, base_type, label) for item in operand]
    elif operator in NUMERIC_OPERATORS:
        if base_type not in INTEGER_TYPES:
            raise SRLCompileError(f"{label} requires a numeric field")
        compiled_operand = _normalize_scalar(operand, base_type, label)
    elif operator == "equals":
        if base_type not in STRING_TYPES | INTEGER_TYPES | BOOLEAN_TYPES:
            raise SRLCompileError(f"{label} is not valid for field type {base_type}")
        compiled_operand = _normalize_scalar(operand, base_type, label)
    elif operator in STRING_OPERATORS:
        if base_type not in STRING_TYPES:
            raise SRLCompileError(f"{label} requires a string-like field")
        compiled_operand = _normalize_scalar(operand, base_type, label)
    else:
        raise SRLCompileError(f"{label} is unsupported")
    return {"field": field, "fieldType": field_type, "operator": operator, "operand": compiled_operand}


def _wildcard_group(field: str) -> str:
    return field.split("[].", 1)[0] if "[]." in field else ""


def _compile_selector(name: str, raw: Any, kind: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SRLCompileError(f"selector {name} must be a mapping")
    if "facts" in raw:
        if kind != "correlation":
            raise SRLCompileError(f"selector {name}: fact selectors are allowed only in correlation rules")
        if set(raw) != {"facts"}:
            raise SRLCompileError(f"selector {name}: fact selector may not mix collection fields")
        facts = raw.get("facts")
        if not isinstance(facts, dict) or len(facts) != 1:
            raise SRLCompileError(f"selector {name}: facts must contain exactly one of any/all")
        mode, values = next(iter(facts.items()))
        if mode not in {"any", "all"} or not isinstance(values, list) or not values:
            raise SRLCompileError(f"selector {name}: facts requires any/all with a non-empty list")
        if len(values) > MAX_VALUES_PER_OPERATOR:
            raise SRLCompileError(f"selector {name}: too many facts")
        fact_ids = sorted({_require_id(v, f"selector {name} fact") for v in values})
        return {"name": name, "type": "facts", "mode": mode, "facts": fact_ids}

    collection = str(raw.get("collection") or "")
    where = raw.get("where")
    if not collection or not isinstance(where, dict) or not where:
        raise SRLCompileError(f"selector {name} requires collection and non-empty where")
    legal = observation_projection.COLLECTIONS.get(collection)
    if legal is None or not bool(legal.get("srlEligible")):
        raise SRLCompileError(f"selector {name} uses non-SRL or unknown collection {collection}")
    fields = FIELD_REGISTRY.get(collection)
    if fields is None:
        raise SRLCompileError(f"selector {name}: collection {collection} has no frozen typed SRL field registry yet")
    predicates: list[dict[str, Any]] = []
    wildcard_groups: set[str] = set()
    for field, predicate in sorted(where.items()):
        field = str(field)
        if field not in fields:
            raise SRLCompileError(f"selector {name}: unknown field {collection}.{field}")
        group = _wildcard_group(field)
        if group:
            wildcard_groups.add(group)
        predicates.append(_compile_predicate(field, fields[field], predicate, name))
    if len(wildcard_groups) > 1:
        raise SRLCompileError(f"selector {name}: SRL v1 permits only one repeated-array path group per selector")
    return {
        "name": name,
        "type": "collection",
        "collection": collection,
        "predicates": predicates,
        "sameRecord": True,
        "wildcardGroup": next(iter(wildcard_groups), ""),
    }


def _compile_condition(raw: Any, selectors: set[str], depth: int = 0) -> dict[str, Any]:
    if depth > MAX_CONDITION_DEPTH:
        raise SRLCompileError(f"condition exceeds maximum depth {MAX_CONDITION_DEPTH}")
    if isinstance(raw, str):
        if raw not in selectors:
            raise SRLCompileError(f"condition references unknown selector {raw}")
        return {"selector": raw}
    if not isinstance(raw, dict) or len(raw) != 1:
        raise SRLCompileError("condition must be a selector name or one-key all/any/not/count mapping")
    op, value = next(iter(raw.items()))
    op = str(op)
    if op in {"all", "any"}:
        if not isinstance(value, list) or not value:
            raise SRLCompileError(f"condition {op} requires a non-empty list")
        return {op: [_compile_condition(item, selectors, depth + 1) for item in value]}
    if op == "not":
        return {"not": _compile_condition(value, selectors, depth + 1)}
    if op == "count":
        if not isinstance(value, dict):
            raise SRLCompileError("condition count requires a mapping")
        selector = str(value.get("selector") or "")
        if selector not in selectors:
            raise SRLCompileError(f"count references unknown selector {selector}")
        thresholds = [(name, value.get(name)) for name in ("gt", "gte", "lt", "lte", "equals") if name in value]
        if len(thresholds) != 1:
            raise SRLCompileError("count requires exactly one threshold: gt/gte/lt/lte/equals")
        threshold_op, threshold = thresholds[0]
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
            raise SRLCompileError("count threshold must be a non-negative integer")
        return {"count": {"selector": selector, "operator": threshold_op, "value": threshold}}
    raise SRLCompileError(f"unknown condition operator {op}")


def _condition_selector_refs(node: dict[str, Any]) -> set[str]:
    if "selector" in node:
        return {str(node["selector"])}
    if "count" in node:
        return {str(node["count"]["selector"])}
    if "not" in node:
        return _condition_selector_refs(node["not"])
    refs: set[str] = set()
    for key in ("all", "any"):
        for child in node.get(key) or []:
            refs.update(_condition_selector_refs(child))
    return refs


def _compile_emit(kind: str, raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SRLCompileError("emit must be a mapping")
    if kind in {"observation", "classification"}:
        allowed = {"fact", "confidence", "title", "description", "category"}
        unknown = set(raw) - allowed
        if unknown:
            raise SRLCompileError(f"observation emit contains unsupported fields: {sorted(unknown)}")
        fact = _require_id(raw.get("fact"), "emit.fact")
        result = {"fact": fact}
        for key in ("confidence", "title", "description", "category"):
            if key in raw:
                result[key] = _require_string(raw[key], f"emit.{key}")
        return result
    if kind == "correlation":
        allowed = {"title", "description", "severity", "category", "findingId"}
        unknown = set(raw) - allowed
        if unknown:
            raise SRLCompileError(f"correlation emit contains unsupported fields: {sorted(unknown)}")
        title = _require_string(raw.get("title"), "emit.title")
        result = {"title": title}
        result["findingId"] = _require_id(raw.get("findingId") or "", "emit.findingId") if raw.get("findingId") else ""
        for key in ("description", "severity", "category"):
            if key in raw:
                result[key] = _require_string(raw[key], f"emit.{key}")
        return result
    raise SRLCompileError(f"unsupported rule kind {kind}")


def compile_rule(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise SRLCompileError("rule must be a mapping")
    schema = str(raw.get("schema") or "")
    if schema != RULE_SCHEMA:
        raise SRLCompileError(f"rule schema must be {RULE_SCHEMA}")
    rule_id = _require_id(raw.get("id"), "rule id")
    kind = str(raw.get("kind") or "")
    if kind not in {"observation", "correlation", "classification"}:
        raise SRLCompileError("rule kind must be observation, correlation, or classification")
    status = str(raw.get("status") or "experimental")
    if status not in {"experimental", "reviewed", "deprecated", "disabled"}:
        raise SRLCompileError("rule status must be experimental/reviewed/deprecated/disabled")
    selectors_raw = raw.get("selectors")
    if not isinstance(selectors_raw, dict) or not selectors_raw:
        raise SRLCompileError("rule requires named selectors")
    if len(selectors_raw) > MAX_SELECTORS:
        raise SRLCompileError(f"rule exceeds {MAX_SELECTORS} selectors")
    selectors: dict[str, dict[str, Any]] = {}
    for name, selector in sorted(selectors_raw.items()):
        selector_name = _require_id(name, "selector name")
        selectors[selector_name] = _compile_selector(selector_name, selector, kind)
    required = raw.get("requires")
    if not isinstance(required, list):
        raise SRLCompileError("rule must declare a requires collection list (use [] for fact-only correlations)")
    required_names = sorted({_require_id(item, "required collection") for item in required})
    for collection in required_names:
        spec = observation_projection.COLLECTIONS.get(collection)
        if spec is None or not bool(spec.get("srlEligible")):
            raise SRLCompileError(f"rule requires unknown/non-SRL collection {collection}")
    selector_collections = sorted({s["collection"] for s in selectors.values() if s["type"] == "collection"})
    missing_requires = sorted(set(selector_collections) - set(required_names))
    if missing_requires:
        raise SRLCompileError(f"requires is missing selector collections: {missing_requires}")
    unused_requires = sorted(set(required_names) - set(selector_collections))
    if unused_requires:
        raise SRLCompileError(f"requires contains unused collections: {unused_requires}")
    condition = _compile_condition(raw.get("condition"), set(selectors))
    used_selectors = _condition_selector_refs(condition)
    unused_selectors = sorted(set(selectors) - used_selectors)
    if unused_selectors:
        raise SRLCompileError(f"rule defines selectors not referenced by condition: {unused_selectors}")
    emit = _compile_emit(kind, raw.get("emit"))
    metadata: dict[str, Any] = {}
    for key in ("title", "description", "category", "severity", "license", "source"):
        if key in raw:
            metadata[key] = _require_string(raw[key], key)
    compiled_core = {
        "schema": COMPILED_SCHEMA,
        "ruleSchema": RULE_SCHEMA,
        "id": rule_id,
        "kind": kind,
        "status": status,
        "requires": required_names,
        "selectors": [selectors[name] for name in sorted(selectors)],
        "condition": condition,
        "emit": emit,
        "metadata": metadata,
    }
    compiled_core["ruleRevision"] = f"srl-rule-v1-{_sha(compiled_core)[:24]}"
    return compiled_core


def _document_rules(document: Any) -> list[Mapping[str, Any]]:
    if isinstance(document, dict) and document.get("schema") == RULE_SCHEMA:
        return [document]
    if isinstance(document, dict) and document.get("schema") == RULESET_SCHEMA:
        rules = document.get("rules")
        if not isinstance(rules, list) or not rules:
            raise SRLCompileError("ruleset requires non-empty rules list")
        return rules
    if isinstance(document, list):
        return document
    raise SRLCompileError(f"document must be {RULE_SCHEMA}, {RULESET_SCHEMA}, or a rule list")


def compile_ruleset(document: Any) -> dict[str, Any]:
    rules_raw = _document_rules(document)
    if len(rules_raw) > MAX_RULES:
        raise SRLCompileError(f"ruleset exceeds {MAX_RULES} rules")
    rules = [compile_rule(rule) for rule in rules_raw]
    ids = [rule["id"] for rule in rules]
    if len(ids) != len(set(ids)):
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        raise SRLCompileError(f"duplicate rule IDs: {duplicates}")
    emitted_facts: dict[str, str] = {}
    for rule in rules:
        if rule["kind"] in {"observation", "classification"}:
            fact = rule["emit"]["fact"]
            if fact in emitted_facts:
                raise SRLCompileError(f"fact {fact} is emitted by both {emitted_facts[fact]} and {rule['id']}")
            emitted_facts[fact] = rule["id"]
    # Correlations may consume any externally seeded fact or a fact emitted by this
    # ruleset. Because correlations cannot emit facts, cycles/recursion are impossible.
    for rule in rules:
        if rule["kind"] != "correlation":
            continue
        for selector in rule["selectors"]:
            if selector["type"] != "facts":
                continue
            for fact in selector["facts"]:
                # Unknown facts are permitted as stable facts from another reviewed
                # pack/ruleset. Definition Pack compilation will resolve pack closure.
                _require_id(fact, f"rule {rule['id']} fact reference")
    ordered = sorted(rules, key=lambda r: (0 if r["kind"] in {"observation", "classification"} else 1, r["id"]))
    core = {
        "schema": COMPILED_RULESET_SCHEMA,
        "engineSchema": ENGINE_SCHEMA,
        "rules": ordered,
        "emittedFacts": {k: emitted_facts[k] for k in sorted(emitted_facts)},
    }
    core["ruleSetRevision"] = f"srl-ruleset-v1-{_sha(core)[:24]}"
    return core


def compile_yaml_text(text: str) -> dict[str, Any]:
    return compile_ruleset(parse_yaml_text(text))


def compile_file(path: str | Path) -> dict[str, Any]:
    return compile_ruleset(load_yaml(path))


def _get_path(value: Any, path: str) -> tuple[bool, Any]:
    """Resolve a non-wildcard dotted path."""
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _predicate_match(value_present: bool, value: Any, predicate: Mapping[str, Any]) -> bool:
    op = predicate["operator"]
    operand = predicate["operand"]
    if op == "exists":
        return value_present and value is not None
    if op == "missing":
        return not value_present or value is None
    if not value_present or value is None:
        return False
    values = value if isinstance(value, list) else [value]
    for candidate in values:
        if candidate is None:
            continue
        if op == "equals":
            if candidate == operand:
                return True
        elif op in {"equals-ci", "contains", "contains-ci", "starts-with", "starts-with-ci", "ends-with", "ends-with-ci", "in", "in-ci"}:
            if not isinstance(candidate, str):
                continue
            c = candidate
            if op.endswith("-ci"):
                c = c.casefold()
            if op in {"equals-ci", "contains-ci", "starts-with-ci", "ends-with-ci"}:
                target = str(operand).casefold()
            else:
                target = operand
            if op in {"equals", "equals-ci"} and c == target:
                return True
            if op in {"contains", "contains-ci"} and str(target) in c:
                return True
            if op in {"starts-with", "starts-with-ci"} and c.startswith(str(target)):
                return True
            if op in {"ends-with", "ends-with-ci"} and c.endswith(str(target)):
                return True
            if op in {"in", "in-ci"}:
                haystack = [str(x).casefold() for x in operand] if op == "in-ci" else operand
                if c in haystack:
                    return True
        elif op in NUMERIC_OPERATORS:
            if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
                continue
            if op == "gt" and candidate > operand:
                return True
            if op == "gte" and candidate >= operand:
                return True
            if op == "lt" and candidate < operand:
                return True
            if op == "lte" and candidate <= operand:
                return True
    return False


def _row_matches_selector(row: Mapping[str, Any], selector: Mapping[str, Any]) -> bool:
    wildcard_group = str(selector.get("wildcardGroup") or "")
    predicates = selector.get("predicates") or []
    scalar_predicates = [p for p in predicates if "[]." not in p["field"]]
    wildcard_predicates = [p for p in predicates if "[]." in p["field"]]
    for predicate in scalar_predicates:
        present, value = _get_path(row, predicate["field"])
        if not _predicate_match(present, value, predicate):
            return False
    if not wildcard_predicates:
        return True
    present, repeated = _get_path(row, wildcard_group)
    if not present or not isinstance(repeated, list):
        return False
    # Same-element semantics for fields in the same repeated-array group.
    for element in repeated:
        if not isinstance(element, dict):
            continue
        all_match = True
        for predicate in wildcard_predicates:
            tail = predicate["field"].split("[].", 1)[1]
            value_present, value = _get_path(element, tail)
            if not _predicate_match(value_present, value, predicate):
                all_match = False
                break
        if all_match:
            return True
    return False


def _selector_result(selector: Mapping[str, Any], observations: Mapping[str, Sequence[Mapping[str, Any]]], facts: set[str]) -> dict[str, Any]:
    if selector["type"] == "facts":
        wanted = set(selector["facts"])
        matched = wanted & facts
        truth = bool(matched) if selector["mode"] == "any" else wanted <= facts
        return {
            "name": selector["name"], "type": "facts", "matched": truth,
            "matchCount": len(matched), "matchedFacts": sorted(matched), "evidenceRows": [],
        }
    collection = selector["collection"]
    raw_rows = observations.get(collection) or []
    if len(raw_rows) > MAX_ROWS_PER_COLLECTION:
        raise SRLEvaluationError(f"collection {collection} exceeds evaluator row limit {MAX_ROWS_PER_COLLECTION}")
    matched_rows: list[dict[str, Any]] = []
    match_count = 0
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, Mapping):
            continue
        if _row_matches_selector(raw, selector):
            match_count += 1
            if len(matched_rows) < MAX_MATCH_ROWS_PER_SELECTOR:
                matched_rows.append({"index": index, "row": dict(raw)})
    return {
        "name": selector["name"], "type": "collection", "collection": collection,
        "matched": match_count > 0, "matchCount": match_count, "evidenceRows": matched_rows,
        "truncated": match_count > len(matched_rows),
    }


def _evaluate_condition(node: Mapping[str, Any], results: Mapping[str, Mapping[str, Any]]) -> bool:
    if "selector" in node:
        return bool(results[str(node["selector"])]["matched"])
    if "not" in node:
        return not _evaluate_condition(node["not"], results)
    if "all" in node:
        return all(_evaluate_condition(item, results) for item in node["all"])
    if "any" in node:
        return any(_evaluate_condition(item, results) for item in node["any"])
    if "count" in node:
        spec = node["count"]
        count = int(results[str(spec["selector"])]["matchCount"])
        value = int(spec["value"])
        op = spec["operator"]
        return {"gt": count > value, "gte": count >= value, "lt": count < value, "lte": count <= value, "equals": count == value}[op]
    raise SRLEvaluationError("compiled condition is malformed")


def evaluate_rule(compiled_rule: Mapping[str, Any], observations: Mapping[str, Sequence[Mapping[str, Any]]], facts: Iterable[str] = ()) -> dict[str, Any]:
    fact_set = {str(item) for item in facts if str(item)}
    if len(fact_set) > MAX_FACTS:
        raise SRLEvaluationError(f"fact input exceeds {MAX_FACTS}")
    replay = observation_projection.replay_audit(
        {"contractRevision": observation_projection.contract_revision(), "collections": {
            name: {"completeness": "retained"} for name in observations if name in observation_projection.COLLECTIONS
        }},
        compiled_rule.get("requires") or [],
    )
    # Direct evaluator inputs are assumed complete fixture/local rows. Production/real
    # Evidence evaluation must pass the retained variant contract through the ruleset
    # evaluator's observation_contract parameter instead of synthesizing completeness.
    selector_results: dict[str, dict[str, Any]] = {}
    for selector in compiled_rule.get("selectors") or []:
        result = _selector_result(selector, observations, fact_set)
        selector_results[result["name"]] = result
    matched = _evaluate_condition(compiled_rule["condition"], selector_results)
    evidence: list[dict[str, Any]] = []
    for name in sorted(selector_results):
        result = selector_results[name]
        for row in result.get("evidenceRows") or []:
            if len(evidence) >= MAX_EVIDENCE_ROWS_PER_RULE:
                break
            evidence.append({"selector": name, **row})
    emitted_fact = ""
    finding: dict[str, Any] | None = None
    if matched and compiled_rule["status"] not in {"disabled", "deprecated"}:
        if compiled_rule["kind"] in {"observation", "classification"}:
            emitted_fact = str(compiled_rule["emit"]["fact"])
        elif compiled_rule["kind"] == "correlation":
            emit = dict(compiled_rule["emit"])
            finding = {
                "ruleId": compiled_rule["id"],
                "findingId": emit.get("findingId") or compiled_rule["id"],
                "title": emit["title"],
                "description": emit.get("description", ""),
                "severity": emit.get("severity", compiled_rule.get("metadata", {}).get("severity", "informational")),
                "category": emit.get("category", compiled_rule.get("metadata", {}).get("category", "behavior")),
                "evidence": evidence,
            }
    return {
        "schema": EVALUATION_SCHEMA,
        "ruleId": compiled_rule["id"],
        "ruleRevision": compiled_rule["ruleRevision"],
        "kind": compiled_rule["kind"],
        "status": compiled_rule["status"],
        "matched": matched,
        "selectors": [selector_results[name] for name in sorted(selector_results)],
        "emittedFact": emitted_fact,
        "finding": finding,
        "evidenceTruncated": len(evidence) >= MAX_EVIDENCE_ROWS_PER_RULE,
        "fixtureReplay": replay,
    }


def evaluate_ruleset(
    compiled_ruleset: Mapping[str, Any],
    observations: Mapping[str, Sequence[Mapping[str, Any]]],
    initial_facts: Iterable[str] = (),
    observation_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    facts = {str(item) for item in initial_facts if str(item)}
    if len(facts) > MAX_FACTS:
        raise SRLEvaluationError(f"initial facts exceed {MAX_FACTS}")
    rules = list(compiled_ruleset.get("rules") or [])
    if len(rules) > MAX_RULES:
        raise SRLEvaluationError(f"compiled ruleset exceeds {MAX_RULES} rules")
    required = sorted({name for rule in rules for name in rule.get("requires") or []})
    if observation_contract is None:
        replay_contract = {"contractRevision": observation_projection.contract_revision(), "collections": {
            name: {"completeness": "retained"} for name in observations if name in observation_projection.COLLECTIONS
        }}
    else:
        replay_contract = dict(observation_contract)
    replay = observation_projection.replay_audit(replay_contract, required)
    if not replay["reusableWithoutRescan"]:
        return {
            "schema": RULESET_EVALUATION_SCHEMA,
            "ruleSetRevision": compiled_ruleset.get("ruleSetRevision", ""),
            "evaluated": False,
            "replayAudit": replay,
            "facts": sorted(facts),
            "findings": [],
            "rules": [],
        }
    evaluations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    # Compiler ordering guarantees observation/classification before correlation.
    for rule in rules:
        result = evaluate_rule(rule, observations, facts)
        evaluations.append(result)
        fact = str(result.get("emittedFact") or "")
        if fact:
            facts.add(fact)
            if len(facts) > MAX_FACTS:
                raise SRLEvaluationError(f"evaluation emitted more than {MAX_FACTS} facts")
        finding = result.get("finding")
        if isinstance(finding, dict):
            findings.append(finding)
            if len(findings) > MAX_FINDINGS:
                raise SRLEvaluationError(f"evaluation emitted more than {MAX_FINDINGS} findings")
    findings.sort(key=lambda item: (str(item.get("ruleId") or ""), str(item.get("findingId") or "")))
    return {
        "schema": RULESET_EVALUATION_SCHEMA,
        "ruleSetRevision": compiled_ruleset.get("ruleSetRevision", ""),
        "evaluated": True,
        "replayAudit": replay,
        "facts": sorted(facts),
        "findings": findings,
        "rules": evaluations,
    }


def run_fixture(compiled_ruleset: Mapping[str, Any], fixture: Mapping[str, Any]) -> dict[str, Any]:
    if str(fixture.get("schema") or "") != FIXTURE_SCHEMA:
        raise SRLCompileError(f"fixture schema must be {FIXTURE_SCHEMA}")
    name = _require_string(fixture.get("name"), "fixture.name", 160)
    observations = fixture.get("observations")
    if not isinstance(observations, dict):
        raise SRLCompileError("fixture.observations must be a mapping of logical collection to rows")
    clean_observations: dict[str, list[dict[str, Any]]] = {}
    for collection, rows in observations.items():
        collection = str(collection)
        if collection not in observation_projection.COLLECTIONS or not bool(observation_projection.COLLECTIONS[collection].get("srlEligible")):
            raise SRLCompileError(f"fixture uses unknown/non-SRL collection {collection}")
        if not isinstance(rows, list):
            raise SRLCompileError(f"fixture collection {collection} must be a list")
        if len(rows) > MAX_ROWS_PER_COLLECTION:
            raise SRLCompileError(f"fixture collection {collection} exceeds row limit")
        clean_observations[collection] = [dict(row) for row in rows if isinstance(row, dict)]
    initial_facts = fixture.get("initialFacts") or []
    if not isinstance(initial_facts, list):
        raise SRLCompileError("fixture.initialFacts must be a list")
    result = evaluate_ruleset(compiled_ruleset, clean_observations, initial_facts)
    expected = fixture.get("expected") if isinstance(fixture.get("expected"), dict) else {}
    expected_facts = sorted({str(item) for item in expected.get("facts") or [] if str(item)})
    expected_rules = sorted({str(item) for item in expected.get("matchedRules") or [] if str(item)})
    expected_findings = sorted({str(item) for item in expected.get("findingIds") or [] if str(item)})
    actual_rules = sorted(str(item["ruleId"]) for item in result.get("rules") or [] if item.get("matched"))
    actual_findings = sorted(str(item.get("findingId") or item.get("ruleId") or "") for item in result.get("findings") or [])
    failures: list[str] = []
    if "facts" in expected and expected_facts != result.get("facts"):
        failures.append(f"facts expected {expected_facts} but got {result.get('facts')}")
    if "matchedRules" in expected and expected_rules != actual_rules:
        failures.append(f"matchedRules expected {expected_rules} but got {actual_rules}")
    if "findingIds" in expected and expected_findings != actual_findings:
        failures.append(f"findingIds expected {expected_findings} but got {actual_findings}")
    return {
        "schema": FIXTURE_RESULT_SCHEMA,
        "name": name,
        "passed": not failures,
        "failures": failures,
        "evaluation": result,
    }


def run_fixture_file(rule_path: str | Path, fixture_path: str | Path) -> dict[str, Any]:
    return run_fixture(compile_file(rule_path), load_yaml(fixture_path))
