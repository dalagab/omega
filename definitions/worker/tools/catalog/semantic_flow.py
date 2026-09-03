"""Bounded interprocedural C# taint observations for SigmaScope.

This module never assigns a security verdict.  It builds neutral source -> sink flow
observations from the selected plugin source surface.  SRL/Stigma-1 decides what a flow
means.  Resolution is deliberately conservative and local to source text: method bodies,
parameters, assignments, local calls and returns are modeled without executing code.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

SCHEMA = "omega.sigmascope.semantic-flow.v1"
REGISTRY_SCHEMA = "omega.sigmascope.semantic-flow-registry.v1"
CONTRACT_VERSION = 1
MAX_FILES = 512
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 24 * 1024 * 1024
MAX_METHODS = 4096
MAX_METHOD_STATEMENTS = 4096
MAX_SUMMARY_PASSES = 16
MAX_SUMMARY_ORIGINS = 128
MAX_SINK_TEMPLATES = 8192
MAX_FLOWS = 8192
MAX_CALL_DEPTH = 16
MAX_EVIDENCE = 8

METHOD_HEADER_RE = re.compile(
    r"\b(?:public|private|protected|internal|static|async|virtual|override|sealed|partial|new|unsafe|extern|\s)+"
    r"(?P<return>[A-Za-z_][A-Za-z0-9_<>\[\],?.:]*)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)\s*(?P<body>\{|=>)"
)
CONSTRUCTOR_HEADER_RE = re.compile(
    r"\b(?:public|private|protected|internal|static|unsafe|extern|\s)+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)\s*(?P<body>\{|=>)"
)
CALL_HEAD_RE = re.compile(r"(?P<target>[A-Za-z_][A-Za-z0-9_<>]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_<>]*)*)\s*\(")
IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
DECL_ASSIGN_RE = re.compile(r"^(?:var|[A-Za-z_][A-Za-z0-9_<>\[\],?.:]*)\s+(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$", re.S)
PLAIN_ASSIGN_RE = re.compile(r"^(?P<lhs>[A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(?!=)(?P<rhs>.+)$", re.S)
RETURN_RE = re.compile(r"^return\s+(?P<expr>.+)$", re.S)
CONTROL_WORDS = {"if", "for", "foreach", "while", "switch", "catch", "using", "lock", "return", "typeof", "sizeof", "nameof", "checked", "unchecked"}


@dataclasses.dataclass(frozen=True, order=True)
class Origin:
    kind: str  # param | source
    ref: str
    sanitizers: tuple[str, ...] = ()


@dataclasses.dataclass
class Method:
    method_id: str
    path: str
    name: str
    return_type: str
    line: int
    parameters: list[dict[str, str]]
    statements: list[tuple[int, str]]


@dataclasses.dataclass(frozen=True)
class SinkTemplate:
    sink_id: str
    sink_node_id: str
    sink_data_class: str
    path: str
    line: int
    method_id: str
    symbol: str
    argument_index: int
    origin: Origin
    call_path: tuple[str, ...]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _id(kind: str, *parts: object) -> str:
    return f"{kind}-{hashlib.sha256('|'.join(str(item) for item in parts).encode('utf-8')).hexdigest()[:20]}"


def default_registry_path() -> Path:
    return Path(__file__).resolve().parents[2] / "security-definitions" / "semantic-flow" / "registry.json"


def _text(value: Any, field: str, *, required: bool = False, maximum: int = 1024) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    result = value.strip()
    if required and not result:
        raise ValueError(f"{field} is required")
    if len(result) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return result


def _strings(value: Any, field: str, *, required: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        text = _text(item, f"{field}[{index}]", required=True, maximum=128)
        key = text.casefold()
        if key not in seen:
            seen.add(key)
            result.append(text)
    if required and not result:
        raise ValueError(f"{field} must not be empty")
    return result


def _indexes(value: Any, field: str) -> list[int]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    result: list[int] = []
    for index, item in enumerate(value):
        if not isinstance(item, int) or isinstance(item, bool) or item < 0 or item > 31:
            raise ValueError(f"{field}[{index}] must be an integer from 0 to 31")
        if item not in result:
            result.append(item)
    return result


def validate_registry(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != REGISTRY_SCHEMA:
        raise ValueError(f"semantic-flow registry schema must be {REGISTRY_SCHEMA}")
    if int(document.get("version") or 0) != 1:
        raise ValueError("semantic-flow registry version must be 1")
    unknown = set(document) - {"schema", "version", "sources", "sinks", "sanitizers", "assignmentSinks"}
    if unknown:
        raise ValueError(f"semantic-flow registry has unsupported fields: {', '.join(sorted(unknown))}")
    normalized: dict[str, Any] = {"schema": REGISTRY_SCHEMA, "version": 1}
    seen_ids: set[str] = set()
    for collection in ("sources", "sinks", "sanitizers"):
        raw_items = document.get(collection)
        if not isinstance(raw_items, list):
            raise ValueError(f"semantic-flow registry {collection} must be a list")
        items: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_items):
            if not isinstance(raw, dict):
                raise ValueError(f"{collection}[{index}] must be an object")
            item_id = _text(raw.get("id"), f"{collection}[{index}].id", required=True, maximum=128)
            if not re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+", item_id):
                raise ValueError(f"invalid semantic-flow id: {item_id}")
            if item_id in seen_ids:
                raise ValueError(f"duplicate semantic-flow id: {item_id}")
            seen_ids.add(item_id)
            item: dict[str, Any] = {
                "id": item_id,
                "dataClass": _text(raw.get("dataClass"), f"{collection}[{index}].dataClass", required=collection != "sanitizers", maximum=128),
                "members": _strings(raw.get("members") or [], f"{collection}[{index}].members"),
                "receiverContains": _strings(raw.get("receiverContains") or [], f"{collection}[{index}].receiverContains"),
                "argumentIndexes": _indexes(raw.get("argumentIndexes") or [], f"{collection}[{index}].argumentIndexes"),
                "triggerKinds": _strings(raw.get("triggerKinds") or [], f"{collection}[{index}].triggerKinds"),
                "eventContains": _strings(raw.get("eventContains") or [], f"{collection}[{index}].eventContains"),
                "parameterNames": _strings(raw.get("parameterNames") or [], f"{collection}[{index}].parameterNames"),
                "effect": _text(raw.get("effect"), f"{collection}[{index}].effect", maximum=128),
            }
            is_trigger_source = collection == "sources" and bool(item["triggerKinds"])
            is_call_matcher = bool(item["members"])
            if collection == "sources" and not (is_trigger_source or is_call_matcher):
                raise ValueError(f"source {item_id} must declare triggerKinds or members")
            if collection in {"sinks", "sanitizers"} and not is_call_matcher:
                raise ValueError(f"{collection[:-1]} {item_id} must declare members")
            if collection == "sinks" and not item["argumentIndexes"]:
                raise ValueError(f"sink {item_id} must declare argumentIndexes")
            items.append(item)
        normalized[collection] = sorted(items, key=lambda row: row["id"])
    assignment_items = document.get("assignmentSinks")
    if not isinstance(assignment_items, list):
        raise ValueError("semantic-flow registry assignmentSinks must be a list")
    normalized_assignment: list[dict[str, Any]] = []
    for index, raw in enumerate(assignment_items):
        if not isinstance(raw, dict):
            raise ValueError(f"assignmentSinks[{index}] must be an object")
        item_id = _text(raw.get("id"), f"assignmentSinks[{index}].id", required=True, maximum=128)
        if item_id in seen_ids:
            raise ValueError(f"duplicate semantic-flow id: {item_id}")
        seen_ids.add(item_id)
        normalized_assignment.append({
            "id": item_id,
            "dataClass": _text(raw.get("dataClass"), f"assignmentSinks[{index}].dataClass", required=True, maximum=128),
            "targetSuffixes": _strings(raw.get("targetSuffixes") or [], f"assignmentSinks[{index}].targetSuffixes", required=True),
        })
    normalized["assignmentSinks"] = sorted(normalized_assignment, key=lambda row: row["id"])
    normalized["revision"] = f"semantic-flow-registry-v1-{hashlib.sha256(_canonical(normalized)).hexdigest()[:16]}"
    return normalized


def load_registry(path: Path | None = None) -> dict[str, Any]:
    source = path or default_registry_path()
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"semantic-flow registry is unreadable: {source}: {exc}") from exc
    return validate_registry(document)


def _strip_comments(text: str) -> str:
    out: list[str] = []
    index = 0
    state = "code"
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                state = "line"
                out.extend("  ")
                index += 2
                continue
            if char == "/" and nxt == "*":
                state = "block"
                out.extend("  ")
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            out.append(char)
            index += 1
            continue
        if state == "line":
            if char == "\n":
                state = "code"
                out.append(char)
            else:
                out.append(" ")
            index += 1
            continue
        if state == "block":
            if char == "*" and nxt == "/":
                out.extend("  ")
                state = "code"
                index += 2
            else:
                out.append("\n" if char == "\n" else " ")
                index += 1
            continue
        out.append(char)
        if char == "\\":
            if index + 1 < len(text):
                out.append(text[index + 1])
                index += 2
            else:
                index += 1
            continue
        if (state == "string" and char == '"') or (state == "char" and char == "'"):
            state = "code"
        index += 1
    return "".join(out)


def _split_balanced(value: str, delimiter: str = ",") -> list[str]:
    result: list[str] = []
    start = 0
    round_depth = square_depth = angle_depth = brace_depth = 0
    in_string = False
    quote = ""
    escaped = False
    for index, char in enumerate(value):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                in_string = False
            continue
        if char in {'"', "'"}:
            in_string, quote = True, char
            continue
        if char == "(": round_depth += 1
        elif char == ")": round_depth = max(0, round_depth - 1)
        elif char == "[": square_depth += 1
        elif char == "]": square_depth = max(0, square_depth - 1)
        elif char == "<": angle_depth += 1
        elif char == ">": angle_depth = max(0, angle_depth - 1)
        elif char == "{": brace_depth += 1
        elif char == "}": brace_depth = max(0, brace_depth - 1)
        elif char == delimiter and not any((round_depth, square_depth, angle_depth, brace_depth)):
            result.append(value[start:index].strip())
            start = index + 1
    result.append(value[start:].strip())
    return result


def _parse_parameters(value: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for raw in _split_balanced(value):
        raw = raw.strip()
        if not raw:
            continue
        raw = raw.split("=", 1)[0].strip()
        parts = [part for part in re.split(r"\s+", raw) if part and part not in {"ref", "out", "in", "params", "this"}]
        if len(parts) < 2:
            continue
        name = parts[-1].lstrip("@").strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        result.append({"name": name, "type": " ".join(parts[:-1])[:256]})
    return result


def _logical_statements(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0
    depth = 0
    in_string = False
    quote = ""
    escaped = False
    for line_no, line in lines:
        for char in line + "\n":
            if not buffer:
                start_line = line_no
            buffer.append(char)
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    in_string = False
                continue
            if char in {'"', "'"}:
                in_string, quote = True, char
                continue
            if char == "(": depth += 1
            elif char == ")": depth = max(0, depth - 1)
            elif char == ";" and depth == 0:
                statement = "".join(buffer[:-1]).strip().strip("{} ")
                if statement:
                    result.append((start_line, re.sub(r"\s+", " ", statement)[:8192]))
                buffer = []
                start_line = 0
        if len(result) >= MAX_METHOD_STATEMENTS:
            break
    tail = "".join(buffer).strip().strip("{} ")
    if tail and len(result) < MAX_METHOD_STATEMENTS:
        result.append((start_line or (lines[-1][0] if lines else 0), re.sub(r"\s+", " ", tail)[:8192]))
    return result


def _parse_methods(path: str, text: str) -> list[Method]:
    lines = _strip_comments(text).splitlines()
    methods: list[Method] = []
    index = 0
    while index < len(lines) and len(methods) < MAX_METHODS:
        line = lines[index]
        match = METHOD_HEADER_RE.search(line)
        constructor = False
        if not match:
            match = CONSTRUCTOR_HEADER_RE.search(line)
            constructor = bool(match)
        if not match or match.group("name") in CONTROL_WORDS:
            index += 1
            continue
        name = match.group("name")
        params = _parse_parameters(match.group("params"))
        return_type = "<constructor>" if constructor else match.group("return")
        method_id = _id("method", path, index + 1, name, len(params))
        if match.group("body") == "=>":
            expression = line.split("=>", 1)[1].strip()
            if expression.endswith(";"):
                expression = expression[:-1]
            methods.append(Method(method_id, path, name, return_type, index + 1, params, [(index + 1, f"return {expression}")]))
            index += 1
            continue
        body_lines: list[tuple[int, str]] = []
        brace_index = line.find("{", match.start("body"))
        depth = line.count("{", brace_index) - line.count("}", brace_index)
        same_line = line[brace_index + 1:] if brace_index >= 0 else ""
        if depth <= 0 and "}" in same_line:
            same_line = same_line.rsplit("}", 1)[0]
        if same_line.strip():
            body_lines.append((index + 1, same_line))
        cursor = index + 1
        while cursor < len(lines) and depth > 0:
            current = lines[cursor]
            next_depth = depth + current.count("{") - current.count("}")
            if next_depth <= 0 and "}" in current:
                current = current.rsplit("}", 1)[0]
            if current.strip():
                body_lines.append((cursor + 1, current))
            depth = next_depth
            cursor += 1
        methods.append(Method(method_id, path, name, return_type, index + 1, params, _logical_statements(body_lines)))
        index = max(index + 1, cursor)
    return methods


def _calls(expression: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for match in CALL_HEAD_RE.finditer(expression):
        target = re.sub(r"\s+", "", match.group("target"))
        member = target.rsplit(".", 1)[-1]
        if member.casefold() in CONTROL_WORDS:
            continue
        open_index = match.end() - 1
        depth = 1
        index = open_index + 1
        in_string = False
        quote = ""
        escaped = False
        while index < len(expression) and depth:
            char = expression[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    in_string = False
                index += 1
                continue
            if char in {'"', "'"}:
                in_string, quote = True, char
            elif char == "(": depth += 1
            elif char == ")": depth -= 1
            index += 1
        if depth:
            continue
        args_text = expression[open_index + 1:index - 1]
        result.append({
            "target": target,
            "receiver": target.rsplit(".", 1)[0] if "." in target else "",
            "member": member,
            "arguments": _split_balanced(args_text),
            "start": match.start(),
        })
    return result


def _matchers(call: Mapping[str, Any], entries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    member = str(call.get("member") or "").casefold()
    receiver = str(call.get("receiver") or "").casefold()
    target = str(call.get("target") or "").casefold()
    result: list[dict[str, Any]] = []
    for raw in entries:
        members = [str(item).casefold() for item in raw.get("members") or []]
        if members and member not in members:
            continue
        receiver_contains = [str(item).casefold() for item in raw.get("receiverContains") or []]
        if receiver_contains and not any(item in receiver or item in target for item in receiver_contains):
            continue
        result.append(dict(raw))
    return result


def _matcher(call: Mapping[str, Any], entries: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    matches = _matchers(call, entries)
    return matches[0] if matches else None


def _assignment(statement: str) -> tuple[str, str] | None:
    value = statement.strip()
    for regex in (DECL_ASSIGN_RE, PLAIN_ASSIGN_RE):
        match = regex.match(value)
        if match:
            return match.group("lhs"), match.group("rhs").strip()
    return None


def _origin_limit(values: Iterable[Origin]) -> set[Origin]:
    return set(sorted(set(values))[:MAX_SUMMARY_ORIGINS])


def _with_sanitizer(origin: Origin, sanitizer_id: str) -> Origin:
    values = tuple(dict.fromkeys([*origin.sanitizers, sanitizer_id]))[:8]
    return Origin(origin.kind, origin.ref, values)


def _substitute(origin: Origin, argument_origins: list[set[Origin]]) -> set[Origin]:
    if origin.kind != "param":
        return {origin}
    try:
        index = int(origin.ref)
    except ValueError:
        return set()
    if index < 0 or index >= len(argument_origins):
        return set()
    result = set()
    for item in argument_origins[index]:
        merged = item
        for sanitizer in origin.sanitizers:
            merged = _with_sanitizer(merged, sanitizer)
        result.add(merged)
    return _origin_limit(result)


def _method_lookup(methods: list[Method]) -> dict[tuple[str, str], list[Method]]:
    result: dict[tuple[str, str], list[Method]] = {}
    for method in methods:
        result.setdefault((method.path, method.name.casefold()), []).append(method)
    return result


def _resolve_local(method: Method, call: Mapping[str, Any], lookup: Mapping[tuple[str, str], list[Method]]) -> Method | None:
    member = str(call.get("member") or "").casefold()
    receiver = str(call.get("receiver") or "").casefold()
    if receiver and receiver not in {"this", "base"}:
        return None
    candidates = list(lookup.get((method.path, member)) or [])
    argc = len(call.get("arguments") or [])
    exact = [item for item in candidates if len(item.parameters) == argc]
    if len(exact) == 1:
        return exact[0]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _source_node(source_nodes: dict[str, dict[str, Any]], matcher: Mapping[str, Any], method: Method, line: int, symbol: str) -> Origin:
    source_id = _id("source", matcher.get("id"), method.path, line, method.method_id, symbol)
    source_nodes.setdefault(source_id, {
        "sourceId": source_id,
        "kind": str(matcher.get("id") or ""),
        "dataClass": str(matcher.get("dataClass") or ""),
        "origin": "source",
        "path": method.path,
        "line": line,
        "method": method.name,
        "methodId": method.method_id,
        "symbol": symbol[:512],
        "evidence": [f"source:{method.path}:{line}: semantic flow source {matcher.get('id')} via {symbol[:180]}"],
    })
    return Origin("source", source_id)


def _expr_origins(
    expression: str,
    env: Mapping[str, set[Origin]],
    method: Method,
    line: int,
    registry: Mapping[str, Any],
    source_nodes: dict[str, dict[str, Any]],
    lookup: Mapping[tuple[str, str], list[Method]],
    return_summaries: Mapping[str, set[Origin]],
) -> set[Origin]:
    result: set[Origin] = set()
    calls = _calls(expression)
    for call in calls:
        source_match = _matcher(call, registry.get("sources") or [])
        if source_match and not source_match.get("triggerKinds"):
            result.add(_source_node(source_nodes, source_match, method, line, str(call.get("target") or "")))
        sanitizer = _matcher(call, registry.get("sanitizers") or [])
        if sanitizer:
            indexes = list(sanitizer.get("argumentIndexes") or [])
            args = list(call.get("arguments") or [])
            san_origins: set[Origin] = set()
            for arg_index in indexes:
                if arg_index < len(args):
                    san_origins.update(_expr_origins(args[arg_index], env, method, line, registry, source_nodes, lookup, return_summaries))
            result.update(_with_sanitizer(item, str(sanitizer.get("id") or "")) for item in san_origins)
        local = _resolve_local(method, call, lookup)
        if local:
            args = list(call.get("arguments") or [])
            arg_origins = [
                _expr_origins(arg, env, method, line, registry, source_nodes, lookup, return_summaries)
                for arg in args
            ]
            for origin in return_summaries.get(local.method_id, set()):
                result.update(_substitute(origin, arg_origins))
    # Preserve ordinary assignment/concatenation flow even when no registered call is involved.
    for identifier in IDENT_RE.findall(expression):
        result.update(env.get(identifier, set()))
    return _origin_limit(result)


def _analyze_method(
    method: Method,
    registry: Mapping[str, Any],
    source_nodes: dict[str, dict[str, Any]],
    sink_nodes: dict[str, dict[str, Any]],
    lookup: Mapping[tuple[str, str], list[Method]],
    return_summaries: Mapping[str, set[Origin]],
    sink_summaries: Mapping[str, set[SinkTemplate]],
) -> tuple[set[Origin], set[SinkTemplate]]:
    env: dict[str, set[Origin]] = {
        parameter["name"]: {Origin("param", str(index))}
        for index, parameter in enumerate(method.parameters)
    }
    returns: set[Origin] = set()
    sinks: set[SinkTemplate] = set()
    for line, statement in method.statements[:MAX_METHOD_STATEMENTS]:
        assignment = _assignment(statement)
        lhs, rhs = assignment if assignment else ("", "")
        expression = rhs if assignment else statement
        calls = _calls(expression)

        for call in calls:
            args = list(call.get("arguments") or [])
            for sink_match in _matchers(call, registry.get("sinks") or []):
                for arg_index in sink_match.get("argumentIndexes") or []:
                    if arg_index >= len(args):
                        continue
                    origins = _expr_origins(args[arg_index], env, method, line, registry, source_nodes, lookup, return_summaries)
                    sink_node_id = _id("sink", sink_match.get("id"), method.path, line, method.method_id, call.get("target"), arg_index)
                    sink_nodes.setdefault(sink_node_id, {
                        "sinkId": sink_node_id,
                        "kind": str(sink_match.get("id") or ""),
                        "dataClass": str(sink_match.get("dataClass") or ""),
                        "origin": "source",
                        "path": method.path,
                        "line": line,
                        "method": method.name,
                        "methodId": method.method_id,
                        "symbol": str(call.get("target") or "")[:512],
                        "argumentIndex": int(arg_index),
                        "evidence": [f"source:{method.path}:{line}: semantic flow sink {sink_match.get('id')} via {str(call.get('target') or '')[:180]} argument {arg_index}"],
                    })
                    for origin in origins:
                        sinks.add(SinkTemplate(
                            str(sink_match.get("id") or ""), sink_node_id, str(sink_match.get("dataClass") or ""),
                            method.path, line, method.method_id, str(call.get("target") or ""), int(arg_index),
                            origin, (method.method_id,),
                        ))

            local = _resolve_local(method, call, lookup)
            if local:
                arg_origins = [
                    _expr_origins(arg, env, method, line, registry, source_nodes, lookup, return_summaries)
                    for arg in args
                ]
                for template in sink_summaries.get(local.method_id, set()):
                    substituted = _substitute(template.origin, arg_origins)
                    for origin in substituted:
                        call_path = (method.method_id, *template.call_path)[:MAX_CALL_DEPTH + 1]
                        sinks.add(dataclasses.replace(template, origin=origin, call_path=call_path))

        if assignment:
            # Assignment/property sinks are useful for ProcessStartInfo.Arguments/CommandText-like APIs.
            for sink_match in registry.get("assignmentSinks") or []:
                if any(lhs.casefold().endswith(str(suffix).casefold()) for suffix in sink_match.get("targetSuffixes") or []):
                    origins = _expr_origins(rhs, env, method, line, registry, source_nodes, lookup, return_summaries)
                    sink_node_id = _id("sink", sink_match.get("id"), method.path, line, method.method_id, lhs)
                    sink_nodes.setdefault(sink_node_id, {
                        "sinkId": sink_node_id,
                        "kind": str(sink_match.get("id") or ""),
                        "dataClass": str(sink_match.get("dataClass") or ""),
                        "origin": "source", "path": method.path, "line": line,
                        "method": method.name, "methodId": method.method_id,
                        "symbol": lhs[:512], "argumentIndex": -1,
                        "evidence": [f"source:{method.path}:{line}: semantic flow assignment sink {sink_match.get('id')} via {lhs[:180]}"],
                    })
                    for origin in origins:
                        sinks.add(SinkTemplate(
                            str(sink_match.get("id") or ""), sink_node_id, str(sink_match.get("dataClass") or ""),
                            method.path, line, method.method_id, lhs, -1, origin, (method.method_id,),
                        ))
            env_name = lhs.rsplit(".", 1)[-1] if "." not in lhs else lhs
            env[env_name] = _expr_origins(rhs, env, method, line, registry, source_nodes, lookup, return_summaries)

        return_match = RETURN_RE.match(statement)
        if return_match:
            returns.update(_expr_origins(return_match.group("expr"), env, method, line, registry, source_nodes, lookup, return_summaries))

    return _origin_limit(returns), set(sorted(sinks, key=lambda item: (
        item.sink_node_id, item.origin.kind, item.origin.ref, item.origin.sanitizers, item.call_path
    ))[:MAX_SINK_TEMPLATES])


def _trigger_origins(
    methods: list[Method], source_behavior: Mapping[str, Any], registry: Mapping[str, Any], source_nodes: dict[str, dict[str, Any]],
) -> dict[str, dict[int, set[Origin]]]:
    result: dict[str, dict[int, set[Origin]]] = {}
    by_path_name: dict[tuple[str, str], list[Method]] = {}
    for method in methods:
        by_path_name.setdefault((method.path, method.name.casefold()), []).append(method)
    for trigger in source_behavior.get("triggers") or []:
        if not isinstance(trigger, Mapping):
            continue
        path = str(trigger.get("path") or "")
        handler = str(trigger.get("handler") or trigger.get("method") or "")
        kind = str(trigger.get("kind") or "")
        event = str(trigger.get("event") or "")
        candidates = by_path_name.get((path, handler.casefold())) or []
        if len(candidates) != 1:
            continue
        method = candidates[0]
        for matcher in registry.get("sources") or []:
            trigger_kinds = [str(item).casefold() for item in matcher.get("triggerKinds") or []]
            if not trigger_kinds or kind.casefold() not in trigger_kinds:
                continue
            event_contains = [str(item).casefold() for item in matcher.get("eventContains") or []]
            if event_contains and not any(item in event.casefold() for item in event_contains):
                continue
            wanted_names = {str(item).casefold() for item in matcher.get("parameterNames") or []}
            matched_indexes = [
                index for index, parameter in enumerate(method.parameters)
                if parameter["name"].casefold() in wanted_names
            ]
            if not matched_indexes and kind.casefold() == "user-command":
                string_indexes = [index for index, parameter in enumerate(method.parameters) if "string" in parameter["type"].casefold()]
                if len(string_indexes) >= 2:
                    matched_indexes = [string_indexes[-1]]
            for index in matched_indexes[:8]:
                source_id = _id("source", matcher.get("id"), method.path, trigger.get("line"), method.method_id, index)
                source_nodes.setdefault(source_id, {
                    "sourceId": source_id,
                    "kind": str(matcher.get("id") or ""),
                    "dataClass": str(matcher.get("dataClass") or ""),
                    "origin": "source-trigger",
                    "path": method.path,
                    "line": int(trigger.get("line") or method.line),
                    "method": method.name,
                    "methodId": method.method_id,
                    "parameterIndex": index,
                    "parameter": method.parameters[index]["name"],
                    "triggerId": str(trigger.get("triggerId") or ""),
                    "evidence": [f"source:{method.path}:{int(trigger.get('line') or method.line)}: {matcher.get('id')} enters handler {method.name} parameter {method.parameters[index]['name']}"],
                })
                result.setdefault(method.method_id, {}).setdefault(index, set()).add(Origin("source", source_id))
    return result


def _instantiate(origin: Origin, parameter_origins: Mapping[int, set[Origin]]) -> set[Origin]:
    if origin.kind == "source":
        return {origin}
    try:
        index = int(origin.ref)
    except ValueError:
        return set()
    result: set[Origin] = set()
    for item in parameter_origins.get(index, set()):
        merged = item
        for sanitizer in origin.sanitizers:
            merged = _with_sanitizer(merged, sanitizer)
        result.add(merged)
    return result


def collect(
    source_entries: Mapping[str, int], read_file: Callable[[str], bytes], *, source_behavior: Mapping[str, Any] | None = None,
    registry_path: Path | None = None,
) -> dict[str, Any]:
    registry = load_registry(registry_path)
    methods: list[Method] = []
    total_bytes = 0
    dropped = {"files": 0, "bytes": 0, "methods": 0, "flows": 0, "summaryTemplates": 0}
    for path in sorted(source_entries, key=str.casefold):
        if PurePosixPath(path).suffix.casefold() != ".cs":
            continue
        if len(methods) >= MAX_METHODS:
            dropped["methods"] += 1
            break
        declared_bytes = int(source_entries.get(path) or 0)
        if declared_bytes > MAX_FILE_BYTES:
            dropped["files"] += 1
            continue
        if total_bytes + max(0, declared_bytes) > MAX_TOTAL_BYTES:
            dropped["bytes"] += max(0, declared_bytes)
            continue
        try:
            raw = read_file(path)
        except Exception:
            dropped["files"] += 1
            continue
        if len(raw) > MAX_FILE_BYTES:
            dropped["files"] += 1
            continue
        if total_bytes + len(raw) > MAX_TOTAL_BYTES:
            dropped["bytes"] += len(raw)
            continue
        total_bytes += len(raw)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", "ignore")
        parsed = _parse_methods(path, text)
        remaining = MAX_METHODS - len(methods)
        methods.extend(parsed[:remaining])
        if len(parsed) > remaining:
            dropped["methods"] += len(parsed) - remaining

    lookup = _method_lookup(methods)
    source_nodes: dict[str, dict[str, Any]] = {}
    sink_nodes: dict[str, dict[str, Any]] = {}
    return_summaries: dict[str, set[Origin]] = {method.method_id: set() for method in methods}
    sink_summaries: dict[str, set[SinkTemplate]] = {method.method_id: set() for method in methods}
    passes = 0
    converged = False
    for passes in range(1, MAX_SUMMARY_PASSES + 1):
        changed = False
        next_returns: dict[str, set[Origin]] = {}
        next_sinks: dict[str, set[SinkTemplate]] = {}
        for method in methods:
            returns, sinks = _analyze_method(method, registry, source_nodes, sink_nodes, lookup, return_summaries, sink_summaries)
            next_returns[method.method_id] = returns
            next_sinks[method.method_id] = sinks
            if returns != return_summaries.get(method.method_id, set()) or sinks != sink_summaries.get(method.method_id, set()):
                changed = True
        return_summaries, sink_summaries = next_returns, next_sinks
        if not changed:
            converged = True
            break

    trigger_origins = _trigger_origins(methods, source_behavior or {}, registry, source_nodes)
    flows_by_key: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    # Direct sources are meaningful from any method. Parameter-derived flows become concrete only
    # for entry handlers where we have an objective trigger-to-parameter observation.
    for method in methods:
        parameters = trigger_origins.get(method.method_id, {})
        for template in sink_summaries.get(method.method_id, set()):
            concrete = _instantiate(template.origin, parameters)
            if template.origin.kind == "source":
                concrete.add(template.origin)
            for origin in concrete:
                if origin.kind != "source" or origin.ref not in source_nodes:
                    continue
                key = (origin.ref, template.sink_node_id, origin.sanitizers)
                flow = {
                    "flowId": _id("flow", origin.ref, template.sink_node_id, ",".join(origin.sanitizers)),
                    "sourceId": origin.ref,
                    "sourceKind": str(source_nodes[origin.ref].get("kind") or ""),
                    "sourceDataClass": str(source_nodes[origin.ref].get("dataClass") or ""),
                    "sinkId": template.sink_node_id,
                    "sinkKind": template.sink_id,
                    "sinkDataClass": template.sink_data_class,
                    "sanitizers": list(origin.sanitizers),
                    "sanitized": bool(origin.sanitizers),
                    "interprocedural": len(template.call_path) > 1,
                    "interproceduralDepth": max(0, len(template.call_path) - 1),
                    "callPath": list(template.call_path),
                    "confidence": "high" if len(template.call_path) <= 1 else "medium",
                    "authority": "static-flow-observation-only",
                    "evidence": (list(source_nodes[origin.ref].get("evidence") or []) + list(sink_nodes.get(template.sink_node_id, {}).get("evidence") or []))[:MAX_EVIDENCE],
                }
                previous = flows_by_key.get(key)
                if previous is None or int(flow["interproceduralDepth"]) < int(previous["interproceduralDepth"]):
                    flows_by_key[key] = flow
                if len(flows_by_key) >= MAX_FLOWS:
                    dropped["flows"] += 1
                    break
            if len(flows_by_key) >= MAX_FLOWS:
                break
        if len(flows_by_key) >= MAX_FLOWS:
            break

    flows = sorted(flows_by_key.values(), key=lambda item: (item["sourceKind"], item["sinkKind"], item["flowId"]))
    return {
        "schema": SCHEMA,
        "contractVersion": CONTRACT_VERSION,
        "registryRevision": str(registry.get("revision") or ""),
        "sources": sorted(source_nodes.values(), key=lambda item: (item["path"].casefold(), int(item["line"]), item["kind"])),
        "sinks": sorted(sink_nodes.values(), key=lambda item: (item["path"].casefold(), int(item["line"]), item["kind"], int(item.get("argumentIndex") or -1))),
        "flows": flows,
        "summary": {
            "methodCount": len(methods),
            "sourceBytesAnalyzed": total_bytes,
            "sourceByteLimit": MAX_TOTAL_BYTES,
            "sourceCount": len(source_nodes),
            "sinkCount": len(sink_nodes),
            "flowCount": len(flows),
            "interproceduralFlowCount": sum(1 for item in flows if item.get("interprocedural")),
            "sanitizedFlowCount": sum(1 for item in flows if item.get("sanitized")),
            "summaryPasses": passes,
            "summaryConverged": converged,
            "analysisMode": "bounded-interprocedural-csharp-taint",
            "symbolResolution": "source-text-local-method-approximation",
            "authority": "objective-static-observation-only",
            "dropped": dropped,
            "limitations": [
                "Local source-text method resolution only; overloads or dynamic dispatch may remain unresolved.",
                "No claim is made that a statically represented branch executes at runtime.",
                "Sanitizer observations record transformations only; they do not declare a flow safe.",
            ],
        },
    }
