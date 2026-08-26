"""Bounded non-executing source behavior observations for SigmaScope.

This is deliberately a conservative lexical C# pass. It emits primitive operations and
relationships only; Stigma-1/SRL owns all higher-level behavioral conclusions.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

from semantic_registry import api_registry, match_source_call, service_for_url, service_registry

SCHEMA = "omega.sigmascope.source-behavior.v1"
CONTRACT_VERSION = 1
MAX_FILES = 512
MAX_FILE_BYTES = 1024 * 1024
MAX_ROWS = 8192
MAX_EDGES = 16384

METHOD_RE = re.compile(r"\b(?:public|private|protected|internal|static|async|virtual|override|sealed|partial|new|\s)+(?:[\w<>\[\],?.]+\s+)+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:=>|\{)?")
CALL_RE = re.compile(r"(?P<receiver>[A-Za-z_][A-Za-z0-9_.$<>]*)\s*\.\s*(?P<member>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
ASSIGN_RE = re.compile(r"\b(?:var|[\w<>\[\],?.]+)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)")
PLAIN_ASSIGN_RE = re.compile(r"(?<![=!<>])\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?!=)(?P<rhs>.+)")
EVENT_RE = re.compile(r"(?P<event>[A-Za-z_][A-Za-z0-9_.$<>]*)\s*\+=\s*(?P<handler>[A-Za-z_][A-Za-z0-9_]*)")
COMMAND_RE = re.compile(r'AddHandler\s*\(\s*"(?P<command>/[^"\s]+)"\s*,\s*(?P<handler>[A-Za-z_][A-Za-z0-9_]*)')
CONDITION_RE = re.compile(r"\b(?P<kind>if|while)\s*\((?P<expr>.*)\)")
DELAY_MS_RE = re.compile(r"(?:Task\.)?Delay\s*\(\s*(?P<value>\d+)\s*\)")
DELAY_TS_RE = re.compile(r"Task\.Delay\s*\(\s*TimeSpan\.From(?P<unit>Milliseconds|Seconds|Minutes)\s*\(\s*(?P<value>\d+(?:\.\d+)?)\s*\)\s*\)")
PERIODIC_RE = re.compile(r"PeriodicTimer\s*\(\s*TimeSpan\.From(?P<unit>Milliseconds|Seconds|Minutes)\s*\(\s*(?P<value>\d+(?:\.\d+)?)\s*\)")
STRINGS_RE = re.compile(r'@?"(?:[^"]|"")*"|"(?:\\.|[^"\\])*"')


def _id(kind: str, *parts: object) -> str:
    return f"{kind}-{hashlib.sha256('|'.join(str(p) for p in parts).encode()).hexdigest()[:20]}"


def _duration(match: re.Match[str] | None) -> int | None:
    if not match:
        return None
    value = float(match.group("value"))
    unit = match.groupdict().get("unit")
    factor = {"Milliseconds": 1, "Seconds": 1000, "Minutes": 60000}.get(str(unit), 1)
    return min(int(value * factor), 86_400_000)



def _strip_line_comment(value: str) -> str:
    in_string = False
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_string:
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if not in_string and char == "/" and index + 1 < len(value) and value[index + 1] == "/":
            return value[:index]
    return value

def _safe_condition(value: str) -> str:
    return re.sub(r"\s+", " ", STRINGS_RE.sub('"<redacted>"', value)).strip()[:1024]


def _operation(path: str, line: int, method: str, operation: str, symbol: str, *, matcher: str = "",
               receiver: str = "", member: str = "", semantic_api_revision: str = "",
               service: dict[str, Any] | None = None, awaited: bool = False,
               target: str = "", guard: str = "", delay_ms: int = 0) -> dict[str, Any]:
    row = {
        "operationId": _id("op", path, line, method, operation, symbol),
        "origin": "source", "path": path, "line": line, "method": method,
        "operation": operation, "symbol": symbol[:512], "receiver": receiver[:256], "member": member[:256],
        "matcherId": matcher, "semanticApiRegistryRevision": semantic_api_revision,
        "awaited": bool(awaited), "semanticTarget": target,
        "guardConditionId": guard, "delayMs": int(delay_ms),
        "serviceId": "", "serviceName": "", "serviceRecognition": "", "serviceRegistryRevision": "",
        "serviceCategories": [], "serviceCapabilities": [],
        "upstreamServiceIds": [], "upstreamServiceCapabilities": [],
        "evidence": [f"source:{path}:{line}: {operation} via {symbol[:180]}"],
    }
    if service:
        for key in ("serviceId", "serviceName", "serviceRecognition", "serviceRegistryRevision", "serviceCategories", "serviceCapabilities"):
            row[key] = service.get(key, row[key])
    return row


def collect(source_entries: Mapping[str, int], read_file: Callable[[str], bytes]) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    flow: list[dict[str, Any]] = []
    triggers: list[dict[str, Any]] = []
    conditions: list[dict[str, Any]] = []
    data_flow: list[dict[str, Any]] = []
    first_by_method: dict[tuple[str, str], dict[str, Any]] = {}
    pending_trigger_links: list[tuple[dict[str, Any], str, str, int]] = []
    dropped = {"files": 0, "operations": 0, "flowEdges": 0, "triggers": 0, "conditions": 0, "dataFlow": 0}

    paths = [str(p) for p in sorted(source_entries, key=str.casefold) if PurePosixPath(str(p)).suffix.casefold() == ".cs"]
    if len(paths) > MAX_FILES:
        dropped["files"] += len(paths) - MAX_FILES
        paths = paths[:MAX_FILES]

    for path in paths:
        if int(source_entries.get(path) or 0) > MAX_FILE_BYTES:
            dropped["files"] += 1
            continue
        try:
            raw = read_file(path)
        except Exception:
            continue
        if len(raw) > MAX_FILE_BYTES:
            dropped["files"] += 1
            continue
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            continue

        method = "<file>"
        previous: dict[str, Any] | None = None
        variables: dict[str, dict[str, Any]] = {}
        guard = ""
        pending_delay = 0
        brace_depth = 0
        method_depth: int | None = None
        awaiting_method_brace = False
        condition_stack: list[tuple[int, str]] = []
        pending_single_guard = ""

        for line_no, raw_line in enumerate(lines, 1):
            line = _strip_line_comment(raw_line).strip()
            if not line:
                continue
            # Keep only structural block scope. This remains a conservative lexical
            # approximation and is labelled as such in the collection summary.
            while condition_stack and brace_depth < condition_stack[-1][0]:
                condition_stack.pop()
            guard = condition_stack[-1][1] if condition_stack else pending_single_guard
            pending_single_guard = ""

            mm = METHOD_RE.search(line)
            if mm and not line.startswith(("if ", "while ", "for ", "switch ")):
                method = mm.group("name")
                previous = None
                variables = {}
                guard = ""
                pending_delay = 0
                condition_stack.clear()
                if "{" in line:
                    method_depth = brace_depth + 1
                    awaiting_method_brace = False
                else:
                    method_depth = None
                    awaiting_method_brace = True
            elif awaiting_method_brace and "{" in line:
                method_depth = brace_depth + 1
                awaiting_method_brace = False

            cm = CONDITION_RE.search(line)
            if cm:
                normalized = _safe_condition(cm.group("expr"))
                cid = _id("cond", path, line_no, method, cm.group("kind"), normalized)
                row = {
                    "conditionId": cid, "origin": "source", "path": path, "line": line_no,
                    "method": method, "kind": cm.group("kind"), "normalizedExpression": normalized,
                    "expressionSha256": hashlib.sha256(normalized.encode()).hexdigest(),
                    "evidence": [f"source:{path}:{line_no}: {cm.group('kind')} condition"],
                }
                if len(conditions) < MAX_ROWS:
                    conditions.append(row)
                    guard = cid
                    if "{" in line:
                        condition_stack.append((brace_depth + 1, cid))
                    else:
                        pending_single_guard = cid
                else:
                    dropped["conditions"] += 1

            event = EVENT_RE.search(line)
            command = COMMAND_RE.search(line)
            periodic = _duration(PERIODIC_RE.search(line))
            if event or command or periodic is not None:
                if command:
                    kind, label, handler, period = "user-command", command.group("command"), command.group("handler"), 0
                elif event:
                    kind, label, handler, period = "event", event.group("event"), event.group("handler"), 0
                else:
                    kind, label, handler, period = "periodic", "PeriodicTimer", method, int(periodic or 0)
                trigger = {
                    "triggerId": _id("trigger", path, line_no, kind, label, handler),
                    "origin": "source", "path": path, "line": line_no, "method": method,
                    "kind": kind, "event": label[:512], "handler": handler, "periodMs": period,
                    "evidence": [f"source:{path}:{line_no}: {kind} trigger {label[:180]}"],
                }
                if len(triggers) < MAX_ROWS:
                    triggers.append(trigger)
                    pending_trigger_links.append((trigger, path, handler, line_no))
                else:
                    dropped["triggers"] += 1

            found: list[dict[str, Any]] = []
            delay = _duration(DELAY_TS_RE.search(line)) or _duration(DELAY_MS_RE.search(line))
            if delay:
                found.append(_operation(path, line_no, method, "time.delay", "Task.Delay",
                                        matcher="time.delay", receiver="Task", member="Delay",
                                        semantic_api_revision=str(api_registry().get("revision") or ""),
                                        awaited="await" in line, guard=guard, delay_ms=delay))
                pending_delay = delay

            urls = URL_RE.findall(line)
            for call in CALL_RE.finditer(line):
                receiver, member = call.group("receiver"), call.group("member")
                matched = match_source_call(receiver, member)
                if not matched or (matched["operation"] == "time.delay" and delay):
                    continue
                attrs = dict(matched.get("attributes") or {})
                service = service_for_url(urls[0]) if urls and matched["operation"] == "network.http.request" else None
                found.append(_operation(
                    path, line_no, method, str(matched["operation"]), f"{receiver}.{member}",
                    matcher=str(matched["matcherId"]), receiver=receiver, member=member,
                    semantic_api_revision=str(matched.get("semanticApiRegistryRevision") or ""),
                    service=service, awaited="await" in line,
                    target=str(attrs.get("semanticTarget") or ""), guard=guard,
                ))

            for current in found:
                if len(operations) >= MAX_ROWS:
                    dropped["operations"] += 1
                    continue
                operations.append(current)
                first_by_method.setdefault((path, method), current)

                if previous:
                    edge = {
                        "edgeId": _id("edge", previous["operationId"], current["operationId"]),
                        "origin": "source", "path": path, "method": method,
                        "fromOperationId": previous["operationId"], "toOperationId": current["operationId"],
                        "fromOperation": previous["operation"], "toOperation": current["operation"],
                        "relation": "after-await" if current["awaited"] else "happens-before",
                        "minimumDelayMs": int(pending_delay),
                        "guardConditionId": current["guardConditionId"],
                        "fromServiceCapabilities": list(previous.get("serviceCapabilities") or []),
                        "toServiceCapabilities": list(current.get("serviceCapabilities") or []),
                        "evidence": [f"source:{path}:{line_no}: lexical/control order in {method}"],
                    }
                    if len(flow) < MAX_EDGES:
                        flow.append(edge)
                    else:
                        dropped["flowEdges"] += 1

                assign = ASSIGN_RE.search(line) or PLAIN_ASSIGN_RE.search(line)
                assigned_name = assign.group("name") if assign else ""
                rhs = assign.group("rhs") if assign else line
                used_producers: list[tuple[str, dict[str, Any]]] = []
                for name, producer in list(variables.items()):
                    # A variable appearing only on the assignment LHS is not a use.
                    if producer["operationId"] != current["operationId"] and re.search(rf"\b{re.escape(name)}\b", rhs):
                        used_producers.append((name, producer))

                upstream_ids: set[str] = set(current.get("upstreamServiceIds") or [])
                upstream_capabilities: set[str] = set(current.get("upstreamServiceCapabilities") or [])
                for _name, producer in used_producers:
                    if producer.get("serviceId"):
                        upstream_ids.add(str(producer["serviceId"]))
                    upstream_ids.update(str(v) for v in producer.get("upstreamServiceIds") or [])
                    upstream_capabilities.update(str(v) for v in producer.get("serviceCapabilities") or [])
                    upstream_capabilities.update(str(v) for v in producer.get("upstreamServiceCapabilities") or [])
                current["upstreamServiceIds"] = sorted(upstream_ids)[:32]
                current["upstreamServiceCapabilities"] = sorted(upstream_capabilities)[:64]

                for name, producer in used_producers:
                    provenance_capabilities = sorted({
                        *(str(v) for v in producer.get("serviceCapabilities") or []),
                        *(str(v) for v in producer.get("upstreamServiceCapabilities") or []),
                    })[:64]
                    edge = {
                        "edgeId": _id("data", producer["operationId"], current["operationId"], name),
                        "origin": "source", "path": path, "method": method,
                        "fromOperationId": producer["operationId"], "toOperationId": current["operationId"],
                        "fromOperation": producer["operation"], "toOperation": current["operation"],
                        "relation": "value-used-by", "valueId": name[:128],
                        "fromServiceCapabilities": provenance_capabilities,
                        "evidence": [f"source:{path}:{line_no}: value {name} consumed by {current['operation']}"],
                    }
                    if len(data_flow) < MAX_EDGES:
                        data_flow.append(edge)
                    else:
                        dropped["dataFlow"] += 1
                if assigned_name:
                    variables[assigned_name] = current

                previous = current
                if current["operation"] != "time.delay":
                    pending_delay = 0

            # Propagate provenance through a plain assignment that contains no registered
            # primitive call (for example: selected = Choose(prices)).
            if not found:
                assign = ASSIGN_RE.search(line) or PLAIN_ASSIGN_RE.search(line)
                if assign:
                    rhs = assign.group("rhs")
                    sources = [producer for name, producer in variables.items() if re.search(rf"\b{re.escape(name)}\b", rhs)]
                    if len(sources) == 1:
                        variables[assign.group("name")] = sources[0]

            brace_depth += line.count("{") - line.count("}")
            while condition_stack and brace_depth < condition_stack[-1][0]:
                condition_stack.pop()
            if method_depth is not None and brace_depth < method_depth:
                method = "<file>"
                method_depth = None
                awaiting_method_brace = False
                previous = None
                variables = {}
                condition_stack.clear()
                pending_delay = 0

    for trigger, path, handler, trigger_line in pending_trigger_links:
        if trigger.get("kind") == "periodic":
            candidates = [
                item for item in operations
                if item.get("path") == path and item.get("method") == handler and int(item.get("line") or 0) > trigger_line
            ]
            target = min(candidates, key=lambda item: int(item.get("line") or 0), default=None)
        else:
            target = first_by_method.get((path, handler))
        if not target:
            continue
        edge = {
            "edgeId": _id("edge", trigger["triggerId"], target["operationId"]),
            "origin": "source", "path": path, "method": handler,
            "fromOperationId": trigger["triggerId"], "toOperationId": target["operationId"],
            "fromOperation": f"trigger.{trigger['kind']}", "toOperation": target["operation"],
            "relation": "triggers", "minimumDelayMs": int(trigger.get("periodMs") or 0),
            "guardConditionId": "", "fromServiceCapabilities": [],
            "toServiceCapabilities": list(target.get("serviceCapabilities") or []),
            "evidence": list(trigger["evidence"]) + list(target["evidence"]),
        }
        if len(flow) < MAX_EDGES:
            flow.append(edge)
        else:
            dropped["flowEdges"] += 1

    return {
        "schema": SCHEMA,
        "contractVersion": CONTRACT_VERSION,
        "operations": operations, "flowEdges": flow, "triggers": triggers,
        "conditions": conditions, "dataFlow": data_flow,
        "summary": {
            "operationCount": len(operations), "flowEdgeCount": len(flow),
            "triggerCount": len(triggers), "conditionCount": len(conditions),
            "dataFlowCount": len(data_flow), "dropped": dropped,
            "analysisMode": "bounded-lexical-source-behavior",
            "authority": "objective-static-observation-only",
            "semanticApiRegistryRevision": str(api_registry().get("revision") or ""),
            "serviceRegistryRevision": str(service_registry().get("revision") or ""),
        },
    }
