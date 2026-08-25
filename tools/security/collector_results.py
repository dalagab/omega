#!/usr/bin/env python3
"""Generic immutable result envelope for Omega observation collectors.

Collectors only return typed observations plus bounded provenance.  This module validates
that a collector is registered for every returned observation and content-addresses the
result.  It contains no Evidence-v2 mutation, rule evaluation, workflow launch, or policy
logic, so every future collector can use the same producer/result contract.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import analysis_broker  # noqa: E402
import collector_contracts  # noqa: E402

RESULT_SCHEMA = "omega.collector-result.v1"
COLLECTION_SCHEMA = "omega.collector-result-collection.v1"
MAX_RESULT_ROWS = 10_000
MAX_COLLECTION_ROWS = 5_000
MAX_ERRORS = 256
MAX_ERROR_TEXT = 2_000
MAX_TEXT = 8_192
MAX_STRING_ITEMS = 4_096
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def record_digest(rows: Iterable[Mapping[str, Any]]) -> tuple[int, str]:
    hashes = sorted(sha256_bytes(canonical_json_bytes(dict(row))) for row in rows)
    digest = hashlib.sha256()
    for item in hashes:
        digest.update(item.encode("ascii"))
        digest.update(b"\n")
    return len(hashes), digest.hexdigest()


def _validate_scalar(kind: str, value: Any, label: str) -> None:
    if kind == "string" or kind == "https-url":
        if not isinstance(value, str):
            raise ValueError(f"{label} must be a string")
        if len(value) > MAX_TEXT:
            raise ValueError(f"{label} exceeds {MAX_TEXT} characters")
        if kind == "https-url" and value and not value.startswith("https://"):
            raise ValueError(f"{label} must be HTTPS")
        return
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{label} must be an integer")
        return
    if kind == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"{label} must be a boolean")
        return
    if kind == "string[]":
        if (not isinstance(value, list) or len(value) > MAX_STRING_ITEMS
                or any(not isinstance(item, str) or len(item) > MAX_TEXT for item in value)):
            raise ValueError(f"{label} must be a bounded string array")
        return
    raise ValueError(f"{label} uses unsupported field kind {kind!r}")


def validate_observation_row(observation: str, row: Mapping[str, Any]) -> dict[str, Any]:
    spec = collector_contracts.OBSERVATION_TYPES.get(str(observation))
    if not isinstance(spec, Mapping):
        raise ValueError(f"unknown collector observation type: {observation!r}")
    fields = spec.get("fields") if isinstance(spec.get("fields"), Mapping) else {}
    extras = sorted(set(row) - set(fields))
    if extras:
        raise ValueError(f"{observation} row contains unsupported fields: {extras}")
    result = dict(row)
    for field, value in result.items():
        _validate_scalar(str(fields[field]), value, f"{observation}.{field}")
    return result


def _normalize_errors(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip().replace("\x00", "")[:MAX_ERROR_TEXT]
        if text:
            result.append(text)
        if len(result) >= MAX_ERRORS:
            break
    return result


def build_result(
    request_value: Mapping[str, Any], *, collector_id: str, collections: Mapping[str, Iterable[Mapping[str, Any]]],
    work_item_id: str = "", status: str = "complete", errors: Iterable[Any] = (), generated_at_utc: str = "",
) -> dict[str, Any]:
    request = analysis_broker.compile_request(request_value)
    collector = collector_contracts.collector_map().get(str(collector_id))
    if not isinstance(collector, Mapping):
        raise ValueError(f"unknown collector: {collector_id!r}")
    if str(collector.get("status") or "active") != "active":
        raise ValueError(f"collector is not active: {collector_id}")
    normalized_status = str(status or "").strip().lower()
    if normalized_status not in {"complete", "partial", "failed"}:
        raise ValueError("collector result status must be complete, partial, or failed")
    declared = {str(item) for item in collector.get("provides") or [] if str(item)}
    wanted = str(request.get("observation") or "")
    if wanted not in declared:
        raise ValueError(f"collector {collector_id} does not provide requested observation {wanted!r}")

    normalized_collections: dict[str, Any] = {}
    total_rows = 0
    for observation, raw_rows in sorted(collections.items()):
        name = str(observation or "")
        if name not in declared:
            raise ValueError(f"collector {collector_id} does not provide {name!r}")
        rows = [validate_observation_row(name, dict(row)) for row in raw_rows]
        if len(rows) > MAX_COLLECTION_ROWS:
            raise ValueError(f"collector result collection {name} exceeds {MAX_COLLECTION_ROWS} rows")
        total_rows += len(rows)
        if total_rows > MAX_RESULT_ROWS:
            raise ValueError(f"collector result exceeds {MAX_RESULT_ROWS} rows")
        count, digest = record_digest(rows)
        spec = collector_contracts.OBSERVATION_TYPES[name]
        normalized_collections[name] = {
            "schema": COLLECTION_SCHEMA,
            "observationSchema": str(spec.get("schema") or ""),
            "semanticClass": str(spec.get("semanticClass") or ""),
            "authority": str(spec.get("authority") or "observation-only"),
            "contractRevision": collector_contracts.observation_contract_revision(name),
            "records": count,
            "recordDigest": digest,
            "rows": rows,
        }
    if normalized_status != "failed" and wanted not in normalized_collections:
        raise ValueError(f"successful collector result must contain requested observation {wanted!r}")

    generated = str(generated_at_utc or utc_now())
    subject = dict(request.get("subject") or {})
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "requestId": str(request.get("requestId") or ""),
        "workItemId": str(work_item_id or "")[:256],
        "observation": wanted,
        "subject": subject,
        "subjectKey": str(request.get("subjectKey") or analysis_broker.subject_key(subject)),
        "collector": {
            "id": str(collector_id),
            "version": int(collector.get("version") or 0),
            "componentId": str(collector.get("componentId") or ""),
            "registryRevision": collector_contracts.registry_revision(),
            "contractRevision": collector_contracts.collector_contract_revision(str(collector_id)),
        },
        "status": normalized_status,
        "generatedAtUtc": generated,
        "authority": "observation-only",
        "records": total_rows,
        "collections": normalized_collections,
        "errors": _normalize_errors(errors),
    }
    semantic_collector = {key: payload["collector"][key] for key in ("id", "version", "componentId", "contractRevision")}
    semantic = {
        key: payload[key]
        for key in ("schema", "requestId", "workItemId", "observation", "subject", "subjectKey", "status", "generatedAtUtc", "authority", "records", "collections", "errors")
    }
    semantic["collector"] = semantic_collector
    payload["resultRevision"] = "collector-result-v1-" + sha256_bytes(canonical_json_bytes(semantic))[:24]
    return payload


def validate_result(value: Mapping[str, Any]) -> dict[str, Any]:
    if str(value.get("schema") or "") != RESULT_SCHEMA:
        raise ValueError(f"collector result schema must be {RESULT_SCHEMA}")
    request_stub = {
        "schema": analysis_broker.ANALYSIS_REQUEST_SCHEMA,
        "requestId": str(value.get("requestId") or ""),
        "observation": str(value.get("observation") or ""),
        "subject": dict(value.get("subject") or {}),
        "subjectKey": str(value.get("subjectKey") or ""),
        "reason": "collector result validation",
        "priority": 0,
        "requestedBy": {"componentId": "omega.analysis-broker"},
        "freshness": {},
    }
    # Preserve the original request identity while using the broker's canonical subject validator.
    request = analysis_broker.compile_request(request_stub)
    collector_info = value.get("collector") if isinstance(value.get("collector"), Mapping) else {}
    collector_id = str(collector_info.get("id") or "")
    collector = collector_contracts.collector_map().get(collector_id)
    if not isinstance(collector, Mapping):
        raise ValueError(f"collector result references unknown collector: {collector_id!r}")
    if str(collector_info.get("componentId") or "") != str(collector.get("componentId") or ""):
        raise ValueError("collector result component identity mismatch")
    if int(collector_info.get("version") or 0) != int(collector.get("version") or 0):
        raise ValueError("collector result version identity mismatch")
    if str(collector_info.get("contractRevision") or "") != collector_contracts.collector_contract_revision(collector_id):
        raise ValueError("collector result contract revision mismatch")
    registry_revision = str(collector_info.get("registryRevision") or "")
    if registry_revision and not registry_revision.startswith("collector-registry-v1-"):
        raise ValueError("collector result registry revision is malformed")
    status = str(value.get("status") or "")
    collections = value.get("collections") if isinstance(value.get("collections"), Mapping) else {}
    rebuilt = build_result(
        request,
        collector_id=collector_id,
        collections={name: list((descriptor or {}).get("rows") or []) for name, descriptor in collections.items() if isinstance(descriptor, Mapping)},
        work_item_id=str(value.get("workItemId") or ""),
        status=status,
        errors=list(value.get("errors") or []),
        generated_at_utc=str(value.get("generatedAtUtc") or ""),
    )
    # generatedAtUtc is transport metadata, but every semantic/content-addressed field must reproduce.
    for key in ("requestId", "workItemId", "observation", "subject", "subjectKey", "status", "generatedAtUtc", "authority", "records", "collections", "errors", "resultRevision"):
        if value.get(key) != rebuilt.get(key):
            raise ValueError(f"collector result {key} does not reproduce")
    for key in ("id", "version", "componentId", "contractRevision"):
        if collector_info.get(key) != (rebuilt.get("collector") or {}).get(key):
            raise ValueError(f"collector result collector.{key} does not reproduce")
    return dict(value)


def rows_from_result(value: Mapping[str, Any], observation: str = "") -> dict[str, list[dict[str, Any]]] | list[dict[str, Any]]:
    result = validate_result(value)
    collections = result.get("collections") if isinstance(result.get("collections"), Mapping) else {}
    rows = {
        str(name): [dict(row) for row in (descriptor.get("rows") or []) if isinstance(row, Mapping)]
        for name, descriptor in collections.items() if isinstance(descriptor, Mapping)
    }
    if observation:
        return rows.get(str(observation), [])
    return rows


__all__ = [
    "RESULT_SCHEMA", "COLLECTION_SCHEMA", "build_result", "validate_result", "rows_from_result",
    "record_digest", "canonical_json_bytes", "sha256_bytes", "utc_now",
]
