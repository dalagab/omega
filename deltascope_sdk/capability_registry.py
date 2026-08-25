#!/usr/bin/env python3
"""Shared SigmaScope capability registry loader/validator.

The registry is descriptive security vocabulary. It does not assign verdicts and it
never suppresses scanner evidence. Developer profile declarations and future SRL rules
normalize through this module so the same capability ID means the same thing across
SigmaScope, DeltaScope, and Omega.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "omega.sigmascope.capability-registry.v1"
CAPABILITY_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")
MAX_CAPABILITIES = 512
MAX_ALIASES_PER_CAPABILITY = 32
MAX_TEXT = 2048
_RUNTIME_REGISTRY: dict[str, Any] | None = None


def default_registry_path() -> Path:
    return Path(__file__).resolve().parents[1] / "security-definitions" / "capabilities" / "registry.json"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _text(value: Any, field: str, *, maximum: int = MAX_TEXT, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field} is required")
    if len(value) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return value


def validate_registry(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ValueError("capability registry must be a JSON object")
    if document.get("schema") != SCHEMA:
        raise ValueError(f"unsupported capability registry schema: {document.get('schema')!r}")
    try:
        version = int(document.get("version") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("capability registry version must be an integer") from exc
    if version != 1:
        raise ValueError(f"unsupported capability registry version: {version}")

    categories_raw = document.get("categories")
    if not isinstance(categories_raw, list) or not categories_raw:
        raise ValueError("capability registry categories must be a non-empty list")
    categories: list[str] = []
    category_seen: set[str] = set()
    for index, value in enumerate(categories_raw):
        category = _text(value, f"categories[{index}]", maximum=64, required=True)
        if category in category_seen:
            raise ValueError(f"duplicate capability category: {category}")
        category_seen.add(category)
        categories.append(category)

    entries_raw = document.get("capabilities")
    if not isinstance(entries_raw, list):
        raise ValueError("capability registry capabilities must be a list")
    if len(entries_raw) > MAX_CAPABILITIES:
        raise ValueError(f"capability registry exceeds {MAX_CAPABILITIES} entries")

    entries: list[dict[str, Any]] = []
    ids: set[str] = set()
    lookup_keys: dict[str, str] = {}
    for index, raw in enumerate(entries_raw):
        if not isinstance(raw, dict):
            raise ValueError(f"capabilities[{index}] must be an object")
        unknown = set(raw) - {"id", "category", "label", "description", "aliases", "attributes", "deprecated", "replacement"}
        if unknown:
            raise ValueError(f"capabilities[{index}] has unsupported fields: {', '.join(sorted(unknown))}")
        capability_id = _text(raw.get("id"), f"capabilities[{index}].id", maximum=128, required=True)
        if not CAPABILITY_ID_RE.fullmatch(capability_id):
            raise ValueError(f"invalid capability id: {capability_id}")
        if capability_id in ids:
            raise ValueError(f"duplicate capability id: {capability_id}")
        ids.add(capability_id)
        category = _text(raw.get("category"), f"capabilities[{index}].category", maximum=64, required=True)
        if category not in category_seen:
            raise ValueError(f"unknown category for {capability_id}: {category}")
        label = _text(raw.get("label"), f"capabilities[{index}].label", maximum=160, required=True)
        description = _text(raw.get("description"), f"capabilities[{index}].description", maximum=1200, required=True)
        aliases_raw = raw.get("aliases") or []
        if not isinstance(aliases_raw, list) or len(aliases_raw) > MAX_ALIASES_PER_CAPABILITY:
            raise ValueError(f"aliases for {capability_id} must be a list of at most {MAX_ALIASES_PER_CAPABILITY}")
        aliases: list[str] = []
        local_aliases: set[str] = set()
        for alias_index, value in enumerate(aliases_raw):
            alias = _text(value, f"capabilities[{index}].aliases[{alias_index}]", maximum=160, required=True)
            folded = alias.casefold()
            if folded == capability_id.casefold() or folded in local_aliases:
                continue
            local_aliases.add(folded)
            aliases.append(alias)
        attributes = raw.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise ValueError(f"attributes for {capability_id} must be an object")
        if len(attributes) > 16:
            raise ValueError(f"attributes for {capability_id} exceed 16 fields")
        normalized_attributes: dict[str, Any] = {}
        for key, value in sorted(attributes.items()):
            key_text = _text(key, f"attributes key for {capability_id}", maximum=64, required=True)
            if not isinstance(value, (str, int, float, bool)) and value is not None:
                raise ValueError(f"attribute {capability_id}.{key_text} must be scalar")
            if isinstance(value, str) and len(value) > 128:
                raise ValueError(f"attribute {capability_id}.{key_text} exceeds 128 characters")
            normalized_attributes[key_text] = value
        deprecated = bool(raw.get("deprecated"))
        replacement = _text(raw.get("replacement"), f"capabilities[{index}].replacement", maximum=128)
        entries.append({
            "id": capability_id,
            "category": category,
            "label": label,
            "description": description,
            "aliases": sorted(aliases, key=str.casefold),
            "attributes": normalized_attributes,
            "deprecated": deprecated,
            "replacement": replacement,
        })

    for entry in entries:
        for key in [entry["id"], entry["label"], *entry["aliases"]]:
            folded = str(key).casefold()
            previous = lookup_keys.get(folded)
            if previous and previous != entry["id"]:
                raise ValueError(f"capability alias/label collision: {key!r} maps to both {previous} and {entry['id']}")
            lookup_keys[folded] = entry["id"]
        if entry["replacement"] and entry["replacement"] not in ids:
            raise ValueError(f"replacement for {entry['id']} is unknown: {entry['replacement']}")
        if entry["replacement"] and not entry["deprecated"]:
            raise ValueError(f"non-deprecated capability {entry['id']} cannot declare replacement")

    normalized = {
        "schema": SCHEMA,
        "version": version,
        "categories": categories,
        "capabilities": sorted(entries, key=lambda item: item["id"]),
    }
    normalized["revision"] = f"capabilities-v1-{hashlib.sha256(canonical_bytes(normalized)).hexdigest()[:16]}"
    return normalized


def configure_registry(document: dict[str, Any] | None) -> None:
    global _RUNTIME_REGISTRY
    _RUNTIME_REGISTRY = None if document is None else validate_registry(document)


def load_registry(path: Path | None = None) -> dict[str, Any]:
    if path is None and _RUNTIME_REGISTRY is not None:
        return dict(_RUNTIME_REGISTRY)
    path = (path or default_registry_path()).resolve()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"capability registry is unreadable: {path}: {exc}") from exc
    registry = validate_registry(document)
    registry["path"] = path.as_posix()
    return registry


def capability_index(registry: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    registry = registry or load_registry()
    return {str(item["id"]): item for item in registry.get("capabilities") or []}


def alias_index(registry: dict[str, Any] | None = None) -> dict[str, str]:
    registry = registry or load_registry()
    result: dict[str, str] = {}
    for item in registry.get("capabilities") or []:
        canonical = str(item.get("id") or "")
        for value in [canonical, item.get("label"), *(item.get("aliases") or [])]:
            if str(value or "").strip():
                result[str(value).strip().casefold()] = canonical
    return result


def normalize_capability_id(value: str, registry: dict[str, Any] | None = None) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    registry = registry or load_registry()
    return alias_index(registry).get(value.casefold(), "")


def describe_capability(value: str, registry: dict[str, Any] | None = None) -> dict[str, Any] | None:
    registry = registry or load_registry()
    canonical = normalize_capability_id(value, registry)
    if not canonical:
        return None
    return capability_index(registry).get(canonical)


def legacy_capability_ids(values: list[Any], permission_candidates: list[dict[str, Any]] | None = None,
                          automation_capabilities: list[dict[str, Any]] | None = None,
                          registry: dict[str, Any] | None = None) -> list[str]:
    """Normalize today's label/permission/automation outputs to stable registry IDs."""
    registry = registry or load_registry()
    result: set[str] = set()
    for value in values or []:
        if isinstance(value, dict):
            candidates = [value.get("capabilityId"), value.get("capability_id"), value.get("label")]
        else:
            candidates = [value]
        for candidate in candidates:
            canonical = normalize_capability_id(str(candidate or ""), registry)
            if canonical:
                result.add(canonical)
                break
    for row in permission_candidates or []:
        canonical = normalize_capability_id(str(row.get("permissionId") or row.get("permission_id") or ""), registry)
        if canonical:
            result.add(canonical)
    for row in automation_capabilities or []:
        canonical = normalize_capability_id(str(row.get("capabilityId") or row.get("capability_id") or ""), registry)
        if canonical:
            result.add(canonical)
    return sorted(result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate or inspect the SigmaScope capability registry")
    parser.add_argument("command", nargs="?", choices=["validate", "list"], default="validate")
    parser.add_argument("--registry", type=Path, default=default_registry_path())
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        registry = load_registry(args.registry)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    if args.command == "list":
        payload = registry
    else:
        payload = {
            "schema": registry["schema"],
            "version": registry["version"],
            "revision": registry["revision"],
            "capabilityCount": len(registry.get("capabilities") or []),
            "categoryCount": len(registry.get("categories") or []),
        }
    if args.json or args.command == "list":
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"Capability registry OK: {payload['capabilityCount']} capabilities, {payload['categoryCount']} categories, {payload['revision']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
