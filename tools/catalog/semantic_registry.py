"""Definitions-backed semantic service/API registry helpers.

The registry contributes labels and primitive semantic identities only. It never emits
security findings or high-level behavior conclusions; Stigma-1/SRL owns that logic.
"""
from __future__ import annotations

import functools
import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SERVICE_REGISTRY = ROOT / "security-definitions" / "services" / "registry.json"
API_REGISTRY = ROOT / "security-definitions" / "semantic-apis" / "registry.json"

SERVICE_SCHEMA = "omega.service-registry.v1"
API_SCHEMA = "omega.semantic-api-registry.v1"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}$", re.I)
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", re.I)


def _load(path: Path, schema: str, revision_prefix: str) -> dict[str, Any]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != schema:
        raise ValueError(f"{path}: expected {schema}")
    if int(doc.get("version") or 0) != 1:
        raise ValueError(f"{path}: unsupported registry version")
    semantic = dict(doc)
    semantic.pop("revision", None)
    digest = hashlib.sha256(json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()[:16]
    doc["revision"] = f"{revision_prefix}-{digest}"
    return doc


def load_service_registry(path: Path | None = None) -> dict[str, Any]:
    doc = _load((path or SERVICE_REGISTRY).resolve(), SERVICE_SCHEMA, "services-v1")
    seen_ids: set[str] = set()
    seen_hosts: set[str] = set()
    for index, item in enumerate(doc.get("services") or []):
        if not isinstance(item, dict):
            raise ValueError(f"services[{index}] must be an object")
        service_id = str(item.get("id") or "")
        if not _ID_RE.fullmatch(service_id):
            raise ValueError("invalid service registry entry")
        if service_id in seen_ids:
            raise ValueError(f"duplicate service id: {service_id}")
        seen_ids.add(service_id)
        hosts = item.get("hosts") or []
        if not isinstance(hosts, list) or not hosts:
            raise ValueError(f"service {service_id} must declare at least one host")
        for host in hosts:
            normalized = str(host).casefold().strip(".")
            if not _HOST_RE.fullmatch(normalized):
                raise ValueError(f"invalid registered service host: {host}")
            if normalized in seen_hosts:
                raise ValueError(f"duplicate registered service host: {host}")
            seen_hosts.add(normalized)
        for field in ("categories", "capabilities"):
            values = item.get(field) or []
            if not isinstance(values, list) or any(not _ID_RE.fullmatch(str(value or "")) for value in values):
                raise ValueError(f"service {service_id} has invalid {field}")
        for field in ("name", "purpose", "recognition"):
            if not isinstance(item.get(field), str) or not str(item.get(field) or "").strip():
                raise ValueError(f"service {service_id} requires {field}")
    return doc


@functools.lru_cache(maxsize=1)
def service_registry() -> dict[str, Any]:
    return load_service_registry(SERVICE_REGISTRY)


def load_api_registry(path: Path | None = None) -> dict[str, Any]:
    doc = _load((path or API_REGISTRY).resolve(), API_SCHEMA, "semantic-apis-v1")
    seen_ids: set[str] = set()
    for group, receiver_field in (("sourceMatchers", "receiverContains"), ("compiledMatchers", "typeContains")):
        rows = doc.get(group) or []
        if not isinstance(rows, list):
            raise ValueError(f"{group} must be a list")
        for index, item in enumerate(rows):
            if not isinstance(item, dict):
                raise ValueError(f"{group}[{index}] must be an object")
            matcher_id = str(item.get("id") or "")
            if not _ID_RE.fullmatch(matcher_id):
                raise ValueError(f"invalid semantic API matcher in {group}")
            if matcher_id in seen_ids:
                raise ValueError(f"duplicate semantic API matcher id: {matcher_id}")
            seen_ids.add(matcher_id)
            if not _ID_RE.fullmatch(str(item.get("operation") or "")):
                raise ValueError(f"invalid primitive operation in {group}")
            members = item.get("members") or []
            if not isinstance(members, list) or not members or any(not str(value or "").strip() for value in members):
                raise ValueError(f"semantic API matcher {matcher_id} requires members")
            receiver_values = item.get(receiver_field) or []
            if not isinstance(receiver_values, list) or any(not str(value or "").strip() for value in receiver_values):
                raise ValueError(f"semantic API matcher {matcher_id} has invalid {receiver_field}")
            attributes = item.get("attributes") or {}
            if not isinstance(attributes, dict):
                raise ValueError(f"semantic API matcher {matcher_id} has invalid attributes")
            traffic_direction = str(attributes.get("trafficDirection") or "")
            if traffic_direction and traffic_direction not in {"inbound", "outbound", "bidirectional", "unknown"}:
                raise ValueError(f"semantic API matcher {matcher_id} has invalid trafficDirection")
    return doc


@functools.lru_cache(maxsize=1)
def api_registry() -> dict[str, Any]:
    return load_api_registry(API_REGISTRY)


@functools.lru_cache(maxsize=1)
def _service_host_index() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in service_registry().get("services") or []:
        for host in item.get("hosts") or []:
            result[str(host).casefold().strip(".")] = item
    return result


@functools.lru_cache(maxsize=1)
def _source_member_index() -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for item in api_registry().get("sourceMatchers") or []:
        for member in item.get("members") or []:
            result.setdefault(str(member).casefold(), []).append(item)
    return result


@functools.lru_cache(maxsize=1)
def _compiled_member_index() -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for item in api_registry().get("compiledMatchers") or []:
        for member in item.get("members") or []:
            result.setdefault(str(member).casefold(), []).append(item)
    return result


def service_for_host(host: str) -> dict[str, Any]:
    normalized = str(host or "").casefold().strip(".")
    item = _service_host_index().get(normalized)
    if item is not None:
        return {
            "serviceId": str(item["id"]),
            "serviceRegistryRevision": str(service_registry().get("revision") or ""),
            "serviceName": str(item.get("name") or item["id"]),
            "serviceCategories": [str(v) for v in item.get("categories") or []][:32],
            "serviceCapabilities": [str(v) for v in item.get("capabilities") or []][:64],
            "servicePurpose": str(item.get("purpose") or ""),
            "serviceRecognition": str(item.get("recognition") or "registered"),
        }
    return {
        "serviceId": f"host:{normalized}" if normalized else "host:unknown",
        "serviceRegistryRevision": str(service_registry().get("revision") or ""),
        "serviceName": normalized or "unknown",
        "serviceCategories": [],
        "serviceCapabilities": [],
        "servicePurpose": "unclassified public service",
        "serviceRecognition": "unknown",
    }


def service_for_url(value: str) -> dict[str, Any]:
    try:
        host = urllib.parse.urlsplit(str(value or "")).hostname or ""
    except ValueError:
        host = ""
    return service_for_host(host)


def match_source_call(receiver: str, member: str) -> dict[str, Any] | None:
    receiver_cf = str(receiver or "").casefold()
    member_cf = str(member or "").casefold()
    for item in _source_member_index().get(member_cf, []):
        needles = [str(v).casefold() for v in item.get("receiverContains") or []]
        if needles and not any(needle in receiver_cf for needle in needles):
            continue
        return {
            "matcherId": str(item["id"]),
            "operation": str(item["operation"]),
            "semanticApiRegistryRevision": str(api_registry().get("revision") or ""),
            "attributes": dict(item.get("attributes") or {}),
        }
    return None


def match_compiled_call(declaring_type: str, member: str) -> dict[str, Any] | None:
    type_cf = str(declaring_type or "").casefold()
    member_cf = str(member or "").casefold()
    for item in _compiled_member_index().get(member_cf, []):
        needles = [str(v).casefold() for v in item.get("typeContains") or []]
        if needles and not any(needle in type_cf for needle in needles):
            continue
        return {
            "matcherId": str(item["id"]),
            "operation": str(item["operation"]),
            "semanticApiRegistryRevision": str(api_registry().get("revision") or ""),
            "attributes": dict(item.get("attributes") or {}),
        }
    return None
