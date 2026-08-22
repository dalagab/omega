"""Build bounded dependency/component summaries for SigmaScope evidence transport.

Detailed dependency rows remain authoritative and are preserved in the normalized
Evidence-v2 datasets. This helper derives a concise, deterministic summary suitable for
variant reports and Omega presentation without flattening plugin dependencies, NuGet
packages, managed assemblies, native components and IPC relationships into one bucket.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "omega.sigmascope.component-summary.v1"
MAX_COMPONENT_ITEMS = 48
MAX_RELATIONSHIPS = 48

WINDOWS_PLATFORM_NATIVE = {
    "advapi32", "bcrypt", "combase", "comctl32", "crypt32", "d3d11", "d3d12", "dbghelp",
    "gdi32", "imm32", "iphlpapi", "kernel32", "kernelbase", "msvcrt", "ntdll", "ole32", "oleaut32",
    "psapi", "rpcrt4", "secur32", "setupapi", "shell32", "shlwapi", "user32", "userenv", "version",
    "winhttp", "wininet", "winmm", "ws2_32", "wtsapi32",
}


def _normalize_native(name: str) -> str:
    value = Path((name or "").replace("\\", "/")).name.casefold().strip()
    for suffix in (".dll", ".so", ".dylib"):
        if value.endswith(suffix):
            value = value[:-len(suffix)]
    # ELF sonames such as libssl.so.3 become libssl after Path suffix handling above.
    value = re.sub(r"\.so(?:\.[0-9]+)*$", "", value)
    return value


def _family(kind: str) -> str:
    if kind in {"external-plugin"}:
        return "plugin"
    if kind == "ipc":
        return "ipc"
    if kind in {"nuget", "nuget-lock", "nuget-resolved"}:
        return "nuget"
    if kind in {"assembly-reference", "managed-assembly", "managed-assembly-reference", "managed-executable"}:
        return "managed-assembly"
    if kind in {"native-import", "native-library"}:
        return "native"
    if kind == "project-reference":
        return "project"
    if kind == "executable":
        return "executable"
    return "other"


def _canonical_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_component_summary(intel: dict) -> dict:
    dependencies = [item for item in (intel.get("dependencies") or []) if isinstance(item, dict)]
    native_imports = [item for item in (intel.get("nativeImports") or []) if isinstance(item, dict)]
    managed_calls = [item for item in (intel.get("managedCallSites") or []) if isinstance(item, dict)]
    direct_native_calls: dict[tuple[str, str, str], int] = {}
    for call in managed_calls:
        library = _normalize_native(str(call.get("targetNativeLibrary") or ""))
        entry = str(call.get("targetNativeEntryPoint") or "").casefold()
        path = str(call.get("path") or "").casefold()
        if library:
            key = (path, library, entry)
            direct_native_calls[key] = direct_native_calls.get(key, 0) + 1
    by_family: dict[str, int] = {}
    by_requirement: dict[str, int] = {}
    by_status: dict[str, int] = {}
    exact_versioned = 0
    unresolved_versioned = 0
    nuget: list[dict] = []
    relationships: list[dict] = []
    bundled_native: dict[str, dict] = {}

    for item in dependencies:
        kind = str(item.get("kind") or "")
        family = _family(kind)
        by_family[family] = by_family.get(family, 0) + 1
        requirement = str(item.get("requirement") or "observed")
        by_requirement[requirement] = by_requirement.get(requirement, 0) + 1
        status = str(item.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        version = str(item.get("resolvedVersion") or item.get("version") or "").strip()
        if version:
            exact_versioned += 1
        elif family in {"nuget", "managed-assembly", "plugin"}:
            unresolved_versioned += 1
        if family == "nuget" and len(nuget) < MAX_COMPONENT_ITEMS:
            nuget.append({
                "name": str(item.get("name") or ""),
                "version": version,
                "versionRequirement": str(item.get("versionRequirement") or ""),
                "requirement": requirement,
                "origin": str(item.get("origin") or ""),
            })
        if kind == "native-library":
            normalized = _normalize_native(str(item.get("name") or ""))
            if normalized:
                bundled_native.setdefault(normalized, {
                    "name": str(item.get("name") or ""), "path": str(item.get("path") or ""),
                    "origin": str(item.get("origin") or ""),
                })
        if kind in {"external-plugin", "ipc"} and len(relationships) < MAX_RELATIONSHIPS:
            relationships.append({
                "kind": family,
                "name": str(item.get("name") or ""),
                "requirement": requirement,
                "relationship": str(item.get("relationship") or ""),
                "confidence": str(item.get("relationshipConfidence") or ""),
                "versionRequirement": str(item.get("versionRequirement") or item.get("version") or ""),
                "origin": str(item.get("origin") or ""),
            })

    native_relationships: list[dict] = []
    seen_native: set[tuple[str, str, str]] = set()
    platform_imports = bundled_matches = unresolved_imports = 0
    for item in native_imports:
        library = str(item.get("library") or "").strip()
        normalized = _normalize_native(library)
        if not normalized:
            continue
        consumer = str(item.get("path") or "")
        entry_point = str(item.get("entryPoint") or "")
        key = (consumer.casefold(), normalized, entry_point.casefold())
        if key in seen_native:
            continue
        seen_native.add(key)
        target = bundled_native.get(normalized)
        if target is not None:
            disposition = "bundled-component"
            confidence = "VeryHigh"
            bundled_matches += 1
        elif normalized in WINDOWS_PLATFORM_NATIVE or normalized.startswith(("api-ms-win-", "ext-ms-win-")):
            disposition = "platform-library"
            confidence = "VeryHigh"
            platform_imports += 1
        else:
            disposition = "external-or-runtime-resolved"
            confidence = "Medium"
            unresolved_imports += 1
        direct_call_count = direct_native_calls.get((consumer.casefold(), normalized, entry_point.casefold()), 0)
        if direct_call_count:
            confidence = "VeryHigh"
        if len(native_relationships) < MAX_RELATIONSHIPS:
            native_relationships.append({
                "consumerPath": consumer,
                "library": library,
                "entryPoint": entry_point,
                "managedName": str(item.get("managedName") or ""),
                "disposition": disposition,
                "confidence": confidence,
                "targetPath": str((target or {}).get("path") or ""),
                "directManagedCallObserved": bool(direct_call_count),
                "directManagedCallCount": direct_call_count,
            })

    # Deterministic ordering makes the summary suitable for cache/evidence fingerprints.
    nuget.sort(key=lambda x: (x["name"].casefold(), x["version"], x["origin"]))
    relationships.sort(key=lambda x: (x["kind"], x["name"].casefold(), x["origin"]))
    native_relationships.sort(key=lambda x: (x["library"].casefold(), x["consumerPath"].casefold(), x["entryPoint"].casefold()))
    fingerprint_source = {
        "families": by_family, "requirements": by_requirement, "statuses": by_status,
        "nuget": nuget, "relationships": relationships, "nativeRelationships": native_relationships,
    }
    return {
        "schema": SCHEMA,
        "dependencyCount": len(dependencies),
        "families": {key: by_family[key] for key in sorted(by_family)},
        "requirements": {key: by_requirement[key] for key in sorted(by_requirement)},
        "statuses": {key: by_status[key] for key in sorted(by_status)},
        "exactVersionObservedCount": exact_versioned,
        "versionUnknownCount": unresolved_versioned,
        "nugetComponents": nuget,
        "pluginRelationships": relationships,
        "nativeRelationships": native_relationships,
        "nativeRelationshipCounts": {
            "bundledComponent": bundled_matches,
            "platformLibrary": platform_imports,
            "externalOrRuntimeResolved": unresolved_imports,
        },
        "fingerprint": _canonical_hash(fingerprint_source),
    }
