#!/usr/bin/env python3
"""Validate SigmaScope's external analyzer research-source registry.

The registry records public projects that may inform native detector development. It
never imports third-party rules, executes analyzers, assigns findings, or changes SRL
semantics. Restrictive licenses are represented explicitly and fail closed when a
registry edit attempts to enable automated inspection, AI ingestion, runtime import,
or implementation copying.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA = "omega.sigmascope.external-analysis-sources.v1"
SEMANTICS = "research-input-only"
SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$")
LICENSE_CLASSES = {
    "permissive",
    "weak-copyleft",
    "source-available-restricted",
    "restricted-rules",
}
COPY_POLICIES = {"permitted-with-attribution", "review-required", "blocked"}
DERIVATION_MODES = {"independent-reimplementation", "architecture-reference", "metadata-only"}
RESTRICTED_LICENSE_CLASSES = {"source-available-restricted", "restricted-rules"}
MAX_SOURCES = 64
MAX_LIST_ITEMS = 32
MAX_TEXT = 2048


def default_registry_path() -> Path:
    return Path(__file__).resolve().parents[2] / "security-definitions" / "external-analysis" / "registry.json"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _text(value: Any, field: str, *, maximum: int = MAX_TEXT, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    text = value.strip()
    if required and not text:
        raise ValueError(f"{field} is required")
    if len(text) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return text


def _string_list(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    if not allow_empty and not value:
        raise ValueError(f"{field} must not be empty")
    if len(value) > MAX_LIST_ITEMS:
        raise ValueError(f"{field} exceeds {MAX_LIST_ITEMS} entries")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        text = _text(item, f"{field}[{index}]", maximum=240, required=True)
        folded = text.casefold()
        if folded in seen:
            raise ValueError(f"{field} contains duplicate value: {text}")
        seen.add(folded)
        result.append(text)
    return sorted(result, key=str.casefold)


def _github_repository(value: Any, field: str) -> str:
    text = _text(value, field, maximum=512, required=True)
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password:
        raise ValueError(f"{field} must be a public https://github.com/owner/repository URL")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{field} may not contain query or fragment data")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2 or parts[1].endswith(".git"):
        raise ValueError(f"{field} must identify exactly one GitHub repository")
    return f"https://github.com/{parts[0]}/{parts[1]}"


def _https_url(value: Any, field: str) -> str:
    text = _text(value, field, maximum=1024, required=True)
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{field} must be a public HTTPS URL")
    return text


def _focus_paths(value: Any, field: str) -> list[str]:
    paths = _string_list(value, field)
    for path in paths:
        pure = path.replace("\\", "/")
        if pure.startswith("/") or ".." in pure.split("/"):
            raise ValueError(f"{field} contains an unsafe repository path: {path}")
    return paths


def validate_registry(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ValueError("external analysis source registry must be a JSON object")
    unknown_root = set(document) - {"schema", "version", "semantics", "sources"}
    if unknown_root:
        raise ValueError(f"registry has unsupported fields: {', '.join(sorted(unknown_root))}")
    if document.get("schema") != SCHEMA:
        raise ValueError(f"unsupported external analysis source schema: {document.get('schema')!r}")
    try:
        version = int(document.get("version") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("external analysis source registry version must be an integer") from exc
    if version != 1:
        raise ValueError(f"unsupported external analysis source registry version: {version}")
    if document.get("semantics") != SEMANTICS:
        raise ValueError(f"external analysis source semantics must be {SEMANTICS!r}")

    raw_sources = document.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ValueError("external analysis source registry requires a non-empty sources list")
    if len(raw_sources) > MAX_SOURCES:
        raise ValueError(f"external analysis source registry exceeds {MAX_SOURCES} sources")

    normalized_sources: list[dict[str, Any]] = []
    ids: set[str] = set()
    repositories: set[str] = set()
    for index, raw in enumerate(raw_sources):
        if not isinstance(raw, dict):
            raise ValueError(f"sources[{index}] must be an object")
        unknown = set(raw) - {
            "id", "name", "repository", "defaultRef", "focusPaths", "languages",
            "analysisKinds", "license", "usage",
        }
        if unknown:
            raise ValueError(f"sources[{index}] has unsupported fields: {', '.join(sorted(unknown))}")
        source_id = _text(raw.get("id"), f"sources[{index}].id", maximum=128, required=True)
        if not SOURCE_ID_RE.fullmatch(source_id):
            raise ValueError(f"invalid external analysis source id: {source_id}")
        if source_id in ids:
            raise ValueError(f"duplicate external analysis source id: {source_id}")
        ids.add(source_id)

        repository = _github_repository(raw.get("repository"), f"sources[{index}].repository")
        if repository.casefold() in repositories:
            raise ValueError(f"duplicate external analysis repository: {repository}")
        repositories.add(repository.casefold())
        name = _text(raw.get("name"), f"sources[{index}].name", maximum=200, required=True)
        default_ref = _text(raw.get("defaultRef"), f"sources[{index}].defaultRef", maximum=160, required=True)
        focus_paths = _focus_paths(raw.get("focusPaths"), f"sources[{index}].focusPaths")
        languages = _string_list(raw.get("languages"), f"sources[{index}].languages", allow_empty=False)
        analysis_kinds = _string_list(raw.get("analysisKinds"), f"sources[{index}].analysisKinds", allow_empty=False)

        raw_license = raw.get("license")
        if not isinstance(raw_license, dict):
            raise ValueError(f"sources[{index}].license must be an object")
        unknown_license = set(raw_license) - {"name", "spdx", "classification", "source"}
        if unknown_license:
            raise ValueError(f"sources[{index}].license has unsupported fields: {', '.join(sorted(unknown_license))}")
        license_class = _text(raw_license.get("classification"), f"sources[{index}].license.classification", maximum=64, required=True)
        if license_class not in LICENSE_CLASSES:
            raise ValueError(f"unsupported license classification for {source_id}: {license_class}")
        license_data = {
            "name": _text(raw_license.get("name"), f"sources[{index}].license.name", maximum=200, required=True),
            "spdx": _text(raw_license.get("spdx"), f"sources[{index}].license.spdx", maximum=160, required=True),
            "classification": license_class,
            "source": _https_url(raw_license.get("source"), f"sources[{index}].license.source"),
        }

        raw_usage = raw.get("usage")
        if not isinstance(raw_usage, dict):
            raise ValueError(f"sources[{index}].usage must be an object")
        unknown_usage = set(raw_usage) - {
            "automatedInspection", "aiIngestion", "copyImplementation", "runtimeImport",
            "derivationMode", "notes",
        }
        if unknown_usage:
            raise ValueError(f"sources[{index}].usage has unsupported fields: {', '.join(sorted(unknown_usage))}")
        if not isinstance(raw_usage.get("automatedInspection"), bool):
            raise ValueError(f"sources[{index}].usage.automatedInspection must be boolean")
        if not isinstance(raw_usage.get("aiIngestion"), bool):
            raise ValueError(f"sources[{index}].usage.aiIngestion must be boolean")
        if not isinstance(raw_usage.get("runtimeImport"), bool):
            raise ValueError(f"sources[{index}].usage.runtimeImport must be boolean")
        copy_policy = _text(raw_usage.get("copyImplementation"), f"sources[{index}].usage.copyImplementation", maximum=64, required=True)
        if copy_policy not in COPY_POLICIES:
            raise ValueError(f"unsupported copy policy for {source_id}: {copy_policy}")
        derivation_mode = _text(raw_usage.get("derivationMode"), f"sources[{index}].usage.derivationMode", maximum=64, required=True)
        if derivation_mode not in DERIVATION_MODES:
            raise ValueError(f"unsupported derivation mode for {source_id}: {derivation_mode}")
        usage = {
            "automatedInspection": bool(raw_usage["automatedInspection"]),
            "aiIngestion": bool(raw_usage["aiIngestion"]),
            "copyImplementation": copy_policy,
            "runtimeImport": bool(raw_usage["runtimeImport"]),
            "derivationMode": derivation_mode,
            "notes": _text(raw_usage.get("notes"), f"sources[{index}].usage.notes", maximum=1600, required=True),
        }

        if usage["runtimeImport"]:
            raise ValueError(f"{source_id} may not be a runtime import; external sources are research-only")
        if usage["aiIngestion"] and not usage["automatedInspection"]:
            raise ValueError(f"{source_id} cannot enable AI ingestion while automated inspection is disabled")
        if license_class in RESTRICTED_LICENSE_CLASSES:
            if usage["automatedInspection"] or usage["aiIngestion"]:
                raise ValueError(f"restricted source {source_id} must remain metadata-only and may not be automatically ingested")
            if copy_policy != "blocked" or derivation_mode != "metadata-only":
                raise ValueError(f"restricted source {source_id} must block implementation copying and use metadata-only derivation")
        if license_class == "weak-copyleft" and copy_policy == "permitted-with-attribution":
            raise ValueError(f"weak-copyleft source {source_id} requires explicit review before implementation copying")

        normalized_sources.append({
            "id": source_id,
            "name": name,
            "repository": repository,
            "defaultRef": default_ref,
            "focusPaths": focus_paths,
            "languages": languages,
            "analysisKinds": analysis_kinds,
            "license": license_data,
            "usage": usage,
        })

    normalized = {
        "schema": SCHEMA,
        "version": version,
        "semantics": SEMANTICS,
        "sources": sorted(normalized_sources, key=lambda item: item["id"]),
    }
    normalized["revision"] = f"external-analysis-sources-v1-{hashlib.sha256(canonical_bytes(normalized)).hexdigest()[:16]}"
    return normalized


def load_registry(path: Path | None = None) -> dict[str, Any]:
    path = (path or default_registry_path()).resolve()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"external analysis source registry is unreadable: {path}: {exc}") from exc
    registry = validate_registry(document)
    registry["path"] = path.as_posix()
    return registry


def automated_research_sources(registry: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    registry = registry or load_registry()
    return [
        source for source in registry.get("sources") or []
        if bool((source.get("usage") or {}).get("automatedInspection"))
        and bool((source.get("usage") or {}).get("aiIngestion"))
    ]



def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def external_analysis_revision(document: dict[str, Any]) -> str:
    semantic = {
        "schema": str(document.get("schema") or ""),
        "registryRevision": str(document.get("registryRevision") or ""),
        "semantics": str(document.get("semantics") or ""),
        "sources": [
            {
                "id": str(source.get("id") or ""),
                "repository": str(source.get("repository") or ""),
                "defaultRef": str(source.get("defaultRef") or ""),
                "inspectionPolicy": str(source.get("inspectionPolicy") or ""),
                "observedRevision": str(source.get("observedRevision") or ""),
                "status": str(source.get("status") or ""),
            }
            for source in document.get("sources") or []
            if isinstance(source, dict)
        ],
    }
    return f"external-analysis-v1-{hashlib.sha256(canonical_bytes(semantic)).hexdigest()[:16]}"


def _default_ref_resolver(repository: str, ref: str, timeout: float) -> str:
    completed = subprocess.run(
        ["git", "ls-remote", repository, f"refs/heads/{ref}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "git ls-remote failed").strip())
    line = (completed.stdout or "").splitlines()[0] if (completed.stdout or "").splitlines() else ""
    sha = line.split("\t", 1)[0].strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError(f"no branch head found for {repository}@{ref}")
    return sha


def build_observation(
    registry: dict[str, Any] | None = None,
    *,
    ref_resolver: Callable[[str, str, float], str] | None = None,
    timeout: float = 12.0,
    observed_at_utc: str | None = None,
) -> dict[str, Any]:
    registry = registry or load_registry()
    ref_resolver = ref_resolver or _default_ref_resolver
    rows: list[dict[str, Any]] = []
    for source in registry.get("sources") or []:
        usage = source.get("usage") or {}
        automated = bool(usage.get("automatedInspection")) and bool(usage.get("aiIngestion"))
        row = {
            "id": source["id"],
            "name": source["name"],
            "repository": source["repository"],
            "defaultRef": source["defaultRef"],
            "licenseClass": (source.get("license") or {}).get("classification") or "",
            "derivationMode": usage.get("derivationMode") or "",
            "inspectionPolicy": "head-observed" if automated else "metadata-only",
            "status": "metadata-only",
            "observedRevision": "",
            "error": "",
        }
        if automated:
            try:
                row["observedRevision"] = ref_resolver(source["repository"], source["defaultRef"], timeout)
                row["status"] = "observed"
            except Exception as exc:
                row["status"] = "observe-failed"
                row["error"] = f"{type(exc).__name__}: {exc}"
        rows.append(row)
    document = {
        "schema": "omega.sigmascope.external-analysis-source-observations.v1",
        "semantics": SEMANTICS,
        "observedAtUtc": observed_at_utc or _utc_now(),
        "registryRevision": registry["revision"],
        "counts": {
            "sources": len(rows),
            "headObserved": sum(1 for row in rows if row["status"] == "observed"),
            "metadataOnly": sum(1 for row in rows if row["inspectionPolicy"] == "metadata-only"),
            "observeFailed": sum(1 for row in rows if row["status"] == "observe-failed"),
        },
        "sources": sorted(rows, key=lambda row: row["id"]),
    }
    document["externalAnalysisRevision"] = external_analysis_revision(document)
    return document

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate or inspect SigmaScope external analysis research sources")
    parser.add_argument("command", nargs="?", choices=["validate", "list", "automated", "observe"], default="validate")
    parser.add_argument("--registry", type=Path, default=default_registry_path())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args(argv)
    try:
        registry = load_registry(args.registry)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    if args.command == "list":
        payload: Any = registry
    elif args.command == "automated":
        payload = {
            "schema": SCHEMA,
            "revision": registry["revision"],
            "sources": automated_research_sources(registry),
        }
    elif args.command == "observe":
        payload = build_observation(registry, timeout=args.timeout)
    else:
        payload = {
            "schema": SCHEMA,
            "ok": True,
            "revision": registry["revision"],
            "sourceCount": len(registry["sources"]),
            "automatedSourceCount": len(automated_research_sources(registry)),
            "restrictedSourceCount": sum(
                1 for source in registry["sources"]
                if str((source.get("license") or {}).get("classification") or "") in RESTRICTED_LICENSE_CLASSES
            ),
        }
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
