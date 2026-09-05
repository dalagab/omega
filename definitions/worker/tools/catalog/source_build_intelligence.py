#!/usr/bin/env python3
"""Bounded source-build and release-context observations for SigmaScope.

This module inspects only already-selected public source-tree text blobs. It never executes
build tools, project scripts, workflows, or plugin code. The resulting rows are developer-
authored source context and immutable file identities; they are not proof that a distributed
artifact was produced by the observed projects or CI workflows. Rebuilder owns future
source-to-artifact build proof.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import xml.etree.ElementTree as ET
import urllib.parse
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

SCHEMA = "omega.sigmascope.source-build-intelligence.v1"
CONTRACT_VERSION = 1
MAX_PROJECTS = 256
MAX_EDGES = 1_024
MAX_INPUTS = 1_024
MAX_ENVIRONMENT = 128
MAX_DEPENDENCIES = 8_192
MAX_WORKFLOWS = 64
MAX_LIST_VALUES = 128
MAX_WORKFLOW_LINES = 4_000
MAX_TEXT_FIELD = 2_048


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _tag(element: ET.Element) -> str:
    return str(element.tag).rsplit("}", 1)[-1]


def _child_text(element: ET.Element, name: str) -> str:
    for child in element:
        if _tag(child) == name and child.text:
            return str(child.text).strip()
    return ""


def _values(value: str) -> list[str]:
    result: list[str] = []
    for item in re.split(r"[;,]", str(value or "")):
        item = item.strip()
        if item and item not in result:
            result.append(item[:256])
    return result[:64]


def _bool(value: str) -> bool | None:
    text = str(value or "").strip().casefold()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def _property_map(root: ET.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for group in root.iter():
        if _tag(group) != "PropertyGroup":
            continue
        for child in group:
            name = _tag(child)
            if not name or child.text is None:
                continue
            text = str(child.text).strip()
            if text and name not in values:
                values[name] = text[:MAX_TEXT_FIELD]
    return values


def _normalize_repo_path(base_dir: str, value: str) -> str:
    value = str(value or "").strip().replace("\\", "/")
    if not value:
        return ""
    value = value.replace("$(MSBuildProjectDirectory)", base_dir or ".")
    value = value.replace("$(MSBuildThisFileDirectory)", (base_dir.rstrip("/") + "/") if base_dir else "")
    if "$(" in value:
        return ""
    resolved = posixpath.normpath(posixpath.join(base_dir, value))
    if resolved in {"", ".", ".."} or resolved.startswith("../"):
        return ""
    return resolved.lstrip("./")


def _dedupe_append(rows: list[dict[str, Any]], row: dict[str, Any], keys: tuple[str, ...], limit: int, dropped: dict[str, int], label: str) -> None:
    identity = tuple(str(row.get(key) or "").casefold() for key in keys)
    for existing in rows:
        if tuple(str(existing.get(key) or "").casefold() for key in keys) == identity:
            return
    if len(rows) >= limit:
        dropped[label] = int(dropped.get(label, 0)) + 1
        return
    rows.append(row)


def _project_row(path: str, text: str, role: str) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    props = _property_map(root)
    sdk = str(root.attrib.get("Sdk") or "").strip()
    if not sdk:
        for element in root.iter():
            if _tag(element) == "Sdk":
                sdk = str(element.attrib.get("Name") or element.text or "").strip()
                if sdk:
                    break
    row: dict[str, Any] = {
        "origin": "source",
        "path": path,
        "role": role,
        "sdk": sdk[:512],
        "targetFrameworks": _values(props.get("TargetFrameworks") or props.get("TargetFramework") or ""),
        "runtimeIdentifiers": _values(props.get("RuntimeIdentifiers") or props.get("RuntimeIdentifier") or ""),
        "outputType": str(props.get("OutputType") or "")[:128],
        "assemblyName": str(props.get("AssemblyName") or "")[:256],
        "projectVersion": str(props.get("Version") or "")[:128],
        "rootNamespace": str(props.get("RootNamespace") or "")[:256],
        "langVersion": str(props.get("LangVersion") or "")[:128],
        "nullable": str(props.get("Nullable") or "")[:128],
        "packageReferenceCount": sum(1 for element in root.iter() if _tag(element) == "PackageReference"),
        "projectReferenceCount": sum(1 for element in root.iter() if _tag(element) == "ProjectReference"),
        "importCount": sum(1 for element in root.iter() if _tag(element) == "Import"),
        "conditionalItemCount": sum(1 for element in root.iter() if str(element.attrib.get("Condition") or "").strip()),
    }
    for prop, key in (
        ("AllowUnsafeBlocks", "allowUnsafeBlocks"),
        ("PublishAot", "publishAot"),
        ("SelfContained", "selfContained"),
        ("PublishTrimmed", "publishTrimmed"),
        ("PublishReadyToRun", "publishReadyToRun"),
        ("UseWPF", "useWpf"),
        ("UseWindowsForms", "useWindowsForms"),
    ):
        parsed = _bool(props.get(prop) or "")
        if parsed is not None:
            row[key] = parsed
    return row


def _dependency_xml_rows(path: str, text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    project_path = path if path.casefold().endswith(".csproj") else ""
    rows: list[dict[str, Any]] = []
    kinds = {
        "PackageReference": "nuget",
        "PackageVersion": "nuget-central-version",
        "PackageDownload": "nuget-download",
        "FrameworkReference": "framework-reference",
        "ProjectReference": "project-reference",
        "Reference": "assembly-reference",
    }
    for element in root.iter():
        tag = _tag(element)
        if tag not in kinds:
            continue
        attrs = {str(k).rsplit("}", 1)[-1]: str(v) for k, v in element.attrib.items()}
        name = str(attrs.get("Include") or attrs.get("Update") or "").strip()
        if not name:
            continue
        rows.append({
            "origin": "source",
            "sourceKind": "msbuild",
            "path": path,
            "projectPath": project_path,
            "kind": kinds[tag],
            "name": name[:512],
            "versionExpression": str(attrs.get("Version") or _child_text(element, "Version") or "")[:512],
            "condition": str(attrs.get("Condition") or "")[:1024],
            "privateAssets": str(attrs.get("PrivateAssets") or _child_text(element, "PrivateAssets") or "")[:512],
            "includeAssets": str(attrs.get("IncludeAssets") or _child_text(element, "IncludeAssets") or "")[:1024],
            "excludeAssets": str(attrs.get("ExcludeAssets") or _child_text(element, "ExcludeAssets") or "")[:1024],
            "aliases": str(attrs.get("Aliases") or _child_text(element, "Aliases") or "")[:512],
            "direct": tag in {"PackageReference", "PackageDownload", "FrameworkReference", "ProjectReference", "Reference"},
            "transitive": False,
        })
    return rows


def _dependency_json_rows(path: str, text: str) -> list[dict[str, Any]]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []
    name = PurePosixPath(path).name.casefold()
    rows: list[dict[str, Any]] = []
    if name == "packages.lock.json" and isinstance(doc, dict):
        dependencies = doc.get("dependencies") if isinstance(doc.get("dependencies"), dict) else {}
        for framework, packages in dependencies.items():
            if not isinstance(packages, dict):
                continue
            for package, payload in packages.items():
                if not isinstance(payload, dict):
                    continue
                dep_type = str(payload.get("type") or "").strip().casefold()
                rows.append({
                    "origin": "source", "sourceKind": "packages-lock", "path": path, "projectPath": "",
                    "targetFramework": str(framework)[:256], "kind": "nuget-lock", "name": str(package)[:512],
                    "versionExpression": str(payload.get("requested") or "")[:512],
                    "resolvedVersion": str(payload.get("resolved") or "")[:512],
                    "contentHash": str(payload.get("contentHash") or "")[:512],
                    "condition": "", "privateAssets": "", "includeAssets": "", "excludeAssets": "", "aliases": "",
                    "direct": dep_type == "direct", "transitive": dep_type == "transitive",
                })
    elif name == "project.assets.json" and isinstance(doc, dict):
        targets = doc.get("targets") if isinstance(doc.get("targets"), dict) else {}
        libraries = doc.get("libraries") if isinstance(doc.get("libraries"), dict) else {}
        for framework, packages in targets.items():
            if not isinstance(packages, dict):
                continue
            for package_key, target_payload in packages.items():
                package_key = str(package_key)
                if "/" not in package_key:
                    continue
                package, resolved = package_key.split("/", 1)
                lib_payload = libraries.get(package_key) if isinstance(libraries.get(package_key), dict) else {}
                package_type = str(lib_payload.get("type") or (target_payload.get("type") if isinstance(target_payload, dict) else "") or "package")
                rows.append({
                    "origin": "source", "sourceKind": "project-assets", "path": path, "projectPath": "",
                    "targetFramework": str(framework)[:256],
                    "kind": "project-reference" if package_type == "project" else "nuget-resolved",
                    "name": package[:512], "versionExpression": "", "resolvedVersion": resolved[:512],
                    "contentHash": str(lib_payload.get("sha512") or "")[:512],
                    "condition": "", "privateAssets": "", "includeAssets": "", "excludeAssets": "", "aliases": "",
                    "direct": False, "transitive": package_type != "project",
                })
    return rows


def _sanitize_package_source(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return value[:MAX_TEXT_FIELD]
    if not parsed.scheme or not parsed.hostname:
        return value[:MAX_TEXT_FIELD]
    host = parsed.hostname
    if parsed.port:
        host += f":{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path or "", "", ""))[:MAX_TEXT_FIELD]


def _environment_row(path: str, text: str) -> dict[str, Any] | None:
    name = PurePosixPath(path).name.casefold()
    if name == "global.json":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return None
        sdk = doc.get("sdk") if isinstance(doc, dict) and isinstance(doc.get("sdk"), dict) else {}
        row: dict[str, Any] = {
            "origin": "source", "path": path, "kind": "dotnet-sdk",
            "sdkVersion": str(sdk.get("version") or "")[:256],
            "rollForward": str(sdk.get("rollForward") or "")[:128],
            "packageSources": [],
        }
        if "allowPrerelease" in sdk:
            row["allowPrerelease"] = bool(sdk.get("allowPrerelease"))
        return row
    if name == "nuget.config":
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return None
        sources: list[str] = []
        for section in root.iter():
            if _tag(section).casefold() != "packagesources":
                continue
            for element in section:
                if _tag(element).casefold() != "add":
                    continue
                value = _sanitize_package_source(str(element.attrib.get("value") or ""))
                if value and value not in sources:
                    sources.append(value)
        return {"origin": "source", "path": path, "kind": "nuget-config", "sdkVersion": "", "rollForward": "", "packageSources": sources[:64]}
    if path.casefold().endswith((".props", ".targets", ".csproj")):
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return None
        props = _property_map(root)
        central = _bool(props.get("ManagePackageVersionsCentrally") or "")
        locked = _bool(props.get("RestoreLockedMode") or "")
        if central is None and locked is None:
            return None
        row = {"origin": "source", "path": path, "kind": "msbuild-policy", "sdkVersion": "", "rollForward": "", "packageSources": []}
        if central is not None:
            row["managePackageVersionsCentrally"] = central
        if locked is not None:
            row["restoreLockedMode"] = locked
        return row
    return None


def _workflow_scalar(value: str) -> str:
    return str(value or "").strip().strip('"\'')[:MAX_TEXT_FIELD]


def _release_workflow(path: str, text: str) -> dict[str, Any]:
    lines = text.splitlines()
    name = ""
    triggers: list[str] = []
    jobs: list[str] = []
    runners: list[str] = []
    actions: list[str] = []
    commands: list[str] = []
    in_jobs = False
    run_block_indent: int | None = None
    for raw in lines[:MAX_WORKFLOW_LINES]:
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))
        if not stripped or stripped.startswith("#"):
            continue
        if not name and indent == 0 and stripped.startswith("name:"):
            name = _workflow_scalar(stripped.split(":", 1)[1])
        if indent == 0 and stripped == "jobs:":
            in_jobs = True
            continue
        if indent == 0 and stripped.startswith("on:"):
            tail = stripped.split(":", 1)[1].strip()
            if tail and tail not in {"|", ">"}:
                triggers.extend(re.findall(r"[A-Za-z_][A-Za-z0-9_-]*", tail))
            continue
        if not in_jobs and indent <= 2:
            match = re.match(r"^(push|pull_request|pull_request_target|workflow_dispatch|workflow_call|release|schedule|repository_dispatch|merge_group):", stripped)
            if match and match.group(1) not in triggers:
                triggers.append(match.group(1))
        if in_jobs and indent == 2 and re.match(r"^[A-Za-z0-9_.-]+:\s*$", stripped):
            job = stripped[:-1]
            if job not in jobs:
                jobs.append(job[:256])
        if stripped.startswith("runs-on:"):
            value = _workflow_scalar(stripped.split(":", 1)[1])
            if value and value not in runners:
                runners.append(value[:512])
        if stripped.startswith("uses:") or " uses:" in stripped:
            value = _workflow_scalar(stripped.split("uses:", 1)[1])
            if value and value not in actions:
                actions.append(value[:1024])
        if run_block_indent is not None:
            if indent > run_block_indent:
                if stripped and len(commands) < MAX_LIST_VALUES:
                    commands.append(stripped[:MAX_TEXT_FIELD])
                continue
            run_block_indent = None
        if stripped.startswith("run:") or " run:" in stripped:
            value = stripped.split("run:", 1)[1].strip()
            if value in {"|", ">", "|-", ">-"}:
                run_block_indent = indent
            elif value and len(commands) < MAX_LIST_VALUES:
                commands.append(_workflow_scalar(value))
    dotnet_verbs: list[str] = []
    dotnet_targets: list[str] = []
    for command in commands:
        for match in re.finditer(r"(?:^|[;&|]\s*)dotnet\s+(restore|build|publish|pack|test)\b", command, re.IGNORECASE):
            verb = match.group(1).casefold()
            if verb not in dotnet_verbs:
                dotnet_verbs.append(verb)
        for match in re.finditer(r"(?:^|\s)([^\s\"']+\.(?:csproj|sln))(?:\s|$)", command, re.IGNORECASE):
            target = match.group(1).replace("\\", "/")[:1024]
            if "$(" not in target and target not in dotnet_targets:
                dotnet_targets.append(target)
    action_text = "\n".join(actions).casefold()
    command_text = "\n".join(commands).casefold()
    return {
        "origin": "source", "path": path, "name": name,
        "triggers": sorted(set(triggers), key=str.casefold)[:32],
        "jobs": jobs[:64], "runners": runners[:32], "actions": actions[:MAX_LIST_VALUES],
        "dotnetVerbs": dotnet_verbs, "dotnetTargets": dotnet_targets[:64],
        "uploadsArtifacts": "upload-artifact" in action_text,
        "downloadsArtifacts": "download-artifact" in action_text,
        "publishesRelease": any(token in action_text or token in command_text for token in ("action-gh-release", "release-action", "gh release", "create-release")),
        "truncated": len(lines) > MAX_WORKFLOW_LINES or len(actions) >= MAX_LIST_VALUES or len(commands) >= MAX_LIST_VALUES,
    }


def collect(
    source_entries: Mapping[str, int],
    descriptor_text: Mapping[str, str],
    scope: Mapping[str, Any],
    read_file: Callable[[str], bytes],
    *,
    internal_name: str = "",
    plugin_name: str = "",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "contractVersion": 0,
        "projects": [],
        "edges": [],
        "inputs": [],
        "environment": [],
        "dependencies": [],
        "releaseWorkflows": [],
        "limits": {"truncated": False, "droppedByCollection": {}},
        "fingerprints": {"buildGraphSha256": "", "dependencyDeclarationSha256": "", "releaseWorkflowSha256": ""},
        "authority": {"sourceContextOnly": True, "buildProof": False, "artifactAuthority": False, "execution": False},
    }
    if str(scope.get("mode") or "") != "plugin-build-graph":
        return result
    dropped: dict[str, int] = result["limits"]["droppedByCollection"]
    primary = str(scope.get("primaryProject") or "")
    project_files = [str(item) for item in (scope.get("projectFiles") or []) if str(item)]
    critical_paths = {str(item) for item in (scope.get("criticalPaths") or []) if str(item)}

    for project in project_files[:MAX_PROJECTS]:
        text = str(descriptor_text.get(project) or "")
        if not text:
            raw = read_file(project)
            text = raw.decode("utf-8", "ignore") if raw else ""
        row = _project_row(project, text, "primary" if project == primary else "referenced")
        if row:
            _dedupe_append(result["projects"], row, ("origin", "path"), MAX_PROJECTS, dropped, "projects")
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            root = None
        if root is not None:
            base_dir = str(PurePosixPath(project).parent)
            if base_dir == ".":
                base_dir = ""
            for element in root.iter():
                if _tag(element) != "ProjectReference":
                    continue
                target = _normalize_repo_path(base_dir, str(element.attrib.get("Include") or ""))
                if not target:
                    continue
                edge: dict[str, Any] = {
                    "origin": "source", "fromProject": project, "toProject": target,
                    "condition": str(element.attrib.get("Condition") or "")[:1024],
                    "privateAssets": str(element.attrib.get("PrivateAssets") or _child_text(element, "PrivateAssets") or "")[:512],
                }
                ref_out = _bool(str(element.attrib.get("ReferenceOutputAssembly") or _child_text(element, "ReferenceOutputAssembly") or ""))
                if ref_out is not None:
                    edge["referenceOutputAssembly"] = ref_out
                _dedupe_append(result["edges"], edge, ("origin", "fromProject", "toProject", "condition"), MAX_EDGES, dropped, "edges")
        for row in _dependency_xml_rows(project, text):
            _dedupe_append(result["dependencies"], row, ("origin", "sourceKind", "path", "kind", "name", "versionExpression", "condition"), MAX_DEPENDENCIES, dropped, "dependencies")

    build_names = {"packages.lock.json", "project.assets.json", "global.json", "nuget.config"}
    for path in sorted(critical_paths, key=str.casefold):
        suffix = PurePosixPath(path).suffix.casefold()
        name = PurePosixPath(path).name.casefold()
        if suffix not in {".csproj", ".props", ".targets", ".sln"} and name not in build_names:
            continue
        raw = read_file(path)
        if not raw:
            continue
        kind = "project" if suffix == ".csproj" else (
            "props" if suffix == ".props" else "targets" if suffix == ".targets" else "solution" if suffix == ".sln" else
            "dependency-lock" if name == "packages.lock.json" else "restore-assets" if name == "project.assets.json" else
            "dotnet-sdk" if name == "global.json" else "nuget-config"
        )
        role = "primary" if path == primary else ("project-closure" if path in project_files else "inherited-build-input")
        _dedupe_append(result["inputs"], {
            "origin": "source", "path": path, "kind": kind, "role": role, "sha256": _sha256(raw), "bytes": len(raw),
        }, ("origin", "path", "sha256"), MAX_INPUTS, dropped, "inputs")
        text = raw.decode("utf-8", "ignore")
        if suffix in {".props", ".targets"}:
            for row in _dependency_xml_rows(path, text):
                _dedupe_append(result["dependencies"], row, ("origin", "sourceKind", "path", "kind", "name", "versionExpression", "condition"), MAX_DEPENDENCIES, dropped, "dependencies")
        if name in {"packages.lock.json", "project.assets.json"}:
            for row in _dependency_json_rows(path, text):
                _dedupe_append(result["dependencies"], row, ("origin", "sourceKind", "path", "targetFramework", "kind", "name", "resolvedVersion"), MAX_DEPENDENCIES, dropped, "dependencies")
        env = _environment_row(path, text)
        if env:
            _dedupe_append(result["environment"], env, ("origin", "path", "kind"), MAX_ENVIRONMENT, dropped, "environment")

    # Directory-level MSBuild policy files are selected by SigmaScope's source-scope resolver.
    for path in sorted(critical_paths, key=str.casefold):
        if PurePosixPath(path).name.casefold() not in {"directory.packages.props", "directory.build.props", "directory.build.targets"}:
            continue
        raw = read_file(path)
        if not raw:
            continue
        text = raw.decode("utf-8", "ignore")
        for row in _dependency_xml_rows(path, text):
            _dedupe_append(result["dependencies"], row, ("origin", "sourceKind", "path", "kind", "name", "versionExpression", "condition"), MAX_DEPENDENCIES, dropped, "dependencies")
        env = _environment_row(path, text)
        if env:
            _dedupe_append(result["environment"], env, ("origin", "path", "kind"), MAX_ENVIRONMENT, dropped, "environment")

    workflow_paths = [
        path for path in source_entries
        if path.casefold().startswith(".github/workflows/") and PurePosixPath(path).suffix.casefold() in {".yml", ".yaml"}
    ]
    identity_tokens = {
        re.sub(r"[^a-z0-9]+", "", value.casefold())
        for value in (internal_name, plugin_name, PurePosixPath(primary).stem)
        if str(value or "").strip()
    }
    for path in sorted(workflow_paths, key=str.casefold)[:128]:
        raw = read_file(path)
        if not raw:
            continue
        text = raw.decode("utf-8", "ignore")
        normalized = re.sub(r"[^a-z0-9]+", "", text.casefold())
        lower = text.casefold()
        identity_match = any(token and token in normalized for token in identity_tokens)
        build_signal = "dotnet " in lower and any(token in lower for token in (" build", " publish", " pack", "upload-artifact", "release"))
        if not identity_match and not (len(project_files) == 1 and build_signal):
            continue
        row = _release_workflow(path, text)
        row.update({"sha256": _sha256(raw), "bytes": len(raw), "identityMatched": identity_match})
        _dedupe_append(result["releaseWorkflows"], row, ("origin", "path", "sha256"), MAX_WORKFLOWS, dropped, "releaseWorkflows")

    result["contractVersion"] = CONTRACT_VERSION
    result["projects"].sort(key=lambda row: (str(row.get("role") or ""), str(row.get("path") or "").casefold()))
    result["edges"].sort(key=lambda row: (str(row.get("fromProject") or "").casefold(), str(row.get("toProject") or "").casefold(), str(row.get("condition") or "")))
    result["inputs"].sort(key=lambda row: (str(row.get("kind") or ""), str(row.get("path") or "").casefold()))
    result["environment"].sort(key=lambda row: (str(row.get("kind") or ""), str(row.get("path") or "").casefold()))
    result["dependencies"].sort(key=lambda row: (str(row.get("sourceKind") or ""), str(row.get("path") or "").casefold(), str(row.get("targetFramework") or ""), str(row.get("kind") or ""), str(row.get("name") or "").casefold(), str(row.get("resolvedVersion") or row.get("versionExpression") or "")))
    result["releaseWorkflows"].sort(key=lambda row: str(row.get("path") or "").casefold())
    result["limits"]["truncated"] = bool(dropped)
    result["fingerprints"] = {
        "buildGraphSha256": _canonical_sha({"projects": result["projects"], "edges": result["edges"], "inputs": result["inputs"], "environment": result["environment"]}) if any((result["projects"], result["edges"], result["inputs"], result["environment"])) else "",
        "dependencyDeclarationSha256": _canonical_sha(result["dependencies"]) if result["dependencies"] else "",
        "releaseWorkflowSha256": _canonical_sha(result["releaseWorkflows"]) if result["releaseWorkflows"] else "",
    }
    return result
