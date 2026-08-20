#!/usr/bin/env python3
"""Build and verify Omega's frozen scanner Definitions snapshot.

Definitions are refreshed at the daily publication boundary. A Sigmascope worker may
run many times during that day, but it must use the same Definitions revision. The
snapshot therefore captures:

* semantic hashes of scanner/rule-bearing source files;
* a self-contained immutable worker bundle with the exact catalog/security Python code;
* a frozen OSV advisory response for the exact NuGet pairs known at refresh time;
* an explicit versioned reputation-feed document (empty until such a feed exists).

The Git branch that launches Actions is development/transport only. Scheduled workers execute
the frozen bundle carried by ``catalog-data`` and never checkout a historical development
commit. A development commit may be recorded as provenance, but it is not executable input.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import analysis_revision  # noqa: E402
import collect_public_advisories  # noqa: E402
import sigmascope  # noqa: E402
import secondary_security_assets  # noqa: E402

SCHEMA = "omega.definitions.v1"
FORMAT_VERSION = 1

WORKER_BUNDLE_SCHEMA = "omega.sigmascope.worker-bundle.v1"
WORKER_BUNDLE_PATH = "worker"
WORKER_BUNDLE_DIRS = ("tools/catalog", "tools/security")
WORKER_BUNDLE_EXTRA_FILES = ("sources/source-overrides.json",)

SECONDARY_SECURITY_SCHEMA = "omega.secondary-security-definitions.v2"
SECONDARY_SECURITY_PATH = "secondary-security"
SECONDARY_SECURITY_SOURCE_PATH = "security-definitions"
SECONDARY_SECURITY_ALLOWED_SUFFIXES = {
    "yara": {".yar", ".yara"},
    "clamav": {".cvd", ".cld"},
}
SECONDARY_SECURITY_MAX_FILES = {"yara": 128, "clamav": 32}
SECONDARY_SECURITY_MAX_FILE_BYTES = 95 * 1024 * 1024
YARA_POLICY_SCHEMA = "omega.sigmascope.yara-policy.v1"
YARA_RULE_METADATA_SCHEMA = "omega.sigmascope.yara-rule-metadata.v1"
YARA_POLICY_FILE = "policy.json"
YARA_METADATA_SUFFIX = ".metadata.json"

RULE_SET_FILES = (
    # Static artifact/source analysis and the helper modules whose semantics feed
    # directly into findings, source provenance, endpoint/path evidence, and
    # cross-source conclusions. Changes elsewhere in the catalog pipeline do not
    # force expensive artifact rescans.
    "tools/catalog/sigmascope.py",
    "tools/catalog/security_endpoint_inventory.py",
    "tools/catalog/security_path_access.py",
    "tools/catalog/security_hash_consensus.py",
    "tools/catalog/security_secondary_engines.py",
    "tools/catalog/secondary_security_assets.py",
    "tools/catalog/source_resolution.py",
    "tools/catalog/public_git_source.py",
    "tools/catalog/source_stability.py",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def git_commit(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True, capture_output=True, check=True
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def rule_files(repo_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for rel in RULE_SET_FILES:
        path = repo_root / rel
        if not path.is_file():
            raise RuntimeError(f"scanner rule-set file is missing: {rel}")
        result[rel] = sha256_file(path)
    return result


def rule_set_revision(fingerprints: dict[str, str], scanner_version: str | None = None) -> str:
    semantic = {
        "schema": "omega.sigmascope.rule-set.v1",
        "scannerVersion": str(scanner_version or sigmascope.SCANNER_VERSION),
        "files": fingerprints,
    }
    return f"rules-v1-{sha256_bytes(canonical(semantic))[:16]}"


def worker_bundle_files(repo_root: Path) -> list[str]:
    files: set[str] = set()
    for rel_dir in WORKER_BUNDLE_DIRS:
        directory = repo_root / rel_dir
        if not directory.is_dir():
            raise RuntimeError(f"worker bundle directory is missing: {rel_dir}")
        for path in directory.rglob("*.py"):
            if path.is_file() and "__pycache__" not in path.parts:
                files.add(path.relative_to(repo_root).as_posix())
    for rel in WORKER_BUNDLE_EXTRA_FILES:
        if not (repo_root / rel).is_file():
            raise RuntimeError(f"worker bundle file is missing: {rel}")
        files.add(rel)
    return sorted(files)


def build_worker_bundle(repo_root: Path, definitions_root: Path) -> dict[str, Any]:
    bundle_root = definitions_root / WORKER_BUNDLE_PATH
    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for rel in worker_bundle_files(repo_root):
        source = repo_root / rel
        destination = bundle_root / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        size = destination.stat().st_size
        total_bytes += size
        entries.append({"path": rel, "sha256": sha256_file(destination), "bytes": size})
    semantic = {"schema": WORKER_BUNDLE_SCHEMA, "files": entries}
    scanner_revision = f"scanner-v1-{sha256_bytes(canonical(semantic))[:16]}"
    manifest = {
        "schema": WORKER_BUNDLE_SCHEMA,
        "scannerRevision": scanner_revision,
        "fileCount": len(entries),
        "totalBytes": total_bytes,
        "files": entries,
    }
    manifest_path = bundle_root / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {
        "path": WORKER_BUNDLE_PATH,
        "manifestPath": f"{WORKER_BUNDLE_PATH}/manifest.json",
        "sha256": sha256_file(manifest_path),
        "scannerRevision": scanner_revision,
        "fileCount": len(entries),
        "totalBytes": total_bytes,
    }


def verify_worker_bundle(definitions_root: Path, descriptor: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    manifest_rel = str(descriptor.get("manifestPath") or "")
    expected_manifest_sha = str(descriptor.get("sha256") or "")
    manifest_path = definitions_root / manifest_rel
    if not manifest_rel or not manifest_path.is_file():
        return [f"worker bundle manifest missing: {manifest_rel or '<unset>'}"]
    if sha256_file(manifest_path) != expected_manifest_sha:
        errors.append("worker bundle manifest SHA-256 mismatch")
        return errors
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"worker bundle manifest unreadable: {type(exc).__name__}: {exc}"]
    if manifest.get("schema") != WORKER_BUNDLE_SCHEMA:
        errors.append(f"unsupported worker bundle schema: {manifest.get('schema')!r}")
    entries = [item for item in manifest.get("files") or [] if isinstance(item, dict)]
    semantic_entries: list[dict[str, Any]] = []
    total_bytes = 0
    bundle_root = definitions_root / str(descriptor.get("path") or WORKER_BUNDLE_PATH)
    for item in entries:
        rel = str(item.get("path") or "")
        expected = str(item.get("sha256") or "")
        expected_bytes = int(item.get("bytes") or 0)
        path = bundle_root / rel
        if not rel or not path.is_file():
            errors.append(f"worker bundle file missing: {rel or '<unset>'}")
            continue
        actual_bytes = path.stat().st_size
        if actual_bytes != expected_bytes:
            errors.append(f"worker bundle file size mismatch: {rel}")
        if sha256_file(path) != expected:
            errors.append(f"worker bundle file SHA-256 mismatch: {rel}")
        total_bytes += actual_bytes
        semantic_entries.append({"path": rel, "sha256": expected, "bytes": expected_bytes})
    expected_revision = f"scanner-v1-{sha256_bytes(canonical({'schema': WORKER_BUNDLE_SCHEMA, 'files': semantic_entries}))[:16]}"
    manifest_revision = str(manifest.get("scannerRevision") or "")
    descriptor_revision = str(descriptor.get("scannerRevision") or "")
    if expected_revision != manifest_revision or expected_revision != descriptor_revision:
        errors.append("scanner revision does not match frozen worker bundle")
    if len(entries) != int(descriptor.get("fileCount") or 0):
        errors.append("worker bundle file count mismatch")
    if total_bytes != int(descriptor.get("totalBytes") or 0):
        errors.append("worker bundle byte count mismatch")
    return errors


def _yara_policy_semantic(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": str(policy.get("schema") or ""),
        "semantics": str(policy.get("semantics") or ""),
        "defaultRuleState": str(policy.get("defaultRuleState") or ""),
        "requiredMetadata": sorted(str(item) for item in (policy.get("requiredMetadata") or [])),
        "allowedStatuses": sorted(str(item) for item in (policy.get("allowedStatuses") or [])),
    }


def _validate_yara_policy(source_dir: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    policy_path = source_dir / YARA_POLICY_FILE
    rules = sorted(
        [path for path in source_dir.rglob("*") if path.is_file() and path.suffix.casefold() in {".yar", ".yara"}],
        key=lambda path: path.relative_to(source_dir).as_posix().casefold(),
    ) if source_dir.is_dir() else []
    if not policy_path.is_file():
        if rules:
            raise RuntimeError("YARA rules exist without security-definitions/yara/policy.json")
        return {}, {}
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"YARA policy is unreadable: {type(exc).__name__}: {exc}") from exc
    if policy.get("schema") != YARA_POLICY_SCHEMA:
        raise RuntimeError("YARA policy schema is unsupported")
    if str(policy.get("semantics") or "") != "supplemental-evidence-only":
        raise RuntimeError("YARA policy semantics must remain supplemental-evidence-only")
    if str(policy.get("defaultRuleState") or "") != "disabled-unless-reviewed":
        raise RuntimeError("YARA policy must default rules to disabled-unless-reviewed")
    required = {
        "schema", "ruleFile", "ruleNames", "status", "provenance", "license", "reviewedAtUtc",
        "falsePositiveExpectation", "scope", "reviewNotes",
    }
    declared = {str(item) for item in (policy.get("requiredMetadata") or [])}
    if not required.issubset(declared):
        raise RuntimeError("YARA policy omits mandatory provenance/false-positive metadata requirements")
    metadata_by_rule: dict[str, dict[str, Any]] = {}
    for rule in rules:
        rel = rule.relative_to(source_dir).as_posix()
        metadata_path = rule.with_name(rule.name + YARA_METADATA_SUFFIX)
        if not metadata_path.is_file():
            raise RuntimeError(f"YARA rule lacks reviewed metadata sidecar: {rel}")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(f"YARA metadata is unreadable for {rel}: {type(exc).__name__}: {exc}") from exc
        if metadata.get("schema") != YARA_RULE_METADATA_SCHEMA:
            raise RuntimeError(f"YARA metadata schema is unsupported for {rel}")
        missing = sorted(name for name in required if name not in metadata)
        if missing:
            raise RuntimeError(f"YARA metadata for {rel} is incomplete: {', '.join(missing)}")
        if str(metadata.get("ruleFile") or "") != rel:
            raise RuntimeError(f"YARA metadata ruleFile does not match {rel}")
        if str(metadata.get("status") or "") not in {"enabled", "disabled"}:
            raise RuntimeError(f"YARA metadata status is invalid for {rel}")
        rule_names = [str(name).strip() for name in (metadata.get("ruleNames") or []) if str(name).strip()]
        if not rule_names or len(rule_names) != len(set(rule_names)):
            raise RuntimeError(f"YARA metadata ruleNames are empty or duplicated for {rel}")
        metadata["ruleNames"] = rule_names
        provenance = metadata.get("provenance") if isinstance(metadata.get("provenance"), dict) else {}
        if not str(provenance.get("kind") or "") or not str(provenance.get("source") or ""):
            raise RuntimeError(f"YARA metadata provenance is incomplete for {rel}")
        if not str(metadata.get("license") or "") or not str(metadata.get("reviewedAtUtc") or ""):
            raise RuntimeError(f"YARA metadata review/license fields are incomplete for {rel}")
        if str(metadata.get("falsePositiveExpectation") or "") not in {"low", "medium", "high", "unknown"}:
            raise RuntimeError(f"YARA false-positive expectation is invalid for {rel}")
        metadata_by_rule[rel] = metadata
    return policy, metadata_by_rule


def _secondary_security_semantic(document: dict[str, Any]) -> dict[str, Any]:
    engines = []
    for item in document.get("engines") or []:
        if not isinstance(item, dict):
            continue
        transport = item.get("transport") if isinstance(item.get("transport"), dict) else {}
        engines.append({
            "engine": str(item.get("engine") or ""),
            "status": str(item.get("status") or "disabled"),
            "files": sorted(
                [
                    {
                        "path": str(entry.get("path") or ""), "sha256": str(entry.get("sha256") or ""),
                        "bytes": int(entry.get("bytes") or 0), "enabled": bool(entry.get("enabled", True)),
                        "metadataSha256": str(entry.get("metadataSha256") or ""),
                    }
                    for entry in item.get("files") or [] if isinstance(entry, dict)
                ],
                key=lambda entry: entry["path"].casefold(),
            ),
            "policy": _yara_policy_semantic(item.get("policy") or {}) if str(item.get("engine") or "") == "yara" else {},
            "executableIdentity": item.get("executableIdentity") or {},
            "transport": ({
                "schema": str(transport.get("schema") or ""),
                "revision": str(transport.get("revision") or ""),
                "asset": transport.get("asset") or {},
                "executableIdentity": transport.get("executableIdentity") or {},
            } if transport else {}),
        })
    return {
        "schema": SECONDARY_SECURITY_SCHEMA,
        "semantics": "supplemental-evidence-only",
        "engines": sorted(engines, key=lambda item: item["engine"]),
    }


def secondary_security_revision(document: dict[str, Any]) -> str:
    return f"secondary-security-v2-{sha256_bytes(canonical(_secondary_security_semantic(document)))[:16]}"


def build_secondary_security_snapshot(
    repo_root: Path, definitions_root: Path, input_root: Path | None = None,
    asset_manifest: Path | None = None,
) -> dict[str, Any]:
    source_root = (input_root.resolve() if input_root is not None else (repo_root / SECONDARY_SECURITY_SOURCE_PATH))
    destination_root = definitions_root / SECONDARY_SECURITY_PATH
    if destination_root.exists():
        shutil.rmtree(destination_root)
    destination_root.mkdir(parents=True, exist_ok=True)

    clamav_transport: dict[str, Any] = {}
    if asset_manifest is not None:
        if not asset_manifest.is_file():
            raise RuntimeError(f"secondary-security asset manifest does not exist: {asset_manifest}")
        clamav_transport = json.loads(asset_manifest.read_text(encoding="utf-8"))
        asset_errors = secondary_security_assets.validate_asset_manifest(clamav_transport)
        if asset_errors:
            raise RuntimeError("invalid ClamAV frozen asset manifest: " + "; ".join(asset_errors))

    engines: list[dict[str, Any]] = []
    yara_dir = source_root / "yara"
    yara_policy, yara_metadata = _validate_yara_policy(yara_dir)
    yara_candidates = sorted(
        [path for path in yara_dir.rglob("*") if path.is_file() and path.suffix.casefold() in SECONDARY_SECURITY_ALLOWED_SUFFIXES["yara"]],
        key=lambda path: path.as_posix().casefold(),
    ) if yara_dir.is_dir() else []
    if len(yara_candidates) > SECONDARY_SECURITY_MAX_FILES["yara"]:
        raise RuntimeError(f"too many frozen yara definition files: {len(yara_candidates)}")
    yara_entries: list[dict[str, Any]] = []
    for source in yara_candidates:
        size = source.stat().st_size
        if size > SECONDARY_SECURITY_MAX_FILE_BYTES:
            raise RuntimeError(f"frozen yara definition exceeds the inline Definitions limit: {source.name} ({size} bytes)")
        rel_name = source.relative_to(yara_dir).as_posix()
        metadata = yara_metadata.get(rel_name) or {}
        destination = destination_root / "yara" / rel_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        metadata_destination = destination.with_name(destination.name + YARA_METADATA_SUFFIX)
        metadata_destination.write_text(json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        yara_entries.append({
            "path": f"{SECONDARY_SECURITY_PATH}/yara/{rel_name}",
            "sha256": sha256_file(destination), "bytes": size,
            "enabled": str(metadata.get("status") or "disabled") == "enabled",
            "metadataPath": f"{SECONDARY_SECURITY_PATH}/yara/{rel_name}{YARA_METADATA_SUFFIX}",
            "metadataSha256": sha256_file(metadata_destination),
            "metadata": metadata,
        })
    frozen_policy: dict[str, Any] = {}
    if yara_policy:
        policy_destination = destination_root / "yara" / YARA_POLICY_FILE
        policy_destination.parent.mkdir(parents=True, exist_ok=True)
        policy_destination.write_text(json.dumps(yara_policy, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        frozen_policy = {
            **yara_policy,
            "path": f"{SECONDARY_SECURITY_PATH}/yara/{YARA_POLICY_FILE}",
            "sha256": sha256_file(policy_destination),
        }
    enabled_yara = sum(1 for item in yara_entries if item["enabled"])
    yara_executable_identity: dict[str, Any] = {}
    if enabled_yara:
        # An enabled rule set is not allowed to float across arbitrary YARA binaries.
        # The exact executable identity observed at the Definitions boundary is frozen
        # and workers verify it before invocation.
        yara_executable_identity = secondary_security_assets.executable_identity("yara")
    engines.append({
        "engine": "yara",
        "status": "configured" if enabled_yara else "disabled",
        "files": yara_entries,
        "policy": frozen_policy,
        "executableIdentity": yara_executable_identity,
        "note": f"{enabled_yara} reviewed YARA rule(s) enabled." if enabled_yara else "No reviewed YARA production rules are enabled.",
    })

    clamav_dir = source_root / "clamav"
    inline_candidates = sorted(
        [path for path in clamav_dir.rglob("*") if path.is_file() and path.suffix.casefold() in SECONDARY_SECURITY_ALLOWED_SUFFIXES["clamav"]],
        key=lambda path: path.as_posix().casefold(),
    ) if clamav_dir.is_dir() else []
    if clamav_transport and inline_candidates:
        raise RuntimeError("ClamAV Definitions cannot mix inline databases with immutable large-asset transport")
    if len(inline_candidates) > SECONDARY_SECURITY_MAX_FILES["clamav"]:
        raise RuntimeError(f"too many frozen clamav definition files: {len(inline_candidates)}")
    clamav_entries: list[dict[str, Any]] = []
    for source in inline_candidates:
        size = source.stat().st_size
        if size > SECONDARY_SECURITY_MAX_FILE_BYTES:
            raise RuntimeError(
                f"frozen clamav definition exceeds the inline Definitions limit: {source.name} ({size} bytes); "
                "use immutable large-signature transport"
            )
        rel_name = source.relative_to(clamav_dir).as_posix()
        destination = destination_root / "clamav" / rel_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        clamav_entries.append({
            "path": f"{SECONDARY_SECURITY_PATH}/clamav/{rel_name}", "sha256": sha256_file(destination),
            "bytes": size, "enabled": True,
        })
    clamav_enabled = bool(clamav_entries or clamav_transport)
    clamav_executable_identity: dict[str, Any] = {}
    if clamav_transport:
        clamav_executable_identity = dict(clamav_transport.get("executableIdentity") or {})
    elif clamav_entries:
        clamav_executable_identity = secondary_security_assets.executable_identity("clamscan")
    engines.append({
        "engine": "clamav",
        "status": "configured" if clamav_enabled else "disabled",
        "files": clamav_entries,
        "transport": clamav_transport,
        "executableIdentity": clamav_executable_identity,
        "note": (
            "Frozen ClamAV database is supplied through content-addressed large-signature transport."
            if clamav_transport else
            ("Frozen inline ClamAV database files are present." if clamav_entries else "No frozen ClamAV database is configured.")
        ),
    })

    document = {
        "schema": SECONDARY_SECURITY_SCHEMA,
        "semantics": "supplemental-evidence-only",
        "engines": engines,
    }
    document["revision"] = secondary_security_revision(document)
    path = destination_root / "index.json"
    path.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {
        "path": f"{SECONDARY_SECURITY_PATH}/index.json",
        "sha256": sha256_file(path),
        "revision": document["revision"],
        "engines": [{
            "engine": item["engine"], "status": item["status"], "fileCount": len(item["files"]),
            "transport": bool(item.get("transport")),
        } for item in engines],
    }


def verify_secondary_security_snapshot(definitions_root: Path, descriptor: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    rel = str(descriptor.get("path") or "")
    path = definitions_root / rel
    if not rel or not path.is_file():
        return {}, ["secondary security Definitions descriptor is missing"]
    if sha256_file(path) != str(descriptor.get("sha256") or ""):
        return {}, ["secondary security Definitions descriptor SHA-256 mismatch"]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, [f"secondary security Definitions descriptor unreadable: {type(exc).__name__}: {exc}"]
    if document.get("schema") != SECONDARY_SECURITY_SCHEMA:
        errors.append("secondary security Definitions schema is unsupported")
    if str(document.get("semantics") or "") != "supplemental-evidence-only":
        errors.append("secondary security Definitions semantics are unsafe")
    expected_revision = secondary_security_revision(document)
    if expected_revision != str(document.get("revision") or "") or expected_revision != str(descriptor.get("revision") or ""):
        errors.append("secondary security Definitions revision mismatch")
    for engine in document.get("engines") or []:
        engine_name = str(engine.get("engine") or "") if isinstance(engine, dict) else ""
        if not isinstance(engine, dict) or engine_name not in SECONDARY_SECURITY_ALLOWED_SUFFIXES:
            errors.append("secondary security Definitions contain an unsupported engine")
            continue
        if engine_name == "yara":
            policy = engine.get("policy") if isinstance(engine.get("policy"), dict) else {}
            if engine.get("files") and policy.get("schema") != YARA_POLICY_SCHEMA:
                errors.append("YARA definitions have rules without a frozen reviewed policy")
            if policy:
                policy_rel = str(policy.get("path") or "")
                policy_path = definitions_root / policy_rel
                if not policy_rel or not policy_path.is_file() or sha256_file(policy_path) != str(policy.get("sha256") or ""):
                    errors.append("frozen YARA policy identity mismatch")
            enabled_rules = [entry for entry in engine.get("files") or [] if isinstance(entry, dict) and bool(entry.get("enabled"))]
            identity = engine.get("executableIdentity") if isinstance(engine.get("executableIdentity"), dict) else {}
            if enabled_rules and identity.get("schema") != secondary_security_assets.EXECUTABLE_IDENTITY_SCHEMA:
                errors.append("enabled YARA rules lack a frozen executable identity")
        transport = engine.get("transport") if isinstance(engine.get("transport"), dict) else {}
        if transport:
            if engine_name != "clamav":
                errors.append("large secondary-security transport is only supported for ClamAV")
            errors.extend(secondary_security_assets.validate_asset_manifest(transport))
        if engine_name == "clamav" and str(engine.get("status") or "") == "configured":
            identity = engine.get("executableIdentity") if isinstance(engine.get("executableIdentity"), dict) else {}
            if identity.get("schema") != secondary_security_assets.EXECUTABLE_IDENTITY_SCHEMA:
                errors.append("configured ClamAV lacks a frozen executable identity")
        for entry in engine.get("files") or []:
            if not isinstance(entry, dict):
                errors.append("secondary security Definitions contain a malformed file entry")
                continue
            file_rel = str(entry.get("path") or "")
            file_path = definitions_root / file_rel
            if not file_rel or not file_path.is_file():
                errors.append(f"secondary security definition missing: {file_rel or '<unset>'}")
                continue
            if file_path.stat().st_size != int(entry.get("bytes") or 0):
                errors.append(f"secondary security definition size mismatch: {file_rel}")
            if sha256_file(file_path) != str(entry.get("sha256") or ""):
                errors.append(f"secondary security definition hash mismatch: {file_rel}")
            if engine_name == "yara":
                metadata_rel = str(entry.get("metadataPath") or "")
                metadata_path = definitions_root / metadata_rel
                if not metadata_rel or not metadata_path.is_file():
                    errors.append(f"YARA rule metadata missing: {file_rel}")
                elif sha256_file(metadata_path) != str(entry.get("metadataSha256") or ""):
                    errors.append(f"YARA rule metadata hash mismatch: {file_rel}")
    return document, errors


def bind_artifact_analysis_revision(code_revision: str, secondary_revision: str) -> str:
    semantic = {
        "schema": "omega.sigmascope.artifact-analysis-contract.v3",
        "codeRevision": str(code_revision or ""),
        "secondarySecurityRevision": str(secondary_revision or ""),
    }
    return f"artifact-analysis-v3-{sha256_bytes(canonical(semantic))[:16]}"

def definitions_revision(
    *, scanner_version: str, scanner_revision: str, scanner_rule_revision: str, fingerprints: dict[str, str],
    artifact_analysis_revision: str, source_analysis_revision: str, source_observation_revision: str,
    osv_document: dict[str, Any], reputation: dict[str, Any], secondary_security: dict[str, Any],
) -> str:
    semantic = {
        "schema": SCHEMA,
        "formatVersion": FORMAT_VERSION,
        "scannerVersion": scanner_version,
        "scannerRevision": scanner_revision,
        "artifactAnalysisRevision": artifact_analysis_revision,
        "sourceAnalysisRevision": source_analysis_revision,
        "sourceObservationRevision": source_observation_revision,
        "ruleSetRevision": scanner_rule_revision,
        "ruleFiles": fingerprints,
        "osv": _semantic_osv(osv_document),
        "reputation": reputation,
        "secondarySecurity": _secondary_security_semantic(secondary_security),
    }
    return f"defs-v1-{sha256_bytes(canonical(semantic))[:16]}"


def _semantic_osv(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": document.get("schema"),
        "source": document.get("source"),
        "ecosystem": document.get("ecosystem"),
        "queriedPackages": int(document.get("queriedPackages") or 0),
        "matchedPackages": int(document.get("matchedPackages") or 0),
        # The exact frozen query universe is semantic. Two days that happened to query the
        # same number of packages must not share a Definitions revision when the package/version
        # identities differ.
        "queriedPackageVersionPairs": sorted(
            [
                {"name": str(item.get("name") or ""), "version": str(item.get("version") or "")}
                for item in document.get("queriedPackageVersionPairs") or []
                if isinstance(item, dict) and str(item.get("name") or "") and str(item.get("version") or "")
            ],
            key=lambda item: (item["name"].casefold(), item["version"]),
        ),
        "advisories": document.get("advisories") or [],
    }



def _semantic_source_observations(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": str(document.get("schema") or "omega.source-revision-observations.v1"),
        "repositories": sorted(
            [
                {
                    "repositoryKey": str(item.get("repositoryKey") or ""),
                    "repository": str(item.get("repository") or ""),
                    "status": str(item.get("status") or ""),
                    "defaultRef": str(item.get("defaultRef") or ""),
                    "commitSha": str(item.get("commitSha") or "").lower(),
                }
                for item in document.get("repositories") or []
                if isinstance(item, dict) and str(item.get("repository") or "")
            ],
            key=lambda item: item["repository"].casefold(),
        ),
    }


def source_observation_revision(document: dict[str, Any]) -> str:
    return f"source-observations-v1-{sha256_bytes(canonical(_semantic_source_observations(document)))[:16]}"

def build_snapshot(
    *,
    repo_root: Path,
    evidence_root: Path,
    output: Path,
    source_commit: str = "",
    advisories_input: Path | None = None,
    source_observations_input: Path | None = None,
    secondary_security_input: Path | None = None,
    secondary_security_asset_manifest: Path | None = None,
    timeout: float = 20.0,
    max_packages: int = 2000,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = evidence_root.resolve()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    built_from_dev_commit = source_commit.strip() or git_commit(repo_root)
    fingerprints = rule_files(repo_root)
    scanner_rule_revision = rule_set_revision(fingerprints)
    worker_bundle = build_worker_bundle(repo_root, output)
    scanner_revision = str(worker_bundle["scannerRevision"])
    analysis_revisions = analysis_revision.compute(repo_root)
    artifact_code_revision = str(analysis_revisions["artifactAnalysisRevision"])
    source_analysis_revision = str(analysis_revisions["sourceAnalysisRevision"])
    secondary_security_descriptor = build_secondary_security_snapshot(
        repo_root, output, secondary_security_input, secondary_security_asset_manifest
    )
    secondary_security_document = json.loads((output / str(secondary_security_descriptor["path"])).read_text(encoding="utf-8"))
    artifact_analysis_revision = bind_artifact_analysis_revision(artifact_code_revision, str(secondary_security_descriptor["revision"]))

    evidence_index_path = evidence_root / "index.json"
    evidence_index = json.loads(evidence_index_path.read_text(encoding="utf-8")) if evidence_index_path.is_file() else {}
    evidence_revision = str((evidence_index.get("revisions") or {}).get("evidenceRevision") or "")
    nuget_meta = (evidence_index.get("indexes") or {}).get("nuget") or {}
    nuget_path = evidence_root / str(nuget_meta.get("path") or "indexes/nuget.json")

    osv_path = output / "osv-advisories.json"
    if advisories_input is not None:
        document = json.loads(advisories_input.read_text(encoding="utf-8"))
        osv_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif nuget_path.is_file():
        document = collect_public_advisories.collect_from_nuget_index(
            nuget_path, osv_path, timeout=timeout, max_packages=max_packages
        )
    else:
        document = {
            "schema": "omega.public-advisories.v1",
            "generatedAtUtc": utc_now(),
            "source": "OSV",
            "ecosystem": "NuGet",
            "queriedPackages": 0,
            "matchedPackages": 0,
            "advisories": [],
        }
        osv_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Preserve the exact package/version query set beside the frozen advisory response.
    # New dependencies discovered by workers during the day remain explicitly uncovered
    # until the next Definitions refresh rather than triggering live OSV calls.
    queried_pairs: list[dict[str, str]] = []
    if nuget_path.is_file():
        for name, version in collect_public_advisories.observed_nuget_index(nuget_path, max_packages):
            queried_pairs.append({"name": name, "version": version})
    document["queriedPackageVersionPairs"] = queried_pairs
    osv_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    source_observations_path = output / "source-revisions.json"
    if source_observations_input is not None and source_observations_input.is_file():
        source_observations_document = json.loads(source_observations_input.read_text(encoding="utf-8"))
        if source_observations_document.get("schema") != "omega.source-revision-observations.v1":
            raise RuntimeError("source revision observations use an unsupported schema")
    else:
        source_observations_document = {
            "schema": "omega.source-revision-observations.v1",
            "generatedAtUtc": utc_now(),
            "counts": {"repositories": 0, "observed": 0, "failed": 0},
            "repositories": [],
        }
    source_observations_revision = source_observation_revision(source_observations_document)
    source_observations_document["revision"] = source_observations_revision
    source_observations_path.write_text(
        json.dumps(source_observations_document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

    reputation = {
        "schema": "omega.reputation-definitions.v1",
        "feeds": [],
        "policy": "No third-party URL/IP reputation feed is enabled. Findings remain static and deterministic.",
    }
    reputation_path = output / "reputation.json"
    reputation_path.write_text(json.dumps(reputation, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    revision = definitions_revision(
        scanner_version=sigmascope.SCANNER_VERSION,
        scanner_revision=scanner_revision,
        scanner_rule_revision=scanner_rule_revision,
        fingerprints=fingerprints,
        artifact_analysis_revision=artifact_analysis_revision,
        source_analysis_revision=source_analysis_revision,
        source_observation_revision=source_observations_revision,
        osv_document=document,
        reputation=reputation,
        secondary_security=secondary_security_document,
    )
    advisory_revision = f"osv-v1-{sha256_bytes(canonical(_semantic_osv(document)))[:16]}"
    index = {
        "schema": SCHEMA,
        "formatVersion": FORMAT_VERSION,
        "definitionsRevision": revision,
        "generatedAtUtc": utc_now(),
        "builtFromDevCommit": built_from_dev_commit,
        "scannerVersion": sigmascope.SCANNER_VERSION,
        "scannerRevision": scanner_revision,
        "scannerBundle": worker_bundle,
        "artifactAnalysisRevision": artifact_analysis_revision,
        "sourceAnalysisRevision": source_analysis_revision,
        "sourceObservationRevision": source_observations_revision,
        "sourceEvidenceRevision": evidence_revision,
        "ruleSetRevision": scanner_rule_revision,
        "advisoryRevision": advisory_revision,
        "ruleFiles": fingerprints,
        "osv": {
            "path": "osv-advisories.json",
            "sha256": sha256_file(osv_path),
            "queriedPackages": int(document.get("queriedPackages") or 0),
            "matchedPackages": int(document.get("matchedPackages") or 0),
            "semanticSha256": sha256_bytes(canonical(_semantic_osv(document))),
        },
        "sourceObservations": {
            "path": "source-revisions.json",
            "sha256": sha256_file(source_observations_path),
            "revision": source_observations_revision,
            "counts": source_observations_document.get("counts") or {},
        },
        "reputation": {
            "path": "reputation.json",
            "sha256": sha256_file(reputation_path),
            "feeds": 0,
        },
        "secondarySecurity": secondary_security_descriptor,
    }
    (output / "index.json").write_text(json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return index


def verify_snapshot(*, definitions_root: Path, repo_root: Path | None = None) -> dict[str, Any]:
    definitions_root = definitions_root.resolve()
    errors: list[str] = []
    try:
        index = json.loads((definitions_root / "index.json").read_text(encoding="utf-8"))
    except Exception as exc:
        return {"schema": "omega.definitions.validation.v1", "ok": False, "errors": [f"index unreadable: {type(exc).__name__}: {exc}"]}
    if index.get("schema") != SCHEMA:
        errors.append(f"unsupported schema {index.get('schema')!r}")
    worker_bundle = index.get("scannerBundle") if isinstance(index.get("scannerBundle"), dict) else {}
    errors.extend(verify_worker_bundle(definitions_root, worker_bundle))
    bundle_root = definitions_root / str(worker_bundle.get("path") or WORKER_BUNDLE_PATH)
    for rel, expected in sorted((index.get("ruleFiles") or {}).items()):
        path = bundle_root / rel
        if not path.is_file():
            errors.append(f"frozen scanner rule file missing from worker bundle: {rel}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"frozen scanner rule file hash mismatch: {rel}")
    secondary_descriptor = index.get("secondarySecurity") if isinstance(index.get("secondarySecurity"), dict) else {}
    secondary_security_document, secondary_errors = verify_secondary_security_snapshot(definitions_root, secondary_descriptor)
    errors.extend(secondary_errors)

    payloads: dict[str, dict[str, Any]] = {}
    for key in ("osv", "reputation"):
        item = index.get(key) or {}
        rel = str(item.get("path") or "")
        path = definitions_root / rel
        if not path.is_file():
            errors.append(f"definitions payload missing: {rel}")
        elif str(item.get("sha256") or "") != sha256_file(path):
            errors.append(f"definitions payload hash mismatch: {rel}")
        else:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                payloads[key] = value if isinstance(value, dict) else {}
            except Exception as exc:
                errors.append(f"definitions payload unreadable: {rel}: {type(exc).__name__}: {exc}")
    source_observations_item = index.get("sourceObservations") if isinstance(index.get("sourceObservations"), dict) else {}
    source_observations_rel = str(source_observations_item.get("path") or "")
    source_observations_path = definitions_root / source_observations_rel
    source_observations_document: dict[str, Any] = {}
    if not source_observations_rel or not source_observations_path.is_file():
        errors.append("definitions source revision observations payload missing")
    elif sha256_file(source_observations_path) != str(source_observations_item.get("sha256") or ""):
        errors.append("definitions source revision observations payload hash mismatch")
    else:
        try:
            value = json.loads(source_observations_path.read_text(encoding="utf-8"))
            source_observations_document = value if isinstance(value, dict) else {}
        except Exception as exc:
            errors.append(f"definitions source revision observations unreadable: {type(exc).__name__}: {exc}")
    expected_source_observation_revision = source_observation_revision(source_observations_document) if source_observations_document else ""
    if expected_source_observation_revision != str(index.get("sourceObservationRevision") or ""):
        errors.append("source observation revision does not match frozen ref observations")
    if expected_source_observation_revision != str(source_observations_item.get("revision") or ""):
        errors.append("source observation descriptor revision mismatch")

    frozen_analysis_revisions: dict[str, Any] = {}
    try:
        frozen_analysis_revisions = analysis_revision.compute(bundle_root)
    except Exception as exc:
        errors.append(f"analysis revision computation failed: {type(exc).__name__}: {exc}")
    expected_artifact_code_revision = str(frozen_analysis_revisions.get("artifactAnalysisRevision") or "")
    expected_source_analysis_revision = str(frozen_analysis_revisions.get("sourceAnalysisRevision") or "")
    expected_artifact_analysis_revision = bind_artifact_analysis_revision(
        expected_artifact_code_revision, str(secondary_descriptor.get("revision") or "")
    ) if secondary_security_document else ""
    if expected_artifact_analysis_revision != str(index.get("artifactAnalysisRevision") or ""):
        errors.append("artifact analysis revision does not match frozen analysis code")
    if expected_source_analysis_revision != str(index.get("sourceAnalysisRevision") or ""):
        errors.append("source analysis revision does not match frozen analysis code")

    scanner_version = str(index.get("scannerVersion") or "")
    fingerprints = {str(k): str(v) for k, v in (index.get("ruleFiles") or {}).items()}
    expected_rule_set = rule_set_revision(fingerprints, scanner_version=scanner_version) if fingerprints else ""
    if expected_rule_set != str(index.get("ruleSetRevision") or ""):
        errors.append("rule-set revision does not match frozen scanner rule files")
    if "osv" in payloads:
        expected_advisory_revision = f"osv-v1-{sha256_bytes(canonical(_semantic_osv(payloads["osv"])))[:16]}"
        if expected_advisory_revision != str(index.get("advisoryRevision") or ""):
            errors.append("advisory revision does not match frozen OSV payload")
    if "osv" in payloads and "reputation" in payloads and expected_rule_set:
        expected_definitions = definitions_revision(
            scanner_version=scanner_version,
            scanner_revision=str(index.get("scannerRevision") or ""),
            scanner_rule_revision=expected_rule_set,
            fingerprints=fingerprints,
            artifact_analysis_revision=expected_artifact_analysis_revision,
            source_analysis_revision=expected_source_analysis_revision,
            source_observation_revision=expected_source_observation_revision,
            osv_document=payloads["osv"],
            reputation=payloads["reputation"],
            secondary_security=secondary_security_document,
        )
        if expected_definitions != str(index.get("definitionsRevision") or ""):
            errors.append("Definitions revision does not match frozen semantic payload")
    return {
        "schema": "omega.definitions.validation.v1",
        "ok": not errors,
        "definitionsRevision": str(index.get("definitionsRevision") or ""),
        "ruleSetRevision": str(index.get("ruleSetRevision") or ""),
        "scannerRevision": str(index.get("scannerRevision") or ""),
        "artifactAnalysisRevision": str(index.get("artifactAnalysisRevision") or ""),
        "sourceAnalysisRevision": str(index.get("sourceAnalysisRevision") or ""),
        "sourceObservationRevision": str(index.get("sourceObservationRevision") or ""),
        "scannerBundleSha256": str((index.get("scannerBundle") or {}).get("sha256") or ""),
        "advisoryRevision": str(index.get("advisoryRevision") or ""),
        "secondarySecurityRevision": str(secondary_descriptor.get("revision") or ""),
        "builtFromDevCommit": str(index.get("builtFromDevCommit") or ""),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--repo-root", type=Path, default=Path.cwd())
    build.add_argument("--evidence-root", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--built-from-dev-commit", "--source-commit", dest="source_commit", default="", help="Optional development provenance only; never an execution dependency")
    build.add_argument("--advisories-input", type=Path)
    build.add_argument("--source-observations", dest="source_observations_input", type=Path)
    build.add_argument("--secondary-security-input", type=Path)
    build.add_argument("--secondary-security-asset-manifest", type=Path)
    build.add_argument("--timeout", type=float, default=20.0)
    build.add_argument("--max-packages", type=int, default=2000)
    verify = sub.add_parser("verify")
    verify.add_argument("--definitions-root", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        result = build_snapshot(
            repo_root=args.repo_root,
            evidence_root=args.evidence_root,
            output=args.output,
            source_commit=args.source_commit,
            advisories_input=args.advisories_input,
            source_observations_input=args.source_observations_input,
            secondary_security_input=args.secondary_security_input,
            secondary_security_asset_manifest=args.secondary_security_asset_manifest,
            timeout=args.timeout,
            max_packages=args.max_packages,
        )
    else:
        result = verify_snapshot(definitions_root=args.definitions_root)
        if not result.get("ok"):
            print(json.dumps(result, indent=2))
            return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
