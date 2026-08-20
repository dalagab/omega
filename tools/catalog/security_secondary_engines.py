"""Bounded adapters for optional secondary security engines.

Secondary engines are deliberately evidence feeds only. They do not replace
SigmaScope's artifact-first static analysis, source attribution, severity model, or
coverage model. Production callers should supply only frozen engine/rule/database
inputs; this module performs no definition updates and no network access.

YARA receives both the exact downloaded package container and a bounded materialized
view of safe ZIP members. Member filenames are never used as filesystem paths: each
candidate is written under a generated filename and the original archive path is kept
only as evidence metadata. This lets rule matches identify the DLL/script/config that
matched without weakening SigmaScope's hostile-archive handling.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
from typing import Any, Iterable
import zipfile

import secondary_security_assets

SCHEMA = "omega.sigmascope.secondary-security.v1"
ENGINE_RESULT_SCHEMA = "omega.sigmascope.secondary-engine-result.v1"
YARA_SCAN_SCOPE_SCHEMA = "omega.sigmascope.yara-scan-scope.v1"
SUPPORTED_ENGINES = {"yara", "clamav"}
MAX_OUTPUT_BYTES = 512 * 1024
MAX_MATCHES = 256
DEFAULT_TIMEOUT_SECONDS = 90

# YARA archive-member materialization is intentionally narrower than SigmaScope's
# primary archive parser. We scan code/config/payload-like members and small unknown
# files, not large media/font assets. The original package container is always scanned.
MAX_YARA_ARCHIVE_MEMBERS = 256
MAX_YARA_MEMBER_BYTES = 16 * 1024 * 1024
MAX_YARA_MEMBER_TOTAL_BYTES = 64 * 1024 * 1024
MAX_YARA_UNKNOWN_MEMBER_BYTES = 4 * 1024 * 1024
MAX_YARA_COMPRESSION_RATIO = 500.0
YARA_MEMBER_SUFFIXES = {
    ".dll", ".exe", ".so", ".dylib", ".bin", ".dat",
    ".ps1", ".psm1", ".psd1", ".cmd", ".bat", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".py", ".cs", ".json", ".config", ".xml", ".ini", ".toml", ".yaml", ".yml", ".txt",
}
YARA_SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".ttf", ".otf", ".woff", ".woff2",
    ".wav", ".mp3", ".ogg", ".flac", ".mp4", ".webm",
}


def _text(value: Any, limit: int = 4096) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _descriptor_revision(
    engine: str,
    executable: str,
    definitions: Iterable[Path],
    expected_identity: dict[str, Any] | None = None,
    policy_revision: str = "",
) -> str:
    semantic = {
        "engine": engine,
        "executable": executable,
        "expectedExecutableIdentity": expected_identity or {},
        "policyRevision": policy_revision,
        "definitions": [
            {"name": path.name, "sha256": _sha256_file(path), "bytes": path.stat().st_size}
            for path in sorted((Path(item) for item in definitions), key=lambda p: p.as_posix().casefold())
            if path.is_file()
        ],
    }
    raw = json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"secondary-v1-{hashlib.sha256(raw).hexdigest()[:20]}"


def _base_result(engine: str, *, status: str, available: bool, enabled: bool, revision: str = "") -> dict[str, Any]:
    return {
        "schema": ENGINE_RESULT_SCHEMA,
        "engine": engine,
        "status": status,
        "available": bool(available),
        "enabled": bool(enabled),
        "revision": revision,
        "version": "",
        "executableIdentity": {},
        "policyRevision": "",
        "scanScope": {},
        "matches": [],
        "error": "",
    }


def _run_version(executable: str, args: list[str]) -> str:
    try:
        proc = subprocess.run(
            [executable, *args], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=15, text=True, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return _text((proc.stdout or "").strip().splitlines()[0] if (proc.stdout or "").strip() else "", 512)


def _bounded_lines(raw: bytes) -> list[str]:
    text = raw[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    return [line.strip() for line in text.splitlines() if line.strip()][:MAX_MATCHES]


def _safe_archive_label(name: str) -> str:
    """Return a bounded display-only POSIX path or an empty string when unsafe."""
    raw = str(name or "").replace("\\", "/")
    try:
        path = PurePosixPath(raw)
    except Exception:
        return ""
    if not raw or raw.startswith("/") or any(part in {"", ".", ".."} for part in path.parts):
        return ""
    if path.parts and ":" in path.parts[0]:
        return ""
    return _text(path.as_posix(), 2048)


def _member_is_yara_candidate(label: str, size: int) -> bool:
    suffix = PurePosixPath(label).suffix.casefold()
    if suffix in YARA_SKIP_SUFFIXES:
        return False
    if suffix in YARA_MEMBER_SUFFIXES:
        return True
    # Extensionless/unknown small files can still contain scripts or embedded payloads.
    return int(size) <= MAX_YARA_UNKNOWN_MEMBER_BYTES


def _materialize_yara_targets(artifact: bytes, artifact_sha256: str, root: Path) -> tuple[Path, dict[str, dict[str, Any]], dict[str, Any]]:
    target_root = root / "yara-targets"
    target_root.mkdir(parents=True, exist_ok=True)
    lookup: dict[str, dict[str, Any]] = {}

    container_path = target_root / "0000-artifact.bin"
    container_path.write_bytes(artifact)
    lookup[container_path.name] = {
        "kind": "artifact-container",
        "path": "",
        "sha256": artifact_sha256,
        "bytes": len(artifact),
    }

    scope: dict[str, Any] = {
        "schema": YARA_SCAN_SCOPE_SCHEMA,
        "artifactContainerScanned": True,
        "archiveDetected": False,
        "archiveMemberCandidates": 0,
        "archiveMembersScanned": 0,
        "archiveMembersSkipped": 0,
        "archiveMemberBytesScanned": 0,
        "targetCount": 1,
        "truncated": False,
        "skipReasons": {},
        "limits": {
            "maxMembers": MAX_YARA_ARCHIVE_MEMBERS,
            "maxMemberBytes": MAX_YARA_MEMBER_BYTES,
            "maxMemberTotalBytes": MAX_YARA_MEMBER_TOTAL_BYTES,
        },
    }

    def skip(reason: str) -> None:
        scope["archiveMembersSkipped"] = int(scope["archiveMembersSkipped"]) + 1
        reasons = scope["skipReasons"]
        reasons[reason] = int(reasons.get(reason) or 0) + 1

    try:
        archive = zipfile.ZipFile(io.BytesIO(artifact), "r")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError):
        return target_root, lookup, scope

    scope["archiveDetected"] = True
    total = 0
    scanned_members = 0
    try:
        infos = sorted(archive.infolist(), key=lambda item: str(item.filename).casefold())
        for info in infos:
            if info.is_dir():
                continue
            label = _safe_archive_label(info.filename)
            if not label:
                skip("unsafe-path")
                continue
            if info.flag_bits & 0x1:
                skip("encrypted")
                continue
            size = max(0, int(info.file_size or 0))
            if not _member_is_yara_candidate(label, size):
                skip("non-code-resource")
                continue
            scope["archiveMemberCandidates"] = int(scope["archiveMemberCandidates"]) + 1
            if scanned_members >= MAX_YARA_ARCHIVE_MEMBERS:
                scope["truncated"] = True
                skip("member-count-limit")
                continue
            if size > MAX_YARA_MEMBER_BYTES:
                skip("member-byte-limit")
                continue
            compressed = max(0, int(info.compress_size or 0))
            if compressed == 0 and size > 0:
                skip("invalid-compressed-size")
                continue
            if compressed > 0 and size / compressed > MAX_YARA_COMPRESSION_RATIO:
                skip("compression-ratio-limit")
                continue
            if total + size > MAX_YARA_MEMBER_TOTAL_BYTES:
                scope["truncated"] = True
                skip("aggregate-byte-limit")
                continue
            try:
                with archive.open(info, "r") as stream:
                    data = stream.read(MAX_YARA_MEMBER_BYTES + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                skip("read-error")
                continue
            if len(data) > MAX_YARA_MEMBER_BYTES or len(data) != size:
                skip("member-size-mismatch")
                continue
            scanned_members += 1
            total += len(data)
            suffix = PurePosixPath(label).suffix.casefold()
            if len(suffix) > 12 or not suffix.replace(".", "").isalnum():
                suffix = ".bin"
            target = target_root / f"member-{scanned_members:04d}{suffix or '.bin'}"
            target.write_bytes(data)
            lookup[target.name] = {
                "kind": "archive-member",
                "path": label,
                "sha256": _sha256_bytes(data),
                "bytes": len(data),
            }
    finally:
        archive.close()

    scope["archiveMembersScanned"] = scanned_members
    scope["archiveMemberBytesScanned"] = total
    scope["targetCount"] = 1 + scanned_members
    return target_root, lookup, scope


def _metadata_by_rule(rule_metadata: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for metadata in rule_metadata:
        if not isinstance(metadata, dict):
            continue
        for rule_name in metadata.get("ruleNames") or []:
            name = str(rule_name or "").strip()
            if name:
                output[name] = metadata
    return output


def _target_from_yara_output(value: str, lookup: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not value:
        return {}
    name = Path(value).name
    target = lookup.get(name)
    return dict(target) if isinstance(target, dict) else {}


def run_yara(
    artifact_path: Path,
    rule_files: Iterable[Path],
    *,
    executable: str = "yara",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    expected_executable_identity: dict[str, Any] | None = None,
    policy_revision: str = "",
    rule_metadata: Iterable[dict[str, Any]] = (),
    target_lookup: dict[str, dict[str, Any]] | None = None,
    scan_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rules = [Path(path) for path in rule_files if Path(path).is_file()]
    resolved = shutil.which(executable)
    if not rules:
        return _base_result("yara", status="disabled", available=bool(resolved), enabled=False)
    revision = _descriptor_revision("yara", executable, rules, expected_executable_identity, policy_revision)
    if not expected_executable_identity:
        result = _base_result("yara", status="unavailable", available=False, enabled=True, revision=revision)
        result["error"] = "YARA rules are configured without a frozen executable identity."
        result["policyRevision"] = policy_revision
        return result
    identity = secondary_security_assets.verify_executable_identity(expected_executable_identity)
    if not identity.get("verified"):
        result = _base_result("yara", status="unavailable", available=False, enabled=True, revision=revision)
        result["error"] = str(identity.get("error") or "YARA executable identity mismatch.")
        result["executableIdentity"] = identity
        result["policyRevision"] = policy_revision
        return result
    resolved = str(identity.get("resolvedPath") or resolved or executable)
    result = _base_result("yara", status="failed", available=True, enabled=True, revision=revision)
    result["version"] = str(identity.get("actualVersion") or _run_version(resolved, ["--version"]))
    result["executableIdentity"] = identity
    result["policyRevision"] = policy_revision
    result["scanScope"] = dict(scan_scope or {})
    try:
        # A directory target lets YARA compile the frozen rules once and scan all
        # generated bounded targets in a single process. No shell is used.
        proc = subprocess.run(
            [resolved, "--no-warnings", *[str(path) for path in rules], str(artifact_path)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=max(1, int(timeout)),
        )
        lines = _bounded_lines(proc.stdout or b"")
        metadata_index = _metadata_by_rule(rule_metadata)
        lookup = target_lookup or {}
        matches = []
        for line in lines:
            rule_name, _, target_value = line.partition(" ")
            rule_name = rule_name.strip()
            target_value = target_value.strip()
            match: dict[str, Any] = {
                "kind": "rule",
                "value": _text(line, 2048),
                "rule": _text(rule_name, 256),
            }
            target = _target_from_yara_output(target_value, lookup)
            if target:
                match["target"] = target
            metadata = metadata_index.get(rule_name) or {}
            if metadata:
                provenance = metadata.get("provenance") if isinstance(metadata.get("provenance"), dict) else {}
                match.update({
                    "provenance": {
                        "kind": _text(provenance.get("kind"), 128),
                        "source": _text(provenance.get("source"), 1024),
                    },
                    "license": _text(metadata.get("license"), 256),
                    "reviewedAtUtc": _text(metadata.get("reviewedAtUtc"), 64),
                    "reviewer": _text(metadata.get("reviewer"), 256),
                    "reviewedRuleSha256": _text(metadata.get("reviewedRuleSha256"), 128),
                    "ruleClass": _text(metadata.get("ruleClass"), 64),
                    "confidence": _text(metadata.get("confidence"), 32),
                    "falsePositiveExpectation": _text(metadata.get("falsePositiveExpectation"), 64),
                    "scope": _text(metadata.get("scope"), 1024),
                })
            matches.append(match)
        result["matches"] = matches[:MAX_MATCHES]
        if proc.returncode == 0:
            result["status"] = "complete"
        else:
            result["error"] = _text("; ".join(lines[-8:]) or f"YARA exited with code {proc.returncode}", 4096)
    except subprocess.TimeoutExpired:
        result["error"] = "YARA scan timed out."
    except OSError as exc:
        result["error"] = _text(f"YARA invocation failed: {exc}")
    return result


def run_clamav(
    artifact_path: Path,
    database_files: Iterable[Path],
    *,
    executable: str = "clamscan",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    expected_executable_identity: dict[str, Any] | None = None,
    configuration_error: str = "",
) -> dict[str, Any]:
    databases = [Path(path) for path in database_files if Path(path).is_file()]
    resolved = shutil.which(executable)
    if not databases:
        if configuration_error:
            result = _base_result("clamav", status="unavailable", available=bool(resolved), enabled=True)
            result["error"] = _text(configuration_error)
            return result
        return _base_result("clamav", status="disabled", available=bool(resolved), enabled=False)
    revision = _descriptor_revision("clamav", executable, databases, expected_executable_identity)
    if not expected_executable_identity:
        result = _base_result("clamav", status="unavailable", available=False, enabled=True, revision=revision)
        result["error"] = "ClamAV databases are configured without a frozen executable identity."
        return result
    identity = secondary_security_assets.verify_executable_identity(expected_executable_identity)
    if not identity.get("verified"):
        result = _base_result("clamav", status="unavailable", available=False, enabled=True, revision=revision)
        result["error"] = str(identity.get("error") or "ClamAV executable identity mismatch.")
        result["executableIdentity"] = identity
        return result
    resolved = str(identity.get("resolvedPath") or resolved or executable)
    result = _base_result("clamav", status="failed", available=True, enabled=True, revision=revision)
    result["version"] = str(identity.get("actualVersion") or _run_version(resolved, ["--version"]))
    result["executableIdentity"] = identity
    db_dirs = {path.resolve().parent for path in databases}
    if len(db_dirs) != 1:
        result["error"] = "Frozen ClamAV database files must share one directory."
        return result
    db_dir = next(iter(db_dirs))
    try:
        proc = subprocess.run(
            [resolved, "--no-summary", "--stdout", "--infected", f"--database={db_dir}", str(artifact_path)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=max(1, int(timeout)),
        )
        lines = _bounded_lines(proc.stdout or b"")
        matches = []
        for line in lines:
            if line.endswith(" FOUND"):
                matches.append({"kind": "signature", "value": _text(line[:-6].strip(), 2048)})
        result["matches"] = matches[:MAX_MATCHES]
        if proc.returncode in {0, 1}:  # 0=clean, 1=infected, 2=error
            result["status"] = "complete"
        else:
            result["error"] = _text("; ".join(lines[-8:]) or f"ClamAV exited with code {proc.returncode}", 4096)
    except subprocess.TimeoutExpired:
        result["error"] = "ClamAV scan timed out."
    except OSError as exc:
        result["error"] = _text(f"ClamAV invocation failed: {exc}")
    return result


def scan_artifact_bytes(
    artifact: bytes,
    artifact_sha256: str,
    *,
    yara_rules: Iterable[Path] = (),
    clamav_databases: Iterable[Path] = (),
    yara_executable_identity: dict[str, Any] | None = None,
    clamav_executable_identity: dict[str, Any] | None = None,
    yara_policy_revision: str = "",
    yara_rule_metadata: Iterable[dict[str, Any]] = (),
    clamav_configuration_error: str = "",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run configured local secondary engines against exactly the downloaded bytes."""
    expected = hashlib.sha256(artifact).hexdigest()
    if str(artifact_sha256 or "").strip().lower() != expected:
        raise ValueError("secondary-engine artifact hash does not match downloaded bytes")
    with tempfile.TemporaryDirectory(prefix="omega-secondary-security-") as td:
        root = Path(td)
        artifact_path = root / f"artifact-{expected}.bin"
        artifact_path.write_bytes(artifact)
        yara_target_root, yara_target_lookup, yara_scope = _materialize_yara_targets(artifact, expected, root)
        engines = [
            run_yara(
                yara_target_root,
                yara_rules,
                timeout=timeout,
                expected_executable_identity=yara_executable_identity,
                policy_revision=yara_policy_revision,
                rule_metadata=yara_rule_metadata,
                target_lookup=yara_target_lookup,
                scan_scope=yara_scope,
            ),
            run_clamav(
                artifact_path,
                clamav_databases,
                timeout=timeout,
                expected_executable_identity=clamav_executable_identity,
                configuration_error=clamav_configuration_error,
            ),
        ]
    return {
        "schema": SCHEMA,
        "artifactSha256": expected,
        "semantics": "supplemental-evidence-only",
        "engines": engines,
        "matchCount": sum(len(item.get("matches") or []) for item in engines),
    }
