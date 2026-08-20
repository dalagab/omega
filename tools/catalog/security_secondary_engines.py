"""Bounded adapters for optional secondary security engines.

Secondary engines are deliberately evidence feeds only.  They do not replace
SigmaScope's artifact-first static analysis, source attribution, severity model, or
coverage model.  Production callers should supply only frozen engine/rule/database
inputs; this module performs no definition updates and no network access.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Iterable

import secondary_security_assets

SCHEMA = "omega.sigmascope.secondary-security.v1"
ENGINE_RESULT_SCHEMA = "omega.sigmascope.secondary-engine-result.v1"
SUPPORTED_ENGINES = {"yara", "clamav"}
MAX_OUTPUT_BYTES = 512 * 1024
MAX_MATCHES = 256
DEFAULT_TIMEOUT_SECONDS = 90


def _text(value: Any, limit: int = 4096) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _descriptor_revision(engine: str, executable: str, definitions: Iterable[Path], expected_identity: dict[str, Any] | None = None, policy_revision: str = "") -> str:
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


def run_yara(
    artifact_path: Path, rule_files: Iterable[Path], *, executable: str = "yara",
    timeout: int = DEFAULT_TIMEOUT_SECONDS, expected_executable_identity: dict[str, Any] | None = None,
    policy_revision: str = "", rule_metadata: Iterable[dict[str, Any]] = (),
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
    try:
        # YARA accepts multiple rule files before the target.  No shell is used and the
        # untrusted artifact path is a generated temporary filename.
        proc = subprocess.run(
            [resolved, "--no-warnings", *[str(path) for path in rules], str(artifact_path)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=max(1, int(timeout)),
        )
        lines = _bounded_lines(proc.stdout or b"")
        metadata_by_name: dict[str, dict[str, Any]] = {}
        for metadata in rule_metadata:
            if not isinstance(metadata, dict):
                continue
            for rule_name in metadata.get("ruleNames") or []:
                name = str(rule_name or "").strip()
                if name:
                    metadata_by_name[name] = metadata
        matches = []
        for line in lines:
            rule_name = line.split(None, 1)[0] if line else ""
            match = {"kind": "rule", "value": _text(line, 2048), "rule": _text(rule_name, 256)}
            metadata = metadata_by_name.get(rule_name) or {}
            if metadata:
                provenance = metadata.get("provenance") if isinstance(metadata.get("provenance"), dict) else {}
                match.update({
                    "provenance": {"kind": _text(provenance.get("kind"), 128), "source": _text(provenance.get("source"), 1024)},
                    "license": _text(metadata.get("license"), 256),
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
    artifact_path: Path, database_files: Iterable[Path], *, executable: str = "clamscan",
    timeout: int = DEFAULT_TIMEOUT_SECONDS, expected_executable_identity: dict[str, Any] | None = None,
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
    # ClamAV supports one database path. Frozen Definitions should place the database
    # files in one directory; verify that before invoking it.
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
        artifact_path = Path(td) / f"artifact-{expected}.bin"
        artifact_path.write_bytes(artifact)
        engines = [
            run_yara(
                artifact_path, yara_rules, timeout=timeout,
                expected_executable_identity=yara_executable_identity, policy_revision=yara_policy_revision,
                rule_metadata=yara_rule_metadata,
            ),
            run_clamav(
                artifact_path, clamav_databases, timeout=timeout,
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
