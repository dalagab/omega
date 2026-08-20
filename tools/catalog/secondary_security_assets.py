#!/usr/bin/env python3
"""Build and materialize immutable large secondary-security definition assets.

The daily catalog/Definitions job is the *only* place where mutable upstream security
feeds may be refreshed.  Large payloads such as the official ClamAV CVD/CLD databases
are packed into a deterministic content-addressed asset, uploaded outside the
``catalog-data`` Git tree, and referenced by exact SHA-256/byte count from frozen
Definitions.  Continuous SigmaScope workers only download that exact frozen asset and
verify every byte before making it visible to the scanner.

This module intentionally does not run ``freshclam`` and does not install scanners.
Those are workflow concerns at the daily Definitions boundary.  It also never executes
untrusted plugin bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from typing import Any, Iterable
import zipfile

ASSET_MANIFEST_SCHEMA = "omega.secondary-security.asset-manifest.v1"
BUNDLE_SCHEMA = "omega.secondary-security.clamav-bundle.v1"
EXECUTABLE_IDENTITY_SCHEMA = "omega.secondary-security.executable-identity.v1"
RUNTIME_SCHEMA = "omega.secondary-security.runtime.v1"
ALLOWED_DATABASE_SUFFIXES = {".cvd", ".cld"}
MAX_DATABASE_FILES = 32
MAX_DATABASE_FILE_BYTES = 512 * 1024 * 1024
MAX_ASSET_BYTES = 1024 * 1024 * 1024
DOWNLOAD_CHUNK = 1024 * 1024


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(DOWNLOAD_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_line(value: str, limit: int = 512) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    text = lines[0] if lines else ""
    return text[:limit]


def executable_identity(executable: str) -> dict[str, Any]:
    resolved_text = shutil.which(executable)
    if not resolved_text:
        raise RuntimeError(f"secondary-security executable is unavailable: {executable}")
    resolved = Path(resolved_text).resolve()
    if not resolved.is_file():
        raise RuntimeError(f"secondary-security executable is not a regular file: {resolved}")
    try:
        proc = subprocess.run(
            [str(resolved), "--version"], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", timeout=15,
        )
        version = _first_line(proc.stdout or "")
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"unable to identify secondary-security executable {resolved}: {exc}") from exc
    return {
        "schema": EXECUTABLE_IDENTITY_SCHEMA,
        "command": executable,
        "resolvedName": resolved.name,
        "sha256": sha256_file(resolved),
        "bytes": resolved.stat().st_size,
        "version": version,
    }


def verify_executable_identity(identity: dict[str, Any]) -> dict[str, Any]:
    command = str(identity.get("command") or "")
    result = {
        "schema": EXECUTABLE_IDENTITY_SCHEMA,
        "command": command,
        "expectedSha256": str(identity.get("sha256") or "").lower(),
        "expectedBytes": int(identity.get("bytes") or 0),
        "expectedVersion": str(identity.get("version") or ""),
        "available": False,
        "verified": False,
        "resolvedPath": "",
        "actualSha256": "",
        "actualBytes": 0,
        "actualVersion": "",
        "error": "",
    }
    if identity.get("schema") != EXECUTABLE_IDENTITY_SCHEMA or not command:
        result["error"] = "Frozen executable identity is malformed."
        return result
    resolved_text = shutil.which(command)
    if not resolved_text:
        result["error"] = f"Frozen executable command is unavailable: {command}"
        return result
    resolved = Path(resolved_text).resolve()
    result["available"] = resolved.is_file()
    result["resolvedPath"] = str(resolved)
    if not resolved.is_file():
        result["error"] = "Resolved executable is not a regular file."
        return result
    result["actualSha256"] = sha256_file(resolved)
    result["actualBytes"] = resolved.stat().st_size
    try:
        proc = subprocess.run(
            [str(resolved), "--version"], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", timeout=15,
        )
        result["actualVersion"] = _first_line(proc.stdout or "")
    except (OSError, subprocess.SubprocessError):
        result["actualVersion"] = ""
    mismatches = []
    if result["expectedSha256"] != result["actualSha256"]:
        mismatches.append("SHA-256")
    if result["expectedBytes"] != result["actualBytes"]:
        mismatches.append("byte count")
    # Version is provenance/debug context. Binary SHA-256 + byte count are the hard identity.
    if mismatches:
        result["error"] = "Executable identity mismatch: " + ", ".join(mismatches)
        return result
    result["verified"] = True
    return result


def _database_entries(database_dir: Path) -> list[dict[str, Any]]:
    candidates = sorted(
        [path for path in database_dir.rglob("*") if path.is_file() and path.suffix.casefold() in ALLOWED_DATABASE_SUFFIXES],
        key=lambda path: path.relative_to(database_dir).as_posix().casefold(),
    )
    if not candidates:
        raise RuntimeError("no ClamAV CVD/CLD databases were supplied")
    if len(candidates) > MAX_DATABASE_FILES:
        raise RuntimeError(f"too many ClamAV database files: {len(candidates)}")
    entries: list[dict[str, Any]] = []
    for path in candidates:
        size = path.stat().st_size
        if size <= 0 or size > MAX_DATABASE_FILE_BYTES:
            raise RuntimeError(f"ClamAV database has an invalid size: {path.name} ({size} bytes)")
        rel = path.relative_to(database_dir).as_posix()
        if PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts:
            raise RuntimeError(f"unsafe ClamAV database path: {rel}")
        entries.append({"path": f"clamav/{rel}", "sha256": sha256_file(path), "bytes": size})
    return entries


def _write_deterministic_bundle(database_dir: Path, entries: list[dict[str, Any]], output_path: Path) -> dict[str, Any]:
    bundle_manifest = {
        "schema": BUNDLE_SCHEMA,
        "semantics": "frozen-content-addressed-definitions",
        "files": entries,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for entry in entries:
            rel = str(entry["path"])[len("clamav/"):]
            source = database_dir / rel
            info = zipfile.ZipInfo(str(entry["path"]), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            with source.open("rb") as stream, archive.open(info, "w", force_zip64=True) as target:
                shutil.copyfileobj(stream, target, length=DOWNLOAD_CHUNK)
        info = zipfile.ZipInfo("bundle.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, json.dumps(bundle_manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    if output_path.stat().st_size > MAX_ASSET_BYTES:
        raise RuntimeError(f"ClamAV definition asset exceeds {MAX_ASSET_BYTES} bytes")
    return bundle_manifest


def build_clamav_asset(
    *, database_dir: Path, output_dir: Path, asset_base_url: str, executable: str = "clamscan",
    manifest_output: Path | None = None,
) -> dict[str, Any]:
    database_dir = database_dir.resolve()
    if not database_dir.is_dir():
        raise RuntimeError(f"ClamAV database directory does not exist: {database_dir}")
    parsed = urllib.parse.urlsplit(asset_base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RuntimeError("secondary-security asset base URL must be HTTPS")
    entries = _database_entries(database_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="omega-clamav-asset-") as td:
        temp_bundle = Path(td) / "clamav-definitions.zip"
        bundle_manifest = _write_deterministic_bundle(database_dir, entries, temp_bundle)
        asset_sha = sha256_file(temp_bundle)
        asset_name = f"omega-clamav-definitions-{asset_sha[:24]}.zip"
        destination = output_dir / asset_name
        shutil.copy2(temp_bundle, destination)
    identity = executable_identity(executable)
    document = {
        "schema": ASSET_MANIFEST_SCHEMA,
        "engine": "clamav",
        "semantics": "frozen-content-addressed-definitions",
        "asset": {
            "name": asset_name,
            "url": asset_base_url.rstrip("/") + "/" + asset_name,
            "sha256": asset_sha,
            "bytes": destination.stat().st_size,
            "bundleSchema": BUNDLE_SCHEMA,
            "files": entries,
        },
        "executableIdentity": identity,
        "bundle": bundle_manifest,
    }
    document["revision"] = "clamav-asset-v1-" + hashlib.sha256(canonical({
        "engine": document["engine"], "asset": document["asset"], "executableIdentity": identity,
    })).hexdigest()[:20]
    if manifest_output is not None:
        manifest_output.parent.mkdir(parents=True, exist_ok=True)
        manifest_output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return document


def validate_asset_manifest(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("schema") != ASSET_MANIFEST_SCHEMA:
        errors.append("unsupported secondary-security asset manifest schema")
    if str(document.get("engine") or "") != "clamav":
        errors.append("secondary-security asset manifest engine is not clamav")
    asset = document.get("asset") if isinstance(document.get("asset"), dict) else {}
    parsed = urllib.parse.urlsplit(str(asset.get("url") or ""))
    if parsed.scheme != "https" or not parsed.netloc:
        errors.append("ClamAV asset URL must be HTTPS")
    sha = str(asset.get("sha256") or "").lower()
    if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        errors.append("ClamAV asset SHA-256 is invalid")
    size = int(asset.get("bytes") or 0)
    if size <= 0 or size > MAX_ASSET_BYTES:
        errors.append("ClamAV asset byte count is invalid")
    files = [item for item in asset.get("files") or [] if isinstance(item, dict)]
    if not files or len(files) > MAX_DATABASE_FILES:
        errors.append("ClamAV asset file list is empty or oversized")
    seen: set[str] = set()
    for item in files:
        rel = str(item.get("path") or "")
        pure = PurePosixPath(rel)
        if not rel.startswith("clamav/") or pure.is_absolute() or ".." in pure.parts or rel in seen:
            errors.append(f"unsafe or duplicate ClamAV asset member: {rel or '<unset>'}")
        seen.add(rel)
        item_sha = str(item.get("sha256") or "").lower()
        if len(item_sha) != 64 or any(ch not in "0123456789abcdef" for ch in item_sha):
            errors.append(f"invalid ClamAV database SHA-256: {rel}")
        item_bytes = int(item.get("bytes") or 0)
        if item_bytes <= 0 or item_bytes > MAX_DATABASE_FILE_BYTES:
            errors.append(f"invalid ClamAV database byte count: {rel}")
    identity = document.get("executableIdentity") if isinstance(document.get("executableIdentity"), dict) else {}
    if identity.get("schema") != EXECUTABLE_IDENTITY_SCHEMA:
        errors.append("ClamAV executable identity is missing or unsupported")
    if str(identity.get("command") or "") != "clamscan":
        errors.append("ClamAV executable identity must target clamscan")
    expected_revision = "clamav-asset-v1-" + hashlib.sha256(canonical({
        "engine": str(document.get("engine") or ""), "asset": asset, "executableIdentity": identity,
    })).hexdigest()[:20]
    if str(document.get("revision") or "") != expected_revision:
        errors.append("ClamAV asset manifest revision mismatch")
    return errors


def _download(url: str, destination: Path, expected_bytes: int) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RuntimeError("secondary-security asset URL must be HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "Omega-SigmaScope/secondary-security"})
    total = 0
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as stream:
        while True:
            chunk = response.read(DOWNLOAD_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ASSET_BYTES or total > expected_bytes:
                raise RuntimeError("secondary-security asset exceeded the frozen byte count")
            stream.write(chunk)
    if total != expected_bytes:
        raise RuntimeError(f"secondary-security asset byte count mismatch: expected {expected_bytes}, got {total}")


def _safe_extract_bundle(bundle: Path, output: Path, files: Iterable[dict[str, Any]]) -> None:
    expected = {str(item.get("path") or ""): item for item in files}
    with zipfile.ZipFile(bundle, "r") as archive:
        names = archive.namelist()
        allowed = set(expected) | {"bundle.json"}
        unexpected = sorted(set(names) - allowed)
        missing = sorted(set(expected) - set(names))
        if unexpected or missing or len(names) != len(set(names)):
            raise RuntimeError(f"ClamAV asset member mismatch; unexpected={unexpected[:5]} missing={missing[:5]}")
        try:
            embedded = json.loads(archive.read("bundle.json").decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"ClamAV bundle manifest unreadable: {exc}") from exc
        if embedded.get("schema") != BUNDLE_SCHEMA:
            raise RuntimeError("ClamAV bundle schema is unsupported")
        for rel, descriptor in expected.items():
            pure = PurePosixPath(rel)
            if pure.is_absolute() or ".." in pure.parts or not rel.startswith("clamav/"):
                raise RuntimeError(f"unsafe ClamAV bundle member: {rel}")
            target = output / Path(*pure.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            total = 0
            with archive.open(rel, "r") as source, target.open("wb") as stream:
                while True:
                    chunk = source.read(DOWNLOAD_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > int(descriptor.get("bytes") or 0):
                        raise RuntimeError(f"ClamAV database expanded beyond frozen byte count: {rel}")
                    digest.update(chunk)
                    stream.write(chunk)
            if total != int(descriptor.get("bytes") or 0) or digest.hexdigest() != str(descriptor.get("sha256") or ""):
                raise RuntimeError(f"ClamAV database identity mismatch after extraction: {rel}")


def materialize_clamav_asset(
    *, definitions_root: Path, output: Path, asset_file: Path | None = None,
) -> dict[str, Any]:
    secondary_index_path = definitions_root / "secondary-security" / "index.json"
    if not secondary_index_path.is_file():
        raise RuntimeError("frozen secondary-security index is missing")
    secondary_index = json.loads(secondary_index_path.read_text(encoding="utf-8"))
    clamav = next((item for item in secondary_index.get("engines") or [] if isinstance(item, dict) and item.get("engine") == "clamav"), None)
    if not isinstance(clamav, dict):
        raise RuntimeError("frozen ClamAV descriptor is missing")
    transport = clamav.get("transport") if isinstance(clamav.get("transport"), dict) else {}
    if not transport:
        output.mkdir(parents=True, exist_ok=True)
        runtime = {"schema": RUNTIME_SCHEMA, "engine": "clamav", "status": "disabled", "reason": "no-frozen-asset"}
        (output / "runtime.json").write_text(json.dumps(runtime, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return runtime
    errors = validate_asset_manifest(transport)
    if errors:
        raise RuntimeError("invalid frozen ClamAV transport descriptor: " + "; ".join(errors))
    asset = transport["asset"]
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="omega-clamav-materialize-") as td:
        bundle = Path(td) / str(asset.get("name") or "clamav.zip")
        if asset_file is not None:
            shutil.copy2(asset_file, bundle)
            if bundle.stat().st_size != int(asset["bytes"]):
                raise RuntimeError("provided ClamAV asset byte count mismatch")
        else:
            _download(str(asset["url"]), bundle, int(asset["bytes"]))
        if sha256_file(bundle) != str(asset["sha256"]):
            raise RuntimeError("ClamAV asset SHA-256 mismatch")
        staging = Path(td) / "extracted"
        staging.mkdir()
        _safe_extract_bundle(bundle, staging, asset.get("files") or [])
        final_clamav = output / "clamav"
        if final_clamav.exists():
            shutil.rmtree(final_clamav)
        shutil.copytree(staging / "clamav", final_clamav)
    executable = verify_executable_identity(transport.get("executableIdentity") or {})
    runtime = {
        "schema": RUNTIME_SCHEMA,
        "engine": "clamav",
        "status": "ready" if executable.get("verified") else "engine-identity-mismatch",
        "assetSha256": str(asset.get("sha256") or ""),
        "assetRevision": str(transport.get("revision") or ""),
        "executableIdentity": executable,
    }
    (output / "runtime.json").write_text(json.dumps(runtime, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return runtime


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-clamav")
    build.add_argument("--database-dir", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--asset-base-url", required=True)
    build.add_argument("--manifest-output", type=Path, required=True)
    build.add_argument("--executable", default="clamscan")
    materialize = sub.add_parser("materialize-clamav")
    materialize.add_argument("--definitions-root", type=Path, required=True)
    materialize.add_argument("--output", type=Path, required=True)
    materialize.add_argument("--asset-file", type=Path)
    args = parser.parse_args()
    if args.command == "build-clamav":
        result = build_clamav_asset(
            database_dir=args.database_dir, output_dir=args.output_dir, asset_base_url=args.asset_base_url,
            executable=args.executable, manifest_output=args.manifest_output,
        )
    else:
        result = materialize_clamav_asset(definitions_root=args.definitions_root, output=args.output, asset_file=args.asset_file)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
