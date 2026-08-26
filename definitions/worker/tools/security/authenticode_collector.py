#!/usr/bin/env python3
"""Bounded Windows-native Authenticode observation collector.

The collector downloads one exact artifact already bound in Security Evidence v2, validates
its SHA-256, safely walks a ZIP (or standalone PE), and calls Windows
Get-AuthenticodeSignature for each PE without loading/executing it.  Platform statuses are
projected conservatively into neutral typed observations; no risk/security verdict is made.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Mapping
import zipfile

SCRIPT_DIR = Path(__file__).resolve().parent
CATALOG_DIR = SCRIPT_DIR.parent / "catalog"
for item in (SCRIPT_DIR, CATALOG_DIR):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import analysis_broker  # noqa: E402
import collector_contracts  # noqa: E402
import collector_results  # noqa: E402
import security_evidence_v2  # noqa: E402
import sigmascope  # noqa: E402

COLLECTOR_ID = "omega.collector.sigmascope.authenticode"
TARGET_SCHEMA = "omega.authenticode.analysis-target.v1"
PROBE_SCHEMA = "omega.authenticode.windows-probe.v1"
MAX_PE_FILES = 2_048
MAX_PE_FILE_BYTES = 128 * 1024 * 1024


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _find_variant(evidence_root: Path, variant_id: int) -> dict[str, Any]:
    matches = []
    for _entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        if int(payload.get("variantId") or 0) == variant_id:
            matches.append(payload)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one current Evidence-v2 variant {variant_id}, found {len(matches)}")
    return matches[0]


def resolve_request(evidence_root: Path, request_value: Mapping[str, Any], *, work_item_id: str = "") -> dict[str, Any]:
    request = analysis_broker.compile_request(request_value)
    if str(request.get("observation") or "") != "binarySignatureTrust":
        raise ValueError("Authenticode collector only accepts binarySignatureTrust requests")
    active = collector_contracts.providers_for("binarySignatureTrust", include_planned=False)
    if COLLECTOR_ID not in active:
        raise ValueError("Authenticode collector is not active in the frozen collector registry")
    subject = request.get("subject") if isinstance(request.get("subject"), Mapping) else {}
    variant_id = int(subject.get("variantId") or 0)
    artifact_sha = str(subject.get("artifactSha256") or "").strip().lower()
    if variant_id <= 0 or len(artifact_sha) != 64:
        raise ValueError("binarySignatureTrust requests require exact subject.variantId + subject.artifactSha256")
    payload = _find_variant(evidence_root.resolve(), variant_id)
    current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
    current_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()
    if current_sha != artifact_sha:
        raise ValueError(f"request artifact does not match current Evidence-v2 variant: request={artifact_sha}, evidence={current_sha}")
    report = current.get("report_json") if isinstance(current.get("report_json"), Mapping) else {}
    manifest = report.get("manifestObservation") if isinstance(report.get("manifestObservation"), Mapping) else {}
    artifact_url = str(manifest.get("downloadUrl") or report.get("artifactUrl") or "").strip()
    if not artifact_url:
        raise ValueError("current Evidence-v2 variant does not retain an artifact download URL")
    # Resolve DNS/HTTPS policy now as well as at download time. This prevents the target
    # envelope from becoming an SSRF-style input to the Windows worker.
    sigmascope.validate_public_https_url(artifact_url)
    return {
        "schema": TARGET_SCHEMA,
        "request": request,
        "workItemId": str(work_item_id or "")[:256],
        "variantId": variant_id,
        "artifactSha256": artifact_sha,
        "artifactUrl": artifact_url,
    }


def _cert_fields(prefix: str, cert: Mapping[str, Any] | None, row: dict[str, Any]) -> None:
    if not isinstance(cert, Mapping):
        return
    mapping = {
        "subject": f"{prefix}Subject" if prefix == "timestamp" else "publisher",
        "issuer": f"{prefix}Issuer" if prefix == "timestamp" else "issuer",
        "thumbprint": f"{prefix}Thumbprint" if prefix == "timestamp" else "thumbprint",
        "serialNumber": "signerSerialNumber" if prefix != "timestamp" else "timestampSerialNumber",
        "notBeforeUtc": "signerNotBeforeUtc" if prefix != "timestamp" else "timestampNotBeforeUtc",
        "notAfterUtc": "signerNotAfterUtc" if prefix != "timestamp" else "timestampNotAfterUtc",
        "signatureAlgorithm": "signerSignatureAlgorithm" if prefix != "timestamp" else "timestampSignatureAlgorithm",
        "publicKeyAlgorithm": "signerPublicKeyAlgorithm" if prefix != "timestamp" else "timestampPublicKeyAlgorithm",
    }
    for source, target in mapping.items():
        value = str(cert.get(source) or "").strip()
        if value:
            row[target] = value[:8192]


def observation_from_platform_record(*, artifact_sha256: str, path: str, file_sha256: str, record: Mapping[str, Any]) -> dict[str, Any]:
    if str(record.get("schema") or "") != PROBE_SCHEMA:
        raise ValueError("unsupported Windows Authenticode probe schema")
    raw_status = str(record.get("status") or "").strip()
    status_key = raw_status.casefold()
    normalized = {
        "valid": "valid",
        "notsigned": "not-signed",
        "hashmismatch": "hash-mismatch",
        "nottrusted": "not-trusted",
        "notsupportedfileformat": "not-supported",
        "unknownerror": "unknown-error",
        "incompatible": "incompatible",
    }.get(status_key, status_key.replace("_", "-") or "unknown")
    row: dict[str, Any] = {
        "artifactSha256": artifact_sha256,
        "path": path,
        "fileSha256": file_sha256,
        "format": "pe",
        "platformStatus": raw_status,
        "platformStatusMessage": str(record.get("statusMessage") or "")[:8192],
        "validationStatus": normalized,
        "timestampPresent": isinstance(record.get("timestamper"), Mapping),
        "validationPlatform": str(record.get("validationPlatform") or "Windows")[:8192],
        "validationMethod": str(record.get("validationMethod") or "Get-AuthenticodeSignature/WinVerifyTrust")[:8192],
        "validationEngineVersion": str(record.get("validationEngineVersion") or "")[:8192],
        "validatedAtUtc": str(record.get("validatedAtUtc") or "")[:8192],
        "validationTrustContext": str(record.get("validationTrustContext") or "current Windows runner trust configuration")[:8192],
        "validationNetworkPolicy": str(record.get("validationNetworkPolicy") or "platform-default")[:8192],
    }
    for optional in ("validationEngineVersion", "validatedAtUtc"):
        if not row[optional]:
            row.pop(optional)
    if status_key == "valid":
        row.update({"signaturePresent": True, "digestValid": True, "chainValid": True})
    elif status_key == "notsigned":
        row["signaturePresent"] = False
    elif status_key == "hashmismatch":
        row.update({"signaturePresent": True, "digestValid": False})
    elif status_key == "nottrusted":
        # WinVerifyTrust has recognized a signature but did not establish platform trust.
        # Do not infer digest validity from this status alone.
        row.update({"signaturePresent": True, "chainValid": False})
    elif isinstance(record.get("signer"), Mapping):
        row["signaturePresent"] = True
    _cert_fields("signer", record.get("signer") if isinstance(record.get("signer"), Mapping) else None, row)
    _cert_fields("timestamp", record.get("timestamper") if isinstance(record.get("timestamper"), Mapping) else None, row)
    return collector_results.validate_observation_row("binarySignatureTrust", row)


def _powershell_executable() -> str:
    for name in ("pwsh", "powershell.exe", "powershell"):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError("Windows PowerShell/PowerShell Core is unavailable")


def probe_pe(path: Path, logical_path: str, artifact_sha256: str) -> dict[str, Any]:
    ps = _powershell_executable()
    proc = subprocess.run(
        [ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT_DIR / "authenticode_probe.ps1"), "-Path", str(path)],
        check=False, text=True, capture_output=True, timeout=60,
    )
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "PowerShell Authenticode probe failed").strip()[:2000]
        raise RuntimeError(message)
    record = json.loads(proc.stdout.strip())
    if not isinstance(record, dict):
        raise RuntimeError("PowerShell Authenticode probe returned a non-object JSON value")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return observation_from_platform_record(
        artifact_sha256=artifact_sha256, path=logical_path, file_sha256=digest, record=record,
    )


def _archive_pe_members(data: bytes) -> list[tuple[str, bytes]]:
    if not data.startswith(b"PK"):
        if not data.startswith(b"MZ"):
            return []
        if len(data) > MAX_PE_FILE_BYTES:
            raise ValueError(f"Standalone PE exceeds {MAX_PE_FILE_BYTES} byte Authenticode limit")
        return [("artifact", data)]
    results: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > sigmascope.MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Archive has {len(infos)} entries; limit is {sigmascope.MAX_ARCHIVE_ENTRIES}")
        seen: set[str] = set()
        total = 0
        for info in infos:
            if not sigmascope.safe_member_name(info.filename):
                raise ValueError(f"Unsafe archive path: {info.filename}")
            normalized = sigmascope.normalized_archive_member_name(info.filename)
            if normalized in seen:
                raise ValueError(f"Archive contains a duplicate normalized path: {info.filename}")
            seen.add(normalized)
            if sigmascope.archive_member_is_symlink(info):
                raise ValueError(f"Archive contains a symbolic-link entry: {info.filename}")
            if info.flag_bits & 0x1:
                raise ValueError(f"Encrypted archive entries are not inspected: {info.filename}")
            total += max(0, info.file_size)
        if total > sigmascope.MAX_ARCHIVE_UNCOMPRESSED:
            raise ValueError("Archive exceeds uncompressed size limit")
        for info in infos:
            if info.is_dir() or info.file_size <= 0:
                continue
            if info.compress_size > 0 and info.file_size / info.compress_size > 500:
                raise ValueError(f"Suspicious compression ratio: {info.filename}")
            with archive.open(info) as stream:
                prefix = stream.read(2)
                if prefix != b"MZ":
                    continue
                if info.file_size > MAX_PE_FILE_BYTES:
                    raise ValueError(f"PE member exceeds {MAX_PE_FILE_BYTES} byte Authenticode limit: {info.filename}")
                rest = stream.read(MAX_PE_FILE_BYTES + 1)
                raw = prefix + rest
                if len(raw) != info.file_size:
                    raise ValueError(f"PE member size changed while reading: {info.filename}")
            results.append((info.filename.replace("\\", "/"), raw))
            if len(results) > MAX_PE_FILES:
                raise ValueError(f"Archive contains more than {MAX_PE_FILES} PE files")
    return results


def _probe_suffix(logical_path: str) -> str:
    suffix = Path(str(logical_path or "")).suffix.lower()
    if suffix and len(suffix) <= 16 and re.fullmatch(r"\.[a-z0-9._-]+", suffix):
        return suffix
    return ".bin"


def collect(target: Mapping[str, Any], *, github_token: str = "") -> dict[str, Any]:
    if str(target.get("schema") or "") != TARGET_SCHEMA:
        raise ValueError(f"target schema must be {TARGET_SCHEMA}")
    request = target.get("request") if isinstance(target.get("request"), Mapping) else {}
    expected_sha = str(target.get("artifactSha256") or "").strip().lower()
    artifact, _final_url = sigmascope.request_bytes(str(target.get("artifactUrl") or ""), sigmascope.MAX_ARTIFACT_BYTES, token=github_token)
    actual_sha = hashlib.sha256(artifact).hexdigest()
    if actual_sha != expected_sha:
        raise RuntimeError(f"downloaded artifact SHA-256 mismatch: expected={expected_sha}, actual={actual_sha}")
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="omega-authenticode-") as temp_name:
        temp = Path(temp_name)
        for index, (logical_path, raw) in enumerate(_archive_pe_members(artifact), start=1):
            file_path = temp / f"pe-{index:04d}{_probe_suffix(logical_path)}"
            file_path.write_bytes(raw)
            try:
                rows.append(probe_pe(file_path, logical_path, expected_sha))
            except Exception as exc:
                file_sha = hashlib.sha256(raw).hexdigest()
                errors.append(f"{logical_path}: {type(exc).__name__}: {exc}"[:2000])
                rows.append(collector_results.validate_observation_row("binarySignatureTrust", {
                    "artifactSha256": expected_sha,
                    "path": logical_path,
                    "fileSha256": file_sha,
                    "format": "pe",
                    "validationStatus": "probe-error",
                    "platformStatus": "ProbeError",
                    "platformStatusMessage": str(exc)[:8192],
                }))
    return collector_results.build_result(
        request,
        collector_id=COLLECTOR_ID,
        collections={"binarySignatureTrust": rows},
        work_item_id=str(target.get("workItemId") or ""),
        status="partial" if errors else "complete",
        errors=errors,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect exact Windows Authenticode observations without executing PE files")
    sub = parser.add_subparsers(dest="command", required=True)
    p_resolve = sub.add_parser("resolve")
    p_resolve.add_argument("--evidence-root", type=Path, required=True)
    p_resolve.add_argument("--request", type=Path, required=True)
    p_resolve.add_argument("--work-item-id", default="")
    p_resolve.add_argument("--output", type=Path, required=True)
    p_collect = sub.add_parser("collect")
    p_collect.add_argument("--target", type=Path, required=True)
    p_collect.add_argument("--output", type=Path, required=True)
    p_collect.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""))
    args = parser.parse_args()
    if args.command == "resolve":
        result = resolve_request(args.evidence_root, _load(args.request), work_item_id=args.work_item_id)
    else:
        result = collect(_load(args.target), github_token=args.github_token)
    _write(args.output, result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
