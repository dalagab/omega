#!/usr/bin/env python3
"""Shared primitives for Omega security-evidence v2.

The v2 format is intentionally transport-oriented rather than query-oriented:
small JSON manifests/indexes describe the current graph while large forensic
collections are emitted as deterministic gzip-compressed JSON Lines shards.
The published root index is written last and acts as the atomic revision pointer.
"""
from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import tempfile
import urllib.parse
from typing import Any, Iterable, Iterator, Sequence

SCHEMA = "omega.security-evidence.v2"
FORMAT_VERSION = 2
DEFAULT_CHUNK_BYTES = 16 * 1024 * 1024
MAX_PUBLISH_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_INLINE_DATASET_BYTES = 4 * 1024 * 1024
JSON_COLUMNS_SUFFIX = "_json"
NUGET_KINDS = ("nuget", "nuget-lock", "nuget-resolved")

TRANSPORT_REPORT_SCHEMA = "omega.security-evidence.scan-summary.v2"
MAX_TRANSPORT_REPORT_BYTES = 256 * 1024


def _bounded_text(value: Any, limit: int = 4096) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _countish_transport(value: Any) -> int:
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def compact_report_for_transport(row: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded summary for legacy ``report_json`` transport.

    The original scanner report duplicates normalized Evidence v2 tables and can be
    tens of MiB.  Variant descriptors only need the small compatibility fields still
    consumed by incremental scanning, source follow-ups and legacy projections.  The
    detailed findings/dependencies/calls/symbols remain in their dedicated v2 datasets.
    """
    raw = row.get("report_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    report = raw if isinstance(raw, dict) else {}

    source = report.get("source") if isinstance(report.get("source"), dict) else {}
    source_provenance = source.get("provenance") if isinstance(source.get("provenance"), dict) else {}
    source_candidates = source.get("candidates") if isinstance(source.get("candidates"), list) else []
    source_intel = source.get("dependencyIntelligence") if isinstance(source.get("dependencyIntelligence"), dict) else {}
    source_fingerprints = source_intel.get("fingerprints") if isinstance(source_intel.get("fingerprints"), dict) else {}
    package = report.get("package") if isinstance(report.get("package"), dict) else {}
    automation = report.get("automation") if isinstance(report.get("automation"), dict) else {}
    intelligence = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
    if not intelligence and isinstance(report.get("intelligence"), dict):
        intelligence = report.get("intelligence")
    scan_provenance = report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {}

    capabilities = automation.get("capabilities") if isinstance(automation.get("capabilities"), list) else []
    compact_caps: list[Any] = []
    for item in capabilities[:128]:
        if isinstance(item, dict):
            compact_caps.append({
                key: item.get(key)
                for key in ("id", "capabilityId", "label", "level", "automationLevel", "confidence", "reachable", "indirect")
                if key in item
            })
        elif isinstance(item, (str, int, float, bool)):
            compact_caps.append(item)

    report_counts_raw = report.get("counts") if isinstance(report.get("counts"), dict) else {}
    report_counts = {
        "informational": int(report_counts_raw.get("informational") or 0),
        "caution": int(report_counts_raw.get("caution") or 0),
        "high": int(report_counts_raw.get("high") or 0),
        "critical": int(report_counts_raw.get("critical") or 0),
    }
    row_counts = {
        "informational": int(row.get("informational_count") or 0),
        "caution": int(row.get("caution_count") or 0),
        "high": int(row.get("high_count") or 0),
        "critical": int(row.get("critical_count") or 0),
    }
    # Early v2 descriptors could carry zeroed current summary columns while the
    # immutable scan report and normalized findings still contained the real static
    # conclusion.  Preserve a non-empty legacy report conclusion when the row is the
    # known empty/stale shape; otherwise current row values remain authoritative so
    # intentional derived current-projection findings are not lost.
    counts = report_counts if not any(row_counts.values()) and any(report_counts.values()) else row_counts
    row_highest = str(row.get("highest_severity") or "none").strip().casefold()
    report_highest = str(report.get("highestSeverity") or "none").strip().casefold()
    highest = report_highest if row_highest in {"", "none"} and report_highest not in {"", "none"} else (row_highest or "none")
    top_capabilities = report.get("capabilities") if isinstance(report.get("capabilities"), list) else []
    compact_top_capabilities = [
        item for item in top_capabilities[:128]
        if isinstance(item, (str, int, float, bool))
    ]
    endpoint_records = intelligence.get("networkEndpoints") if isinstance(intelligence.get("networkEndpoints"), list) else []
    compact_endpoints: list[dict[str, str]] = []
    for endpoint in endpoint_records[:48]:
        if not isinstance(endpoint, dict):
            continue
        compact_endpoints.append({
            "url": _bounded_text(endpoint.get("url"), 2048),
            "host": _bounded_text(endpoint.get("host"), 512),
            "origin": _bounded_text(endpoint.get("origin"), 64),
            "classification": _bounded_text(endpoint.get("classification"), 128),
            "purpose": _bounded_text(endpoint.get("purpose"), 512),
        })

    summary = {
        "schema": TRANSPORT_REPORT_SCHEMA,
        "scannerVersion": str(row.get("scanner_version") or report.get("scannerVersion") or ""),
        "scanProvenance": {
            key: scan_provenance.get(key)
            for key in (
                "schema", "catalogRevision", "catalogIdentityEpoch", "definitionsRevision", "scannerRevision", "scannerBundleSha256", "definitionsSourceCommit", "ruleSetRevision",
                "queueSeedRevision", "queueKey", "targetFingerprint", "primaryReason", "baselineSecurityRebuild",
                "reasons", "attemptId", "attemptNumber", "variantId",
            )
            if key in scan_provenance
        },
        "scannedAtUtc": str(row.get("scanned_at_utc") or report.get("scannedAtUtc") or ""),
        "status": str(row.get("status") or report.get("status") or ""),
        "highestSeverity": highest,
        "counts": counts,
        "capabilities": compact_top_capabilities,
        "source": {
            "available": bool(row.get("source_available") or source.get("available") or False),
            "repository": _bounded_text(row.get("source_repository") or source.get("repository") or "", 8192),
            "commit": _bounded_text(row.get("source_commit") or source.get("commit") or "", 512),
            "branch": _bounded_text(source.get("branch"), 512),
            "treeSha256": _bounded_text(source.get("treeSha256"), 128),
            "candidates": [_bounded_text(item, 8192) for item in source_candidates[:16] if str(item or "")],
            "provenance": {
                key: source_provenance.get(key)
                for key in (
                    "schema", "confidence", "requestedAssemblyVersion", "selectedRef", "selectedRefKind",
                    "manifestPath", "manifestInternalName", "manifestAssemblyVersion", "manifestRepoUrl",
                    "identityMatched", "versionMatched", "manifestRepositoryMatched", "artifactOriginMatched",
                    "repoUrlMatched", "originMatched", "sourceToBinaryVerified", "inheritedViaArtifact",
                    "inheritedArtifactSha256", "inheritedFromVariantId", "distributionSource",
                )
                if key in source_provenance
            },
            "error": _bounded_text(source.get("error"), 8192),
            "dependencyIntelligence": {
                "fingerprints": {
                    "relevantSourceSha256": _bounded_text(source_fingerprints.get("relevantSourceSha256"), 128),
                }
            },
        },
        "package": {
            "archive": _bounded_text(package.get("archive"), 2048),
            "fileCount": _countish_transport(package.get("fileCount") or package.get("files")),
            "uncompressedBytes": _countish_transport(package.get("uncompressedBytes")),
            "bundledExecutableCount": _countish_transport(package.get("bundledExecutableCount") or package.get("bundledExecutables")),
            "bundledManagedAssemblyCount": _countish_transport(package.get("bundledManagedAssemblyCount") or package.get("bundledManagedAssemblies")),
            "bundledNativeLibraryCount": _countish_transport(package.get("bundledNativeLibraryCount") or package.get("bundledNativeLibraries")),
        },
        "automation": {
            "level": str(automation.get("level") or row.get("automation_level") or "none"),
            "capabilities": compact_caps,
        },
        "intelligence": {
            "coverage": intelligence.get("coverage") if isinstance(intelligence.get("coverage"), dict) else {},
            "limits": intelligence.get("limits") if isinstance(intelligence.get("limits"), dict) else {},
            "networkEndpoints": compact_endpoints,
        },
        "error": _bounded_text(row.get("error") or report.get("error") or "", 8192),
    }
    encoded = canonical_json_bytes(summary)
    if len(encoded) > MAX_TRANSPORT_REPORT_BYTES:
        # Coverage/limits are informational compatibility data.  Preserve the fields
        # required by incremental/source workflows first, then drop these optional
        # maps rather than ever allowing a legacy report to inflate a variant file.
        summary["intelligence"] = {"coverage": {}, "limits": {}}
        encoded = canonical_json_bytes(summary)
    if len(encoded) > MAX_TRANSPORT_REPORT_BYTES:
        summary["automation"]["capabilities"] = []
        encoded = canonical_json_bytes(summary)
    if len(encoded) > MAX_TRANSPORT_REPORT_BYTES:
        raise ValueError(f"transport report summary exceeds {MAX_TRANSPORT_REPORT_BYTES} bytes")
    return summary


def transport_security_row(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a scan/current row for bounded Evidence v2 transport."""
    result = dict(row)
    if "report_json" in result:
        result["report_json"] = compact_report_for_transport(result)
    return result

# Core evidence is tied to one scan. Primary keys and scan_id are transport
# identities, not semantic evidence, so they are excluded from record digests.
CORE_DATASETS: tuple[tuple[str, str, str], ...] = (
    ("findings", "plugin_security_findings", "finding_id"),
    ("dependencies", "plugin_security_dependencies", "dependency_id"),
    ("ipc", "plugin_security_ipc_endpoints", "ipc_endpoint_id"),
    ("imports", "plugin_security_imports", "import_id"),
    ("assemblies", "plugin_security_managed_assemblies", "managed_assembly_id"),
    ("symbols", "plugin_security_managed_symbols", "managed_symbol_id"),
    ("calls", "plugin_security_managed_calls", "managed_call_id"),
    ("reachability", "plugin_security_managed_reachability", "reachability_id"),
    ("permissions", "plugin_security_permission_candidates", "candidate_id"),
    ("automation", "plugin_security_automation_capabilities", "automation_capability_id"),
)

LARGE_DATASETS = {"imports", "symbols", "calls", "reachability"}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_value(key: str, value: Any) -> Any:
    if value is None:
        return None
    if key.endswith(JSON_COLUMNS_SUFFIX) and isinstance(value, str):
        text = value.strip()
        if not text:
            return [] if text == "" else value
        try:
            return json.loads(text)
        except Exception:
            # Preserve malformed legacy evidence exactly instead of inventing data.
            return value
    return value


def variant_index_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the small identity/current projection used by the online Developer View.

    The summary intentionally contains no detailed findings, calls, symbols or source text.
    Those remain in the variant/analysis graph and are fetched lazily by developers.
    """
    plugin = payload.get("plugin") if isinstance(payload.get("plugin"), dict) else {}
    variant = payload.get("variant") if isinstance(payload.get("variant"), dict) else {}
    source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    report = current.get("report_json") if isinstance(current.get("report_json"), dict) else {}
    report_source = report.get("source") if isinstance(report.get("source"), dict) else {}
    provenance = report_source.get("provenance") if isinstance(report_source.get("provenance"), dict) else {}
    scan_provenance = report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {}
    return {
        "plugin_id": int(payload.get("pluginId") or plugin.get("plugin_id") or variant.get("plugin_id") or 0),
        "source_id": int(payload.get("sourceId") or source.get("source_id") or variant.get("source_id") or 0),
        "internal_name": str(plugin.get("internal_name") or ""),
        "canonical_name": str(plugin.get("canonical_name") or variant.get("name") or plugin.get("internal_name") or ""),
        "name": str(variant.get("name") or plugin.get("canonical_name") or plugin.get("internal_name") or ""),
        "author": str(variant.get("author") or ""),
        "assembly_version": str(variant.get("assembly_version") or current.get("assembly_version") or ""),
        "source_name": str(source.get("name") or ""),
        "source_url": str(source.get("url") or ""),
        "source_provider": str(source.get("provider") or ""),
        "scan_id": int(current.get("scan_id") or 0),
        "scanner_version": str(current.get("scanner_version") or ""),
        "scan_status": str(current.get("status") or "unscanned"),
        "scanned_at_utc": str(current.get("scanned_at_utc") or ""),
        "highest_severity": str(current.get("highest_severity") or "none"),
        "informational_count": int(current.get("informational_count") or 0),
        "caution_count": int(current.get("caution_count") or 0),
        "high_count": int(current.get("high_count") or 0),
        "critical_count": int(current.get("critical_count") or 0),
        "automation_level": str(current.get("automation_level") or "none"),
        "artifact_sha256": str(current.get("artifact_sha256") or "").strip().lower(),
        "source_available": int(current.get("source_available") or 0),
        "source_repository": str(current.get("source_repository") or ""),
        "source_commit": str(current.get("source_commit") or ""),
        "source_provenance_confidence": str(provenance.get("confidence") or ""),
        "source_identity_matched": bool(provenance.get("identityMatched")),
        "source_version_matched": bool(provenance.get("versionMatched")),
        "source_artifact_origin_matched": bool(provenance.get("artifactOriginMatched")),
        "source_selected_ref": str(provenance.get("selectedRef") or ""),
        "catalog_revision": str(scan_provenance.get("catalogRevision") or ""),
        "definitions_revision": str(scan_provenance.get("definitionsRevision") or ""),
        "definitions_source_commit": str(scan_provenance.get("definitionsSourceCommit") or ""),
        "scanner_revision": str(scan_provenance.get("scannerRevision") or ""),
        "scanner_bundle_sha256": str(scan_provenance.get("scannerBundleSha256") or ""),
        "rule_set_revision": str(scan_provenance.get("ruleSetRevision") or ""),
        "scan_queue_reason": str(scan_provenance.get("primaryReason") or ""),
        "scan_queue_seed_revision": str(scan_provenance.get("queueSeedRevision") or ""),
    }


def normalize_row(row: sqlite3.Row | dict[str, Any], *, exclude: Iterable[str] = ()) -> dict[str, Any]:
    excluded = set(exclude)
    source = dict(row)
    return {key: normalize_value(key, value) for key, value in source.items() if key not in excluded}


def table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def table_columns(db: sqlite3.Connection, name: str) -> list[str]:
    if not table_exists(db, name):
        return []
    return [str(row[1]) for row in db.execute(f'PRAGMA table_info("{name}")')]


def primary_key_column(db: sqlite3.Connection, table: str) -> str | None:
    rows = list(db.execute(f'PRAGMA table_info("{table}")'))
    for row in rows:
        if int(row[5] or 0) == 1:
            return str(row[1])
    return None


def read_meta(db: sqlite3.Connection) -> dict[str, str]:
    if not table_exists(db, "catalog_meta"):
        return {}
    return {str(row[0]): str(row[1]) for row in db.execute("SELECT key,value FROM catalog_meta ORDER BY key")}


def open_ro(path: Path) -> sqlite3.Connection:
    resolved = path.resolve()
    uri = "file:" + urllib.parse.quote(str(resolved).replace("\\", "/"), safe="/:_") + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def safe_relpath(path: str) -> str:
    pure = PurePosixPath(path.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe evidence path: {path!r}")
    return pure.as_posix()


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def write_json(path: Path, value: Any, *, pretty: bool = True) -> dict[str, Any]:
    if pretty:
        data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    else:
        data = canonical_json_bytes(value) + b"\n"
    atomic_write_bytes(path, data)
    return {"path": path.name, "bytes": len(data), "sha256": sha256_bytes(data), "encoding": "json"}


def dataset_record_digest(rows: Iterable[dict[str, Any]]) -> tuple[int, str]:
    row_hashes: list[str] = []
    count = 0
    for row in rows:
        row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
        count += 1
    row_hashes.sort()
    digest = hashlib.sha256()
    for item in row_hashes:
        digest.update(item.encode("ascii"))
        digest.update(b"\n")
    return count, digest.hexdigest()


@dataclass
class ChunkResult:
    path: str
    bytes: int
    sha256: str
    records: int
    record_digest: str
    encoding: str = "jsonl+gzip"

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "records": self.records,
            "recordDigest": self.record_digest,
            "encoding": self.encoding,
        }


class JsonlGzipChunkWriter:
    """Deterministic bounded gzip JSONL writer.

    gzip mtime is fixed at zero so repeated migrations of identical evidence
    produce byte-identical shards. Chunks roll after the compressed file crosses
    the target size; the hard publish ceiling is checked separately.
    """

    def __init__(self, directory: Path, stem: str, *, target_bytes: int = DEFAULT_CHUNK_BYTES):
        self.directory = directory
        self.stem = stem
        self.target_bytes = max(1024 * 1024, int(target_bytes))
        self.directory.mkdir(parents=True, exist_ok=True)
        self._index = 0
        self._raw = None
        self._gzip = None
        self._path: Path | None = None
        self._records = 0
        self._row_hashes: list[str] = []
        self.results: list[ChunkResult] = []

    def _open(self) -> None:
        self._index += 1
        self._path = self.directory / f"{self.stem}-{self._index:04d}.jsonl.gz"
        self._raw = self._path.open("wb")
        self._gzip = gzip.GzipFile(filename="", mode="wb", fileobj=self._raw, compresslevel=6, mtime=0)
        self._records = 0
        self._row_hashes = []

    def _finish(self) -> None:
        if self._gzip is None or self._raw is None or self._path is None:
            return
        self._gzip.close()
        self._raw.close()
        count, digest = dataset_record_digest_from_hashes(self._row_hashes)
        size = self._path.stat().st_size
        self.results.append(ChunkResult(
            path=self._path.name,
            bytes=size,
            sha256=sha256_file(self._path),
            records=count,
            record_digest=digest,
        ))
        self._gzip = None
        self._raw = None
        self._path = None
        self._records = 0
        self._row_hashes = []

    def write(self, row: dict[str, Any]) -> None:
        if self._gzip is None:
            self._open()
        data = canonical_json_bytes(row) + b"\n"
        self._gzip.write(data)
        self._records += 1
        self._row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
        # Flush before measuring compressed position. This is slightly more CPU
        # intensive but keeps shard size bounded for GitHub branch publication.
        self._gzip.flush()
        if self._raw.tell() >= self.target_bytes and self._records > 0:
            self._finish()

    def close(self) -> list[ChunkResult]:
        self._finish()
        return self.results


def dataset_record_digest_from_hashes(row_hashes: Sequence[str]) -> tuple[int, str]:
    ordered = sorted(row_hashes)
    digest = hashlib.sha256()
    for item in ordered:
        digest.update(item.encode("ascii"))
        digest.update(b"\n")
    return len(ordered), digest.hexdigest()


def combine_chunk_record_digests(chunks: Sequence[ChunkResult]) -> tuple[int, str]:
    # Chunk-level record digests cannot be combined into the same multiset digest
    # as all rows, so callers that need an overall digest should track row hashes
    # separately. This helper is only a transport fingerprint.
    payload = [{"records": c.records, "recordDigest": c.record_digest} for c in chunks]
    return sum(c.records for c in chunks), sha256_bytes(canonical_json_bytes(payload))


def file_entry(root: Path, path: Path, *, records: int | None = None, record_digest: str | None = None, encoding: str | None = None) -> dict[str, Any]:
    rel = path.relative_to(root).as_posix()
    result: dict[str, Any] = {
        "path": rel,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    if records is not None:
        result["records"] = int(records)
    if record_digest:
        result["recordDigest"] = record_digest
    if encoding:
        result["encoding"] = encoding
    return result


def verify_file_entry(root: Path, entry: dict[str, Any], *, max_bytes: int | None = None) -> list[str]:
    errors: list[str] = []
    try:
        rel = safe_relpath(str(entry.get("path") or ""))
    except ValueError as exc:
        return [str(exc)]
    path = root / rel
    if not path.is_file():
        return [f"missing file: {rel}"]
    actual_size = path.stat().st_size
    expected_size = int(entry.get("bytes") or -1)
    if actual_size != expected_size:
        errors.append(f"size mismatch for {rel}: manifest={expected_size}, actual={actual_size}")
    if max_bytes is not None and actual_size > max_bytes:
        errors.append(f"file exceeds {max_bytes} byte ceiling: {rel} ({actual_size} bytes)")
    expected_hash = str(entry.get("sha256") or "").lower()
    actual_hash = sha256_file(path)
    if expected_hash != actual_hash:
        errors.append(f"sha256 mismatch for {rel}: manifest={expected_hash}, actual={actual_hash}")
    return errors


def write_record_dataset(
    root: Path,
    directory: Path,
    stem: str,
    rows: Iterable[dict[str, Any]],
    *,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    inline_bytes: int = DEFAULT_INLINE_DATASET_BYTES,
) -> dict[str, Any]:
    """Write a bounded record collection as JSON or deterministic JSONL+gzip shards.

    This is used for evidence that belongs to a current variant but is not part of the
    immutable artifact analysis (for example dependency resolution and OSV projection
    rows).  The descriptor has the same records/digest/files shape as an analysis
    dataset so intrinsic validation can use one contract for both.
    """
    root = root.resolve()
    directory = directory.resolve()
    if directory != root and root not in directory.parents:
        raise ValueError(f"record dataset directory escaped evidence root: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    safe_stem = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in stem).strip(".-") or "records"

    # Remove the previous transport representation for this logical dataset before
    # replacing it, otherwise a JSON -> JSONL transition would leave orphan files.
    for old in directory.glob(f"{safe_stem}*"):
        if old.is_file() and (old.name == f"{safe_stem}.json" or old.name.startswith(f"{safe_stem}-")):
            old.unlink()

    materialized: list[dict[str, Any]] = []
    row_hashes: list[str] = []
    total_uncompressed = 0
    for row in rows:
        normalized = dict(row)
        encoded = canonical_json_bytes(normalized)
        materialized.append(normalized)
        row_hashes.append(sha256_bytes(encoded))
        total_uncompressed += len(encoded) + 1
    count, digest = dataset_record_digest_from_hashes(row_hashes)

    if total_uncompressed <= max(0, int(inline_bytes)):
        path = directory / f"{safe_stem}.json"
        write_json(path, materialized)
        return {
            "records": count,
            "recordDigest": digest,
            "files": [file_entry(root, path, records=count, record_digest=digest, encoding="json")],
        }

    writer = JsonlGzipChunkWriter(directory, safe_stem, target_bytes=chunk_bytes)
    for row in materialized:
        writer.write(row)
    chunks = writer.close()
    return {
        "records": count,
        "recordDigest": digest,
        "files": [
            file_entry(
                root,
                directory / chunk.path,
                records=chunk.records,
                record_digest=chunk.record_digest,
                encoding=chunk.encoding,
            )
            for chunk in chunks
        ],
    }


def read_record_dataset(root: Path, descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    """Read a generic v2 records/digest/files descriptor.

    Hash/size verification remains the validator's job; this helper intentionally only
    performs safe-path parsing and decoding so callers can reconstruct semantic rows.
    """
    rows: list[dict[str, Any]] = []
    for file_info in descriptor.get("files") or []:
        if not isinstance(file_info, dict):
            continue
        rel = safe_relpath(str(file_info.get("path") or ""))
        path = root.resolve() / rel
        encoding = str(file_info.get("encoding") or "")
        if encoding == "json":
            value = json.loads(path.read_text(encoding="utf-8"))
            values = value if isinstance(value, list) else [value]
            rows.extend(item for item in values if isinstance(item, dict))
        elif encoding == "jsonl+gzip":
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(value)
        else:
            raise ValueError(f"unsupported record dataset encoding: {encoding!r}")
    return rows


def row_digest_from_query(db: sqlite3.Connection, sql: str, params: Sequence[Any], *, exclude: Iterable[str]) -> tuple[int, str]:
    row_hashes: list[str] = []
    count = 0
    for row in db.execute(sql, params):
        normalized = normalize_row(row, exclude=exclude)
        row_hashes.append(sha256_bytes(canonical_json_bytes(normalized)))
        count += 1
    return dataset_record_digest_from_hashes(row_hashes)


def read_json_file(root: Path, relative: str) -> Any:
    rel = safe_relpath(relative)
    path = (root / rel).resolve()
    resolved_root = root.resolve()
    if path != resolved_root and resolved_root not in path.parents:
        raise ValueError(f"evidence path escaped root: {relative!r}")
    if not path.is_file():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def read_dataset_rows(root: Path, analysis_path: str, dataset: str) -> list[dict[str, Any]]:
    """Read one v2 analysis dataset and verify its declared files while doing so."""
    manifest = read_json_file(root, f"{safe_relpath(analysis_path)}/manifest.json")
    item = ((manifest.get("datasets") or {}).get(dataset) or {}) if isinstance(manifest, dict) else {}
    rows: list[dict[str, Any]] = []
    for entry in item.get("files") or []:
        errors = verify_file_entry(root, entry, max_bytes=MAX_PUBLISH_FILE_BYTES)
        if errors:
            raise ValueError("; ".join(errors))
        rel = safe_relpath(str(entry.get("path") or ""))
        path = root / rel
        encoding = str(entry.get("encoding") or "")
        if encoding == "json":
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, list):
                rows.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict):
                rows.append(value)
        elif encoding == "jsonl+gzip":
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(value)
        else:
            raise ValueError(f"unsupported v2 evidence encoding {encoding!r} for {rel}")
    return rows


def iter_variant_entries(root: Path) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    index = read_json_file(root, "index.json")
    if index.get("schema") != SCHEMA:
        raise ValueError(f"unsupported evidence schema: {index.get('schema')!r}")
    plugins_entry = ((index.get("indexes") or {}).get("plugins") or {})
    plugins = read_json_file(root, str(plugins_entry.get("path") or "indexes/plugins.json"))
    for entry in plugins.get("currentVariants") or []:
        if not isinstance(entry, dict):
            continue
        payload = read_json_file(root, str(entry.get("variantPath") or ""))
        yield entry, payload


def validate_snapshot(root: Path, *, require_no_orphans: bool = True) -> dict[str, Any]:
    """Validate a published/staged v2 tree without requiring the retired v1 SQLite DB.

    This is the production incremental publication gate. It verifies the atomic root,
    every declared index, every current variant pointer, every analysis manifest and
    shard hash/size, the v2 file-size ceiling, and the root counts. It intentionally
    does not attempt to prove semantic parity with the archived v1 database; that was
    the one-time migration gate.
    """
    root = root.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    index_path = root / "index.json"
    if not index_path.is_file():
        return {
            "schema": "omega.security-evidence.snapshot-validation.v2",
            "ok": False,
            "mode": "intrinsic",
            "errors": ["index.json is missing"],
            "warnings": [],
        }
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "schema": "omega.security-evidence.snapshot-validation.v2",
            "ok": False,
            "mode": "intrinsic",
            "errors": [f"index.json is unreadable: {type(exc).__name__}: {exc}"],
            "warnings": [],
        }
    if index.get("schema") != SCHEMA or int(index.get("formatVersion") or 0) != FORMAT_VERSION:
        errors.append(f"unexpected root schema/version: {index.get('schema')!r}/{index.get('formatVersion')!r}")

    scanner_queue = index.get("scannerQueue") or {}
    if scanner_queue:
        if not isinstance(scanner_queue, dict):
            errors.append("scannerQueue descriptor is not an object")
        else:
            errors.extend(f"scannerQueue: {item}" for item in verify_file_entry(root, scanner_queue, max_bytes=MAX_PUBLISH_FILE_BYTES))
            try:
                queue_doc = read_json_file(root, str(scanner_queue.get("path") or ""))
                if queue_doc.get("schema") != "omega.sigmascope.queue-state.v1":
                    errors.append("scannerQueue payload has an unsupported schema")
            except Exception as exc:
                errors.append(f"scannerQueue unreadable: {type(exc).__name__}: {exc}")

    indexes = index.get("indexes") or {}
    for name, entry in sorted(indexes.items()):
        if not isinstance(entry, dict):
            errors.append(f"index entry {name!r} is not an object")
            continue
        errors.extend(f"index {name}: {item}" for item in verify_file_entry(root, entry, max_bytes=MAX_PUBLISH_FILE_BYTES))

    plugin_entries: list[dict[str, Any]] = []
    try:
        plugins_path = str((indexes.get("plugins") or {}).get("path") or "")
        plugins = read_json_file(root, plugins_path)
        plugin_entries = [item for item in (plugins.get("currentVariants") or []) if isinstance(item, dict)]
    except Exception as exc:  # validation should aggregate rather than abort
        errors.append(f"plugins index unreadable: {type(exc).__name__}: {exc}")

    artifact_index_groups: dict[str, dict[str, Any]] = {}
    try:
        artifacts_path = str((indexes.get("artifacts") or {}).get("path") or "")
        artifacts_index = read_json_file(root, artifacts_path)
        for item in artifacts_index.get("artifacts") or []:
            if not isinstance(item, dict):
                errors.append("artifacts index contains a non-object entry")
                continue
            artifact_key = str(item.get("artifactSha256") or "").strip().lower() or "unknown"
            if artifact_key in artifact_index_groups:
                errors.append(f"duplicate artifact group {artifact_key}")
                continue
            artifact_index_groups[artifact_key] = item
    except Exception as exc:
        errors.append(f"artifacts index unreadable: {type(exc).__name__}: {exc}")

    variant_ids: set[int] = set()
    analysis_ids: set[str] = set()
    referenced_analysis_paths: set[str] = set()
    referenced_files: set[str] = {"index.json"}
    for entry in indexes.values():
        if isinstance(entry, dict) and entry.get("path"):
            try:
                referenced_files.add(safe_relpath(str(entry["path"])))
            except ValueError:
                pass

    def validate_record_descriptor(label: str, dataset: dict[str, Any]) -> None:
        declared_records = int(dataset.get("records") or 0)
        file_records = 0
        row_hashes: list[str] = []
        for file_info in dataset.get("files") or []:
            if not isinstance(file_info, dict):
                errors.append(f"{label}: malformed file entry")
                continue
            errors.extend(f"{label}: {item}" for item in verify_file_entry(root, file_info, max_bytes=MAX_PUBLISH_FILE_BYTES))
            try:
                rel = safe_relpath(str(file_info.get("path") or ""))
                referenced_files.add(rel)
                path = root / rel
                encoding = str(file_info.get("encoding") or "")
                if encoding == "json":
                    value = json.loads(path.read_text(encoding="utf-8"))
                    rows = value if isinstance(value, list) else [value]
                    rows = [row for row in rows if isinstance(row, dict)]
                    for row in rows:
                        row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                    file_records += len(rows)
                elif encoding == "jsonl+gzip":
                    with gzip.open(path, "rt", encoding="utf-8") as stream:
                        for line in stream:
                            if not line.strip():
                                continue
                            row = json.loads(line)
                            if isinstance(row, dict):
                                row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                                file_records += 1
                else:
                    errors.append(f"{label}: unsupported encoding {encoding!r}")
            except Exception as exc:
                errors.append(f"{label}: cannot read records: {type(exc).__name__}: {exc}")
        count, digest = dataset_record_digest_from_hashes(row_hashes)
        if count != declared_records or file_records != declared_records:
            errors.append(f"{label}: record count mismatch declared={declared_records}, read={count}")
        if str(dataset.get("recordDigest") or "") != digest:
            errors.append(f"{label}: semantic record digest mismatch")

    for entry in plugin_entries:
        try:
            variant_id = int(entry.get("variantId") or 0)
            if variant_id <= 0:
                raise ValueError("variantId is missing/invalid")
            if variant_id in variant_ids:
                errors.append(f"duplicate current variant {variant_id}")
                continue
            variant_ids.add(variant_id)
            variant_path = safe_relpath(str(entry.get("variantPath") or ""))
            referenced_files.add(variant_path)
            payload = read_json_file(root, variant_path)
            if int(payload.get("variantId") or 0) != variant_id:
                errors.append(f"variant {variant_id} identity mismatch in {variant_path}")
            declared_variant_sha = str(entry.get("variantSha256") or "").strip().lower()
            if declared_variant_sha and declared_variant_sha != sha256_file(root / variant_path):
                errors.append(f"variant {variant_id} plugins index descriptor SHA mismatch")
            declared_summary = entry.get("summary")
            if declared_summary is not None and declared_summary != variant_index_summary(payload):
                errors.append(f"variant {variant_id} plugins index summary mismatch")
            current = payload.get("current") or {}
            analysis = payload.get("analysis") or {}
            analysis_id = str(analysis.get("analysisId") or "")
            analysis_path = str(analysis.get("path") or "")
            artifact_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").lower().strip()
            artifact_key = str(entry.get("artifactSha256") or artifact_sha or "").lower().strip() or "unknown"
            group = artifact_index_groups.get(artifact_key)
            if group is None:
                errors.append(f"variant {variant_id} references missing artifact group {artifact_key}")
            elif variant_id not in {int(value) for value in (group.get("variants") or []) if str(value).isdigit()}:
                errors.append(f"variant {variant_id} is missing from artifact group {artifact_key}")
            derived_evidence = payload.get("derivedEvidence") or {}
            if not isinstance(derived_evidence, dict):
                errors.append(f"variant {variant_id} derivedEvidence is not an object")
            else:
                for dataset_name, dataset in sorted(derived_evidence.items()):
                    if not isinstance(dataset, dict):
                        errors.append(f"variant {variant_id} derived dataset {dataset_name} is not an object")
                        continue
                    validate_record_descriptor(f"variant {variant_id}/derived/{dataset_name}", dataset)

            if str(current.get("status") or "") == "complete":
                if not analysis_id or not analysis_path:
                    errors.append(f"variant {variant_id} is complete but has no analysis pointer")
                    continue
                if str(entry.get("analysisId") or "") != analysis_id:
                    errors.append(f"variant {variant_id} plugins index analysisId mismatch")
                if str(entry.get("artifactSha256") or "").lower().strip() != artifact_sha:
                    errors.append(f"variant {variant_id} plugins index artifact SHA mismatch")
                analysis_ids.add(analysis_id)
                analysis_path = safe_relpath(analysis_path)
                referenced_analysis_paths.add(analysis_path)
                manifest_rel = f"{analysis_path}/manifest.json"
                referenced_files.add(manifest_rel)
                manifest = read_json_file(root, manifest_rel)
                if group is not None:
                    group_analysis_ids = {str(item.get("analysisId") or "") for item in (group.get("analyses") or []) if isinstance(item, dict)}
                    if analysis_id not in group_analysis_ids:
                        errors.append(f"analysis {analysis_id} is missing from artifact group {artifact_key}")
                if str(manifest.get("analysisId") or "") != analysis_id:
                    errors.append(f"analysis manifest ID mismatch for variant {variant_id}: {analysis_path}")
                if str(manifest.get("artifactSha256") or "").lower().strip() != artifact_sha:
                    errors.append(f"analysis artifact SHA mismatch for variant {variant_id}: {analysis_path}")
                for dataset_name, dataset in sorted((manifest.get("datasets") or {}).items()):
                    if not isinstance(dataset, dict):
                        errors.append(f"analysis {analysis_id} dataset {dataset_name} is not an object")
                        continue
                    declared_records = int(dataset.get("records") or 0)
                    file_records = 0
                    row_hashes: list[str] = []
                    for file_info in dataset.get("files") or []:
                        if not isinstance(file_info, dict):
                            errors.append(f"analysis {analysis_id} dataset {dataset_name} has malformed file entry")
                            continue
                        errors.extend(
                            f"analysis {analysis_id}/{dataset_name}: {item}"
                            for item in verify_file_entry(root, file_info, max_bytes=MAX_PUBLISH_FILE_BYTES)
                        )
                        try:
                            rel = safe_relpath(str(file_info.get("path") or ""))
                            referenced_files.add(rel)
                            path = root / rel
                            encoding = str(file_info.get("encoding") or "")
                            if encoding == "json":
                                value = json.loads(path.read_text(encoding="utf-8"))
                                rows = value if isinstance(value, list) else [value]
                                rows = [row for row in rows if isinstance(row, dict)]
                                for row in rows:
                                    row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                                file_records += len(rows)
                            elif encoding == "jsonl+gzip":
                                with gzip.open(path, "rt", encoding="utf-8") as stream:
                                    for line in stream:
                                        if not line.strip():
                                            continue
                                        row = json.loads(line)
                                        if isinstance(row, dict):
                                            row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                                            file_records += 1
                            else:
                                errors.append(f"analysis {analysis_id}/{dataset_name}: unsupported encoding {encoding!r}")
                        except Exception as exc:
                            errors.append(f"analysis {analysis_id}/{dataset_name}: cannot read records: {type(exc).__name__}: {exc}")
                    count, digest = dataset_record_digest_from_hashes(row_hashes)
                    if count != declared_records or file_records != declared_records:
                        errors.append(
                            f"analysis {analysis_id}/{dataset_name}: record count mismatch declared={declared_records}, read={count}"
                        )
                    if str(dataset.get("recordDigest") or "") != digest:
                        errors.append(f"analysis {analysis_id}/{dataset_name}: semantic record digest mismatch")
        except Exception as exc:
            errors.append(f"current variant entry invalid: {type(exc).__name__}: {exc}")

    counts = index.get("counts") or {}
    expected_counts = {
        "currentVariants": len(variant_ids),
        "analyses": len(analysis_ids),
        "artifactGroups": len(artifact_index_groups),
    }
    for key, actual in expected_counts.items():
        if int(counts.get(key) or 0) != actual:
            errors.append(f"root count mismatch {key}: index={counts.get(key)!r}, actual={actual}")

    # Every published file must be bounded. Orphan analysis objects are rejected for
    # production snapshots so repeated bounded scans cannot regrow branch storage.
    all_files: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith(".git/") or rel.startswith(".staging/") or path.name == ".omega-security-evidence-v2-migration.json":
            continue
        all_files.add(rel)
        if path.stat().st_size > MAX_PUBLISH_FILE_BYTES:
            errors.append(f"published file exceeds {MAX_PUBLISH_FILE_BYTES} byte ceiling: {rel}")
    if require_no_orphans:
        for path in sorted(all_files):
            if path.startswith("artifacts/") and path.endswith("/manifest.json"):
                analysis_dir = path.rsplit("/", 1)[0]
                if analysis_dir not in referenced_analysis_paths:
                    errors.append(f"orphan analysis object is still published: {analysis_dir}")
            if path.startswith("derived/") and path not in referenced_files:
                errors.append(f"orphan derived evidence file is still published: {path}")

    return {
        "schema": "omega.security-evidence.snapshot-validation.v2",
        "ok": not errors,
        "mode": "intrinsic",
        "indexSha256": sha256_file(index_path),
        "evidenceRevision": str((index.get("revisions") or {}).get("evidenceRevision") or ""),
        "checkedVariants": len(variant_ids),
        "checkedAnalyses": len(analysis_ids),
        "errors": errors,
        "warnings": warnings,
    }
