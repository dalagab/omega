"""Bounded transport for the published Security Evidence plugin navigation index.

The logical plugin index is small enough to query as records but no longer small enough
to publish as one JSON document. Version 3 keeps a tiny JSON manifest and stores the
current/terminal/history collections as deterministic bounded gzip JSONL shards.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any, Iterable, Iterator

try:
    from .security_evidence_v2 import (
        DEFAULT_CHUNK_BYTES,
        MAX_PUBLISH_FILE_BYTES,
        SCHEMA,
        JsonlGzipChunkWriter,
        canonical_json_bytes,
        dataset_record_digest_from_hashes,
        file_entry,
        read_json_file,
        safe_relpath,
        sha256_bytes,
        verify_file_entry,
        write_json,
    )
except ImportError:
    from security_evidence_v2 import (  # type: ignore
        DEFAULT_CHUNK_BYTES,
        MAX_PUBLISH_FILE_BYTES,
        SCHEMA,
        JsonlGzipChunkWriter,
        canonical_json_bytes,
        dataset_record_digest_from_hashes,
        file_entry,
        read_json_file,
        safe_relpath,
        sha256_bytes,
        verify_file_entry,
        write_json,
    )

PLUGIN_INDEX_LEGACY_SCHEMA = "omega.security-evidence.plugins-index.v2"
PLUGIN_INDEX_SCHEMA = "omega.security-evidence.plugins-index.v3"
PLUGIN_INDEX_STORAGE = "sharded-jsonl-gzip"
PLUGIN_INDEX_DATASETS = ("currentVariants", "terminalVariants", "historicalSnapshots")

_STEMS = {
    "currentVariants": "current-variants",
    "terminalVariants": "terminal-variants",
    "historicalSnapshots": "historical-snapshots",
}


def _write_sharded_dataset(
    root: Path,
    directory: Path,
    stem: str,
    rows: Iterable[dict[str, Any]],
    *,
    chunk_bytes: int,
) -> dict[str, Any]:
    root = root.resolve()
    directory = directory.resolve()
    if directory != root and root not in directory.parents:
        raise ValueError(f"plugin index directory escaped evidence root: {directory}")
    directory.mkdir(parents=True, exist_ok=True)

    for old in directory.glob(f"{stem}*"):
        if old.is_file() and (old.name == f"{stem}.json" or old.name.startswith(f"{stem}-")):
            old.unlink()

    writer = JsonlGzipChunkWriter(directory, stem, target_bytes=chunk_bytes)
    row_hashes: list[str] = []
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError(f"plugin index {stem} contains a non-object record")
        row = dict(raw)
        row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
        writer.write(row)
    chunks = writer.close()
    count, digest = dataset_record_digest_from_hashes(row_hashes)
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


def write_plugin_index(
    root: Path,
    *,
    current_variants: Iterable[dict[str, Any]],
    terminal_variants: Iterable[dict[str, Any]] = (),
    historical_snapshots: Iterable[dict[str, Any]] = (),
    lifecycle_contract_version: int = 0,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> dict[str, Any]:
    """Write a tiny plugins.json manifest plus deterministic bounded data shards."""
    root = root.resolve()
    rows_by_name = {
        "currentVariants": current_variants,
        "terminalVariants": terminal_variants,
        "historicalSnapshots": historical_snapshots,
    }
    directory = root / "indexes" / "plugins"
    datasets: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for name in PLUGIN_INDEX_DATASETS:
        descriptor = _write_sharded_dataset(
            root,
            directory,
            _STEMS[name],
            rows_by_name[name],
            chunk_bytes=chunk_bytes,
        )
        datasets[name] = descriptor
        counts[name] = int(descriptor["records"])

    manifest = {
        "schema": PLUGIN_INDEX_SCHEMA,
        "storage": PLUGIN_INDEX_STORAGE,
        "lifecycleContractVersion": int(lifecycle_contract_version),
        "counts": counts,
        "datasets": datasets,
    }
    manifest_path = root / "indexes" / "plugins.json"
    write_json(manifest_path, manifest)
    entry = file_entry(
        root,
        manifest_path,
        records=sum(counts.values()),
        encoding="json",
    )
    entry.update({
        "pluginIndexSchema": PLUGIN_INDEX_SCHEMA,
        "storage": PLUGIN_INDEX_STORAGE,
        "counts": dict(counts),
    })
    return entry


def _load_manifest(root: Path, *, verify_root: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    root = root.resolve()
    index = read_json_file(root, "index.json")
    if index.get("schema") != SCHEMA:
        raise ValueError(f"unsupported evidence schema: {index.get('schema')!r}")
    indexes = index.get("indexes") if isinstance(index.get("indexes"), dict) else {}
    meta = indexes.get("plugins") if isinstance(indexes.get("plugins"), dict) else {}
    rel = safe_relpath(str(meta.get("path") or "indexes/plugins.json"))
    if verify_root:
        errors = verify_file_entry(root, meta, max_bytes=MAX_PUBLISH_FILE_BYTES)
        if errors:
            raise ValueError("; ".join(errors))
    manifest = read_json_file(root, rel)
    if not isinstance(manifest, dict):
        raise ValueError("plugins index must be an object")
    schema = str(manifest.get("schema") or "")
    if schema not in {PLUGIN_INDEX_LEGACY_SCHEMA, PLUGIN_INDEX_SCHEMA}:
        raise ValueError(f"unsupported plugins index schema: {schema!r}")
    if schema == PLUGIN_INDEX_SCHEMA:
        if str(manifest.get("storage") or "") != PLUGIN_INDEX_STORAGE:
            raise ValueError("unsupported plugins index storage")
        counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
        if verify_root:
            if meta.get("pluginIndexSchema") and str(meta.get("pluginIndexSchema")) != PLUGIN_INDEX_SCHEMA:
                raise ValueError("plugins root schema descriptor mismatch")
            if meta.get("storage") and str(meta.get("storage")) != PLUGIN_INDEX_STORAGE:
                raise ValueError("plugins root storage descriptor mismatch")
            root_counts = meta.get("counts") if isinstance(meta.get("counts"), dict) else {}
            if root_counts and root_counts != counts:
                raise ValueError("plugins root counts descriptor mismatch")
    return meta, manifest


def _iter_v3_dataset(root: Path, manifest: dict[str, Any], dataset_name: str) -> Iterator[dict[str, Any]]:
    datasets = manifest.get("datasets") if isinstance(manifest.get("datasets"), dict) else {}
    descriptor = datasets.get(dataset_name) if isinstance(datasets.get(dataset_name), dict) else {}
    if not descriptor:
        raise ValueError(f"plugins dataset {dataset_name} is missing")
    all_hashes: list[str] = []
    total = 0
    for file_info in descriptor.get("files") or []:
        if not isinstance(file_info, dict):
            raise ValueError(f"plugins dataset {dataset_name} has malformed file metadata")
        errors = verify_file_entry(root, file_info, max_bytes=MAX_PUBLISH_FILE_BYTES)
        if errors:
            raise ValueError("; ".join(errors))
        if str(file_info.get("encoding") or "") != "jsonl+gzip":
            raise ValueError(f"plugins dataset {dataset_name} has unsupported encoding")
        rel = safe_relpath(str(file_info.get("path") or ""))
        file_hashes: list[str] = []
        file_count = 0
        with gzip.open(root / rel, "rt", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"plugins dataset {dataset_name} contains a non-object record")
                row_hash = sha256_bytes(canonical_json_bytes(value))
                file_hashes.append(row_hash)
                all_hashes.append(row_hash)
                file_count += 1
                total += 1
                yield value
        actual_file_count, actual_file_digest = dataset_record_digest_from_hashes(file_hashes)
        if int(file_info.get("records") or 0) != actual_file_count:
            raise ValueError(f"plugins dataset {dataset_name} shard record count mismatch")
        if str(file_info.get("recordDigest") or "") != actual_file_digest:
            raise ValueError(f"plugins dataset {dataset_name} shard semantic digest mismatch")
    actual_count, actual_digest = dataset_record_digest_from_hashes(all_hashes)
    if int(descriptor.get("records") or 0) != actual_count or total != actual_count:
        raise ValueError(f"plugins dataset {dataset_name} record count mismatch")
    if str(descriptor.get("recordDigest") or "") != actual_digest:
        raise ValueError(f"plugins dataset {dataset_name} semantic digest mismatch")
    counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
    if int(counts.get(dataset_name) or 0) != actual_count:
        raise ValueError(f"plugins dataset {dataset_name} manifest count mismatch")


def iter_plugin_index_records(root: Path, dataset_name: str) -> Iterator[dict[str, Any]]:
    if dataset_name not in PLUGIN_INDEX_DATASETS:
        raise ValueError(f"unsupported plugin index dataset: {dataset_name}")
    root = root.resolve()
    _meta, manifest = _load_manifest(root)
    schema = str(manifest.get("schema") or "")
    if schema == PLUGIN_INDEX_LEGACY_SCHEMA:
        values = manifest.get(dataset_name)
        if values is None and dataset_name != "currentVariants":
            values = []
        if not isinstance(values, list):
            raise ValueError(f"legacy plugins dataset {dataset_name} is not an array")
        for value in values:
            if not isinstance(value, dict):
                raise ValueError(f"legacy plugins dataset {dataset_name} contains a non-object record")
            yield dict(value)
        return
    yield from _iter_v3_dataset(root, manifest, dataset_name)


def read_plugin_index(root: Path, *, verify_root: bool = True) -> dict[str, Any]:
    root = root.resolve()
    meta, manifest = _load_manifest(root, verify_root=verify_root)
    schema = str(manifest.get("schema") or "")
    if schema == PLUGIN_INDEX_LEGACY_SCHEMA:
        result = dict(manifest)
        result.setdefault("terminalVariants", [])
        result.setdefault("historicalSnapshots", [])
        return result
    rows = {name: list(_iter_v3_dataset(root, manifest, name)) for name in PLUGIN_INDEX_DATASETS}
    if verify_root and "records" in meta and int(meta.get("records") or 0) != sum(len(rows[name]) for name in PLUGIN_INDEX_DATASETS):
        raise ValueError("plugins root record count mismatch")
    return {**manifest, **rows}


def convert_plugin_index_in_place(root: Path, *, chunk_bytes: int = DEFAULT_CHUNK_BYTES) -> dict[str, Any]:
    root = root.resolve()
    logical = read_plugin_index(root)
    current_root = read_json_file(root, "index.json")
    plugin_meta = ((current_root.get("indexes") or {}).get("plugins") or {})
    before_path = root / safe_relpath(str(plugin_meta.get("path") or "indexes/plugins.json"))
    before_bytes = before_path.stat().st_size
    entry = write_plugin_index(
        root,
        current_variants=logical.get("currentVariants") or [],
        terminal_variants=logical.get("terminalVariants") or [],
        historical_snapshots=logical.get("historicalSnapshots") or [],
        lifecycle_contract_version=int(logical.get("lifecycleContractVersion") or 0),
        chunk_bytes=chunk_bytes,
    )
    current_root.setdefault("indexes", {})["plugins"] = entry
    write_json(root / "index.json", current_root)
    manifest = read_json_file(root, "indexes/plugins.json")
    shard_bytes = sum(int(item.get("bytes") or 0) for descriptor in (manifest.get("datasets") or {}).values() if isinstance(descriptor, dict) for item in descriptor.get("files") or [] if isinstance(item, dict))
    manifest_bytes = (root / "indexes" / "plugins.json").stat().st_size
    return {
        "beforeManifestBytes": before_bytes,
        "afterManifestBytes": manifest_bytes,
        "afterShardBytes": shard_bytes,
        "afterTransportBytes": manifest_bytes + shard_bytes,
        "counts": manifest.get("counts") or {},
        "schema": manifest.get("schema"),
        "storage": manifest.get("storage"),
    }
