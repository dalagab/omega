#!/usr/bin/env python3
"""Read-only readers for published Security Evidence v2 contract indexes.

This module belongs to the producer/security-services side. It intentionally exposes
only neutral Evidence-v2 contracts and has no DeltaScope UI or local-state dependency.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from .security_evidence_v2 import (
        canonical_json_bytes,
        dataset_record_digest,
        read_json_file,
        read_record_dataset,
        safe_relpath,
        sha256_bytes,
        verify_file_entry,
    )
except ImportError:
    from security_evidence_v2 import (  # type: ignore
        canonical_json_bytes,
        dataset_record_digest,
        read_json_file,
        read_record_dataset,
        safe_relpath,
        sha256_bytes,
        verify_file_entry,
    )

RELATIONSHIP_SCHEMAS = {
    "omega.security-evidence.workbench-relationships.v1",
    "omega.security-evidence.workbench-relationships.v2",
}


def read_workbench_relationship_index(root: Path) -> dict[str, Any]:
    root = root.resolve()
    index = read_json_file(root, "index.json")
    indexes = index.get("indexes") if isinstance(index.get("indexes"), dict) else {}
    meta = indexes.get("workbenchRelationships") if isinstance(indexes.get("workbenchRelationships"), dict) else {}
    rel = safe_relpath(str(meta.get("path") or "")) if meta.get("path") else ""
    if not rel:
        return {
            "schema": "omega.security-evidence.workbench-relationships.v2",
            "relationshipRevision": "",
            "readOnly": True,
            "mutationAuthority": "none",
            "policyInput": False,
            "counts": {"endpoints": 0, "components": 0, "advisories": 0},
            "endpoints": [], "components": [], "advisories": [],
        }
    errors = verify_file_entry(root, dict(meta))
    if errors:
        raise ValueError("; ".join(errors))
    value = read_json_file(root, rel)
    if not isinstance(value, dict):
        raise ValueError("workbench relationship index must be an object")
    schema = str(value.get("schema") or "")
    if schema not in RELATIONSHIP_SCHEMAS:
        raise ValueError("unsupported workbench relationship index schema")
    if value.get("readOnly") is not True or str(value.get("mutationAuthority") or "") != "none" or bool(value.get("policyInput")):
        raise ValueError("workbench relationship index violates the read-only contract")
    if schema.endswith(".v1"):
        return value
    if str(value.get("storage") or "") != "sharded-jsonl-gzip":
        raise ValueError("unsupported workbench relationship storage")
    datasets = value.get("datasets") if isinstance(value.get("datasets"), dict) else {}
    rows: dict[str, list[dict[str, Any]]] = {}
    counts = value.get("counts") if isinstance(value.get("counts"), dict) else {}
    for name in ("endpoints", "components", "advisories"):
        descriptor = datasets.get(name) if isinstance(datasets.get(name), dict) else {}
        for item in descriptor.get("files") or []:
            if not isinstance(item, dict):
                raise ValueError(f"malformed {name} relationship shard descriptor")
            file_errors = verify_file_entry(root, item)
            if file_errors:
                raise ValueError("; ".join(file_errors))
        records = read_record_dataset(root, descriptor)
        record_count, record_digest = dataset_record_digest(records)
        if int(descriptor.get("records") or 0) != record_count:
            raise ValueError(f"workbenchRelationships {name} record count mismatch")
        if str(descriptor.get("recordDigest") or "") != record_digest:
            raise ValueError(f"workbenchRelationships {name} semantic record digest mismatch")
        if int(counts.get(name) or 0) != len(records):
            raise ValueError(f"workbenchRelationships {name} count mismatch")
        rows[name] = records
    semantic_core = {name: rows[name] for name in ("endpoints", "components", "advisories")}
    expected_revision = "workbench-rel-v2-" + sha256_bytes(canonical_json_bytes(semantic_core))[:20]
    if str(value.get("relationshipRevision") or "") != expected_revision:
        raise ValueError("workbenchRelationships semantic revision mismatch")
    if str(meta.get("relationshipRevision") or "") != expected_revision:
        raise ValueError("workbenchRelationships root relationshipRevision mismatch")
    return {**value, **rows}
