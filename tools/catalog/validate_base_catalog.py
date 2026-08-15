#!/usr/bin/env python3
"""Validate the base SQLite catalog produced before security enrichment."""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


def validate_database(database: Path) -> dict[str, Any]:
    with closing(sqlite3.connect(database)) as db:
        integrity = db.execute("PRAGMA integrity_check").fetchone()
        if not integrity or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
        version = db.execute("SELECT value FROM catalog_meta WHERE key='schema_version'").fetchone()
        if not version or int(version[0]) != 1:
            raise RuntimeError("unexpected SQLite catalog schema version")
        variants = int(db.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0])
        if variants <= 0:
            raise RuntimeError("runtime_plugin_variants is empty")
        meta = dict(db.execute("SELECT key,value FROM catalog_meta"))
        if not str(meta.get("catalog_base_revision", "")).startswith("base-v1-"):
            raise RuntimeError("base catalog is missing catalog_base_revision")
        if db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='catalog_changelog'").fetchone()[0] != 1:
            raise RuntimeError("base catalog is missing catalog_changelog")
    return {"integrity": "ok", "variantCount": variants, "metadata": meta}


def validate_bundle(bundle: bytes, descriptor: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    if hashlib.sha256(bundle).hexdigest() != descriptor.get("bundleSha256"):
        raise RuntimeError("bundle SHA-256 does not match descriptor")
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        if archive.namelist() != ["omega-catalog.sqlite"]:
            raise RuntimeError("catalog bundle must contain exactly omega-catalog.sqlite")
        raw = archive.read("omega-catalog.sqlite")
    if hashlib.sha256(raw).hexdigest() != descriptor.get("catalogSha256"):
        raise RuntimeError("catalog SHA-256 does not match descriptor")
    return raw, {"bundleBytes": len(bundle), "databaseBytes": len(raw)}


def _validate_raw_database(raw: bytes) -> dict[str, Any]:
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        Path(path).write_bytes(raw)
        return validate_database(Path(path))
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def validate_local(root: Path) -> dict[str, Any]:
    descriptor = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    database = root / "omega-catalog.sqlite"
    bundle = (root / "omega-catalog.sqlite.zip").read_bytes()
    raw, transport = validate_bundle(bundle, descriptor)
    if database.read_bytes() != raw:
        raise RuntimeError("bundle database and extracted database differ")
    database_result = validate_database(database)
    if descriptor.get("catalogBaseRevision") != database_result["metadata"].get("catalog_base_revision"):
        raise RuntimeError("descriptor catalogBaseRevision does not match database metadata")
    return {"database": database_result, "transport": transport}


def validate_published(base_url: str) -> dict[str, Any]:
    base = base_url.rstrip("/") + "/"
    descriptor = json.load(urllib.request.urlopen(base + "catalog.json"))
    bundle = urllib.request.urlopen(base + "omega-catalog.sqlite.zip").read()
    raw, transport = validate_bundle(bundle, descriptor)
    return {"database": _validate_raw_database(raw), "transport": transport}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an Omega base SQLite catalog")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--root", type=Path)
    source.add_argument("--base-url")
    args = parser.parse_args()
    result = validate_local(args.root) if args.root else validate_published(args.base_url)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
