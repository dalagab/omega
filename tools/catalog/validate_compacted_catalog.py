#!/usr/bin/env python3
"""Validate a compacted Omega catalog locally or after publication."""
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

import compact_sqlite_catalog
from catalog_revisions import CATALOG_REVISION_SCHEMA, CHANGELOG_SCHEMA, SECURITY_REVISION_SCHEMA


def validate_database_bytes(raw: bytes, descriptor: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    if descriptor.get("compactorVersion") != compact_sqlite_catalog.COMPACTOR_VERSION:
        raise RuntimeError("descriptor compactor version does not match implementation")
    if report.get("compactorVersion") != compact_sqlite_catalog.COMPACTOR_VERSION:
        raise RuntimeError("compaction report version does not match implementation")
    if hashlib.sha256(raw).hexdigest() != descriptor.get("catalogSha256"):
        raise RuntimeError("catalog SHA-256 does not match descriptor")
    if len(raw) != int(descriptor.get("databaseBytes", -1)):
        raise RuntimeError("database byte count does not match descriptor")

    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        Path(path).write_bytes(raw)
        with closing(sqlite3.connect(path)) as db:
            integrity = db.execute("PRAGMA integrity_check").fetchone()
            if not integrity or str(integrity[0]).lower() != "ok":
                raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
            foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_keys:
                raise RuntimeError(f"foreign key violations: {len(foreign_keys)}")
            version = db.execute("SELECT value FROM catalog_meta WHERE key='database_compactor_version'").fetchone()
            if not version or version[0] != compact_sqlite_catalog.COMPACTOR_VERSION:
                raise RuntimeError("database compactor metadata is missing or stale")
            schema = db.execute("SELECT value FROM catalog_meta WHERE key='security_report_payload_schema'").fetchone()
            if not schema or schema[0] != compact_sqlite_catalog.SUMMARY_SCHEMA:
                raise RuntimeError("security report payload schema metadata is missing or stale")
            max_scan = db.execute("SELECT COALESCE(MAX(LENGTH(report_json)),0) FROM plugin_security_scans").fetchone()[0]
            max_current = db.execute("SELECT COALESCE(MAX(LENGTH(report_json)),0) FROM plugin_security_current").fetchone()[0]
            if max_scan > compact_sqlite_catalog.MAX_SUMMARY_BYTES or max_current > compact_sqlite_catalog.MAX_SUMMARY_BYTES:
                raise RuntimeError("compacted report JSON exceeds the configured summary ceiling")
            meta = dict(db.execute("SELECT key,value FROM catalog_meta"))
            catalog_revision = str(meta.get("catalog_revision", ""))
            security_revision = str(meta.get("security_revision", ""))
            if descriptor.get("catalogRevision") != catalog_revision or not catalog_revision.startswith("cat-v1-"):
                raise RuntimeError("descriptor catalogRevision does not match compacted database")
            if descriptor.get("securityRevision") != security_revision or not security_revision.startswith("sec-"):
                raise RuntimeError("descriptor securityRevision does not match compacted database")
            if meta.get("catalog_revision_schema") != CATALOG_REVISION_SCHEMA or meta.get("security_revision_schema") != SECURITY_REVISION_SCHEMA:
                raise RuntimeError("compacted database revision schema metadata is missing")
            if meta.get("catalog_changelog_schema") != CHANGELOG_SCHEMA:
                raise RuntimeError("compacted database changelog schema metadata is missing")
            if db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='catalog_changelog'").fetchone()[0] != 1:
                raise RuntimeError("compacted database is missing catalog_changelog")
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    revisions = report.get("revisions") or {}
    if revisions.get("catalogRevision") != descriptor.get("catalogRevision") or revisions.get("securityRevision") != descriptor.get("securityRevision"):
        raise RuntimeError("compaction report revisions do not match descriptor")
    publication = report.get("publication") or {}
    if not isinstance(publication.get("required"), bool):
        raise RuntimeError("compaction report publication decision is missing")
    return {"integrity": "ok", "databaseBytes": len(raw), "maxSummaryBytes": max(max_scan, max_current), "catalogRevision": descriptor.get("catalogRevision"), "securityRevision": descriptor.get("securityRevision"), "publicationRequired": publication.get("required")}


def validate_bundle(bundle: bytes, descriptor: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    if hashlib.sha256(bundle).hexdigest() != descriptor.get("bundleSha256"):
        raise RuntimeError("bundle SHA-256 does not match descriptor")
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        if archive.namelist() != ["omega-catalog.sqlite"]:
            raise RuntimeError("compacted bundle must contain exactly omega-catalog.sqlite")
        raw = archive.read("omega-catalog.sqlite")
    return {"bundleBytes": len(bundle), **validate_database_bytes(raw, descriptor, report)}


def validate_local(root: Path) -> dict[str, Any]:
    descriptor = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    report = json.loads((root / "compaction-report.json").read_text(encoding="utf-8"))
    raw = (root / "omega-catalog.sqlite").read_bytes()
    bundle = (root / "omega-catalog.sqlite.zip").read_bytes()
    if descriptor.get("databaseBytes") != report.get("databaseBytesAfter"):
        raise RuntimeError("descriptor and compaction report disagree about database size")
    if descriptor.get("compactionSavedBytes") != report.get("databaseBytesSaved"):
        raise RuntimeError("descriptor and compaction report disagree about saved bytes")
    validation = report.get("validation") or {}
    if not validation.get("runtimeProjectionSha256"):
        raise RuntimeError("compaction report is missing runtime projection validation")
    result = validate_bundle(bundle, descriptor, report)
    if hashlib.sha256(raw).hexdigest() != descriptor.get("catalogSha256"):
        raise RuntimeError("local extracted database SHA-256 does not match descriptor")
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        if archive.read("omega-catalog.sqlite") != raw:
            raise RuntimeError("local bundle and extracted database differ")
    return result


def validate_published(base_url: str) -> dict[str, Any]:
    base = base_url.rstrip("/") + "/"
    descriptor = json.load(urllib.request.urlopen(base + "catalog.json"))
    report = json.load(urllib.request.urlopen(base + "compaction-report.json"))
    bundle = urllib.request.urlopen(base + "omega-catalog.sqlite.zip").read()
    return validate_bundle(bundle, descriptor, report)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an Omega compacted catalog")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--root", type=Path)
    source.add_argument("--base-url")
    args = parser.parse_args()
    result = validate_local(args.root) if args.root else validate_published(args.base_url)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
