#!/usr/bin/env python3
"""Fail-closed validation for Omega's client marketplace SQLite bundle."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import urllib.request
import zipfile

BUNDLE_NAME = "omega-marketplace.sqlite.zip"
DESCRIPTOR_NAME = "catalog.json"
INTERNAL_DB_NAME = "omega-catalog.sqlite"
FORBIDDEN_PREFIX = "plugin_security_"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_bytes(descriptor_bytes: bytes, bundle: bytes) -> dict:
    descriptor = json.loads(descriptor_bytes.decode("utf-8"))
    if descriptor.get("schema") != "omega.catalog.sqlite.v1" or int(descriptor.get("schemaVersion") or 0) != 1:
        raise RuntimeError("unsupported marketplace descriptor schema")
    if descriptor.get("databaseRole") != "marketplace":
        raise RuntimeError("catalog descriptor is not a marketplace projection")
    if descriptor.get("detailedSecurityEvidenceIncluded") is not False:
        raise RuntimeError("marketplace descriptor must explicitly exclude detailed security evidence")
    if sha256(bundle) != str(descriptor.get("bundleSha256") or ""):
        raise RuntimeError("marketplace bundle SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        if archive.namelist() != [INTERNAL_DB_NAME]:
            raise RuntimeError("marketplace bundle must contain exactly omega-catalog.sqlite")
        raw = archive.read(INTERNAL_DB_NAME)
    if sha256(raw) != str(descriptor.get("catalogSha256") or ""):
        raise RuntimeError("marketplace database SHA-256 mismatch")
    with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
        tmp.write(raw); tmp.flush()
        db = sqlite3.connect(tmp.name)
        try:
            if str(db.execute("PRAGMA integrity_check").fetchone()[0]).lower() != "ok":
                raise RuntimeError("marketplace integrity_check failed")
            if int(db.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0]) <= 0:
                raise RuntimeError("marketplace runtime projection is empty")
            if int(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='marketplace_security_current'").fetchone()[0]) != 1:
                raise RuntimeError("marketplace current-security summary table is missing")
            security_columns = {row[1] for row in db.execute("PRAGMA table_info(marketplace_security_current)")}
            for required in ("dependencies_json", "dependency_total_count"):
                if required not in security_columns:
                    raise RuntimeError(f"marketplace dependency summary column is missing: {required}")
            runtime_columns = {row[1] for row in db.execute("PRAGMA table_info(runtime_plugin_variants)")}
            for required in ("security_dependencies_json", "security_dependency_total_count"):
                if required not in runtime_columns:
                    raise RuntimeError(f"runtime dependency projection column is missing: {required}")
            for encoded, total in db.execute("SELECT dependencies_json,dependency_total_count FROM marketplace_security_current"):
                dependencies = json.loads(encoded or "[]")
                if not isinstance(dependencies, list) or len(dependencies) > 30:
                    raise RuntimeError("marketplace dependency summary is malformed or exceeds the 30-entry bound")
                if int(total or 0) < len(dependencies):
                    raise RuntimeError("marketplace dependency total count is smaller than its projected summary")
            leaked = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%' ORDER BY name")]
            if leaked:
                raise RuntimeError(f"detailed security tables leaked into marketplace database: {leaked}")
            meta = dict(db.execute("SELECT key,value FROM catalog_meta"))
            if meta.get("database_role") != "marketplace" or meta.get("detailed_security_evidence_included") != "0":
                raise RuntimeError("marketplace database role metadata is invalid")
            if meta.get("evidence_revision", "") != str(descriptor.get("evidenceRevision") or ""):
                raise RuntimeError("marketplace evidence revision mismatch")
            return {
                "integrity": "ok",
                "databaseBytes": len(raw),
                "bundleBytes": len(bundle),
                "catalogRevision": meta.get("catalog_revision", ""),
                "securityRevision": meta.get("security_revision", ""),
                "evidenceRevision": meta.get("evidence_revision", ""),
                "variants": int(db.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0]),
                "dependencySummaryRows": int(db.execute("SELECT COUNT(*) FROM marketplace_security_current WHERE dependency_total_count>0").fetchone()[0]),
            }
        finally:
            db.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--base-url", default="")
    args = parser.parse_args()
    if args.root:
        descriptor = (args.root / DESCRIPTOR_NAME).read_bytes()
        bundle = (args.root / BUNDLE_NAME).read_bytes()
    elif args.base_url:
        base = args.base_url.rstrip("/") + "/"
        descriptor = urllib.request.urlopen(base + DESCRIPTOR_NAME, timeout=30).read()
        bundle = urllib.request.urlopen(base + BUNDLE_NAME, timeout=60).read()
    else:
        raise SystemExit("--root or --base-url is required")
    print(json.dumps(validate_bytes(descriptor, bundle), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
