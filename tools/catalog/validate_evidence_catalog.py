#!/usr/bin/env python3
"""Fail-closed validation for Omega's server-side security evidence bundle."""
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

BUNDLE_NAME = "omega-security-evidence.sqlite.zip"
DESCRIPTOR_NAME = "evidence.json"
REQUIRED_TABLES = (
    "plugin_security_scans", "plugin_security_findings", "plugin_security_current",
    "plugin_security_dependencies", "plugin_security_permission_candidates",
    "plugin_security_managed_assemblies", "plugin_security_managed_symbols",
    "plugin_security_managed_calls", "plugin_security_managed_reachability",
    "plugin_security_automation_capabilities",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_bytes(descriptor_bytes: bytes, bundle: bytes) -> dict:
    descriptor = json.loads(descriptor_bytes.decode("utf-8"))
    if descriptor.get("schema") != "omega.security-evidence.sqlite.v1" or int(descriptor.get("schemaVersion") or 0) != 1:
        raise RuntimeError("unsupported evidence descriptor schema")
    if descriptor.get("databaseRole") != "security-evidence":
        raise RuntimeError("evidence descriptor database role is invalid")
    if sha256(bundle) != str(descriptor.get("bundleSha256") or ""):
        raise RuntimeError("evidence bundle SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        names = archive.namelist()
        if len(names) != 1:
            raise RuntimeError("evidence bundle must contain exactly one SQLite database")
        raw = archive.read(names[0])
    if sha256(raw) != str(descriptor.get("databaseSha256") or ""):
        raise RuntimeError("evidence database SHA-256 mismatch")
    with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
        tmp.write(raw); tmp.flush()
        db = sqlite3.connect(tmp.name)
        try:
            if str(db.execute("PRAGMA integrity_check").fetchone()[0]).lower() != "ok":
                raise RuntimeError("evidence integrity_check failed")
            if db.execute("PRAGMA foreign_key_check").fetchall():
                raise RuntimeError("evidence database has foreign-key violations")
            for table in REQUIRED_TABLES:
                if int(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0]) != 1:
                    raise RuntimeError(f"evidence table is missing: {table}")
            meta = dict(db.execute("SELECT key,value FROM catalog_meta"))
            if meta.get("evidence_revision", "") != str(descriptor.get("evidenceRevision") or ""):
                raise RuntimeError("evidence revision mismatch")
            return {
                "integrity": "ok",
                "databaseBytes": len(raw),
                "bundleBytes": len(bundle),
                "catalogRevision": meta.get("catalog_revision", ""),
                "securityRevision": meta.get("security_revision", ""),
                "evidenceRevision": meta.get("evidence_revision", ""),
                "managedCalls": int(db.execute("SELECT COUNT(*) FROM plugin_security_managed_calls").fetchone()[0]),
                "managedSymbols": int(db.execute("SELECT COUNT(*) FROM plugin_security_managed_symbols").fetchone()[0]),
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
        bundle = urllib.request.urlopen(base + BUNDLE_NAME, timeout=120).read()
    else:
        raise SystemExit("--root or --base-url is required")
    print(json.dumps(validate_bytes(descriptor, bundle), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
