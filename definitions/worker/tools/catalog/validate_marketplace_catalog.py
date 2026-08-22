#!/usr/bin/env python3
"""Fail-closed validation for Omega's client marketplace SQLite bundle."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
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


def validate_bytes(descriptor_bytes: bytes, bundle: bytes, *, require_v2: bool = False) -> dict:
    descriptor = json.loads(descriptor_bytes.decode("utf-8"))
    schema = str(descriptor.get("schema") or "")
    schema_version = int(descriptor.get("schemaVersion") or 0)
    is_v1 = schema_version == 1 and schema == "omega.catalog.sqlite.v1"
    is_v2 = schema_version == 2 and schema == "omega.catalog.marketplace.v2"
    if require_v2 and not is_v2:
        raise RuntimeError("production marketplace publication must use descriptor v2")
    if not is_v1 and not is_v2:
        raise RuntimeError("unsupported marketplace descriptor schema")

    catalog_revision = str(descriptor.get("catalogRevision") or "")
    catalog_json_revision = str(descriptor.get("catalogJsonRevision") or "")
    if is_v2:
        if re.fullmatch(r"cat-v2-[0-9a-f]{16}", catalog_revision) is None:
            raise RuntimeError("marketplace catalog revision is not a valid v2 revision")
        if re.fullmatch(r"cat-json-v1-[0-9a-f]{16}", catalog_json_revision) is None:
            raise RuntimeError("marketplace canonical catalog revision is invalid")
        if catalog_revision.removeprefix("cat-v2-") != catalog_json_revision.removeprefix("cat-json-v1-"):
            raise RuntimeError("marketplace and canonical catalog revision suffixes do not match")
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
    # NamedTemporaryFile remains open on Windows and SQLite cannot reopen that
    # path there. Materialize the database inside a temporary directory instead.
    with tempfile.TemporaryDirectory(prefix="omega-marketplace-validate-") as td:
        db_path = Path(td) / INTERNAL_DB_NAME
        db_path.write_bytes(raw)
        db = sqlite3.connect(db_path)
        try:
            if str(db.execute("PRAGMA integrity_check").fetchone()[0]).lower() != "ok":
                raise RuntimeError("marketplace integrity_check failed")
            if int(db.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0]) <= 0:
                raise RuntimeError("marketplace runtime projection is empty")
            if int(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='marketplace_security_current'").fetchone()[0]) != 1:
                raise RuntimeError("marketplace current-security summary table is missing")
            security_columns = {row[1] for row in db.execute("PRAGMA table_info(marketplace_security_current)")}
            for required in ("dependencies_json", "dependency_total_count", "known_advisory_count", "known_advisory_highest_severity", "risk_score"):
                if required not in security_columns:
                    raise RuntimeError(f"marketplace dependency summary column is missing: {required}")
            runtime_columns = {row[1] for row in db.execute("PRAGMA table_info(runtime_plugin_variants)")}
            for required in ("security_dependencies_json", "security_dependency_total_count", "security_known_advisory_count", "security_known_advisory_highest_severity", "security_risk_score"):
                if required not in runtime_columns:
                    raise RuntimeError(f"runtime dependency projection column is missing: {required}")
            for advisory_count, risk_score in db.execute("SELECT known_advisory_count,risk_score FROM marketplace_security_current"):
                if int(advisory_count or 0) < 0:
                    raise RuntimeError("marketplace known-advisory count cannot be negative")
                if not 0 <= int(risk_score or 0) <= 100:
                    raise RuntimeError("marketplace internal risk score must stay within 0..100")
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
            revision_pairs = (
                ("catalog_revision", "catalogRevision", "catalog"),
                ("catalog_json_revision", "catalogJsonRevision", "canonical catalog"),
                ("catalog_identity_epoch", "catalogIdentityEpoch", "catalog identity epoch"),
                ("definitions_revision", "definitionsRevision", "Definitions"),
                ("security_revision", "securityRevision", "security"),
                ("evidence_revision", "evidenceRevision", "evidence"),
                ("source_security_revision", "sourceSecurityRevision", "source-evidence security"),
            )
            for meta_key, descriptor_key, label in revision_pairs:
                expected = str(descriptor.get(descriptor_key) or "")
                if expected and meta.get(meta_key, "") != expected:
                    raise RuntimeError(f"marketplace {label} revision mismatch")
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
    parser.add_argument("--require-v2", action="store_true")
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
    print(json.dumps(validate_bytes(descriptor, bundle, require_v2=args.require_v2), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
