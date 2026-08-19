#!/usr/bin/env python3
"""Compile Omega's daily client SQLite from canonical JSON + Security Evidence v2.

This is the only intended path from online canonical data to the database consumed by
Omega. Deltascope may inspect this output, but it is never part of this compiler or a
publication gate.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR.parent
SECURITY_DIR = TOOLS_DIR / "security"
for item in (SCRIPT_DIR, SECURITY_DIR):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import catalog_json_store  # noqa: E402
import definitions_snapshot  # noqa: E402
import project_marketplace_catalog  # noqa: E402
import sigmascope  # noqa: E402
from production_sigmascope_v2_pipeline import materialize_current_state, semantic_security_revision  # noqa: E402

SCHEMA = "omega.marketplace-build.v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(
    *,
    catalog_root: Path,
    definitions_root: Path,
    evidence_root: Path,
    output: Path,
    download_url: str,
    evidence_index_url: str,
) -> dict[str, Any]:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    catalog_root = catalog_root.resolve()
    definitions_root = definitions_root.resolve()
    evidence_root = evidence_root.resolve()

    catalog_validation = catalog_json_store.validate_snapshot(catalog_root)
    if not catalog_validation.get("ok"):
        raise RuntimeError("catalog JSON is invalid: " + "; ".join(catalog_validation.get("errors") or []))
    definitions_validation = definitions_snapshot.verify_snapshot(
        repo_root=Path.cwd(), definitions_root=definitions_root
    )
    # Compilation does not require the current checkout to match the daily scanner
    # commit; that strict check belongs to workers. The Definitions payload hashes
    # themselves are mandatory here.
    if not definitions_validation.get("ok"):
        file_change_only = all(
            str(error).startswith("definition file changed since freeze:")
            or str(error).startswith("definition file missing at worker checkout:")
            for error in definitions_validation.get("errors") or []
        )
        if not file_change_only:
            raise RuntimeError("definitions snapshot is invalid: " + "; ".join(definitions_validation.get("errors") or []))

    catalog_index = json.loads((catalog_root / "index.json").read_text(encoding="utf-8"))
    definitions_index = json.loads((definitions_root / "index.json").read_text(encoding="utf-8"))
    evidence_index = json.loads((evidence_root / "index.json").read_text(encoding="utf-8"))
    evidence_revisions = evidence_index.get("revisions") or {}
    catalog_identity_epoch = str(catalog_index.get("identityEpoch") or "")
    evidence_identity_epoch = str(evidence_revisions.get("catalogIdentityEpoch") or "")
    evidence_compatible = bool(not catalog_identity_epoch or evidence_identity_epoch == catalog_identity_epoch)

    base_db = output / "omega-catalog-base.sqlite"
    work_db = output / "omega-marketplace-work.sqlite"
    marketplace_db = output / project_marketplace_catalog.MARKETPLACE_DB_FILENAME
    catalog_json_store.materialize_snapshot(
        catalog_root,
        base_db,
        definitions_revision=str(definitions_index.get("definitionsRevision") or ""),
    )
    materialized = materialize_current_state(base_db, evidence_root, work_db, include_evidence=evidence_compatible)
    materialized["catalogIdentityEpoch"] = catalog_identity_epoch
    materialized["availableEvidenceIdentityEpoch"] = evidence_identity_epoch
    materialized["evidenceCompatible"] = evidence_compatible

    # The daily database must represent today's frozen Definitions even when the latest
    # Security Evidence v2 snapshot was produced against yesterday's advisory payload.
    # Recompute only catalog/Definitions-derived conclusions here; never rescan artifacts
    # and never perform a live advisory lookup during compilation.
    osv_meta = definitions_index.get("osv") if isinstance(definitions_index.get("osv"), dict) else {}
    osv_path = definitions_root / str(osv_meta.get("path") or "osv-advisories.json")
    advisories = sigmascope.load_advisories(str(osv_path))
    advisory_coverage = sigmascope.load_advisory_coverage(str(osv_path))
    with closing(sqlite3.connect(work_db)) as db:
        db.row_factory = sqlite3.Row
        definitions_projection = sigmascope.refresh_current_security_projection(db, advisories, advisory_coverage)
        compiled_security_revision = semantic_security_revision(db)
        available_source_security_revision = str(evidence_revisions.get("securityRevision") or "")
        available_evidence_revision = str(evidence_revisions.get("evidenceRevision") or "")
        source_security_revision = available_source_security_revision if evidence_compatible else ""
        evidence_revision = available_evidence_revision if evidence_compatible else ""
        meta = {
            "catalog_revision": str(catalog_index.get("catalogRevision") or ""),
            "catalog_json_revision": str(catalog_index.get("catalogRevision") or ""),
            "catalog_base_revision": str(catalog_index.get("catalogBaseRevision") or ""),
            "catalog_identity_epoch": catalog_identity_epoch,
            "definitions_revision": str(definitions_index.get("definitionsRevision") or ""),
            "definitions_source_commit": str(definitions_index.get("sourceCommit") or ""),
            "definitions_rule_set_revision": str(definitions_index.get("ruleSetRevision") or ""),
            "security_revision": compiled_security_revision,
            "source_security_revision": source_security_revision,
            "evidence_revision": evidence_revision,
            "security_evidence_revision": evidence_revision,
            "available_evidence_revision": available_evidence_revision,
            "available_evidence_identity_epoch": evidence_identity_epoch,
            "evidence_compatible": "1" if evidence_compatible else "0",
            "marketplace_compiled_at_utc": utc_now(),
        }
        for key, value in meta.items():
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES(?,?)", (key, value))
        db.commit()

    projection = project_marketplace_catalog.project_database(work_db, marketplace_db)
    bundle, bundle_sha = project_marketplace_catalog.write_marketplace_bundle(marketplace_db, output)
    with closing(sqlite3.connect(marketplace_db)) as db:
        db.row_factory = sqlite3.Row
        logical_plugins = int(db.execute("SELECT COUNT(*) FROM plugins WHERE active=1").fetchone()[0])
        active_variants = int(db.execute(
            "SELECT COUNT(*) FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id WHERE v.active=1 AND p.active=1"
        ).fetchone()[0])
        sources = int(db.execute("SELECT COUNT(*) FROM sources").fetchone()[0])
        meta_rows = {str(row[0]): str(row[1]) for row in db.execute("SELECT key,value FROM catalog_meta")}

    descriptor = {
        "schemaVersion": 1,
        "schema": project_marketplace_catalog.MARKETPLACE_SCHEMA,
        "databaseRole": "marketplace",
        "generatedAtUtc": utc_now(),
        "downloadUrl": download_url,
        "catalogSha256": sha256_file(marketplace_db),
        "bundleSha256": bundle_sha,
        "size": bundle.stat().st_size,
        "databaseBytes": marketplace_db.stat().st_size,
        "marketplaceProjectorVersion": project_marketplace_catalog.PROJECTOR_VERSION,
        "detailedSecurityEvidenceIncluded": False,
        "catalogRevision": str(catalog_index.get("catalogRevision") or ""),
        "catalogBaseRevision": str(catalog_index.get("catalogBaseRevision") or ""),
        "catalogIdentityEpoch": catalog_identity_epoch,
        "definitionsRevision": str(definitions_index.get("definitionsRevision") or ""),
        "definitionsSourceCommit": str(definitions_index.get("sourceCommit") or ""),
        "securityRevision": compiled_security_revision,
        "sourceSecurityRevision": source_security_revision,
        "evidenceRevision": evidence_revision,
        "evidenceCompatible": evidence_compatible,
        "evidenceIndexUrl": evidence_index_url,
        "pluginCount": logical_plugins,
        "variantCount": active_variants,
        "sourceCount": sources,
    }
    (output / "catalog.json").write_text(json.dumps(descriptor, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    build_manifest = {
        "schema": SCHEMA,
        "generatedAtUtc": descriptor["generatedAtUtc"],
        "inputs": {
            "catalogRevision": descriptor["catalogRevision"],
            "catalogContentSha256": str(catalog_index.get("contentSha256") or ""),
            "definitionsRevision": descriptor["definitionsRevision"],
            "securityRevision": descriptor["securityRevision"],
            "sourceSecurityRevision": descriptor["sourceSecurityRevision"],
            "evidenceRevision": descriptor["evidenceRevision"],
            "catalogIdentityEpoch": catalog_identity_epoch,
            "availableEvidenceRevision": available_evidence_revision,
            "availableEvidenceIdentityEpoch": evidence_identity_epoch,
            "evidenceCompatible": evidence_compatible,
        },
        "output": {
            "database": marketplace_db.name,
            "databaseSha256": descriptor["catalogSha256"],
            "bundle": bundle.name,
            "bundleSha256": bundle_sha,
            "logicalPluginCount": logical_plugins,
            "variantCount": active_variants,
            "sourceCount": sources,
        },
        "projection": projection,
        "definitionsProjectionRefresh": definitions_projection,
        "materializedEvidence": materialized,
        "databaseMeta": meta_rows,
    }
    (output / "database-build.json").write_text(json.dumps(build_manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    endpoint = {"schemaVersion": 1, "descriptorUrl": "https://github.com/dalagab/omega/releases/download/catalog-latest/catalog.json"}
    (output / "catalog-endpoint.json").write_text(json.dumps(endpoint, indent=2) + "\n", encoding="utf-8")
    base_db.unlink(missing_ok=True)
    work_db.unlink(missing_ok=True)
    return build_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-root", type=Path, required=True)
    parser.add_argument("--definitions-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--download-url", required=True)
    parser.add_argument("--evidence-index-url", required=True)
    args = parser.parse_args()
    result = build(
        catalog_root=args.catalog_root,
        definitions_root=args.definitions_root,
        evidence_root=args.evidence_root,
        output=args.output,
        download_url=args.download_url,
        evidence_index_url=args.evidence_index_url,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
