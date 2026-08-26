#!/usr/bin/env python3
"""Phase-4-only converter for Omega's one authoritative catalog-json v1 state.

This is intentionally not a compatibility reader. It exists only so the one live
``catalog-data`` snapshot can preserve exact source/plugin/variant integer identities
while the internal canonical JSON representation changes to sharded v2 storage.
Delete this tool and its workflow branch after the Phase-4 cutover receipt is complete.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from typing import Any

import build_sqlite_catalog
import catalog_json_store
from catalog_revisions import write_meta

V1_SCHEMA = "omega.catalog-json.v1"
V1_FORMAT_VERSION = 1
EXPECTED_IDENTITY_EPOCH = catalog_json_store.IDENTITY_EPOCH


def _read(root: Path, relative: str, expected_sha256: str = "") -> Any:
    return catalog_json_store._read_json(root, relative, expected_sha256)


def _insert_rows(db: sqlite3.Connection, table: str, rows: list[dict[str, Any]]) -> None:
    catalog_json_store._insert_rows(db, table, rows)


def materialize_v1_seed(root: Path, database: Path) -> dict[str, Any]:
    root = root.resolve()
    index = _read(root, "index.json")
    if index.get("schema") != V1_SCHEMA:
        raise RuntimeError(f"Phase-4 predecessor has unexpected schema: {index.get('schema')!r}")
    if int(index.get("formatVersion") or 0) != V1_FORMAT_VERSION:
        raise RuntimeError(f"Phase-4 predecessor has unexpected formatVersion: {index.get('formatVersion')!r}")
    if str(index.get("identityEpoch") or "") != EXPECTED_IDENTITY_EPOCH:
        raise RuntimeError(f"Phase-4 predecessor has unexpected identity epoch: {index.get('identityEpoch')!r}")

    # Verify every descriptor before using any predecessor row as identity seed data.
    for item in index.get("files") or []:
        if not isinstance(item, dict):
            raise RuntimeError("Phase-4 predecessor contains malformed file descriptor")
        rel = str(item.get("path") or "")
        if not rel:
            raise RuntimeError("Phase-4 predecessor contains an empty file descriptor")
        _read(root, rel, str(item.get("sha256") or ""))

    meta = _read(root, "meta.json")
    source_index = _read(root, "sources/index.json")
    website_index = _read(root, "websites/index.json")
    plugin_index = _read(root, "plugins/index.json")
    identity = _read(root, "identity/model.json")
    if identity.get("schema") != "omega.catalog-json.identity-model.v1":
        raise RuntimeError("Phase-4 predecessor identity/model.json has an unexpected schema")

    sources = [_read(root, row["path"], row.get("sha256") or "")["source"] for row in source_index.get("sources") or []]
    websites = [_read(root, row["path"], row.get("sha256") or "")["website"] for row in website_index.get("websites") or []]
    plugin_payloads = [_read(root, row["path"], row.get("sha256") or "") for row in plugin_index.get("plugins") or []]

    database = database.resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    database.unlink(missing_ok=True)
    with closing(build_sqlite_catalog.reset_database(database)) as db:
        db.execute("PRAGMA foreign_keys=OFF")
        for table in reversed(catalog_json_store.BASE_TABLES):
            db.execute(f'DELETE FROM "{table}"')
        db.execute("DELETE FROM catalog_meta")

        _insert_rows(db, "sources", sources)
        _insert_rows(db, "websites", websites)
        _insert_rows(db, "plugins", [payload["plugin"] for payload in plugin_payloads])

        variants: list[dict[str, Any]] = []
        tags: list[dict[str, Any]] = []
        images: list[dict[str, Any]] = []
        presentation: list[dict[str, Any]] = []
        searches: list[dict[str, Any]] = []
        for payload in plugin_payloads:
            for grouped in payload.get("variants") or []:
                variants.append(grouped["variant"])
                tags.extend(grouped.get("tags") or [])
                images.extend(grouped.get("images") or [])
            if isinstance(payload.get("presentation"), dict):
                presentation.append(payload["presentation"])
            if isinstance(payload.get("search"), dict):
                searches.append(payload["search"])

        _insert_rows(db, "plugin_variants", variants)
        _insert_rows(db, "manifest_observations", identity.get("manifestObservations") or [])
        _insert_rows(db, "source_repositories", identity.get("sourceRepositories") or [])
        _insert_rows(db, "source_repository_aliases", identity.get("sourceRepositoryAliases") or [])
        _insert_rows(db, "manifest_source_candidates", identity.get("manifestSourceCandidates") or [])
        _insert_rows(db, "plugin_identity_aliases", identity.get("pluginIdentityAliases") or [])
        _insert_rows(db, "plugin_tags", tags)
        _insert_rows(db, "plugin_images", images)
        _insert_rows(db, "presentation", presentation)
        _insert_rows(db, "plugin_search", searches)

        db.execute("PRAGMA foreign_keys=ON")
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('schema_version',?)", (str(build_sqlite_catalog.SCHEMA_VERSION),))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('schema_name',?)", (build_sqlite_catalog.SCHEMA_NAME,))
        write_meta(db, "catalog_base_revision", str(meta.get("catalogBaseRevision") or index.get("catalogBaseRevision") or ""))
        write_meta(db, "catalog_json_revision", str(index.get("catalogRevision") or ""))
        write_meta(db, "catalog_identity_epoch", EXPECTED_IDENTITY_EPOCH)
        write_meta(db, "catalog_built_from_dev_commit", str(index.get("builtFromDevCommit") or ""))
        build_sqlite_catalog.create_runtime_view(db)
        db.execute("ANALYZE")
        db.commit()
        violations = db.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"Phase-4 predecessor materialization has foreign key violations: {violations[:5]}")
        build_sqlite_catalog.validate_database(db)
        counts = {
            "plugins": int(db.execute("SELECT COUNT(*) FROM plugins").fetchone()[0]),
            "variants": int(db.execute("SELECT COUNT(*) FROM plugin_variants").fetchone()[0]),
            "sources": int(db.execute("SELECT COUNT(*) FROM sources").fetchone()[0]),
        }

    return {
        "schema": "omega.catalog-json-v1-phase4-seed.v1",
        "identityEpoch": EXPECTED_IDENTITY_EPOCH,
        "database": str(database),
        "counts": counts,
        "sha256": catalog_json_store.sha256_file(database),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(materialize_v1_seed(args.root, args.database), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
