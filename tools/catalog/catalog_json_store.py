#!/usr/bin/env python3
"""Canonical JSON storage for Omega catalog state.

The JSON tree is the durable/public catalog representation. SQLite is a compiled
consumer artifact and can be recreated from this tree without rediscovery.

The format intentionally separates logical plugins from repository variants while
preserving the exact relational rows required by the existing Omega runtime compiler.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_sqlite_catalog  # noqa: E402
from catalog_revisions import read_meta, write_meta  # noqa: E402

SCHEMA = "omega.catalog-json.v1"
FORMAT_VERSION = 1
IDENTITY_EPOCH = "omega-catalog-identity-v1"
MAX_FILE_BYTES = 16 * 1024 * 1024
BASE_TABLES = (
    "sources",
    "plugins",
    "plugin_variants",
    "plugin_tags",
    "plugin_images",
    "websites",
    "presentation",
    "plugin_search",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if len(data) > MAX_FILE_BYTES:
        raise RuntimeError(f"catalog JSON file exceeds {MAX_FILE_BYTES:,} bytes: {path}")
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(data)
    temp.replace(path)
    return {"path": path.as_posix(), "bytes": len(data), "sha256": sha256_bytes(data)}


def _rows(db: sqlite3.Connection, table: str, *, where: str = "", params: tuple[Any, ...] = (), order: str = "") -> list[dict[str, Any]]:
    sql = f'SELECT * FROM "{table}"'
    if where:
        sql += f" WHERE {where}"
    if order:
        sql += f" ORDER BY {order}"
    return [dict(row) for row in db.execute(sql, params)]


def _semantic_revision(base_revision: str) -> str:
    suffix = str(base_revision or "").split("-")[-1]
    if len(suffix) < 8:
        suffix = sha256_bytes(str(base_revision or "").encode("utf-8"))[:16]
    return f"cat-json-v1-{suffix[:16]}"


def export_snapshot(database: Path, output: Path, *, source_commit: str = "") -> dict[str, Any]:
    database = database.resolve()
    output = output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        build_sqlite_catalog.validate_database(db)
        generated = utc_now()
        base_revision = read_meta(db, "catalog_base_revision") or build_sqlite_catalog.compute_catalog_base_revision(db)
        catalog_revision = _semantic_revision(base_revision)

        sources = _rows(db, "sources", order="source_id")
        websites = _rows(db, "websites", order="website_id")
        plugins = _rows(db, "plugins", order="plugin_id")
        variants = _rows(db, "plugin_variants", order="variant_id")
        tags = _rows(db, "plugin_tags", order="variant_id,kind,tag COLLATE NOCASE")
        images = _rows(db, "plugin_images", order="image_id")
        presentations = {int(row["plugin_id"]): row for row in _rows(db, "presentation", order="plugin_id")}
        searches = {int(row["plugin_id"]): row for row in _rows(db, "plugin_search", order="plugin_id")}

        variants_by_plugin: dict[int, list[dict[str, Any]]] = {}
        tags_by_variant: dict[int, list[dict[str, Any]]] = {}
        images_by_variant: dict[int, list[dict[str, Any]]] = {}
        for row in variants:
            variants_by_plugin.setdefault(int(row["plugin_id"]), []).append(row)
        for row in tags:
            tags_by_variant.setdefault(int(row["variant_id"]), []).append(row)
        for row in images:
            images_by_variant.setdefault(int(row["variant_id"]), []).append(row)

        files: list[dict[str, Any]] = []
        source_index: list[dict[str, Any]] = []
        for row in sources:
            source_id = int(row["source_id"])
            rel = Path("sources") / f"{source_id:06d}.json"
            descriptor = write_json(output / rel, {"schema": "omega.catalog-json.source.v1", "source": row})
            descriptor["path"] = rel.as_posix()
            files.append(descriptor)
            source_index.append({
                "sourceId": source_id,
                "url": row.get("url") or "",
                "name": row.get("name") or "",
                "provider": row.get("provider") or "",
                "pluginCount": int(row.get("plugin_count") or 0),
                "path": rel.as_posix(),
                "sha256": descriptor["sha256"],
            })
        source_index_file = write_json(output / "sources" / "index.json", {
            "schema": "omega.catalog-json.sources-index.v1",
            "records": len(source_index),
            "sources": source_index,
        })
        source_index_file["path"] = "sources/index.json"
        files.append(source_index_file)

        website_index: list[dict[str, Any]] = []
        for row in websites:
            website_id = int(row["website_id"])
            rel = Path("websites") / f"{website_id:06d}.json"
            descriptor = write_json(output / rel, {"schema": "omega.catalog-json.website.v1", "website": row})
            descriptor["path"] = rel.as_posix()
            files.append(descriptor)
            website_index.append({
                "websiteId": website_id,
                "url": row.get("url") or "",
                "ok": bool(row.get("ok")),
                "path": rel.as_posix(),
                "sha256": descriptor["sha256"],
            })
        website_index_file = write_json(output / "websites" / "index.json", {
            "schema": "omega.catalog-json.websites-index.v1",
            "records": len(website_index),
            "websites": website_index,
        })
        website_index_file["path"] = "websites/index.json"
        files.append(website_index_file)

        plugin_index: list[dict[str, Any]] = []
        for plugin in plugins:
            plugin_id = int(plugin["plugin_id"])
            grouped_variants: list[dict[str, Any]] = []
            for variant in variants_by_plugin.get(plugin_id, []):
                variant_id = int(variant["variant_id"])
                grouped_variants.append({
                    "variant": variant,
                    "tags": tags_by_variant.get(variant_id, []),
                    "images": images_by_variant.get(variant_id, []),
                })
            rel = Path("plugins") / f"{plugin_id // 1000:04d}" / f"{plugin_id}.json"
            payload = {
                "schema": "omega.catalog-json.plugin.v1",
                "plugin": plugin,
                "variants": grouped_variants,
                "presentation": presentations.get(plugin_id),
                "search": searches.get(plugin_id),
            }
            descriptor = write_json(output / rel, payload)
            descriptor["path"] = rel.as_posix()
            files.append(descriptor)
            active_variant_ids = [
                int((grouped.get("variant") or {}).get("variant_id") or 0)
                for grouped in grouped_variants
                if int((grouped.get("variant") or {}).get("active") or 0) == 1
            ]
            plugin_index.append({
                "pluginId": plugin_id,
                "internalName": plugin.get("internal_name") or "",
                "name": plugin.get("canonical_name") or "",
                "active": bool(plugin.get("active")),
                "variantCount": len(grouped_variants),
                "activeVariantCount": len(active_variant_ids),
                # Bounded reverse lookup so read-only developer tools do not need to fetch every
                # plugin shard merely to resolve a repository variant to its logical plugin.
                "activeVariantIds": active_variant_ids,
                "path": rel.as_posix(),
                "sha256": descriptor["sha256"],
            })
        plugin_index_file = write_json(output / "plugins" / "index.json", {
            "schema": "omega.catalog-json.plugins-index.v1",
            "records": len(plugin_index),
            "activePlugins": sum(1 for row in plugin_index if row["active"]),
            "plugins": plugin_index,
        })
        plugin_index_file["path"] = "plugins/index.json"
        files.append(plugin_index_file)

        meta = {
            "schemaVersion": str(build_sqlite_catalog.SCHEMA_VERSION),
            "schemaName": build_sqlite_catalog.SCHEMA_NAME,
            "catalogBaseRevision": base_revision,
            "catalogRevision": catalog_revision,
            "identityEpoch": IDENTITY_EPOCH,
            "builtFromDevCommit": source_commit,
        }
        meta_file = write_json(output / "meta.json", {"schema": "omega.catalog-json.meta.v1", **meta})
        meta_file["path"] = "meta.json"
        files.append(meta_file)

        counts = {
            "plugins": sum(1 for row in plugins if int(row.get("active") or 0) == 1),
            "variants": sum(1 for row in variants if int(row.get("active") or 0) == 1),
            "sources": len(sources),
            "websites": sum(1 for row in websites if int(row.get("ok") or 0) == 1),
        }

    semantic_manifest = {
        "schema": SCHEMA,
        "formatVersion": FORMAT_VERSION,
        "catalogRevision": catalog_revision,
        "catalogBaseRevision": base_revision,
        "identityEpoch": IDENTITY_EPOCH,
        "builtFromDevCommit": source_commit,
        "counts": counts,
        "files": [{"path": row["path"], "sha256": row["sha256"]} for row in sorted(files, key=lambda item: item["path"])],
    }
    content_sha = sha256_bytes(canonical_json_bytes(semantic_manifest))
    index = {
        **semantic_manifest,
        "generatedAtUtc": generated,
        "contentSha256": content_sha,
        "files": sorted(files, key=lambda item: item["path"]),
    }
    write_json(output / "index.json", index)
    return index


def _read_json(root: Path, relative: str, expected_sha256: str = "") -> Any:
    path = (root / relative).resolve()
    if root.resolve() not in path.parents and path != root.resolve():
        raise ValueError(f"catalog JSON path escaped root: {relative}")
    data = path.read_bytes()
    if expected_sha256 and sha256_bytes(data) != expected_sha256:
        raise ValueError(f"catalog JSON SHA-256 mismatch: {relative}")
    return json.loads(data.decode("utf-8"))


def validate_snapshot(root: Path) -> dict[str, Any]:
    root = root.resolve()
    errors: list[str] = []
    try:
        index = _read_json(root, "index.json")
    except Exception as exc:
        return {"schema": "omega.catalog-json.validation.v1", "ok": False, "errors": [f"index unreadable: {type(exc).__name__}: {exc}"]}
    if index.get("schema") != SCHEMA:
        errors.append(f"unsupported schema: {index.get('schema')!r}")
    if str(index.get("identityEpoch") or "") != IDENTITY_EPOCH:
        errors.append(f"unsupported catalog identity epoch: {index.get('identityEpoch')!r}")
    seen: set[str] = set()
    for item in index.get("files") or []:
        if not isinstance(item, dict):
            errors.append("index contains malformed file descriptor")
            continue
        rel = str(item.get("path") or "")
        if not rel or rel in seen:
            errors.append(f"duplicate/empty file descriptor: {rel!r}")
            continue
        seen.add(rel)
        try:
            _read_json(root, rel, str(item.get("sha256") or ""))
        except Exception as exc:
            errors.append(f"{rel}: {type(exc).__name__}: {exc}")
    try:
        plugin_index = _read_json(root, "plugins/index.json")
        source_index = _read_json(root, "sources/index.json")
        counts = index.get("counts") or {}
        active_plugins = sum(1 for row in plugin_index.get("plugins") or [] if bool(row.get("active")))
        variants = sum(
            int(row.get("activeVariantCount") if row.get("activeVariantCount") is not None else row.get("variantCount") or 0)
            for row in plugin_index.get("plugins") or []
            if bool(row.get("active"))
        )
        if active_plugins != int(counts.get("plugins") or 0):
            errors.append(f"plugin count mismatch: index={counts.get('plugins')}, records={active_plugins}")
        if variants != int(counts.get("variants") or 0):
            errors.append(f"variant count mismatch: index={counts.get('variants')}, records={variants}")
        if len(source_index.get("sources") or []) != int(counts.get("sources") or 0):
            errors.append("source count mismatch")
    except Exception as exc:
        errors.append(f"index cross-check failed: {type(exc).__name__}: {exc}")
    return {
        "schema": "omega.catalog-json.validation.v1",
        "ok": not errors,
        "catalogRevision": str(index.get("catalogRevision") or ""),
        "errors": errors,
    }


def _insert_rows(db: sqlite3.Connection, table: str, rows: Iterable[dict[str, Any]]) -> None:
    columns = [str(row[1]) for row in db.execute(f'PRAGMA table_info("{table}")')]
    for row in rows:
        usable = [column for column in columns if column in row]
        if not usable:
            continue
        quoted = ",".join(f'"{column}"' for column in usable)
        placeholders = ",".join("?" for _ in usable)
        db.execute(
            f'INSERT INTO "{table}"({quoted}) VALUES({placeholders})',
            tuple(row.get(column) for column in usable),
        )


def materialize_snapshot(root: Path, database: Path, *, definitions_revision: str = "") -> dict[str, Any]:
    root = root.resolve()
    validation = validate_snapshot(root)
    if not validation.get("ok"):
        raise RuntimeError("catalog JSON snapshot failed validation: " + "; ".join(validation.get("errors") or []))
    index = _read_json(root, "index.json")
    meta = _read_json(root, "meta.json")
    database = database.resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    database.unlink(missing_ok=True)

    with closing(build_sqlite_catalog.reset_database(database)) as db:
        db.execute("PRAGMA foreign_keys=OFF")
        for table in reversed(BASE_TABLES):
            db.execute(f'DELETE FROM "{table}"')
        db.execute("DELETE FROM catalog_meta")

        source_index = _read_json(root, "sources/index.json")
        sources = [_read_json(root, row["path"], row.get("sha256") or "")["source"] for row in source_index.get("sources") or []]
        website_index = _read_json(root, "websites/index.json")
        websites = [_read_json(root, row["path"], row.get("sha256") or "")["website"] for row in website_index.get("websites") or []]
        plugin_index = _read_json(root, "plugins/index.json")
        plugin_payloads = [_read_json(root, row["path"], row.get("sha256") or "") for row in plugin_index.get("plugins") or []]

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
        _insert_rows(db, "plugin_tags", tags)
        _insert_rows(db, "plugin_images", images)
        _insert_rows(db, "presentation", presentation)
        _insert_rows(db, "plugin_search", searches)

        db.execute("PRAGMA foreign_keys=ON")
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('schema_version',?)", (str(build_sqlite_catalog.SCHEMA_VERSION),))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('schema_name',?)", (build_sqlite_catalog.SCHEMA_NAME,))
        write_meta(db, "catalog_base_revision", str(meta.get("catalogBaseRevision") or index.get("catalogBaseRevision") or ""))
        write_meta(db, "catalog_json_revision", str(index.get("catalogRevision") or ""))
        write_meta(db, "catalog_identity_epoch", str(index.get("identityEpoch") or ""))
        write_meta(db, "catalog_built_from_dev_commit", str(index.get("builtFromDevCommit") or index.get("sourceCommit") or ""))
        if definitions_revision:
            write_meta(db, "definitions_revision", definitions_revision)
        build_sqlite_catalog.create_runtime_view(db)
        db.execute("ANALYZE")
        db.commit()
        violations = db.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"materialized catalog has foreign key violations: {violations[:5]}")
        build_sqlite_catalog.validate_database(db)
        counts = {
            "plugins": int(db.execute("SELECT COUNT(*) FROM plugins WHERE active=1").fetchone()[0]),
            "variants": int(db.execute("SELECT COUNT(*) FROM plugin_variants WHERE active=1").fetchone()[0]),
            "sources": int(db.execute("SELECT COUNT(*) FROM sources").fetchone()[0]),
        }
    return {
        "schema": "omega.catalog-json.materialization.v1",
        "catalogRevision": str(index.get("catalogRevision") or ""),
        "definitionsRevision": definitions_revision,
        "database": str(database),
        "counts": counts,
        "sha256": sha256_file(database),
    }


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export")
    export.add_argument("--database", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path)
    export.add_argument("--built-from-dev-commit", "--source-commit", dest="source_commit", default="", help="Optional development provenance only; never an execution dependency")
    validate = sub.add_parser("validate")
    validate.add_argument("--root", required=True, type=Path)
    materialize = sub.add_parser("materialize")
    materialize.add_argument("--root", required=True, type=Path)
    materialize.add_argument("--database", required=True, type=Path)
    materialize.add_argument("--definitions-revision", default="")
    args = parser.parse_args()
    if args.command == "export":
        result = export_snapshot(args.database, args.output, source_commit=args.source_commit)
    elif args.command == "validate":
        result = validate_snapshot(args.root)
        if not result.get("ok"):
            print(json.dumps(result, indent=2))
            return 1
    else:
        result = materialize_snapshot(args.root, args.database, definitions_revision=args.definitions_revision)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
