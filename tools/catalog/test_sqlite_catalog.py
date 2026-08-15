#!/usr/bin/env python3
"""Fast self-test for Omega's SQLite catalog builder.

Exercises the storage invariants that matter independently of live network access:
- one canonical SQLite database + strict schema
- raw manifest preservation
- source failure retains last-known-good variants when seeded
- successful source refresh is authoritative for that source
- website scrape failure retains last-known-good enrichment
- rich presentation source may differ from preferred installation source
- indexed search projection is populated
"""
from __future__ import annotations

from contextlib import closing
import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def run_builder(root: Path, out: Path, curated: Path, raw: Path, enriched: Path, websites: Path, seed: Path | None = None) -> None:
    cmd = [
        sys.executable, str(root / "tools/catalog/build_sqlite_catalog.py"),
        "--out", str(out),
        "--curated", str(curated),
        "--raw-sources", str(raw),
        "--enriched-sources", str(enriched),
        "--website-enrichment", str(websites),
        "--download-url", "https://example.invalid/omega-catalog.sqlite.zip",
        "--descriptor-url", "https://example.invalid/catalog.json",
    ]
    if seed:
        cmd += ["--seed", str(seed)]
    subprocess.run(cmd, check=True, cwd=root, stdout=subprocess.DEVNULL)


def query(db_path: Path, sql: str, args: tuple = ()):
    with closing(sqlite3.connect(db_path)) as db:
        return db.execute(sql, args).fetchone()


def fixture_documents(tmp: Path) -> tuple[Path, Path, Path, Path]:
    official = "https://example.invalid/official.json"
    rich = "https://example.invalid/rich.json"
    curated = tmp / "curated.json"
    raw = tmp / "raw.json"
    enriched = tmp / "enriched.json"
    websites = tmp / "websites.json"
    write_json(curated, [
        {"id": "official", "name": "Official", "url": official, "isOfficial": True, "enabledByDefault": True},
        {"id": "rich", "name": "Rich", "url": rich, "isOfficial": False, "enabledByDefault": True},
    ])
    write_json(raw, {"sources": [
        {"url": official, "provider": "Official", "kind": "curated", "discoveredBy": "test"},
        {"url": rich, "provider": "Rich", "kind": "curated", "discoveredBy": "test"},
    ]})
    base = {
        "author": "Author", "name": "Example", "internalName": "ExamplePlugin",
        "punchline": "Useful example", "description": "A useful example plugin with enough descriptive content for a product page.",
        "tags": ["utility"], "categoryTags": ["utility"], "dalamudApiLevel": 15,
        "assemblyVersion": "1.0.0.0", "applicableVersion": "any", "downloadLinkInstall": "https://example.invalid/plugin.zip",
        "rawManifest": {"Name": "Example", "InternalName": "ExamplePlugin", "CustomFutureField": "preserved"},
    }
    official_plugin = dict(base, iconUrl="https://example.invalid/icon.png", repoUrl="https://example.invalid/project")
    rich_plugin = dict(base, assemblyVersion="0.9.0.0", iconUrl="https://example.invalid/icon-rich.png",
                       repoUrl="https://example.invalid/project", imageUrls=["https://example.invalid/screenshot.png"])
    write_json(enriched, {"sources": [
        {"url": official, "provider": "Official", "ok": True, "plugins": [official_plugin]},
        {"url": rich, "provider": "Rich", "ok": True, "plugins": [rich_plugin]},
    ]})
    write_json(websites, {"repos": {"https://example.invalid/project": {
        "url": "https://example.invalid/project", "ok": True, "description": "Website description",
        "imageUrls": ["https://example.invalid/web.png"], "stars": 42,
    }}})
    return curated, raw, enriched, websites


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    args = ap.parse_args()
    root = Path(args.root).resolve()
    with tempfile.TemporaryDirectory(prefix="omega-sqlite-selftest-") as td:
        tmp = Path(td)
        curated, raw, enriched, websites = fixture_documents(tmp)
        out1 = tmp / "first"
        run_builder(root, out1, curated, raw, enriched, websites)
        db1 = out1 / "omega-catalog.sqlite"
        assert query(db1, "pragma integrity_check")[0] == "ok"
        assert query(db1, "select value from catalog_meta where key='schema_name'")[0] == "omega.catalog.sqlite.v1"
        assert query(db1, "select count(*) from runtime_plugin_variants")[0] == 2
        assert query(db1, "select count(*) from plugin_search")[0] == 1
        raw_manifest = json.loads(query(db1, "select raw_manifest_json from plugin_variants where source_entry_key like 'exampleplugin|1.0.0.0|15|%'")[0])
        assert raw_manifest["CustomFutureField"] == "preserved"
        preferred, presentation = query(db1, "select preferred_variant_id,presentation_variant_id from presentation")
        assert preferred != presentation, "official install source and richer presentation source should be independently selectable"

        # Second run: official source and website transiently fail. Seed must retain both last-known-good records.
        failed_enriched = tmp / "failed-enriched.json"
        failed_websites = tmp / "failed-websites.json"
        rich_url = "https://example.invalid/rich.json"
        official_url = "https://example.invalid/official.json"
        previous = json.loads(enriched.read_text(encoding="utf-8"))
        write_json(failed_enriched, {"sources": [
            {"url": official_url, "provider": "Official", "ok": False, "error": "temporary timeout", "plugins": []},
            previous["sources"][1],
        ]})
        write_json(failed_websites, {"repos": {"https://example.invalid/project": {
            "url": "https://example.invalid/project", "ok": False, "error": "rate limited"
        }}})
        out2 = tmp / "second"
        run_builder(root, out2, curated, raw, failed_enriched, failed_websites, out1 / "omega-catalog.sqlite.zip")
        db2 = out2 / "omega-catalog.sqlite"
        assert query(db2, "select count(*) from runtime_plugin_variants")[0] == 2
        assert query(db2, "select ok from websites where url='https://example.invalid/project'")[0] == 1
        assert "temporary timeout" in query(db2, "select last_error from sources where url=?", (official_url,))[0]
        assert query(db2, "select count(*) from presentation where rich_card=1")[0] == 1

        # Third run: both manifests report HTTP 304. Empty payloads must not deactivate
        # any previously active variants; conditional fetches are state-preserving.
        not_modified = tmp / "not-modified-enriched.json"
        write_json(not_modified, {"sources": [
            {"url": official_url, "provider": "Official", "ok": True, "notModified": True,
             "etag": '"official-etag"', "lastModified": "Thu, 14 Aug 2026 12:00:00 GMT", "plugins": []},
            {"url": rich_url, "provider": "Rich", "ok": True, "notModified": True,
             "etag": '"rich-etag"', "lastModified": "Thu, 14 Aug 2026 12:00:00 GMT", "plugins": []},
        ]})
        out3 = tmp / "third"
        run_builder(root, out3, curated, raw, not_modified, failed_websites, out2 / "omega-catalog.sqlite.zip")
        db3 = out3 / "omega-catalog.sqlite"
        assert query(db3, "select count(*) from runtime_plugin_variants")[0] == 2
        assert query(db3, "select count(*) from plugin_search")[0] == 1
        assert query(db3, "select etag from sources where url=?", (official_url,))[0] == '"official-etag"'
        assert query(db3, "select count(*) from presentation where rich_card=1")[0] == 1

        with zipfile.ZipFile(out3 / "omega-catalog.sqlite.zip") as zf:
            assert zf.namelist() == ["omega-catalog.sqlite"]
    print("Omega SQLite catalog self-test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
