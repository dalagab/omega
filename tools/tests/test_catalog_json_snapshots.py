from __future__ import annotations

from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import common
import test_sqlite_catalog
import catalog_json_store
import catalog_state
import definitions_snapshot


class CatalogJsonSnapshotTests(unittest.TestCase):
    def test_canonical_json_round_trips_base_catalog_exactly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-catalog-json-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            built = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
            source_db = built / "omega-catalog.sqlite"
            snapshot = root / "catalog-json"
            index = catalog_json_store.export_snapshot(source_db, snapshot, source_commit="fixture-commit")
            validation = catalog_json_store.validate_snapshot(snapshot)
            self.assertTrue(validation["ok"], validation)
            self.assertEqual("fixture-commit", index["sourceCommit"])

            materialized = root / "materialized.sqlite"
            report = catalog_json_store.materialize_snapshot(snapshot, materialized, definitions_revision="defs-fixture")
            self.assertEqual(index["counts"]["plugins"], report["counts"]["plugins"])
            self.assertEqual(index["counts"]["variants"], report["counts"]["variants"])
            self.assertEqual(index["counts"]["sources"], report["counts"]["sources"])

            tables = catalog_json_store.BASE_TABLES
            with closing(sqlite3.connect(source_db)) as source, closing(sqlite3.connect(materialized)) as target:
                for table in tables:
                    source_rows = source.execute(f'SELECT * FROM "{table}"').fetchall()
                    target_rows = target.execute(f'SELECT * FROM "{table}"').fetchall()
                    self.assertEqual(sorted(source_rows, key=repr), sorted(target_rows, key=repr), table)
                self.assertEqual("defs-fixture", target.execute("SELECT value FROM catalog_meta WHERE key='definitions_revision'").fetchone()[0])

            plugin_index = json.loads((snapshot / "plugins" / "index.json").read_text(encoding="utf-8"))
            active_variants = sum(int(row.get("activeVariantCount") or 0) for row in plugin_index["plugins"] if row.get("active"))
            self.assertEqual(index["counts"]["variants"], active_variants)
            self.assertTrue(all("activeVariantIds" in row for row in plugin_index["plugins"]))

    def test_definitions_revision_includes_exact_osv_query_identities(self) -> None:
        def evidence(root: Path, name: str) -> Path:
            target = root / name
            (target / "indexes").mkdir(parents=True)
            nuget = {
                "schema": "omega.security-evidence.nuget-index.v2",
                "packages": [{"name": name, "version": "1.0.0", "observations": 1}],
            }
            (target / "indexes" / "nuget.json").write_text(json.dumps(nuget), encoding="utf-8")
            (target / "index.json").write_text(json.dumps({
                "schema": "omega.security-evidence.v2",
                "revisions": {"evidenceRevision": "ev-fixture"},
                "indexes": {"nuget": {"path": "indexes/nuget.json"}},
            }), encoding="utf-8")
            return target

        frozen_advisories = {
            "schema": "omega.public-advisories.v1",
            "source": "OSV",
            "ecosystem": "NuGet",
            "queriedPackages": 1,
            "matchedPackages": 0,
            "advisories": [],
        }
        with tempfile.TemporaryDirectory(prefix="omega-definitions-") as td:
            root = Path(td)
            advisory_file = root / "advisories.json"
            advisory_file.write_text(json.dumps(frozen_advisories), encoding="utf-8")
            first = definitions_snapshot.build_snapshot(
                repo_root=common.ROOT,
                evidence_root=evidence(root, "Package.One"),
                output=root / "defs-one",
                source_commit="same-commit",
                advisories_input=advisory_file,
            )
            second = definitions_snapshot.build_snapshot(
                repo_root=common.ROOT,
                evidence_root=evidence(root, "Package.Two"),
                output=root / "defs-two",
                source_commit="same-commit",
                advisories_input=advisory_file,
            )
            self.assertNotEqual(first["definitionsRevision"], second["definitionsRevision"])
            self.assertEqual(first["ruleSetRevision"], second["ruleSetRevision"], "OSV query changes must not force artifact rescans")
            self.assertTrue(first["ruleSetRevision"].startswith("rules-v1-"))

    def test_catalog_state_validation_detects_definition_payload_tampering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-catalog-state-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            built = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
            catalog_json_store.export_snapshot(built / "omega-catalog.sqlite", root / "catalog", source_commit="fixture")

            evidence = root / "evidence"
            (evidence / "indexes").mkdir(parents=True)
            (evidence / "indexes" / "nuget.json").write_text(json.dumps({"schema": "omega.security-evidence.nuget-index.v2", "packages": []}), encoding="utf-8")
            (evidence / "index.json").write_text(json.dumps({"revisions": {"evidenceRevision": "ev-fixture"}, "indexes": {"nuget": {"path": "indexes/nuget.json"}}}), encoding="utf-8")
            advisories = root / "advisories.json"
            advisories.write_text(json.dumps({"schema": "omega.public-advisories.v1", "source": "OSV", "ecosystem": "NuGet", "queriedPackages": 0, "matchedPackages": 0, "advisories": []}), encoding="utf-8")
            definitions_snapshot.build_snapshot(repo_root=common.ROOT, evidence_root=evidence, output=root / "definitions", source_commit="fixture", advisories_input=advisories)
            catalog_state.assemble(catalog=root / "catalog", definitions=root / "definitions", output=root / "state")
            self.assertTrue(catalog_state.validate(root / "state")["ok"])
            reputation = root / "state" / "definitions" / "reputation.json"
            reputation.write_text(reputation.read_text(encoding="utf-8") + " ", encoding="utf-8")
            report = catalog_state.validate(root / "state")
            self.assertFalse(report["ok"])
            self.assertTrue(any("reputation payload SHA-256 mismatch" in item for item in report["errors"]), report)


if __name__ == "__main__":
    unittest.main()
