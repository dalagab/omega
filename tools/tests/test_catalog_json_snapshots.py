from __future__ import annotations

from contextlib import closing
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import common
import test_sqlite_catalog
import catalog_json_store
import catalog_json_v1_seed
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
            self.assertEqual("fixture-commit", index["builtFromDevCommit"])
            self.assertEqual(catalog_json_store.IDENTITY_EPOCH, index["identityEpoch"])
            self.assertTrue(index["catalogRevision"].startswith("cat-json-v1-"), "client-facing catalog revision mapping remains stable")

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
                self.assertEqual(catalog_json_store.IDENTITY_EPOCH, target.execute("SELECT value FROM catalog_meta WHERE key='catalog_identity_epoch'").fetchone()[0])

            plugin_index = json.loads((snapshot / "plugins" / "index.json").read_text(encoding="utf-8"))
            active_variants = sum(int(row.get("activeVariantCount") or 0) for row in plugin_index["plugins"] if row.get("active"))
            self.assertEqual(index["counts"]["variants"], active_variants)
            self.assertTrue(all("activeVariantIds" in row for row in plugin_index["plugins"]))
            identity_index = json.loads((snapshot / "identity" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual("omega.catalog-json.identity-index.v2", identity_index["schema"])
            self.assertEqual(set(catalog_json_store.IDENTITY_TABLES), set(identity_index["tables"]))
            self.assertFalse((snapshot / "identity" / "model.json").exists())

    def test_catalog_json_has_one_current_internal_format_and_no_legacy_identity_reader(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-catalog-current-format-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            built = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
            snapshot = root / "catalog-json"
            index = catalog_json_store.export_snapshot(built / "omega-catalog.sqlite", snapshot, source_commit="fixture-dev")

            self.assertEqual("omega.catalog-json.v2", index["schema"])
            self.assertEqual(2, index["formatVersion"])
            self.assertEqual("omega-catalog-identity-v1", index["identityEpoch"])
            self.assertTrue((snapshot / "identity" / "index.json").is_file())
            self.assertFalse((snapshot / "identity" / "model.json").exists())

            # There is no compatibility reader for the retired monolithic identity shape.
            (snapshot / "identity" / "index.json").unlink()
            with self.assertRaisesRegex(RuntimeError, "catalog JSON snapshot failed validation"):
                catalog_json_store.materialize_snapshot(snapshot, root / "must-not-materialize.sqlite")

            result = subprocess.run(
                [sys.executable, str(common.ROOT / "tools" / "catalog" / "catalog_json_store.py"), "identity-compatible", "--root", str(snapshot)],
                cwd=common.ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("invalid choice", result.stderr)

    def test_identity_rows_over_16_mib_are_sharded_and_round_trip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-catalog-large-identity-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            built = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
            source_db = built / "omega-catalog.sqlite"

            with closing(sqlite3.connect(source_db)) as db:
                plugin_id = int(db.execute("SELECT plugin_id FROM plugins ORDER BY plugin_id LIMIT 1").fetchone()[0])
                next_alias = int(db.execute("SELECT COALESCE(MAX(alias_id), 0) + 1 FROM plugin_identity_aliases").fetchone()[0])
                payload = "x" * 800_000
                for offset in range(24):
                    value = f"stress-{offset:04d}-" + payload
                    db.execute(
                        """INSERT INTO plugin_identity_aliases(
                            alias_id,plugin_id,alias_type,alias_value,normalized_value,source_kind,confidence,active
                        ) VALUES(?,?,?,?,?,?,?,?)""",
                        (next_alias + offset, plugin_id, "stress", f"alias-{offset:04d}", value, "test", 100, 1),
                    )
                db.commit()

            snapshot = root / "catalog-json"
            index = catalog_json_store.export_snapshot(source_db, snapshot, source_commit="large-fixture")
            validation = catalog_json_store.validate_snapshot(snapshot)
            self.assertTrue(validation["ok"], validation)

            identity_index = json.loads((snapshot / "identity" / "index.json").read_text(encoding="utf-8"))
            alias_table = identity_index["tables"]["plugin_identity_aliases"]
            self.assertGreater(len(alias_table["shards"]), 1)
            self.assertGreater(sum(int(row["bytes"]) for row in alias_table["shards"]), catalog_json_store.MAX_FILE_BYTES)
            for shard in alias_table["shards"]:
                self.assertLessEqual(int(shard["bytes"]), catalog_json_store.MAX_FILE_BYTES)
                self.assertTrue((snapshot / shard["path"]).is_file())

            materialized = root / "materialized.sqlite"
            catalog_json_store.materialize_snapshot(snapshot, materialized)
            with closing(sqlite3.connect(source_db)) as source, closing(sqlite3.connect(materialized)) as target:
                expected = source.execute("SELECT COUNT(*) FROM plugin_identity_aliases").fetchone()[0]
                actual = target.execute("SELECT COUNT(*) FROM plugin_identity_aliases").fetchone()[0]
                self.assertEqual(expected, actual)
            self.assertEqual("omega.catalog-json.v2", index["schema"])


    def test_phase4_v1_seed_converter_preserves_exact_integer_identities(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-catalog-v1-seed-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            built = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
            source_db = built / "omega-catalog.sqlite"
            predecessor = root / "predecessor"
            catalog_json_store.export_snapshot(source_db, predecessor, source_commit="phase4-predecessor")

            # Build the exact retired shape from our own current data. The normal reader
            # deliberately does not know how to consume this monolith.
            identity_rows = catalog_json_store._read_identity_store(predecessor)
            for path in (predecessor / "identity").rglob("*.json"):
                path.unlink()
            model_descriptor = catalog_json_store.write_json(predecessor / "identity" / "model.json", {
                "schema": "omega.catalog-json.identity-model.v1",
                "manifestObservations": identity_rows["manifest_observations"],
                "sourceRepositories": identity_rows["source_repositories"],
                "sourceRepositoryAliases": identity_rows["source_repository_aliases"],
                "manifestSourceCandidates": identity_rows["manifest_source_candidates"],
                "pluginIdentityAliases": identity_rows["plugin_identity_aliases"],
            })
            model_descriptor["path"] = "identity/model.json"
            index_path = predecessor / "index.json"
            old_index = json.loads(index_path.read_text(encoding="utf-8"))
            old_index["schema"] = "omega.catalog-json.v1"
            old_index["formatVersion"] = 1
            old_index["files"] = [
                row for row in old_index["files"]
                if not str(row.get("path") or "").startswith("identity/")
            ] + [model_descriptor]
            index_path.write_text(json.dumps(old_index, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

            converted = root / "converted.sqlite"
            report = catalog_json_v1_seed.materialize_v1_seed(predecessor, converted)
            self.assertEqual(catalog_json_store.IDENTITY_EPOCH, report["identityEpoch"])
            with closing(sqlite3.connect(source_db)) as source, closing(sqlite3.connect(converted)) as target:
                for table in catalog_json_store.BASE_TABLES:
                    source_rows = source.execute(f'SELECT * FROM "{table}"').fetchall()
                    target_rows = target.execute(f'SELECT * FROM "{table}"').fetchall()
                    self.assertEqual(sorted(source_rows, key=repr), sorted(target_rows, key=repr), table)

            current = root / "current-v2"
            catalog_json_store.export_snapshot(source_db, current, source_commit="current")
            with self.assertRaisesRegex(RuntimeError, "unexpected schema"):
                catalog_json_v1_seed.materialize_v1_seed(current, root / "no.sqlite")

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
            self.assertEqual(first["scannerRevision"], second["scannerRevision"], "data-only Definitions changes reuse the exact frozen worker bundle")
            self.assertTrue(first["ruleSetRevision"].startswith("rules-v1-"))
            self.assertTrue(first["scannerRevision"].startswith("scanner-v1-"))
            validation = definitions_snapshot.verify_snapshot(definitions_root=root / "defs-one")
            self.assertTrue(validation["ok"], validation)
            self.assertEqual(first["scannerRevision"], validation["scannerRevision"])
            self.assertTrue((root / "defs-one" / "worker" / "tools" / "security" / "production_sigmascope_v2_pipeline.py").is_file())
            self.assertTrue((root / "defs-one" / "worker" / "sources" / "source-overrides.json").is_file())

    def test_frozen_worker_bundle_detects_tampering_without_dev_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-worker-bundle-") as td:
            root = Path(td)
            evidence = root / "evidence"
            (evidence / "indexes").mkdir(parents=True)
            (evidence / "indexes" / "nuget.json").write_text(json.dumps({"schema": "omega.security-evidence.nuget-index.v2", "packages": []}), encoding="utf-8")
            (evidence / "index.json").write_text(json.dumps({"revisions": {"evidenceRevision": "ev-fixture"}, "indexes": {"nuget": {"path": "indexes/nuget.json"}}}), encoding="utf-8")
            advisories = root / "advisories.json"
            advisories.write_text(json.dumps({"schema": "omega.public-advisories.v1", "source": "OSV", "ecosystem": "NuGet", "queriedPackages": 0, "matchedPackages": 0, "advisories": []}), encoding="utf-8")
            definitions = root / "definitions"
            index = definitions_snapshot.build_snapshot(repo_root=common.ROOT, evidence_root=evidence, output=definitions, source_commit="dev-provenance-only", advisories_input=advisories)
            self.assertEqual("dev-provenance-only", index["builtFromDevCommit"])
            self.assertTrue(definitions_snapshot.verify_snapshot(definitions_root=definitions, repo_root=root / "deleted-dev-checkout")["ok"])
            for relative, args in (("tools/catalog/sigmascope.py", ["--self-test"]), ("tools/security/production_sigmascope_v2_pipeline.py", ["--self-test"])):
                result = subprocess.run([sys.executable, str(definitions / "worker" / relative), *args], cwd=root, text=True, capture_output=True)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            frozen_rule = definitions / "worker" / "tools" / "catalog" / "security_path_access.py"
            frozen_rule.write_text(frozen_rule.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
            report = definitions_snapshot.verify_snapshot(definitions_root=definitions)
            self.assertFalse(report["ok"])
            self.assertTrue(any("worker bundle file" in item or "frozen scanner rule" in item for item in report["errors"]), report)

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
