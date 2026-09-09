from __future__ import annotations

import json
import sqlite3
import unittest

import common

CATALOG = common.ROOT / "tools" / "catalog"
import sys
if str(CATALOG) not in sys.path:
    sys.path.insert(0, str(CATALOG))

import plugin_dependency_graph  # noqa: E402


class PluginDependencyGraphTests(unittest.TestCase):
    def database(self) -> sqlite3.Connection:
        db = sqlite3.connect(":memory:")
        db.executescript("""
            CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY,internal_name TEXT);
            INSERT INTO plugins VALUES(1,'Consumer'),(2,'Provider'),(3,'IpcProvider'),(4,'WeakIpcProvider');
            CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY,plugin_id INTEGER,assembly_version TEXT);
            INSERT INTO plugin_variants VALUES(10,1,'1.0.0'),(20,2,'2.0.0'),(30,3,'3.0.0'),(40,4,'4.0.0');
            CREATE TABLE plugin_security_current(variant_id INTEGER PRIMARY KEY,scan_id INTEGER,status TEXT);
            INSERT INTO plugin_security_current VALUES(10,100,'complete');
            CREATE TABLE plugin_security_dependencies(
                dependency_id INTEGER PRIMARY KEY,scan_id INTEGER,origin TEXT
            );
            INSERT INTO plugin_security_dependencies VALUES(1,100,'source-project');
            INSERT INTO plugin_security_dependencies VALUES(2,100,'artifact-ipc');
            INSERT INTO plugin_security_dependencies VALUES(3,100,'source-manifest');
            INSERT INTO plugin_security_dependencies VALUES(4,100,'source-project-reference');
            INSERT INTO plugin_security_dependencies VALUES(5,100,'artifact-ipc');
            CREATE TABLE plugin_security_dependency_resolutions(
                dependency_id INTEGER,source_variant_id INTEGER,source_plugin_id INTEGER,scan_id INTEGER,
                dependency_kind TEXT,dependency_name TEXT,version_requirement TEXT,resolved_version TEXT,
                requirement TEXT,relationship TEXT,relationship_confidence TEXT,confidence TEXT,
                resolution_status TEXT,version_status TEXT,target_plugin_id INTEGER,target_internal_name TEXT,target_version TEXT,
                relationship_evidence_json TEXT
            );
            INSERT INTO plugin_security_dependency_resolutions VALUES(
                1,10,1,100,'external-plugin','Provider','>=2.0','2.0.0',
                'required','','VeryHigh','very-high','resolved-plugin','compatible',2,'Provider','2.0.0','[]'
            );
            INSERT INTO plugin_security_dependency_resolutions VALUES(
                2,10,1,100,'ipc','Weak.Channel','','',
                'soft','required','High','high','resolved-ipc-provider','compatible',4,'WeakIpcProvider','4.0.0',
                '["startup path: Initialize","IPC is invoked directly without an observed availability guard"]'
            );
            INSERT INTO plugin_security_dependency_resolutions VALUES(
                3,10,1,100,'external-plugin','MissingProvider','>=1.0','',
                'required','','High','high','external-unresolved','unknown',0,'','','[]'
            );
            INSERT INTO plugin_security_dependency_resolutions VALUES(
                4,10,1,100,'project-reference','../Shared/Shared.csproj','','',
                'required','','High','high','component','unknown',0,'','','[]'
            );
            INSERT INTO plugin_security_dependency_resolutions VALUES(
                5,10,1,100,'ipc','Hard.Channel','','',
                'soft','required','VeryHigh','very-high','resolved-ipc-provider','compatible',3,'IpcProvider','3.0.0',
                '["startup path: Initialize","missing provider leads to an exception"]'
            );
        """)
        return db

    def test_build_graph_retains_unresolved_requirements_and_excludes_nonpackages(self) -> None:
        db = self.database()
        try:
            graph = plugin_dependency_graph.build_graph(db)
        finally:
            db.close()
        self.assertEqual(3, graph["counts"]["edges"])
        self.assertEqual(2, graph["counts"]["providers"])
        self.assertEqual(2, graph["counts"]["resolvedEdges"])
        self.assertEqual(1, graph["counts"]["unresolvedEdges"])
        self.assertEqual(3, graph["counts"]["requiredEdges"])
        self.assertEqual(1, graph["counts"]["blockedRequiredEdges"])
        self.assertEqual(2, graph["counts"]["installEligibleEdges"])
        self.assertEqual(1, graph["counts"]["promotedIpcEdges"])
        edges = {edge["providerInternalName"]: edge for edge in graph["edges"]}
        edge = edges["Provider"]
        self.assertEqual("Consumer", edge["consumerInternalName"])
        self.assertEqual("Provider", edge["providerInternalName"])
        self.assertEqual("required", edge["relationship"])
        self.assertEqual(">=2.0", edge["versionConstraint"])
        self.assertTrue(edge["installEligible"])
        missing = edges["MissingProvider"]
        self.assertEqual(0, missing["providerPluginId"])
        self.assertEqual("external-unresolved", missing["resolutionStatus"])
        self.assertEqual("required", missing["relationship"])
        self.assertFalse(missing["installEligible"])
        promoted = edges["IpcProvider"]
        self.assertEqual("required", promoted["relationship"])
        self.assertEqual("plugin", promoted["sourceKind"])
        self.assertTrue(promoted["installEligible"])
        self.assertIn("verified-ipc-runtime-requirement", promoted["origins"])
        self.assertNotIn("WeakIpcProvider", edges)
        self.assertNotIn("../Shared/Shared.csproj", edges)
        providers = {item["providerInternalName"]: item for item in graph["providers"]}
        self.assertEqual(1, providers["Provider"]["requiredByCount"])
        self.assertEqual(1, providers["IpcProvider"]["requiredByCount"])
        self.assertEqual("Consumer", providers["Provider"]["requiredBy"][0]["internalName"])

    def test_high_confidence_ipc_requires_explicit_required_evidence_for_promotion(self) -> None:
        common = ("ipc", "required", "High")
        self.assertFalse(plugin_dependency_graph._verified_required_ipc(
            *common,
            '["startup path: Initialize","IPC is invoked directly without an observed availability guard"]',
            "resolved-ipc-provider", 3, "IpcProvider",
        ))
        self.assertTrue(plugin_dependency_graph._verified_required_ipc(
            *common,
            '["explicit required/mandatory dependency marker","startup path: Initialize"]',
            "resolved-ipc-provider", 3, "IpcProvider",
        ))

    def test_materialized_tables_support_reverse_dependency_queries(self) -> None:
        db = self.database()
        graph = plugin_dependency_graph.materialize_catalog_tables(db)
        row = db.execute(
            "SELECT relationship,install_eligible FROM plugin_dependencies WHERE provider_internal_name='Provider'"
        ).fetchone()
        missing = db.execute(
            "SELECT relationship,resolution_status,provider_plugin_id,install_eligible FROM plugin_dependencies WHERE provider_internal_name='MissingProvider'"
        ).fetchone()
        provider = db.execute(
            "SELECT required_by_count,total_dependent_plugins FROM plugin_dependency_providers WHERE provider_internal_name='Provider'"
        ).fetchone()
        promoted = db.execute(
            "SELECT relationship,source_kind,origins_json,install_eligible FROM plugin_dependencies WHERE provider_internal_name='IpcProvider'"
        ).fetchone()
        revision = dict(db.execute("SELECT key,value FROM catalog_meta"))["dependency_graph_revision"]
        db.close()
        self.assertEqual(("required", 1), row)
        self.assertEqual(("required", "external-unresolved", 0, 0), missing)
        self.assertEqual((1, 1), provider)
        self.assertEqual("required", promoted[0])
        self.assertEqual("plugin", promoted[1])
        self.assertIn("verified-ipc-runtime-requirement", json.loads(promoted[2]))
        self.assertEqual(1, promoted[3])
        self.assertEqual(graph["dependencyGraphRevision"], revision)

    def test_materialization_preserves_existing_sqlite_transaction(self) -> None:
        db = self.database()
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        plugin_dependency_graph.materialize_catalog_tables(db)
        self.assertTrue(db.in_transaction)
        db.rollback()
        db.close()


if __name__ == "__main__":
    unittest.main()
