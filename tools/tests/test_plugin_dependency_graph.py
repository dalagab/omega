from __future__ import annotations

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
            INSERT INTO plugins VALUES(1,'Consumer'),(2,'Provider'),(3,'IpcProvider');
            CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY,plugin_id INTEGER,assembly_version TEXT);
            INSERT INTO plugin_variants VALUES(10,1,'1.0.0'),(20,2,'2.0.0'),(30,3,'3.0.0');
            CREATE TABLE plugin_security_current(variant_id INTEGER PRIMARY KEY,scan_id INTEGER,status TEXT);
            INSERT INTO plugin_security_current VALUES(10,100,'complete');
            CREATE TABLE plugin_security_dependencies(
                dependency_id INTEGER PRIMARY KEY,scan_id INTEGER,origin TEXT
            );
            INSERT INTO plugin_security_dependencies VALUES(1,100,'source-project');
            INSERT INTO plugin_security_dependencies VALUES(2,100,'artifact-ipc');
            CREATE TABLE plugin_security_dependency_resolutions(
                dependency_id INTEGER,source_variant_id INTEGER,source_plugin_id INTEGER,scan_id INTEGER,
                dependency_kind TEXT,dependency_name TEXT,version_requirement TEXT,resolved_version TEXT,
                requirement TEXT,relationship TEXT,relationship_confidence TEXT,confidence TEXT,
                resolution_status TEXT,version_status TEXT,target_plugin_id INTEGER,target_internal_name TEXT,target_version TEXT
            );
            INSERT INTO plugin_security_dependency_resolutions VALUES(
                1,10,1,100,'external-plugin','Provider','>=2.0','2.0.0',
                'required','','VeryHigh','very-high','resolved-plugin','compatible',2,'Provider','2.0.0'
            );
            INSERT INTO plugin_security_dependency_resolutions VALUES(
                2,10,1,100,'ipc','Some.Channel','','',
                'required','required','High','high','resolved-plugin','compatible',3,'IpcProvider','3.0.0'
            );
        """)
        return db

    def test_build_graph_projects_plugin_requirements_and_excludes_ipc(self) -> None:
        db = self.database()
        try:
            graph = plugin_dependency_graph.build_graph(db)
        finally:
            db.close()
        self.assertEqual(1, graph["counts"]["edges"])
        self.assertEqual(1, graph["counts"]["providers"])
        edge = graph["edges"][0]
        self.assertEqual("Consumer", edge["consumerInternalName"])
        self.assertEqual("Provider", edge["providerInternalName"])
        self.assertEqual("required", edge["relationship"])
        self.assertEqual(">=2.0", edge["versionConstraint"])
        self.assertTrue(edge["installEligible"])
        self.assertNotEqual("IpcProvider", edge["providerInternalName"])
        self.assertEqual(1, graph["providers"][0]["requiredByCount"])
        self.assertEqual("Consumer", graph["providers"][0]["requiredBy"][0]["internalName"])

    def test_materialized_tables_support_reverse_dependency_queries(self) -> None:
        db = self.database()
        graph = plugin_dependency_graph.materialize_catalog_tables(db)
        row = db.execute(
            "SELECT relationship,install_eligible FROM plugin_dependencies WHERE provider_internal_name='Provider'"
        ).fetchone()
        provider = db.execute(
            "SELECT required_by_count,total_dependent_plugins FROM plugin_dependency_providers WHERE provider_internal_name='Provider'"
        ).fetchone()
        revision = dict(db.execute("SELECT key,value FROM catalog_meta"))["dependency_graph_revision"]
        db.close()
        self.assertEqual(("required", 1), row)
        self.assertEqual((1, 1), provider)
        self.assertEqual(graph["dependencyGraphRevision"], revision)


if __name__ == "__main__":
    unittest.main()
