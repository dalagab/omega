from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from argparse import Namespace
from contextlib import closing
from unittest import mock
import sqlite3

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tools" / "catalog"
SECURITY = ROOT / "tools" / "security"
for path in (CATALOG, SECURITY):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import local_security_v2_test_scanner
import security_scan


class LocalSecurityV2TestScannerTests(unittest.TestCase):
    def test_dotnet_deps_json_yields_exact_nuget_versions_from_artifact(self) -> None:
        deps = {
            "runtimeTarget": {"name": ".NETCoreApp,Version=v9.0/win-x64"},
            "libraries": {
                "FixturePlugin/1.0.0": {"type": "project"},
                "Newtonsoft.Json/13.0.3": {"type": "package"},
                "Microsoft.Extensions.Http/9.0.0": {"type": "package"},
            },
        }
        payload = Path("FixturePlugin.deps.json")
        intel = security_scan.empty_dependency_intelligence("artifact")
        security_scan.scan_dependency_json(str(payload), json.dumps(deps), intel)
        security_scan.finalize_intelligence(intel)
        found = {
            (item["kind"], item["name"], item.get("resolvedVersion", ""))
            for item in intel["dependencies"]
        }
        self.assertIn(("nuget-resolved", "Newtonsoft.Json", "13.0.3"), found)
        self.assertIn(("nuget-resolved", "Microsoft.Extensions.Http", "9.0.0"), found)
        self.assertNotIn(("nuget-resolved", "FixturePlugin", "1.0.0"), found)

    def test_archive_scan_uses_packaged_deps_json_without_source_repository(self) -> None:
        deps = {
            "libraries": {
                "FixturePlugin/1.0.0": {"type": "project"},
                "Newtonsoft.Json/13.0.3": {"type": "package"},
            }
        }
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "fixture.zip"
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("FixturePlugin.deps.json", json.dumps(deps))
            intel = security_scan.empty_dependency_intelligence("artifact")
            security_scan.scan_archive(bundle.read_bytes(), defaultdict(list), intel)
            security_scan.finalize_intelligence(intel)
        self.assertTrue(any(
            item["kind"] == "nuget-resolved"
            and item["name"] == "Newtonsoft.Json"
            and item.get("resolvedVersion") == "13.0.3"
            for item in intel["dependencies"]
        ))


    def test_local_runner_populates_fresh_v2_nuget_index_from_packaged_deps(self) -> None:
        deps = {
            "libraries": {
                "FixturePlugin/1.0.0": {"type": "project"},
                "Newtonsoft.Json/13.0.3": {"type": "package"},
            }
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.sqlite"
            with closing(sqlite3.connect(source)) as db:
                db.executescript("""
                    CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    INSERT INTO catalog_meta VALUES('security_revision','sec-test');
                    INSERT INTO catalog_meta VALUES('evidence_revision','ev-test');
                    INSERT INTO catalog_meta VALUES('catalog_revision','cat-test');
                    INSERT INTO catalog_meta VALUES('base_revision','base-test');
                    CREATE TABLE sources(source_id INTEGER PRIMARY KEY,name TEXT,url TEXT,source_repo_url TEXT,is_official INTEGER);
                    CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY,internal_name TEXT,name TEXT,author TEXT,active INTEGER);
                    CREATE TABLE plugin_variants(
                      variant_id INTEGER PRIMARY KEY,plugin_id INTEGER,source_id INTEGER,name TEXT,author TEXT,
                      assembly_version TEXT,testing_assembly_version TEXT,download_link_install TEXT,download_link_testing TEXT,
                      repo_url TEXT,active INTEGER
                    );
                    CREATE TABLE presentation(plugin_id INTEGER PRIMARY KEY,preferred_variant_id INTEGER);
                    INSERT INTO sources VALUES(1,'Fixture','https://example.invalid/repo.json','',0);
                    INSERT INTO plugins VALUES(1,'FixturePlugin','Fixture Plugin','Tester',1);
                    INSERT INTO plugin_variants VALUES(1,1,1,'Fixture Plugin','Tester','1.0.0','','https://example.invalid/plugin.zip','','',1);
                    INSERT INTO presentation VALUES(1,1);
                """)
                db.commit()
            bundle = root / "plugin.zip"
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("FixturePlugin.deps.json", json.dumps(deps))
            artifact = bundle.read_bytes()
            args = Namespace(
                database=source, evidence=None, work_dir=root / "work", v2_output=None, max_scans=1, all=False,
                internal_names="FixturePlugin", rescan_after_hours=168, force_rescan=False, max_batch_seconds=0,
                source_overrides=root / "missing-overrides.json", skip_source=True, skip_osv=True, osv_timeout=1.0,
                max_osv_packages=2000, no_v2=False, quick_validation=True, reset=True,
            )
            with mock.patch.object(security_scan, "request_bytes", return_value=(artifact, "https://example.invalid/plugin.zip")):
                result = local_security_v2_test_scanner.run_local_scan(args)
            self.assertEqual(result["summary"]["completeScans"], 1)
            self.assertEqual(result["summary"]["nugetPackageVersionPairs"], 1)
            self.assertGreaterEqual(result["summary"]["depsJsonDependencyObservations"], 1)
            self.assertTrue(result["v2"]["validation"]["ok"], result["v2"]["validation"])
            index = json.loads((root / "work" / "security-evidence-v2-test" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["counts"]["nugetPackageVersionPairs"], 1)

    def test_local_scanner_self_test(self) -> None:
        local_security_v2_test_scanner.self_test()


if __name__ == "__main__":
    unittest.main()
