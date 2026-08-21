from __future__ import annotations

from collections import defaultdict
import sys
import unittest

import common
CATALOG = common.ROOT / "tools" / "catalog"
SECURITY = common.ROOT / "tools" / "security"
for path in (CATALOG, SECURITY):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import behavior_consistency
import plugin_profile
import project_marketplace_catalog
import security_evidence_v2
import sigmascope


PROFILE = b"""schema: omega.plugin-profile.v1
capabilities:
  - id: network.http
    expected: true
    required: true
    reason: Uses Universalis for market data.
    destinations: [universalis.app]
  - id: process.execute
    expected: false
    reason: External process launch is not intentional.
  - id: filesystem.write
    expected: true
    reason: Stores plugin configuration.
services:
  - id: universalis
    name: Universalis
    url: https://universalis.app
    purpose: Market data API.
    required: true
"""


class BehaviorConsistencyTests(unittest.TestCase):
    def _report(self) -> dict:
        observation = plugin_profile.validate_profile_bytes(PROFILE)
        return {
            "capabilities": ["Network access", "Process execution", "Clipboard access"],
            "capabilityIds": ["network.http", "process.execute", "privacy.clipboard"],
            "capabilityRegistryRevision": observation["profile"]["capabilityRegistryRevision"],
            "source": {"developerProfile": observation},
            "dependencyIntelligence": {
                "networkEndpoints": [
                    {
                        "host": "universalis.app", "url": "https://universalis.app/api/v2", "confidence": "High",
                        "classification": "recognised-platform", "originType": "source-code", "concreteDestinationEvidence": True,
                        "evidence": ["source:Plugin/Market.cs: https://universalis.app/api/v2"],
                    },
                    {
                        "host": "unexpected.example.net", "url": "https://unexpected.example.net/api", "confidence": "Medium",
                        "classification": "unrecognised-host", "originType": "artifact-config", "concreteDestinationEvidence": True,
                        "evidence": ["artifact:config.json: https://unexpected.example.net/api"],
                    },
                ],
                "endpointSummary": {"destinationsUndetermined": False},
                "permissionCandidates": [],
            },
            "automation": {"capabilities": []},
        }

    def test_comparison_separates_expected_undeclared_and_not_expected(self) -> None:
        result = behavior_consistency.compute_behavior_consistency(self._report())
        by_id = {row["id"]: row for row in result["capabilities"]}
        self.assertEqual("expected-observed", by_id["network.http"]["state"])
        self.assertEqual("not-expected-observed", by_id["process.execute"]["state"])
        self.assertEqual("observed-undeclared", by_id["privacy.clipboard"]["state"])
        self.assertEqual("expected-not-observed", by_id["filesystem.write"]["state"])
        self.assertEqual(1, result["summary"]["notExpectedObservedCount"])
        self.assertEqual(1, result["summary"]["observedUndeclaredCount"])
        self.assertEqual(1, result["summary"]["expectedNotObservedCount"])

    def test_destination_comparison_matches_declared_service_and_keeps_unexplained(self) -> None:
        result = behavior_consistency.compute_behavior_consistency(self._report())
        self.assertEqual(["universalis.app"], [row["host"] for row in result["destinations"]["explained"]])
        self.assertEqual(["unexpected.example.net"], [row["host"] for row in result["destinations"]["unexplained"]])
        self.assertEqual(1, result["summary"]["explainedDestinationCount"])
        self.assertEqual(1, result["summary"]["unexplainedDestinationCount"])

    def test_wildcard_destination_matches_subdomains_but_not_base_domain(self) -> None:
        self.assertTrue(behavior_consistency.destination_matches("*.example.com", "api.example.com"))
        self.assertTrue(behavior_consistency.destination_matches("*.example.com", "deep.api.example.com"))
        self.assertFalse(behavior_consistency.destination_matches("*.example.com", "example.com"))
        self.assertTrue(behavior_consistency.destination_matches("example.com", "example.com"))

    def test_no_profile_does_not_label_observations_as_undeclared(self) -> None:
        report = self._report()
        report["source"] = {}
        result = behavior_consistency.compute_behavior_consistency(report)
        self.assertFalse(result["profileAvailable"])
        self.assertEqual(3, result["summary"]["observedWithoutProfileCount"])
        self.assertEqual(0, result["summary"]["observedUndeclaredCount"])
        self.assertEqual(2, result["summary"]["observedDestinationWithoutProfileCount"])
        self.assertEqual(0, result["summary"]["unexplainedDestinationCount"])

    def test_developer_profile_url_cannot_prove_its_own_observed_destination(self) -> None:
        report = self._report()
        report["dependencyIntelligence"]["networkEndpoints"].append({
            "host": "profile-only.example.org", "url": "https://profile-only.example.org", "confidence": "High",
            "classification": "unrecognised-host", "originType": "source-code", "concreteDestinationEvidence": True,
            "evidence": ["source:Plugin/.omega/plugin.yaml: https://profile-only.example.org"],
        })
        result = behavior_consistency.compute_behavior_consistency(report)
        self.assertNotIn("profile-only.example.org", [row["host"] for row in result["destinations"]["observed"]])

    def test_source_scanner_does_not_treat_omega_profile_as_independent_source_code(self) -> None:
        files = {
            "Plugin/Plugin.csproj": b'<Project Sdk="Dalamud.NET.Sdk"><PropertyGroup><AssemblyName>Fixture</AssemblyName></PropertyGroup></Project>',
            "Plugin/Plugin.cs": b"namespace Fixture; public class Plugin {}",
            "Plugin/.omega/plugin.yaml": PROFILE.replace(b"https://universalis.app", b"https://profile-only.example.org"),
        }
        intel, scope, _scanned, _manifest, profile = sigmascope._inspect_source_tree(
            {key: len(value) for key, value in files.items()}, lambda path: files.get(path, b""), defaultdict(list),
            "Fixture", "Fixture", "", analyze=True,
        )
        self.assertEqual("plugin-build-graph", scope["mode"])
        self.assertTrue(profile["valid"])
        self.assertNotIn("profile-only.example.org", [row.get("host") for row in intel.get("networkEndpoints") or []])
        self.assertNotIn("Plugin/.omega/plugin.yaml", [row.get("path") for row in intel.get("sourceFiles") or []])

    def test_evidence_transport_reprojects_behavior_consistency_without_rescan(self) -> None:
        report = self._report()
        compact = security_evidence_v2.compact_report_for_transport({
            "status": "complete", "report_json": report,
        })
        behavior = compact["behaviorConsistency"]
        self.assertEqual("omega.sigmascope.behavior-consistency.v1", behavior["schema"])
        self.assertEqual(1, behavior["summary"]["notExpectedObservedCount"])
        self.assertEqual(1, behavior["summary"]["unexplainedDestinationCount"])

    def test_marketplace_projection_exposes_behavior_summary_without_changing_findings(self) -> None:
        import json
        import sqlite3
        report = self._report()
        db = sqlite3.connect(":memory:")
        db.execute("""CREATE TABLE marketplace_security_current(
            variant_id INTEGER PRIMARY KEY,scan_id INTEGER,
            behavior_consistency_json TEXT DEFAULT '{}',behavior_observed_undeclared_count INTEGER DEFAULT 0,
            behavior_not_expected_observed_count INTEGER DEFAULT 0,behavior_expected_not_observed_count INTEGER DEFAULT 0,
            behavior_unexplained_destination_count INTEGER DEFAULT 0)""")
        db.execute("CREATE TABLE plugin_security_scans(scan_id INTEGER PRIMARY KEY,report_json TEXT)")
        db.execute("INSERT INTO marketplace_security_current(variant_id,scan_id) VALUES(1,7)")
        db.execute("INSERT INTO plugin_security_scans(scan_id,report_json) VALUES(7,?)", (json.dumps(report),))
        project_marketplace_catalog.refresh_marketplace_behavior_consistency(db)
        row = db.execute("""SELECT behavior_consistency_json,behavior_observed_undeclared_count,
                                    behavior_not_expected_observed_count,behavior_expected_not_observed_count,
                                    behavior_unexplained_destination_count
                               FROM marketplace_security_current WHERE variant_id=1""").fetchone()
        projected = json.loads(row[0])
        self.assertEqual(1, row[1])
        self.assertEqual(1, row[2])
        self.assertEqual(1, row[3])
        self.assertEqual(1, row[4])
        self.assertEqual("privacy.clipboard", next(item["id"] for item in projected["capabilities"] if item["state"] == "observed-undeclared"))
        db.close()


if __name__ == "__main__":
    unittest.main()
