from __future__ import annotations

import sqlite3
import sys
import unittest
from collections import defaultdict

import common
SECURITY = common.ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))
import plugin_profile
import project_marketplace_catalog
import security_evidence_v2
import sigmascope


VALID = b"""schema: omega.plugin-profile.v1
profile:
  tagline: Market helper
  description: Shows prices and can optionally open the project page.
  tags: [market, utility]
  homepage: https://example.com/plugin
capabilities:
  - id: network.http
    expected: true
    required: true
    reason: Fetches market data from the documented API.
    destinations:
      - universalis.app
  - id: process.execute
    expected: false
    reason: The plugin does not intentionally launch external programs.
services:
  - id: universalis
    name: Universalis
    url: https://universalis.app
    purpose: Market-board pricing data.
    required: true
nativeComponents:
  - name: example-native.dll
    purpose: Optional image conversion.
    required: false
ipc:
  - plugin: AllaganTools
    channel: AllaganTools.GetInventory
    purpose: Optional inventory integration.
media:
  icon: .omega/icon.png
  screenshots:
    - .omega/screenshots/main.png
"""


class PluginProfileTests(unittest.TestCase):
    def test_valid_profile_normalizes_capabilities_and_context(self) -> None:
        result = plugin_profile.validate_profile_bytes(VALID)
        self.assertTrue(result["valid"], result)
        profile = result["profile"]
        self.assertEqual("network.http", profile["capabilities"][0]["id"])
        self.assertTrue(profile["capabilities"][0]["expected"])
        self.assertFalse(profile["capabilities"][1]["expected"])
        self.assertEqual("universalis.app", profile["capabilities"][0]["destinations"][0])
        self.assertTrue(profile["capabilityRegistryRevision"].startswith("capabilities-v1-"))

    def test_authority_claim_is_rejected_without_throwing(self) -> None:
        result = plugin_profile.validate_profile_bytes(b"schema: omega.plugin-profile.v1\nsafe: true\n")
        self.assertFalse(result["valid"])
        self.assertEqual("authority-field", result["diagnostics"][0]["code"])

    def test_unknown_capability_is_rejected(self) -> None:
        result = plugin_profile.validate_profile_bytes(
            b"schema: omega.plugin-profile.v1\ncapabilities:\n  - id: magic.rootkit\n    reason: nope\n"
        )
        self.assertFalse(result["valid"])
        self.assertEqual("unknown-capability", result["diagnostics"][0]["code"])

    def test_yaml_aliases_and_duplicate_keys_are_rejected(self) -> None:
        alias = plugin_profile.validate_profile_bytes(
            b"schema: omega.plugin-profile.v1\nprofile: &p\n  tagline: x\ncopy: *p\n"
        )
        self.assertFalse(alias["valid"])
        self.assertEqual("yaml-feature", alias["diagnostics"][0]["code"])
        duplicate = plugin_profile.validate_profile_bytes(
            b"schema: omega.plugin-profile.v1\nprofile:\n  tagline: x\n  tagline: y\n"
        )
        self.assertFalse(duplicate["valid"])
        self.assertEqual("duplicate-key", duplicate["diagnostics"][0]["code"])

    def test_project_local_profile_precedes_repository_root(self) -> None:
        files = {
            "Plugin/Plugin.csproj": b"<Project />",
            "Plugin/.omega/plugin.yaml": VALID,
            ".omega/plugin.yaml": VALID.replace(b"Market helper", b"Root helper"),
        }
        observation = plugin_profile.observe_profile(
            set(files), lambda path: files.get(path, b""), primary_project="Plugin/Plugin.csproj"
        )
        self.assertEqual("Plugin/.omega/plugin.yaml", observation["path"])
        self.assertEqual("Market helper", observation["profile"]["profile"]["tagline"])

    def test_source_tree_invalid_profile_does_not_block_source_analysis(self) -> None:
        files = {
            "Plugin/Plugin.csproj": b'<Project Sdk="Dalamud.NET.Sdk"><PropertyGroup><AssemblyName>Fixture</AssemblyName></PropertyGroup></Project>',
            "Plugin/Plugin.cs": b"namespace Fixture; public class Plugin {}",
            "Plugin/.omega/plugin.yaml": b"schema: omega.plugin-profile.v1\ntrusted: true\n",
        }
        intel, scope, scanned, _manifest, profile = sigmascope._inspect_source_tree(
            {key: len(value) for key, value in files.items()}, lambda path: files.get(path, b""), defaultdict(list), "Fixture", "Fixture", "", analyze=True
        )
        self.assertEqual("plugin-build-graph", scope["mode"])
        self.assertGreaterEqual(scanned, 1)
        self.assertFalse(profile["valid"])
        self.assertEqual("authority-field", profile["diagnostics"][0]["code"])
        self.assertEqual("source", intel["origin"])

    def test_evidence_transport_preserves_bounded_profile(self) -> None:
        observation = plugin_profile.validate_profile_bytes(VALID)
        compact = security_evidence_v2.compact_report_for_transport({
            "status": "complete",
            "source_available": 1,
            "source_repository": "https://github.com/example/plugin",
            "source_commit": "a" * 40,
            "report_json": {
                "status": "complete",
                "source": {"available": True, "repository": "https://github.com/example/plugin", "commit": "a" * 40, "developerProfile": observation},
            },
        })
        projected = compact["source"]["developerProfile"]
        self.assertTrue(projected["valid"])
        self.assertEqual("network.http", projected["profile"]["capabilities"][0]["id"])

    def test_marketplace_projection_exposes_profile_json(self) -> None:
        observation = plugin_profile.validate_profile_bytes(VALID)
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE marketplace_security_current(variant_id INTEGER PRIMARY KEY,scan_id INTEGER,developer_profile_status TEXT DEFAULT 'absent',developer_profile_sha256 TEXT DEFAULT '',developer_profile_json TEXT DEFAULT '{}')")
        db.execute("CREATE TABLE plugin_security_scans(scan_id INTEGER PRIMARY KEY,report_json TEXT)")
        import json
        report = {"source": {"developerProfile": observation}}
        db.execute("INSERT INTO marketplace_security_current(variant_id,scan_id) VALUES(1,7)")
        db.execute("INSERT INTO plugin_security_scans(scan_id,report_json) VALUES(7,?)", (json.dumps(report),))
        project_marketplace_catalog.refresh_marketplace_developer_profiles(db)
        row = db.execute("SELECT developer_profile_status,developer_profile_sha256,developer_profile_json FROM marketplace_security_current WHERE variant_id=1").fetchone()
        self.assertEqual("valid", row[0])
        self.assertEqual(observation["sha256"], row[1])
        self.assertEqual("network.http", json.loads(row[2])["profile"]["capabilities"][0]["id"])
        db.close()

    def test_sigmascope_projects_legacy_capability_labels_to_registry_ids_without_rescan(self) -> None:
        report = {
            "capabilities": ["Network access", "Process execution"],
            "automation": {"capabilities": [{"capabilityId": "game.character.move"}]},
            "dependencyIntelligence": {"permissionCandidates": [{"permissionId": "privacy.clipboard"}]},
        }
        sigmascope._refresh_capability_registry_projection(report)
        self.assertEqual(
            ["game.character.move", "network.http", "privacy.clipboard", "process.execute"],
            report["capabilityIds"],
        )
        self.assertTrue(report["capabilityRegistryRevision"].startswith("capabilities-v1-"))

    def test_evidence_transport_preserves_canonical_capability_projection(self) -> None:
        compact = security_evidence_v2.compact_report_for_transport({
            "status": "complete",
            "report_json": {
                "status": "complete",
                "capabilities": ["Network access"],
                "capabilityIds": ["network.http"],
                "capabilityRegistryRevision": "capabilities-v1-fixture",
                "source": {},
            },
        })
        self.assertEqual(["network.http"], compact["capabilityIds"])
        self.assertEqual("capabilities-v1-fixture", compact["capabilityRegistryRevision"])


if __name__ == "__main__":
    unittest.main()
