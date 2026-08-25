from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "tools" / "security", ROOT / "tools" / "catalog", ROOT / "tools" / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import analysis_broker
import observation_inventory
from test_rule_reprojection import RuleReprojectionTests


class ObservationInventoryTests(unittest.TestCase):
    def helper(self) -> RuleReprojectionTests:
        return RuleReprojectionTests("test_compatible_retained_observations_reproject_without_legacy_findings")

    def test_retained_sigmascope_collection_satisfies_exact_variant_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-observation-inventory-") as td:
            root = Path(td)
            evidence = self.helper().evidence(root)
            inventory = observation_inventory.build_inventory(evidence, generated_at="2026-08-24T20:00:00Z")
            self.assertEqual(analysis_broker.INVENTORY_SCHEMA, inventory["schema"])
            self.assertGreater(inventory["recordCount"], 0)
            request = analysis_broker.compile_request({
                "observation": "staticPatternMatches",
                "subject": {"type": "variant", "variantId": 1, "artifactSha256": "a" * 64},
                "reason": "Stigma needs exact retained static pattern evidence",
                "requestedAtUtc": "2026-08-24T20:00:00Z",
            })
            resolution = analysis_broker.resolve_request(request, inventory=inventory, now="2026-08-24T20:00:00Z")
            self.assertTrue(resolution["reuseSatisfied"], resolution)
            self.assertFalse(resolution["needsDispatch"], resolution)
            self.assertEqual("omega.sigmascope", resolution["reuseCandidates"][0]["componentId"])

    def test_discovery_snapshot_gets_ttl_expiry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-discovery-inventory-") as td:
            root = Path(td)
            discovery = root / "discovery"
            discovery.mkdir()
            bundle = {
                "schema": "omega.collector-observation-bundle.v1",
                "registryRevision": "fixture",
                "componentId": "omega.discovery",
                "generatedAtUtc": "2026-08-24T12:00:00Z",
                "records": 1,
                "collections": {
                    "catalogPluginFacts": {
                        "schema": "omega.observation.catalog-plugin-fact.v1",
                        "semanticClass": "catalog-intelligence",
                        "authority": "candidate-context-only",
                        "completeness": "retained-snapshot",
                        "records": 1,
                        "providers": ["omega.collector.discovery.puni-directory"],
                        "recordDigest": "d" * 64,
                        "rows": [{
                            "classification": "new-plugin",
                            "_collector": {
                                "id": "omega.collector.discovery.puni-directory", "version": 1,
                                "componentId": "omega.discovery", "observedAtUtc": "2026-08-24T12:00:00Z",
                            },
                        }],
                    }
                },
            }
            (discovery / "observations.json").write_text(json.dumps(bundle), encoding="utf-8")
            (discovery / "index.json").write_text(json.dumps({"schema": "omega.catalog-discovery.v1", "generatedAtUtc": "2026-08-24T12:00:00Z"}), encoding="utf-8")
            inventory = observation_inventory.build_inventory(None, discovery_root=discovery, generated_at="2026-08-24T12:01:00Z")
            row = next(item for item in inventory["records"] if item["observation"] == "catalogPluginFacts")
            self.assertEqual("2026-08-24T18:00:00Z", row["expiresAtUtc"])
            request = analysis_broker.compile_request({
                "observation": "catalogPluginFacts", "subject": {"type": "catalog"},
                "reason": "Need fresh ecosystem plugin facts", "requestedAtUtc": "2026-08-24T12:01:00Z",
            })
            self.assertTrue(analysis_broker.resolve_request(request, inventory=inventory, now="2026-08-24T17:59:59Z")["reuseSatisfied"])
            self.assertFalse(analysis_broker.resolve_request(request, inventory=inventory, now="2026-08-24T18:00:01Z")["reuseSatisfied"])


if __name__ == "__main__":
    unittest.main()
