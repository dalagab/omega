from __future__ import annotations
import unittest

import common  # noqa: F401
import collector_contracts


class CollectorContractTests(unittest.TestCase):
    def test_registry_has_first_class_discovery_and_provider_resolution(self) -> None:
        registry = collector_contracts.build_registry()
        self.assertEqual("omega.collector-registry.v1", registry["schema"])
        self.assertEqual("Omega Discovery", registry["components"]["omega.discovery"]["name"])
        providers = collector_contracts.providers_for("catalogManifestCandidates")
        self.assertIn("omega.collector.discovery.github-code-search", providers)
        self.assertIn("omega.collector.discovery.project-page", providers)
        self.assertNotIn("omega.collector.discovery.pluginmaster-validator", providers)

    def test_bundle_requires_registered_provider_for_observation_type(self) -> None:
        row = collector_contracts.make_row(
            "catalogProjectLinks", "omega.collector.discovery.project-page",
            {"projectUrl": "https://github.com/example/plugin", "url": "https://example.invalid/repo.json", "linkKind": "readme", "source": "fixture", "candidateKind": "json"},
            observed_at="2026-08-24T12:00:00Z",
        )
        bundle = collector_contracts.build_bundle({"catalogProjectLinks": [row]}, generated_at="2026-08-24T12:00:00Z")
        self.assertEqual(1, bundle["records"])
        self.assertEqual(["omega.collector.discovery.project-page"], bundle["collections"]["catalogProjectLinks"]["providers"])
        with self.assertRaisesRegex(ValueError, "does not provide"):
            collector_contracts.make_row(
                "catalogProjectLinks", "omega.collector.discovery.pluginmaster-validator",
                {"projectUrl": "https://example.invalid", "url": "https://example.invalid/repo.json"},
            )

    def test_observation_request_resolves_providers_without_executing_them(self) -> None:
        request = collector_contracts.compile_observation_request({
            "collection": "catalogRepositoryCandidates",
            "reason": "Plugin fact has no repository candidate",
            "priority": 700,
        })
        self.assertIsNotNone(request)
        resolved = collector_contracts.resolve_observation_request(request or {})
        self.assertTrue(resolved["satisfiable"])
        self.assertEqual("orchestrator-only", resolved["executionAuthority"])
        self.assertIn("omega.collector.discovery.project-page", resolved["providerCandidates"])
        self.assertNotIn("collectorId", request or {})
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            collector_contracts.compile_observation_request({
                "collection": "catalogRepositoryCandidates", "reason": "x", "collectorId": "implementation-coupling"
            })

    def test_rift_is_active_typed_runtime_provider(self) -> None:
        registry = collector_contracts.build_registry()
        rift = next(row for row in registry["collectors"] if row["id"] == "omega.collector.rift.runtime")
        self.assertEqual("active", rift["status"])
        self.assertIn("riftRuntimeEvents", rift["provides"])
        self.assertIn("omega.collector.rift.runtime", collector_contracts.providers_for("riftRuntimeBoundary"))
        row = collector_contracts.make_row(
            "riftRuntimeBoundary", "omega.collector.rift.runtime",
            {"requestId": "r", "variantId": 1, "artifactSha256": "a" * 64, "attested": True},
            observed_at="2026-08-24T20:00:00Z",
        )
        bundle = collector_contracts.build_bundle({"riftRuntimeBoundary": [row]}, component_id="omega.rift")
        self.assertEqual("omega.rift", bundle["componentId"])


if __name__ == "__main__":
    unittest.main()
