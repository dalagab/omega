from __future__ import annotations

import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_corpus_intelligence as corpus
import deltascope_workbench as workbench


class CorpusIntelligenceTests(unittest.TestCase):
    def relationship_index(self):
        return {
            "relationshipRevision": "rel-1",
            "counts": {"endpoints": 2, "components": 1, "advisories": 1},
            "endpoints": [
                {
                    "endpointKey": "host:api.example.test", "host": "api.example.test",
                    "variantIds": [10, 11], "pluginCount": 2, "observations": 4,
                    "classifications": ["unrecognised"], "purposes": ["api"],
                },
                {
                    "endpointKey": "host:cdn.example.test", "host": "cdn.example.test",
                    "variantIds": [10, 11], "pluginCount": 2, "observations": 2,
                    "classifications": ["cdn"], "purposes": ["content"],
                },
            ],
            "components": [{
                "componentKey": "nuget:example.package", "displayName": "Example.Package", "kind": "nuget",
                "usage": [{"variantId": 10, "version": "1.0"}, {"variantId": 11, "version": "1.0"}],
                "pluginCount": 2, "versions": ["1.0"], "versionDivergence": "none",
            }],
            "advisories": [{
                "advisoryId": "GHSA-test", "componentKey": "nuget:example.package", "componentName": "Example.Package",
                "affectedVersion": "1.0", "fixedVersion": "1.1", "severity": "high", "title": "Example advisory",
                "affectedAssets": [{"variantId": 10}, {"variantId": 11}],
            }],
        }

    def assets(self):
        return [
            {
                "plugin_id": 1, "variant_id": 10, "canonical_name": "Alpha", "internal_name": "Alpha",
                "author": "Researcher", "assembly_version": "1.0", "source_repository": "https://github.com/example/family.git",
                "scanned_at_utc": "2026-08-20T10:00:00Z", "capabilityIds": ["network.http", "process.launch"],
            },
            {
                "plugin_id": 2, "variant_id": 11, "canonical_name": "Beta", "internal_name": "Beta",
                "author": "Researcher", "assembly_version": "2.0", "source_repository": "https://github.com/example/family/tree/main",
                "scanned_at_utc": "2026-08-21T10:00:00Z", "capabilityIds": ["network.http"],
            },
        ]

    def findings(self):
        return [
            {"variantId": 10, "ruleId": "compound.network-execute", "title": "Network plus process execution", "category": "compound", "severity": "high"},
            {"variantId": 11, "ruleId": "network.endpoint", "title": "Network endpoint", "category": "network-endpoint", "severity": "caution"},
        ]

    def test_catalog_adds_exact_family_author_capability_and_cooccurrence_pivots(self):
        relationships = self.relationship_index()
        base = workbench.project_intelligence_catalog(relationships)
        result = corpus.project_catalog(base, relationships, self.assets(), self.findings())
        self.assertEqual(corpus.SCHEMA, result["corpusIntelligenceSchema"])
        self.assertEqual(1, len(result["families"]))
        family = result["families"][0]
        self.assertTrue(family["crossPlugin"])
        self.assertEqual(2, family["pluginCount"])
        self.assertEqual("shared-source-repository", family["familyKind"])
        self.assertFalse(family["forkInference"])
        self.assertEqual(1, len(result["authors"]))
        self.assertEqual(2, result["authors"][0]["pluginCount"])
        caps = {row["key"]: row for row in result["capabilities"]}
        self.assertEqual(2, caps["network.http"]["variantCount"])
        self.assertTrue(caps["network.http"]["exact"])
        self.assertTrue(any(row["overlapVariants"] == 2 for row in result["cooccurrences"]))
        self.assertFalse(result["codeReuse"]["available"])
        self.assertFalse(result["familyModel"]["crossRepositoryForkDetection"])

    def test_behavior_fallback_is_explicitly_bounded(self):
        relationships = self.relationship_index()
        base = workbench.project_intelligence_catalog(relationships)
        assets = [{k: v for k, v in row.items() if k != "capabilityIds"} for row in self.assets()]
        result = corpus.project_catalog(base, relationships, assets, self.findings())
        self.assertEqual([], result["capabilities"])
        self.assertGreaterEqual(len(result["behaviors"]), 1)
        self.assertFalse(result["behaviors"][0]["exact"])
        self.assertEqual("newest-finding-window", result["behaviors"][0]["scope"])
        self.assertFalse(result["capabilityCoverage"]["fullCorpusCapabilityIndexAvailable"])

    def test_local_endpoint_history_reports_new_only_after_a_previous_revision(self):
        relationships = self.relationship_index()
        with tempfile.TemporaryDirectory() as tmp:
            store = corpus.LocalCorpusIntelligenceHistory(Path(tmp))
            first = corpus.project_catalog(
                workbench.project_intelligence_catalog(relationships), relationships, self.assets(), self.findings(),
                history_store=store, evidence_revision="evidence-1", generated_at_utc="2026-08-20T10:00:00Z",
            )
            self.assertFalse(first["history"]["hasPreviousSnapshot"])
            self.assertEqual([], first["history"]["newEndpointKeys"])
            changed = self.relationship_index()
            changed["relationshipRevision"] = "rel-2"
            changed["endpoints"].append({
                "endpointKey": "host:new.example.test", "host": "new.example.test", "variantIds": [10], "pluginCount": 1, "observations": 1,
            })
            changed["counts"]["endpoints"] = 3
            second = corpus.project_catalog(
                workbench.project_intelligence_catalog(changed), changed, self.assets(), self.findings(),
                history_store=store, evidence_revision="evidence-2", generated_at_utc="2026-08-21T10:00:00Z",
            )
            self.assertTrue(second["history"]["hasPreviousSnapshot"])
            self.assertIn("host:new.example.test", second["history"]["newEndpointKeys"])
            endpoint = next(row for row in second["endpoints"] if row["key"] == "host:new.example.test")
            self.assertTrue(endpoint["newSincePreviousLocalSnapshot"])
            self.assertEqual("this-deltascope-instance", endpoint["firstSeenScope"])
            self.assertFalse(second["history"]["authoritativeFirstSeen"])

    def test_pivot_returns_affected_assets_and_selected_entity_cooccurrences(self):
        relationships = self.relationship_index()
        catalog = corpus.project_catalog(workbench.project_intelligence_catalog(relationships), relationships, self.assets(), self.findings())
        pivot = corpus.project_pivot(catalog, "endpoint", "host:api.example.test", self.assets())
        self.assertEqual(corpus.PIVOT_SCHEMA, pivot["schema"])
        self.assertEqual([10, 11], [row["variantId"] for row in pivot["assets"]])
        labels = {row["entity"]["label"] for row in pivot["cooccurrences"]}
        self.assertIn("cdn.example.test", labels)
        self.assertIn("Example.Package", labels)

    def test_published_endpoint_first_seen_wins_over_local_fallback(self):
        relationships = self.relationship_index()
        relationships["endpoints"][0]["firstSeenUtc"] = "2026-01-01T00:00:00Z"
        base = workbench.project_intelligence_catalog(relationships)
        result = corpus.project_catalog(base, relationships, self.assets(), self.findings())
        endpoint = next(row for row in result["endpoints"] if row["key"] == "host:api.example.test")
        self.assertEqual("2026-01-01T00:00:00Z", endpoint["publishedFirstSeenUtc"])
        self.assertEqual("published-corpus", endpoint["firstSeenScope"])


if __name__ == "__main__":
    unittest.main()
