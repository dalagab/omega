from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_threat_intelligence


class _Inspector:
    def threat_intelligence(self):
        return {
            "reputationRevision": "rep-123",
            "generatedAtUtc": "2026-08-28T00:00:00Z",
            "feeds": [
                {"id": "feodo", "name": "Feodo Tracker", "source": "abuse.ch", "status": "complete", "records": 3, "required": True, "generatedAtUtc": "2026-08-28T00:00:00Z"},
            ],
            "indicators": [
                {"indicatorId": "ioc-ip-exact", "indicatorType": "ip", "value": "138.68.142.140", "risk": "critical", "category": "botnet-c2", "source": "Feodo Tracker", "active": True, "lastSeen": "2026-08-27T00:00:00Z"},
                {"indicatorId": "ioc-ip-cdn", "indicatorType": "ip", "value": "151.101.1.229", "risk": "high", "category": "botnet-c2", "source": "Feodo Tracker", "active": True},
                {"indicatorId": "ioc-retired", "indicatorType": "domain", "value": "retired.example", "risk": "critical", "category": "botnet-cc", "source": "ThreatFox", "active": False, "lastSeen": "2026-07-01T00:00:00Z"},
            ],
            "observedEndpointResolutions": [
                {"host": "138.68.142.140", "resolvedIps": ["138.68.142.140"], "resolutionStatus": "resolved", "variantIds": [1]},
                {"host": "cdn.jsdelivr.net", "resolvedIps": ["151.101.1.229", "151.101.65.229"], "resolutionStatus": "resolved", "variantIds": [2]},
                {"host": "169.254.169.254", "resolvedIps": [], "resolutionStatus": "no-public-address", "variantIds": [3]},
                {"host": "mystery.example", "resolvedIps": ["203.0.113.9"], "resolutionStatus": "resolved", "variantIds": [4]},
            ],
            "observedEndpointMatches": [
                {"host": "138.68.142.140", "indicatorIds": ["ioc-ip-exact"], "resolvedIps": ["138.68.142.140"], "variantIds": [1]},
                {"host": "cdn.jsdelivr.net", "indicatorIds": ["ioc-ip-cdn"], "resolvedIps": ["151.101.1.229", "151.101.65.229"], "variantIds": [2]},
            ],
        }

    def workbench_relationship_index(self):
        return {
            "endpoints": [
                {"host": "138.68.142.140", "variantIds": [1], "firstSeenUtc": "2026-08-22T00:00:00Z", "lastSeenUtc": "2026-08-27T00:00:00Z"},
                {"host": "cdn.jsdelivr.net", "variantIds": [2], "classifications": ["known-platform"], "purposes": ["cdn"], "firstSeenUtc": "2024-01-12T00:00:00Z", "lastSeenUtc": "2026-08-27T00:00:00Z"},
                {"host": "169.254.169.254", "variantIds": [3], "firstSeenUtc": "2026-08-25T00:00:00Z", "lastSeenUtc": "2026-08-27T00:00:00Z"},
                {"host": "mystery.example", "variantIds": [4], "firstSeenUtc": "2026-08-27T00:00:00Z", "lastSeenUtc": "2026-08-27T00:00:00Z"},
            ]
        }

    def workbench_assets_for_variants(self, variant_ids):
        names = {1: "ExactBad", 2: "SharedCdn", 3: "MetadataProbe", 4: "Mystery"}
        return [
            {"variant_id": i, "plugin_id": i, "canonical_name": names[i], "internal_name": names[i], "assembly_version": "1.0.0"}
            for i in sorted(variant_ids)
        ]


class DeltaScopeThreatIntelligenceTests(unittest.TestCase):
    def test_exact_ioc_identity_is_separate_from_resolved_ip_adjacency(self) -> None:
        payload = deltascope_threat_intelligence.project_threat_intelligence(_Inspector())
        rows = {row["host"]: row for row in payload["endpointInventory"]}

        exact = rows["138.68.142.140"]
        self.assertTrue(exact["exactMatched"])
        self.assertFalse(exact["sharedInfrastructure"])
        self.assertEqual(exact["reputationState"], "exact-match")
        self.assertEqual(exact["exactRisk"], "critical")
        self.assertEqual(exact["assets"][0]["name"], "ExactBad")

        cdn = rows["cdn.jsdelivr.net"]
        self.assertFalse(cdn["exactMatched"])
        self.assertTrue(cdn["sharedInfrastructure"])
        self.assertEqual(cdn["reputationState"], "shared-infrastructure")
        self.assertEqual(cdn["adjacencyRisk"], "high")
        self.assertEqual(cdn["wellKnown"]["kind"], "shared-cdn")

        self.assertEqual(payload["summary"]["exactMatchedHosts"], 1)
        self.assertEqual(payload["summary"]["sharedInfrastructureHosts"], 1)
        self.assertEqual(payload["summary"]["strictHighRiskHosts"], 1)
        self.assertEqual(payload["summary"]["adjacencyHighRiskHosts"], 1)

    def test_unlisted_infrastructure_is_split_into_recognised_and_unrecognised(self) -> None:
        payload = deltascope_threat_intelligence.project_threat_intelligence(_Inspector())
        rows = {row["host"]: row for row in payload["endpointInventory"]}

        metadata = rows["169.254.169.254"]
        self.assertTrue(metadata["recognised"])
        self.assertEqual(metadata["wellKnown"]["kind"], "cloud-metadata")
        self.assertEqual(metadata["wellKnown"]["risk"], "caution")

        mystery = rows["mystery.example"]
        self.assertFalse(mystery["recognised"])
        self.assertEqual(payload["summary"]["unlistedUnrecognisedHosts"], 1)

    def test_feed_intersection_and_lifecycle_are_projected_without_firehose_being_primary(self) -> None:
        payload = deltascope_threat_intelligence.project_threat_intelligence(_Inspector(), limit=2)
        intersections = {row["indicatorId"]: row for row in payload["corpusIndicators"]}
        self.assertEqual(intersections["ioc-ip-exact"]["exactHosts"], ["138.68.142.140"])
        self.assertEqual(intersections["ioc-ip-cdn"]["adjacencyHosts"], ["cdn.jsdelivr.net"])
        self.assertEqual(intersections["ioc-ip-exact"]["assets"][0]["name"], "ExactBad")
        self.assertEqual(payload["summary"]["corpusIndicators"], 2)
        self.assertEqual(payload["summary"]["unobservedIndicators"], 1)
        self.assertEqual(payload["summary"]["inactiveIndicators"], 1)
        self.assertEqual(payload["inactiveIndicators"][0]["value"], "retired.example")
        self.assertEqual(len(payload["indicators"]), 2)
        self.assertTrue(payload["indicatorRowsTruncated"])

    def test_feed_freshness_distinguishes_feed_timestamp_from_snapshot_timestamp(self) -> None:
        payload = deltascope_threat_intelligence.project_threat_intelligence(_Inspector())
        feed = payload["feeds"][0]
        self.assertEqual(feed["freshnessTimestampScope"], "feed")
        self.assertEqual(feed["freshnessTimestampUtc"], "2026-08-28T00:00:00Z")
        self.assertIn(feed["freshnessState"], {"current", "attention", "stale"})


if __name__ == "__main__":
    unittest.main()
