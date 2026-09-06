from __future__ import annotations

from pathlib import Path
import sys
import unittest

import common  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))
from security_endpoint_inventory import endpoint_candidates, endpoint_findings, endpoint_summary
from security_evidence_v2 import compact_report_for_transport


class EndpointIntelligenceTests(unittest.TestCase):
    def test_source_webhook_is_redacted_and_origin_confidence_is_retained(self) -> None:
        endpoints = endpoint_candidates(
            'const string url = "https://discord.com/api/webhooks/123456789012345678901234/abcdefghijklmnopqrstuvwxyzABCDE";',
            "source:Plugin.cs",
        )
        self.assertEqual(1, len(endpoints))
        item = endpoints[0]
        self.assertEqual("webhook-endpoint", item["classification"])
        self.assertEqual("source-code", item["originType"])
        self.assertEqual("High", item["confidence"])
        self.assertEqual("https://discord.com/api/webhooks/<redacted>", item["url"])
        self.assertTrue(item["concreteDestinationEvidence"])

    def test_registered_service_metadata_is_definition_backed(self) -> None:
        endpoints = endpoint_candidates(
            'const string url = "https://universalis.app/api/v2/Europe/5333";',
            "source:Plugin.cs",
        )
        self.assertEqual(1, len(endpoints))
        item = endpoints[0]
        self.assertEqual("recognised-platform", item["classification"])
        self.assertEqual("ffxiv.universalis", item["serviceId"])
        self.assertIn("ffxiv.market-data", item["serviceCapabilities"])
        self.assertTrue(item["serviceRegistryRevision"].startswith("services-v1-"))

    def test_special_endpoint_classification_keeps_service_identity(self) -> None:
        endpoints = endpoint_candidates(
            'https://discord.com/api/webhooks/123456789012345678901234/abcdefghijklmnopqrstuvwxyzABCDE',
            "source:Plugin.cs",
        )
        item = endpoints[0]
        self.assertEqual("webhook-endpoint", item["classification"])
        self.assertEqual("platform.discord", item["serviceId"])
        self.assertEqual("established", item["serviceRecognition"])

    def test_templated_port_literal_is_ignored_instead_of_failing_scan(self) -> None:
        endpoints = endpoint_candidates(
            'const string endpoint = "http://127.0.0.1:{0}/speech";',
            "artifact:TextToTalk.dll",
        )
        self.assertEqual([], endpoints)

    def test_binary_certificate_url_is_inventory_evidence_not_destination(self) -> None:
        endpoints = endpoint_candidates(
            "https://ocsp.digicert.com/ https://api.unknown-service.test/v1",
            "artifact:native/helper.dll",
            origin_type="artifact-binary-string",
            confidence="Low",
        )
        cert = next(item for item in endpoints if item["host"] == "ocsp.digicert.com")
        self.assertEqual("certificate-infrastructure", cert["classification"])
        self.assertFalse(cert["concreteDestinationEvidence"])
        findings, _ = endpoint_findings(endpoints, True, [])
        self.assertFalse(any("digicert" in item["title"].casefold() for item in findings))
        unknown = next(item for item in findings if item["category"] == "network-endpoint")
        self.assertEqual("Low", unknown["confidence"])
        self.assertEqual("artifact-binary-string", unknown["endpointOrigin"])

    def test_ipv6_and_summary_distinguish_capability_from_literals(self) -> None:
        endpoints = endpoint_candidates("http://[::1]:8080/status", "artifact:settings.json")
        self.assertEqual("private-or-loopback", endpoints[0]["classification"])
        summary = endpoint_summary(endpoints, True)
        self.assertTrue(summary["networkCapabilityObserved"])
        self.assertEqual(1, summary["concreteDestinationCount"])
        self.assertFalse(summary["destinationsUndetermined"])
        self.assertEqual("VeryHigh", summary["hosts"][0]["confidence"])

    def test_no_concrete_destination_keeps_undetermined_gap(self) -> None:
        endpoints = endpoint_candidates("https://github.com/example/repo/blob/main/README.md", "source:README.md")
        summary = endpoint_summary(endpoints, True)
        self.assertEqual(0, summary["concreteDestinationCount"])
        self.assertTrue(summary["destinationsUndetermined"])
        findings, caps = endpoint_findings(endpoints, True, ["https://github.com/example/repo"])
        self.assertEqual("network.endpoint.dynamic-or-undetermined", findings[0]["ruleId"])
        self.assertIn("Network destination undetermined", caps)

    def test_transport_keeps_compact_endpoint_and_component_summaries(self) -> None:
        row = {
            "report_json": {
                "dependencyIntelligence": {
                    "networkEndpoints": [{
                        "url": "https://api.service.test/v1", "host": "api.service.test", "origin": "artifact",
                        "originType": "artifact-config", "confidence": "VeryHigh",
                        "classification": "unrecognised-host", "purpose": "unrecognised public host",
                        "concreteDestinationEvidence": True,
                    }],
                    "endpointSummary": {
                        "schema": "omega.sigmascope.endpoint-summary.v1", "networkCapabilityObserved": True,
                        "literalCount": 1, "concreteDestinationCount": 1, "hostCount": 1, "destinationsUndetermined": False,
                        "hosts": [{"host": "api.service.test", "literalCount": 1, "concreteCount": 1, "confidence": "VeryHigh", "classifications": ["unrecognised-host"], "originTypes": ["artifact-config"]}],
                    },
                    "componentSummary": {
                        "schema": "omega.sigmascope.component-summary.v1", "dependencyCount": 1,
                        "families": {"nuget": 1}, "requirements": {"bundled": 1},
                        "exactVersionObservedCount": 1, "versionUnknownCount": 0,
                        "nativeRelationshipCounts": {}, "pluginRelationships": [], "nativeRelationships": [],
                        "fingerprint": "a" * 64,
                    },
                }
            }
        }
        compact = compact_report_for_transport(row)
        intel = compact["intelligence"]
        self.assertEqual("VeryHigh", intel["networkEndpoints"][0]["confidence"])
        self.assertEqual(1, intel["endpointSummary"]["concreteDestinationCount"])
        self.assertEqual({"nuget": 1}, intel["componentSummary"]["families"])
        self.assertEqual("a" * 64, intel["componentSummary"]["fingerprint"])


if __name__ == "__main__":
    unittest.main()
