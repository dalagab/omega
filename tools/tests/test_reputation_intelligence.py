from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT / "tools" / "security", ROOT / "tools" / "catalog"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import collect_reputation_intelligence as collector
import deltascope_threat_intelligence
import deltascope_workbench
import definitions_snapshot
import reputation_intelligence
import rule_reprojection


class ReputationIntelligenceTests(unittest.TestCase):
    def sample_document(self) -> dict:
        indicator = collector._indicator(
            source="Feodo Tracker", indicator_type="ip", value="8.8.8.8",
            risk="critical", category="botnet-c2", active=True, last_seen="2026-08-24T00:00:00Z",
        )
        return {
            "schema": collector.SCHEMA,
            "generatedAtUtc": "2026-08-24T00:00:00Z",
            "reputationRevision": "reputation-v2-test",
            "policy": "frozen",
            "feeds": [{"id": "feodo-recommended", "status": "complete", "records": 1}],
            "indicators": [indicator],
            "observedEndpointResolutions": [{"host": "bad.example", "resolvedIps": ["8.8.8.8"], "urlSamples": ["https://bad.example/x"], "variantIds": [12], "pluginIds": [4]}],
            "observedEndpointMatches": [{"host": "bad.example", "resolvedIps": ["8.8.8.8"], "urlSamples": ["https://bad.example/x"], "risk": "critical", "categories": ["botnet-c2"], "sources": ["Feodo Tracker"], "indicatorIds": [indicator["indicatorId"]], "variantIds": [12], "pluginIds": [4]}],
            "indexes": {"byIp": {"8.8.8.8": [indicator["indicatorId"]]}, "byHost": {}, "byUrl": {}},
            "counts": {"activeFeeds": 1, "indicators": 1, "matchedEndpointHosts": 1, "matchedCurrentVariants": 1},
        }

    def test_endpoint_hostname_is_enriched_from_frozen_dns_and_ip_indicator(self) -> None:
        row = {"url": "https://bad.example/x", "host": "bad.example"}
        enriched = reputation_intelligence.enrich_network_endpoints([row], self.sample_document())[0]
        self.assertTrue(enriched["threatIntelMatched"])
        self.assertEqual(enriched["threatIntelRisk"], "critical")
        self.assertIn("botnet-c2", enriched["threatIntelCategories"])
        self.assertEqual(enriched["resolvedIps"], ["8.8.8.8"])

    def test_direct_ip_literal_matches_without_dns(self) -> None:
        row = {"url": "https://8.8.8.8/x", "host": "8.8.8.8"}
        enriched = reputation_intelligence.enrich_network_endpoints([row], self.sample_document())[0]
        self.assertTrue(enriched["threatIntelMatched"])

    def test_definitions_semantic_reputation_ignores_generated_timestamp(self) -> None:
        a = self.sample_document()
        b = json.loads(json.dumps(a))
        b["generatedAtUtc"] = "2026-08-25T00:00:00Z"
        self.assertEqual(definitions_snapshot._semantic_reputation(a), definitions_snapshot._semantic_reputation(b))

    def test_projection_revision_changes_when_reputation_revision_changes(self) -> None:
        rules = {"ruleSetRevision": "rules-1"}
        contract = {"contractRevision": "contract-1", "observationDigest": "obs-1"}
        a = rule_reprojection.projection_revision(rules, contract, ["networkEndpoints"], "reputation-v2-a")
        b = rule_reprojection.projection_revision(rules, contract, ["networkEndpoints"], "reputation-v2-b")
        self.assertNotEqual(a, b)

    def test_collector_retains_previous_snapshot_on_feed_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "previous.json"
            output = root / "out.json"
            previous.write_text(json.dumps(self.sample_document()), encoding="utf-8")
            with mock.patch.object(collector, "build_document", side_effect=OSError("offline")):
                result = collector.collect(evidence_root=None, output=output, previous_path=previous)
            self.assertTrue(result["retainedPrevious"])
            self.assertEqual(json.loads(output.read_text())["reputationRevision"], "reputation-v2-test")

    def test_threat_intelligence_workbench_projection_lists_urls_ips_and_risk(self) -> None:
        class Inspector:
            def threat_intelligence(self_nonlocal):
                return self.sample_document()
        projected = deltascope_threat_intelligence.project_threat_intelligence(Inspector())
        self.assertEqual(projected["summary"]["criticalHosts"], 1)
        row = projected["endpointMatches"][0]
        self.assertEqual(row["host"], "bad.example")
        self.assertEqual(row["resolvedIps"], ["8.8.8.8"])
        self.assertEqual(row["risk"], "critical")
        self.assertEqual(row["variantIds"], [12])


    def test_threat_intelligence_inventory_includes_unlisted_endpoints_without_calling_them_safe(self) -> None:
        doc = self.sample_document()
        doc["observedEndpointResolutions"].append({
            "host": "ordinary.example",
            "resolvedIps": ["1.1.1.1"],
            "resolutionStatus": "resolved",
            "urlSamples": ["https://ordinary.example/api"],
            "variantIds": [13],
            "pluginIds": [5],
        })
        class Inspector:
            def threat_intelligence(self_nonlocal):
                return doc
        projected = deltascope_threat_intelligence.project_threat_intelligence(Inspector())
        self.assertEqual(projected["summary"]["observedHosts"], 2)
        self.assertEqual(projected["summary"]["matchedHosts"], 1)
        self.assertEqual(projected["summary"]["unlistedHosts"], 1)
        ordinary = next(row for row in projected["endpointInventory"] if row["host"] == "ordinary.example")
        self.assertFalse(ordinary["matched"])
        self.assertEqual(ordinary["risk"], "none")
        self.assertEqual(ordinary["reputationState"], "unlisted")
        self.assertIn("not a safe/clean verdict", projected["note"])

    def test_optional_threatfox_failure_keeps_fresh_feodo_and_disables_stale_optional_rows(self) -> None:
        previous = self.sample_document()
        stale = collector._indicator(
            source="ThreatFox", indicator_type="domain", value="old.example",
            risk="critical", category="botnet-cc", active=True, last_seen="2026-08-23T00:00:00Z",
        )
        previous["indicators"].append(stale)
        with mock.patch.object(collector, "collect_feodo", return_value=(
            {"id": "feodo-recommended", "name": "Feodo", "source": "abuse.ch / Feodo Tracker", "required": True, "status": "complete", "records": 1, "categories": ["botnet-c2"]},
            [collector._indicator(source="Feodo Tracker", indicator_type="ip", value="9.9.9.9", risk="critical", category="botnet-c2")],
        )), mock.patch.object(collector, "collect_threatfox", side_effect=OSError("temporary API failure")), mock.patch.object(collector, "_current_endpoint_rows", return_value=[]):
            document = collector.build_document(evidence_root=None, previous=previous, timeout=1, abusech_auth_key="configured", include_threatfox=True)
        feodo = next(feed for feed in document["feeds"] if feed["id"] == "feodo-recommended")
        threatfox = next(feed for feed in document["feeds"] if feed["id"] == "threatfox-recent")
        self.assertEqual(feodo["status"], "complete")
        self.assertEqual(threatfox["status"], "retained-previous")
        retained = next(row for row in document["indicators"] if row["source"] == "ThreatFox")
        self.assertFalse(retained["active"])
        self.assertEqual(retained["confidence"], "retained-previous")
        self.assertNotIn(retained["indicatorId"], document["indexes"]["byHost"].get("old.example", []))

    def test_compare_attributes_same_artifact_rule_change_to_definitions(self) -> None:
        before = {
            "identity": {"variant_id": 1, "artifact_sha256": "a" * 64, "highest_severity": "high"},
            "scanProvenance": {"definitionsRevision": "defs-a", "artifactAnalysisRevision": "art-a", "sourceAnalysisRevision": "src-a", "ruleSetRevision": "rules-a"},
            "researcher": {"findings": [{"findingId": "one"}]},
        }
        after = {
            "identity": {"variant_id": 1, "artifact_sha256": "a" * 64, "highest_severity": "none"},
            "scanProvenance": {"definitionsRevision": "defs-b", "artifactAnalysisRevision": "art-a", "sourceAnalysisRevision": "src-a", "ruleSetRevision": "rules-b"},
            "researcher": {"findings": []},
        }
        result = deltascope_workbench.project_version_compare(before, after)
        self.assertEqual(result["changeAttribution"]["primaryCause"], "definitions-change")


    def test_compare_attributes_reputation_only_change_to_frozen_intelligence_without_rescan(self) -> None:
        before = {
            "identity": {"variant_id": 1, "artifact_sha256": "a" * 64, "highest_severity": "high"},
            "scanProvenance": {"definitionsRevision": "defs-a", "artifactAnalysisRevision": "art-a", "sourceAnalysisRevision": "src-a", "ruleSetRevision": "rules-a", "reputationRevision": "rep-a"},
            "projection": {"ruleSetRevision": "rules-a", "reputationRevision": "rep-a"},
            "researcher": {"findings": [{"findingId": "one"}]},
        }
        after = {
            "identity": {"variant_id": 1, "artifact_sha256": "a" * 64, "highest_severity": "critical"},
            "scanProvenance": {"definitionsRevision": "defs-b", "artifactAnalysisRevision": "art-a", "sourceAnalysisRevision": "src-a", "ruleSetRevision": "rules-a", "reputationRevision": "rep-b"},
            "projection": {"ruleSetRevision": "rules-a", "reputationRevision": "rep-b"},
            "researcher": {"findings": [{"findingId": "one"}, {"findingId": "threat"}]},
        }
        result = deltascope_workbench.project_version_compare(before, after)
        attribution = result["changeAttribution"]
        self.assertEqual(attribution["primaryCause"], "reputation-intelligence")
        self.assertTrue(attribution["artifact"]["same"])
        self.assertFalse(attribution["evaluation"]["artifactReanalysis"])
        self.assertTrue(attribution["evaluation"]["retainedEvidenceOnly"])
        self.assertTrue(attribution["evaluation"]["ruleReprojectionOnly"])

    def test_compare_scanner_semantics_change_requires_reanalysis_even_when_artifact_is_same(self) -> None:
        before = {
            "identity": {"variant_id": 1, "artifact_sha256": "a" * 64, "highest_severity": "none"},
            "scanProvenance": {"definitionsRevision": "defs-a", "artifactAnalysisRevision": "art-a", "sourceAnalysisRevision": "src-a"},
            "researcher": {"findings": []},
        }
        after = {
            "identity": {"variant_id": 1, "artifact_sha256": "a" * 64, "highest_severity": "high"},
            "scanProvenance": {"definitionsRevision": "defs-a", "artifactAnalysisRevision": "art-b", "sourceAnalysisRevision": "src-a"},
            "researcher": {"findings": [{"findingId": "new-detector"}]},
        }
        result = deltascope_workbench.project_version_compare(before, after)
        attribution = result["changeAttribution"]
        self.assertEqual(attribution["primaryCause"], "scanner-change")
        self.assertTrue(attribution["evaluation"]["artifactReanalysis"])
        self.assertEqual(attribution["evaluation"]["mode"], "artifact-analysis")

    def test_compare_uses_mixed_when_plugin_and_definitions_both_changed(self) -> None:
        before = {"identity": {"variant_id": 1, "artifact_sha256": "a" * 64, "highest_severity": "none"}, "scanProvenance": {"definitionsRevision": "defs-a"}, "researcher": {"findings": []}}
        after = {"identity": {"variant_id": 1, "artifact_sha256": "b" * 64, "highest_severity": "high"}, "scanProvenance": {"definitionsRevision": "defs-b"}, "researcher": {"findings": [{"findingId": "x"}]}}
        result = deltascope_workbench.project_version_compare(before, after)
        self.assertEqual(result["changeAttribution"]["primaryCause"], "mixed")

    def test_daily_workflow_collects_reputation_before_freeze(self) -> None:
        text = (ROOT / ".github" / "workflows" / "catalog-builder.yml").read_text(encoding="utf-8")
        collect = text.index("Collect daily endpoint threat intelligence")
        freeze = text.index("Freeze daily Definitions and OSV data")
        self.assertLess(collect, freeze)
        self.assertIn("--reputation-input catalog/reputation-intelligence.json", text)


if __name__ == "__main__":
    unittest.main()
