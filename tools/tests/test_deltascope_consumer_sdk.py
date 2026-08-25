from __future__ import annotations

from pathlib import Path
import unittest

import common
from deltascope_sdk import configure_published_contracts, sdk_status, srl


class DeltaScopeConsumerSdkTests(unittest.TestCase):
    def tearDown(self) -> None:
        # Restore bundled compatibility data so test order cannot affect other SRL tests.
        from deltascope_sdk import component_registry, collector_contracts, capability_registry
        component_registry.configure_registry(None)
        collector_contracts.configure_registry(None)
        capability_registry.configure_registry(None)
        srl.refresh_contracts()

    def test_verified_registry_binding_adds_future_rule_collection_without_sdk_code_change(self) -> None:
        components = {
            "schema": "omega.component-registry.v1",
            "revision": "component-registry-v1-future",
            "components": [{
                "id": "omega.future", "name": "Future Analyzer", "type": "future-analysis-service", "status": "active",
                "branch": "future", "executionClass": "future-analysis",
                "launch": {"mode": "none", "available": False, "brokerDispatchable": False},
                "authority": {"observations": True, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
                "boundary": {"network": "none", "hostileCodeExecution": False, "writesEvidence": False},
                "purpose": "Test future provider",
            }],
        }
        collectors = {
            "schema": "omega.collector-registry.v1",
            "revision": "collector-registry-v1-future",
            "components": {"omega.future": {"name": "Future Analyzer"}},
            "observationTypes": {
                "futureObservation": {
                    "schema": "omega.observation.future.v1", "semanticClass": "test",
                    "ruleEligible": True, "authority": "observation-only",
                    "fields": {"score": "integer", "label": "string"},
                }
            },
            "collectors": [{
                "id": "omega.collector.future", "version": 1, "componentId": "omega.future",
                "title": "Future provider", "purpose": "Test", "provides": ["futureObservation"],
                "cadence": "on-demand", "authority": "observation-only", "network": False,
            }],
            "providers": {"futureObservation": ["omega.collector.future"]},
        }
        status = configure_published_contracts(components=components, collectors=collectors)
        self.assertEqual("component-registry-v1-future", status["publishedContractBinding"]["componentRegistryRevision"])
        self.assertIn("futureObservation", srl.FIELD_REGISTRY)
        self.assertEqual("integer", srl.FIELD_REGISTRY["futureObservation"]["score"])
        compiled = srl.compile_ruleset({
            "schema": srl.RULESET_SCHEMA,
            "rules": [{
                "schema": srl.RULE_SCHEMA, "id": "future.test", "kind": "observation", "status": "experimental",
                "requires": ["futureObservation"],
                "selectors": {"high": {"collection": "futureObservation", "where": {"score": {"gte": 5}}}},
                "condition": "high",
                "emit": {"fact": "future.high", "confidence": "high", "title": "Future"},
            }],
        })
        result = srl.evaluate_ruleset(compiled, {"futureObservation": [{"score": 7, "label": "x"}]})
        self.assertTrue(result["evaluated"])
        self.assertIn("future.high", result["facts"])

    def test_sdk_declares_no_remote_code_or_production_write_authority(self) -> None:
        status = sdk_status()
        self.assertFalse(status["remoteCodeExecution"])
        self.assertFalse(status["productionAuthority"])
        self.assertFalse(status["repositoryWriteBack"])
        self.assertFalse(status["evidenceWriteBack"])
        self.assertFalse(status["queueWriteBack"])

    def test_primary_deltascope_modules_import_consumer_sdk_not_production_srl_modules(self) -> None:
        root = common.ROOT
        files = [
            root / "tools/security/developer_view.py",
            root / "tools/security/deltascope_rule_store.py",
            root / "tools/security/deltascope_finding_lineage.py",
            root / "tools/security/deltascope_detection_coverage.py",
        ]
        for path in files:
            text = path.read_text(encoding="utf-8")
            self.assertIn("deltascope_sdk", text, path.as_posix())
            self.assertNotIn("import stigma1 as srl", text, path.as_posix())


if __name__ == "__main__":
    unittest.main()
