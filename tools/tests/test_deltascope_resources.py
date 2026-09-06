from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

import common
import deltascope_resources


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def remote_fixture(base: str) -> dict[str, bytes]:
    pack_manifest = b"schema: omega.sigmascope.definition-pack.v1\nid: omega-test\ntitle: Test\ntrustTier: experimental\nrules: []\nfixtures: []\n"
    rule_file = b"schema: omega.sigmascope.rule.v1\nid: test.rule\nkind: finding\nstatus: experimental\nrequires: []\nselectors: {}\ncondition: true\nemit:\n  findingId: test.rule\n  title: Test\n  severity: informational\n"
    fixture_file = b"schema: omega.sigmascope.rule-fixture.v1\nname: Test\nobservations: {}\ninitialFacts: []\nexpected: {}\n"
    compiled = canonical_json({"schema": "omega.sigmascope.compiled-ruleset.v1", "ruleSetRevision": "srl-ruleset-v1-test", "rules": []})
    component = canonical_json({
        "schema": "omega.component-registry.v1", "revision": "component-registry-v1-test",
        "components": [{"id": "omega.future", "name": "Future", "type": "analysis-service", "status": "planned", "launch": {"mode": "none", "available": False}}],
    })
    collector = canonical_json({
        "schema": "omega.collector-registry.v1", "revision": "collector-registry-v1-test",
        "components": {"omega.future": {"name": "Future"}},
        "observationTypes": {},
        "collectors": [{"id": "omega.collector.future", "componentId": "omega.future", "title": "Future provider", "status": "planned", "provides": ["futureObservation"]}],
    })
    capability = canonical_json({"schema": "omega.sigmascope.capability-registry.v1", "revision": "capabilities-v1-test", "capabilities": []})
    inspectable = {
        "semanticApiRegistry": ("semantic/api-registry.json", canonical_json({"schema": "omega.semantic-api-registry.v1", "matchers": []})),
        "semanticFlowRegistry": ("semantic/flow-registry.json", canonical_json({"schema": "omega.semantic-flow-registry.v1", "sources": [], "sinks": []})),
        "serviceRegistry": ("semantic/service-registry.json", canonical_json({"schema": "omega.service-registry.v1", "services": []})),
        "reputation": ("reputation.json", canonical_json({"schema": "omega.reputation.v1", "indicators": []})),
        "osv": ("osv-advisories.json", canonical_json({"schema": "omega.osv-advisories.v1", "advisories": []})),
        "sourceObservations": ("source-revisions.json", canonical_json({"schema": "omega.source-revisions.v1", "repositories": []})),
        "secondarySecurity": ("secondary-security/index.json", canonical_json({"schema": "omega.secondary-security.v1", "engines": []})),
    }
    srl_index = {
        "schema": "omega.sigmascope.definition-packs.v1",
        "definitionPackRevision": "definition-packs-v1-test",
        "ruleSetRevision": "srl-ruleset-v1-test",
        "activeRuleCount": 0,
        "totalRuleCount": 1,
        "compiledRuleSet": {"path": "srl/compiled-ruleset.json", "sha256": digest(compiled), "schema": "omega.sigmascope.compiled-ruleset.v1", "ruleSetRevision": "srl-ruleset-v1-test", "ruleCount": 0},
        "packs": [{
            "id": "omega-test",
            "manifest": {"path": "pack.yaml", "sha256": digest(pack_manifest), "bytes": len(pack_manifest)},
            "rules": [{"path": "rules/test.yaml", "sha256": digest(rule_file), "bytes": len(rule_file)}],
            "fixtures": [{"path": "fixtures/test.yaml", "sha256": digest(fixture_file), "bytes": len(fixture_file)}],
        }],
    }
    srl = canonical_json(srl_index)
    index_document = {
        "schema": "omega.definitions.v1", "definitionsRevision": "defs-v1-test",
        "capabilityRegistry": {"path": "capabilities/registry.json", "sha256": digest(capability), "revision": "capabilities-v1-test"},
        "componentRegistry": {"path": "platform/component-registry.json", "sha256": digest(component), "revision": "component-registry-v1-test"},
        "collectorRegistry": {"path": "platform/collector-registry.json", "sha256": digest(collector), "revision": "collector-registry-v1-test"},
        "srlDefinitionPacks": {"path": "srl/index.json", "sha256": digest(srl), "schema": "omega.sigmascope.definition-packs.v1", "definitionPackRevision": "definition-packs-v1-test", "ruleSetRevision": "srl-ruleset-v1-test"},
        "scannerBundle": {"path": "worker", "manifestPath": "worker/manifest.json", "sha256": "f" * 64},
    }
    for key, (relative, payload) in inspectable.items():
        index_document[key] = {"path": relative, "sha256": digest(payload), "revision": f"{key}-v1-test"}
    index = canonical_json(index_document)
    result = {
        f"{base}/index.json": index,
        f"{base}/capabilities/registry.json": capability,
        f"{base}/platform/component-registry.json": component,
        f"{base}/platform/collector-registry.json": collector,
        f"{base}/srl/index.json": srl,
        f"{base}/srl/compiled-ruleset.json": compiled,
        f"{base}/srl/packs/omega-test/pack.yaml": pack_manifest,
        f"{base}/srl/packs/omega-test/rules/test.yaml": rule_file,
        f"{base}/srl/packs/omega-test/fixtures/test.yaml": fixture_file,
    }
    result.update({f"{base}/{relative}": payload for relative, payload in inspectable.values()})
    return result


class DeltaScopePublishedResourceTests(unittest.TestCase):
    def test_sync_downloads_only_verified_consumer_contracts(self) -> None:
        base = "https://example.invalid/definitions"
        remote = remote_fixture(base)
        calls: list[str] = []

        def reader(url: str, *, maximum: int) -> bytes:
            calls.append(url)
            if url not in remote:
                raise AssertionError(f"unexpected URL {url}")
            data = remote[url]
            self.assertLessEqual(len(data), maximum)
            return data

        with tempfile.TemporaryDirectory(prefix="omega-deltascope-resources-") as td, mock.patch.object(deltascope_resources, "_read_url", side_effect=reader):
            resources = deltascope_resources.sync_published_resources(Path(td), base_url=base)
            self.assertEqual("defs-v1-test", resources.public_status()["definitionsRevision"])
            self.assertEqual("definition-packs-v1-test", resources.public_status()["definitionPackRevision"])
            self.assertEqual("component-registry-v1-test", resources.component_registry["revision"])
            self.assertEqual("collector-registry-v1-test", resources.collector_registry["revision"])
            self.assertTrue((resources.packs_root / "omega-test" / "rules" / "test.yaml").is_file())
            self.assertFalse(any("/worker/" in url or url.endswith("/worker") for url in calls))
            self.assertFalse(resources.public_status()["downloadedWorkerCode"])
            self.assertTrue((resources.root / "semantic" / "api-registry.json").is_file())
            self.assertTrue((resources.root / "secondary-security" / "index.json").is_file())

            inventory = resources.contract_inventory()
            groups = {group["id"]: group for group in inventory["groups"]}
            self.assertIn("semantic-apis", groups)
            self.assertEqual("omega-test", groups["srl"]["children"][0]["id"])
            exact = resources.read_contract_resource("srl/packs/omega-test/rules/test.yaml")
            self.assertTrue(exact["verified"])
            self.assertIn("id: test.rule", exact["content"])
            with self.assertRaises(deltascope_resources.ResourceError):
                resources.read_contract_resource("../current.json")
            with self.assertRaises(deltascope_resources.ResourceError):
                resources.read_contract_resource("not-in-manifest.json")
            self.assertEqual(resources.root.name, inventory["snapshots"][0]["snapshotName"])

    def test_sync_downloads_published_execution_topology_when_available(self) -> None:
        base = "https://example.invalid/definitions"
        remote = remote_fixture(base)
        topology = canonical_json({
            "schema": "omega.execution-topology.v1", "revision": "execution-topology-v1-test",
            "readOnly": True, "mutationAuthority": "none", "policyInput": False, "launchAuthority": False,
            "nodes": [{"id": "future", "componentId": "omega.future", "workflow": "future.yml", "job": "Future", "step": "Run"}],
        })
        index = json.loads(remote[f"{base}/index.json"].decode("utf-8"))
        index["executionTopology"] = {
            "path": "platform/execution-topology.json", "sha256": digest(topology),
            "revision": "execution-topology-v1-test", "schema": "omega.execution-topology.v1",
        }
        remote[f"{base}/index.json"] = canonical_json(index)
        remote[f"{base}/platform/execution-topology.json"] = topology
        with tempfile.TemporaryDirectory(prefix="omega-deltascope-resources-") as td, mock.patch.object(
            deltascope_resources, "_read_url", side_effect=lambda url, maximum: remote[url]
        ):
            resources = deltascope_resources.sync_published_resources(Path(td), base_url=base)
            self.assertEqual("execution-topology-v1-test", resources.execution_topology["revision"])
            self.assertEqual("published-frozen-definitions", resources.public_status()["executionTopologyAuthority"])
            self.assertTrue((resources.root / "platform" / "execution-topology.json").is_file())


    def test_security_telemetry_projects_new_published_contracts(self) -> None:
        projected = deltascope_resources.project_security_telemetry({
            "generatedAtUtc": "2026-09-03T22:43:57Z",
            "scannerVersion": "2.15.0", "scannerRevision": "scanner-v1-current",
            "artifactAnalysisRevision": "artifact-v3", "sourceAnalysisRevision": "source-v1",
            "srlDefinitionPacks": {"ruleSetRevision": "srl-v1", "totalRuleCount": 66, "packCount": 7, "activeRuleCount": 16, "productionRuleEvaluationEnabled": False},
            "capabilityRegistry": {"revision": "cap-v1", "capabilityCount": 40, "categoryCount": 14},
            "semanticApiRegistry": {"revision": "api-v1", "sourceMatcherCount": 11, "compiledMatcherCount": 6},
            "semanticFlowRegistry": {"revision": "flow-v1", "sourceCount": 7, "sinkCount": 10, "sanitizerCount": 4},
            "serviceRegistry": {"revision": "services-v1", "serviceCount": 7},
            "reputation": {"reputationRevision": "rep-v2", "indicators": 3791, "activeFeeds": 2, "matchedEndpointHosts": 2},
            "advisoryRevision": "osv-v1", "osv": {"matchedPackages": 35, "queriedPackages": 2000},
            "sourceObservations": {"revision": "observations-v1", "counts": {"observed": 1341, "repositories": 1457, "failed": 116}},
            "secondarySecurity": {"revision": "secondary-v2", "engines": [{"engine": "yara", "status": "configured"}, {"engine": "clamav", "status": "configured"}]},
            "componentRegistry": {"revision": "components-v1", "componentCount": 13, "launchableCount": 5},
            "collectorRegistry": {"revision": "collectors-v1", "collectorCount": 18, "observationTypeCount": 17},
        })
        by_id = {row["id"]: row for row in projected["contracts"]}
        self.assertEqual(66, by_id["srl"]["primaryCount"])
        self.assertIn("16 active", by_id["srl"]["detail"])
        self.assertEqual(17, by_id["semantic-apis"]["primaryCount"])
        self.assertEqual(17, by_id["semantic-flow"]["primaryCount"])
        self.assertEqual(3791, by_id["reputation"]["primaryCount"])
        self.assertEqual(1341, by_id["source-observations"]["primaryCount"])
        self.assertEqual(2, by_id["secondary-security"]["primaryCount"])
        self.assertEqual("2.15.0", projected["scanner"]["version"])
    def test_network_failure_reuses_last_verified_snapshot(self) -> None:
        base = "https://example.invalid/definitions"
        remote = remote_fixture(base)
        with tempfile.TemporaryDirectory(prefix="omega-deltascope-resources-") as td:
            cache = Path(td)
            with mock.patch.object(deltascope_resources, "_read_url", side_effect=lambda url, maximum: remote[url]):
                first = deltascope_resources.sync_published_resources(cache, base_url=base)
            with mock.patch.object(deltascope_resources, "_read_url", side_effect=urllib.error.URLError("offline")):
                stale = deltascope_resources.sync_published_resources(cache, base_url=base)
            self.assertEqual(first.root, stale.root)
            self.assertTrue(stale.stale)
            self.assertIn("last verified snapshot", stale.warning)

    def test_tampered_cache_is_rejected_offline(self) -> None:
        base = "https://example.invalid/definitions"
        remote = remote_fixture(base)
        with tempfile.TemporaryDirectory(prefix="omega-deltascope-resources-") as td:
            cache = Path(td)
            with mock.patch.object(deltascope_resources, "_read_url", side_effect=lambda url, maximum: remote[url]):
                resources = deltascope_resources.sync_published_resources(cache, base_url=base)
            (resources.root / "platform" / "component-registry.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(deltascope_resources.ResourceError):
                deltascope_resources.sync_published_resources(cache, base_url=base, offline=True)


if __name__ == "__main__":
    unittest.main()
