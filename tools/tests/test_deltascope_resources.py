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
    index = canonical_json({
        "schema": "omega.definitions.v1", "definitionsRevision": "defs-v1-test",
        "capabilityRegistry": {"path": "capabilities/registry.json", "sha256": digest(capability), "revision": "capabilities-v1-test"},
        "componentRegistry": {"path": "platform/component-registry.json", "sha256": digest(component), "revision": "component-registry-v1-test"},
        "collectorRegistry": {"path": "platform/collector-registry.json", "sha256": digest(collector), "revision": "collector-registry-v1-test"},
        "srlDefinitionPacks": {"path": "srl/index.json", "sha256": digest(srl), "schema": "omega.sigmascope.definition-packs.v1", "definitionPackRevision": "definition-packs-v1-test", "ruleSetRevision": "srl-ruleset-v1-test"},
        "scannerBundle": {"path": "worker", "manifestPath": "worker/manifest.json", "sha256": "f" * 64},
    })
    return {
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
