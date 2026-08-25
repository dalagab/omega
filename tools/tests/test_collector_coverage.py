from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
import analysis_broker
import collector_coverage
from test_rule_reprojection import RuleReprojectionTests


class CollectorCoverageTests(unittest.TestCase):
    def evidence(self, root: Path, *, kind: str, format_name: str = "pe") -> Path:
        helper = RuleReprojectionTests("test_compatible_retained_observations_reproject_without_legacy_findings")
        evidence = helper.evidence(root)
        entry = next((evidence / "variants").rglob("*.json"))
        import json
        payload = json.loads(entry.read_text(encoding="utf-8"))
        current = payload.setdefault("current", {})
        report = current.setdefault("report_json", {})
        package = report.setdefault("dependencyIntelligence", {})
        package["binaryClassifications"] = [{
            "path": "native/helper.bin",
            "filename": "helper.bin",
            "format": format_name,
            "kind": kind,
            "role": "library",
            "architecture": "x86-64",
            "bitness": 64,
            "sha256": "b" * 64,
            "bytesExamined": 4096,
        }]
        entry.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return evidence

    def test_native_pe_generates_exact_low_priority_authenticode_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-coverage-native-") as td:
            evidence = self.evidence(Path(td), kind="native-pe")
            requests = collector_coverage.candidate_requests(evidence, requested_at="2026-08-25T18:00:00Z")
            self.assertEqual(1, len(requests))
            request = requests[0]
            self.assertEqual("binarySignatureTrust", request["observation"])
            self.assertEqual(450, request["priority"])
            self.assertEqual(1, request["subject"]["variantId"])
            self.assertEqual("a" * 64, request["subject"]["artifactSha256"])
            self.assertEqual("ttl", request["freshness"]["model"])
            self.assertEqual(604800, request["freshness"]["ttlSeconds"])

    def test_managed_only_pe_does_not_flood_authenticode_coverage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-coverage-managed-") as td:
            evidence = self.evidence(Path(td), kind="managed-pe")
            self.assertEqual([], collector_coverage.candidate_requests(evidence, requested_at="2026-08-25T18:00:00Z"))


    def test_native_elf_and_macho_generate_structural_coverage_requests(self) -> None:
        for kind, format_name, observation in (("native-elf", "elf", "elfBinaryStructure"), ("native-mach-o", "mach-o", "machOBinaryStructure")):
            with self.subTest(observation=observation), tempfile.TemporaryDirectory(prefix="omega-coverage-native-structure-") as td:
                evidence = self.evidence(Path(td), kind=kind, format_name=format_name)
                requests = collector_coverage.candidate_requests(evidence, requested_at="2026-08-25T20:00:00Z")
                self.assertEqual(1, len(requests))
                self.assertEqual(observation, requests[0]["observation"])
                self.assertEqual(425, requests[0]["priority"])
                self.assertEqual("immutable-with-subject", requests[0]["freshness"]["model"])

    def test_reconciliation_reuses_exact_existing_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-coverage-reuse-") as td:
            evidence = self.evidence(Path(td), kind="native-pe")
            requests = collector_coverage.candidate_requests(evidence, requested_at="2026-08-25T18:00:00Z")
            request = requests[0]
            inventory = {
                "schema": analysis_broker.INVENTORY_SCHEMA,
                "records": [{
                    "observation": "binarySignatureTrust",
                    "subjectKey": request["subjectKey"],
                    "observedAtUtc": "2026-08-25T17:00:00Z",
                    "expiresAtUtc": "",
                    "collectorId": "omega.collector.sigmascope.authenticode",
                    "componentId": "omega.sigmascope",
                    "reference": "fixture",
                    "recordDigest": "c" * 64,
                }],
            }
            updated, report = collector_coverage.reconcile(
                analysis_broker.empty_state(), evidence_root=evidence, inventory=inventory, now="2026-08-25T18:00:00Z",
            )
            self.assertEqual(1, report["candidateRequests"])
            self.assertEqual(1, report["reused"])
            self.assertEqual(0, report["enqueued"])
            self.assertFalse(report["authority"]["componentExecution"])
            self.assertFalse(report["authority"]["securityFindings"])


if __name__ == "__main__":
    unittest.main()
