from __future__ import annotations

import unittest

import common  # noqa: F401

from deltascope_casework import project_casework


class FakeInspector:
    def __init__(self) -> None:
        self.details = {
            1: {
                "identity": {
                    "variant_id": 1,
                    "scan_id": 20,
                    "assembly_version": "2.0.0",
                    "artifact_sha256": "b" * 64,
                    "canonical_name": "Example",
                    "internal_name": "Example.Plugin",
                    "scanned_at_utc": "2026-08-24T12:00:00Z",
                },
                "researcher": {"findings": [{"findingId": "finding-current", "ruleId": "rule.network", "title": "Network behavior"}]},
            },
            2: {
                "identity": {
                    "variant_id": 2,
                    "scan_id": 7,
                    "assembly_version": "1.0.0",
                    "artifact_sha256": "c" * 64,
                    "canonical_name": "Stable",
                    "internal_name": "Stable.Plugin",
                    "scanned_at_utc": "2026-08-24T10:00:00Z",
                },
                "researcher": {"findings": []},
            },
        }
        self.snapshots = {
            1: [
                {"scanId": 10, "artifactSha256": "a" * 64, "variantPath": "history/1/10.json", "snapshotKind": "superseded"},
                {"scanId": 20, "artifactSha256": "b" * 64, "variantPath": "current/1.json", "snapshotKind": "current"},
            ],
            2: [{"scanId": 7, "artifactSha256": "c" * 64, "variantPath": "current/2.json", "snapshotKind": "current"}],
        }
        self.plugin_detail_calls = 0

    def plugin_detail(self, variant_id: int):
        self.plugin_detail_calls += 1
        if variant_id not in self.details:
            raise ValueError("unknown variant")
        return self.details[variant_id]

    def variant_snapshots(self, variant_id: int):
        return self.snapshots.get(variant_id, [])

    def workbench_relationship_index(self):
        return {"endpoints": [{"key": "api.example.test"}], "components": [], "advisories": []}


class DeltaScopeCaseworkTests(unittest.TestCase):
    def test_reference_health_distinguishes_current_retained_reobserved_and_missing(self) -> None:
        inspector = FakeInspector()
        case = {
            "caseId": "case-0123456789abcdef0123",
            "title": "Case",
            "revision": 4,
            "createdAtUtc": "2026-08-24T09:00:00Z",
            "notes": [{"noteId": "note-1", "text": "Check the old scan", "createdAtUtc": "2026-08-24T11:30:00Z"}],
            "items": [
                {"itemId": "item-current", "kind": "bookmark", "label": "Stable", "createdAtUtc": "2026-08-24T10:01:00Z", "reference": {"variantId": 2, "scanId": 7, "artifactSha256": "c" * 64, "scannedAtUtc": "2026-08-24T10:00:00Z"}},
                {"itemId": "item-snapshot", "kind": "evidence-snapshot", "label": "Old Example", "createdAtUtc": "2026-08-24T10:02:00Z", "reference": {"variantId": 1, "scanId": 10, "artifactSha256": "a" * 64}},
                {"itemId": "item-finding", "kind": "finding", "label": "Network behavior", "createdAtUtc": "2026-08-24T12:01:00Z", "reference": {"variantId": 1, "scanId": 10, "findingId": "finding-current", "ruleId": "rule.network", "title": "Network behavior"}},
                {"itemId": "item-missing", "kind": "bookmark", "label": "Gone", "createdAtUtc": "2026-08-24T12:02:00Z", "reference": {"variantId": 999, "scanId": 1}},
                {"itemId": "item-pivot", "kind": "pivot", "label": "api.example.test", "createdAtUtc": "2026-08-24T12:03:00Z", "reference": {"pivotKind": "endpoint", "pivotKey": "api.example.test"}},
            ],
        }

        projected = project_casework(case, inspector)
        states = {row["itemId"]: row["state"] for row in projected["items"]}
        self.assertEqual("current", states["item-current"])
        self.assertEqual("retained", states["item-snapshot"])
        self.assertEqual("reobserved", states["item-finding"])
        self.assertEqual("missing", states["item-missing"])
        self.assertEqual("current", states["item-pivot"])
        self.assertEqual("history/1/10.json", next(x for x in projected["items"] if x["itemId"] == "item-snapshot")["openSnapshotPath"])
        self.assertEqual(1, projected["summary"]["attention"])
        self.assertTrue(projected["readOnly"])
        self.assertTrue(projected["localOnly"])
        self.assertFalse(projected["securityAuthority"])
        self.assertFalse(projected["policyInput"])
        self.assertFalse(projected["queueMutationAuthorized"])
        self.assertGreaterEqual(len(projected["timeline"]), 6)
        self.assertEqual("pin", projected["timeline"][0]["kind"])

    def test_resolution_caches_repeated_variant_fetches(self) -> None:
        inspector = FakeInspector()
        case = {
            "caseId": "case-0123456789abcdef0123",
            "revision": 1,
            "items": [
                {"itemId": "item-1", "kind": "bookmark", "label": "Example", "reference": {"variantId": 1, "scanId": 20}},
                {"itemId": "item-2", "kind": "finding", "label": "Network", "reference": {"variantId": 1, "scanId": 20, "findingId": "finding-current"}},
                {"itemId": "item-3", "kind": "observation", "label": "Endpoint", "reference": {"variantId": 1, "scanId": 20, "collection": "networkEndpoints"}},
            ],
            "notes": [],
        }
        projected = project_casework(case, inspector)
        self.assertEqual(1, inspector.plugin_detail_calls)
        self.assertEqual(3, projected["summary"]["current"])


if __name__ == "__main__":
    unittest.main()
