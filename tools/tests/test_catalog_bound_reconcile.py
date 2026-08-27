from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys

import common

ORCHESTRATION = common.ROOT / "tools" / "orchestration"
if str(ORCHESTRATION) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATION))
import reconcile_work  # noqa: E402


def _policy() -> dict:
    return {
        "schema": "omega.orchestration-policy.v1",
        "version": 4,
        "queues": [
            {
                "queueId": "catalog-discovery",
                "component": "omega.discovery",
                "kind": "refresh-catalog-discovery",
                "cadenceSeconds": 21600,
                "priority": 300,
                "subject": {"type": "catalog"},
                "reason": ["test"],
            },
            {
                "queueId": "catalog-enrichment",
                "component": "omega.catalog",
                "kind": "refresh-catalog-enrichment",
                "cadenceSeconds": 43200,
                "priority": 300,
                "subject": {"type": "catalog"},
                "reason": ["test"],
                "prerequisites": ["catalog-discovery"],
                "revisionInputs": ["catalog"],
            },
            {
                "queueId": "catalog-scrape",
                "component": "omega.catalog",
                "kind": "refresh-website-scrape",
                "cadenceSeconds": 43200,
                "priority": 290,
                "subject": {"type": "catalog-websites"},
                "reason": ["test"],
                "prerequisites": ["catalog-enrichment"],
                "revisionInputs": ["catalog"],
            },
            {
                "queueId": "source-head-observation",
                "component": "omega.sigmascope",
                "kind": "refresh-source-heads",
                "cadenceSeconds": 86400,
                "priority": 350,
                "subject": {"type": "catalog"},
                "reason": ["test"],
                "revisionInputs": ["catalog"],
            },
        ],
    }


def _catalog(root: Path, revision: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.json").write_text(json.dumps({"catalogRevision": revision}) + "\n", encoding="utf-8")
    return root


class CatalogBoundReconcileTests(unittest.TestCase):
    def test_same_catalog_and_cadence_does_not_duplicate_bound_work(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            catalog = _catalog(root / "catalog", "cat-a")
            first_root = root / "first"
            first = reconcile_work.reconcile(
                policy=_policy(), previous_root=None, output_root=first_root,
                catalog_root=catalog, now="2026-08-27T00:01:00Z",
            )
            self.assertEqual(4, first["createdWorkItems"])
            second_root = root / "second"
            second = reconcile_work.reconcile(
                policy=_policy(), previous_root=first_root, output_root=second_root,
                catalog_root=catalog, now="2026-08-27T00:02:00Z",
            )
            self.assertEqual(0, second["createdWorkItems"])

    def test_catalog_revision_change_requeues_all_catalog_bound_lanes_in_same_cadence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            catalog = _catalog(root / "catalog", "cat-a")
            first_root = root / "first"
            reconcile_work.reconcile(
                policy=_policy(), previous_root=None, output_root=first_root,
                catalog_root=catalog, now="2026-08-27T00:01:00Z",
            )
            _catalog(catalog, "cat-b")
            second_root = root / "second"
            second = reconcile_work.reconcile(
                policy=_policy(), previous_root=first_root, output_root=second_root,
                catalog_root=catalog, now="2026-08-27T00:02:00Z",
            )
            self.assertEqual(3, second["createdWorkItems"])
            for queue_id in ("catalog-enrichment", "catalog-scrape", "source-head-observation"):
                queue = json.loads((second_root / "queues" / f"{queue_id}.json").read_text(encoding="utf-8"))
                self.assertEqual(2, len(queue["items"]), queue_id)
                self.assertTrue(queue["items"][-1]["requiredRevision"].startswith("work-inputs-v1-"))
            discovery = json.loads((second_root / "queues" / "catalog-discovery.json").read_text(encoding="utf-8"))
            self.assertEqual(1, len(discovery["items"]))

    def test_prerequisite_required_revision_change_requeues_dependent_lane(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            catalog = _catalog(root / "catalog", "cat-a")
            first_root = root / "first"
            reconcile_work.reconcile(
                policy=_policy(), previous_root=None, output_root=first_root,
                catalog_root=catalog, now="2026-08-27T00:01:00Z",
            )
            second_root = root / "second"
            second = reconcile_work.reconcile(
                policy=_policy(), previous_root=first_root, output_root=second_root,
                catalog_root=catalog, now="2026-08-27T06:01:00Z",
            )
            # Discovery advances on its 6h cadence. Enrichment and scrape are still inside
            # their 12h cadence, but dependency identity must advance them anyway.
            self.assertEqual(3, second["createdWorkItems"])
            for queue_id in ("catalog-discovery", "catalog-enrichment", "catalog-scrape"):
                queue = json.loads((second_root / "queues" / f"{queue_id}.json").read_text(encoding="utf-8"))
                self.assertEqual(2, len(queue["items"]), queue_id)
            source_head = json.loads((second_root / "queues" / "source-head-observation.json").read_text(encoding="utf-8"))
            self.assertEqual(1, len(source_head["items"]))

    def test_catalog_revision_input_fails_closed_without_catalog_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError, "--catalog-root"):
                reconcile_work.reconcile(
                    policy=_policy(), previous_root=None, output_root=Path(td) / "out",
                    now="2026-08-27T00:01:00Z",
                )

    def test_unknown_revision_input_is_rejected(self) -> None:
        policy = _policy()
        policy["queues"][1]["revisionInputs"] = ["imaginary-authority"]
        with self.assertRaisesRegex(ValueError, "unknown revisionInputs"):
            reconcile_work.validate_policy(policy)

    def test_shipped_policy_binds_catalog_consumers_to_catalog_revision(self) -> None:
        policy = json.loads(
            (common.ROOT / "security-definitions" / "orchestration" / "work-policy.json").read_text(encoding="utf-8")
        )
        self.assertGreaterEqual(int(policy["version"]), 4)
        by_id = {row["queueId"]: row for row in policy["queues"]}
        for queue_id in ("catalog-enrichment", "catalog-scrape", "source-head-observation"):
            self.assertEqual(["catalog"], by_id[queue_id].get("revisionInputs"), queue_id)

    def test_reconcile_workflow_supplies_authoritative_catalog_identity(self) -> None:
        text = (common.ROOT / ".github" / "workflows" / "security-reconcile.yml").read_text(encoding="utf-8")
        self.assertIn("ref: catalog-data", text)
        self.assertIn("path: catalog/current-catalog", text)
        self.assertIn("--catalog-root catalog/current-catalog/catalog", text)


if __name__ == "__main__":
    unittest.main()
