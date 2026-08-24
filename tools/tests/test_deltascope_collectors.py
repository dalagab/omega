from __future__ import annotations

import datetime as dt
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_collectors
import deltascope_docs


class DeltaScopeCollectorTests(unittest.TestCase):
    def test_collector_projection_uses_recent_runner_history_and_published_metrics(self) -> None:
        catalog_history = {
            "available": True,
            "runs": [
                {
                    "runId": 100,
                    "runNumber": 900,
                    "createdAtUtc": "2026-08-23T18:00:00Z",
                    "updatedAtUtc": "2026-08-23T18:05:00Z",
                    "url": "https://github.com/dalagab/omega/actions/runs/100",
                    "jobs": [
                        {
                            "name": "Discover source feeds",
                            "status": "completed",
                            "conclusion": "success",
                            "url": "https://github.com/dalagab/omega/actions/runs/100/job/1",
                            "steps": [
                                {
                                    "name": "Discover curated, Puni.sh and GitHub PluginMaster sources",
                                    "status": "completed",
                                    "conclusion": "success",
                                }
                            ],
                            "logPreview": "2026-08-23T18:01:00Z Wrote build/raw-sources.json: 44 source(s) — 7 curated, 8 community, 12 puni.sh, 17 github-search\n",
                        },
                        {
                            "name": "Fetch and normalize manifests",
                            "status": "completed",
                            "conclusion": "success",
                            "url": "https://github.com/dalagab/omega/actions/runs/100/job/2",
                            "steps": [{"name": "Fetch PluginMaster feeds", "status": "completed", "conclusion": "success"}],
                            "logPreview": "Wrote build/enriched-sources.json: 1352 plugins (1200 metadata-complete) from 42/44 source(s) OK.\n",
                        },
                    ],
                }
            ],
        }
        sigmascope_history = {
            "available": True,
            "runs": [
                {
                    "runId": 200,
                    "runNumber": 901,
                    "createdAtUtc": "2026-08-23T19:00:00Z",
                    "updatedAtUtc": "2026-08-23T19:10:00Z",
                    "url": "https://github.com/dalagab/omega/actions/runs/200",
                    "jobs": [
                        {
                            "name": "Process bounded Sigmascope batch against frozen daily inputs",
                            "status": "completed",
                            "conclusion": "success",
                            "url": "https://github.com/dalagab/omega/actions/runs/200/job/1",
                            "steps": [
                                {"name": "Examine bounded due-variant batch and build Evidence v2 candidate", "status": "completed", "conclusion": "success"},
                                {"name": "Project public-source coverage follow-ups", "status": "completed", "conclusion": "success"},
                                {"name": "Publish validated Security Evidence v2 snapshot atomically", "status": "completed", "conclusion": "success"},
                            ],
                            "logPreview": '{"successful": 18, "failedRetained": 2, "batch": {"queueSelected": 20, "scanSelected": 20, "completed": 18, "failed": 2}}',
                        }
                    ],
                }
            ],
        }
        histories = {
            "catalog-builder.yml": catalog_history,
            "sigmascope.yml": sigmascope_history,
            "deep-scan.yml": {"available": True, "runs": []},
        }
        summary = {
            "counts": {"plugins": 1300, "variants": 1352, "analyses": 1223, "completeScans": 1200, "failedScans": 3, "queuePending": 3181, "queueRetry": 13},
            "queueSummary": {"pendingByReason": {"source_followup": 10, "source_unresolved": 2}},
            "lastBatch": {"selectedCount": 20},
            "latestScanUtc": "2026-08-23T19:10:00Z",
            "generatedAtUtc": "2026-08-23T19:11:00Z",
        }
        result = deltascope_collectors.project_collectors(histories, summary, {"ruleProjections": {"available": True}})
        self.assertTrue(result["readOnly"])
        self.assertFalse(result["policyInput"])
        by_id = {row["id"]: row for row in result["collectors"]}
        source = by_id["source-discovery"]
        self.assertEqual("healthy", source["state"])
        metrics = {row["label"]: row["value"] for row in source["metrics"]}
        self.assertEqual(44, metrics["Deduplicated sources"])
        self.assertEqual(1300, metrics["Current plugins"])
        sigma = by_id["sigmascope-batch"]
        sigma_metrics = {row["label"]: row["value"] for row in sigma["metrics"]}
        self.assertEqual(18, sigma_metrics["Successful analyses"])
        self.assertEqual(20, sigma_metrics["Queue selected"])
        self.assertEqual(3181, sigma_metrics["Queue pending"])


    def test_collector_trends_flag_duration_and_stable_volume_regression(self) -> None:
        runs = []
        values = [10, 44, 45, 43, 44]
        durations = [300, 60, 62, 58, 61]
        for index, (value, duration) in enumerate(zip(values, durations)):
            day = 24 - index
            started = f"2026-08-{day:02d}T10:00:00Z"
            completed_dt = dt.datetime(2026, 8, day, 10, 0, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=duration)
            completed = completed_dt.isoformat().replace("+00:00", "Z")
            runs.append({
                "runId": 500 + index, "runNumber": 1000 - index,
                "createdAtUtc": started, "updatedAtUtc": completed,
                "url": f"https://github.com/dalagab/omega/actions/runs/{500+index}",
                "jobs": [{
                    "name": "Discover source feeds", "status": "completed", "conclusion": "success",
                    "startedAtUtc": started, "completedAtUtc": completed,
                    "url": f"https://github.com/dalagab/omega/actions/runs/{500+index}/job/1",
                    "steps": [{
                        "name": "Discover curated, Puni.sh and GitHub PluginMaster sources",
                        "status": "completed", "conclusion": "success",
                        "startedAtUtc": started, "completedAtUtc": completed,
                    }],
                    "logPreview": f"Wrote build/raw-sources.json: {value} source(s) — 7 curated, 8 community, 12 puni.sh, 17 github-search\n",
                }],
            })
        histories = {
            "catalog-builder.yml": {"available": True, "runs": runs},
            "sigmascope.yml": {"available": True, "runs": []},
            "deep-scan.yml": {"available": True, "runs": []},
        }
        result = deltascope_collectors.project_collectors(
            histories, {"counts": {}}, {"ruleProjections": {"available": True}},
            now_utc=dt.datetime(2026, 8, 24, 11, 0, tzinfo=dt.timezone.utc),
        )
        source = {row["id"]: row for row in result["collectors"]}["source-discovery"]
        self.assertEqual("degraded", source["trendState"])
        self.assertEqual(10.0, source["trend"]["throughput"]["latest"])
        self.assertEqual(44.0, source["trend"]["throughput"]["baselineMedian"])
        self.assertEqual(300.0, source["trend"]["duration"]["latestSeconds"])
        self.assertEqual("fresh", source["trend"]["freshness"]["state"])
        codes = {row["code"] for row in source["trend"]["signals"]}
        self.assertIn("throughput-drop", codes)
        self.assertIn("duration-regression", codes)
        self.assertGreaterEqual(result["degradingCount"], 1)

    def test_workload_collector_does_not_treat_normal_volume_change_as_stable_input_loss(self) -> None:
        def sigma_run(run_number: int, completed: int, selected: int, created: str) -> dict:
            return {
                "runId": run_number, "runNumber": run_number, "createdAtUtc": created, "updatedAtUtc": created,
                "jobs": [{
                    "name": "Process bounded Sigmascope batch against frozen daily inputs",
                    "status": "completed", "conclusion": "success",
                    "steps": [{"name": "Examine bounded due-variant batch and build Evidence v2 candidate", "status": "completed", "conclusion": "success"}],
                    "logPreview": '{"successful": %d, "failedRetained": 0, "batch": {"queueSelected": %d, "scanSelected": %d, "completed": %d, "failed": 0}}' % (completed, selected, selected, completed),
                }],
            }
        histories = {
            "catalog-builder.yml": {"available": True, "runs": []},
            "sigmascope.yml": {"available": True, "runs": [
                sigma_run(5, 2, 2, "2026-08-24T10:00:00Z"),
                sigma_run(4, 18, 20, "2026-08-24T09:00:00Z"),
                sigma_run(3, 20, 20, "2026-08-24T08:00:00Z"),
                sigma_run(2, 17, 20, "2026-08-24T07:00:00Z"),
            ]},
            "deep-scan.yml": {"available": True, "runs": []},
        }
        result = deltascope_collectors.project_collectors(
            histories, {"counts": {}}, {"ruleProjections": {"available": True}},
            now_utc=dt.datetime(2026, 8, 24, 10, 30, tzinfo=dt.timezone.utc),
        )
        sigma = {row["id"]: row for row in result["collectors"]}["sigmascope-batch"]
        codes = {row["code"] for row in sigma["trend"]["signals"]}
        self.assertNotIn("throughput-drop", codes)
        self.assertEqual(2.0, sigma["trend"]["throughput"]["latest"])

    def test_documentation_catalog_is_role_and_task_oriented_without_delivery_history(self) -> None:
        catalog = deltascope_docs.catalog()
        ids = {row["id"] for row in catalog["documents"]}
        for required in ("platform", "plugin-developers", "investigators", "researchers", "operations", "collectors", "detection-systems", "tagging", "extending", "stigma1", "rule-data"):
            self.assertIn(required, ids)
        forbidden = re.compile(r"\bPhase\s+\d+|\bunreleased\b|\bDeltaScope\s+\d+\.\d+|\bSigmaScope\s+\d+\.\d+\s+(?:development|line)|\bintroduced\s+in\b|\bimplemented locally\b", re.I)
        for item in catalog["documents"]:
            if not item.get("available") or not str(item.get("path") or "").endswith(".md"):
                continue
            document = deltascope_docs.read_document(item["id"])
            self.assertIsNone(forbidden.search(document["content"]), item["path"])

    def test_detection_tagging_and_collector_guides_have_extension_workflows(self) -> None:
        detection = deltascope_docs.read_document("detection-systems")["content"]
        tagging = deltascope_docs.read_document("tagging")["content"]
        collectors = deltascope_docs.read_document("collectors")["content"]
        self.assertIn("How to add a new detection", detection)
        self.assertIn("Capability vocabulary", tagging)
        self.assertIn("Adding a collector", collectors)
        self.assertIn("Operations → Collectors", collectors)


if __name__ == "__main__":
    unittest.main()
