from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = REPO_ROOT / "tools" / "operations" / "roboscope_git_operations.py"


class _FakeCoverage(types.ModuleType):
    SOURCE_PRIORITY_RANK = {"official": 0, "curated": 1, "discovered": 2}

    @staticmethod
    def current_has_artifact_coverage(current):
        return bool(current and current.get("status") == "complete" and (current.get("scan_id") or current.get("scanned_at_utc")))


class _FakeScanQueue(types.ModuleType):
    SEED_SCHEMA = "omega.sigmascope.queue-seed.v2"
    REASON_PRIORITIES = {"manual": 1000, "new_variant": 900, "failed_retry": 600}

    @staticmethod
    def parse_utc(value):
        if not value:
            return None
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(dt.timezone.utc)

    @staticmethod
    def utc_now(now=None):
        value = now or dt.datetime.now(dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def due_reasons(variant, current, *, artifact_analysis_revision, manual=False):
        result = ["manual"] if manual else []
        if not current:
            result.append("new_variant")
        return result

    @staticmethod
    def _queue_item(variant, current, reasons, **kwargs):
        ordered = sorted(reasons, key=lambda reason: (-_FakeScanQueue.REASON_PRIORITIES.get(reason, 0), reason))
        return {
            "queueKey": f"variant-{variant['variantId']}", "workType": "artifact",
            "targetFingerprint": f"artifact-target-v2-base-{variant['variantId']}",
            **variant, "reasons": ordered, "primaryReason": ordered[0],
            "priority": max(_FakeScanQueue.REASON_PRIORITIES.get(reason, 0) for reason in ordered),
            "currentScanId": int((current or {}).get("scan_id") or 0),
            "currentScannedAtUtc": str((current or {}).get("scanned_at_utc") or ""),
        }

    @staticmethod
    def _selection_sort_key(item, covered_plugins=None):
        return (-int(item.get("operatorNudgeScore") or 0), -int(item.get("priority") or 0), int(item.get("variantId") or 0))

    @staticmethod
    def catalog_variants(_root):
        return []

    @staticmethod
    def evidence_current(_root):
        return {}


class _FakeDiscovery(types.ModuleType):
    COLLECTOR_ROBOSCOPE = "omega.collector.discovery.roboscope-operations"

    @staticmethod
    def canonical_github_repo(value):
        text = str(value or "")
        prefix = "https://github.com/"
        if not text.startswith(prefix):
            return ""
        parts = [part for part in text[len(prefix):].split("/") if part]
        return f"{prefix}{parts[0]}/{parts[1]}" if len(parts) >= 2 else ""


def _load_module():
    saved = {name: sys.modules.get(name) for name in ("scan_queue", "plugin_coverage_policy", "discovery_collectors")}
    sys.modules["scan_queue"] = _FakeScanQueue("scan_queue")
    sys.modules["plugin_coverage_policy"] = _FakeCoverage("plugin_coverage_policy")
    sys.modules["discovery_collectors"] = _FakeDiscovery("discovery_collectors")
    try:
        spec = importlib.util.spec_from_file_location("roboscope_git_operations_tested", OPERATIONS)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        for name, value in saved.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


ops = _load_module()


def _write_request(root: Path, kind: str, value: dict) -> Path:
    path = root / "requests" / kind / f"{value['requestId']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class RoboScopeGitOperationsTests(unittest.TestCase):
    def test_scan_request_id_is_content_derived_and_tampering_is_rejected(self):
        value = {
            "schema": ops.SCAN_REQUEST_SCHEMA,
            "requestedAtUtc": "2026-08-31T21:30:00Z",
            "pluginIds": [9, 3],
            "reason": "operator-nudge",
        }
        value["requestId"] = ops.scan_request_id(value)
        validated = ops.validate_scan_request(value)
        self.assertEqual(validated["pluginIds"], [3, 9])
        tampered = dict(value, requestedAtUtc="2026-08-31T21:30:01Z")
        with self.assertRaisesRegex(ValueError, "requestId"):
            ops.validate_scan_request(tampered)

    def test_source_repository_request_projects_repository_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            value = {
                "schema": ops.SOURCE_REQUEST_SCHEMA,
                "requestedAtUtc": "2026-08-31T21:31:00Z",
                "reference": "example/project",
                "type": "custom",
                "notes": "review this",
            }
            value["requestId"] = ops.source_request_id(value)
            _write_request(root, "sources", value)
            output = root / "out.json"
            result = ops.project_source_candidates(operations_root=root, output=output)
            self.assertEqual(result["sources"], [])
            self.assertEqual(result["repositoryCandidates"][0]["repositoryUrl"], "https://github.com/example/project")
            self.assertEqual(result["repositoryCandidates"][0]["collectorId"], ops.discovery_collectors.COLLECTOR_ROBOSCOPE)

    def test_source_direct_https_request_projects_source_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            value = {
                "schema": ops.SOURCE_REQUEST_SCHEMA,
                "requestedAtUtc": "2026-08-31T21:31:00Z",
                "reference": "https://plugins.example.invalid/pluginmaster.json",
                "type": "community",
                "notes": "",
            }
            value["requestId"] = ops.source_request_id(value)
            _write_request(root, "sources", value)
            result = ops.project_source_candidates(operations_root=root, output=root / "out.json")
            self.assertEqual(len(result["sources"]), 1)
            self.assertEqual(result["sources"][0]["discoveredBy"], "roboscope-git-request")

    def test_multiple_unsatisfied_nudges_raise_score_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            seed_path = root / "seed.json"
            seed = {
                "schema": ops.scan_queue.SEED_SCHEMA, "queueSeedRevision": "queue-base",
                "generatedAtUtc": "2026-08-31T21:00:00Z", "catalogRevision": "cat",
                "catalogIdentityEpoch": "epoch", "definitionsRevision": "defs",
                "scannerRevision": "scanner", "artifactAnalysisRevision": "analysis",
                "ruleSetRevision": "rules", "counts": {"queued": 0}, "items": [],
            }
            seed_path.write_text(json.dumps(seed), encoding="utf-8")
            variants = [{
                "variantId": 71, "pluginId": 7, "sourceId": 1, "internalName": "Seven",
                "name": "Seven", "sourceName": "Dalamud official", "sourcePriorityClass": "official",
                "assemblyVersion": "1.0", "artifactChannel": "stable", "artifactUrl": "https://example.invalid/a.zip",
                "repositoryUrl": "", "sourceRepositoryUrl": "",
            }]
            for second in (1, 2):
                request = {
                    "schema": ops.SCAN_REQUEST_SCHEMA,
                    "requestedAtUtc": f"2026-08-31T21:30:0{second}Z",
                    "pluginIds": [7], "reason": "operator-nudge",
                }
                request["requestId"] = ops.scan_request_id(request)
                _write_request(root, "scans", request)
            with mock.patch.object(ops.scan_queue, "catalog_variants", return_value=variants), \
                 mock.patch.object(ops.scan_queue, "evidence_current", return_value={}):
                report = ops.build_scan_overlay(
                    queue_seed=seed_path, catalog_root=root, evidence_root=root,
                    operations_root=root, output=root / "effective.json", report_path=root / "report.json",
                )
            effective = json.loads((root / "effective.json").read_text(encoding="utf-8"))
            item = effective["items"][0]
            self.assertEqual(item["operatorNudgeCount"], 2)
            self.assertEqual(item["operatorNudgeScore"], 50)
            self.assertNotEqual(item["targetFingerprint"], "artifact-target-v2-base-71")
            self.assertEqual(report["activeRequestCount"], 2)

    def test_newer_evidence_satisfies_nudge_without_overlay(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            seed = {
                "schema": ops.scan_queue.SEED_SCHEMA, "queueSeedRevision": "queue-base",
                "generatedAtUtc": "2026-08-31T21:00:00Z", "counts": {"queued": 0}, "items": [],
            }
            seed_path = root / "seed.json"; seed_path.write_text(json.dumps(seed), encoding="utf-8")
            variants = [{"variantId": 71, "pluginId": 7, "sourcePriorityClass": "official", "artifactChannel": "stable"}]
            current = {71: {"status": "complete", "scan_id": 4, "scanned_at_utc": "2026-08-31T21:40:00Z"}}
            request = {
                "schema": ops.SCAN_REQUEST_SCHEMA, "requestedAtUtc": "2026-08-31T21:30:00Z",
                "pluginIds": [7], "reason": "operator-nudge",
            }
            request["requestId"] = ops.scan_request_id(request); _write_request(root, "scans", request)
            with mock.patch.object(ops.scan_queue, "catalog_variants", return_value=variants), \
                 mock.patch.object(ops.scan_queue, "evidence_current", return_value=current):
                report = ops.build_scan_overlay(
                    queue_seed=seed_path, catalog_root=root, evidence_root=root,
                    operations_root=root, output=root / "effective.json", report_path=root / "report.json",
                )
            self.assertEqual(report["activeRequestCount"], 0)
            self.assertEqual((root / "effective.json").read_bytes(), seed_path.read_bytes())

    def test_merge_source_candidates_deduplicates_urls_and_repositories(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base.json"
            operator = root / "operator.json"
            base.write_text(json.dumps({
                "metadata": {}, "sources": [{"url": "https://a.example/repo.json"}],
                "repositoryCandidates": [{"repositoryUrl": "https://github.com/a/b"}],
            }), encoding="utf-8")
            operator.write_text(json.dumps({
                "schema": ops.SOURCE_CANDIDATES_SCHEMA, "acceptedRequestFiles": 2, "invalidRequestFiles": [],
                "sources": [{"url": "https://a.example/repo.json"}, {"url": "https://b.example/repo.json"}],
                "repositoryCandidates": [{"repositoryUrl": "https://github.com/a/b"}, {"repositoryUrl": "https://github.com/c/d"}],
            }), encoding="utf-8")
            merged = ops.merge_source_candidates(base=base, operator=operator, output=root / "merged.json")
            self.assertEqual(len(merged["sources"]), 2)
            self.assertEqual(len(merged["repositoryCandidates"]), 2)

    def test_rescan_prefers_already_covered_representative(self):
        variants = [
            {"variantId": 1, "sourcePriorityClass": "official", "artifactChannel": "stable"},
            {"variantId": 2, "sourcePriorityClass": "curated", "artifactChannel": "stable"},
        ]
        current = {2: {"status": "complete", "scan_id": 9, "scanned_at_utc": "2026-08-31T21:00:00Z"}}
        ordered = sorted(variants, key=lambda row: ops._variant_rank(row, current))
        self.assertEqual(ordered[0]["variantId"], 2)

    def test_reconciliation_bootstraps_operations_branch_and_consumers_read_it(self):
        reconcile = (REPO_ROOT / ".github" / "workflows" / "security-reconcile.yml").read_text(encoding="utf-8")
        drain = (REPO_ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        discovery = (REPO_ROOT / ".github" / "workflows" / "catalog-discovery-worker.yml").read_text(encoding="utf-8")
        self.assertIn("Ensure append-only RoboScope operations branch exists", reconcile)
        self.assertIn("switch --orphan security-operations", reconcile)
        self.assertIn("--operations-root catalog/roboscope-operations", reconcile)
        self.assertIn("build-scan-overlay", drain)
        self.assertIn("roboscope-effective-scan-queue.json", drain)
        self.assertIn("project-source-candidates", discovery)



if __name__ == "__main__":
    unittest.main()
