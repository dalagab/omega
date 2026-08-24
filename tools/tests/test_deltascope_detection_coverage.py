import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_detection_coverage as coverage  # noqa: E402


class FakeInspector:
    def summary(self):
        return {"generatedAtUtc": "2026-08-24T09:00:00Z", "meta": {}}

    def list_plugins(self, limit=2000, **_kwargs):
        self.limit = limit
        return [
            {
                "variant_id": 1, "plugin_id": 10, "canonical_name": "Current",
                "assembly_version": "2.0.0", "scan_status": "complete",
                "scanned_at_utc": "2026-08-24T08:00:00Z", "source_available": 1,
                "artifact_analysis_revision": "artifact-current", "source_analysis_revision": "source-current",
            },
            {
                "variant_id": 2, "plugin_id": 20, "canonical_name": "Stale",
                "assembly_version": "1.0.0", "scan_status": "complete",
                "scanned_at_utc": "2026-08-20T08:00:00Z", "source_available": 1,
                "artifact_analysis_revision": "artifact-old", "source_analysis_revision": "source-old",
            },
            {
                "variant_id": 3, "plugin_id": 30, "canonical_name": "Pending",
                "assembly_version": "3.0.0", "scan_status": "pending",
                "scanned_at_utc": "", "source_available": 0,
                "artifact_analysis_revision": "", "source_analysis_revision": "",
            },
        ]

    def workbench_system_context(self):
        return {
            "generatedAtUtc": "2026-08-24T09:00:00Z",
            "evidence": {"revisions": {
                "evidenceRevision": "ev-current", "definitionsRevision": "defs-current",
                "artifactAnalysisRevision": "artifact-current", "sourceAnalysisRevision": "source-current",
                "ruleSetRevision": "rules-current",
            }},
            "source": {"osv": {
                "schema": "omega.security-evidence.osv-coverage.v1",
                "expectedQueryPackageVersionPairs": 10, "queriedPackageVersionPairs": 8,
                "notCoveredByFrozenDefinitions": 2, "advisoryRevision": "osv-current",
            }},
            "queue": {"available": True, "summary": {"states": {"pending": 2, "retry": 1}}},
        }

    def definition_provenance(self):
        return {
            "available": True,
            "activeRules": [
                {"active": True, "ruleId": "primitive.process", "packId": "core", "kind": "observation", "requires": ["staticPatternMatches"]},
                {"active": True, "ruleId": "network.rule", "packId": "core", "kind": "observation", "requires": ["networkEndpoints"]},
            ],
        }


class DetectionCoverageTests(unittest.TestCase):
    def test_current_revision_is_coverage_and_stale_or_incomplete_are_gaps(self):
        inspector = FakeInspector()
        payload = coverage.project_detection_coverage(inspector)
        self.assertEqual(coverage.SCHEMA, payload["schema"])
        self.assertTrue(payload["readOnly"])
        self.assertEqual("none", payload["mutationAuthority"])
        self.assertEqual(3, payload["corpus"]["currentVariants"])
        self.assertEqual(1, payload["corpus"]["artifactRevisionCurrent"])
        row = next(x for x in payload["collections"] if x["collection"] == "staticPatternMatches")
        self.assertEqual(3, row["targetVariants"])
        self.assertEqual(1, row["coveredVariants"])
        self.assertEqual(1, row["staleVariants"])
        self.assertEqual(1, row["incompleteVariants"])
        self.assertEqual(2, row["gapVariants"])
        self.assertTrue(row["rescanRequiredForGap"])
        self.assertFalse(row["reprojectionSufficientForMissingRawObservation"])
        self.assertEqual(["primitive.process"], [x["ruleId"] for x in row["rules"]])
        self.assertEqual("published-definitions", payload["ruleDependencyAuthority"])
        self.assertEqual(2000, inspector.limit)

    def test_source_only_collection_uses_attributable_source_as_scope(self):
        payload = coverage.project_detection_coverage(FakeInspector())
        row = next(x for x in payload["collections"] if x["collection"] == "sourceFiles")
        self.assertEqual(2, row["targetVariants"])
        self.assertEqual(1, row["outsideScopeVariants"])
        self.assertEqual(1, row["coveredVariants"])
        self.assertEqual(1, row["staleVariants"])
        self.assertEqual("sourceAnalysisRevision", row["revisionKey"])
        self.assertEqual("source follow-up / source re-analysis", row["remediation"])

    def test_osv_coverage_uses_package_version_pair_universe_not_plugin_denominator(self):
        payload = coverage.project_detection_coverage(FakeInspector())
        row = next(x for x in payload["collections"] if x["collection"] == "OSV / NuGet advisories")
        self.assertEqual("package-version pairs", row["unit"])
        self.assertEqual(10, row["targetVariants"])
        self.assertEqual(8, row["coveredVariants"])
        self.assertEqual(2, row["gapVariants"])
        self.assertEqual(80.0, row["coveragePercent"])
        self.assertFalse(row["rescanRequiredForGap"])

    def test_repository_rules_are_only_fallback_when_published_provenance_is_absent(self):
        class NoProvenance(FakeInspector):
            def definition_provenance(self):
                return {}

        library = {"packs": [{"packId": "repo-pack", "rules": [{"ruleId": "repo.rule", "requires": ["dependencies"]}]}]}
        payload = coverage.project_detection_coverage(NoProvenance(), repository_library=library)
        row = next(x for x in payload["collections"] if x["collection"] == "dependencies")
        self.assertEqual("repository-source", payload["ruleDependencyAuthority"])
        self.assertEqual("repo.rule", row["rules"][0]["ruleId"])

    def test_empty_complete_collection_is_not_inferred_from_positive_row_count(self):
        payload = coverage.project_detection_coverage(FakeInspector())
        row = next(x for x in payload["collections"] if x["collection"] == "managedCallSites")
        self.assertIn("narrow analysis revision", row["coverageBasis"])
        self.assertIn("exact row presence", row["coverageExactness"])
        self.assertNotIn("rowCount", row)


if __name__ == "__main__":
    unittest.main()
