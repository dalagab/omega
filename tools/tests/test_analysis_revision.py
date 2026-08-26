from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import common
import analysis_revision


class AnalysisRevisionTests(unittest.TestCase):
    def copy_analysis_tree(self, root: Path) -> Path:
        repo = root / "repo"
        for rel in {
            "tools/catalog/sigmascope.py",
            *analysis_revision.ARTIFACT_SUPPORT_FILES,
            *analysis_revision.SOURCE_SUPPORT_FILES,
        }:
            source = common.ROOT / rel
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return repo

    def test_unrelated_scheduler_file_does_not_change_analysis_revisions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            scheduler = repo / "tools/catalog/scan_queue.py"
            scheduler.write_text("# unrelated scheduler change\n", encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_source_only_helper_change_changes_only_source_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-source-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            helper = repo / "tools/catalog/source_stability.py"
            helper.write_text(helper.read_text(encoding="utf-8") + "\nOMEGA_SOURCE_REVISION_TEST_FIXTURE = 1\n", encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertNotEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_source_build_intelligence_change_changes_only_source_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-source-build-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            helper = repo / "tools/catalog/source_build_intelligence.py"
            helper.write_text(
                helper.read_text(encoding="utf-8") + "\nOMEGA_SOURCE_BUILD_REVISION_TEST_FIXTURE = 1\n",
                encoding="utf-8",
            )
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertNotEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_artifact_support_change_changes_artifact_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-artifact-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            helper = repo / "tools/catalog/security_endpoint_inventory.py"
            helper.write_text(helper.read_text(encoding="utf-8") + "\nOMEGA_SHARED_REVISION_TEST_FIXTURE = 1\n", encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertNotEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertNotEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_sigmascope_comments_do_not_change_ast_analysis_revisions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-comment-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            sigmascope = repo / "tools/catalog/sigmascope.py"
            sigmascope.write_text("# comment-only fixture\n" + sigmascope.read_text(encoding="utf-8"), encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_support_file_comments_do_not_change_analysis_revisions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-support-comment-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            helper = repo / "tools/catalog/source_stability.py"
            helper.write_text("# comment-only support fixture\n" + helper.read_text(encoding="utf-8"), encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_engine_version_bump_does_not_change_narrow_analysis_revisions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-version-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            sigmascope = repo / "tools/catalog/sigmascope.py"
            text = sigmascope.read_text(encoding="utf-8")
            text = text.replace('SIGMASCOPE_VERSION = "2.15.0"', 'SIGMASCOPE_VERSION = "99.99.99"')
            sigmascope.write_text(text, encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_capability_registry_change_changes_only_source_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-capabilities-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            registry = repo / "security-definitions/capabilities/registry.json"
            registry.write_text(registry.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertNotEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_service_registry_change_changes_artifact_and_source_revisions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-services-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            registry = repo / "security-definitions/services/registry.json"
            registry.write_text(registry.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertNotEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertNotEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_semantic_api_registry_change_changes_only_source_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-semantic-api-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            registry = repo / "security-definitions/semantic-apis/registry.json"
            registry.write_text(registry.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertNotEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])

    def test_source_behavior_collector_change_changes_only_source_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-analysis-revision-source-behavior-") as td:
            repo = self.copy_analysis_tree(Path(td))
            first = analysis_revision.compute(repo)
            helper = repo / "tools/catalog/source_behavior.py"
            helper.write_text(helper.read_text(encoding="utf-8") + "\nOMEGA_SOURCE_BEHAVIOR_REVISION_TEST_FIXTURE = 1\n", encoding="utf-8")
            second = analysis_revision.compute(repo)
            self.assertEqual(first["artifactAnalysisRevision"], second["artifactAnalysisRevision"])
            self.assertNotEqual(first["sourceAnalysisRevision"], second["sourceAnalysisRevision"])



if __name__ == "__main__":
    unittest.main()
