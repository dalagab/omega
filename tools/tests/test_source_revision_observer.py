from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import common
import public_git_source
import source_revision_observer


class SourceRevisionObserverTests(unittest.TestCase):
    def test_observe_remote_head_uses_only_ls_remote(self) -> None:
        stdout = b"ref: refs/heads/main\tHEAD\n" + (b"a" * 40) + b"\tHEAD\n"
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=b"")
        with patch("public_git_source._public_https_remote", return_value="https://github.com/example/plugin.git"), \
             patch("public_git_source.subprocess.run", return_value=completed) as run:
            result = public_git_source.observe_remote_head("https://github.com/example/plugin", timeout=3)
        self.assertEqual("refs/heads/main", result["defaultRef"])
        self.assertEqual("a" * 40, result["commitSha"])
        argv = run.call_args.args[0]
        self.assertIn("ls-remote", argv)
        self.assertIn("--symref", argv)
        self.assertNotIn("clone", argv)
        self.assertNotIn("fetch", argv)
        self.assertNotIn("checkout", argv)

    def test_catalog_repository_candidates_are_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-observer-catalog-") as td:
            root = Path(td)
            (root / "plugins").mkdir(parents=True)
            (root / "sources").mkdir(parents=True)
            (root / "plugins/index.json").write_text(json.dumps({"plugins": [
                {"active": True, "path": "plugins/a.json"},
                {"active": True, "path": "plugins/b.json"},
            ]}), encoding="utf-8")
            (root / "sources/index.json").write_text(json.dumps({"sources": [
                {"sourceId": 1, "path": "sources/1.json"},
            ]}), encoding="utf-8")
            (root / "sources/1.json").write_text(json.dumps({"source": {"source_id": 1, "source_repo_url": "https://github.com/example/plugin"}}), encoding="utf-8")
            for name in ("a", "b"):
                (root / f"plugins/{name}.json").write_text(json.dumps({"variants": [{"variant": {
                    "active": 1, "source_id": 1, "repo_url": "https://github.com/example/plugin",
                    "download_link_install": "https://github.com/example/plugin/releases/download/v1/plugin.zip",
                    "download_link_testing": "",
                }}]}), encoding="utf-8")
            repositories = source_revision_observer.catalog_repositories(root)
            self.assertEqual(["https://github.com/example/plugin"], repositories)

    def test_observe_emits_stable_machine_revision_and_failure_rows(self) -> None:
        with patch("source_revision_observer.catalog_repositories", return_value=[
                 "https://github.com/example/a", "https://github.com/example/b"]), \
             patch("source_revision_observer.observe_remote_head", side_effect=[
                 {"defaultRef": "refs/heads/main", "commitSha": "1" * 40},
                 RuntimeError("unreachable"),
             ]):
            first = source_revision_observer.observe(common.ROOT, concurrency=1)
        self.assertEqual(2, first["counts"]["repositories"])
        self.assertEqual(1, first["counts"]["observed"])
        self.assertEqual(1, first["counts"]["failed"])
        self.assertTrue(first["revision"].startswith("source-observations-v1-"))
        self.assertEqual("observed", first["repositories"][0]["status"])
        self.assertEqual("failed", first["repositories"][1]["status"])


if __name__ == "__main__":
    unittest.main()
