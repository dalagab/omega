from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import common

SECURITY = common.ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import publish_deep_scan_state  # noqa: E402


class DeepScanPublisherGitSafetyTests(unittest.TestCase):
    def test_repo_git_uses_exact_safe_directory_not_wildcard(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-deep-publisher-") as td:
            repo = Path(td).resolve()
            command = publish_deep_scan_state._repo_git(
                repo, "rev-parse", "--show-toplevel"
            )

        self.assertEqual("git", command[0])
        self.assertEqual("-c", command[1])
        self.assertEqual(f"safe.directory={repo}", command[2])
        self.assertNotIn("safe.directory=*", command)

    def test_git_root_requires_exact_repository_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-deep-root-") as td:
            repo = Path(td).resolve()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            self.assertEqual(repo, publish_deep_scan_state.git_root(repo))

            child = repo / "child"
            child.mkdir()
            with self.assertRaisesRegex(RuntimeError, "must be its exact Git root"):
                publish_deep_scan_state.git_root(child)


if __name__ == "__main__":
    unittest.main()
