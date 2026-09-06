from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
ORCHESTRATION = ROOT / "tools" / "orchestration"
if str(ORCHESTRATION) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATION))

import git_snapshot_history as history  # noqa: E402


class GitSnapshotSafeDirectoryTests(unittest.TestCase):
    def make_repo(self, root: Path) -> tuple[Path, Path]:
        bare = root / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "remote", "add", "origin", str(bare)], cwd=repo, check=True)
        return repo.resolve(), bare.resolve()

    def test_git_root_trusts_only_exact_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, _ = self.make_repo(Path(td))
            calls: list[list[str]] = []
            real_run = history.run

            def recording(cmd: list[str], **kwargs):
                calls.append(cmd)
                return real_run(cmd, **kwargs)

            with patch.object(history, "run", side_effect=recording):
                self.assertEqual(repo, history.git_root(repo))

            self.assertEqual(
                ["git", "-c", "core.longpaths=true", "-c", f"safe.directory={repo}", "rev-parse", "--show-toplevel"],
                calls[0],
            )
            self.assertFalse(any("safe.directory=*" in part for cmd in calls for part in cmd))

    def test_remote_reads_use_exact_checkout_and_resolved_url(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, bare = self.make_repo(Path(td))
            calls: list[list[str]] = []
            real_run = history.run

            def recording(cmd: list[str], **kwargs):
                calls.append(cmd)
                return real_run(cmd, **kwargs)

            with patch.object(history, "run", side_effect=recording):
                url = history.remote_url(repo, "origin")
                self.assertEqual(str(bare), url)
                self.assertEqual("", history.remote_branch_sha(repo, url, "catalog-data"))

            self.assertEqual(
                ["git", "-c", "core.longpaths=true", "-c", f"safe.directory={repo}", "remote", "get-url", "origin"],
                calls[0],
            )
            self.assertEqual(
                ["git", "-c", "core.longpaths=true", "-c", f"safe.directory={repo}", "ls-remote", "--heads", str(bare), "refs/heads/catalog-data"],
                calls[1],
            )
            self.assertNotIn("origin", calls[1])
            self.assertFalse(any("safe.directory=*" in part for cmd in calls for part in cmd))

    def test_git_root_rejects_non_root_repo_argument(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, _ = self.make_repo(Path(td))
            nested = repo / "nested"
            nested.mkdir()
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=str(repo) + "\n",
                stderr="",
            )
            with patch.object(history, "run", return_value=completed) as mocked:
                with self.assertRaisesRegex(RuntimeError, "exact Git root"):
                    history.git_root(nested)
            command = mocked.call_args.args[0]
            self.assertIn(f"safe.directory={nested.resolve()}", command)
            self.assertNotIn("safe.directory=*", command)


if __name__ == "__main__":
    unittest.main()
