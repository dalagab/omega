from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ORCHESTRATION = ROOT / "tools" / "orchestration"
if str(ORCHESTRATION) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATION))

from git_snapshot_history import (  # noqa: E402
    HISTORY_FAST_FORWARD,
    HISTORY_LEGACY_ORPHAN,
    publish_snapshot_tree,
)


def run(cmd: list[str], cwd: Path, *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=capture, check=True)


class GitSnapshotHistoryTests(unittest.TestCase):
    def make_transport(self, root: Path) -> tuple[Path, Path]:
        bare = root / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
        repo = root / "source"
        repo.mkdir()
        run(["git", "init", "-q"], repo)
        run(["git", "config", "user.name", "Fixture"], repo)
        run(["git", "config", "user.email", "fixture@example.invalid"], repo)
        run(["git", "remote", "add", "origin", str(bare)], repo)
        return repo, bare

    def snapshot(self, root: Path, value: str) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / "index.json").write_text('{"value":"' + value + '"}\n', encoding="utf-8")
        nested = root / "variants" / "0001"
        nested.mkdir(parents=True, exist_ok=True)
        (nested / "1.json").write_text('{"value":"' + value + '"}\n', encoding="utf-8")
        return root

    def remote_head(self, bare: Path, branch: str) -> str:
        return run(["git", "rev-parse", f"refs/heads/{branch}"], bare, capture=True).stdout.strip()

    def parents(self, bare: Path, sha: str) -> list[str]:
        line = run(["git", "rev-list", "--parents", "-n", "1", sha], bare, capture=True).stdout.strip()
        return line.split()[1:]

    def test_existing_orphan_head_becomes_genesis_parent_of_fast_forward_history(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, bare = self.make_transport(root)
            first = self.snapshot(root / "first", "one")
            initial = publish_snapshot_tree(
                first,
                repo=repo,
                remote="origin",
                branch="evidence",
                push=True,
                author_name="Publisher",
                author_email="publisher@example.invalid",
                commit_message="snapshot one",
                history_mode=HISTORY_LEGACY_ORPHAN,
            )
            self.assertEqual([], self.parents(bare, initial.new_head), "fixture must start at the legacy orphan boundary")

            second = self.snapshot(root / "second", "two")
            migrated = publish_snapshot_tree(
                second,
                repo=repo,
                remote="origin",
                branch="evidence",
                push=True,
                author_name="Publisher",
                author_email="publisher@example.invalid",
                commit_message="snapshot two",
                history_mode=HISTORY_FAST_FORWARD,
            )
            self.assertTrue(migrated.pushed)
            self.assertFalse(migrated.no_op)
            self.assertEqual(initial.new_head, migrated.previous_head)
            self.assertEqual(initial.new_head, migrated.parent_head)
            self.assertEqual([initial.new_head], self.parents(bare, migrated.new_head))
            self.assertEqual(migrated.new_head, self.remote_head(bare, "evidence"))
            count = run(["git", "rev-list", "--count", "refs/heads/evidence"], bare, capture=True).stdout.strip()
            self.assertEqual("2", count)

    def test_unchanged_fast_forward_snapshot_is_a_noop(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, bare = self.make_transport(root)
            source = self.snapshot(root / "snapshot", "same")
            first = publish_snapshot_tree(
                source,
                repo=repo,
                remote="origin",
                branch="catalog",
                push=True,
                author_name="Publisher",
                author_email="publisher@example.invalid",
                commit_message="first",
            )
            second = publish_snapshot_tree(
                source,
                repo=repo,
                remote="origin",
                branch="catalog",
                push=True,
                author_name="Publisher",
                author_email="publisher@example.invalid",
                commit_message="must not exist",
            )
            self.assertTrue(second.no_op)
            self.assertFalse(second.pushed)
            self.assertEqual(first.new_head, second.new_head)
            self.assertEqual(first.new_head, self.remote_head(bare, "catalog"))
            count = run(["git", "rev-list", "--count", "refs/heads/catalog"], bare, capture=True).stdout.strip()
            self.assertEqual("1", count)

    def test_preflight_reports_current_parent_without_modifying_remote(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, bare = self.make_transport(root)
            source = self.snapshot(root / "snapshot", "one")
            first = publish_snapshot_tree(
                source,
                repo=repo,
                remote="origin",
                branch="state",
                push=True,
                author_name="Publisher",
                author_email="publisher@example.invalid",
                commit_message="first",
            )
            preview = publish_snapshot_tree(
                source,
                repo=repo,
                remote="origin",
                branch="state",
                push=False,
                author_name="Publisher",
                author_email="publisher@example.invalid",
                commit_message="preview",
            )
            self.assertFalse(preview.pushed)
            self.assertEqual(HISTORY_FAST_FORWARD, preview.history_mode)
            self.assertEqual(first.new_head, preview.previous_head)
            self.assertEqual(first.new_head, preview.parent_head)
            self.assertEqual(first.new_head, self.remote_head(bare, "state"))

    def test_expected_parent_mismatch_fails_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, bare = self.make_transport(root)
            source = self.snapshot(root / "snapshot", "one")
            first = publish_snapshot_tree(
                source,
                repo=repo,
                remote="origin",
                branch="evidence",
                push=True,
                author_name="Publisher",
                author_email="publisher@example.invalid",
                commit_message="first",
            )
            changed = self.snapshot(root / "changed", "two")
            with self.assertRaisesRegex(RuntimeError, "head mismatch"):
                publish_snapshot_tree(
                    changed,
                    repo=repo,
                    remote="origin",
                    branch="evidence",
                    push=True,
                    author_name="Publisher",
                    author_email="publisher@example.invalid",
                    commit_message="must fail",
                    expected_previous_head="0" * 40,
                )
            self.assertEqual(first.new_head, self.remote_head(bare, "evidence"))


if __name__ == "__main__":
    unittest.main()
