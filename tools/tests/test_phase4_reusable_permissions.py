from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def read(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


class Phase4ReusablePermissionTests(unittest.TestCase):
    def assert_call_permissions(
        self,
        workflow: str,
        called: str,
        expected: tuple[str, ...],
    ) -> None:
        text = read(workflow)
        marker = f"uses: ./.github/workflows/{called}"
        self.assertIn(marker, text)
        start = text.index(marker)
        # A reusable-workflow call job is compact. Limit the assertion to its local
        # block so a workflow-level permission cannot accidentally satisfy the test.
        block = text[start : start + 420]
        self.assertIn("permissions:", block)
        for permission in expected:
            self.assertIn(permission, block)

    def test_top_level_migration_explicitly_passes_each_reusable_permission_ceiling(self) -> None:
        self.assert_call_permissions(
            "sigmascope-phase4-migration.yml",
            "worker-images.yml",
            ("contents: write", "packages: write"),
        )
        self.assert_call_permissions(
            "sigmascope-phase4-migration.yml",
            "security-reconcile.yml",
            ("contents: write", "actions: write"),
        )
        self.assert_call_permissions(
            "sigmascope-phase4-migration.yml",
            "catalog-freeze.yml",
            ("contents: write", "packages: read"),
        )
        self.assert_call_permissions(
            "sigmascope-phase4-migration.yml",
            "sigmascope-parallel-shadow.yml",
            ("contents: read", "packages: read"),
        )
        self.assert_call_permissions(
            "sigmascope-phase4-migration.yml",
            "sigmascope-parallel-publish.yml",
            ("contents: write", "actions: write", "issues: write", "packages: read"),
        )
        self.assertNotIn(
            "uses: ./.github/workflows/sigmascope-phase4-cutover-core.yml",
            read("sigmascope-phase4-migration.yml"),
        )

    def test_deeper_nested_calls_are_explicit_too(self) -> None:
        self.assert_call_permissions(
            "catalog-freeze.yml",
            "catalog-builder.yml",
            ("contents: write", "packages: read"),
        )
        self.assert_call_permissions(
            "sigmascope-parallel-shadow.yml",
            "sigmascope-parallel-worker.yml",
            ("contents: read", "packages: read"),
        )

    def test_parallel_publisher_declares_its_real_maximum_permission_contract(self) -> None:
        text = read("sigmascope-parallel-publish.yml")
        head = text[: text.index("concurrency:")]
        for permission in (
            "contents: write",
            "actions: write",
            "issues: write",
            "packages: read",
        ):
            self.assertIn(permission, head)
        resolve = text[text.index("  resolve-images:") : text.index("  authorize:")]
        self.assertIn("permissions:", resolve)
        self.assertIn("contents: read", resolve)
        self.assertIn("packages: read", resolve)


if __name__ == "__main__":
    unittest.main()
