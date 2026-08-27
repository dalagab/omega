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
            "sigmascope-parallel-publish.yml",
            ("contents: write", "actions: write", "issues: write", "packages: read"),
        )
        self.assert_call_permissions(
            "sigmascope-phase4-migration.yml",
            "catalog-client-publish.yml",
            ("contents: write", "packages: read"),
        )
        migration = read("sigmascope-phase4-migration.yml")
        self.assertNotIn("uses: ./.github/workflows/sigmascope-parallel-shadow.yml", migration)
        self.assertNotIn(
            "uses: ./.github/workflows/sigmascope-phase4-cutover-core.yml",
            migration,
        )

    def test_inlined_phase4b_jobs_are_explicitly_read_only(self) -> None:
        migration = read("sigmascope-phase4-migration.yml")
        workers = migration[migration.index("  shadow-workers:\n") : migration.index("  shadow-merge:\n")]
        merge = migration[migration.index("  shadow-merge:\n") : migration.index("  authorize-and-publish:\n")]
        for block in (workers, merge):
            self.assertIn("permissions:", block)
            self.assertIn("contents: read", block)
            self.assertIn("packages: read", block)
            self.assertNotIn("contents: write", block)
            self.assertNotIn("actions: write", block)
            self.assertNotIn("issues: write", block)

    def test_standalone_shadow_remains_result_only_and_static(self) -> None:
        shadow = read("sigmascope-parallel-shadow.yml")
        self.assertNotIn("uses: ./.github/workflows/sigmascope-parallel-worker.yml", shadow)
        self.assertNotIn("fromJSON(needs.plan.outputs.matrix)", shadow)
        workers = shadow[shadow.index("  workers:\n") : shadow.index("  merge-plan:\n")]
        self.assertIn("runs-on: ubuntu-latest", workers)
        self.assertIn("permissions:", workers)
        self.assertIn("contents: read", workers)
        self.assertIn("packages: read", workers)
        self.assertIn("slot: [0, 1, 2, 3, 4, 5, 6, 7]", workers)
        self.assertIn('image: ${{ needs.resolve-merge-image.outputs.image }}', workers)
        self.assertIn('--queue-key "${{ steps.assignment.outputs.queue_key }}"', workers)

    def test_deeper_nested_calls_are_explicit_too(self) -> None:
        self.assert_call_permissions(
            "catalog-freeze.yml",
            "catalog-builder.yml",
            ("contents: write", "packages: read"),
        )
        self.assert_call_permissions(
            "catalog-freeze.yml",
            "catalog-client-publish.yml",
            ("contents: write", "packages: read"),
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
