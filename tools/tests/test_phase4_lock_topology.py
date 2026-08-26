from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


class Phase4AuthorityLockTopologyTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def test_migration_enters_one_locked_core_only_after_collector_settlement(self) -> None:
        migration = self.read("sigmascope-phase4-migration.yml")
        self.assertNotIn("\n  freeze-current-definitions:\n", migration)
        self.assertIn("name: Run locked Phase-4 freeze, proof and one-writer cutover", migration)
        self.assertIn("needs: wait-for-operational-state", migration)
        self.assertIn("uses: ./.github/workflows/sigmascope-phase4-cutover-core.yml", migration)
        cutover = migration[migration.index("\n  cutover:\n") :]
        self.assertIn("concurrency:", cutover)
        self.assertIn("group: omega-catalog-sigmascope-exclusive", cutover)
        self.assertIn("cancel-in-progress: false", cutover)
        self.assertIn("queue: max", cutover)
        self.assertLess(
            cutover.index("concurrency:"),
            cutover.index("uses: ./.github/workflows/sigmascope-phase4-cutover-core.yml"),
        )

    def test_cutover_holds_global_authority_lock_across_freeze_and_evidence_transaction(self) -> None:
        migration = self.read("sigmascope-phase4-migration.yml")
        cutover = migration[migration.index("\n  cutover:\n") :]
        core = self.read("sigmascope-phase4-cutover-core.yml")
        self.assertIn("group: omega-catalog-sigmascope-exclusive", cutover)
        self.assertNotIn("\nconcurrency:\n", core)
        self.assertIn("freeze-current-definitions:", core)
        self.assertIn("uses: ./.github/workflows/catalog-freeze.yml", core)
        self.assertIn("authority_lock_held: true", core)
        self.assertIn("needs: freeze-current-definitions", core)
        self.assertLess(core.index("freeze-current-definitions:"), core.index("prerequisites:"))
        self.assertLess(core.index("prerequisites:"), core.index("shadow:"))
        self.assertLess(core.index("shadow:"), core.index("authorize-and-publish:"))
        self.assertLess(core.index("authorize-and-publish:"), core.index("verify:"))

    def test_nested_freeze_never_recursively_acquires_global_authority_lock(self) -> None:
        wrapper = self.read("catalog-freeze.yml")
        builder = self.read("catalog-builder.yml")
        self.assertIn("authority_lock_held:", wrapper)
        self.assertIn("authority_lock_held: ${{ inputs.authority_lock_held || false }}", wrapper)
        self.assertIn("authority_lock_held:", builder)
        self.assertIn("omega-catalog-freeze-under-phase4-{0}", builder)
        self.assertIn("'omega-catalog-sigmascope-exclusive'", builder)
        self.assertNotIn("\n  group: omega-catalog-sigmascope-exclusive\n", builder)


if __name__ == "__main__":
    unittest.main()
