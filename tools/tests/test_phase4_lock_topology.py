from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


class Phase4AuthorityLockTopologyTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def test_complete_migration_owns_one_global_authority_lock(self) -> None:
        migration = self.read("sigmascope-phase4-migration.yml")
        head = migration[: migration.index("\npermissions:\n")]
        self.assertIn("group: omega-catalog-sigmascope-exclusive", head)
        self.assertIn("cancel-in-progress: false", head)
        self.assertIn("queue: max", head)
        self.assertNotIn("group: omega-sigmascope-phase4-migration", migration)
        self.assertNotIn("uses: ./.github/workflows/sigmascope-phase4-cutover-core.yml", migration)

    def test_migration_sequences_freeze_proof_publish_and_verify_under_same_lock(self) -> None:
        migration = self.read("sigmascope-phase4-migration.yml")
        self.assertIn("\n  freeze-current-definitions:\n", migration)
        self.assertIn("needs: wait-for-operational-state", migration)
        self.assertIn("uses: ./.github/workflows/catalog-freeze.yml", migration)
        self.assertIn("authority_lock_held: true", migration)
        self.assertIn("needs: freeze-current-definitions", migration)
        self.assertLess(migration.index("\n  freeze-current-definitions:\n"), migration.index("\n  prerequisites:\n"))
        self.assertLess(migration.index("\n  prerequisites:\n"), migration.index("\n  shadow:\n"))
        self.assertLess(migration.index("\n  shadow:\n"), migration.index("\n  authorize-and-publish:\n"))
        self.assertLess(migration.index("\n  authorize-and-publish:\n"), migration.index("\n  verify:\n"))
        self.assertIn("publish_client: false", migration)
        self.assertIn("\n  publish-customer-catalog:\n", migration)
        self.assertLess(migration.index("\n  verify:\n"), migration.index("\n  publish-customer-catalog:\n"))
        customer = migration[migration.index("\n  publish-customer-catalog:\n") :]
        self.assertIn("needs: verify", customer)
        self.assertIn("uses: ./.github/workflows/catalog-client-publish.yml", customer)
        self.assertIn("authority_lock_held: true", customer)

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
