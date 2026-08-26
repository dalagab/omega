from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
AUTHORITY_GROUP = "omega-catalog-sigmascope-exclusive"


class AuthorityConcurrencyQueueTests(unittest.TestCase):
    def test_every_shared_authority_mutex_is_a_real_queue(self) -> None:
        users: list[str] = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(
                r"(?ms)^concurrency:\n(?P<body>(?:  [^\n]*\n)+)",
                text,
            ):
                block = match.group(0)
                if AUTHORITY_GROUP not in block:
                    continue
                users.append(path.name)
                self.assertIn(
                    "cancel-in-progress: false",
                    block,
                    f"{path.name}: authoritative writers must never cancel the running writer",
                )
                self.assertIn(
                    "queue: max",
                    block,
                    f"{path.name}: default queue:single can evict an existing pending authority writer",
                )

        self.assertGreaterEqual(len(users), 4)
        for expected in (
            "sigmascope.yml",
            "catalog-builder.yml",
            "sigmascope-parallel-publish.yml",
            "rift-evidence-ingest.yml",
        ):
            self.assertIn(expected, users)

        migration = (WORKFLOWS / "sigmascope-phase4-migration.yml").read_text(encoding="utf-8")
        cutover = migration[migration.index("\n  cutover:\n") :]
        self.assertIn("concurrency:", cutover)
        self.assertIn(AUTHORITY_GROUP, cutover)
        self.assertIn("cancel-in-progress: false", cutover)
        self.assertIn("queue: max", cutover)

        core = (WORKFLOWS / "sigmascope-phase4-cutover-core.yml").read_text(encoding="utf-8")
        self.assertNotIn("\nconcurrency:\n", core)


if __name__ == "__main__":
    unittest.main()
