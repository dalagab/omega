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
                    f"{path.name}: authoritative work must preserve the pending writer queue",
                )

        for expected in (
            "sigmascope.yml",
            "catalog-builder.yml",
            "catalog-release-intake.yml",
            "catalog-client-publish.yml",
            "rift-evidence-ingest.yml",
        ):
            self.assertIn(expected, users)

        drain = (WORKFLOWS / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        top = drain[: drain.index("\njobs:")]
        publish = drain[drain.index("\n  publish:"): drain.index("\n  publish-client:")]
        self.assertIn("group: omega-sigmascope-parallel-drain-exclusive", top)
        self.assertNotIn(f"group: {AUTHORITY_GROUP}", top)
        self.assertIn(f"group: {AUTHORITY_GROUP}", publish)
        self.assertIn("cancel-in-progress: false", publish)
        self.assertIn("queue: max", publish)
        self.assertIn("refs/heads/catalog-data", publish)
        self.assertIn("refs/heads/security-evidence-v2", publish)


if __name__ == "__main__":
    unittest.main()
