from __future__ import annotations

import unittest

import common


class SigmaScopeDrainWakeCircuitBreakerTests(unittest.TestCase):
    def test_automatic_wake_suppresses_unchanged_failed_production_inputs(self) -> None:
        text = (
            common.ROOT / ".github" / "workflows" / "sigmascope-drain-wake.yml"
        ).read_text(encoding="utf-8")

        for required in (
            "--json databaseId,status,conclusion,headSha,url,createdAt",
            "git/ref/heads/sigmascope",
            "git/ref/heads/security-evidence-v2",
            "omega-sigmascope-drain-plan",
            ".executionContext.baseEvidenceHead",
            ".capacity // 0",
            'failure_fingerprint="production-drain-failure"',
            "Automatic production drain suppressed",
            "circuit breaker is fail-open",
            "Manual direct drain dispatch: still available",
        ):
            self.assertIn(required, text)

        breaker = text.index("# Automatic wake circuit breaker")
        dispatch = text.index("gh workflow run sigmascope-parallel-drain.yml")
        self.assertLess(breaker, dispatch)
        self.assertIn('[ "$previous_capacity" -eq 64 ]', text)
        self.assertIn('[ "$previous_evidence" = "$current_evidence" ]', text)
        self.assertIn('[ "$latest_source" = "$current_source" ]', text)
        self.assertIn('latest_completed=\'{}\'', text)
        self.assertIn('<<<"$latest_completed"', text)
        self.assertNotIn('${latest_completed:-{}}', text)


if __name__ == "__main__":
    unittest.main()
