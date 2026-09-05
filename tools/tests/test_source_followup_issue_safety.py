from __future__ import annotations

import json
import unittest
from unittest import mock

import common  # noqa: F401
import cleanup_source_followup_issues
import create_source_followup_issues


def managed_issue(number: int, internal_name: str) -> dict:
    return {
        "number": number,
        "title": f"Source needed: {internal_name}",
        "body": (
            f"<!-- omega-source-followup:src-{number} -->\\n"
            f"<!-- omega-source-internal:{internal_name} -->"
        ),
    }


class SourceFollowupIssueSafetyTests(unittest.TestCase):
    def test_open_followups_uses_complete_rest_pagination(self) -> None:
        payload = [
            [managed_issue(1, "One")],
            [{"number": 9, "pull_request": {"url": "https://api.github.test/pulls/9"}}, managed_issue(2, "Two")],
            [],
        ]
        with mock.patch.object(
            create_source_followup_issues, "gh", return_value=json.dumps(payload),
        ) as github:
            issues = create_source_followup_issues._open_followup_issues("example/omega")
        self.assertEqual([1, 2], [row["number"] for row in issues])
        arguments = github.call_args.args
        self.assertEqual(("api", "--paginate", "--slurp"), arguments[:3])
        self.assertTrue(any("per_page=100" in argument for argument in arguments))

    def test_open_followups_fails_closed_on_malformed_pagination(self) -> None:
        with mock.patch.object(
            create_source_followup_issues, "gh", return_value=json.dumps({"items": []}),
        ), self.assertRaisesRegex(RuntimeError, "incomplete or malformed"):
            create_source_followup_issues._open_followup_issues("example/omega")

    def test_issue_beyond_old_thousand_item_window_is_not_recreated(self) -> None:
        existing = [managed_issue(number, f"Plugin{number}") for number in range(1, 1001)]
        existing.append(managed_issue(1001, "ExistingTarget"))
        document = {
            "followups": [{
                "key": "omega-source-followup:src-target",
                "overrideKey": "src-target",
                "internalName": "ExistingTarget",
                "pluginName": "Existing Target",
                "assemblyVersion": "1.0.0",
                "catalogSource": "Mirror",
                "catalogSourceUrl": "https://example.invalid/plugins.json",
                "artifactUrl": "https://example.invalid/plugin.zip",
                "reason": "source missing",
                "sourceCandidates": [],
                "actionable": True,
            }],
            "resolved": [],
            "resolvedKeys": [],
        }
        calls = []
        with mock.patch.object(
            create_source_followup_issues, "_open_followup_issues", return_value=existing,
        ), mock.patch.object(
            create_source_followup_issues, "gh", side_effect=lambda *args: calls.append(args) or "",
        ):
            result = create_source_followup_issues.reconcile_issues(document, "example/omega")
        self.assertEqual((0, 0), result)
        self.assertFalse(any(call[:2] == ("issue", "create") for call in calls))

    def test_reconciliation_bounds_duplicate_closures(self) -> None:
        existing = [managed_issue(number, "Repeated") for number in range(1, 8)]
        calls = []
        with mock.patch.object(
            create_source_followup_issues, "_open_followup_issues", return_value=existing,
        ), mock.patch.object(
            create_source_followup_issues, "gh", side_effect=lambda *args: calls.append(args) or "",
        ):
            result = create_source_followup_issues.reconcile_issues(
                {"followups": [], "resolved": [], "resolvedKeys": []},
                "example/omega",
                max_new=0,
                max_close=3,
            )
        self.assertEqual((0, 3), result)
        self.assertEqual(3, sum(call[:2] == ("issue", "close") for call in calls))

    def test_cleanup_plan_keeps_oldest_and_apply_is_bounded(self) -> None:
        plan = cleanup_source_followup_issues.cleanup_plan([
            managed_issue(8, "Alpha"),
            managed_issue(3, "Alpha"),
            managed_issue(5, "Beta"),
            managed_issue(4, "Alpha"),
        ])
        self.assertEqual(1, plan["duplicatePlugins"])
        self.assertEqual(2, plan["duplicateIssues"])
        self.assertEqual(3, plan["groups"][0]["keepIssue"])
        self.assertEqual([4, 8], plan["groups"][0]["closeIssues"])
        with mock.patch.object(
            cleanup_source_followup_issues, "_close_issue", return_value=True,
        ) as close:
            closed = cleanup_source_followup_issues.apply_cleanup(plan, "example/omega", 1)
        self.assertEqual(1, closed)
        close.assert_called_once()


if __name__ == "__main__":
    unittest.main()


