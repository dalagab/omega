from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deep_scan_contract
import deep_scan_queue
import deep_scan_worker
import srl


RULE = """
schema: omega.sigmascope.rule.v1
id: provenance.divergent-artifact-deep-review
kind: correlation
status: reviewed
requires: []
selectors:
  divergence:
    facts:
      any: [artifact.cross-source-hash-mismatch]
condition: divergence
emit:
  findingId: provenance.divergent-artifact-deep-review
  title: Divergent artifact needs deeper comparison
  severity: caution
  category: provenance
analysisRequest:
  profile: artifact-differential-v1
  compareWith: stable-artifact-baseline
  reason: Compare divergent package bytes with the stable publisher baseline.
"""


class DeepScanTests(unittest.TestCase):
    def test_stigma_rule_emits_typed_analysis_request_only_when_matched(self) -> None:
        compiled = srl.compile_yaml_text(RULE)
        request = compiled["rules"][0]["analysisRequest"]
        self.assertEqual(deep_scan_contract.REQUEST_SCHEMA, request["schema"])
        self.assertEqual("artifact-differential-v1", request["profile"])
        self.assertEqual("standard", request["depth"])
        hit = srl.evaluate_ruleset(compiled, {}, initial_facts=["artifact.cross-source-hash-mismatch"])
        miss = srl.evaluate_ruleset(compiled, {}, initial_facts=[])
        self.assertEqual(1, len(hit["analysisRequests"]))
        self.assertEqual("provenance.divergent-artifact-deep-review", hit["analysisRequests"][0]["ruleId"])
        self.assertEqual([], miss["analysisRequests"])

    def test_rule_cannot_define_commands_or_runner_controls(self) -> None:
        bad = RULE.replace("  reason: Compare divergent package bytes with the stable publisher baseline.", "  reason: bad\n  command: powershell.exe")
        with self.assertRaisesRegex(srl.SRLCompileError, "unsupported fields"):
            srl.compile_yaml_text(bad)

    def test_sandbox_profile_is_declared_but_fail_closed_without_isolation(self) -> None:
        status = deep_scan_contract.profile_status("sandbox-differential-v1")
        self.assertFalse(status["available"])
        self.assertIn("isolated", status["blockedReason"])

    @mock.patch("deep_scan_queue._variant_rows")
    def test_queue_resolves_stable_baseline_and_deduplicates_multiple_rules(self, rows) -> None:
        rows.return_value = [
            {"variantId": 1, "internalName": "Fixture", "name": "Fixture", "assemblyVersion": "1.0", "sourceName": "Puni.sh", "sourceUrl": "https://puni.sh/x", "artifactSha256": "a"*64, "artifactUrl": "https://example.test/a.zip"},
            {"variantId": 2, "internalName": "Fixture", "name": "Fixture", "assemblyVersion": "1.0", "sourceName": "Mirror", "sourceUrl": "https://mirror.test/x", "artifactSha256": "b"*64, "artifactUrl": "https://example.test/b.zip"},
        ]
        requests = [
            {"variantId": 2, "profile": "artifact-differential-v1", "compareWith": "stable-artifact-baseline", "reason": "one", "ruleId": "r.one", "ruleRevision": "rev1"},
            {"variantId": 2, "profile": "artifact-differential-v1", "compareWith": "stable-artifact-baseline", "reason": "two", "ruleId": "r.two", "ruleRevision": "rev2"},
        ]
        queue = deep_scan_queue.build_queue(Path("."), requests)
        self.assertEqual(1, len(queue["items"]))
        item = queue["items"][0]
        self.assertEqual("pending", item["state"])
        self.assertEqual(1, item["baselineVariantId"])
        self.assertEqual("a"*64, item["baselineArtifactSha256"])
        self.assertEqual(2, len(item["requestedBy"]))


    @mock.patch("deep_scan_queue._variant_rows")
    def test_same_completed_evidence_is_reused_when_another_rule_later_requests_it(self, rows) -> None:
        rows.return_value = [
            {"variantId": 1, "internalName": "Fixture", "name": "Fixture", "assemblyVersion": "1.0", "sourceName": "Puni.sh", "sourceUrl": "https://puni.sh/x", "artifactSha256": "a"*64, "artifactUrl": "https://example.test/a.zip"},
            {"variantId": 2, "internalName": "Fixture", "name": "Fixture", "assemblyVersion": "1.0", "sourceName": "Mirror", "sourceUrl": "https://mirror.test/x", "artifactSha256": "b"*64, "artifactUrl": "https://example.test/b.zip"},
        ]
        first = deep_scan_queue.build_queue(Path("."), [{"variantId": 2, "profile": "artifact-differential-v1", "compareWith": "stable-artifact-baseline", "reason": "one", "ruleId": "r.one", "ruleRevision": "rev1"}])
        first["items"][0]["state"] = "complete"
        first["items"][0]["result"] = {"path": "results/demo.json"}
        request_id = first["items"][0]["requestId"]
        second = deep_scan_queue.build_queue(Path("."), [
            {"variantId": 2, "profile": "artifact-differential-v1", "compareWith": "stable-artifact-baseline", "reason": "one", "ruleId": "r.one", "ruleRevision": "rev1"},
            {"variantId": 2, "profile": "artifact-differential-v1", "compareWith": "stable-artifact-baseline", "reason": "two", "ruleId": "r.two", "ruleRevision": "rev2"},
        ], previous=first)
        self.assertEqual(request_id, second["items"][0]["requestId"])
        self.assertEqual("complete", second["items"][0]["state"])
        self.assertEqual(2, len(second["items"][0]["requestedBy"]))


    @mock.patch("deep_scan_queue._variant_rows")
    def test_deepest_requested_depth_wins_and_drives_dynamic_budget(self, rows) -> None:
        rows.return_value = [
            {"variantId": 1, "internalName": "Fixture", "name": "Fixture", "assemblyVersion": "1.0", "sourceName": "Puni.sh", "sourceUrl": "https://puni.sh/x", "artifactSha256": "a"*64, "artifactUrl": "https://example.test/a.zip"},
            {"variantId": 2, "internalName": "Fixture", "name": "Fixture", "assemblyVersion": "1.0", "sourceName": "Mirror", "sourceUrl": "https://mirror.test/x", "artifactSha256": "b"*64, "artifactUrl": "https://example.test/b.zip"},
        ]
        queue = deep_scan_queue.build_queue(Path("."), [
            {"variantId": 2, "profile": "artifact-differential-v1", "depth": "extended", "compareWith": "stable-artifact-baseline", "reason": "divergent", "ruleId": "r.divergent", "ruleRevision": "rev1"},
            {"variantId": 2, "profile": "artifact-differential-v1", "depth": "exhaustive", "compareWith": "stable-artifact-baseline", "reason": "divergent plus high-risk capabilities", "ruleId": "r.high", "ruleRevision": "rev2"},
        ])
        self.assertEqual(1, len(queue["items"]))
        item = queue["items"][0]
        self.assertEqual("exhaustive", item["depth"])
        self.assertEqual(65, item["workflowTimeoutMinutes"])
        self.assertIn("expanded-literal-diff", item["analysisFamilies"])
        selected = deep_scan_queue.select_request(queue)
        self.assertEqual(item["requestId"], selected["requestId"])
        self.assertEqual("exhaustive", selected["depth"])

    def test_rule_depth_is_bounded_not_a_raw_timeout(self) -> None:
        compiled = srl.compile_yaml_text(RULE.replace("  profile: artifact-differential-v1", "  profile: artifact-differential-v1\n  depth: extended"))
        self.assertEqual("extended", compiled["rules"][0]["analysisRequest"]["depth"])
        bad = RULE.replace("  reason: Compare divergent package bytes with the stable publisher baseline.", "  reason: bad\n  timeoutMinutes: 999")
        with self.assertRaisesRegex(srl.SRLCompileError, "unsupported fields"):
            srl.compile_yaml_text(bad)

    @mock.patch("deep_scan_queue._variant_rows")
    def test_stable_baseline_request_does_not_fall_back_to_arbitrary_mirror(self, rows) -> None:
        rows.return_value = [
            {"variantId": 1, "internalName": "Fixture", "name": "Fixture", "assemblyVersion": "1.0", "sourceName": "Community A", "sourceUrl": "https://a.test/x", "artifactSha256": "a"*64, "artifactUrl": "https://a.test/a.zip"},
            {"variantId": 2, "internalName": "Fixture", "name": "Fixture", "assemblyVersion": "1.0", "sourceName": "Community B", "sourceUrl": "https://b.test/x", "artifactSha256": "b"*64, "artifactUrl": "https://b.test/b.zip"},
        ]
        queue = deep_scan_queue.build_queue(Path("."), [{"variantId": 2, "profile": "artifact-differential-v1", "compareWith": "stable-artifact-baseline", "reason": "compare", "ruleId": "r.one", "ruleRevision": "rev1"}])
        self.assertEqual("blocked", queue["items"][0]["state"])
        self.assertEqual(0, queue["items"][0]["baselineVariantId"])
        self.assertIn("stable artifact baseline", queue["items"][0]["blockedReason"])

    def test_static_differential_inventory_never_executes_plugin_code(self) -> None:
        import io, zipfile
        def z(files):
            buf=io.BytesIO()
            with zipfile.ZipFile(buf,"w") as arc:
                for name,data in files.items(): arc.writestr(name,data)
            return buf.getvalue()
        base = deep_scan_worker._inventory(z({"Plugin.dll": b"old", "same.txt": b"x"}), 10, 100)
        cand = deep_scan_worker._inventory(z({"Plugin.dll": b"new", "same.txt": b"x", "added.dll": b"z"}), 10, 100)
        diff = deep_scan_worker._compare(cand, base)
        self.assertEqual(1, len(diff["added"]))
        self.assertEqual(1, len(diff["changed"]))
        self.assertEqual(1, diff["sameMemberCount"])

    def test_workflow_uses_frozen_worker_and_never_executes_plugin_binary(self) -> None:
        text = (ROOT / ".github" / "workflows" / "deep-scan.yml").read_text(encoding="utf-8")
        self.assertIn("$OMEGA_FROZEN_WORKER/tools/security/deep_scan_worker.py", text)
        self.assertIn("deep-scan-state", text)
        self.assertIn("Resolve dynamic scan depth and workflow budget", text)
        self.assertIn("fromJSON(needs.select.outputs.timeout_minutes)", text)
        self.assertIn('--request-id "$DEEP_SCAN_REQUEST_ID"', text)
        caller = (ROOT / "docs" / "workflow-callers" / "deep-scan-main.yml").read_text(encoding="utf-8")
        self.assertIn("uses: dalagab/omega/.github/workflows/deep-scan.yml@sigmascope", caller)
        self.assertIn('cron: "37 * * * *"', caller)
        self.assertNotIn("chmod +x", text)
        self.assertNotIn("wine ", text.casefold())
        self.assertNotIn("dotnet exec", text.casefold())


if __name__ == "__main__":
    unittest.main()
