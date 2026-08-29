from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import deltascope_triage_store as triage


class DeltaScopeTriageStoreTests(unittest.TestCase):
    def test_case_and_finding_triage_are_local_only(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = triage.LocalFindingsTriageStore(Path(temporary_directory))
            case = store.update_case(incident_id="incident-0123456789abcdef0123", variant_id=10, scan_id=20, state="investigating", owner="Researcher")
            finding = store.update_finding(incident_id="incident-0123456789abcdef0123", variant_id=10, scan_id=20, finding_id="game.hooking", rule_id="primitive.game.hooking", state="triaging", owner="Researcher")
            snapshot = store.snapshot()
        self.assertTrue(case["localOnly"])
        self.assertFalse(case["securityAuthority"])
        self.assertEqual("local-user-files-only", case["mutationAuthority"])
        self.assertEqual("investigating", snapshot["cases"][0]["state"])
        self.assertEqual("triaging", snapshot["findings"][0]["state"])
        self.assertEqual("Researcher", finding["finding"]["owner"])

    def test_terminal_states_require_a_reason(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = triage.LocalFindingsTriageStore(Path(temporary_directory))
            with self.assertRaisesRegex(ValueError, "requires a reason"):
                store.update_case(incident_id="incident-0123456789abcdef0123", variant_id=10, scan_id=20, state="dismissed")
            with self.assertRaisesRegex(ValueError, "requires a reason"):
                store.update_finding(incident_id="incident-0123456789abcdef0123", variant_id=10, scan_id=20, finding_id="x", rule_id="x", state="escalated")

    def test_bulk_triage_updates_known_derived_identities(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = triage.LocalFindingsTriageStore(Path(temporary_directory))
            result = store.bulk_update_cases([
                {"incidentId": "incident-0123456789abcdef0123", "variantId": 10, "scanId": 20},
                {"incidentId": "incident-abcdef0123456789abcd", "variantId": 11, "scanId": 21},
            ], state="triaging", owner="Me")
            snapshot = store.snapshot()
        self.assertEqual(2, result["updated"])
        self.assertEqual(2, snapshot["caseCount"])
        self.assertEqual({"triaging"}, {row["state"] for row in snapshot["cases"]})


if __name__ == "__main__":
    unittest.main()
