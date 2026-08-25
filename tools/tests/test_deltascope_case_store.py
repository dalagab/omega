from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import common  # noqa: F401

from deltascope_case_store import LocalInvestigatorCaseStore


class DeltaScopeInvestigatorCaseStoreTests(unittest.TestCase):
    def test_casework_is_local_bounded_and_non_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = LocalInvestigatorCaseStore(Path(td) / "cases")
            created = store.create_case("Suspicious network behavior", summary="Research notes", labels=["network", "triage"])
            self.assertTrue(created["localOnly"])
            self.assertFalse(created["securityAuthority"])
            self.assertFalse(created["policyInput"])
            self.assertFalse(created["productionWriteBack"])
            self.assertFalse(created["queueMutationAuthorized"])
            self.assertEqual("open", created["status"])

            note = store.add_note(created["caseId"], "Compare the endpoint against the prior plugin version.")
            self.assertEqual(1, len(note["case"]["notes"]))

            pinned = store.add_item(
                created["caseId"], kind="finding", label="Network plus execution",
                reference={
                    "variantId": 42, "scanId": 9, "findingId": "network-execute",
                    "ruleId": "compound.network-execute", "evidenceRevision": "evidence-abc",
                    "artifactSha256": "a" * 64,
                    "unexpectedKey": "must be dropped",
                },
            )
            self.assertTrue(pinned["saved"])
            self.assertNotIn("unexpectedKey", pinned["item"]["reference"])
            self.assertFalse(pinned["item"]["securityAuthority"])
            self.assertFalse(pinned["item"]["findingAuthority"])
            self.assertFalse(pinned["item"]["evidenceWriteBack"])
            self.assertEqual("local-user-files-only", pinned["item"]["mutationAuthority"])

            pivot = store.add_item(
                created["caseId"], kind="pivot", label="api.example.test",
                reference={"pivotKind": "endpoint", "pivotKey": "api.example.test", "relationshipRevision": "rel-1"},
            )
            self.assertEqual("pivot", pivot["item"]["kind"])

            snapshot = store.add_item(
                created["caseId"], kind="evidence-snapshot", label="1.2.3 current evidence",
                reference={"variantId": 42, "snapshotKind": "current", "evidenceRevision": "evidence-abc", "definitionsRevision": "defs-1"},
            )
            self.assertEqual("evidence-abc", snapshot["item"]["reference"]["evidenceRevision"])

            listed = store.list_cases()
            self.assertEqual(1, listed["caseCount"])
            self.assertEqual(3, listed["cases"][0]["itemCount"])
            self.assertEqual(1, listed["cases"][0]["noteCount"])

            updated = store.update_case(created["caseId"], status="watching", title="Endpoint investigation")
            self.assertEqual("watching", updated["status"])
            self.assertGreater(updated["revision"], created["revision"])

            removed = store.remove_item(created["caseId"], pivot["item"]["itemId"])
            self.assertEqual(2, len(removed["case"]["items"]))

            path = Path(td) / "cases" / f"{created['caseId']}.json"
            on_disk = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(on_disk["evidenceWriteBack"])
            self.assertFalse(on_disk["definitionsWriteBack"])

    def test_local_file_cannot_self_grant_security_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = LocalInvestigatorCaseStore(Path(td))
            case = store.create_case("Case")
            pinned = store.add_item(case["caseId"], kind="bookmark", label="Plugin", reference={"variantId": 7})
            path = Path(td) / f"{case['caseId']}.json"
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["securityAuthority"] = True
            raw["findingAuthority"] = True
            raw["policyInput"] = True
            raw["items"][0]["securityAuthority"] = True
            raw["items"][0]["queueMutationAuthorized"] = True
            path.write_text(json.dumps(raw), encoding="utf-8")

            loaded = store.get_case(case["caseId"])
            self.assertFalse(loaded["securityAuthority"])
            self.assertFalse(loaded["findingAuthority"])
            self.assertFalse(loaded["policyInput"])
            self.assertFalse(loaded["items"][0]["securityAuthority"])
            self.assertFalse(loaded["items"][0]["queueMutationAuthorized"])
            self.assertEqual(pinned["item"]["itemId"], loaded["items"][0]["itemId"])

    def test_duplicate_pin_is_idempotent_without_distinct_note(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = LocalInvestigatorCaseStore(Path(td))
            case = store.create_case("Case")
            first = store.add_item(case["caseId"], kind="bookmark", label="Plugin", reference={"variantId": 7})
            second = store.add_item(case["caseId"], kind="bookmark", label="Plugin", reference={"variantId": 7})
            self.assertTrue(first["saved"])
            self.assertFalse(second["saved"])
            self.assertTrue(second["duplicate"])
            self.assertEqual(1, len(store.get_case(case["caseId"])["items"]))

    def test_symlinked_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            target = base / "target"
            target.mkdir()
            link = base / "cases"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            store = LocalInvestigatorCaseStore(link)
            with self.assertRaises(ValueError):
                store.create_case("unsafe")


if __name__ == "__main__":
    unittest.main()
