from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SECURITY = Path(__file__).resolve().parents[1] / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import security_system_state


class SecuritySystemStateTests(unittest.TestCase):
    def test_readiness_keeps_planned_external_and_failed_distinct(self) -> None:
        payload = {
            "variantId": 42,
            "plugin": {"canonical_name": "Broken Example"},
            "current": {"status": "failed", "error": "bounded parser timeout", "scanned_at_utc": "2026-08-29T12:00:00Z"},
        }
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(security_system_state.security_evidence_v2, "iter_variant_entries", return_value=iter([({"variantId": 42}, payload)])), \
             mock.patch.object(security_system_state.security_evidence_v2, "variant_coverage_summary", return_value={"status": "failed"}):
            root = Path(directory)
            descriptor = security_system_state.materialize(root)
            document = json.loads((root / descriptor["path"]).read_text(encoding="utf-8"))
        by_id = {row["id"]: row for row in document["systems"]}

        self.assertTrue(document["policy"]["noFindingDoesNotImplyCovered"])
        self.assertEqual("degraded", by_id["omega.sigmascope"]["state"])
        self.assertEqual(42, by_id["omega.sigmascope"]["recentErrors"][0]["variantId"])
        self.assertEqual("blocked", by_id["omega.rift"]["state"])
        self.assertEqual("planned", by_id["omega.rebuilder"]["state"])
        self.assertEqual(descriptor["stateRevision"], document["stateRevision"])

    def test_all_declared_runtime_states_are_supported(self) -> None:
        self.assertEqual({
            "operational", "degraded", "experimental", "disabled", "blocked",
            "incomplete", "planned", "failed", "stale", "unsupported",
        }, security_system_state.ALLOWED_STATES)


if __name__ == "__main__":
    unittest.main()
