from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

SECURITY = Path(__file__).resolve().parents[1] / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import evidence_v2_inspector


class DeltaScopeSparseEvidenceAuthorityTests(unittest.TestCase):
    def write_json(self, path: Path, value) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def full_root(self) -> dict:
        return {
            "schema": "omega.security-evidence.v2",
            "formatVersion": 2,
            "generatedAtUtc": "2026-09-07T19:00:00Z",
            "revisions": {"evidenceRevision": "evidence-test-full"},
            "counts": {
                "currentVariants": 0,
                "terminalVariants": 0,
                "historicalSnapshots": 0,
            },
            "indexes": {
                "plugins": {"path": "indexes/plugins.json"},
            },
        }

    def write_full_tree(self, root: Path) -> None:
        self.write_json(root / "index.json", self.full_root())
        self.write_json(
            root / "indexes/plugins.json",
            {
                "currentVariants": [],
                "terminalVariants": [],
                "historicalSnapshots": [],
            },
        )

    def test_full_local_evidence_remains_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_full_tree(root)
            inspector = evidence_v2_inspector.V2SigmascopeInspector(root=root)
            try:
                self.assertEqual("evidence-test-full", inspector.root["revisions"]["evidenceRevision"])
                self.assertEqual({}, inspector.entries)
            finally:
                inspector.close()

    def test_embedded_sparse_view_is_rejected_before_plugin_index_is_needed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sparse_root = self.full_root()
            sparse_root["sparseEvidenceView"] = {
                "schema": "omega.sigmascope.sparse-evidence-view.v1",
                "sourceRef": "origin/security-evidence-v2",
                "queueKeys": ["artifact:7"],
                "variantIds": [7],
            }
            # Intentionally do not create indexes/plugins.json. The authority guard must
            # run before DeltaScope attempts to stage sparse corpus data.
            self.write_json(root / "index.json", sparse_root)
            with self.assertRaises(evidence_v2_inspector.SparseEvidenceAuthorityError) as raised:
                evidence_v2_inspector.V2SigmascopeInspector(root=root)
            message = str(raised.exception)
            self.assertIn("Sparse worker projection — non-authoritative", message)
            self.assertIn("omega.sigmascope.sparse-evidence-view.v1", message)
            self.assertIn("full authoritative Security Evidence v2", message)

    def test_sparse_view_key_presence_fails_closed_even_when_metadata_is_null(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sparse_root = self.full_root()
            sparse_root["sparseEvidenceView"] = None
            self.write_json(root / "index.json", sparse_root)
            with self.assertRaises(evidence_v2_inspector.SparseEvidenceAuthorityError):
                evidence_v2_inspector.V2SigmascopeInspector(root=root)

    def test_local_sparse_marker_rejects_otherwise_full_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_full_tree(root)
            self.write_json(
                root / evidence_v2_inspector.SPARSE_EVIDENCE_MARKER,
                {
                    "schema": "omega.sigmascope.sparse-evidence-view.v1",
                    "sourceHead": "a" * 40,
                },
            )
            with self.assertRaises(evidence_v2_inspector.SparseEvidenceAuthorityError) as raised:
                evidence_v2_inspector.V2SigmascopeInspector(root=root)
            self.assertIn(evidence_v2_inspector.SPARSE_EVIDENCE_MARKER, str(raised.exception))

    def test_local_marker_presence_is_authority_signal_even_if_marker_is_malformed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_full_tree(root)
            (root / evidence_v2_inspector.SPARSE_EVIDENCE_MARKER).write_bytes(b"not-json")
            with self.assertRaises(evidence_v2_inspector.SparseEvidenceAuthorityError):
                evidence_v2_inspector.V2SigmascopeInspector(root=root)

    def test_sparse_refresh_candidate_cannot_replace_last_known_good_full_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_full_tree(root)
            inspector = evidence_v2_inspector.V2SigmascopeInspector(root=root)
            try:
                before_root = inspector.root
                before_revision = inspector.root["revisions"]["evidenceRevision"]
                sparse_root = self.full_root()
                sparse_root["revisions"] = {"evidenceRevision": "sparse-candidate"}
                sparse_root["sparseEvidenceView"] = {
                    "schema": evidence_v2_inspector.SPARSE_EVIDENCE_SCHEMA,
                    "variantIds": [99],
                }
                with self.assertRaises(evidence_v2_inspector.SparseEvidenceAuthorityError):
                    inspector._load_snapshot(root=sparse_root)
                self.assertIs(before_root, inspector.root)
                self.assertEqual(before_revision, inspector.root["revisions"]["evidenceRevision"])
            finally:
                inspector.close()

    def test_marker_appearing_after_load_blocks_local_refresh_without_replacing_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_full_tree(root)
            inspector = evidence_v2_inspector.V2SigmascopeInspector(root=root)
            try:
                before_revision = inspector.root["revisions"]["evidenceRevision"]
                (root / evidence_v2_inspector.SPARSE_EVIDENCE_MARKER).write_text(
                    "{}\n", encoding="utf-8"
                )
                with self.assertRaises(evidence_v2_inspector.SparseEvidenceAuthorityError):
                    inspector._load_snapshot(root=dict(inspector.root))
                self.assertEqual(before_revision, inspector.root["revisions"]["evidenceRevision"])
            finally:
                inspector.close()


if __name__ == "__main__":
    unittest.main()
