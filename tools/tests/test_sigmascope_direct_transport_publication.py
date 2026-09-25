from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
ORCHESTRATION = ROOT / "tools" / "orchestration"
for path in (SECURITY, ORCHESTRATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import publish_security_evidence_v2 as publisher  # noqa: E402
import security_evidence_v2  # noqa: E402
import sigmascope_direct_transport_publish as direct  # noqa: E402
import sigmascope_evidence_transport as transport  # noqa: E402


def run(cmd: list[str], cwd: Path, *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=capture, check=True)


class SigmaScopeDirectTransportPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="omega-direct-evidence-publish-"))
        self.bare = self.root / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(self.bare)], check=True)

        self.workspace = self.root / "workspace"
        self.repo = self.workspace / "catalog" / "security-v2-current"
        self.repo.mkdir(parents=True)
        run(["git", "init", "-q"], self.repo)
        run(["git", "config", "user.name", "Fixture"], self.repo)
        run(["git", "config", "user.email", "fixture@example.invalid"], self.repo)
        run(["git", "remote", "add", "origin", str(self.bare)], self.repo)

        (self.repo / "large-unchanged.bin").write_bytes(b"A" * (1024 * 1024))
        (self.repo / "index.json").write_text(
            json.dumps({
                "schema": security_evidence_v2.SCHEMA,
                "revisions": {"evidenceRevision": "ev-v2-fixture-one"},
            }) + "\n",
            encoding="utf-8",
        )
        run(["git", "add", "."], self.repo)
        run(["git", "commit", "-m", "base"], self.repo)
        run(["git", "branch", "-M", "security-evidence-v2"], self.repo)
        run(["git", "push", "-u", "origin", "security-evidence-v2"], self.repo)
        self.parent = run(["git", "rev-parse", "HEAD"], self.repo, capture=True).stdout.strip()

        self.candidate = self.root / "candidate"
        shutil.copytree(self.repo, self.candidate, ignore=shutil.ignore_patterns(".git"))
        (self.candidate / "index.json").write_text(
            json.dumps({
                "schema": security_evidence_v2.SCHEMA,
                "revisions": {"evidenceRevision": "ev-v2-fixture-two"},
            }) + "\n",
            encoding="utf-8",
        )
        (self.candidate / "variants").mkdir()
        (self.candidate / "variants" / "new.json").write_text('{"ok":true}\n', encoding="utf-8")
        index_sha = hashlib.sha256((self.candidate / "index.json").read_bytes()).hexdigest()
        (self.candidate / "validation-report.json").write_text(
            json.dumps({
                "schema": "omega.security-evidence.snapshot-validation.v2",
                "ok": True,
                "indexSha256": index_sha,
            }) + "\n",
            encoding="utf-8",
        )

        self.publication = self.workspace / "catalog" / "drain-publication"
        self.publication.mkdir(parents=True)
        self.bundle = self.publication / "candidate.bundle"
        self.metadata = self.publication / "candidate-transport.json"
        self.transport_result = transport.create_transport(
            self.repo,
            self.candidate,
            self.bundle,
            self.metadata,
            expected_parent_sha=self.parent,
            expected_index_sha=index_sha,
        )
        self.output = self.publication / "candidate"
        self.audit = self.publication / "developer-audit.json"
        self.audit.write_text(json.dumps({"counts": {"fail": 0, "warn": 0}}) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_verified_transport_materializes_only_publication_control_files(self) -> None:
        result = direct.verify_transport_for_publication(
            self.repo,
            self.bundle,
            self.metadata,
            self.output,
            expected_parent_sha=self.parent,
            expected_index_sha=self.transport_result["candidateIndexSha256"],
        )
        self.assertEqual("verified-transport-only-no-evidence-publication", result["authority"])
        self.assertTrue((self.output / "index.json").is_file())
        self.assertTrue((self.output / "validation-report.json").is_file())
        self.assertTrue((self.output / direct.TRANSPORT_ONLY_MARKER).is_file())
        self.assertFalse((self.output / "large-unchanged.bin").exists())
        self.assertFalse((self.output / "variants" / "new.json").exists())

    def test_publisher_pushes_validated_candidate_tree_without_full_tree_preflight(self) -> None:
        direct.verify_transport_for_publication(
            self.repo,
            self.bundle,
            self.metadata,
            self.output,
            expected_parent_sha=self.parent,
            expected_index_sha=self.transport_result["candidateIndexSha256"],
        )
        result = publisher.publish(
            self.output,
            repo=self.workspace,
            remote="origin",
            branch="security-evidence-v2",
            push=True,
            snapshot_validation_report=self.output / "validation-report.json",
            audit_report=self.audit,
            commit_message="direct fixture publication",
            expected_parent_sha=self.parent,
        )
        self.assertEqual("validated-git-transport", result["publicationMode"])
        self.assertTrue(result["pushed"])
        remote_head = run(
            ["git", "--git-dir", str(self.bare), "rev-parse", "refs/heads/security-evidence-v2"],
            self.root,
            capture=True,
        ).stdout.strip()
        remote_tree = run(
            ["git", "--git-dir", str(self.bare), "show", "-s", "--format=%T", remote_head],
            self.root,
            capture=True,
        ).stdout.strip()
        self.assertEqual(self.transport_result["candidateTreeSha"], remote_tree)
        parents = run(
            ["git", "--git-dir", str(self.bare), "show", "-s", "--format=%P", remote_head],
            self.root,
            capture=True,
        ).stdout.strip()
        self.assertEqual(self.parent, parents)


if __name__ == "__main__":
    unittest.main()
