from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "security" / "sigmascope_evidence_transport.py"
spec = importlib.util.spec_from_file_location("sigmascope_evidence_transport", MODULE_PATH)
transport = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(transport)


class SigmaScopeEvidenceTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="omega-evidence-transport-"))
        self.repo = self.root / "evidence"
        self.repo.mkdir()
        subprocess.run(["git", "init"], cwd=self.repo, check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=self.repo, check=True)
        (self.repo / "large-unchanged.bin").write_bytes(b"A" * (1024 * 1024))
        (self.repo / "index.json").write_text('{"schema":"omega.security-evidence.v2","revision":1}\n', encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "base"], cwd=self.repo, check=True, stdout=subprocess.PIPE)
        self.parent = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        self.candidate = self.root / "candidate"
        shutil.copytree(self.repo, self.candidate, ignore=shutil.ignore_patterns(".git"))
        (self.candidate / "index.json").write_text('{"schema":"omega.security-evidence.v2","revision":2}\n', encoding="utf-8")
        (self.candidate / "new-analysis.json").write_text('{"ok":true}\n', encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_incremental_bundle_reuses_parent_objects_and_round_trips_exact_tree(self) -> None:
        bundle = self.root / "candidate.bundle"
        metadata = self.root / "candidate-transport.json"
        result = transport.create_transport(
            self.repo,
            self.candidate,
            bundle,
            metadata,
            expected_parent_sha=self.parent,
        )
        self.assertEqual(self.parent, result["parentSha"])
        self.assertEqual(2, result["changedPathCount"])
        self.assertLess(result["bundleBytes"], (self.candidate / "large-unchanged.bin").stat().st_size // 4)

        output = self.root / "rehydrated"
        rehydrated = transport.rehydrate_transport(
            self.repo,
            bundle,
            metadata,
            output,
            expected_parent_sha=self.parent,
            expected_index_sha=result["candidateIndexSha256"],
        )
        self.assertEqual(result["candidateCommitSha"], rehydrated["candidateCommitSha"])
        candidate_files = sorted(path.relative_to(self.candidate) for path in self.candidate.rglob("*") if path.is_file())
        output_files = sorted(path.relative_to(output) for path in output.rglob("*") if path.is_file())
        self.assertEqual(candidate_files, output_files)
        for rel in candidate_files:
            self.assertEqual((self.candidate / rel).read_bytes(), (output / rel).read_bytes())

    def test_transport_fails_closed_on_parent_or_bundle_tampering(self) -> None:
        bundle = self.root / "candidate.bundle"
        metadata = self.root / "candidate-transport.json"
        result = transport.create_transport(
            self.repo,
            self.candidate,
            bundle,
            metadata,
            expected_parent_sha=self.parent,
        )
        with self.assertRaises(RuntimeError):
            transport.rehydrate_transport(
                self.repo,
                bundle,
                metadata,
                self.root / "wrong-parent",
                expected_parent_sha="f" * 40,
            )
        with bundle.open("ab") as stream:
            stream.write(b"tampered")
        with self.assertRaises(RuntimeError):
            transport.rehydrate_transport(
                self.repo,
                bundle,
                metadata,
                self.root / "tampered",
                expected_parent_sha=self.parent,
                expected_index_sha=result["candidateIndexSha256"],
            )

    def test_incremental_transport_works_from_a_shallow_evidence_checkout(self) -> None:
        source = self.root / "source-history"
        source.mkdir()
        subprocess.run(["git", "init"], cwd=source, check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=source, check=True)
        (source / "index.json").write_text('{"revision":1}\n', encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=source, check=True)
        subprocess.run(["git", "commit", "-m", "one"], cwd=source, check=True, stdout=subprocess.PIPE)
        (source / "index.json").write_text('{"revision":2}\n', encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "two"], cwd=source, check=True, stdout=subprocess.PIPE)

        shallow = self.root / "shallow"
        subprocess.run(["git", "clone", "--depth", "1", f"file://{source}", str(shallow)], check=True, stdout=subprocess.PIPE)
        self.assertEqual(
            "true",
            subprocess.check_output(["git", "rev-parse", "--is-shallow-repository"], cwd=shallow, text=True).strip(),
        )
        parent = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=shallow, text=True).strip()
        candidate = self.root / "shallow-candidate"
        shutil.copytree(shallow, candidate, ignore=shutil.ignore_patterns(".git"))
        (candidate / "index.json").write_text('{"revision":3}\n', encoding="utf-8")
        bundle = self.root / "shallow.bundle"
        metadata = self.root / "shallow-transport.json"
        transport.create_transport(
            shallow, candidate, bundle, metadata, expected_parent_sha=parent
        )
        output = self.root / "shallow-output"
        transport.rehydrate_transport(
            shallow, bundle, metadata, output, expected_parent_sha=parent
        )
        self.assertEqual((candidate / "index.json").read_bytes(), (output / "index.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
