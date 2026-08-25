from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

import common
import test_production_sigmascope_v2_pipeline

SECURITY = common.ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import collector_contracts
import rift_evidence_adapter
import rift_runtime_contract
import rift_evidence_audit
import rift_execution_request
import srl
from migrate_security_evidence_v2 import migrate
from security_evidence_v2 import validate_snapshot


class RiftEvidenceAdapterTests(unittest.TestCase):
    def _fixture_evidence(self, root: Path):
        helper = test_production_sigmascope_v2_pipeline.ProductionSecurityV2PipelineTests()
        database, variant_id, _ = helper.make_catalog_with_security(root)
        evidence = root / "evidence"
        migrate(database, evidence, reset=True)
        variant = next((evidence / "variants").rglob(f"{variant_id}.json"))
        payload = json.loads(variant.read_text(encoding="utf-8"))
        artifact_sha = payload["analysis"]["artifactSha256"]
        return evidence, variant_id, artifact_sha

    def _write_run(self, root: Path, variant_id: int, artifact_sha: str, *, v2=True):
        request = {
            "schema": rift_runtime_contract.REQUEST_SCHEMA,
            "requestId": "rift-fixture-request-001",
            "variantId": variant_id,
            "artifactSha256": artifact_sha,
            "profile": "rift-runtime-v1",
            "authority": "analysis-broker",
        }
        report = {
            "schema_version": rift_runtime_contract.RUNTIME_SCHEMA,
            "producer": "interdimensional-rift",
            "producer_version": "fixture-1",
            "ran_at": "2026-08-24T20:00:00Z",
            "execution": {
                "artifact_tree_sha256": "b" * 64,
                "artifact_tree_hash_algorithm": "sha256(path-nul-file-sha-lf-v1)",
                "entry_sha256": "c" * 64,
                "network": "isolated",
                "seccomp": "enforced",
                "boundary_profile": "rift-linux-bwrap-v3",
                "contract_mode": "real-dalamud-contract-failfast",
                "exercise_profile": "post-init-safe-v1",
                "framework_ticks": 3,
            },
            "plugin": {"path": "/input/Plugin.dll", "load_outcome": "ok"},
            "exercise": {
                "schema_version": "rift.exercise.v1", "profile": "post-init-safe-v1", "status": "completed",
                "framework_ticks_requested": 3, "registrations_discovered": 1,
                "registrations_exercised": 1, "registrations_unexercised": 0,
                "by_kind": {"framework": 1},
                "registrations": [{"id": "r1", "kind": "framework", "component": "IFramework", "operation": "Update", "status": "exercised", "planned_invocations": 1, "invocations": 1}],
            },
            "observations": [
                {"id": "o1", "kind": "service_access", "ts_offset_ms": 12, "phase": "exercise.framework", "component": "IFramework", "operation": "Update", "outcome": "observed"},
                {"id": "o2", "kind": "assembly_load", "ts_offset_ms": 15, "phase": "exercise.framework", "component": "System.Reflection", "operation": "Load", "target": "Example.Dependency", "outcome": "attempted"},
            ],
            "summary": {"total_observations": 2, "by_kind": {"service_access": 1, "assembly_load": 1}},
        }
        request_path = root / "request.json"
        report_path = root / "runtime.json"
        attestation_path = root / "attestation.json"
        request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
        attestation = {
            "schema_version": rift_runtime_contract.ATTESTATION_SCHEMA_V2 if v2 else rift_runtime_contract.ATTESTATION_SCHEMA_V1,
            "producer": "interdimensional-rift-supervisor", "outcome": "runtime_report_emitted",
            "runtime_report_sha256": report_sha, "artifact_tree_sha256": "b" * 64,
            "artifact_tree_hash_algorithm": "sha256(path-nul-file-sha-lf-v1)", "entry_sha256": "c" * 64,
            "exercise_profile": "post-init-safe-v1", "framework_ticks": 3,
            "network": "isolated", "seccomp": "enforced", "boundary_profile": "rift-linux-bwrap-v3",
            "contract_mode": "real-dalamud-contract-failfast", "wall_timeout_seconds": 30,
            "tmpfs": {"tmp_bytes": 1, "home_bytes": 1, "work_bytes": 1},
            "dalamud_contract": {"track": "release", "dalamud_sha256": "d" * 64, "tree_sha256": "e" * 64, "hash_algorithm": "fixture"},
            "cgroup": {"memory_max": "768M", "memory_swap_max": "0", "tasks_max": 64, "cpu_quota": "100%", "memory_oom_kill_delta": 0, "pids_max_delta": 0},
            "process_exit_code": 0,
        }
        if v2:
            attestation["omega_request"] = {"request_id": request["requestId"], "variant_id": variant_id, "artifact_sha256": artifact_sha}
        attestation_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
        return request_path, report_path, attestation_path

    def test_production_ingest_retains_exact_report_and_typed_observations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-rift-adapter-") as td:
            root = Path(td)
            evidence, variant_id, artifact_sha = self._fixture_evidence(root)
            request, report, attestation = self._write_run(root, variant_id, artifact_sha)
            candidate = root / "candidate"
            result = rift_evidence_adapter.ingest(evidence, candidate, request, report, attestation)
            self.assertTrue(result["productionBound"])
            validation = validate_snapshot(candidate)
            self.assertTrue(validation["ok"], validation["errors"])
            variant = next((candidate / "variants").rglob(f"{variant_id}.json"))
            payload = json.loads(variant.read_text(encoding="utf-8"))
            self.assertEqual("omega.security-evidence.rift-ingestion.v1", payload["runtime"]["schema"])
            self.assertIn("riftRuntimeEvidence", payload["derivedEvidence"])
            bundle_file = next((candidate / "derived" / "variants").rglob("collector-observations.json"))
            bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
            self.assertEqual("omega.rift", bundle["componentId"])
            self.assertEqual(2, bundle["collections"]["riftRuntimeEvents"]["records"])
            copied_report = next((candidate / "derived" / "variants").rglob("runtime-report.json"))
            self.assertEqual(report.read_bytes(), copied_report.read_bytes(), "attested runtime report bytes must remain exact")
            audit = rift_evidence_audit.audit(candidate, variant_id)
            self.assertEqual(0, audit["counts"]["fail"], audit["errors"])

            observations = collector_contracts.rows_from_bundle(bundle)
            compiled = srl.compile_yaml_text("""
schema: omega.sigmascope.rule.v1
id: runtime.dynamic-assembly-observed
kind: observation
status: reviewed
requires: [riftRuntimeEvents]
selectors:
  dynamic_load:
    collection: riftRuntimeEvents
    where:
      kind: {equals: assembly_load}
condition: dynamic_load
emit:
  fact: runtime.dynamic-assembly-observed
""")
            evaluated = srl.evaluate_ruleset(compiled, observations, observation_contract=collector_contracts.bundle_contract(bundle))
            self.assertTrue(evaluated["evaluated"], evaluated["replayAudit"])
            self.assertIn("runtime.dynamic-assembly-observed", evaluated["facts"])

    def test_execution_request_is_bound_to_current_evidence_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-rift-request-") as td:
            root = Path(td)
            evidence, variant_id, artifact_sha = self._fixture_evidence(root)
            request = rift_execution_request.create_request(evidence, variant_id, "rift-runtime-v1")
            self.assertEqual(variant_id, request["variantId"])
            self.assertEqual(artifact_sha, request["artifactSha256"])
            self.assertEqual("analysis-broker", request["authority"])


    def test_production_ingest_rejects_unbound_v1_attestation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-rift-adapter-unbound-") as td:
            root = Path(td)
            evidence, variant_id, artifact_sha = self._fixture_evidence(root)
            request, report, attestation = self._write_run(root, variant_id, artifact_sha, v2=False)
            with self.assertRaisesRegex(RuntimeError, "attestation v2 request binding"):
                rift_evidence_adapter.ingest(evidence, root / "candidate", request, report, attestation)

    def test_production_ingest_rejects_wrong_evidence_artifact_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-rift-adapter-mismatch-") as td:
            root = Path(td)
            evidence, variant_id, artifact_sha = self._fixture_evidence(root)
            request, report, attestation = self._write_run(root, variant_id, "f" * 64)
            with self.assertRaisesRegex(RuntimeError, "does not match current Evidence-v2 variant"):
                rift_evidence_adapter.ingest(evidence, root / "candidate", request, report, attestation)


if __name__ == "__main__":
    unittest.main()
