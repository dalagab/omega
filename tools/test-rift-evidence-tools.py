#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
summarizer = root / "tools/summarize-rift-coverage.py"
validator = root / "tools/validate-rift-attestation.py"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        check=check,
        capture_output=True,
        text=True,
    )


with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)

    # Boundary/exercise metadata must not become plugin behavioral coverage.
    report_path = td / "runtime.json"
    coverage_path = td / "coverage.json"
    runtime = {
        "schema_version": "rift.runtime-observation.v2",
        "plugin": {"internal_name": "EvidenceFixture", "load_outcome": "ok"},
        "exercise": {"schema_version": "rift.exercise.v1", "status": "completed"},
        "observations": [
            {
                "kind": "exercise",
                "phase": "exercise.inventory",
                "component": "rift.exercise",
                "operation": "inventory",
                "outcome": "ok",
                "parameters": {"network_boundary": "isolated"},
            },
            {
                "kind": "boundary",
                "phase": "bootstrap",
                "component": "sandbox",
                "operation": "network",
                "outcome": "isolated",
            },
        ],
    }
    report_path.write_text(json.dumps(runtime), encoding="utf-8")
    run(str(summarizer), str(report_path), "--out", str(coverage_path))
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    assert "network" not in coverage["coverage_categories_touched"]

    # A concrete behavior-bearing networking observation still counts.
    runtime["observations"].append(
        {
            "kind": "service_access",
            "phase": "exercise.command",
            "component": "System.Net.Http.HttpClient",
            "operation": "SendAsync",
            "outcome": "attempted",
        }
    )
    report_path.write_text(json.dumps(runtime), encoding="utf-8")
    run(str(summarizer), str(report_path), "--out", str(coverage_path))
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    assert "network" in coverage["coverage_categories_touched"]

    # Supervisor attestation must bind the exact managed report bytes and all
    # provenance fields the hostile in-process observer also reports.
    execution = {
        "artifact_tree_sha256": "1" * 64,
        "artifact_tree_hash_algorithm": "sha256(path-nul-file-sha-lf-v1)",
        "entry_sha256": "2" * 64,
        "exercise_profile": "post-init-safe-v1",
        "framework_ticks": "3",
        "network": "isolated",
        "seccomp": "enforced",
        "boundary_profile": "bubblewrap-cgroup-v2",
        "contract_mode": "real-dalamud-contract-failfast",
        "wall_timeout_seconds": "20",
        "memory_max": "768M",
        "memory_swap_max": "0",
        "tasks_max": "64",
        "cpu_quota": "100%",
        "tmpfs_tmp_bytes": "134217728",
        "tmpfs_home_bytes": "16777216",
        "tmpfs_work_bytes": "67108864",
        "dalamud_contract_track": "release",
        "dalamud_contract_sha256": "3" * 64,
        "dalamud_contract_tree_sha256": "4" * 64,
        "dalamud_contract_hash_algorithm": "sha256-canonical-tree-v1",
    }
    attested_runtime = {
        "schema_version": "rift.runtime-observation.v2",
        "execution": execution,
        "exercise": {"schema_version": "rift.exercise.v1"},
        "observations": [],
    }
    report_bytes = (json.dumps(attested_runtime, sort_keys=True) + "\n").encode("utf-8")
    report_path.write_bytes(report_bytes)
    attestation_path = td / "runtime.supervisor-attestation.json"
    attestation = {
        "schema_version": "rift.supervisor-attestation.v1",
        "producer": "interdimensional-rift-supervisor",
        "outcome": "runtime_report_emitted",
        "runtime_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "artifact_tree_sha256": execution["artifact_tree_sha256"],
        "artifact_tree_hash_algorithm": execution["artifact_tree_hash_algorithm"],
        "entry_sha256": execution["entry_sha256"],
        "exercise_profile": execution["exercise_profile"],
        "framework_ticks": 3,
        "network": execution["network"],
        "seccomp": execution["seccomp"],
        "boundary_profile": execution["boundary_profile"],
        "contract_mode": execution["contract_mode"],
        "wall_timeout_seconds": 20,
        "tmpfs": {"tmp_bytes": 134217728, "home_bytes": 16777216, "work_bytes": 67108864},
        "dalamud_contract": {
            "track": execution["dalamud_contract_track"],
            "dalamud_sha256": execution["dalamud_contract_sha256"],
            "tree_sha256": execution["dalamud_contract_tree_sha256"],
            "hash_algorithm": execution["dalamud_contract_hash_algorithm"],
        },
        "cgroup": {
            "memory_max": "768M",
            "memory_swap_max": "0",
            "tasks_max": 64,
            "cpu_quota": "100%",
            "memory_oom_kill_delta": 0,
            "pids_max_delta": 0,
        },
        "process_exit_code": 0,
    }
    attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
    run(str(validator), str(report_path), str(attestation_path))

    # Production ingestion requires v2 to bind the exact broker/orchestrator request.
    request_path = td / "rift-request.json"
    request = {
        "schema": "omega.rift.execution-request.v1",
        "requestId": "rift-v42-test",
        "variantId": 42,
        "artifactSha256": "5" * 64,
        "artifactUrl": "https://example.invalid/plugin.zip",
        "profile": "rift-runtime-v1",
        "authority": "analysis-broker",
    }
    request_path.write_text(json.dumps(request), encoding="utf-8")
    v2_attestation = dict(attestation)
    v2_attestation["schema_version"] = "rift.supervisor-attestation.v2"
    v2_attestation["omega_request"] = {
        "request_id": request["requestId"],
        "variant_id": request["variantId"],
        "artifact_sha256": request["artifactSha256"],
    }
    attestation_path.write_text(json.dumps(v2_attestation), encoding="utf-8")
    run(str(validator), str(report_path), str(attestation_path), "--request", str(request_path))

    wrong_request = dict(request)
    wrong_request["artifactSha256"] = "6" * 64
    request_path.write_text(json.dumps(wrong_request), encoding="utf-8")
    failed = run(str(validator), str(report_path), str(attestation_path), "--request", str(request_path), check=False)
    assert failed.returncode != 0
    assert "request binding mismatch" in (failed.stdout + failed.stderr)
    request_path.write_text(json.dumps(request), encoding="utf-8")

    # Same provenance, different report bytes: must fail exact-byte binding.
    report_path.write_bytes(report_bytes + b" \n")
    failed = run(str(validator), str(report_path), str(attestation_path), check=False)
    assert failed.returncode != 0
    assert "runtime report hash does not match" in (failed.stdout + failed.stderr)

    # Restore bytes but falsify one trusted provenance field: must also fail.
    report_path.write_bytes(report_bytes)
    bad_attestation = dict(attestation)
    bad_attestation["exercise_profile"] = "none"
    attestation_path.write_text(json.dumps(bad_attestation), encoding="utf-8")
    failed = run(str(validator), str(report_path), str(attestation_path), check=False)
    assert failed.returncode != 0
    assert "attestation mismatch for exercise_profile" in (failed.stdout + failed.stderr)

print("Rift evidence tool self-test: PASS")
