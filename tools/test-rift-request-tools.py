#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PREPARE = ROOT / "tools/prepare-rift-request.py"
STAGE = ROOT / "tools/stage-rift-request.py"
RESULT = ROOT / "tools/build-rift-result.py"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *args], check=check, capture_output=True, text=True)


with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    package = td / "plugin.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("ExamplePlugin.json", json.dumps({"InternalName": "ExamplePlugin", "AssemblyVersion": "1.2.3"}))
        z.writestr("ExamplePlugin.dll", b"managed-fixture")
        z.writestr("Dependency.dll", b"dependency-fixture")
    package_sha = hashlib.sha256(package.read_bytes()).hexdigest()

    request = td / "rift-request.json"
    run(
        str(PREPARE), "location",
        "--variant-id", "42",
        "--artifact-url", "https://example.invalid/releases/ExamplePlugin.zip",
        "--artifact-sha256", package_sha,
        "--request-id", "rift-test-42",
        "--output", str(request),
    )
    payload = json.loads(request.read_text())
    assert payload["schema"] == "omega.rift.execution-request.v1"
    assert payload["variantId"] == 42
    assert payload["artifactSha256"] == package_sha
    assert payload["entryModel"] == "location"

    canonical = td / "canonical.json"
    run(str(PREPARE), "validate", "--request", str(request), "--output", str(canonical))
    assert json.loads(canonical.read_text())["requestId"] == "rift-test-42"

    bad = run(
        str(PREPARE), "location",
        "--variant-id", "0",
        "--artifact-url", "https://example.invalid/plugin.zip",
        "--artifact-sha256", package_sha,
        "--output", str(td / "bad.json"),
        check=False,
    )
    assert bad.returncode != 0
    assert "positive variant_id" in (bad.stdout + bad.stderr)

    artifact = td / "artifact"
    staging = td / "staging.json"
    run(
        str(STAGE), "--request", str(request), "--download", str(package),
        "--artifact-dir", str(artifact), "--output", str(staging),
    )
    staged = json.loads(staging.read_text())
    assert staged["pluginEntryRelative"] == "ExamplePlugin.dll"
    assert staged["artifactSha256"] == package_sha

    # A direct DLL location is also a valid explicit plugin location without
    # forcing callers to repeat the entry filename.
    direct_dll = td / "download.bin"
    direct_dll.write_bytes(b"direct-dll-fixture")
    direct_sha = hashlib.sha256(direct_dll.read_bytes()).hexdigest()
    direct_request = td / "direct-request.json"
    run(
        str(PREPARE), "location", "--variant-id", "43",
        "--artifact-url", "https://example.invalid/releases/DirectPlugin.dll",
        "--artifact-sha256", direct_sha, "--request-id", "rift-test-43",
        "--output", str(direct_request),
    )
    direct_staging = td / "direct-staging.json"
    run(
        str(STAGE), "--request", str(direct_request), "--download", str(direct_dll),
        "--artifact-dir", str(td / "direct-artifact"), "--output", str(direct_staging),
    )
    assert json.loads(direct_staging.read_text())["pluginEntryRelative"] == "DirectPlugin.dll"

    results = td / "results"
    results.mkdir()
    (results / "runtime-report.json").write_text('{"schema_version":"rift.runtime-observation.v2"}\n')
    (results / "supervisor-attestation.json").write_text('{"schema_version":"rift.supervisor-attestation.v2"}\n')
    result = results / "rift-result.json"
    run(
        str(RESULT), "--request", str(request), "--results-dir", str(results),
        "--entry-model", "location", "--run-id", "12345", "--run-attempt", "2",
        "--exit-code", "0", "--output", str(result),
    )
    exit_payload = json.loads(result.read_text())
    assert exit_payload["schema"] == "omega.rift.scan-result.v1"
    assert exit_payload["runtimeReported"] is True
    assert exit_payload["outcome"] == "completed"
    assert exit_payload["resultArtifact"] == "rift-runtime-results"

print("Rift request/result tools self-test: PASS")
