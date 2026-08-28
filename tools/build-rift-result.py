#!/usr/bin/env python3
"""Build the single machine-readable exit envelope for a Rift workflow run."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--request", required=True, type=Path)
    p.add_argument("--results-dir", required=True, type=Path)
    p.add_argument("--entry-model", required=True, choices=("component", "location"))
    p.add_argument("--run-id", required=True)
    p.add_argument("--run-attempt", required=True)
    p.add_argument("--exit-code", required=True, type=int)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()

    request = json.loads(args.request.read_text(encoding="utf-8"))
    results = args.results_dir
    expected = {
        "runtime-report": results / "runtime-report.json",
        "supervisor-attestation": results / "supervisor-attestation.json",
        "component-security": results / "component-security.json",
        "outer-observer": results / "outer-observer.json",
        "collector-runtime": results / "collector-runtime.json",
    }
    files = {
        key: {"path": path.name, "sha256": sha(path), "bytes": path.stat().st_size}
        for key, path in expected.items() if path.is_file()
    }
    runtime_reported = "runtime-report" in files and "supervisor-attestation" in files
    outcome = "completed" if args.exit_code == 0 and runtime_reported else ("no-runtime-report" if not runtime_reported else "runtime-failed")
    payload = {
        "schema": "omega.rift.scan-result.v1",
        "requestId": str(request.get("requestId") or ""),
        "variantId": int(request.get("variantId") or 0),
        "artifactSha256": str(request.get("artifactSha256") or ""),
        "artifactUrl": str(request.get("artifactUrl") or ""),
        "profile": str(request.get("profile") or ""),
        "authority": str(request.get("authority") or ""),
        "entryModel": args.entry_model,
        "outcome": outcome,
        "runtimeReported": runtime_reported,
        "processExitCode": args.exit_code,
        "resultArtifact": "rift-runtime-results",
        "github": {"runId": str(args.run_id), "runAttempt": str(args.run_attempt)},
        "files": files,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
