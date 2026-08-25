#!/usr/bin/env python3
"""Independent publication audit for Rift runtime Evidence-v2 ingestion."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import collector_contracts
import rift_runtime_contract
from security_evidence_v2 import validate_snapshot

SCHEMA = "omega.rift.evidence-ingestion-audit.v1"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not an object")
    return value


def audit(evidence: Path, variant_id: int) -> dict[str, Any]:
    evidence = evidence.resolve()
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    validation = validate_snapshot(evidence)
    checks.append({"id": "evidence-intrinsic", "ok": bool(validation.get("ok")), "detail": "; ".join(validation.get("errors") or [])[:2000]})
    if not validation.get("ok"):
        errors.extend(validation.get("errors") or [])
    matches = [p for p in (evidence / "variants").rglob(f"{variant_id}.json") if int(_load(p).get("variantId") or 0) == variant_id]
    if len(matches) != 1:
        errors.append(f"current variant descriptor count is {len(matches)}")
        payload = {}
    else:
        payload = _load(matches[0])
    runtime = payload.get("runtime") if isinstance(payload.get("runtime"), Mapping) else {}
    run_id = str(runtime.get("runId") or "")
    artifact_sha = str(runtime.get("artifactSha256") or "").lower()
    current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
    current_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").lower()
    checks.append({"id": "variant-artifact-binding", "ok": bool(artifact_sha and artifact_sha == current_sha), "detail": artifact_sha})
    if not artifact_sha or artifact_sha != current_sha:
        errors.append("runtime artifact identity does not match current variant")
    run_dirs = list((evidence / "derived" / "variants").rglob(f"rift/{run_id}")) if run_id else []
    if len(run_dirs) != 1:
        errors.append(f"runtime run directory count is {len(run_dirs)}")
    else:
        run = run_dirs[0]
        request = _load(run / "request.json")
        report_bytes = (run / "runtime-report.json").read_bytes()
        report = json.loads(report_bytes.decode("utf-8"))
        attestation = _load(run / "supervisor-attestation.json")
        component_path = run / "component-security.json"
        component = _load(component_path) if component_path.is_file() else None
        corr_errors = []
        corr_errors.extend(rift_runtime_contract.validate_request(request))
        corr_errors.extend(rift_runtime_contract.validate_runtime_report(report))
        corr_errors.extend(rift_runtime_contract.validate_attestation(attestation, report_bytes, request, production=True))
        corr_errors.extend(rift_runtime_contract.validate_report_attestation_correlation(report, attestation))
        if component:
            corr_errors.extend(rift_runtime_contract.validate_component_security(component))
        checks.append({"id": "trusted-rift-correlation", "ok": not corr_errors, "detail": "; ".join(corr_errors)[:2000]})
        errors.extend(corr_errors)
        bundle = _load(run / "collector-observations.json")
        bundle_ok = str(bundle.get("schema") or "") == collector_contracts.BUNDLE_SCHEMA and str(bundle.get("componentId") or "") == "omega.rift"
        if bundle_ok:
            try:
                rows = collector_contracts.rows_from_bundle(bundle)
                bundle_ok = bool(rows.get("riftRuntimeBoundary")) and bool(rows.get("riftRuntimeExercise"))
            except Exception:
                bundle_ok = False
        checks.append({"id": "collector-bundle", "ok": bundle_ok, "detail": str(bundle.get("registryRevision") or "")})
        if not bundle_ok:
            errors.append("Rift collector observation bundle is invalid")
    return {
        "schema": SCHEMA,
        "variantId": variant_id,
        "counts": {"fail": len(errors), "warn": 0, "pass": sum(1 for item in checks if item["ok"])},
        "checks": checks,
        "errors": errors,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", required=True, type=Path)
    p.add_argument("--variant-id", required=True, type=int)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = audit(args.evidence, args.variant_id)
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if int(result["counts"]["fail"]) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
