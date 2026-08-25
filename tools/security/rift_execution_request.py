#!/usr/bin/env python3
"""Create a broker request for one exact current Evidence-v2 artifact to be exercised in Rift."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import collector_contracts
import rift_runtime_contract
from security_evidence_v2 import read_json_file


def create_request(evidence: Path, variant_id: int, profile: str) -> dict:
    evidence = evidence.resolve()
    matches = list((evidence / "variants").rglob(f"{variant_id}.json"))
    matches = [p for p in matches if int(json.loads(p.read_text(encoding="utf-8")).get("variantId") or 0) == variant_id]
    if len(matches) != 1:
        raise RuntimeError(f"expected one current variant {variant_id}, found {len(matches)}")
    payload = json.loads(matches[0].read_text(encoding="utf-8"))
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    artifact_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()
    artifact_url = str(current.get("artifact_url") or "")
    if len(artifact_sha) != 64:
        raise RuntimeError("current variant has no exact artifact SHA-256")
    root = read_json_file(evidence, "index.json")
    revisions = root.get("revisions") if isinstance(root.get("revisions"), dict) else {}
    nonce = secrets.token_hex(8)
    request_id = f"rift-v{variant_id}-{artifact_sha[:12]}-{nonce}"
    request = {
        "schema": rift_runtime_contract.REQUEST_SCHEMA,
        "requestId": request_id,
        "variantId": variant_id,
        "artifactSha256": artifact_sha,
        "artifactUrl": artifact_url,
        "profile": profile,
        "authority": "analysis-broker",
        "requestedAtUtc": collector_contracts.utc_now(),
        "evidenceRevision": str(revisions.get("evidenceRevision") or ""),
        "catalogRevision": str(revisions.get("catalogRevision") or ""),
        "definitionsRevision": str(revisions.get("definitionsRevision") or ""),
    }
    errors = rift_runtime_contract.validate_request(request)
    if errors:
        raise RuntimeError("generated invalid Rift request: " + "; ".join(errors))
    return request


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", required=True, type=Path)
    p.add_argument("--variant-id", required=True, type=int)
    p.add_argument("--profile", default="rift-runtime-v1")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    request = create_request(args.evidence, args.variant_id, args.profile)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(request, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"requestId": request["requestId"], "variantId": request["variantId"], "artifactSha256": request["artifactSha256"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
