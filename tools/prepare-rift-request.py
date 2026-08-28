#!/usr/bin/env python3
"""Build/validate the common Rift execution request used by every ingress model.

Rift intentionally has two ways into the runtime lane:
  * component: a broker-generated request for a current Evidence-v2 variant;
  * location: an operator/workload supplies an HTTPS artifact location plus the
    exact current variant identity and artifact SHA-256.

Both normalize to omega.rift.execution-request.v1 so the runtime and the
Security Evidence v2 adapter have one identity/provenance contract.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import re
import secrets
import urllib.parse

SCHEMA = "omega.rift.execution-request.v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_url(value: str) -> str:
    url = value.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("artifactUrl must be an absolute HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("artifactUrl must not contain embedded credentials")
    return url


def validate_request(request: dict) -> list[str]:
    errors: list[str] = []
    if request.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    request_id = str(request.get("requestId") or "")
    if not REQUEST_ID.fullmatch(request_id):
        errors.append("requestId must be 1..160 safe identifier characters")
    try:
        variant_id = int(request.get("variantId") or 0)
    except (TypeError, ValueError):
        variant_id = 0
    if variant_id <= 0:
        errors.append("variantId must be positive")
    sha = str(request.get("artifactSha256") or "").lower()
    if not HEX64.fullmatch(sha):
        errors.append("artifactSha256 must be a lowercase SHA-256")
    try:
        _validate_url(str(request.get("artifactUrl") or ""))
    except ValueError as exc:
        errors.append(str(exc))
    if not str(request.get("profile") or "").strip():
        errors.append("profile is required")
    if str(request.get("authority") or "") not in {"orchestrator", "analysis-broker"}:
        errors.append("authority must be orchestrator or analysis-broker")
    return errors


def load_and_validate(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("request must be a JSON object")
    errors = validate_request(value)
    if errors:
        raise ValueError("invalid Rift request: " + "; ".join(errors))
    return value


def create_location_request(
    *,
    variant_id: int,
    artifact_url: str,
    artifact_sha256: str,
    profile: str,
    request_id: str = "",
) -> dict:
    if variant_id <= 0:
        raise ValueError("location ingress requires a positive variant_id so the result can use the same Evidence-v2 exit lane")
    sha = artifact_sha256.strip().lower()
    if not HEX64.fullmatch(sha):
        raise ValueError("artifact_sha256 must be a lowercase SHA-256")
    url = _validate_url(artifact_url)
    profile = profile.strip()
    if not profile:
        raise ValueError("profile is required")
    rid = request_id.strip() or f"rift-v{variant_id}-{sha[:12]}-{secrets.token_hex(8)}"
    request = {
        "schema": SCHEMA,
        "requestId": rid,
        "variantId": variant_id,
        "artifactSha256": sha,
        "artifactUrl": url,
        "profile": profile,
        "authority": "orchestrator",
        "requestedAtUtc": _utc_now(),
        "entryModel": "location",
    }
    errors = validate_request(request)
    if errors:
        raise ValueError("generated invalid Rift request: " + "; ".join(errors))
    return request


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize a Rift execution request")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("validate", help="validate/canonicalize an existing broker request")
    check.add_argument("--request", required=True, type=Path)
    check.add_argument("--output", required=True, type=Path)

    location = sub.add_parser("location", help="create a request from an explicit plugin artifact location")
    location.add_argument("--variant-id", required=True, type=int)
    location.add_argument("--artifact-url", required=True)
    location.add_argument("--artifact-sha256", required=True)
    location.add_argument("--profile", default="rift-runtime-v1")
    location.add_argument("--request-id", default="")
    location.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()
    try:
        if args.command == "validate":
            request = load_and_validate(args.request)
        else:
            request = create_location_request(
                variant_id=args.variant_id,
                artifact_url=args.artifact_url,
                artifact_sha256=args.artifact_sha256,
                profile=args.profile,
                request_id=args.request_id,
            )
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(request, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "requestId": request["requestId"],
        "variantId": request["variantId"],
        "artifactSha256": request["artifactSha256"],
        "artifactUrl": request["artifactUrl"],
        "output": str(args.output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
