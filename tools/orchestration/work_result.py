#!/usr/bin/env python3
"""Lease-bound immutable result envelopes for Omega orchestration workers.

The envelope is orchestration state, not security evidence.  It binds the payload files a
worker published to the exact durable work item/lease that authorized the execution.  The
reconciler validates the envelope and settles the queue; workers never mutate queue state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

RESULT_SCHEMA = "omega.work-result.v1"
MAX_FILES = 64
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
OUTCOMES = {"complete", "retry", "blocked", "terminal"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _text(value: Any, name: str, maximum: int = 512, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{name} is required")
    if len(text) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return text


def _safe_rel(value: Any) -> str:
    text = _text(value, "file.path", 1024).replace("\\", "/")
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or text.startswith("/"):
        raise ValueError(f"unsafe result file path: {text}")
    return path.as_posix()


def _lease_from_item(item: Mapping[str, Any]) -> dict[str, str]:
    if str(item.get("state") or "") != "leased" or not isinstance(item.get("lease"), Mapping):
        raise ValueError("work result requires a leased work item")
    lease = item["lease"]
    return {
        "owner": _text(lease.get("owner"), "lease.owner", 256),
        "claimToken": _text(lease.get("claimToken"), "lease.claimToken", 128),
        "claimedAtUtc": _text(lease.get("claimedAtUtc"), "lease.claimedAtUtc", 64),
        "expiresAtUtc": _text(lease.get("expiresAtUtc"), "lease.expiresAtUtc", 64),
    }


def build_result(*, queue_id: str, item: Mapping[str, Any], root: Path, files: list[str],
                 outcome: str = "complete", reason: str = "", retry_after_seconds: int = 0,
                 payload_revision: str = "", worker_image: str = "") -> dict[str, Any]:
    queue_id = _text(queue_id, "queueId", 128)
    outcome = _text(outcome, "outcome", 32)
    if outcome not in OUTCOMES:
        raise ValueError(f"unsupported result outcome: {outcome}")
    lease = _lease_from_item(item)
    descriptors: list[dict[str, Any]] = []
    total = 0
    seen: set[str] = set()
    for raw in files:
        rel = _safe_rel(raw)
        if rel in seen:
            raise ValueError(f"duplicate result file: {rel}")
        seen.add(rel)
        path = root / rel
        if not path.is_file():
            raise ValueError(f"result payload file is missing: {rel}")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ValueError(f"result payload file exceeds {MAX_FILE_BYTES} bytes: {rel}")
        total += size
        descriptors.append({"path": rel, "bytes": size, "sha256": sha256_file(path)})
    if len(descriptors) > MAX_FILES:
        raise ValueError(f"result has more than {MAX_FILES} payload files")
    if total > MAX_TOTAL_BYTES:
        raise ValueError(f"result payload exceeds {MAX_TOTAL_BYTES} bytes")
    descriptors.sort(key=lambda row: row["path"].casefold())
    if outcome == "complete" and not descriptors:
        raise ValueError("complete result requires at least one payload file")
    if retry_after_seconds < 0 or retry_after_seconds > 604_800:
        raise ValueError("retryAfterSeconds out of range")
    worker_image = _text(worker_image, "workerImage", 1024, required=False)
    if worker_image and "@sha256:" not in worker_image:
        raise ValueError("workerImage must be an immutable digest reference")
    semantic = {
        "schema": RESULT_SCHEMA,
        "queueId": queue_id,
        "workId": _text(item.get("workId"), "workId", 128),
        "component": _text(item.get("component"), "component", 256),
        "kind": _text(item.get("kind"), "kind", 128),
        "requiredRevision": _text(item.get("requiredRevision"), "requiredRevision", 256),
        "lease": lease,
        "outcome": outcome,
        "reason": _text(reason, "reason", 2048, required=False),
        "retryAfterSeconds": int(retry_after_seconds),
        "payloadRevision": _text(payload_revision, "payloadRevision", 256, required=False),
        "execution": {"workerImage": worker_image} if worker_image else {},
        "files": descriptors,
    }
    return {**semantic, "resultRevision": f"work-result-v1-{_sha(semantic)[:24]}"}


def validate_result(root: Path, *, expected_queue_id: str = "", expected_work_id: str = "",
                    expected_owner: str = "", expected_claim_token: str = "") -> dict[str, Any]:
    path = root / "result.json"
    if not path.is_file():
        raise ValueError("work result.json is missing")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or str(value.get("schema") or "") != RESULT_SCHEMA:
        raise ValueError(f"work result schema must be {RESULT_SCHEMA}")
    files = value.get("files") if isinstance(value.get("files"), list) else []
    item = {
        "state": "leased",
        "workId": value.get("workId"),
        "component": value.get("component"),
        "kind": value.get("kind"),
        "requiredRevision": value.get("requiredRevision"),
        "lease": value.get("lease"),
    }
    rebuilt = build_result(
        queue_id=str(value.get("queueId") or ""), item=item, root=root,
        files=[str(row.get("path") or "") for row in files if isinstance(row, Mapping)],
        outcome=str(value.get("outcome") or ""), reason=str(value.get("reason") or ""),
        retry_after_seconds=int(value.get("retryAfterSeconds") or 0),
        payload_revision=str(value.get("payloadRevision") or ""),
        worker_image=str((value.get("execution") or {}).get("workerImage") or "") if isinstance(value.get("execution"), Mapping) else "",
    )
    if rebuilt != dict(value):
        raise ValueError("work result does not reproduce from its payload")
    if expected_queue_id and rebuilt["queueId"] != expected_queue_id:
        raise ValueError("work result queueId mismatch")
    if expected_work_id and rebuilt["workId"] != expected_work_id:
        raise ValueError("work result workId mismatch")
    if expected_owner and rebuilt["lease"]["owner"] != expected_owner:
        raise ValueError("work result lease owner mismatch")
    if expected_claim_token and rebuilt["lease"]["claimToken"] != expected_claim_token:
        raise ValueError("work result claim token mismatch")
    return rebuilt


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    build = sub.add_parser("build")
    build.add_argument("--queue-id", required=True)
    build.add_argument("--work-item", type=Path, required=True)
    build.add_argument("--root", type=Path, required=True)
    build.add_argument("--file", action="append", default=[])
    build.add_argument("--outcome", choices=sorted(OUTCOMES), default="complete")
    build.add_argument("--reason", default="")
    build.add_argument("--retry-after-seconds", type=int, default=0)
    build.add_argument("--payload-revision", default="")
    build.add_argument("--worker-image", default="")
    validate = sub.add_parser("validate")
    validate.add_argument("--root", type=Path, required=True)
    validate.add_argument("--queue-id", default="")
    validate.add_argument("--work-id", default="")
    validate.add_argument("--owner", default="")
    validate.add_argument("--claim-token", default="")
    args = parser.parse_args()
    if args.cmd == "build":
        item = json.loads(args.work_item.read_text(encoding="utf-8"))
        result = build_result(
            queue_id=args.queue_id, item=item, root=args.root, files=args.file,
            outcome=args.outcome, reason=args.reason, retry_after_seconds=args.retry_after_seconds,
            payload_revision=args.payload_revision, worker_image=args.worker_image,
        )
        (args.root / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    result = validate_result(
        args.root, expected_queue_id=args.queue_id, expected_work_id=args.work_id,
        expected_owner=args.owner, expected_claim_token=args.claim_token,
    )
    print(json.dumps({"ok": True, "resultRevision": result["resultRevision"], "outcome": result["outcome"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
