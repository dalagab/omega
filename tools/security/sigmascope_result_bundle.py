#!/usr/bin/env python3
"""Build and validate immutable, non-authoritative SigmaScope worker result bundles.

Parallel workers never publish Security Evidence v2 directly.  A bundle is a bounded
content-addressed delta from one exact persistent scanner-queue item, bound to the
Evidence-v2 index SHA and frozen Definitions identity the worker started from.  The
serialized merger consumes these bundles in a later phase.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA = "omega.sigmascope-result-bundle.v1"
PLAN_SCHEMA = "omega.sigmascope-result-merge-plan.v1"
MAX_FILES = 20_000
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
_IMAGE_RE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
_ALLOWED_PREFIXES = ("variants/", "artifacts/", "derived/")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _safe_rel(value: str) -> str:
    text = str(value or "").replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe result-bundle path: {value!r}")
    return path.as_posix()


def _item(queue: dict[str, Any], queue_key: str) -> dict[str, Any]:
    row = (queue.get("items") or {}).get(queue_key)
    if not isinstance(row, dict):
        raise ValueError(f"scanner queue item is missing: {queue_key}")
    return dict(row)


_QUEUE_CONTEXT_KEYS = (
    "schema", "queueSeedRevision", "catalogRevision", "catalogIdentityEpoch",
    "baselineSecurityRebuild", "definitionsRevision", "scannerRevision",
    "scannerBundleSha256", "artifactAnalysisRevision", "sourceAnalysisRevision",
    "sourceObservationRevision", "ruleSetRevision", "srlRuleSetRevision",
    "advisoryRevision", "selectionPolicy", "reasonContracts", "srlReprojection",
)


def _queue_context(queue: dict[str, Any]) -> dict[str, Any]:
    return {key: queue.get(key) for key in _QUEUE_CONTEXT_KEYS if key in queue}


def _variant_path(root: Path, variant_id: int) -> Path:
    return root / "variants" / f"{variant_id // 1000:04d}" / f"{variant_id}.json"


def _artifact_sha(payload: dict[str, Any]) -> str:
    return str((payload.get("analysis") or {}).get("artifactSha256") or (payload.get("current") or {}).get("artifact_sha256") or "").strip().lower()


def _referenced_paths(value: Any, root: Path) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        candidate_path = value.get("path")
        if isinstance(candidate_path, str) and candidate_path:
            try:
                rel = _safe_rel(candidate_path)
            except ValueError:
                rel = ""
            if rel and (root / rel).is_file() and rel.startswith(_ALLOWED_PREFIXES):
                result.add(rel)
        for child in value.values():
            result.update(_referenced_paths(child, root))
    elif isinstance(value, list):
        for child in value:
            result.update(_referenced_paths(child, root))
    return result


def _candidate_delta_paths(current: Path, candidate: Path, variant_id: int) -> list[str]:
    variant = _variant_path(candidate, variant_id)
    if not variant.is_file():
        return []
    payload = _read(variant)
    paths = {variant.relative_to(candidate).as_posix()}
    analysis_path = str((payload.get("analysis") or {}).get("path") or "")
    if analysis_path:
        rel_dir = _safe_rel(analysis_path)
        analysis_root = candidate / rel_dir
        if analysis_root.is_dir() and rel_dir.startswith("artifacts/"):
            paths.update(path.relative_to(candidate).as_posix() for path in analysis_root.rglob("*") if path.is_file())
    paths.update(_referenced_paths(payload.get("derivedEvidence") or {}, candidate))
    paths.update(_referenced_paths(payload.get("collectorResults") or {}, candidate))

    changed: list[str] = []
    for rel in sorted(paths):
        if not rel.startswith(_ALLOWED_PREFIXES):
            raise ValueError(f"worker bundle tried to include non-variant/global state: {rel}")
        source = candidate / rel
        if not source.is_file():
            raise ValueError(f"worker bundle referenced a missing file: {rel}")
        old = current / rel
        if old.is_file() and _sha_file(old) == _sha_file(source):
            continue
        changed.append(rel)
    return changed


def _file_entries(root: Path, rels: Iterable[str]) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    total = 0
    for rel in sorted(set(rels)):
        rel = _safe_rel(rel)
        path = root / rel
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ValueError(f"result bundle file exceeds {MAX_FILE_BYTES} bytes: {rel}")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError(f"result bundle exceeds {MAX_TOTAL_BYTES} bytes")
        rows.append({"path": rel, "bytes": size, "sha256": _sha_file(path)})
    if len(rows) > MAX_FILES:
        raise ValueError(f"result bundle exceeds {MAX_FILES} files")
    return rows, total


def _semantic(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key not in {"generatedAtUtc", "bundleRevision"}}


def build(*, current: Path, candidate: Path, work_dir: Path, definitions: Path, queue_key: str,
          worker_image: str, output: Path) -> dict[str, Any]:
    current = current.resolve(); candidate = candidate.resolve(); work_dir = work_dir.resolve(); definitions = definitions.resolve(); output = output.resolve()
    if not _IMAGE_RE.match(worker_image):
        raise ValueError("SigmaScope result bundle requires an immutable worker image @sha256 reference")
    current_index = _read(current / "index.json")
    candidate_index = _read(candidate / "index.json")
    if str(current_index.get("schema") or "") != "omega.security-evidence.v2":
        raise ValueError("current evidence is not Security Evidence v2")
    if str(candidate_index.get("schema") or "") != "omega.security-evidence.v2":
        raise ValueError("candidate evidence is not Security Evidence v2")
    current_queue = _read(current / "scanner-queue.json") if (current / "scanner-queue.json").is_file() else {"items": {}}
    candidate_queue = _read(candidate / "scanner-queue.json")
    after = _item(candidate_queue, queue_key)
    before = dict((current_queue.get("items") or {}).get(queue_key) or {})
    variant_id = int(after.get("variantId") or 0)
    work_type = str(after.get("workType") or "")
    if variant_id <= 0 or work_type not in {"artifact", "source"}:
        raise ValueError("parallel SigmaScope result bundles currently support exact artifact/source variant work only")
    if str(after.get("state") or "") not in {"complete", "retry", "pending"}:
        raise ValueError(f"unexpected candidate queue settlement state: {after.get('state')!r}")
    definitions_index = _read(definitions / "index.json")
    base_revisions = current_index.get("revisions") if isinstance(current_index.get("revisions"), dict) else {}
    candidate_revisions = candidate_index.get("revisions") if isinstance(candidate_index.get("revisions"), dict) else {}
    if str(base_revisions.get("catalogIdentityEpoch") or "") != str(candidate_revisions.get("catalogIdentityEpoch") or ""):
        raise ValueError("parallel bundle cannot cross a catalog identity epoch")
    report = _read(work_dir / "production-sigmascope-v2-report.json")

    # Baseline rebuilds use the same exact-key/result-only contract as steady-state
    # scanning. Phase 4 used to forbid them here because commissioning required a
    # serialized reference scan; that migration-only restriction no longer applies.
    # The real safety boundaries remain the exact Evidence base, identity epoch,
    # frozen Definitions identity and exact requested queue key.
    selected = [row for row in ((report.get("queue") or {}).get("selectedItems") or []) if isinstance(row, dict)]
    if len(selected) != 1 or str(selected[0].get("queueKey") or "") != queue_key:
        raise ValueError("pipeline report is not bound to exactly the requested queue key")

    rels = _candidate_delta_paths(current, candidate, variant_id) if str(after.get("lastAttemptStatus") or "") == "complete" else []
    if output.exists():
        shutil.rmtree(output)
    payload_root = output / "payload"
    payload_root.mkdir(parents=True, exist_ok=True)
    for rel in rels:
        src = candidate / rel
        dst = payload_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    files, total = _file_entries(payload_root, rels)
    current_variant = _variant_path(current, variant_id)
    candidate_variant = _variant_path(candidate, variant_id)
    old_artifact = _artifact_sha(_read(current_variant)) if current_variant.is_file() else ""
    new_artifact = _artifact_sha(_read(candidate_variant)) if candidate_variant.is_file() else old_artifact
    doc: dict[str, Any] = {
        "schema": SCHEMA,
        "generatedAtUtc": str(report.get("generatedAtUtc") or ""),
        "authority": "result-only-no-evidence-publication",
        "base": {
            "indexSha256": _sha_file(current / "index.json"),
            "evidenceRevision": str(base_revisions.get("evidenceRevision") or ""),
            "securityRevision": str(base_revisions.get("securityRevision") or ""),
            "catalogRevision": str(base_revisions.get("catalogRevision") or ""),
            "catalogIdentityEpoch": str(base_revisions.get("catalogIdentityEpoch") or ""),
            "scannerQueueRevision": str(current_queue.get("queueRevision") or ""),
        },
        "frozen": {
            "definitionsRevision": str(definitions_index.get("definitionsRevision") or ""),
            "scannerRevision": str(definitions_index.get("scannerRevision") or ""),
            "scannerBundleSha256": str((definitions_index.get("scannerBundle") or {}).get("sha256") or ""),
            "artifactAnalysisRevision": str(definitions_index.get("artifactAnalysisRevision") or ""),
            "sourceAnalysisRevision": str(definitions_index.get("sourceAnalysisRevision") or ""),
            "ruleSetRevision": str(definitions_index.get("ruleSetRevision") or ""),
            "advisoryRevision": str(definitions_index.get("advisoryRevision") or ""),
            "workerImage": worker_image,
        },
        "work": {
            "queueKey": queue_key,
            "workType": work_type,
            "variantId": variant_id,
            "targetFingerprint": str(after.get("targetFingerprint") or ""),
            "before": before,
            "after": after,
            "queueContextAfter": _queue_context(candidate_queue),
        },
        "outcome": {
            "status": str(after.get("lastAttemptStatus") or ""),
            "successfulVariantIds": list(report.get("successfulVariantIds") or []),
            "failedRetainedVariantIds": list(report.get("failedRetainedVariantIds") or []),
            "archivePreviousVariant": bool(old_artifact and new_artifact and old_artifact != new_artifact),
            "previousArtifactSha256": old_artifact,
            "artifactSha256": new_artifact,
        },
        "payload": {"root": "payload", "files": files, "fileCount": len(files), "totalBytes": total},
    }
    doc["bundleRevision"] = f"sigmascope-result-v1-{_sha_bytes(_canonical(_semantic(doc)))[:20]}"
    (output / "bundle.json").write_text(json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return validate(output, current_evidence=current)


def validate(root: Path, *, current_evidence: Path | None = None) -> dict[str, Any]:
    root = root.resolve()
    doc = _read(root / "bundle.json")
    if doc.get("schema") != SCHEMA:
        raise ValueError("unsupported SigmaScope result-bundle schema")
    if doc.get("authority") != "result-only-no-evidence-publication":
        raise ValueError("SigmaScope result bundle must have no Evidence-v2 publication authority")
    frozen = doc.get("frozen") if isinstance(doc.get("frozen"), dict) else {}
    if not _IMAGE_RE.match(str(frozen.get("workerImage") or "")):
        raise ValueError("SigmaScope result bundle worker image is not digest-pinned")
    expected = f"sigmascope-result-v1-{_sha_bytes(_canonical(_semantic(doc)))[:20]}"
    if str(doc.get("bundleRevision") or "") != expected:
        raise ValueError("SigmaScope result bundle revision mismatch")
    work = doc.get("work") if isinstance(doc.get("work"), dict) else {}
    if int(work.get("variantId") or 0) <= 0 or str(work.get("workType") or "") not in {"artifact", "source"}:
        raise ValueError("SigmaScope result bundle has an unsupported work subject")
    queue_context = work.get("queueContextAfter") if isinstance(work.get("queueContextAfter"), dict) else {}
    if str(queue_context.get("schema") or "") != "omega.sigmascope.queue-state.v2":
        raise ValueError("SigmaScope result bundle is missing its exact scanner-queue context")
    if str(queue_context.get("catalogIdentityEpoch") or "") != str((doc.get("base") or {}).get("catalogIdentityEpoch") or ""):
        raise ValueError("SigmaScope result bundle queue context crosses the Evidence catalog identity epoch")
    files = ((doc.get("payload") or {}).get("files") or []) if isinstance(doc.get("payload"), dict) else []
    if len(files) > MAX_FILES:
        raise ValueError("SigmaScope result bundle has too many files")
    total = 0
    seen: set[str] = set()
    for row in files:
        if not isinstance(row, dict):
            raise ValueError("malformed SigmaScope result-bundle file entry")
        rel = _safe_rel(str(row.get("path") or ""))
        if rel in seen or not rel.startswith(_ALLOWED_PREFIXES):
            raise ValueError(f"invalid/duplicate SigmaScope result-bundle payload path: {rel}")
        seen.add(rel)
        path = root / "payload" / rel
        if not path.is_file():
            raise ValueError(f"SigmaScope result-bundle payload file is missing: {rel}")
        size = path.stat().st_size
        if size != int(row.get("bytes") or -1) or _sha_file(path) != str(row.get("sha256") or ""):
            raise ValueError(f"SigmaScope result-bundle payload integrity mismatch: {rel}")
        total += size
    if total != int((doc.get("payload") or {}).get("totalBytes") or 0):
        raise ValueError("SigmaScope result-bundle total byte count mismatch")
    if len(files) != int((doc.get("payload") or {}).get("fileCount") or 0):
        raise ValueError("SigmaScope result-bundle file count mismatch")
    if current_evidence is not None:
        current = current_evidence.resolve()
        if _sha_file(current / "index.json") != str((doc.get("base") or {}).get("indexSha256") or ""):
            raise ValueError("SigmaScope result bundle is stale: Evidence-v2 base index changed")
    return doc


def build_plan(bundle_roots: list[Path], *, current_evidence: Path, output: Path) -> dict[str, Any]:
    current = current_evidence.resolve()
    current_sha = _sha_file(current / "index.json")
    unique: dict[str, dict[str, Any]] = {}
    roots: dict[str, Path] = {}
    for root in bundle_roots:
        doc = validate(root, current_evidence=current)
        revision = str(doc.get("bundleRevision") or "")
        unique[revision] = doc
        roots[revision] = root.resolve()
    queue_keys: set[str] = set(); variants: set[int] = set(); entries: list[dict[str, Any]] = []
    frozen_identity: bytes | None = None
    queue_context_identity: bytes | None = None
    for revision in sorted(unique):
        doc = unique[revision]
        work = doc["work"]
        frozen_semantic = {key: value for key, value in (doc.get("frozen") or {}).items() if key != "workerImage"}
        this_frozen = _canonical(frozen_semantic)
        this_queue_context = _canonical(work.get("queueContextAfter") or {})
        if frozen_identity is None:
            frozen_identity = this_frozen
            queue_context_identity = this_queue_context
        elif this_frozen != frozen_identity:
            raise ValueError("parallel SigmaScope merge conflict: bundles use different frozen Definitions/scanner identities")
        elif this_queue_context != queue_context_identity:
            raise ValueError("parallel SigmaScope merge conflict: bundles use different scanner-queue seed contexts")
        key = str(work.get("queueKey") or "")
        variant = int(work.get("variantId") or 0)
        if key in queue_keys:
            raise ValueError(f"parallel SigmaScope merge conflict: duplicate queue key {key}")
        if variant in variants:
            raise ValueError(f"parallel SigmaScope merge conflict: multiple bundles mutate variant {variant}")
        queue_keys.add(key); variants.add(variant)
        entries.append({
            "bundleRevision": revision,
            "queueKey": key,
            "workType": str(work.get("workType") or ""),
            "variantId": variant,
            "outcome": str((doc.get("outcome") or {}).get("status") or ""),
            "payloadFileCount": int((doc.get("payload") or {}).get("fileCount") or 0),
            "root": str(roots[revision]),
        })
    first_doc = unique[sorted(unique)[0]] if unique else {}
    semantic = {
        "schema": PLAN_SCHEMA,
        "baseIndexSha256": current_sha,
        "frozen": {key: value for key, value in (first_doc.get("frozen") or {}).items() if key != "workerImage"},
        "queueContext": ((first_doc.get("work") or {}).get("queueContextAfter") or {}),
        "bundles": entries,
    }
    plan = {
        **semantic,
        "authority": "validation-plan-only",
        "mergeReady": bool(entries),
        "bundleCount": len(entries),
        "variantCount": len(variants),
        "planRevision": f"sigmascope-merge-plan-v1-{_sha_bytes(_canonical(semantic))[:20]}",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--current-evidence", required=True, type=Path)
    b.add_argument("--candidate-evidence", required=True, type=Path)
    b.add_argument("--work-dir", required=True, type=Path)
    b.add_argument("--definitions-root", required=True, type=Path)
    b.add_argument("--queue-key", required=True)
    b.add_argument("--worker-image", required=True)
    b.add_argument("--output", required=True, type=Path)
    v = sub.add_parser("validate")
    v.add_argument("--root", required=True, type=Path)
    v.add_argument("--current-evidence", type=Path)
    p = sub.add_parser("plan")
    p.add_argument("--current-evidence", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("bundles", nargs="+", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        result = build(current=args.current_evidence, candidate=args.candidate_evidence, work_dir=args.work_dir,
                       definitions=args.definitions_root, queue_key=args.queue_key, worker_image=args.worker_image, output=args.output)
    elif args.command == "validate":
        result = validate(args.root, current_evidence=args.current_evidence)
    else:
        result = build_plan(args.bundles, current_evidence=args.current_evidence, output=args.output)
    print(json.dumps({
        "schema": result.get("schema"),
        "revision": result.get("bundleRevision") or result.get("planRevision"),
        "queueKey": (result.get("work") or {}).get("queueKey") if isinstance(result.get("work"), dict) else "",
        "bundleCount": result.get("bundleCount", 1 if result.get("bundleRevision") else 0),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
