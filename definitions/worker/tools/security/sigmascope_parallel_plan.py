#!/usr/bin/env python3
"""Build a read-only parallel SigmaScope shadow execution plan from frozen queue state."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_TOOLS = REPO_ROOT / "tools" / "catalog"
if str(CATALOG_TOOLS) not in sys.path:
    sys.path.insert(0, str(CATALOG_TOOLS))
import scan_queue  # noqa: E402

SCHEMA = "omega.sigmascope-parallel-plan.v1"
MAX_ASSIGNMENTS = 8


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(path: Path) -> str:
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


def build(seed_path: Path, evidence_root: Path, *, max_assignments: int, output: Path,
          now: dt.datetime | None = None) -> dict[str, Any]:
    seed = _read(seed_path)
    if seed.get("schema") != scan_queue.SEED_SCHEMA:
        raise ValueError("unsupported frozen SigmaScope queue seed")
    evidence_root = evidence_root.resolve()
    index = _read(evidence_root / "index.json")
    previous = scan_queue.load_state(evidence_root / "scanner-queue.json")
    if bool(seed.get("baselineSecurityRebuild")):
        assignments: list[dict[str, Any]] = []
        blocked = "baseline-security-rebuild-requires-serialized-worker"
    else:
        state = scan_queue.sync_state(seed, previous)
        assignments = []
        blocked = ""
        for _ in range(max(0, min(int(max_assignments), MAX_ASSIGNMENTS))):
            item = scan_queue.select_next(state, now=now)
            if item is None:
                break
            work_type = str(item.get("workType") or "")
            variant_id = int(item.get("variantId") or 0)
            if work_type == "advisory" or variant_id <= 0:
                blocked = "global-advisory-projection-requires-serialized-worker"
                break
            if work_type not in {"artifact", "source"}:
                blocked = f"unsupported-parallel-work-type:{work_type}"
                break
            assignments.append({
                "queueKey": str(item.get("queueKey") or ""),
                "workType": work_type,
                "variantId": variant_id,
                "targetFingerprint": str(item.get("targetFingerprint") or ""),
                "priority": int(item.get("priority") or 0),
                "primaryReason": str(item.get("primaryReason") or ""),
            })
            # select_next intentionally treats an uncommitted attempted item as
            # crash-recoverable on the next call.  A shadow plan is one local atomic
            # selection pass, so mark the chosen key complete locally to ensure the
            # remaining assignments are disjoint.  This state is never published.
            state["items"][str(item.get("queueKey") or "")]["state"] = "complete"
    revisions = index.get("revisions") if isinstance(index.get("revisions"), dict) else {}
    semantic = {
        "schema": SCHEMA,
        "authority": "shadow-result-planning-only",
        "baseIndexSha256": _sha(evidence_root / "index.json"),
        "evidenceRevision": str(revisions.get("evidenceRevision") or ""),
        "catalogIdentityEpoch": str(revisions.get("catalogIdentityEpoch") or ""),
        "queueSeedRevision": str(seed.get("queueSeedRevision") or ""),
        "assignments": assignments,
        "blockedReason": blocked,
    }
    digest = hashlib.sha256(_canonical(semantic)).hexdigest()
    document = {
        **semantic,
        "assignmentCount": len(assignments),
        "parallelPlanRevision": f"sigmascope-parallel-plan-v1-{digest[:20]}",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return document


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--queue-seed", required=True, type=Path)
    ap.add_argument("--evidence-root", required=True, type=Path)
    ap.add_argument("--max-assignments", type=int, default=4)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    result = build(args.queue_seed, args.evidence_root, max_assignments=args.max_assignments, output=args.output)
    print(json.dumps({"assignmentCount": result["assignmentCount"], "blockedReason": result["blockedReason"], "parallelPlanRevision": result["parallelPlanRevision"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
