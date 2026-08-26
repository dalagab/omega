#!/usr/bin/env python3
"""Compute semantic identity for an explicit Omega catalog freeze."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "omega.catalog-freeze.v1"


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def build(*, state_root: Path, evidence_root: Path, work_inputs: Path, repo_root: Path) -> dict[str, Any]:
    catalog = read(state_root / "catalog" / "index.json")
    definitions = read(state_root / "definitions" / "index.json")
    evidence = read(evidence_root / "index.json")
    inputs = read(work_inputs)
    publisher_files = [
        "tools/catalog/catalog_state.py",
        "tools/catalog/compile_marketplace_snapshot.py",
        "tools/catalog/validate_marketplace_catalog.py",
        "tools/catalog/publish_catalog_state.py",
        "tools/orchestration/catalog_freeze_identity.py",
        "tools/orchestration/freeze_inputs.py",
    ]
    publisher_semantic = {rel: sha_file(repo_root / rel) for rel in publisher_files}
    publisher_revision = f"publisher-v1-{sha(publisher_semantic)[:20]}"
    semantic = {
        "schema": SCHEMA,
        "catalogRevision": str(catalog.get("catalogRevision") or ""),
        "definitionsRevision": str(definitions.get("definitionsRevision") or ""),
        "evidenceRevision": str((evidence.get("revisions") or {}).get("evidenceRevision") or ""),
        "publisherRevision": publisher_revision,
    }
    if not all(semantic[key] for key in ("catalogRevision", "definitionsRevision", "evidenceRevision", "publisherRevision")):
        raise ValueError("catalog freeze semantic identity is incomplete")
    freeze_revision = f"catalog-freeze-v1-{sha(semantic)[:20]}"
    return {
        **semantic,
        "freezeRevision": freeze_revision,
        "workStateRevision": str(inputs.get("workStateRevision") or ""),
        "baseCatalogRevision": str(inputs.get("baseCatalogRevision") or ""),
        "laneResults": list(inputs.get("lanes") or []),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--state-root", type=Path, required=True)
    p.add_argument("--evidence-root", type=Path, required=True)
    p.add_argument("--work-inputs", type=Path, required=True)
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--previous", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = build(state_root=args.state_root, evidence_root=args.evidence_root, work_inputs=args.work_inputs, repo_root=args.repo_root)
    previous_revision = ""
    if args.previous and args.previous.is_file():
        try:
            previous_revision = str(read(args.previous).get("freezeRevision") or "")
        except Exception:
            previous_revision = ""
    result["changed"] = result["freezeRevision"] != previous_revision
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
