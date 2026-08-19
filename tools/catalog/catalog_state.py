#!/usr/bin/env python3
"""Assemble/validate the public Omega catalog-data branch snapshot.

The branch carries two immutable inputs for a scanner day:
  catalog/      canonical marketplace JSON
  definitions/  frozen scanner definitions and advisory data
  scan-queue.json immutable queue seed for the daily scanner cycle

The dedicated branch is a bounded atomic current snapshot, mirroring the publication
style of Security Evidence v2. Semantic revision IDs name the frozen inputs without
requiring an ever-growing Git history; index.json names the active pair.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import catalog_json_store  # noqa: E402

SCHEMA = "omega.catalog-state.v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assemble(*, catalog: Path, definitions: Path, output: Path, queue_seed: Path | None = None) -> dict[str, Any]:
    catalog = catalog.resolve()
    definitions = definitions.resolve()
    output = output.resolve()
    catalog_validation = catalog_json_store.validate_snapshot(catalog)
    if not catalog_validation.get("ok"):
        raise RuntimeError("catalog snapshot invalid: " + "; ".join(catalog_validation.get("errors") or []))
    catalog_index = json.loads((catalog / "index.json").read_text(encoding="utf-8"))
    definitions_index = json.loads((definitions / "index.json").read_text(encoding="utf-8"))
    if definitions_index.get("schema") != "omega.definitions.v1":
        raise RuntimeError("definitions snapshot has an unsupported schema")
    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(catalog, output / "catalog")
    shutil.copytree(definitions, output / "definitions")
    queue_seed_doc: dict[str, Any] = {}
    queue_seed_sha = ""
    if queue_seed is not None:
        queue_seed = queue_seed.resolve()
        queue_seed_doc = json.loads(queue_seed.read_text(encoding="utf-8"))
        if queue_seed_doc.get("schema") != "omega.sigmascope.queue-seed.v1":
            raise RuntimeError("scan queue seed has an unsupported schema")
        shutil.copy2(queue_seed, output / "scan-queue.json")
        queue_seed_sha = sha256_file(output / "scan-queue.json")
    catalog_sha = sha256_file(output / "catalog" / "index.json")
    definitions_sha = sha256_file(output / "definitions" / "index.json")
    pair = f"{catalog_index.get('catalogRevision','')}\n{definitions_index.get('definitionsRevision','')}\n{queue_seed_doc.get('queueSeedRevision','')}\n"
    state_revision = f"state-v1-{hashlib.sha256(pair.encode('utf-8')).hexdigest()[:16]}"
    root = {
        "schema": SCHEMA,
        "generatedAtUtc": utc_now(),
        "stateRevision": state_revision,
        "catalog": {
            "revision": str(catalog_index.get("catalogRevision") or ""),
            "path": "catalog/index.json",
            "sha256": catalog_sha,
            "counts": catalog_index.get("counts") or {},
        },
        "definitions": {
            "revision": str(definitions_index.get("definitionsRevision") or ""),
            "ruleSetRevision": str(definitions_index.get("ruleSetRevision") or ""),
            "sourceCommit": str(definitions_index.get("sourceCommit") or ""),
            "path": "definitions/index.json",
            "sha256": definitions_sha,
        },
    }
    if queue_seed_doc:
        root["scanQueue"] = {
            "revision": str(queue_seed_doc.get("queueSeedRevision") or ""),
            "path": "scan-queue.json",
            "sha256": queue_seed_sha,
            "queued": int((queue_seed_doc.get("counts") or {}).get("queued") or 0),
            "ruleSetRevision": str(queue_seed_doc.get("ruleSetRevision") or ""),
            "definitionsSourceCommit": str(queue_seed_doc.get("definitionsSourceCommit") or ""),
        }
    (output / "index.json").write_text(json.dumps(root, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return root


def validate(root: Path) -> dict[str, Any]:
    root = root.resolve()
    errors: list[str] = []
    try:
        index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    except Exception as exc:
        return {"schema": "omega.catalog-state.validation.v1", "ok": False, "errors": [str(exc)]}
    if index.get("schema") != SCHEMA:
        errors.append(f"unsupported schema: {index.get('schema')!r}")
    for key in ("catalog", "definitions", "scanQueue"):
        if key == "scanQueue" and key not in index:
            continue
        item = index.get(key) or {}
        path = root / str(item.get("path") or "")
        if not path.is_file():
            errors.append(f"{key} index missing")
        elif sha256_file(path) != str(item.get("sha256") or ""):
            errors.append(f"{key} index SHA-256 mismatch")
    cat = catalog_json_store.validate_snapshot(root / "catalog")
    if not cat.get("ok"):
        errors.extend(f"catalog: {item}" for item in cat.get("errors") or [])
    try:
        defs = json.loads((root / "definitions" / "index.json").read_text(encoding="utf-8"))
        if str(defs.get("definitionsRevision") or "") != str((index.get("definitions") or {}).get("revision") or ""):
            errors.append("definitions revision mismatch")
        if str(cat.get("catalogRevision") or "") != str((index.get("catalog") or {}).get("revision") or ""):
            errors.append("catalog revision mismatch")
        # Validate every independently published Definitions payload by the hashes carried in
        # definitions/index.json. This checks the public branch bytes without requiring the
        # validator checkout itself to be the frozen source commit.
        queue_meta = index.get("scanQueue") or {}
        if queue_meta:
            queue = json.loads((root / "scan-queue.json").read_text(encoding="utf-8"))
            if queue.get("schema") != "omega.sigmascope.queue-seed.v1":
                errors.append("scan queue seed schema mismatch")
            if str(queue.get("catalogRevision") or "") != str((index.get("catalog") or {}).get("revision") or ""):
                errors.append("scan queue catalog revision mismatch")
            if str(queue.get("definitionsRevision") or "") != str((index.get("definitions") or {}).get("revision") or ""):
                errors.append("scan queue Definitions revision mismatch")
            if str(queue.get("ruleSetRevision") or "") != str((index.get("definitions") or {}).get("ruleSetRevision") or ""):
                errors.append("scan queue rule-set revision mismatch")
            if str(queue.get("definitionsSourceCommit") or "") != str((index.get("definitions") or {}).get("sourceCommit") or ""):
                errors.append("scan queue Definitions source commit mismatch")
            if str(queue.get("queueSeedRevision") or "") != str(queue_meta.get("revision") or ""):
                errors.append("scan queue seed revision mismatch")
        for key in ("osv", "reputation"):
            payload = defs.get(key) or {}
            relative = str(payload.get("path") or "")
            expected = str(payload.get("sha256") or "")
            if not relative or not expected:
                errors.append(f"definitions {key} descriptor is incomplete")
                continue
            path = (root / "definitions" / relative).resolve()
            definitions_root = (root / "definitions").resolve()
            if definitions_root not in path.parents and path != definitions_root:
                errors.append(f"definitions {key} path escapes snapshot root")
                continue
            if not path.is_file():
                errors.append(f"definitions {key} payload missing")
            elif sha256_file(path) != expected:
                errors.append(f"definitions {key} payload SHA-256 mismatch")
    except Exception as exc:
        errors.append(f"definitions index unreadable: {type(exc).__name__}: {exc}")
    return {"schema": "omega.catalog-state.validation.v1", "ok": not errors, "stateRevision": str(index.get("stateRevision") or ""), "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("assemble")
    build.add_argument("--catalog", type=Path, required=True)
    build.add_argument("--definitions", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--queue-seed", type=Path)
    check = sub.add_parser("validate")
    check.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    result = assemble(catalog=args.catalog, definitions=args.definitions, output=args.output, queue_seed=args.queue_seed) if args.command == "assemble" else validate(args.root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
