#!/usr/bin/env python3
"""Materialize a sparse Security Evidence v2 view for exact SigmaScope queue keys.

The output is intentionally a read-only worker input view: it contains the root
Evidence metadata, scanner queue state, filtered plugin/artifact indexes, and only
variant/artifact files needed by the selected queue keys. Publication still happens
through result bundles and the serialized publisher, never from this sparse view.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Any, Callable, Iterable

SCHEMA = "omega.sigmascope.sparse-evidence-view.v1"


def _remove_readonly(func: Callable[[str], None], path: str, _exc_info: object) -> None:
    os.chmod(path, stat.S_IWRITE)
    func(path)


def read_json_bytes(payload: bytes) -> dict[str, Any]:
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def read_json(path: Path) -> dict[str, Any]:
    return read_json_bytes(path.read_bytes())


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def file_entry(root: Path, path: Path, *, records: int | None = None, encoding: str = "json") -> dict[str, Any]:
    payload = path.read_bytes()
    entry: dict[str, Any] = {
        "path": path.relative_to(root).as_posix(),
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
        "encoding": encoding,
    }
    if records is not None:
        entry["records"] = int(records)
    return entry


def safe_relpath(value: str) -> str:
    rel = Path(str(value or ""))
    if not str(value or "") or rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"unsafe Evidence path: {value!r}")
    return rel.as_posix()


def load_queue_keys(path: Path) -> list[str]:
    keys = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not keys or len(keys) != len(set(keys)):
        raise ValueError("queue key file must contain at least one unique key")
    return keys


def git_show(repo: Path, ref: str, relpath: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), "show", f"{ref}:{safe_relpath(relpath)}"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


def git_tree_paths(repo: Path, ref: str, prefix: str) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", ref, "--", safe_relpath(prefix)],
        check=True,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
    )
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def write_git_file(repo: Path, ref: str, output: Path, relpath: str) -> bool:
    try:
        payload = git_show(repo, ref, relpath)
    except subprocess.CalledProcessError:
        return False
    target = output / safe_relpath(relpath)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return True


def descriptor_files(descriptor: dict[str, Any]) -> Iterable[str]:
    for item in descriptor.get("files") or []:
        if isinstance(item, dict) and item.get("path"):
            yield safe_relpath(str(item["path"]))


def copy_variant_payload_dependencies(repo: Path, ref: str, output: Path, payload: dict[str, Any]) -> set[str]:
    copied: set[str] = set()
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
    analysis_path = str(analysis.get("path") or "")
    if analysis_path:
        manifest = f"{safe_relpath(analysis_path)}/manifest.json"
        if write_git_file(repo, ref, output, manifest):
            copied.add(manifest)
    derived = payload.get("derivedEvidence") if isinstance(payload.get("derivedEvidence"), dict) else {}
    for descriptor in derived.values():
        if not isinstance(descriptor, dict):
            continue
        for relpath in descriptor_files(descriptor):
            if write_git_file(repo, ref, output, relpath):
                copied.add(relpath)
    artifact_sha = str(analysis.get("artifactSha256") or (payload.get("current") or {}).get("artifact_sha256") or "").strip().lower()
    if artifact_sha:
        prefix = f"artifacts/{artifact_sha[:2]}/{artifact_sha}"
        for relpath in git_tree_paths(repo, ref, prefix):
            if write_git_file(repo, ref, output, relpath):
                copied.add(relpath)
    return copied


def git_output(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, encoding="utf-8", stdout=subprocess.PIPE).stdout.strip()


def build_sparse_view(repo: Path, ref: str, queue_keys: list[str], output: Path, queue_seed: Path | None = None) -> dict[str, Any]:
    if output.exists():
        shutil.rmtree(output, onexc=_remove_readonly)
    output.mkdir(parents=True, exist_ok=True)

    source_head = git_output(repo, "rev-parse", ref)
    root_index = read_json_bytes(git_show(repo, ref, "index.json"))
    scanner_queue = read_json_bytes(git_show(repo, ref, "scanner-queue.json"))
    queue_items = dict(scanner_queue.get("items") if isinstance(scanner_queue.get("items"), dict) else {})
    if queue_seed is not None:
        seed = read_json(queue_seed)
        raw_seed_items = seed.get("items")
        if isinstance(raw_seed_items, dict):
            seed_items = raw_seed_items.items()
        elif isinstance(raw_seed_items, list):
            seed_items = ((str(item.get("queueKey") or ""), item) for item in raw_seed_items if isinstance(item, dict))
        else:
            seed_items = ()
        for key, item in seed_items:
            if isinstance(item, dict) and key and key not in queue_items:
                queue_items[str(key)] = item
    selected_items = [queue_items[key] for key in queue_keys if isinstance(queue_items.get(key), dict)]
    selected_variant_ids = {int(item.get("variantId") or 0) for item in selected_items if int(item.get("variantId") or 0) > 0}
    if len(selected_items) != len(queue_keys):
        missing = sorted(set(queue_keys) - {str(item.get("queueKey") or "") for item in selected_items})
        raise ValueError(f"selected queue keys missing from current scanner queue: {missing}")

    indexes = root_index.get("indexes") if isinstance(root_index.get("indexes"), dict) else {}
    plugins_rel = str((indexes.get("plugins") or {}).get("path") or "indexes/plugins.json")
    artifacts_rel = str((indexes.get("artifacts") or {}).get("path") or "indexes/artifacts.json")
    plugins = read_json_bytes(git_show(repo, ref, plugins_rel))
    artifacts = read_json_bytes(git_show(repo, ref, artifacts_rel))

    filtered_plugins: dict[str, Any] = dict(plugins)
    artifact_shas: set[str] = set()
    completed_analysis_count = 0
    for collection in ("currentVariants", "terminalVariants", "historicalSnapshots"):
        rows = [row for row in (plugins.get(collection) or []) if isinstance(row, dict) and int(row.get("variantId") or 0) in selected_variant_ids]
        filtered_plugins[collection] = rows
        for row in rows:
            artifact_sha = str(row.get("artifactSha256") or "").strip().lower()
            if artifact_sha:
                artifact_shas.add(artifact_sha)
            variant_rel = safe_relpath(str(row.get("variantPath") or ""))
            if not write_git_file(repo, ref, output, variant_rel):
                raise FileNotFoundError(variant_rel)
            payload = read_json(output / variant_rel)
            current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
            analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
            if str(current.get("status") or "") == "complete" and analysis.get("analysisId") and analysis.get("path"):
                completed_analysis_count += 1
            copy_variant_payload_dependencies(repo, ref, output, payload)

    filtered_artifacts = dict(artifacts)
    filtered_artifacts["artifacts"] = [
        item for item in (artifacts.get("artifacts") or [])
        if isinstance(item, dict) and str(item.get("artifactSha256") or "").strip().lower() in artifact_shas
    ]

    write_json(output / plugins_rel, filtered_plugins)
    write_json(output / artifacts_rel, filtered_artifacts)
    sparse_queue = dict(scanner_queue)
    merged_items = dict(scanner_queue.get("items") if isinstance(scanner_queue.get("items"), dict) else {})
    for item in selected_items:
        merged_items[str(item.get("queueKey") or "")] = item
    sparse_queue["items"] = merged_items
    write_json(output / "scanner-queue.json", sparse_queue)
    sparse_indexes = {
        "plugins": file_entry(output, output / plugins_rel, records=sum(len(filtered_plugins.get(name) or []) for name in ("currentVariants", "terminalVariants", "historicalSnapshots"))),
        "artifacts": file_entry(output, output / artifacts_rel, records=len(filtered_artifacts.get("artifacts") or [])),
    }
    sparse_index = dict(root_index)
    sparse_index["indexes"] = sparse_indexes
    sparse_index.pop("srlRuleProjections", None)
    sparse_index["scannerQueue"] = file_entry(output, output / "scanner-queue.json", encoding="json")
    sparse_index["sparseEvidenceView"] = {
        "schema": SCHEMA,
        "sourceRef": ref,
        "sourceHead": source_head,
        "queueKeys": queue_keys,
        "variantIds": sorted(selected_variant_ids),
    }
    counts = dict(root_index.get("counts") or {})
    current_count = len(filtered_plugins.get("currentVariants") or [])
    terminal_count = len(filtered_plugins.get("terminalVariants") or [])
    historical_count = len(filtered_plugins.get("historicalSnapshots") or [])
    counts["currentVariants"] = current_count
    counts["terminalVariants"] = terminal_count
    counts["historicalSnapshots"] = historical_count
    counts["analyses"] = completed_analysis_count
    counts["artifactGroups"] = len(filtered_artifacts.get("artifacts") or [])
    sparse_index["counts"] = counts
    write_json(output / "index.json", sparse_index)

    return {
        "schema": SCHEMA,
        "sourceRef": ref,
        "sourceHead": source_head,
        "output": str(output),
        "queueKeys": queue_keys,
        "variantIds": sorted(selected_variant_ids),
        "currentVariants": len(filtered_plugins.get("currentVariants") or []),
        "terminalVariants": len(filtered_plugins.get("terminalVariants") or []),
        "historicalSnapshots": len(filtered_plugins.get("historicalSnapshots") or []),
        "artifactGroups": len(filtered_artifacts.get("artifacts") or []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--ref", default="origin/security-evidence-v2")
    parser.add_argument("--queue-keys-file", type=Path, required=True)
    parser.add_argument("--queue-seed", type=Path, help="Optional queue seed used to resolve newly selected queue keys not yet present in current Evidence")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_sparse_view(args.repo, args.ref, load_queue_keys(args.queue_keys_file), args.output, queue_seed=args.queue_seed)
    write_json(args.output / ".sigmascope-sparse-evidence.json", result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
