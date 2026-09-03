#!/usr/bin/env python3
"""Admit settled manifest releases without rebuilding frozen scanner Definitions.

This is a canonical catalog writer, not a collector or a client DB publisher.
The workflow must hold the existing catalog/Evidence writer lock throughout
checkout, candidate construction and fast-forward publication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
for directory in (HERE, HERE.parent / "orchestration"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import build_sqlite_catalog
import catalog_json_store
import catalog_state
import reconcile_work
import scan_queue
import source_inventory_guard
import work_result


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def ready(state: Path, work_state: Path, enrichment: Path) -> dict:
    result = {"schema": "omega.catalog-release-intake.v1", "ready": False, "changed": False}
    if not (enrichment / "result.json").is_file() or not (work_state / "index.json").is_file():
        return {**result, "reason": "awaiting-settled-enrichment"}
    reconcile_work.validate_work_state(work_state)
    envelope = work_result.validate_result(enrichment, expected_queue_id="catalog-enrichment")
    queue = read(work_state / "queues/catalog-enrichment.json")
    item = next((item for item in queue["items"] if item["workId"] == envelope["workId"]), None)
    if not item or item["state"] != "completed" or envelope["outcome"] != "complete":
        return {**result, "reason": "awaiting-settled-enrichment"}
    settlement = item.get("settlement") or {}
    if (settlement.get("resultRevision") != envelope["resultRevision"]
            or settlement.get("resultSha256") != work_result.sha256_file(enrichment / "result.json")
            or item.get("requiredRevision") != envelope["requiredRevision"]):
        raise ValueError("enrichment payload is not the exact settled result")
    payload_paths = {entry["path"] for entry in envelope["files"]}
    if not {"raw-sources.json", "enriched-sources.json", "provenance.json"} <= payload_paths:
        raise ValueError("settled enrichment does not bind all required intake files")
    revision = read(state / "catalog/index.json")["catalogRevision"]
    if read(enrichment / "provenance.json").get("baseCatalogRevision") != revision:
        return {**result, "reason": "enrichment-base-is-stale"}
    return {**result, "ready": True, "reason": "settled-enrichment", "baseCatalogRevision": revision,
            "enrichmentResultRevision": envelope["resultRevision"]}


def artifact_identity(item: dict) -> tuple:
    return tuple(item.get(key) for key in ("variantId", "pluginId", "sourceId", "artifactChannel", "assemblyVersion", "artifactUrl"))


def build(*, state: Path, work_state: Path, enrichment: Path, evidence: Path,
          repo: Path, output: Path) -> dict:
    report = ready(state, work_state, enrichment)
    if not report["ready"]:
        return report
    if output.exists():
        raise ValueError("release intake output must be a new directory")
    validation = catalog_state.validate(state)
    if not validation.get("ok"):
        raise ValueError("current catalog state is invalid: " + "; ".join(validation.get("errors") or []))
    before = scan_queue.catalog_variants(state / "catalog")
    old_artifacts = {artifact_identity(item) for item in before}
    known_plugins = {item["pluginId"] for item in before}
    with tempfile.TemporaryDirectory(prefix="omega-release-intake-") as temporary:
        scratch = Path(temporary)
        database = scratch / "seed.sqlite"
        catalog_json_store.materialize_snapshot(state / "catalog", database)
        build_sqlite_catalog.build(argparse.Namespace(
            out=str(scratch / "normalized"), seed=str(database),
            curated=str(repo / "sources/curated-sources.json"),
            community=str(repo / "sources/community-sources.json"),
            raw_sources=str(enrichment / "raw-sources.json"),
            enriched_sources=str(enrichment / "enriched-sources.json"),
            website_enrichment="", download_url="", descriptor_url="",
        ))
        catalog = scratch / "catalog"
        catalog_json_store.export_snapshot(scratch / "normalized/omega-catalog.sqlite", catalog)
        after = scan_queue.catalog_variants(catalog)
        additions = [item for item in after if artifact_identity(item) not in old_artifacts]
        if not additions:
            return {**report, "reason": "no-new-artifact-releases"}
        old_index, new_index = read(state / "catalog/index.json"), read(catalog / "index.json")
        if new_index["identityEpoch"] != old_index["identityEpoch"]:
            raise ValueError("release intake cannot change the catalog identity epoch")
        inventory = source_inventory_guard.validate(
            raw=enrichment / "raw-sources.json", enriched=enrichment / "enriched-sources.json",
            catalog_root=catalog, previous_catalog_root=state / "catalog",
            curated=repo / "sources/curated-sources.json", community=repo / "sources/community-sources.json",
            aliases=repo / "sources/source-url-aliases.json",
        )
        if not inventory.get("ok"):
            raise ValueError("release intake source inventory failed: " + json.dumps(inventory.get("errors")))
        write(scratch / "source-inventory.json", inventory)
        queue_path = scratch / "scan-queue.json"
        seed = scan_queue.build_seed(catalog_root=catalog, definitions_root=state / "definitions",
                                     evidence_root=evidence, output=queue_path)
        # Keep update intent on a new variant even when no prior scan exists yet.
        # The exact target remains immutable; this flag affects ordering only.
        updated_ids = {item["variantId"] for item in additions if item["pluginId"] in known_plugins}
        previous_items = {item["targetFingerprint"]: item for item in read(state / "scan-queue.json").get("items", [])}
        for item in seed["items"]:
            previous = previous_items.get(item["targetFingerprint"], {})
            item["releaseUpdate"] = item.get("workType") == "artifact" and (
                item.get("variantId") in updated_ids or bool(previous.get("releaseUpdate")))
        # Ordering annotations must participate in the seed identity.
        seed["queueSeedRevision"] = "queue-seed-v2-" + scan_queue.digest({
            "seedRevision": seed["queueSeedRevision"],
            "releaseUpdates": sorted(item["queueKey"] for item in seed["items"] if item.get("releaseUpdate")),
        })[:20]
        write(queue_path, seed)
        catalog_state.assemble(catalog=catalog, definitions=state / "definitions", output=output,
                               queue_seed=queue_path, source_inventory=scratch / "source-inventory.json")
    # assemble copies Definitions byte-for-byte; prove that invariant over all files.
    def tree_hashes(root: Path) -> dict:
        return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in root.rglob("*") if path.is_file() and "__pycache__" not in path.parts}
    if tree_hashes(state / "definitions") != tree_hashes(output / "definitions"):
        raise ValueError("release intake changed frozen Definitions")
    validation = catalog_state.validate(output)
    if not validation.get("ok"):
        raise ValueError("candidate catalog state is invalid: " + "; ".join(validation.get("errors") or []))
    return {**report, "changed": True, "reason": "artifact-releases-admitted",
            "catalogRevision": new_index["catalogRevision"], "releaseUpdates": len(updated_ids),
            "newArtifactTargets": len(additions), "definitionsRevision": read(output / "definitions/index.json")["definitionsRevision"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("ready", "build"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--work-state", type=Path, required=True)
    parser.add_argument("--enrichment", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        if args.evidence is None or args.output is None:
            parser.error("build requires --evidence and --output")
        report = build(state=args.state, work_state=args.work_state, enrichment=args.enrichment,
                       evidence=args.evidence, repo=args.repo, output=args.output)
    else:
        report = ready(args.state, args.work_state, args.enrichment)
    write(args.report, report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
