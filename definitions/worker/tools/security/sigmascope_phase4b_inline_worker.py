from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def run(cmd: list[str], *, check: bool = True, stdout=None) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=check, text=True, stdout=stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build one non-authoritative Phase-4B result bundle from an exact persistent queue key.")
    parser.add_argument("--queue-key", required=True)
    parser.add_argument("--worker-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--catalog-root", type=Path, default=Path("catalog/active-state"))
    parser.add_argument("--current-evidence", type=Path, default=Path("catalog/security-v2-current"))
    parser.add_argument("--work-root", type=Path, default=Path("catalog/security-v2-work"))
    args = parser.parse_args()

    definitions_root = args.catalog_root / "definitions"
    defs_path = definitions_root / "index.json"
    catalog_index_path = args.catalog_root / "catalog" / "index.json"
    queue_seed = args.catalog_root / "scan-queue.json"
    frozen_worker = Path(os.environ.get("OMEGA_FROZEN_WORKER", definitions_root / "worker"))
    secondary_cache = Path(os.environ.get("OMEGA_SECONDARY_SECURITY_CACHE", "catalog/secondary-security-runtime"))
    pipeline = frozen_worker / "tools/security/production_sigmascope_v2_pipeline.py"
    definitions_snapshot = frozen_worker / "tools/catalog/definitions_snapshot.py"
    catalog_store = frozen_worker / "tools/catalog/catalog_json_store.py"
    secondary_assets = frozen_worker / "tools/catalog/secondary_security_assets.py"
    source_overrides = frozen_worker / "sources/source-overrides.json"

    for required in (defs_path, catalog_index_path, queue_seed, pipeline, definitions_snapshot, catalog_store, source_overrides):
        if not required.exists():
            raise SystemExit(f"missing required Phase-4B input: {required}")

    defs = json.loads(defs_path.read_text(encoding="utf-8"))
    catalog_index = json.loads(catalog_index_path.read_text(encoding="utf-8"))
    catalog_revision = str(catalog_index.get("catalogRevision") or "")
    if not catalog_revision:
        raise SystemExit("frozen catalog index is missing catalogRevision")
    run([sys.executable, str(definitions_snapshot), "verify-worker", "--definitions-root", str(definitions_root)])
    help_result = subprocess.run([sys.executable, str(pipeline), "--help"], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if "--queue-key" not in help_result.stdout:
        raise SystemExit("frozen Definitions worker predates exact queue-key execution")

    run(["yara", "--version"])
    try:
        run(["clamscan", "--version"], check=False)
    except FileNotFoundError:
        print("clamscan is unavailable in this worker image; continuing like the existing shadow worker", flush=True)
    if secondary_assets.exists():
        run(
            [
                sys.executable,
                str(secondary_assets),
                "materialize-clamav",
                "--definitions-root",
                str(definitions_root),
                "--output",
                str(secondary_cache),
            ],
            check=False,
        )

    database = Path("catalog/security-input/omega-catalog.sqlite")
    database.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            sys.executable,
            str(catalog_store),
            "materialize",
            "--root",
            str(args.catalog_root / "catalog"),
            "--database",
            str(database),
            "--definitions-revision",
            str(defs["definitionsRevision"]),
        ]
    )

    candidate = Path("catalog/security-v2-candidate")
    args.work_root.mkdir(parents=True, exist_ok=True)
    run(
        [
            sys.executable,
            str(pipeline),
            "--base-database",
            str(database),
            "--current-evidence",
            str(args.current_evidence),
            "--candidate-evidence",
            str(candidate),
            "--work-dir",
            str(args.work_root),
            "--skip-marketplace",
            "--frozen-advisories",
            str(definitions_root / "osv-advisories.json"),
            "--frozen-definitions",
            str(definitions_root),
            "--catalog-revision",
            catalog_revision,
            "--definitions-revision",
            str(defs["definitionsRevision"]),
            "--scanner-revision",
            str(defs["scannerRevision"]),
            "--artifact-analysis-revision",
            str(defs["artifactAnalysisRevision"]),
            "--source-analysis-revision",
            str(defs["sourceAnalysisRevision"]),
            "--scanner-bundle-sha256",
            str(defs["scannerBundle"]["sha256"]),
            "--rule-set-revision",
            str(defs["ruleSetRevision"]),
            "--advisory-revision",
            str(defs["advisoryRevision"]),
            "--queue-seed",
            str(queue_seed),
            "--queue-key",
            args.queue_key,
            "--evidence-index-url",
            f"https://raw.githubusercontent.com/{os.environ.get('GITHUB_REPOSITORY', 'dalagab/omega')}/security-evidence-v2/index.json",
            "--max-scans",
            "1",
            "--max-batch-seconds",
            "3000",
            "--source-overrides",
            str(source_overrides),
        ]
    )

    run(
        [
            sys.executable,
            "tools/security/sigmascope_result_bundle.py",
            "build",
            "--current-evidence",
            str(args.current_evidence),
            "--candidate-evidence",
            str(candidate),
            "--work-dir",
            str(args.work_root),
            "--definitions-root",
            str(definitions_root),
            "--queue-key",
            args.queue_key,
            "--worker-image",
            args.worker_image,
            "--output",
            str(args.output),
        ]
    )
    run(
        [
            sys.executable,
            "tools/security/sigmascope_result_bundle.py",
            "validate",
            "--root",
            str(args.output),
            "--current-evidence",
            str(args.current_evidence),
        ]
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
