from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_evidence_v2 import validate_snapshot  # noqa: E402


def run(cmd: list[str], *, check: bool = True, stdout=None) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=check, text=True, stdout=stdout)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def rm(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge exact Phase-4B result bundles and prove serialized equivalence without publication authority.")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--bundles-root", type=Path, required=True)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--source-run-attempt", required=True)
    parser.add_argument("--catalog-root", type=Path, default=Path("catalog/active-state"))
    parser.add_argument("--current-evidence", type=Path, default=Path("catalog/security-v2-current"))
    args = parser.parse_args()

    plan = load(args.plan)
    assignments = list(plan.get("assignments") or [])
    expected = int(plan.get("assignmentCount") or 0)
    bundles = sorted({path.parent for path in args.bundles_root.rglob("bundle.json")})
    if expected <= 0:
        raise SystemExit("Phase-4B plan contains no assignments")
    if len(bundles) != expected:
        raise SystemExit(f"expected {expected} shadow result bundles, found {len(bundles)}")

    definitions_root = args.catalog_root / "definitions"
    defs_path = definitions_root / "index.json"
    catalog_index_path = args.catalog_root / "catalog" / "index.json"
    defs = load(defs_path)
    catalog_index = load(catalog_index_path)
    catalog_revision = str(catalog_index.get("catalogRevision") or "")
    if not catalog_revision:
        raise SystemExit("frozen catalog index is missing catalogRevision")
    frozen_worker = Path(os.environ.get("OMEGA_FROZEN_WORKER", definitions_root / "worker"))
    secondary_cache = Path(os.environ.get("OMEGA_SECONDARY_SECURITY_CACHE", "catalog/secondary-security-runtime"))
    pipeline = frozen_worker / "tools/security/production_sigmascope_v2_pipeline.py"
    definitions_snapshot = frozen_worker / "tools/catalog/definitions_snapshot.py"
    secondary_assets = frozen_worker / "tools/catalog/secondary_security_assets.py"
    source_followups = frozen_worker / "tools/catalog/sigmascope_source_followups.py"
    source_overrides = frozen_worker / "sources/source-overrides.json"

    merge_plan = Path("catalog/sigmascope-merge-plan.json")
    run(
        [
            sys.executable,
            "tools/security/sigmascope_result_bundle.py",
            "plan",
            "--current-evidence",
            str(args.current_evidence),
            "--output",
            str(merge_plan),
            *[str(bundle) for bundle in bundles],
        ]
    )

    database = Path("catalog/security-input/omega-catalog.sqlite")
    database.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            sys.executable,
            "tools/catalog/catalog_json_store.py",
            "materialize",
            "--root",
            str(args.catalog_root / "catalog"),
            "--database",
            str(database),
            "--definitions-revision",
            str(defs["definitionsRevision"]),
        ]
    )
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

    previous_deep = Path("catalog/deep-scan-current/index.json")
    merged_candidate = Path("catalog/security-v2-merged-candidate")
    merge_work = Path("catalog/security-v2-merge-work")
    merge_report = Path("catalog/sigmascope-merge-report.json")
    run(
        [
            sys.executable,
            "tools/security/sigmascope_result_merger.py",
            "--current-evidence",
            str(args.current_evidence),
            "--base-database",
            str(database),
            "--definitions-root",
            str(definitions_root),
            "--candidate-evidence",
            str(merged_candidate),
            "--work-dir",
            str(merge_work),
            "--report",
            str(merge_report),
            "--previous-deep-scan-state",
            str(previous_deep),
            "--deep-scan-output",
            str(merge_work / "deep-scan-state"),
            "--source-followup-output",
            str(merge_work / "sigmascope-source-followups.json"),
            *[str(bundle) for bundle in bundles],
        ]
    )

    run([sys.executable, str(definitions_snapshot), "verify-worker", "--definitions-root", str(definitions_root)])
    help_result = subprocess.run([sys.executable, str(pipeline), "--help"], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if "--queue-key" not in help_result.stdout:
        raise SystemExit("frozen Definitions worker predates exact queue-key execution")

    serial_current = Path("catalog/security-v2-serial-current")
    serial_next = Path("catalog/security-v2-serial-next")
    serial_deep = Path("catalog/security-v2-serial-deep")
    rm(serial_current)
    rm(serial_next)
    rm(serial_deep)
    shutil.copytree(args.current_evidence, serial_current)
    last_work: Path | None = None

    for ordinal, assignment in enumerate(assignments, start=1):
        queue_key = str(assignment.get("queueKey") or "")
        if not queue_key:
            raise SystemExit(f"assignment {ordinal} is missing queueKey")
        work = Path(f"catalog/security-v2-serial-work-{ordinal}")
        rm(serial_next)
        rm(work)
        run(
            [
                sys.executable,
                str(pipeline),
                "--base-database",
                str(database),
                "--current-evidence",
                str(serial_current),
                "--candidate-evidence",
                str(serial_next),
                "--work-dir",
                str(work),
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
                str(args.catalog_root / "scan-queue.json"),
                "--queue-key",
                queue_key,
                "--evidence-index-url",
                f"https://raw.githubusercontent.com/{os.environ.get('GITHUB_REPOSITORY', 'dalagab/omega')}/security-evidence-v2/index.json",
                "--max-scans",
                "1",
                "--max-batch-seconds",
                "3000",
                "--source-overrides",
                str(source_overrides),
                "--deep-scan-state",
                str(previous_deep),
                "--deep-scan-output",
                str(serial_deep),
            ]
        )
        rm(serial_current)
        serial_next.rename(serial_current)
        last_work = work

    if last_work is None:
        raise SystemExit("serialized Phase-4B reference performed no work")
    serial_followups = Path("catalog/security-v2-serial-source-followups.json")
    run(
        [
            sys.executable,
            str(source_followups),
            "--database",
            str(last_work / "omega-security-v2-working.sqlite"),
            "--output",
            str(serial_followups),
        ]
    )
    validation = validate_snapshot(serial_current, require_no_orphans=True)
    if not validation.get("ok"):
        raise SystemExit("serialized shadow reference failed intrinsic Evidence-v2 validation: " + "; ".join(validation.get("errors") or []))

    equivalence = Path("catalog/sigmascope-parallel-equivalence.json")
    variant_ids = ",".join(str(item.get("variantId") or "") for item in assignments)
    run(
        [
            sys.executable,
            "tools/security/sigmascope_merge_equivalence.py",
            "--parallel-evidence",
            str(merged_candidate),
            "--serial-evidence",
            str(serial_current),
            "--variant-ids",
            variant_ids,
            "--parallel-deep-scan",
            str(merge_work / "deep-scan-state/index.json"),
            "--serial-deep-scan",
            str(serial_deep / "index.json"),
            "--parallel-source-followups",
            str(merge_work / "sigmascope-source-followups.json"),
            "--serial-source-followups",
            str(serial_followups),
            "--output",
            str(equivalence),
        ]
    )

    developer_audit = Path("catalog/sigmascope-parallel-developer-audit.json")
    with developer_audit.open("w", encoding="utf-8") as handle:
        run(
            [
                sys.executable,
                "tools/security/security_developer_audit.py",
                "--database",
                str(merge_work / "omega-security-parallel-merge.sqlite"),
                "--advisories",
                str(definitions_root / "osv-advisories.json"),
                "--json",
            ],
            stdout=handle,
        )

    storage_audit = Path("catalog/sigmascope-parallel-storage-audit.json")
    run(
        [
            sys.executable,
            "tools/security/evidence_storage_audit.py",
            "--root",
            str(merged_candidate),
            "--report",
            str(storage_audit),
        ]
    )

    base_head = subprocess.check_output(["git", "-C", str(args.current_evidence), "rev-parse", "HEAD"], text=True).strip()
    preflight = Path("catalog/sigmascope-parallel-preflight.json")
    run(
        [
            sys.executable,
            "tools/security/sigmascope_parallel_preflight.py",
            "--merge-report",
            str(merge_report),
            "--equivalence-report",
            str(equivalence),
            "--candidate-validation",
            str(merged_candidate / "validation-report.json"),
            "--developer-audit",
            str(developer_audit),
            "--storage-audit",
            str(storage_audit),
            "--base-evidence-git-head",
            base_head,
            "--source-run-id",
            args.source_run_id,
            "--source-run-attempt",
            args.source_run_attempt,
            "--output",
            str(preflight),
        ]
    )

    merge_data = load(merge_report)
    equivalence_data = load(equivalence)
    preflight_data = load(preflight)
    if merge_data.get("authority") != "candidate-only-no-evidence-publication":
        raise SystemExit("shadow merger unexpectedly gained publication authority")
    if not (merge_data.get("validation") or {}).get("ok"):
        raise SystemExit("merged candidate validation did not pass")
    if equivalence_data.get("equivalent") is not True:
        raise SystemExit("parallel merged candidate is not equivalent to serialized reference")
    if preflight_data.get("authority") != "preflight-only-no-evidence-publication":
        raise SystemExit("Phase-4B preflight unexpectedly gained publication authority")
    if preflight_data.get("publishable") is not True:
        raise SystemExit("Phase-4B preflight did not pass all publication-readiness gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
