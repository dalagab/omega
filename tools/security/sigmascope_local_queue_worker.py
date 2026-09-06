#!/usr/bin/env python3
"""Run a bounded SigmaScope queue batch from a local operator machine.

The local worker intentionally follows the serialized production authority model:
it reads frozen catalog/Definitions and current Security Evidence, builds and audits
a candidate locally, then publishes only through the existing fast-forward publisher
with the exact Evidence parent SHA observed before the scan.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import stat
import sys
import time
from typing import Any, Callable


def phase(message: str) -> None:
    print(f"==> {message}", flush=True)


def run(args: list[str], *, cwd: Path, check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=cwd, check=check, text=True, encoding="utf-8", errors="replace", env=env)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def output(args: list[str], *, cwd: Path) -> str:
    completed = subprocess.run(args, cwd=cwd, check=True, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE)
    return completed.stdout.strip()


def _remove_readonly(func: Callable[[str], None], path: str, _exc_info: object) -> None:
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _windows_delete_path(path: Path) -> Path:
    if os.name != "nt":
        return path
    resolved = str(path.resolve())
    if resolved.startswith("\\\\?\\"):
        return Path(resolved)
    return Path("\\\\?\\" + resolved)


def robust_rmtree(path: Path) -> None:
    delete_path = _windows_delete_path(path)
    for attempt in range(5):
        try:
            shutil.rmtree(delete_path, onexc=_remove_readonly)
            return
        except OSError:
            if attempt == 4:
                raise
            time.sleep(0.5)


def ensure_empty(path: Path, *, reset: bool) -> None:
    if path.exists():
        if not reset:
            raise FileExistsError(f"{path} already exists; pass --reset-work-dir to replace it")
        robust_rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def export_branch(repo: Path, branch: str, destination: Path) -> str:
    run(["git", "-c", "core.longpaths=true", "-c", "core.autocrlf=false", "fetch", "--quiet", "--depth=1", "origin", f"refs/heads/{branch}"], cwd=repo)
    sha = output(["git", "rev-parse", "FETCH_HEAD"], cwd=repo)
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "-c", "core.longpaths=true", "-c", "core.autocrlf=false", "worktree", "add", "--quiet", "--detach", str(destination), sha], cwd=repo)
    return sha


def remove_worktree(repo: Path, path: Path) -> None:
    if (path / ".git").exists():
        run(["git", "-c", "core.longpaths=true", "-c", "core.autocrlf=false", "worktree", "remove", "--force", str(path)], cwd=repo, check=False)
    shutil.rmtree(path, ignore_errors=True, onexc=_remove_readonly)


def reset_work_dir(repo: Path, work: Path) -> None:
    for relative in (
        Path("catalog") / "active-state",
        Path("catalog") / "security-v2-current",
        Path("catalog") / "deep-scan-current",
    ):
        remove_worktree(repo, work / relative)
    if work.exists():
        robust_rmtree(work)
    work.mkdir(parents=True, exist_ok=True)

def frozen_revision(definitions: Path, key: str) -> str:
    return str(read_json(definitions / "index.json").get(key) or "")


def fetch_branch_ref(repo: Path, branch: str) -> str:
    run(["git", "-c", "core.longpaths=true", "-c", "core.autocrlf=false", "fetch", "--quiet", "--depth=1", "origin", f"refs/heads/{branch}"], cwd=repo)
    return output(["git", "rev-parse", "FETCH_HEAD"], cwd=repo)


def scanner_bundle_sha(definitions: Path) -> str:
    bundle = read_json(definitions / "index.json").get("scannerBundle")
    if not isinstance(bundle, dict):
        raise ValueError("definitions index has no scannerBundle object")
    return str(bundle.get("sha256") or "")


def write_queue_keys_for_sparse_view(repo: Path, catalog: Path, evidence_head: str, work: Path, max_scans: int) -> Path:
    metadata = work / "catalog" / "security-v2-metadata"
    if metadata.exists():
        robust_rmtree(metadata)
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata / "index.json").write_bytes(subprocess.run(["git", "-C", str(repo), "show", f"{evidence_head}:index.json"], check=True, stdout=subprocess.PIPE).stdout)
    (metadata / "scanner-queue.json").write_bytes(subprocess.run(["git", "-C", str(repo), "show", f"{evidence_head}:scanner-queue.json"], check=True, stdout=subprocess.PIPE).stdout)
    plan = work / "catalog" / "local-sparse-plan.json"
    run([
        sys.executable, str(repo / "tools" / "security" / "sigmascope_parallel_drain_plan.py"),
        "--queue-seed", str(catalog / "scan-queue.json"),
        "--evidence-root", str(metadata),
        "--workers", "1",
        "--items-per-worker", str(max(1, min(max_scans, 16))),
        "--wave", "1",
        "--output", str(plan),
    ], cwd=repo)
    document = read_json(plan)
    matrix = document.get("matrix") if isinstance(document.get("matrix"), dict) else {}
    slots = matrix.get("include") if isinstance(matrix.get("include"), list) else []
    keys = list(slots[0].get("queueKeys") or []) if slots and isinstance(slots[0], dict) else []
    if not keys:
        raise RuntimeError("no eligible sparse SigmaScope queue keys selected")
    queue_keys = work / "catalog" / "local-sparse-queue-keys.txt"
    queue_keys.write_text("".join(f"{key}\n" for key in keys), encoding="utf-8")
    return queue_keys


def overlay_windows_exporter_compatibility(repo: Path, frozen_worker: Path) -> bool:
    if os.name != "nt":
        return False
    overlays = (
        (repo / "tools" / "security" / "security_evidence_v2.py", frozen_worker / "tools" / "security" / "security_evidence_v2.py"),
        (repo / "tools" / "orchestration" / "git_snapshot_history.py", frozen_worker / "tools" / "orchestration" / "git_snapshot_history.py"),
    )
    applied = False
    for source, target in overlays:
        if not source.is_file() or not target.is_file():
            continue
        shutil.copy2(source, target)
        applied = True
    return applied


def materialize_sparse_evidence(repo: Path, evidence_head: str, queue_keys: Path, output_root: Path, queue_seed: Path) -> None:
    run([
        sys.executable, str(repo / "tools" / "security" / "sigmascope_sparse_evidence.py"),
        "--repo", str(repo),
        "--ref", evidence_head,
        "--queue-keys-file", str(queue_keys),
        "--queue-seed", str(queue_seed),
        "--output", str(output_root),
    ], cwd=repo)


def build_env(work: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["OMEGA_FROZEN_WORKER"] = str(work / "catalog" / "active-state" / "definitions" / "worker")
    env["OMEGA_SECONDARY_SECURITY_CACHE"] = str(work / "catalog" / "secondary-security-runtime")
    return env


def default_work_dir() -> Path:
    if os.name == "nt":
        return Path("C:/osl")
    return Path("omega-local-sigmascope-worker")


def validate_windows_work_dir(work: Path, *, force: bool) -> None:
    if os.name != "nt" or force:
        return
    resolved = str(work.resolve())
    if len(resolved) <= 12:
        return
    raise RuntimeError(
        "Windows SigmaScope Evidence paths exceed MAX_PATH from this work root. "
        f"Use a short root such as C:\\osl or pass --allow-long-windows-work-dir to override: {resolved}"
    )


def maybe_run_source_followups(args: argparse.Namespace, work: Path, env: dict[str, str]) -> None:
    if not args.reconcile_source_followups:
        return
    if not args.repository:
        raise ValueError("--repository is required with --reconcile-source-followups")
    script = work / "catalog" / "active-state" / "definitions" / "worker" / "tools" / "catalog" / "create_source_followup_issues.py"
    result = run([
        sys.executable,
        str(script),
        "--input", str(work / "catalog" / "security-v2-work" / "sigmascope-source-followups.json"),
        "--repository", args.repository,
        "--max-new", str(args.max_new_followups),
        "--max-close", str(args.max_close_followups),
    ], cwd=work, check=False, env=env)
    if result.returncode != 0:
        print("warning: source follow-up issue reconciliation failed; Evidence publication is unaffected", file=sys.stderr)


def local_drain(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    work = args.work_dir.resolve()
    validate_windows_work_dir(work, force=args.allow_long_windows_work_dir)
    if args.reset_work_dir:
        reset_work_dir(repo, work)
    else:
        ensure_empty(work, reset=False)

    catalog = work / "catalog" / "active-state"
    current = work / "catalog" / "security-v2-current"
    deep = work / "catalog" / "deep-scan-current"
    try:
        phase("fetch catalog-data")
        catalog_head = export_branch(repo, "catalog-data", catalog)
        if args.sparse_evidence:
            phase("fetch security-evidence-v2 metadata")
            evidence_head = fetch_branch_ref(repo, "security-evidence-v2")
            phase("select sparse queue keys")
            sparse_queue_keys = write_queue_keys_for_sparse_view(repo, catalog, evidence_head, work, args.max_scans)
            phase("materialize sparse security-evidence-v2")
            materialize_sparse_evidence(repo, evidence_head, sparse_queue_keys, current, catalog / "scan-queue.json")
        else:
            phase("fetch security-evidence-v2")
            evidence_head = export_branch(repo, "security-evidence-v2", current)
        try:
            phase("fetch deep-scan-state")
            export_branch(repo, "deep-scan-state", deep)
        except subprocess.CalledProcessError:
            deep.mkdir(parents=True, exist_ok=True)

        env = build_env(work)
        frozen_worker = Path(env["OMEGA_FROZEN_WORKER"])
        definitions = catalog / "definitions"
        phase("verify frozen worker")
        run([sys.executable, str(frozen_worker / "tools" / "catalog" / "definitions_snapshot.py"), "verify-worker", "--definitions-root", str(definitions)], cwd=work, env=env)
        windows_overlay_applied = overlay_windows_exporter_compatibility(repo, frozen_worker)
        if windows_overlay_applied:
            phase("overlay Windows exporter compatibility")
        phase("materialize secondary assets")
        run([sys.executable, str(frozen_worker / "tools" / "catalog" / "secondary_security_assets.py"), "materialize-clamav", "--definitions-root", str(definitions), "--output", env["OMEGA_SECONDARY_SECURITY_CACHE"]], cwd=work, check=False, env=env)
        phase("materialize catalog database")
        run([
            sys.executable,
            str(frozen_worker / "tools" / "catalog" / "catalog_json_store.py"),
            "materialize",
            "--root", str(catalog / "catalog"),
            "--database", str(work / "catalog" / "security-input" / "omega-catalog.sqlite"),
            "--definitions-revision", frozen_revision(definitions, "definitionsRevision"),
        ], cwd=work, env=env)

        report = {
            "schema": "omega.sigmascope-local-queue-worker.v1",
            "catalogHead": catalog_head,
            "baseEvidenceHead": evidence_head,
            "candidate": str(work / "catalog" / "security-v2-candidate"),
            "workDir": str(work / "catalog" / "security-v2-work"),
            "publishRequested": bool(args.push),
            "preflightOnly": bool(args.preflight_only),
            "sparseEvidence": bool(args.sparse_evidence),
            "windowsExporterCompatibilityOverlay": bool(windows_overlay_applied),
        }
        if args.preflight_only:
            (work / "local-sigmascope-queue-worker-report.json").write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
            return 0

        phase("run production SigmaScope pipeline")
        pipeline = frozen_worker / "tools" / "security" / "production_sigmascope_v2_pipeline.py"
        pipeline_args = [
            sys.executable, str(pipeline),
            "--base-database", str(work / "catalog" / "security-input" / "omega-catalog.sqlite"),
            "--current-evidence", str(current),
            "--candidate-evidence", str(work / "catalog" / "security-v2-candidate"),
            "--work-dir", str(work / "catalog" / "security-v2-work"),
            "--skip-marketplace",
            "--frozen-advisories", str(definitions / "osv-advisories.json"),
            "--frozen-definitions", str(definitions),
            "--catalog-revision", frozen_revision(catalog / "catalog", "catalogRevision") or str(read_json(catalog / "catalog" / "index.json").get("catalogRevision") or ""),
            "--definitions-revision", frozen_revision(definitions, "definitionsRevision"),
            "--scanner-revision", frozen_revision(definitions, "scannerRevision"),
            "--artifact-analysis-revision", frozen_revision(definitions, "artifactAnalysisRevision"),
            "--source-analysis-revision", frozen_revision(definitions, "sourceAnalysisRevision"),
            "--scanner-bundle-sha256", scanner_bundle_sha(definitions),
            "--rule-set-revision", frozen_revision(definitions, "ruleSetRevision"),
            "--advisory-revision", frozen_revision(definitions, "advisoryRevision"),
            "--queue-seed", str(catalog / "scan-queue.json"),
            "--evidence-index-url", f"https://raw.githubusercontent.com/{args.repository or 'dalagab/omega'}/security-evidence-v2/index.json",
            "--max-scans", str(args.max_scans),
            "--max-batch-seconds", str(args.max_batch_seconds),
            "--internal-names", args.internal_names,
            "--source-overrides", str(frozen_worker / "sources" / "source-overrides.json"),
        ]
        if (deep / "index.json").is_file():
            pipeline_args.extend(["--deep-scan-state", str(deep / "index.json"), "--deep-scan-output", str(work / "catalog" / "security-v2-work" / "deep-scan-state")])
        run(pipeline_args, cwd=work, env=env)

        phase("generate source followups")
        run([sys.executable, str(frozen_worker / "tools" / "catalog" / "sigmascope_source_followups.py"), "--database", str(work / "catalog" / "security-v2-work" / "omega-security-v2-working.sqlite"), "--output", str(work / "catalog" / "security-v2-work" / "sigmascope-source-followups.json")], cwd=work, env=env)
        maybe_run_source_followups(args, work, env)
        audit = work / "catalog" / "security-v2-work" / "security-developer-audit.json"
        phase("run developer audit")
        run([sys.executable, str(frozen_worker / "tools" / "security" / "security_developer_audit.py"), "--database", str(work / "catalog" / "security-v2-work" / "omega-security-v2-working.sqlite"), "--advisories", str(definitions / "osv-advisories.json"), "--json"], cwd=work, env=env)
        audit.write_text(output([sys.executable, str(frozen_worker / "tools" / "security" / "security_developer_audit.py"), "--database", str(work / "catalog" / "security-v2-work" / "omega-security-v2-working.sqlite"), "--advisories", str(definitions / "osv-advisories.json"), "--json"], cwd=work) + "\n", encoding="utf-8")
        phase("run storage audit")
        run([sys.executable, str(frozen_worker / "tools" / "security" / "evidence_storage_audit.py"), "--root", str(work / "catalog" / "security-v2-candidate"), "--report", str(work / "catalog" / "security-v2-work" / "evidence-storage-audit.json")], cwd=work, env=env)

        if args.push:
            publish_script = frozen_worker / "tools" / "security" / "publish_security_evidence_v2.py"
            publication = output([
                sys.executable, str(publish_script),
                "--input", str(work / "catalog" / "security-v2-candidate"),
                "--repo", str(repo),
                "--branch", "security-evidence-v2",
                "--snapshot-validation-report", str(work / "catalog" / "security-v2-candidate" / "validation-report.json"),
                "--audit-report", str(audit),
                "--history-mode", "fast-forward",
                "--expected-parent-sha", evidence_head,
                "--message", f"Local SigmaScope queue drain from {os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or 'operator'}",
                "--push",
            ], cwd=work)
            report["publication"] = json.loads(publication)
        (work / "local-sigmascope-queue-worker-report.json").write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    finally:
        for path in (catalog, current, deep):
            if (path / ".git").exists():
                remove_worktree(repo, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Omega repository checkout with origin configured")
    parser.add_argument("--work-dir", type=Path, default=default_work_dir())
    parser.add_argument("--reset-work-dir", action="store_true")
    parser.add_argument("--allow-long-windows-work-dir", action="store_true", help="Permit a long Windows work root despite known Evidence path-length failures")
    parser.add_argument("--repository", default="dalagab/omega")
    parser.add_argument("--max-scans", type=int, default=20)
    parser.add_argument("--max-batch-seconds", type=int, default=3300)
    parser.add_argument("--internal-names", default="")
    parser.add_argument("--push", action="store_true", help="Publish the validated candidate with expected-parent protection")
    parser.add_argument("--sparse-evidence", action=argparse.BooleanOptionalAction, default=True, help="Use a sparse current Evidence view for selected queue keys instead of a full branch worktree")
    parser.add_argument("--preflight-only", action="store_true", help="Fetch frozen inputs, verify worker, materialize local inputs, then stop before scanning")
    parser.add_argument("--reconcile-source-followups", action="store_true", help="Best-effort issue side effect; never gates Evidence publication")
    parser.add_argument("--max-new-followups", type=int, default=25)
    parser.add_argument("--max-close-followups", type=int, default=100)
    return local_drain(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
