#!/usr/bin/env python3
"""Run one exact SigmaScope worker slot without rehydrating Evidence for every key.

The production scanner implementation remains the frozen Definitions worker.  This
wrapper only owns orchestration: it constrains ``scan_queue.select_next`` to the exact
planner-owned keys, lets the frozen pipeline process them in one invocation, then
splits the resulting multi-key candidate into the existing one-key result-bundle
contract used by the serialized merger.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
from types import ModuleType
from typing import Any, Callable, Iterable

MAX_SLOT_KEYS = 16
REPORT_NAME = "production-sigmascope-v2-report.json"
SLOT_SUMMARY_SCHEMA = "omega.sigmascope-worker-slot-summary.v1"


def load_queue_keys(path: Path) -> list[str]:
    keys = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not keys:
        raise ValueError("worker slot has no queue keys")
    if len(keys) > MAX_SLOT_KEYS:
        raise ValueError(f"worker slot exceeds {MAX_SLOT_KEYS} queue keys")
    if len(keys) != len(set(keys)):
        raise ValueError("worker slot contains duplicate queue keys")
    if any("\r" in key or "\n" in key for key in keys):
        raise ValueError("worker slot contains an unsafe queue key")
    return keys


def validated_selected_queue_keys(report: dict[str, Any], planned_queue_keys: Iterable[str]) -> list[str]:
    """Accept the exact plan or a budget-stopped prefix; reject every other subset."""
    planned = list(planned_queue_keys)
    queue = report.get("queue") if isinstance(report.get("queue"), dict) else {}
    selected = [
        str(item.get("queueKey") or "")
        for item in (queue.get("selectedItems") or [])
        if isinstance(item, dict)
    ]
    if selected == planned:
        return selected
    if bool(queue.get("stoppedByBatchBudget")) and selected == planned[:len(selected)]:
        return selected
    raise RuntimeError(
        f"frozen SigmaScope batch selected {selected!r}, expected {planned!r}"
        + (" or an exact budget-stopped prefix" if bool(queue.get("stoppedByBatchBudget")) else "")
    )


def planned_selector(
    select_key: Callable[[dict[str, Any], str], dict[str, Any] | None],
    queue_keys: Iterable[str],
) -> Callable[[dict[str, Any]], dict[str, Any] | None]:
    """Return a select_next replacement that can consume only planner-owned keys."""
    remaining = iter(list(queue_keys))

    def select_next(state: dict[str, Any]) -> dict[str, Any] | None:
        try:
            queue_key = next(remaining)
        except StopIteration:
            return None
        selected = select_key(state, queue_key)
        if selected is None:
            raise RuntimeError(f"planned SigmaScope queue item is no longer eligible: {queue_key}")
        return selected

    return select_next


def _load_frozen_pipeline(path: Path) -> ModuleType:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    module_name = "_omega_frozen_sigmascope_worker_batch"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load frozen SigmaScope pipeline: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _option_value(arguments: list[str], name: str) -> str:
    try:
        index = arguments.index(name)
    except ValueError as exc:
        raise ValueError(f"missing required frozen-pipeline argument: {name}") from exc
    if index + 1 >= len(arguments):
        raise ValueError(f"missing value for frozen-pipeline argument: {name}")
    return arguments[index + 1]


def _reject_pipeline_option(arguments: list[str], name: str) -> None:
    if name in arguments or any(item.startswith(name + "=") for item in arguments):
        raise ValueError(f"{name} is owned by sigmascope_worker_batch.py and must not be supplied")


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _safe_evidence_child(root: Path, relative: str, *, label: str) -> Path:
    rel = Path(str(relative or ""))
    if not str(relative or "") or rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"unsafe {label} path in Evidence: {relative!r}")
    root = root.resolve()
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"unsafe {label} path in Evidence: {relative!r}") from exc
    return path


def _write_json_detached(path: Path, value: dict[str, Any]) -> None:
    """Replace a JSON file without mutating a hard-linked source inode."""
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".transport-compat.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _link_or_copy(source: str, destination: str) -> str:
    try:
        os.link(source, destination)
        return destination
    except OSError:
        return str(shutil.copy2(source, destination))


def prepare_frozen_transport_view(
    current_evidence: Path,
    output: Path,
    summary_function: Callable[..., dict[str, Any]],
) -> tuple[Path, int]:
    """Adapt only derived plugin summaries to the frozen worker's read contract.

    Security Evidence may add non-authoritative Developer View fields between daily
    Definitions freezes.  Older frozen workers must still be able to validate and read
    the same authoritative variant payloads.  When only the derived plugin summaries
    differ, build a local hard-linked view whose summaries are regenerated by the
    frozen worker itself.  The published checkout is never modified and result bundles
    remain bound to that original Evidence index.
    """
    current_evidence = current_evidence.resolve()
    output = output.resolve()
    root_index = _read_json_object(current_evidence / "index.json")
    indexes = root_index.get("indexes") if isinstance(root_index.get("indexes"), dict) else {}
    plugins_descriptor = indexes.get("plugins") if isinstance(indexes.get("plugins"), dict) else {}
    plugins_relative = str(plugins_descriptor.get("path") or "indexes/plugins.json")
    plugins = _read_json_object(_safe_evidence_child(current_evidence, plugins_relative, label="plugins index"))
    lifecycle_contract = int(plugins.get("lifecycleContractVersion") or 0)
    if lifecycle_contract not in {0, 1}:
        raise ValueError(f"unsupported frozen plugins lifecycle contract: {lifecycle_contract}")

    changed = 0
    collections = [("currentVariants", lifecycle_contract)]
    if lifecycle_contract == 1:
        collections.extend((("terminalVariants", 1), ("historicalSnapshots", 1)))
    for collection_name, summary_contract in collections:
        rows = plugins.get(collection_name) if isinstance(plugins.get(collection_name), list) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            variant_relative = str(row.get("variantPath") or "")
            payload = _read_json_object(
                _safe_evidence_child(current_evidence, variant_relative, label=f"{collection_name} variant")
            )
            expected = summary_function(payload, lifecycle_contract_version=summary_contract)
            if not isinstance(expected, dict):
                raise ValueError("frozen variant summary function returned a non-object")
            if row.get("summary") != expected:
                row["summary"] = expected
                changed += 1

    if changed == 0:
        if output.exists():
            shutil.rmtree(output)
        return current_evidence, 0

    if output.exists():
        shutil.rmtree(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        current_evidence,
        output,
        copy_function=_link_or_copy,
        ignore=shutil.ignore_patterns(".git"),
    )
    compat_plugins = _safe_evidence_child(output, plugins_relative, label="plugins index")
    _write_json_detached(compat_plugins, plugins)

    compat_descriptor = dict(plugins_descriptor)
    compat_descriptor["path"] = plugins_relative
    compat_descriptor["bytes"] = compat_plugins.stat().st_size
    compat_descriptor["sha256"] = _sha256_file(compat_plugins)
    compat_indexes = dict(indexes)
    compat_indexes["plugins"] = compat_descriptor
    root_index["indexes"] = compat_indexes
    _write_json_detached(output / "index.json", root_index)
    return output, changed


def _replace_option_value(arguments: list[str], name: str, value: str) -> None:
    index = arguments.index(name)
    if index + 1 >= len(arguments):
        raise ValueError(f"missing value for frozen-pipeline argument: {name}")
    arguments[index + 1] = value


def run_frozen_pipeline(pipeline: Path, queue_keys: list[str], pipeline_arguments: list[str]) -> dict[str, Any]:
    for owned in ("--queue-key", "--analysis-request", "--max-scans"):
        _reject_pipeline_option(pipeline_arguments, owned)
    work_dir = Path(_option_value(pipeline_arguments, "--work-dir")).resolve()
    module = _load_frozen_pipeline(pipeline)
    effective_arguments = list(pipeline_arguments)
    if "--current-evidence" in effective_arguments:
        summary_function = getattr(module, "variant_index_summary", None)
        if not callable(summary_function):
            raise RuntimeError("frozen SigmaScope pipeline no longer exposes its variant-summary read contract")
        current_evidence = Path(_option_value(effective_arguments, "--current-evidence")).resolve()
        compatibility_root = work_dir.parent / "frozen-evidence-transport-compat"
        evidence_view, adapted = prepare_frozen_transport_view(
            current_evidence, compatibility_root, summary_function
        )
        if adapted:
            _replace_option_value(effective_arguments, "--current-evidence", str(evidence_view))
            print(
                f"Prepared frozen Evidence transport compatibility view for {adapted} plugin summary entr"
                f"{'y' if adapted == 1 else 'ies'}; published Evidence remains unchanged."
            )
    scan_queue = getattr(module, "scan_queue", None)
    if scan_queue is None or not callable(getattr(scan_queue, "select_next", None)) or not callable(getattr(scan_queue, "select_key", None)):
        raise RuntimeError("frozen SigmaScope pipeline no longer exposes the expected queue-selection contract")

    original_select_next = scan_queue.select_next
    original_argv = sys.argv[:]
    scan_queue.select_next = planned_selector(scan_queue.select_key, queue_keys)
    sys.argv = [str(pipeline), *effective_arguments, "--max-scans", str(len(queue_keys))]
    try:
        rc = int(module.main())
    finally:
        scan_queue.select_next = original_select_next
        sys.argv = original_argv
    if rc != 0:
        raise RuntimeError(f"frozen SigmaScope batch pipeline exited with status {rc}")

    report_path = work_dir / REPORT_NAME
    report = json.loads(report_path.read_text(encoding="utf-8"))
    validated_selected_queue_keys(report, queue_keys)
    return report


def _scan_report_for_variant(scan: dict[str, Any], variant_id: int) -> dict[str, Any]:
    result = copy.deepcopy(scan)
    plugins = [
        dict(item) for item in (scan.get("plugins") or [])
        if isinstance(item, dict) and int(item.get("variantId") or 0) == variant_id
    ]
    result["plugins"] = plugins
    result["selected"] = len(plugins)
    result["completed"] = sum(1 for item in plugins if str(item.get("status") or "") == "complete")
    result["failed"] = len(plugins) - int(result["completed"])
    result["invocations"] = 1 if plugins else 0
    elapsed = [float(item.get("elapsedSeconds") or 0.0) for item in plugins]
    result["pluginElapsedSecondsTotal"] = round(sum(elapsed), 3)
    result["pluginElapsedSecondsAverage"] = round((sum(elapsed) / len(elapsed)) if elapsed else 0.0, 3)
    result["pluginElapsedSecondsMax"] = round(max(elapsed), 3) if elapsed else 0.0
    return result


def split_report_for_key(report: dict[str, Any], queue_key: str) -> dict[str, Any]:
    selected_items = [
        dict(item) for item in ((report.get("queue") or {}).get("selectedItems") or [])
        if isinstance(item, dict) and str(item.get("queueKey") or "") == queue_key
    ]
    if len(selected_items) != 1:
        raise ValueError(f"batch report is not bound to exactly one selected item for {queue_key}")
    selected = selected_items[0]
    variant_id = int(selected.get("variantId") or 0)
    if variant_id <= 0:
        raise ValueError(f"batch report selected item has no variant identity: {queue_key}")

    result = copy.deepcopy(report)
    queue = result.setdefault("queue", {})
    queue["selected"] = selected
    queue["selectedItems"] = [selected]
    queue["selectedCount"] = 1
    queue["requestedQueueKey"] = queue_key
    result["successfulVariantIds"] = [
        value for value in (report.get("successfulVariantIds") or []) if int(value or 0) == variant_id
    ]
    result["failedRetainedVariantIds"] = [
        value for value in (report.get("failedRetainedVariantIds") or []) if int(value or 0) == variant_id
    ]
    if isinstance(report.get("scan"), dict):
        result["scan"] = _scan_report_for_variant(report["scan"], variant_id)
    return result


def _write_slot_summary(
    path: Path,
    *,
    planned_queue_keys: list[str],
    selected_queue_keys: list[str],
    bundled_queue_keys: list[str],
    bundle_revisions: list[str],
    report: dict[str, Any],
    slot: int,
    lane: str,
    plan_revision: str,
) -> None:
    queue = report.get("queue") if isinstance(report.get("queue"), dict) else {}
    selected_items = [
        item for item in (queue.get("selectedItems") or [])
        if isinstance(item, dict)
    ]
    successful = {int(value or 0) for value in (report.get("successfulVariantIds") or []) if int(value or 0) > 0}
    failed = {int(value or 0) for value in (report.get("failedRetainedVariantIds") or []) if int(value or 0) > 0}
    outcomes = []
    for item in selected_items:
        variant_id = int(item.get("variantId") or 0)
        status = "complete" if variant_id in successful else "failed" if variant_id in failed else "unknown"
        outcomes.append({
            "queueKey": str(item.get("queueKey") or ""),
            "variantId": variant_id,
            "workType": str(item.get("workType") or ""),
            "status": status,
        })
    document = {
        "schema": SLOT_SUMMARY_SCHEMA,
        "authority": "operational-result-summary-only",
        "slot": int(slot),
        "lane": str(lane or ""),
        "planRevision": str(plan_revision or ""),
        "scanReportGeneratedAtUtc": str(report.get("generatedAtUtc") or ""),
        "stoppedByBatchBudget": bool(queue.get("stoppedByBatchBudget")),
        "plannedQueueKeys": list(planned_queue_keys),
        "selectedQueueKeys": list(selected_queue_keys),
        "bundledQueueKeys": list(bundled_queue_keys),
        "unprocessedQueueKeys": list(planned_queue_keys[len(selected_queue_keys):]),
        "unbundledSelectedQueueKeys": list(selected_queue_keys[len(bundled_queue_keys):]),
        "bundleCount": len(bundled_queue_keys),
        "bundleRevisions": list(bundle_revisions),
        "successfulVariantIds": sorted(successful),
        "failedRetainedVariantIds": sorted(failed),
        "outcomes": outcomes,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def build_result_bundles(
    *,
    current_evidence: Path,
    candidate_evidence: Path,
    work_dir: Path,
    definitions_root: Path,
    queue_keys: list[str],
    worker_image: str,
    output_root: Path,
    split_work_root: Path,
    summary_path: Path | None = None,
    slot: int = 0,
    lane: str = "",
    plan_revision: str = "",
) -> dict[str, Any]:
    script_dir = Path(__file__).resolve().parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    import sigmascope_result_bundle  # noqa: WPS433 - same-tree production helper

    report = json.loads((work_dir / REPORT_NAME).read_text(encoding="utf-8"))
    selected = validated_selected_queue_keys(report, queue_keys)

    if output_root.exists():
        shutil.rmtree(output_root)
    if split_work_root.exists():
        shutil.rmtree(split_work_root)
    output_root.mkdir(parents=True, exist_ok=True)
    split_work_root.mkdir(parents=True, exist_ok=True)

    revisions: list[str] = []
    bundled: list[str] = []
    if summary_path is not None:
        _write_slot_summary(
            summary_path,
            planned_queue_keys=queue_keys,
            selected_queue_keys=selected,
            bundled_queue_keys=bundled,
            bundle_revisions=revisions,
            report=report,
            slot=slot,
            lane=lane,
            plan_revision=plan_revision,
        )
    for ordinal, queue_key in enumerate(selected, 1):
        split_work = split_work_root / f"key-{ordinal:02d}"
        split_work.mkdir(parents=True, exist_ok=True)
        split = split_report_for_key(report, queue_key)
        (split_work / REPORT_NAME).write_text(
            json.dumps(split, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        bundle_root = output_root / f"key-{ordinal:02d}"
        temporary_bundle = output_root / f".key-{ordinal:02d}.tmp"
        shutil.rmtree(temporary_bundle, ignore_errors=True)
        try:
            validation = sigmascope_result_bundle.build(
                current=current_evidence,
                candidate=candidate_evidence,
                work_dir=split_work,
                definitions=definitions_root,
                queue_key=queue_key,
                worker_image=worker_image,
                output=temporary_bundle,
            )
            sigmascope_result_bundle.validate(temporary_bundle, current_evidence=current_evidence)
            os.replace(temporary_bundle, bundle_root)
        except Exception:
            shutil.rmtree(temporary_bundle, ignore_errors=True)
            raise
        revisions.append(str(validation.get("bundleRevision") or ""))
        bundled.append(queue_key)
        if summary_path is not None:
            _write_slot_summary(
                summary_path,
                planned_queue_keys=queue_keys,
                selected_queue_keys=selected,
                bundled_queue_keys=bundled,
                bundle_revisions=revisions,
                report=report,
                slot=slot,
                lane=lane,
                plan_revision=plan_revision,
            )

    return {
        "bundleCount": len(bundled),
        "plannedQueueKeys": queue_keys,
        "queueKeys": bundled,
        "unprocessedQueueKeys": queue_keys[len(selected):],
        "stoppedByBatchBudget": bool((report.get("queue") or {}).get("stoppedByBatchBudget")),
        "bundleRevisions": revisions,
    }


def _run_command(args: argparse.Namespace) -> int:
    queue_keys = load_queue_keys(args.queue_keys_file)
    run_frozen_pipeline(args.pipeline, queue_keys, list(args.pipeline_arguments))
    return 0


def _bundles_command(args: argparse.Namespace) -> int:
    queue_keys = load_queue_keys(args.queue_keys_file)
    result = build_result_bundles(
        current_evidence=args.current_evidence,
        candidate_evidence=args.candidate_evidence,
        work_dir=args.work_dir,
        definitions_root=args.definitions_root,
        queue_keys=queue_keys,
        worker_image=args.worker_image,
        output_root=args.output_root,
        split_work_root=args.split_work_root,
        summary_path=args.summary,
        slot=args.slot,
        lane=args.lane,
        plan_revision=args.plan_revision,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch exact SigmaScope drain-slot work over one Evidence hydration")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the frozen pipeline once for the exact planned queue keys")
    run_parser.add_argument("--pipeline", type=Path, required=True)
    run_parser.add_argument("--queue-keys-file", type=Path, required=True)
    run_parser.add_argument("pipeline_arguments", nargs=argparse.REMAINDER)
    run_parser.set_defaults(handler=_run_command)

    bundle_parser = subparsers.add_parser("bundles", help="Split one batch candidate into existing exact-key result bundles")
    bundle_parser.add_argument("--current-evidence", type=Path, required=True)
    bundle_parser.add_argument("--candidate-evidence", type=Path, required=True)
    bundle_parser.add_argument("--work-dir", type=Path, required=True)
    bundle_parser.add_argument("--definitions-root", type=Path, required=True)
    bundle_parser.add_argument("--queue-keys-file", type=Path, required=True)
    bundle_parser.add_argument("--worker-image", required=True)
    bundle_parser.add_argument("--output-root", type=Path, required=True)
    bundle_parser.add_argument("--split-work-root", type=Path, required=True)
    bundle_parser.add_argument("--summary", type=Path)
    bundle_parser.add_argument("--slot", type=int, default=0)
    bundle_parser.add_argument("--lane", default="")
    bundle_parser.add_argument("--plan-revision", default="")
    bundle_parser.set_defaults(handler=_bundles_command)

    args = parser.parse_args()
    if args.command == "run" and args.pipeline_arguments and args.pipeline_arguments[0] == "--":
        args.pipeline_arguments = args.pipeline_arguments[1:]
    try:
        return int(args.handler(args))
    except Exception as exc:
        print(f"SigmaScope worker batch failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
