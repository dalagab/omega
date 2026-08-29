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
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from types import ModuleType
from typing import Any, Callable, Iterable

MAX_SLOT_KEYS = 16
REPORT_NAME = "production-sigmascope-v2-report.json"


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


def run_frozen_pipeline(pipeline: Path, queue_keys: list[str], pipeline_arguments: list[str]) -> dict[str, Any]:
    for owned in ("--queue-key", "--analysis-request", "--max-scans"):
        _reject_pipeline_option(pipeline_arguments, owned)
    work_dir = Path(_option_value(pipeline_arguments, "--work-dir")).resolve()
    module = _load_frozen_pipeline(pipeline)
    scan_queue = getattr(module, "scan_queue", None)
    if scan_queue is None or not callable(getattr(scan_queue, "select_next", None)) or not callable(getattr(scan_queue, "select_key", None)):
        raise RuntimeError("frozen SigmaScope pipeline no longer exposes the expected queue-selection contract")

    original_select_next = scan_queue.select_next
    original_argv = sys.argv[:]
    scan_queue.select_next = planned_selector(scan_queue.select_key, queue_keys)
    sys.argv = [str(pipeline), *pipeline_arguments, "--max-scans", str(len(queue_keys))]
    try:
        rc = int(module.main())
    finally:
        scan_queue.select_next = original_select_next
        sys.argv = original_argv
    if rc != 0:
        raise RuntimeError(f"frozen SigmaScope batch pipeline exited with status {rc}")

    report_path = work_dir / REPORT_NAME
    report = json.loads(report_path.read_text(encoding="utf-8"))
    selected = [
        str(item.get("queueKey") or "")
        for item in ((report.get("queue") or {}).get("selectedItems") or [])
        if isinstance(item, dict)
    ]
    if selected != queue_keys:
        raise RuntimeError(f"frozen SigmaScope batch selected {selected!r}, expected {queue_keys!r}")
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
) -> dict[str, Any]:
    script_dir = Path(__file__).resolve().parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    import sigmascope_result_bundle  # noqa: WPS433 - same-tree production helper

    report = json.loads((work_dir / REPORT_NAME).read_text(encoding="utf-8"))
    selected = [
        str(item.get("queueKey") or "")
        for item in ((report.get("queue") or {}).get("selectedItems") or [])
        if isinstance(item, dict)
    ]
    if selected != queue_keys:
        raise RuntimeError(f"cannot split SigmaScope batch with selections {selected!r}; expected {queue_keys!r}")

    if output_root.exists():
        shutil.rmtree(output_root)
    if split_work_root.exists():
        shutil.rmtree(split_work_root)
    output_root.mkdir(parents=True, exist_ok=True)
    split_work_root.mkdir(parents=True, exist_ok=True)

    revisions: list[str] = []
    for ordinal, queue_key in enumerate(queue_keys, 1):
        split_work = split_work_root / f"key-{ordinal:02d}"
        split_work.mkdir(parents=True, exist_ok=True)
        split = split_report_for_key(report, queue_key)
        (split_work / REPORT_NAME).write_text(
            json.dumps(split, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        bundle_root = output_root / f"key-{ordinal:02d}"
        validation = sigmascope_result_bundle.build(
            current=current_evidence,
            candidate=candidate_evidence,
            work_dir=split_work,
            definitions=definitions_root,
            queue_key=queue_key,
            worker_image=worker_image,
            output=bundle_root,
        )
        sigmascope_result_bundle.validate(bundle_root, current_evidence=current_evidence)
        revisions.append(str(validation.get("bundleRevision") or ""))

    return {"bundleCount": len(queue_keys), "queueKeys": queue_keys, "bundleRevisions": revisions}


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
