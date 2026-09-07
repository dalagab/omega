#!/usr/bin/env python3
"""Best-effort producer for DeltaScope's omega.actions.telemetry.v1 log contract.

Operational telemetry is deliberately non-authoritative.  Emission failure must never
change queue, scan, merge, publication, or Security Evidence behavior.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from typing import Any, Mapping, TextIO

SCHEMA = "omega.actions.telemetry.v1"
MARKER = "@@omega "
MAX_STRING = 512
MAX_MESSAGE = 768

ALLOWED_EVENTS = frozenset({
    "workflow.started", "workflow.progress", "workflow.completed",
    "worker.started", "worker.idle", "worker.stopped",
    "queue.loaded", "queue.claimed", "queue.progress",
    "plugin.selected",
    "scan.started", "scan.progress", "scan.completed",
    "source.started", "source.completed",
    "analysis.requested", "analysis.completed",
    "bundle.created", "bundle.accepted", "bundle.rejected",
    "publication.started", "publication.progress", "publication.completed",
})

_SECRET_PATTERNS = (
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{12,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\b(?:authorization|token|password|secret)\s*[:=]\s*[^\s,;]+"),
)
_TEXT_SECTIONS = {
    "worker": {"roleId", "label", "workerId", "state"},
    "subject": {"internalName", "version", "workType", "sourceName"},
    "queue": {"reason", "lane", "workType"},
    "progress": {"unit"},
    "result": {"status"},
    "publication": {"stage", "evidenceRevision", "dependencyGraphRevision"},
    "bundle": {"id", "status"},
}
_INT_SECTIONS = {
    "subject": {"pluginId", "variantId"},
    "queue": {"remaining", "pending", "retry", "complete", "total"},
    "progress": {"current", "total"},
    "result": {"findingCount", "analysisCount", "artifactCount", "durationMs", "errorCount"},
    "publication": {"acceptedBundles", "rejectedBundles", "remainingBundles"},
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _text(value: Any, maximum: int = MAX_STRING) -> str:
    text = str(value or "").strip()
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text[:maximum]


def _integer(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _section(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in sorted(_TEXT_SECTIONS.get(name, ())):
        if key in value and _text(value.get(key)):
            result[key] = _text(value.get(key))
    for key in sorted(_INT_SECTIONS.get(name, ())):
        if key in value:
            result[key] = _integer(value.get(key))
    return result


def build_event(event: str, **fields: Any) -> dict[str, Any]:
    event = _text(event, 96)
    if event not in ALLOWED_EVENTS:
        raise ValueError(f"unsupported Omega Actions telemetry event {event!r}")
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "event": event,
        "emittedAtUtc": _text(fields.get("emittedAtUtc"), 64) or _utc_now(),
    }
    for key in ("component", "stage", "state"):
        value = _text(fields.get(key))
        if value:
            result[key] = value
    message = _text(fields.get("message"), MAX_MESSAGE)
    if message:
        result["message"] = message
    for name in ("worker", "subject", "queue", "progress", "result", "publication", "bundle"):
        value = _section(name, fields.get(name))
        if value:
            result[name] = value
    progress = result.get("progress")
    if isinstance(progress, dict) and int(progress.get("total") or 0) > 0:
        progress["percent"] = min(100, round(int(progress.get("current") or 0) * 100 / int(progress["total"]), 1))
    return result


def emit_event(event: str, *, stream: TextIO | None = None, **fields: Any) -> dict[str, Any]:
    """Emit one event without ever making telemetry a production failure path."""
    try:
        payload = build_event(event, **fields)
        print(MARKER + json.dumps(payload, ensure_ascii=False, separators=(",", ":")), file=stream or sys.stdout, flush=True)
        return payload
    except Exception as exc:
        print(f"::warning::Omega Actions telemetry skipped: {type(exc).__name__}: {exc}", file=sys.stderr)
        return {}


def _cli_fields(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "component": args.component, "stage": args.stage, "state": args.state, "message": args.message,
        "worker": {"roleId": args.worker_role, "label": args.worker_label, "workerId": args.worker_id, "state": args.worker_state},
        "subject": {"variantId": args.variant_id, "internalName": args.internal_name, "version": args.version, "workType": args.work_type},
        "progress": {"current": args.progress_current, "total": args.progress_total, "unit": args.progress_unit},
        "result": {"status": args.result_status, "artifactCount": args.artifact_count, "analysisCount": args.analysis_count},
        "publication": {"stage": args.publication_stage, "evidenceRevision": args.evidence_revision},
        "bundle": {"id": args.bundle_id, "status": args.bundle_status},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit one omega.actions.telemetry.v1 marker")
    parser.add_argument("event", choices=sorted(ALLOWED_EVENTS))
    parser.add_argument("--component", default="")
    parser.add_argument("--stage", default="")
    parser.add_argument("--state", default="")
    parser.add_argument("--message", default="")
    parser.add_argument("--worker-role", default="")
    parser.add_argument("--worker-label", default="")
    parser.add_argument("--worker-id", default="")
    parser.add_argument("--worker-state", default="")
    parser.add_argument("--variant-id", type=int, default=0)
    parser.add_argument("--internal-name", default="")
    parser.add_argument("--version", default="")
    parser.add_argument("--work-type", default="")
    parser.add_argument("--progress-current", type=int, default=0)
    parser.add_argument("--progress-total", type=int, default=0)
    parser.add_argument("--progress-unit", default="")
    parser.add_argument("--result-status", default="")
    parser.add_argument("--artifact-count", type=int, default=0)
    parser.add_argument("--analysis-count", type=int, default=0)
    parser.add_argument("--publication-stage", default="")
    parser.add_argument("--evidence-revision", default="")
    parser.add_argument("--bundle-id", default="")
    parser.add_argument("--bundle-status", default="")
    args = parser.parse_args(argv)
    emit_event(args.event, **_cli_fields(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
