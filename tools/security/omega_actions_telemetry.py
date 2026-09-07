#!/usr/bin/env python3
"""Machine-readable operational telemetry for Omega GitHub Actions.

Producers emit one compact JSON object per line, prefixed with ``@@omega ``.  The
contract is intentionally narrow: only operational identifiers/counters are retained,
unknown fields are discarded, strings are bounded/redacted, and events never carry
security/evidence authority.

Example:

    emit_event(
        "scan.started",
        component="sigmascope",
        worker={"roleId": "sigmascope", "label": "SigmaScope worker"},
        subject={"variantId": 8291, "internalName": "Example.Plugin", "workType": "artifact"},
        queue={"reason": "first-plugin-coverage", "remaining": 1284},
    )
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from typing import Any, Mapping, TextIO

SCHEMA = "omega.actions.telemetry.v1"
PARSE_SCHEMA = "omega.actions.telemetry-parse.v1"
MARKER = "@@omega "
MAX_EVENT_BYTES = 8 * 1024
MAX_EVENTS = 64
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

_TOP_TEXT = {"component", "stage", "state"}
_WORKER_TEXT = {"roleId", "label", "workerId", "state"}
_SUBJECT_TEXT = {"internalName", "version", "workType", "sourceName"}
_QUEUE_TEXT = {"reason", "lane", "workType"}
_PROGRESS_TEXT = {"unit"}
_RESULT_TEXT = {"status"}
_PUBLICATION_TEXT = {"stage", "evidenceRevision", "dependencyGraphRevision"}
_BUNDLE_TEXT = {"id", "status"}

_SUBJECT_INT = {"pluginId", "variantId"}
_QUEUE_INT = {"remaining", "pending", "retry", "complete", "total"}
_PROGRESS_INT = {"current", "total"}
_RESULT_INT = {"findingCount", "analysisCount", "artifactCount", "durationMs", "errorCount"}
_PUBLICATION_INT = {"acceptedBundles", "rejectedBundles", "remainingBundles"}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _redact(value: str) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def _text(value: Any, *, maximum: int = MAX_STRING) -> str:
    return _redact(str(value or "").strip())[:maximum]


def _nonnegative(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _clean_section(
    value: Any,
    *,
    text_fields: set[str] | frozenset[str],
    int_fields: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in sorted(text_fields):
        if key in value:
            text = _text(value.get(key))
            if text:
                result[key] = text
    for key in sorted(int_fields):
        if key in value:
            result[key] = _nonnegative(value.get(key))
    return result


def sanitize_event(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and bound one producer event.

    Unknown event names fail closed. Unknown keys/sections are discarded rather than
    propagated to the client, which prevents an accidental environment/secret dump from
    becoming part of DeltaScope telemetry.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("telemetry event must be an object")
    if str(payload.get("schema") or "") != SCHEMA:
        raise ValueError("unsupported telemetry schema")
    event = _text(payload.get("event"), maximum=96)
    if event not in ALLOWED_EVENTS:
        raise ValueError(f"unsupported telemetry event {event!r}")

    result: dict[str, Any] = {
        "schema": SCHEMA,
        "event": event,
        "emittedAtUtc": _text(payload.get("emittedAtUtc"), maximum=64) or _utc_now(),
    }
    for key in sorted(_TOP_TEXT):
        if key in payload:
            text = _text(payload.get(key))
            if text:
                result[key] = text
    if "message" in payload:
        message = _text(payload.get("message"), maximum=MAX_MESSAGE)
        if message:
            result["message"] = message

    sections = (
        ("worker", _WORKER_TEXT, frozenset()),
        ("subject", _SUBJECT_TEXT, _SUBJECT_INT),
        ("queue", _QUEUE_TEXT, _QUEUE_INT),
        ("progress", _PROGRESS_TEXT, _PROGRESS_INT),
        ("result", _RESULT_TEXT, _RESULT_INT),
        ("publication", _PUBLICATION_TEXT, _PUBLICATION_INT),
        ("bundle", _BUNDLE_TEXT, frozenset()),
    )
    for name, text_fields, int_fields in sections:
        cleaned = _clean_section(payload.get(name), text_fields=text_fields, int_fields=int_fields)
        if cleaned:
            result[name] = cleaned

    progress = result.get("progress")
    if isinstance(progress, dict):
        current = _nonnegative(progress.get("current"))
        total = _nonnegative(progress.get("total"))
        if total > 0:
            progress["percent"] = min(100, round(current * 100 / total, 1))

    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_EVENT_BYTES:
        raise ValueError("telemetry event exceeds the bounded event size")
    return result


def build_event(event: str, **fields: Any) -> dict[str, Any]:
    payload = {"schema": SCHEMA, "event": event, "emittedAtUtc": _utc_now(), **fields}
    return sanitize_event(payload)


def encode_event(event: str, **fields: Any) -> str:
    return MARKER + json.dumps(build_event(event, **fields), ensure_ascii=False, separators=(",", ":"))


def emit_event(event: str, *, stream: TextIO | None = None, **fields: Any) -> dict[str, Any]:
    result = build_event(event, **fields)
    output = stream or sys.stdout
    print(MARKER + json.dumps(result, ensure_ascii=False, separators=(",", ":")), file=output, flush=True)
    return result


def parse_log(text: str, *, max_events: int = MAX_EVENTS) -> dict[str, Any]:
    """Extract bounded telemetry events from a GitHub Actions log preview."""
    maximum = max(1, min(int(max_events or MAX_EVENTS), MAX_EVENTS))
    events: list[dict[str, Any]] = []
    invalid = 0
    matched = 0
    truncated = False
    for line in str(text or "").splitlines():
        index = line.find(MARKER)
        if index < 0:
            continue
        matched += 1
        raw = line[index + len(MARKER):].strip()
        if len(raw.encode("utf-8", "replace")) > MAX_EVENT_BYTES:
            invalid += 1
            continue
        try:
            payload = json.loads(raw)
            event = sanitize_event(payload)
        except (json.JSONDecodeError, TypeError, ValueError):
            invalid += 1
            continue
        if len(events) >= maximum:
            truncated = True
            continue
        events.append(event)
    return {
        "schema": PARSE_SCHEMA,
        "contract": SCHEMA,
        "marker": MARKER.rstrip(),
        "matchedLines": matched,
        "eventCount": len(events),
        "invalidCount": invalid,
        "truncated": truncated,
        "events": events,
    }


def _cli_fields(args: argparse.Namespace) -> dict[str, Any]:
    worker = {
        "roleId": args.worker_role,
        "label": args.worker_label,
        "workerId": args.worker_id,
        "state": args.worker_state,
    }
    subject = {
        "pluginId": args.plugin_id,
        "variantId": args.variant_id,
        "internalName": args.internal_name,
        "version": args.version,
        "workType": args.work_type,
        "sourceName": args.source_name,
    }
    queue = {
        "reason": args.queue_reason,
        "lane": args.queue_lane,
        "workType": args.work_type,
        "remaining": args.queue_remaining,
        "pending": args.queue_pending,
        "retry": args.queue_retry,
    }
    progress = {
        "current": args.progress_current,
        "total": args.progress_total,
        "unit": args.progress_unit,
    }
    result = {
        "status": args.result_status,
        "findingCount": args.finding_count,
        "durationMs": args.duration_ms,
    }
    publication = {
        "stage": args.publication_stage,
        "evidenceRevision": args.evidence_revision,
        "acceptedBundles": args.accepted_bundles,
        "rejectedBundles": args.rejected_bundles,
        "remainingBundles": args.remaining_bundles,
    }
    fields: dict[str, Any] = {
        "component": args.component,
        "stage": args.stage,
        "state": args.state,
        "message": args.message,
        "worker": worker,
        "subject": subject,
        "queue": queue,
        "progress": progress,
        "result": result,
        "publication": publication,
    }
    if args.bundle_id:
        fields["bundle"] = {"id": args.bundle_id, "status": args.bundle_status}
    return fields


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit one omega.actions.telemetry.v1 log marker")
    parser.add_argument("event", choices=sorted(ALLOWED_EVENTS))
    parser.add_argument("--component", default="")
    parser.add_argument("--stage", default="")
    parser.add_argument("--state", default="")
    parser.add_argument("--message", default="")
    parser.add_argument("--worker-role", default="")
    parser.add_argument("--worker-label", default="")
    parser.add_argument("--worker-id", default="")
    parser.add_argument("--worker-state", default="")
    parser.add_argument("--plugin-id", type=int, default=0)
    parser.add_argument("--variant-id", type=int, default=0)
    parser.add_argument("--internal-name", default="")
    parser.add_argument("--version", default="")
    parser.add_argument("--work-type", default="")
    parser.add_argument("--source-name", default="")
    parser.add_argument("--queue-reason", default="")
    parser.add_argument("--queue-lane", default="")
    parser.add_argument("--queue-remaining", type=int, default=0)
    parser.add_argument("--queue-pending", type=int, default=0)
    parser.add_argument("--queue-retry", type=int, default=0)
    parser.add_argument("--progress-current", type=int, default=0)
    parser.add_argument("--progress-total", type=int, default=0)
    parser.add_argument("--progress-unit", default="")
    parser.add_argument("--result-status", default="")
    parser.add_argument("--finding-count", type=int, default=0)
    parser.add_argument("--duration-ms", type=int, default=0)
    parser.add_argument("--publication-stage", default="")
    parser.add_argument("--evidence-revision", default="")
    parser.add_argument("--accepted-bundles", type=int, default=0)
    parser.add_argument("--rejected-bundles", type=int, default=0)
    parser.add_argument("--remaining-bundles", type=int, default=0)
    parser.add_argument("--bundle-id", default="")
    parser.add_argument("--bundle-status", default="")
    args = parser.parse_args(argv)
    emit_event(args.event, **_cli_fields(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
