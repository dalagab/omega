#!/usr/bin/env python3
"""Git-backed RoboScope operator intent for SigmaScope.

RoboScope writes append-only request documents to the ``security-operations`` branch.
This module validates those documents and projects them into existing, bounded Omega
control planes.  It never publishes Evidence-v2, assigns catalog identities, launches
arbitrary workflows, or treats operator intent as a security verdict.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable
import urllib.parse

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_TOOLS = REPO_ROOT / "tools" / "catalog"
if str(CATALOG_TOOLS) not in sys.path:
    sys.path.insert(0, str(CATALOG_TOOLS))

import discovery_collectors  # noqa: E402
import plugin_coverage_policy  # noqa: E402
import scan_queue  # noqa: E402

SCAN_REQUEST_SCHEMA = "omega.roboscope.scan-nudge.v1"
SOURCE_REQUEST_SCHEMA = "omega.roboscope.source-request.v1"
SOURCE_CANDIDATES_SCHEMA = "omega.roboscope.source-candidates.v1"
SCAN_OVERLAY_SCHEMA = "omega.roboscope.scan-overlay.v1"
MAX_REQUEST_FILES = 5_000
MAX_SCAN_PLUGIN_IDS = 10
MAX_NOTES = 1_024
MAX_REFERENCE = 2_048
NUDGE_SCORE_INCREMENT = 25
MAX_NUDGE_SCORE = 500
REQUEST_ID_RE = re.compile(r"^(scan|source)-[0-9a-f]{24}$")
GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _timestamp(value: Any) -> tuple[str, dt.datetime]:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", text):
        raise ValueError("requestedAtUtc must be RFC 3339 UTC at whole-second precision")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("requestedAtUtc is not a valid UTC timestamp") from exc
    return text, parsed.astimezone(dt.timezone.utc)


def _scan_semantic(value: dict[str, Any]) -> dict[str, Any]:
    requested_at, _ = _timestamp(value.get("requestedAtUtc"))
    raw_ids = value.get("pluginIds")
    if not isinstance(raw_ids, list) or not (1 <= len(raw_ids) <= MAX_SCAN_PLUGIN_IDS):
        raise ValueError(f"pluginIds must contain 1-{MAX_SCAN_PLUGIN_IDS} IDs")
    plugin_ids: list[int] = []
    for raw in raw_ids:
        if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
            raise ValueError("pluginIds must contain positive integers")
        if raw not in plugin_ids:
            plugin_ids.append(raw)
    if len(plugin_ids) != len(raw_ids):
        raise ValueError("pluginIds must not contain duplicates")
    reason = str(value.get("reason") or "").strip()
    if reason != "operator-nudge":
        raise ValueError("reason must be operator-nudge")
    return {
        "schema": SCAN_REQUEST_SCHEMA,
        "requestedAtUtc": requested_at,
        "pluginIds": sorted(plugin_ids),
        "reason": reason,
    }


def scan_request_id(value: dict[str, Any]) -> str:
    return f"scan-{digest(_scan_semantic(value))[:24]}"


def validate_scan_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != SCAN_REQUEST_SCHEMA:
        raise ValueError(f"scan request schema must be {SCAN_REQUEST_SCHEMA}")
    allowed = {"schema", "requestId", "requestedAtUtc", "pluginIds", "reason"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"scan request has unknown fields: {unknown}")
    semantic = _scan_semantic(value)
    expected = f"scan-{digest(semantic)[:24]}"
    request_id = str(value.get("requestId") or "")
    if request_id != expected or not REQUEST_ID_RE.fullmatch(request_id):
        raise ValueError("requestId does not match canonical scan request content")
    return {**semantic, "requestId": request_id}


def _source_semantic(value: dict[str, Any]) -> dict[str, Any]:
    requested_at, _ = _timestamp(value.get("requestedAtUtc"))
    reference = str(value.get("reference") or "").strip()
    if not reference or len(reference) > MAX_REFERENCE or any(ord(ch) < 32 for ch in reference):
        raise ValueError("reference is empty, overlong, or contains control characters")
    requested_type = str(value.get("type") or "").strip().casefold()
    if requested_type not in {"official", "community", "custom"}:
        raise ValueError("type must be official, community, or custom")
    notes = str(value.get("notes") or "").strip()
    if len(notes) > MAX_NOTES or any(ch in "\r\x00" for ch in notes):
        raise ValueError(f"notes must be at most {MAX_NOTES} characters")
    return {
        "schema": SOURCE_REQUEST_SCHEMA,
        "requestedAtUtc": requested_at,
        "reference": reference,
        "type": requested_type,
        "notes": notes,
    }


def source_request_id(value: dict[str, Any]) -> str:
    return f"source-{digest(_source_semantic(value))[:24]}"


def _source_reference(reference: str) -> dict[str, str]:
    text = str(reference or "").strip()
    if GITHUB_REPOSITORY_RE.fullmatch(text):
        repository_url = f"https://github.com/{text}"
        return {"kind": "repository", "reference": text, "repositoryUrl": repository_url, "url": ""}
    try:
        parsed = urllib.parse.urlparse(text)
    except ValueError as exc:
        raise ValueError("reference is not a valid repository or HTTPS URL") from exc
    host = (parsed.hostname or "").lower()
    if parsed.scheme.lower() != "https" or not host or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL reference must be public HTTPS without credentials or a fragment")
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise ValueError("local URL references are not allowed")
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise ValueError("non-public IP URL references are not allowed")
    path_parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if host == "github.com" and len(path_parts) == 2 and not parsed.query:
        repository_url = discovery_collectors.canonical_github_repo(text)
        if repository_url:
            owner_repo = "/".join(repository_url.rstrip("/").split("/")[-2:])
            return {"kind": "repository", "reference": owner_repo, "repositoryUrl": repository_url, "url": ""}
    normalized = urllib.parse.urlunparse(("https", parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))
    return {"kind": "source", "reference": normalized, "repositoryUrl": "", "url": normalized}


def validate_source_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != SOURCE_REQUEST_SCHEMA:
        raise ValueError(f"source request schema must be {SOURCE_REQUEST_SCHEMA}")
    allowed = {"schema", "requestId", "requestedAtUtc", "reference", "type", "notes"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"source request has unknown fields: {unknown}")
    semantic = _source_semantic(value)
    expected = f"source-{digest(semantic)[:24]}"
    request_id = str(value.get("requestId") or "")
    if request_id != expected or not REQUEST_ID_RE.fullmatch(request_id):
        raise ValueError("requestId does not match canonical source request content")
    return {**semantic, "requestId": request_id, "normalized": _source_reference(semantic["reference"])}


def _load_requests(root: Path | None, kind: str, validator) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    if root is None:
        return [], []
    request_dir = root / "requests" / kind
    if not request_dir.is_dir():
        return [], []
    paths = sorted(path for path in request_dir.glob("*.json") if path.is_file())
    if len(paths) > MAX_REQUEST_FILES:
        raise ValueError(f"RoboScope {kind} request set exceeds {MAX_REQUEST_FILES} files")
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for path in paths:
        try:
            payload = read_json(path)
            request = validator(payload)
            if path.stem != request["requestId"]:
                raise ValueError("filename must equal requestId.json")
            if request["requestId"] in seen_ids:
                raise ValueError("duplicate requestId")
            seen_ids.add(request["requestId"])
            accepted.append(request)
        except Exception as exc:
            rejected.append({"path": str(path.relative_to(root)).replace("\\", "/"), "error": str(exc)[:512]})
    return accepted, rejected


def _latest_scan_by_plugin(variants: Iterable[dict[str, Any]], current: dict[int, dict[str, Any]]) -> dict[int, dt.datetime]:
    latest: dict[int, dt.datetime] = {}
    for variant in variants:
        plugin_id = int(variant.get("pluginId") or 0)
        row = current.get(int(variant.get("variantId") or 0))
        if plugin_id <= 0 or not plugin_coverage_policy.current_has_artifact_coverage(row):
            continue
        parsed = scan_queue.parse_utc(str((row or {}).get("scanned_at_utc") or ""))
        if parsed is not None and (plugin_id not in latest or parsed > latest[plugin_id]):
            latest[plugin_id] = parsed
    return latest


def _variant_rank(variant: dict[str, Any], current: dict[int, dict[str, Any]]) -> tuple[Any, ...]:
    source_rank = plugin_coverage_policy.SOURCE_PRIORITY_RANK.get(
        str(variant.get("sourcePriorityClass") or "discovered"),
        plugin_coverage_policy.SOURCE_PRIORITY_RANK["discovered"],
    )
    channel = str(variant.get("artifactChannel") or "").casefold()
    channel_rank = 0 if channel == "stable" else 1 if channel == "testing" else 2
    covered_rank = 0 if plugin_coverage_policy.current_has_artifact_coverage(
        current.get(int(variant.get("variantId") or 0))
    ) else 1
    return covered_rank, source_rank, channel_rank, int(variant.get("variantId") or 0)


def _manual_item(seed: dict[str, Any], variant: dict[str, Any], current: dict[str, Any] | None, generated_at: str) -> dict[str, Any]:
    reasons = scan_queue.due_reasons(
        variant,
        current,
        artifact_analysis_revision=str(seed.get("artifactAnalysisRevision") or ""),
        manual=True,
    )
    return scan_queue._queue_item(
        variant,
        current,
        reasons,
        catalog_revision=str(seed.get("catalogRevision") or ""),
        catalog_identity_epoch=str(seed.get("catalogIdentityEpoch") or ""),
        definitions_revision=str(seed.get("definitionsRevision") or ""),
        scanner_revision=str(seed.get("scannerRevision") or ""),
        artifact_analysis_revision=str(seed.get("artifactAnalysisRevision") or ""),
        rule_set_revision=str(seed.get("ruleSetRevision") or ""),
        generated_at=generated_at,
    )


def build_scan_overlay(
    *, queue_seed: Path, catalog_root: Path, evidence_root: Path, operations_root: Path | None,
    output: Path, report_path: Path,
) -> dict[str, Any]:
    seed = read_json(queue_seed, {}) or {}
    if seed.get("schema") != scan_queue.SEED_SCHEMA:
        raise ValueError("unsupported SigmaScope queue seed")
    requests, invalid = _load_requests(operations_root, "scans", validate_scan_request)
    if not requests:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(queue_seed.read_bytes())
        report = {
            "schema": SCAN_OVERLAY_SCHEMA,
            "baseQueueSeedRevision": str(seed.get("queueSeedRevision") or ""),
            "effectiveQueueSeedRevision": str(seed.get("queueSeedRevision") or ""),
            "acceptedRequestFiles": 0,
            "invalidRequestFiles": invalid,
            "activeRequestCount": 0,
            "activePluginCount": 0,
            "plugins": [],
        }
        write_json(report_path, report)
        return report

    variants = scan_queue.catalog_variants(catalog_root)
    current = scan_queue.evidence_current(evidence_root)
    variants_by_plugin: dict[int, list[dict[str, Any]]] = {}
    for variant in variants:
        plugin_id = int(variant.get("pluginId") or 0)
        if plugin_id > 0:
            variants_by_plugin.setdefault(plugin_id, []).append(dict(variant))
    latest_scan = _latest_scan_by_plugin(variants, current)

    active_by_plugin: dict[int, list[dict[str, Any]]] = {}
    plugin_report: dict[int, dict[str, Any]] = {}
    for request in requests:
        requested_at = _timestamp(request["requestedAtUtc"])[1]
        for plugin_id in request["pluginIds"]:
            candidates = variants_by_plugin.get(plugin_id) or []
            if not candidates:
                plugin_report[plugin_id] = {"pluginId": plugin_id, "state": "rejected", "reason": "unknown-or-no-artifact"}
                continue
            satisfied_at = latest_scan.get(plugin_id)
            if satisfied_at is not None and satisfied_at >= requested_at:
                plugin_report.setdefault(plugin_id, {"pluginId": plugin_id, "state": "satisfied", "satisfiedAtUtc": scan_queue.utc_now(satisfied_at)})
                continue
            active_by_plugin.setdefault(plugin_id, []).append(request)

    if not active_by_plugin:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(queue_seed.read_bytes())
        report = {
            "schema": SCAN_OVERLAY_SCHEMA,
            "baseQueueSeedRevision": str(seed.get("queueSeedRevision") or ""),
            "effectiveQueueSeedRevision": str(seed.get("queueSeedRevision") or ""),
            "acceptedRequestFiles": len(requests),
            "invalidRequestFiles": invalid,
            "activeRequestCount": 0,
            "activePluginCount": 0,
            "plugins": [plugin_report[key] for key in sorted(plugin_report)],
        }
        write_json(report_path, report)
        return report

    effective = copy.deepcopy(seed)
    items = [dict(item) for item in effective.get("items") or [] if isinstance(item, dict)]
    by_variant = {
        int(item.get("variantId") or 0): item
        for item in items
        if str(item.get("workType") or "") == "artifact" and int(item.get("variantId") or 0) > 0
    }
    generated_at = str(seed.get("generatedAtUtc") or scan_queue.utc_now())
    all_active_ids: set[str] = set()

    covered_plugins = {
        plugin_id
        for plugin_id, candidates in variants_by_plugin.items()
        if any(plugin_coverage_policy.current_has_artifact_coverage(current.get(int(row.get("variantId") or 0))) for row in candidates)
    }

    for plugin_id in sorted(active_by_plugin):
        active_requests = sorted(active_by_plugin[plugin_id], key=lambda row: (row["requestedAtUtc"], row["requestId"]))
        request_ids = [str(row["requestId"]) for row in active_requests]
        all_active_ids.update(request_ids)
        candidates = sorted(variants_by_plugin[plugin_id], key=lambda row: _variant_rank(row, current))
        variant = dict(candidates[0])
        variant["pluginHasCurrentScan"] = plugin_id in covered_plugins
        variant_id = int(variant["variantId"])
        current_row = current.get(variant_id)
        item = by_variant.get(variant_id)
        if item is None:
            item = _manual_item(seed, variant, current_row, generated_at)
            items.append(item)
            by_variant[variant_id] = item
        reasons = list(dict.fromkeys(["manual", *[str(value) for value in item.get("reasons") or [] if str(value)]]))
        reasons.sort(key=lambda reason: (-scan_queue.REASON_PRIORITIES.get(reason, 0), reason))
        base_fingerprint = str(item.get("targetFingerprint") or "")
        item["reasons"] = reasons
        item["primaryReason"] = reasons[0] if reasons else "manual"
        item["priority"] = max(int(item.get("priority") or 0), scan_queue.REASON_PRIORITIES["manual"])
        item["operatorNudgeCount"] = len(active_requests)
        item["operatorNudgeScore"] = min(MAX_NUDGE_SCORE, len(active_requests) * NUDGE_SCORE_INCREMENT)
        item["operatorRequestIds"] = request_ids
        item["operatorLatestRequestedAtUtc"] = active_requests[-1]["requestedAtUtc"]
        item["targetFingerprint"] = f"artifact-target-v2-{digest({'base': base_fingerprint, 'operatorRequestIds': request_ids})[:20]}"
        plugin_report[plugin_id] = {
            "pluginId": plugin_id,
            "state": "queued-intent",
            "variantId": variant_id,
            "queueKey": str(item.get("queueKey") or ""),
            "nudgeCount": len(active_requests),
            "nudgeScore": int(item["operatorNudgeScore"]),
            "requestIds": request_ids,
        }

    items.sort(key=lambda item: scan_queue._selection_sort_key(item, covered_plugins))
    effective["items"] = items
    counts = dict(effective.get("counts") or {})
    counts["manual"] = sum(1 for item in items if "manual" in (item.get("reasons") or []))
    counts["queued"] = len(items)
    effective["counts"] = counts
    semantic = {
        "schema": SCAN_OVERLAY_SCHEMA,
        "baseQueueSeedRevision": str(seed.get("queueSeedRevision") or ""),
        "operatorRequestIds": sorted(all_active_ids),
        "items": [
            {
                "queueKey": str(item.get("queueKey") or ""),
                "targetFingerprint": str(item.get("targetFingerprint") or ""),
                "operatorNudgeScore": int(item.get("operatorNudgeScore") or 0),
            }
            for item in items
            if item.get("operatorRequestIds")
        ],
    }
    effective["queueSeedRevision"] = f"queue-seed-v2-roboscope-{digest(semantic)[:16]}"
    effective["operatorOverlay"] = {
        "schema": SCAN_OVERLAY_SCHEMA,
        "baseQueueSeedRevision": str(seed.get("queueSeedRevision") or ""),
        "activeRequestCount": len(all_active_ids),
        "activePluginCount": len(active_by_plugin),
        "invalidRequestCount": len(invalid),
        "authority": "scheduling-intent-only",
    }
    write_json(output, effective)
    report = {
        "schema": SCAN_OVERLAY_SCHEMA,
        "baseQueueSeedRevision": str(seed.get("queueSeedRevision") or ""),
        "effectiveQueueSeedRevision": effective["queueSeedRevision"],
        "acceptedRequestFiles": len(requests),
        "invalidRequestFiles": invalid,
        "activeRequestCount": len(all_active_ids),
        "activePluginCount": len(active_by_plugin),
        "plugins": [plugin_report[key] for key in sorted(plugin_report)],
    }
    write_json(report_path, report)
    return report


def project_source_candidates(*, operations_root: Path | None, output: Path) -> dict[str, Any]:
    requests, invalid = _load_requests(operations_root, "sources", validate_source_request)
    sources: list[dict[str, Any]] = []
    repositories: list[dict[str, Any]] = []
    seen_sources: set[str] = set()
    seen_repositories: set[str] = set()
    for request in requests:
        normalized = request["normalized"]
        provenance = {
            "requestId": request["requestId"],
            "requestedAtUtc": request["requestedAtUtc"],
            "requestedType": request["type"],
        }
        if normalized["kind"] == "repository":
            repository_url = normalized["repositoryUrl"]
            key = repository_url.casefold()
            if key in seen_repositories:
                continue
            seen_repositories.add(key)
            owner, repository = repository_url.rstrip("/").split("/")[-2:]
            repositories.append({
                "repositoryUrl": repository_url,
                "owner": owner,
                "repository": repository,
                "reason": "roboscope-git-source-request",
                "sourceUrl": "",
                "collectorId": discovery_collectors.COLLECTOR_ROBOSCOPE,
            })
        else:
            url = normalized["url"]
            key = url.rstrip("/").casefold()
            if key in seen_sources:
                continue
            seen_sources.add(key)
            sources.append({
                "url": url,
                "provider": urllib.parse.urlparse(url).netloc,
                "kind": "operator-request",
                "discoveredBy": "roboscope-git-request",
                "collectorId": discovery_collectors.COLLECTOR_ROBOSCOPE,
                "sourceRepoUrl": "",
                "provenance": provenance,
            })
    document = {
        "schema": SOURCE_CANDIDATES_SCHEMA,
        "acceptedRequestFiles": len(requests),
        "invalidRequestFiles": invalid,
        "sources": sources,
        "repositoryCandidates": repositories,
    }
    write_json(output, document)
    return document


def merge_source_candidates(*, base: Path, operator: Path, output: Path) -> dict[str, Any]:
    base_doc = read_json(base, {}) or {}
    operator_doc = read_json(operator, {}) or {}
    if not isinstance(base_doc, dict) or not isinstance(base_doc.get("sources"), list):
        raise ValueError("base discovery candidate document is invalid")
    if operator_doc.get("schema") != SOURCE_CANDIDATES_SCHEMA:
        raise ValueError("operator source candidate document is invalid")
    merged = copy.deepcopy(base_doc)
    source_rows = [dict(row) for row in merged.get("sources") or [] if isinstance(row, dict)]
    seen_sources = {str(row.get("url") or "").rstrip("/").casefold() for row in source_rows}
    for row in operator_doc.get("sources") or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("url") or "").rstrip("/").casefold()
        if key and key not in seen_sources:
            seen_sources.add(key)
            source_rows.append(dict(row))
    repository_rows = [dict(row) for row in merged.get("repositoryCandidates") or [] if isinstance(row, dict)]
    seen_repositories = {str(row.get("repositoryUrl") or "").rstrip("/").casefold() for row in repository_rows}
    for row in operator_doc.get("repositoryCandidates") or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("repositoryUrl") or "").rstrip("/").casefold()
        if key and key not in seen_repositories:
            seen_repositories.add(key)
            repository_rows.append(dict(row))
    merged["sources"] = source_rows
    merged["repositoryCandidates"] = repository_rows
    metadata = dict(merged.get("metadata") or {})
    metadata["roboscopeOperations"] = {
        "acceptedRequestFiles": int(operator_doc.get("acceptedRequestFiles") or 0),
        "invalidRequestFiles": len(operator_doc.get("invalidRequestFiles") or []),
        "sourceCandidates": len(operator_doc.get("sources") or []),
        "repositoryCandidates": len(operator_doc.get("repositoryCandidates") or []),
    }
    merged["metadata"] = metadata
    write_json(output, merged)
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    overlay = sub.add_parser("build-scan-overlay")
    overlay.add_argument("--queue-seed", required=True, type=Path)
    overlay.add_argument("--catalog-root", required=True, type=Path)
    overlay.add_argument("--evidence-root", required=True, type=Path)
    overlay.add_argument("--operations-root", type=Path)
    overlay.add_argument("--output", required=True, type=Path)
    overlay.add_argument("--report", required=True, type=Path)

    project = sub.add_parser("project-source-candidates")
    project.add_argument("--operations-root", type=Path)
    project.add_argument("--output", required=True, type=Path)

    merge = sub.add_parser("merge-source-candidates")
    merge.add_argument("--base", required=True, type=Path)
    merge.add_argument("--operator", required=True, type=Path)
    merge.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "build-scan-overlay":
        result = build_scan_overlay(
            queue_seed=args.queue_seed, catalog_root=args.catalog_root, evidence_root=args.evidence_root,
            operations_root=args.operations_root, output=args.output, report_path=args.report,
        )
        print(json.dumps({
            "effectiveQueueSeedRevision": result["effectiveQueueSeedRevision"],
            "activeRequestCount": result["activeRequestCount"],
            "activePluginCount": result["activePluginCount"],
            "invalidRequestCount": len(result["invalidRequestFiles"]),
        }, sort_keys=True))
        return 0
    if args.command == "project-source-candidates":
        result = project_source_candidates(operations_root=args.operations_root, output=args.output)
        print(json.dumps({
            "acceptedRequestFiles": result["acceptedRequestFiles"],
            "invalidRequestCount": len(result["invalidRequestFiles"]),
            "sources": len(result["sources"]),
            "repositoryCandidates": len(result["repositoryCandidates"]),
        }, sort_keys=True))
        return 0
    if args.command == "merge-source-candidates":
        result = merge_source_candidates(base=args.base, operator=args.operator, output=args.output)
        print(json.dumps({
            "sources": len(result.get("sources") or []),
            "repositoryCandidates": len(result.get("repositoryCandidates") or []),
        }, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
