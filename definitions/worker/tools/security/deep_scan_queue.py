"""Durable queue projection for Stigma-1-requested deep analysis.

The queue is evidence-acquisition authority only. It never changes findings or severity.
Requests originate from matched, frozen rules and are deduplicated by exact artifact,
baseline, profile revision and semantic scan depth. Multiple rules requesting the same
work coalesce; the deepest requested depth wins.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    from . import deep_scan_contract, security_evidence_v2
except ImportError:
    import deep_scan_contract  # type: ignore
    import security_evidence_v2  # type: ignore

try:
    from source_stability import stable_source_priority
except ImportError:
    import sys
    _CATALOG = Path(__file__).resolve().parents[1] / "catalog"
    if str(_CATALOG) not in sys.path:
        sys.path.insert(0, str(_CATALOG))
    from source_stability import stable_source_priority  # type: ignore

MAX_REQUESTERS = 32
MAX_QUEUE_ITEMS = 5000


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _variant_rows(evidence_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
        report = current.get("report_json") if isinstance(current.get("report_json"), Mapping) else {}
        plugin = payload.get("plugin") if isinstance(payload.get("plugin"), Mapping) else {}
        variant = payload.get("variant") if isinstance(payload.get("variant"), Mapping) else {}
        source = payload.get("source") if isinstance(payload.get("source"), Mapping) else {}
        manifest = report.get("manifestObservation") if isinstance(report.get("manifestObservation"), Mapping) else {}
        identity = report.get("artifactIdentity") if isinstance(report.get("artifactIdentity"), Mapping) else {}
        rows.append({
            "variantId": int(payload.get("variantId") or entry.get("variantId") or 0),
            "internalName": str(plugin.get("internal_name") or ""),
            "name": str(variant.get("name") or plugin.get("canonical_name") or plugin.get("internal_name") or ""),
            "assemblyVersion": str(variant.get("assembly_version") or current.get("assembly_version") or ""),
            "sourceName": str(source.get("name") or ""),
            "sourceUrl": str(source.get("url") or ""),
            "isOfficial": bool(source.get("is_official") or source.get("isOfficial")),
            "artifactSha256": str(current.get("artifact_sha256") or identity.get("artifactSha256") or "").strip().lower(),
            "artifactUrl": str(identity.get("resolvedArtifactUrl") or manifest.get("downloadUrl") or ""),
        })
    return rows


def _source_rank(row: Mapping[str, Any]) -> tuple[int, str, int]:
    priority = stable_source_priority(str(row.get("sourceName") or ""), str(row.get("sourceUrl") or ""), bool(row.get("isOfficial")))
    return (priority if priority is not None else 1000, str(row.get("sourceName") or "").casefold(), int(row.get("variantId") or 0))


def _baseline(target: Mapping[str, Any], rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    candidates = [dict(row) for row in rows if int(row.get("variantId") or 0) != int(target.get("variantId") or 0)
                  and str(row.get("internalName") or "").casefold() == str(target.get("internalName") or "").casefold()
                  and str(row.get("assemblyVersion") or "") == str(target.get("assemblyVersion") or "")
                  and str(row.get("artifactSha256") or "") and str(row.get("artifactSha256") or "") != str(target.get("artifactSha256") or "")
                  and stable_source_priority(str(row.get("sourceName") or ""), str(row.get("sourceUrl") or ""), bool(row.get("isOfficial"))) is not None]
    if not candidates:
        return {}
    candidates.sort(key=_source_rank)
    return candidates[0]


def request_identity(item: Mapping[str, Any]) -> str:
    semantic = {
        "variantId": int(item.get("variantId") or 0),
        "artifactSha256": str(item.get("artifactSha256") or ""),
        "baselineArtifactSha256": str(item.get("baselineArtifactSha256") or ""),
        "profile": str(item.get("profile") or ""),
        "depth": str(item.get("depth") or "standard"),
        "profileSetRevision": str(item.get("profileSetRevision") or ""),
    }
    return "deep-scan-v1-" + _sha(semantic)[:24]


def _queue_revision(items: Iterable[Mapping[str, Any]]) -> str:
    volatile = {"requestedAtUtc", "startedAtUtc", "completedAtUtc", "lastAttemptAtUtc", "lastError"}
    semantic = [{k: v for k, v in dict(item).items() if k not in volatile} for item in items]
    return "deep-queue-v1-" + _sha(semantic)[:24]


def _apply_profile_budget(item: dict[str, Any], depth: str) -> None:
    status = deep_scan_contract.profile_status(str(item.get("profile") or ""), depth)
    item.update({
        "depth": depth,
        "profileSetRevision": status.get("profileSetRevision", ""),
        "profileAvailable": bool(status.get("available")),
        "executionMode": status.get("executionMode", ""),
        "workflowTimeoutMinutes": int(status.get("workflowTimeoutMinutes") or 20),
        "workerBudgetSeconds": int(status.get("workerBudgetSeconds") or 900),
        "analysisFamilies": list(status.get("analysisFamilies") or []),
    })


def build_queue(evidence_root: Path, analysis_requests: Iterable[Mapping[str, Any]], previous: Mapping[str, Any] | None = None) -> dict[str, Any]:
    rows = _variant_rows(evidence_root)
    by_id = {int(row["variantId"]): row for row in rows if int(row["variantId"]) > 0}
    previous_by_id = {str(item.get("requestId") or ""): dict(item) for item in (previous or {}).get("items") or [] if isinstance(item, Mapping)}
    grouped: dict[tuple[int, str, str], dict[str, Any]] = {}
    for request in analysis_requests:
        variant_id = int(request.get("variantId") or 0)
        target = by_id.get(variant_id)
        if not target or not target.get("artifactSha256"):
            continue
        profile = str(request.get("profile") or "")
        depth = deep_scan_contract.normalize_depth(request.get("depth"))
        compare_with = str(request.get("compareWith") or "none")
        baseline = _baseline(target, rows) if compare_with == "stable-artifact-baseline" else {}
        key = (variant_id, profile, str(baseline.get("artifactSha256") or ""))
        item = grouped.get(key)
        if item is None:
            item = {
                "schema": deep_scan_contract.QUEUE_ITEM_SCHEMA,
                "variantId": variant_id,
                "internalName": target.get("internalName", ""),
                "name": target.get("name", ""),
                "assemblyVersion": target.get("assemblyVersion", ""),
                "artifactSha256": target.get("artifactSha256", ""),
                "artifactUrl": target.get("artifactUrl", ""),
                "sourceName": target.get("sourceName", ""),
                "profile": profile,
                "compareWith": compare_with,
                "baselineVariantId": int(baseline.get("variantId") or 0),
                "baselineArtifactSha256": str(baseline.get("artifactSha256") or ""),
                "baselineArtifactUrl": str(baseline.get("artifactUrl") or ""),
                "baselineSourceName": str(baseline.get("sourceName") or ""),
                "requestedBy": [],
                "reasons": [],
            }
            _apply_profile_budget(item, depth)
            grouped[key] = item
        elif deep_scan_contract.DEPTH_ORDER[depth] > deep_scan_contract.DEPTH_ORDER[str(item.get("depth") or "standard")]:
            _apply_profile_budget(item, depth)
        requester = {
            "ruleId": str(request.get("ruleId") or ""),
            "ruleRevision": str(request.get("ruleRevision") or ""),
            "requestedDepth": depth,
        }
        if requester not in item["requestedBy"] and len(item["requestedBy"]) < MAX_REQUESTERS:
            item["requestedBy"].append(requester)
        reason = str(request.get("reason") or "")
        if reason and reason not in item["reasons"]:
            item["reasons"].append(reason)

    items: list[dict[str, Any]] = []
    for item in grouped.values():
        if item["compareWith"] == "stable-artifact-baseline" and not item["baselineArtifactSha256"]:
            item["state"] = "blocked"
            item["blockedReason"] = "no divergent stable artifact baseline is currently available"
        elif not item["profileAvailable"]:
            item["state"] = "blocked"
            item["blockedReason"] = str(deep_scan_contract.profile_status(item["profile"], item["depth"]).get("blockedReason") or "profile unavailable")
        else:
            item["state"] = "pending"
            item["blockedReason"] = ""
        item["requestedBy"].sort(key=lambda r: (r["ruleId"], r["ruleRevision"], r["requestedDepth"]))
        item["reasons"].sort()
        item["requestId"] = request_identity(item)
        old = previous_by_id.get(item["requestId"])
        if old:
            if str(old.get("state") or "") in {"complete", "running", "retry"}:
                for key in ("state", "completedAtUtc", "startedAtUtc", "result", "attemptCount", "lastAttemptAtUtc", "lastError"):
                    if key in old:
                        item[key] = old[key]
            item["requestedAtUtc"] = str(old.get("requestedAtUtc") or _utc())
        else:
            item["requestedAtUtc"] = _utc()
        item.setdefault("attemptCount", 0)
        items.append(item)
    items.sort(key=lambda x: (str(x.get("state")), -deep_scan_contract.DEPTH_ORDER.get(str(x.get("depth") or "standard"), 0), str(x.get("internalName")).casefold(), int(x.get("variantId") or 0), str(x.get("profile"))))
    if len(items) > MAX_QUEUE_ITEMS:
        raise RuntimeError(f"deep-scan queue exceeds safety ceiling of {MAX_QUEUE_ITEMS} items")
    queue_revision = _queue_revision(items)
    generated = _utc()
    if previous and str(previous.get("queueRevision") or "") == queue_revision:
        generated = str(previous.get("generatedAtUtc") or generated)
    return {
        "schema": deep_scan_contract.QUEUE_SCHEMA,
        "profileSetRevision": deep_scan_contract.profile_set_revision(),
        "queueRevision": queue_revision,
        "generatedAtUtc": generated,
        "authority": "frozen-reviewed-rule-evidence-acquisition-only",
        "productionFindingsWriteBack": False,
        "items": items,
        "counts": {state: sum(1 for item in items if item.get("state") == state) for state in ("pending", "running", "retry", "blocked", "complete")},
    }


def select_request(queue: Mapping[str, Any], request_id: str = "") -> dict[str, Any]:
    candidates = [dict(item) for item in queue.get("items") or [] if isinstance(item, Mapping)
                  and str(item.get("state") or "") in {"pending", "retry"}
                  and bool(item.get("profileAvailable"))
                  and (not request_id or str(item.get("requestId") or "") == request_id)]
    if not candidates:
        return {}
    candidates.sort(key=lambda item: (-deep_scan_contract.DEPTH_ORDER.get(str(item.get("depth") or "standard"), 0), str(item.get("requestedAtUtc") or ""), str(item.get("requestId") or "")))
    item = candidates[0]
    # Keep workflow timeouts inside a code-owned hard ceiling even if state is tampered.
    item["workflowTimeoutMinutes"] = max(10, min(70, int(item.get("workflowTimeoutMinutes") or 20)))
    item["workerBudgetSeconds"] = max(60, min(55 * 60, int(item.get("workerBudgetSeconds") or 900)))
    return item


def write_queue(path: Path, queue: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(queue, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def complete_request(queue: Mapping[str, Any], result: Mapping[str, Any], *, result_path: str) -> dict[str, Any]:
    request_id = str(result.get("requestId") or "")
    updated = json.loads(json.dumps(queue))
    found = False
    for item in updated.get("items") or []:
        if not isinstance(item, dict) or str(item.get("requestId") or "") != request_id:
            continue
        found = True
        item["state"] = "complete"
        item["completedAtUtc"] = _utc()
        item["lastError"] = ""
        item["result"] = {
            "schema": str(result.get("schema") or ""),
            "path": result_path,
            "profile": str(result.get("profile") or ""),
            "depth": str(result.get("depth") or item.get("depth") or "standard"),
            "pluginCodeExecuted": bool(result.get("pluginCodeExecuted")),
            "behaviorExecutionPerformed": bool(result.get("behaviorExecutionPerformed")),
            "comparison": dict(result.get("comparison") or {}),
            "budget": dict(result.get("budget") or {}),
        }
        break
    if not found:
        raise ValueError(f"deep-scan request is not present in queue: {request_id}")
    updated["generatedAtUtc"] = _utc()
    updated["counts"] = {state: sum(1 for item in updated.get("items") or [] if isinstance(item, dict) and item.get("state") == state) for state in ("pending", "running", "retry", "blocked", "complete")}
    updated["queueRevision"] = _queue_revision([item for item in updated.get("items") or [] if isinstance(item, Mapping)])
    return updated


def _main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Build/update Omega deep-scan queue state")
    sub = parser.add_subparsers(dest="command", required=True)
    finish = sub.add_parser("complete")
    finish.add_argument("--queue", type=Path, required=True)
    finish.add_argument("--result", type=Path, required=True)
    finish.add_argument("--output-root", type=Path, required=True)
    select = sub.add_parser("select")
    select.add_argument("--queue", type=Path, required=True)
    select.add_argument("--request-id", default="")
    select.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    if args.command == "complete":
        queue = json.loads(args.queue.read_text(encoding="utf-8"))
        result = json.loads(args.result.read_text(encoding="utf-8"))
        out = args.output_root.resolve()
        out.mkdir(parents=True, exist_ok=True)
        result_rel = Path("results") / (str(result.get("requestId") or "unknown") + ".json")
        result_dest = out / result_rel
        result_dest.parent.mkdir(parents=True, exist_ok=True)
        result_dest.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        updated = complete_request(queue, result, result_path=result_rel.as_posix())
        write_queue(out / "index.json", updated)
        return 0
    if args.command == "select":
        queue = json.loads(args.queue.read_text(encoding="utf-8"))
        item = select_request(queue, args.request_id)
        if not item:
            payload = {"request_id": "", "profile": "", "depth": "standard", "timeout_minutes": 20, "worker_budget_seconds": 900}
            print("No executable pending deep-scan request.")
        else:
            payload = {
                "request_id": str(item.get("requestId") or ""),
                "profile": str(item.get("profile") or ""),
                "depth": str(item.get("depth") or "standard"),
                "timeout_minutes": int(item.get("workflowTimeoutMinutes") or 20),
                "worker_budget_seconds": int(item.get("workerBudgetSeconds") or 900),
            }
        print(json.dumps(payload, sort_keys=True))
        if args.github_output:
            args.github_output.parent.mkdir(parents=True, exist_ok=True)
            with args.github_output.open("a", encoding="utf-8") as stream:
                for key, value in payload.items():
                    stream.write(f"{key}={value}\n")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(_main())
