"""Human-facing per-plugin Security Evidence report with bounded SigmaScope correlation.

Published Security Evidence v2 remains the only security authority.  Authenticated GitHub
Actions data is an optional, explicitly acquired operational overlay that can explain where
queued work is, but can never replace a published scan or mutate queue/catalog/rule state.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Iterable, Mapping

import deltascope_scan_queue
import deltascope_workbench

SCHEMA = "omega.deltascope.plugin-scan-report.v1"
OPERATION_SCHEMA = "omega.deltascope.sigmascope-operation.v1"
PLAN_SCHEMA = "omega.sigmascope-parallel-drain-plan.v1"
PLAN_AUTHORITY = "read-only-production-drain-planning"
DRAIN_WORKFLOW = "sigmascope-parallel-drain.yml"
DRAIN_BRANCH = "sigmascope"
ALLOWED_OPERATIONAL_ARTIFACTS = frozenset({"omega-sigmascope-drain-plan"})
ALLOWED_OPERATIONAL_FILES = frozenset({
    "sigmascope-drain-plan.json",
    "roboscope-effective-scan-queue.json",
    "roboscope-operations-report.json",
})
MAX_OPERATIONAL_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_OPERATIONAL_FILE_BYTES = 1024 * 1024
MAX_OPERATIONAL_FILES = 8
MAX_PLAN_ASSIGNMENTS = 64
MAX_PLAN_WORKERS = 8
MAX_KEYS_PER_WORKER = 16
MAX_QUEUE_KEY_CHARS = 1024
MAX_FINDING_EVIDENCE_ITEMS = 8

STATUS_VALUES = (
    "Not queued", "Queued", "Assigned", "Scanning", "Worker completed",
    "Waiting for other workers", "Waiting for merge", "Waiting for publication",
    "Published", "Retry pending", "Failed", "Timed out", "Stale / superseded", "Unknown",
)
_RUNNING = {"queued", "in_progress", "requested", "waiting", "pending"}
_FAILURE = {"failure", "action_required", "startup_failure"}

_CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Specific capability families must precede generic process/shell/network tokens.
    ("PowerShell", ("powershell", "pwsh")),
    ("Memory / process manipulation", ("virtualprotect", "writeprocessmemory", "openprocess", "remote thread", "createremotethread", "process memory")),
    ("Hooks / listeners", ("setwindowshook", "keyboardhook", "mousehook", "hook", "listener")),
    ("Clipboard / credential APIs", ("clipboard", "credential", "password", "credread", "dpapi")),
    ("Registry access", ("registry", "regkey", "regopen")),
    ("Native loading", ("native-load", "loadlibrary", "nativelibrary", "dlopen")),
    ("P/Invoke / native APIs", ("pinvoke", "dllimport", "native import", "win32")),
    ("Process / shell execution", ("process.start", "process launch", "shell", "cmd.exe", "bash", "execute process")),
    ("Filesystem access", ("filesystem", "file.", "directory", "writeall", "readall", "path.")),
    ("Network capabilities", ("network", "http", "socket", "webrequest", "websocket", "dns", "tcp", "udp")),
    ("Dependencies", ("dependency", "package", "nuget", "assembly-reference")),
    ("IPC", ("ipc", "interplugin", "callgate")),
    ("Source attribution", ("source-attribution", "source attribution", "provenance")),
    ("Source / artifact divergence", ("source-artifact", "divergence", "source mismatch")),
    ("Secondary engines", ("clamav", "yara", "secondary")),
    ("Automation capabilities", ("automation", "input", "key press", "mouse")),
    ("Deep / targeted analysis", ("deep-scan", "targeted-analysis", "analysis-request", "reanalysis")),
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _text(value: Any) -> str:
    return str(value or "").strip()


def _integer(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _strict_int(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"SigmaScope planning JSON has invalid {field}") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"SigmaScope planning JSON has out-of-range {field}")
    return parsed


def _iso(value: Any) -> str:
    return _text(value)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any) -> dt.datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except ValueError:
        return None


def _elapsed_seconds(start: Any, end: Any) -> int | None:
    left, right = _parse_utc(start), _parse_utc(end)
    if left is None or right is None or right < left:
        return None
    return int((right - left).total_seconds())


def _bounded(value: Any, *, depth: int = 0) -> Any:
    """Small deterministic evidence preview; never a substitute for raw Evidence."""
    if depth >= 3:
        return "…"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(str(k) for k in value)[:12]:
            result[key] = _bounded(value.get(key), depth=depth + 1)
        if len(value) > 12:
            result["_truncatedFields"] = len(value) - 12
        return result
    if isinstance(value, list):
        result = [_bounded(item, depth=depth + 1) for item in value[:MAX_FINDING_EVIDENCE_ITEMS]]
        if len(value) > MAX_FINDING_EVIDENCE_ITEMS:
            result.append(f"… {len(value) - MAX_FINDING_EVIDENCE_ITEMS} more")
        return result
    if isinstance(value, str):
        return value if len(value) <= 600 else value[:597] + "…"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:600]


def _safe_github_url(value: Any) -> str:
    text = _text(value)
    return text if text.startswith("https://github.com/") else ""


def _redact_secret(value: Any) -> str:
    text = str(value or "")
    # Error messages should not normally contain request headers, but keep the API
    # payload fail-safe even if an opener/client implementation includes a token.
    text = re.sub(r"github_pat_[A-Za-z0-9_]+", "[redacted-github-token]", text)
    text = re.sub(r"\bgh[opusr]_[A-Za-z0-9]+", "[redacted-github-token]", text)
    return text[:1200]


def _api_repository(repository: str) -> str:
    return urllib.parse.quote(repository, safe="/")


def _request_bytes(client: Any, url: str, *, maximum: int, accept: str = "application/octet-stream") -> bytes:
    if not str(url).startswith("https://api.github.com/"):
        raise ValueError("operational artifact URL must be a GitHub API URL")
    request = urllib.request.Request(url, headers=client._headers(accept=accept))
    with client._opener(request, timeout=10) as response:
        raw = response.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("operational artifact exceeded the DeltaScope safety bound")
    return raw


def _safe_zip_member(info: zipfile.ZipInfo) -> str:
    name = str(info.filename or "")
    if not name or "\\" in name or name.startswith("/"):
        raise ValueError("operational artifact contains an unsafe path")
    parts = [part for part in name.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts) or len(parts) > 2:
        raise ValueError("operational artifact contains an unsafe path")
    mode = (info.external_attr >> 16) & 0o177777
    if mode and stat.S_ISLNK(mode):
        raise ValueError("operational artifact may not contain symlinks")
    if info.flag_bits & 0x1:
        raise ValueError("operational artifact may not contain encrypted files")
    if info.is_dir():
        return ""
    basename = parts[-1]
    if basename not in ALLOWED_OPERATIONAL_FILES:
        raise ValueError(f"unexpected operational artifact file: {basename}")
    if info.file_size < 0 or info.file_size > MAX_OPERATIONAL_FILE_BYTES:
        raise ValueError("operational artifact member exceeded the DeltaScope safety bound")
    if info.compress_size > 0 and info.file_size > max(64 * 1024, info.compress_size * 100):
        raise ValueError("operational artifact has a suspicious compression ratio")
    return basename


def parse_operational_artifact(artifact_name: str, archive: bytes) -> dict[str, Any]:
    """Parse only the allow-listed production drain planning artifact, entirely in memory."""
    if artifact_name not in ALLOWED_OPERATIONAL_ARTIFACTS:
        raise ValueError("operational artifact is not allow-listed")
    if len(archive) > MAX_OPERATIONAL_ARCHIVE_BYTES:
        raise ValueError("operational artifact archive exceeded the DeltaScope safety bound")
    try:
        zf = zipfile.ZipFile(io.BytesIO(archive), "r")
    except zipfile.BadZipFile as exc:
        raise ValueError("operational artifact is not a valid ZIP archive") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_OPERATIONAL_FILES:
            raise ValueError("operational artifact contains too many files")
        declared_total = sum(max(0, int(info.file_size or 0)) for info in infos)
        if declared_total > MAX_OPERATIONAL_ARCHIVE_BYTES:
            raise ValueError("operational artifact expanded size exceeded the DeltaScope safety bound")
        files: dict[str, bytes] = {}
        for info in infos:
            basename = _safe_zip_member(info)
            if not basename:
                continue
            if basename in files:
                raise ValueError(f"operational artifact contains duplicate {basename}")
            raw = zf.read(info)
            if len(raw) != info.file_size or len(raw) > MAX_OPERATIONAL_FILE_BYTES:
                raise ValueError("operational artifact member size was invalid")
            files[basename] = raw
    if "sigmascope-drain-plan.json" not in files:
        raise ValueError("operational artifact is missing sigmascope-drain-plan.json")
    try:
        plan = json.loads(files["sigmascope-drain-plan.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("SigmaScope planning JSON is malformed") from exc
    return validate_drain_plan(plan)


def _bounded_queue_key(value: Any) -> str:
    key = _text(value)
    if not key or len(key) > MAX_QUEUE_KEY_CHARS or "\r" in key or "\n" in key:
        raise ValueError("SigmaScope planning JSON contains an invalid queue key")
    return key


def validate_drain_plan(value: Any) -> dict[str, Any]:
    """Fail closed on anything other than the current bounded production plan contract."""
    if not isinstance(value, Mapping):
        raise ValueError("SigmaScope planning JSON must be an object")
    if value.get("schema") != PLAN_SCHEMA or value.get("authority") != PLAN_AUTHORITY:
        raise ValueError("unsupported SigmaScope planning schema or authority")
    assignments = value.get("assignments")
    matrix = _mapping(value.get("matrix")).get("include")
    if not isinstance(assignments, list) or not isinstance(matrix, list):
        raise ValueError("SigmaScope planning JSON is missing assignments or matrix.include")
    if len(assignments) > MAX_PLAN_ASSIGNMENTS or len(matrix) > MAX_PLAN_WORKERS:
        raise ValueError("SigmaScope planning JSON exceeds bounded worker/assignment limits")

    normalized_assignments: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}
    for raw in assignments:
        if not isinstance(raw, Mapping):
            raise ValueError("SigmaScope planning assignment must be an object")
        queue_key = _bounded_queue_key(raw.get("queueKey"))
        if queue_key in by_key:
            raise ValueError("SigmaScope planning JSON contains duplicate queue keys")
        work_type = _text(raw.get("workType"))
        variant_id = _strict_int(raw.get("variantId"), "variantId", minimum=1, maximum=2_147_483_647)
        if work_type not in {"artifact", "source"}:
            raise ValueError("SigmaScope planning assignment has unsupported work identity")
        item = {
            "queueKey": queue_key,
            "workType": work_type,
            "variantId": variant_id,
            "internalName": _text(raw.get("internalName")),
            "sourceName": _text(raw.get("sourceName")),
            "targetFingerprint": _text(raw.get("targetFingerprint")),
            "priority": _integer(raw.get("priority")),
            "primaryReason": _text(raw.get("primaryReason")),
            "selectionLane": _integer(raw.get("selectionLane")),
            "workerLane": _text(raw.get("workerLane")),
            "releaseUpdate": bool(raw.get("releaseUpdate")),
        }
        normalized_assignments.append(item)
        by_key[queue_key] = item

    normalized_slots: list[dict[str, Any]] = []
    seen_slots: set[int] = set()
    matrix_keys: set[str] = set()
    for raw in matrix:
        if not isinstance(raw, Mapping):
            raise ValueError("SigmaScope matrix slot must be an object")
        slot = _strict_int(raw.get("slot"), "matrix slot", minimum=0, maximum=MAX_PLAN_WORKERS - 1)
        if slot in seen_slots:
            raise ValueError("SigmaScope matrix contains an invalid or duplicate slot")
        seen_slots.add(slot)
        queue_keys = raw.get("queueKeys")
        if not isinstance(queue_keys, list) or len(queue_keys) > MAX_KEYS_PER_WORKER:
            raise ValueError("SigmaScope matrix queueKeys are invalid or oversized")
        safe_keys = [_bounded_queue_key(key) for key in queue_keys]
        if len(set(safe_keys)) != len(safe_keys):
            raise ValueError("SigmaScope matrix contains duplicate queue keys in one slot")
        for key in safe_keys:
            if key not in by_key or key in matrix_keys:
                raise ValueError("SigmaScope matrix key does not map exactly to one assignment")
            matrix_keys.add(key)
        assignment_count = _strict_int(raw.get("assignmentCount"), "matrix assignmentCount", minimum=0, maximum=MAX_KEYS_PER_WORKER)
        if assignment_count != len(safe_keys):
            raise ValueError("SigmaScope matrix assignmentCount does not match queueKeys")
        normalized_slots.append({
            "slot": slot, "lane": _text(raw.get("lane")),
            "queueKeys": safe_keys, "assignmentCount": assignment_count,
        })
    if matrix_keys != set(by_key):
        raise ValueError("SigmaScope matrix does not cover every exact assignment")
    wave = _strict_int(value.get("wave"), "wave", minimum=1, maximum=10_000_000)
    workers = _strict_int(value.get("workers"), "workers", minimum=1, maximum=MAX_PLAN_WORKERS)
    items_per_worker = _strict_int(value.get("itemsPerWorker"), "itemsPerWorker", minimum=1, maximum=MAX_KEYS_PER_WORKER)
    capacity = _strict_int(value.get("capacity"), "capacity", minimum=1, maximum=MAX_PLAN_ASSIGNMENTS)
    if capacity != min(workers * items_per_worker, MAX_PLAN_ASSIGNMENTS):
        raise ValueError("SigmaScope plan capacity is inconsistent with workers/itemsPerWorker")
    if any(int(slot["slot"]) >= workers for slot in normalized_slots):
        raise ValueError("SigmaScope matrix slot exceeds requested worker count")
    for slot in normalized_slots:
        lane = _text(slot.get("lane"))
        for key in slot.get("queueKeys") or []:
            assignment_lane = _text(by_key[key].get("workerLane"))
            if lane and assignment_lane and lane != assignment_lane:
                raise ValueError("SigmaScope matrix lane does not match assignment workerLane")
    assignment_count = _strict_int(value.get("assignmentCount"), "assignmentCount", minimum=0, maximum=MAX_PLAN_ASSIGNMENTS)
    active_worker_count = _strict_int(value.get("activeWorkerCount"), "activeWorkerCount", minimum=0, maximum=MAX_PLAN_WORKERS)
    if assignment_count != len(normalized_assignments):
        raise ValueError("SigmaScope plan assignmentCount is inconsistent")
    if active_worker_count != len(normalized_slots):
        raise ValueError("SigmaScope plan activeWorkerCount is inconsistent")
    if assignment_count > capacity:
        raise ValueError("SigmaScope plan assignments exceed capacity")
    plan_revision = _text(value.get("planRevision"))
    if not plan_revision.startswith("sigmascope-drain-plan-v1-"):
        raise ValueError("SigmaScope planning JSON has invalid planRevision")

    return {
        "schema": PLAN_SCHEMA,
        "authority": PLAN_AUTHORITY,
        "queueSeedRevision": _text(value.get("queueSeedRevision")),
        "catalogRevision": _text(value.get("catalogRevision")),
        "catalogIdentityEpoch": _text(value.get("catalogIdentityEpoch")),
        "evidenceRevision": _text(value.get("evidenceRevision")),
        "evidenceCatalogIdentityEpoch": _text(value.get("evidenceCatalogIdentityEpoch")),
        "baselineSecurityRebuild": bool(value.get("baselineSecurityRebuild")),
        "selectionPolicy": _text(value.get("selectionPolicy")),
        "workerAllocationPolicy": _text(value.get("workerAllocationPolicy")),
        "wave": wave,
        "workers": workers,
        "itemsPerWorker": items_per_worker,
        "capacity": capacity,
        "assignments": normalized_assignments,
        "matrix": {"include": normalized_slots},
        "assignmentCount": assignment_count,
        "activeWorkerCount": active_worker_count,
        "moreParallelEligible": bool(value.get("moreParallelEligible")),
        "serialFallbackRequired": bool(value.get("serialFallbackRequired")),
        "blockedReason": _text(value.get("blockedReason")),
        "queueSummaryBefore": _bounded(_mapping(value.get("queueSummaryBefore"))),
        "planRevision": plan_revision,
    }


def correlate_plan(plan: Mapping[str, Any] | None, queue_key: str, variant_id: int) -> dict[str, Any] | None:
    """Correlate only exact persistent queue-key + variant identity; names are never enough."""
    if not isinstance(plan, Mapping) or not queue_key or variant_id <= 0:
        return None
    assignments = [item for item in plan.get("assignments") or [] if isinstance(item, Mapping)]
    match_index = next((idx for idx, item in enumerate(assignments) if _text(item.get("queueKey")) == queue_key and _integer(item.get("variantId")) == variant_id), None)
    if match_index is None:
        return None
    assignment = dict(assignments[match_index])
    slots = [slot for slot in _mapping(plan.get("matrix")).get("include") or [] if isinstance(slot, Mapping)]
    slot = next((dict(row) for row in slots if queue_key in [str(key) for key in row.get("queueKeys") or []]), None)
    if slot is None:
        return None
    keys = [str(key) for key in slot.get("queueKeys") or []]
    return {
        "assignment": assignment,
        "assignmentOrdinal": match_index + 1,
        "waveAssignmentCount": len(assignments),
        "slot": _integer(slot.get("slot")),
        "lane": _text(slot.get("lane")) or _text(assignment.get("workerLane")),
        "workerAssignmentCount": len(keys),
        "workerAssignmentPosition": keys.index(queue_key) + 1,
        "queueKey": queue_key,
        "variantId": variant_id,
        "completionSemantics": "assignment-position-only",
    }


def _job_projection(row: Mapping[str, Any], *, fetched_at: str) -> dict[str, Any]:
    started = _iso(row.get("started_at") or row.get("created_at"))
    completed = _iso(row.get("completed_at"))
    status = _text(row.get("status")).casefold() or "unknown"
    conclusion = _text(row.get("conclusion")).casefold()
    elapsed_end = completed or (fetched_at if status in _RUNNING else "")
    return {
        "jobId": _integer(row.get("id")),
        "name": _text(row.get("name")),
        "status": status,
        "conclusion": conclusion,
        "startedAtUtc": started,
        "completedAtUtc": completed,
        "elapsedSeconds": _elapsed_seconds(started, elapsed_end),
        "url": _safe_github_url(row.get("html_url")),
    }


def _worker_slot(name: str) -> int | None:
    match = re.search(r"\bslot\s+(\d+)\b", str(name or ""), re.IGNORECASE)
    return int(match.group(1)) if match else None


def _operational_log_signals(log_text: str) -> list[dict[str, str]]:
    text = str(log_text or "")
    lower = text.casefold()
    signals: list[dict[str, str]] = []
    if "stale parallel candidate discarded" in lower:
        signals.append({"code": "stale-candidate-discarded", "label": "Stale parallel candidate discarded", "explanation": "The one-writer publication gate detected that an authoritative parent moved and discarded this candidate instead of publishing stale Evidence."})
    if "evidence moved before merge" in lower:
        signals.append({"code": "evidence-parent-moved-before-merge", "label": "Evidence parent moved before merge", "explanation": "The merge stage observed a different Security Evidence parent than the one frozen by the plan and failed closed."})
    if "result bundles, found" in lower and "expected" in lower:
        signals.append({"code": "result-bundle-cardinality-failed", "label": "Worker result bundle count did not match the plan", "explanation": "Merge validation did not receive exactly one bounded result bundle per planned queue item."})
    return signals


def _select_current_run(runs: Iterable[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    rows = [row for row in runs if isinstance(row, Mapping)]
    if not rows:
        return None
    active = [row for row in rows if _text(row.get("status")).casefold() in _RUNNING]
    candidates = active or rows
    return max(candidates, key=lambda row: (_iso(row.get("created_at")), _integer(row.get("id"))))


def acquire_sigmascope_operation(client: Any, *, refresh: bool = False) -> dict[str, Any]:
    """Acquire/cache one bounded drain run plus its allow-listed planning artifact.

    Normal plugin navigation is snapshot-only.  Remote GitHub requests happen only when
    ``refresh=True`` (the UI's explicit Refresh operation button / data acquisition action).
    """
    access = client.access_status()
    if not access.get("tokenConfigured"):
        return {
            "schema": OPERATION_SCHEMA, "available": False, "authenticated": False,
            "readOnly": True, "mutationAuthority": "none", "securityAuthority": False,
            "refreshRequired": False, "state": "signed-out",
            "notice": "Sign in to augment the published scan report with GitHub operational correlation.",
        }
    cache_key = ("sigmascope-plugin-progress",)
    with client._lock:
        cached = client._workflow_cache.get(cache_key)
        if not refresh and cached:
            return dict(cached[1])
    if not refresh:
        return {
            "schema": OPERATION_SCHEMA, "available": False, "authenticated": True,
            "readOnly": True, "mutationAuthority": "none", "securityAuthority": False,
            "refreshRequired": True, "state": "not-acquired",
            "notice": "Operational telemetry has not been explicitly acquired in this session.",
        }

    repository = _api_repository(client.repository)
    fetched_at = _utc_now()
    try:
        run_url = (
            f"https://api.github.com/repos/{repository}/actions/workflows/"
            f"{urllib.parse.quote(DRAIN_WORKFLOW, safe='')}/runs?branch={urllib.parse.quote(DRAIN_BRANCH)}&per_page=8"
        )
        run_payload = client._request_json(run_url)
        runs = run_payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise RuntimeError("GitHub drain workflow response has no workflow_runs list")
        selected = _select_current_run([row for row in runs if isinstance(row, Mapping)])
        if selected is None:
            result = {
                "schema": OPERATION_SCHEMA, "available": True, "authenticated": True,
                "readOnly": True, "mutationAuthority": "none", "securityAuthority": False,
                "refreshRequired": False, "state": "no-run", "fetchedAtUtc": fetched_at,
                "run": {}, "jobs": [], "plan": {}, "planAvailable": False, "signals": [],
            }
        else:
            run_id = _integer(selected.get("id"))
            jobs = client._request_jobs(run_id)
            artifacts = client._request_artifacts(run_id)
            candidates = [row for row in artifacts if isinstance(row, Mapping) and _text(row.get("name")) in ALLOWED_OPERATIONAL_ARTIFACTS and not bool(row.get("expired"))]
            if len(candidates) > 1:
                raise RuntimeError("multiple allow-listed SigmaScope planning artifacts were returned for one run")
            plan: dict[str, Any] = {}
            plan_available = False
            if candidates:
                artifact = candidates[0]
                name = _text(artifact.get("name"))
                archive_url = _text(artifact.get("archive_download_url"))
                archive_size = _integer(artifact.get("size_in_bytes"))
                if archive_size and archive_size > MAX_OPERATIONAL_ARCHIVE_BYTES:
                    raise ValueError("operational artifact metadata exceeds the DeltaScope safety bound")
                plan = parse_operational_artifact(name, _request_bytes(client, archive_url, maximum=MAX_OPERATIONAL_ARCHIVE_BYTES))
                plan_available = True
            job_rows = [_job_projection(row, fetched_at=fetched_at) for row in jobs]
            signals: list[dict[str, str]] = []
            # Only merge/one-writer publication logs are inspected, using the existing
            # bounded GitHub log reader. Raw logs are never returned to the report API.
            for raw_job in jobs:
                name = _text(raw_job.get("name")).casefold()
                inspect_log = "merge" in name or "one-writer publish" in name
                if not inspect_log or _text(raw_job.get("status")).casefold() != "completed" or not _integer(raw_job.get("id")):
                    continue
                try:
                    signals.extend(_operational_log_signals(client._request_job_log(_integer(raw_job.get("id")))))
                except Exception:
                    pass
            deduped_signals = list({row["code"]: row for row in signals}.values())
            result = {
                "schema": OPERATION_SCHEMA, "available": True, "authenticated": True,
                "readOnly": True, "mutationAuthority": "none", "securityAuthority": False,
                "refreshRequired": False, "state": "acquired", "fetchedAtUtc": fetched_at,
                "run": {
                    "runId": run_id,
                    "runNumber": _integer(selected.get("run_number")),
                    "workflow": _text(selected.get("name")) or "SigmaScope production drain",
                    "workflowPath": _text(selected.get("path")),
                    "status": _text(selected.get("status")).casefold() or "unknown",
                    "conclusion": _text(selected.get("conclusion")).casefold(),
                    "createdAtUtc": _iso(selected.get("created_at")),
                    "updatedAtUtc": _iso(selected.get("updated_at")),
                    "url": _safe_github_url(selected.get("html_url")),
                },
                "jobs": job_rows,
                "plan": plan,
                "planAvailable": plan_available,
                "artifactAllowList": sorted(ALLOWED_OPERATIONAL_ARTIFACTS),
                "signals": deduped_signals,
            }
    except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        result = {
            "schema": OPERATION_SCHEMA, "available": False, "authenticated": True,
            "readOnly": True, "mutationAuthority": "none", "securityAuthority": False,
            "refreshRequired": False, "state": "error", "fetchedAtUtc": fetched_at,
            "error": _redact_secret(exc), "run": {}, "jobs": [], "plan": {}, "planAvailable": False, "signals": [],
        }
    with client._lock:
        client._workflow_cache[cache_key] = (time.monotonic(), dict(result))
    return result


def _queue_for_variant(queue_projection: Mapping[str, Any], variant_id: int) -> list[dict[str, Any]]:
    rows = [dict(row) for row in queue_projection.get("queueItems") or [] if isinstance(row, Mapping) and _integer(row.get("variantId")) == variant_id]
    rows.sort(key=lambda row: (_integer(row.get("rank")) or 10**9, _text(row.get("queueKey"))))
    return rows


def _worker_job(operation: Mapping[str, Any], slot: int) -> dict[str, Any] | None:
    for row in operation.get("jobs") or []:
        if isinstance(row, Mapping) and _worker_slot(_text(row.get("name"))) == slot:
            return dict(row)
    return None


def _named_job(operation: Mapping[str, Any], tokens: tuple[str, ...]) -> dict[str, Any] | None:
    for row in operation.get("jobs") or []:
        if not isinstance(row, Mapping):
            continue
        name = _text(row.get("name")).casefold()
        if all(token in name for token in tokens):
            return dict(row)
    return None


def _publication_job(operation: Mapping[str, Any]) -> dict[str, Any] | None:
    candidates = [dict(row) for row in operation.get("jobs") or [] if isinstance(row, Mapping) and "publish" in _text(row.get("name")).casefold()]
    for row in candidates:
        name = _text(row.get("name")).casefold()
        if "one-writer" in name or ("evidence" in name and "client" not in name and "customer" not in name):
            return row
    return next((row for row in candidates if "client" not in _text(row.get("name")).casefold() and "customer" not in _text(row.get("name")).casefold()), None)


def _current_status(
    detail: Mapping[str, Any], queue_items: list[dict[str, Any]], operation: Mapping[str, Any], correlation: Mapping[str, Any] | None,
) -> tuple[str, str, dict[str, Any]]:
    identity = _mapping(detail.get("identity"))
    snapshot_kind = _text(detail.get("snapshotKind")).casefold()
    lifecycle = _mapping(detail.get("lifecycle"))
    if snapshot_kind in {"retired", "superseded"} or _text(lifecycle.get("state")).casefold() in {"retired", "superseded"}:
        return "Stale / superseded", "This is retained historical Evidence, not the current variant publication.", {}

    published_scan_id = _integer(identity.get("scan_id") or identity.get("scanId"))
    published_at = _iso(identity.get("scanned_at_utc") or identity.get("scannedAtUtc"))
    published_status = _text(identity.get("scan_status") or identity.get("status")).casefold()
    selected = queue_items[0] if queue_items else {}
    if correlation:
        exact = next((row for row in queue_items if _text(row.get("queueKey")) == _text(correlation.get("queueKey"))), selected)
        if exact:
            selected = exact
        signal_codes = {_text(row.get("code")) for row in operation.get("signals") or [] if isinstance(row, Mapping)}
        if signal_codes & {"stale-candidate-discarded", "evidence-parent-moved-before-merge"}:
            return "Stale / superseded", "The correlated drain candidate was based on an authoritative parent that moved; the workflow failed closed instead of publishing stale Evidence.", {}
        worker = _worker_job(operation, _integer(correlation.get("slot")))
        if _text(_mapping(operation.get("run")).get("status")).casefold() == "completed" and (_text(selected.get("state")).casefold() == "retry" or _text(selected.get("primaryReason")) == "failed_retry"):
            return "Retry pending", "The correlated run is already complete, while the currently published queue retains this exact key as bounded retry work.", worker or {}
        other_workers = [row for row in operation.get("jobs") or [] if isinstance(row, Mapping) and _worker_slot(_text(row.get("name"))) is not None and _integer(row.get("jobId")) != _integer(_mapping(worker).get("jobId"))]
        if worker:
            status = _text(worker.get("status")).casefold()
            conclusion = _text(worker.get("conclusion")).casefold()
            if status in {"queued", "waiting", "pending", "requested"}:
                return "Assigned", "The exact queue key is assigned to a production drain worker; GitHub does not yet show that worker executing.", worker
            if status == "in_progress":
                return "Scanning", "The worker job containing this exact queue key is currently executing. Assignment position is not per-key completion progress.", worker
            if status == "completed" and conclusion == "timed_out":
                return "Timed out", "The assigned worker job concluded with a timeout. Published Evidence remains unchanged until a later successful publication.", worker
            if status == "completed" and conclusion in _FAILURE:
                return "Failed", "The assigned worker job failed. The last published Security Evidence remains authoritative.", worker
            if status == "completed" and conclusion == "success":
                # If current published Evidence has advanced beyond the queue's previous scan, publication wins.
                prior_scan = _integer(selected.get("currentScanId"))
                prior_at = _iso(selected.get("currentScannedAtUtc"))
                if published_scan_id and ((prior_scan and published_scan_id != prior_scan) or (prior_at and published_at and published_at != prior_at)):
                    return "Published", "Published Security Evidence has advanced beyond the queue record that was planned for this operation.", worker
                if any(_text(row.get("status")).casefold() != "completed" for row in other_workers):
                    return "Waiting for other workers", "This worker completed successfully, but other workers in the same wave have not all completed.", worker
                merge = _named_job(operation, ("merge",))
                publish = _publication_job(operation)
                if merge and _text(merge.get("status")).casefold() != "completed":
                    return "Waiting for merge", "The selected worker completed; the wave merge/validation job has not completed.", worker
                if merge and _text(merge.get("status")).casefold() == "completed" and _text(merge.get("conclusion")).casefold() in _FAILURE | {"timed_out"}:
                    return "Failed" if _text(merge.get("conclusion")).casefold() != "timed_out" else "Timed out", "Worker output completed, but merge/validation did not complete successfully. Published Evidence is unchanged.", worker
                if publish and _text(publish.get("status")).casefold() != "completed":
                    return "Waiting for publication", "Worker and merge stages completed far enough to reach publication, but authoritative Security Evidence has not yet advanced.", worker
                return "Worker completed", "Worker completed; authoritative Evidence has not been published for this queue item yet.", worker
        return "Assigned", "The production plan assigns this exact queue key to a worker slot, but current job execution state is unavailable.", {}

    if queue_items:
        state = _text(selected.get("state")).casefold()
        attempts = _integer(selected.get("attemptCount"))
        if state == "retry" or attempts > 0 and _text(selected.get("primaryReason")) == "failed_retry":
            return "Retry pending", "Published queue state shows bounded retry work pending; no exact live worker assignment is currently correlated.", {}
        return "Queued", "The selected variant is in the published SigmaScope queue, but no exact live worker assignment is currently correlated.", {}
    if detail.get("catalogOnly") or not published_scan_id:
        return "Not queued", "No current published scan and no matching item in the currently published queue were found.", {}
    if published_status == "complete" or published_scan_id:
        return "Published", "The latest authoritative state available to DeltaScope is the current published Security Evidence record.", {}
    return "Unknown", "Available evidence does not support a more specific operational state.", {}


def _category_for_finding(row: Mapping[str, Any]) -> str:
    haystack = " ".join(_text(row.get(key)) for key in ("ruleId", "rule_id", "findingId", "finding_id", "title", "description", "message")).casefold()
    for category, tokens in _CATEGORY_RULES:
        if any(token in haystack for token in tokens):
            return category
    return "Other static findings"


def _finding_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    rule_id = _text(row.get("ruleId") or row.get("rule_id"))
    title = _text(row.get("title") or row.get("label") or row.get("findingId") or row.get("finding_id") or rule_id or "Static observation")
    explanation = _text(row.get("description") or row.get("explanation") or row.get("message") or row.get("summary"))
    if not explanation:
        explanation = f"Published SigmaScope observation{f' for rule {rule_id}' if rule_id else ''}."
    why = _text(row.get("reason") or row.get("trigger") or row.get("matchReason") or row.get("matchedBy"))
    evidence = row.get("evidence") if row.get("evidence") is not None else row.get("evidence_json")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            pass
    if evidence in (None, {}, []):
        evidence = {key: row.get(key) for key in (
            "call", "method", "member", "path", "sourcePath", "artifactPath",
            "import", "api", "endpoint", "url", "host", "match",
        ) if row.get(key) not in (None, "", [], {})}
    origin = _text(row.get("origin") or row.get("scope") or row.get("evidenceOrigin") or row.get("producer"))
    if not origin:
        if row.get("sourcePath") or _text(row.get("evidenceStream")).casefold() == "source":
            origin = "source"
        elif row.get("artifactPath") or row.get("call") or row.get("member"):
            origin = "artifact"
        else:
            origin = "published-evidence"
    return {
        "category": _category_for_finding(row),
        "severity": _text(row.get("severity")).casefold() or "informational",
        "title": title,
        "ruleId": rule_id,
        "findingId": _text(row.get("findingId") or row.get("finding_id")),
        "explanation": explanation,
        "whyTriggered": why,
        "evidence": _bounded(evidence if evidence is not None else {}),
        "origin": origin,
        "confidence": row.get("confidence"),
        "provenance": _bounded(row.get("provenance") or {}),
    }


def _structured_sections(detail: Mapping[str, Any], projection_state: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    researcher = _mapping(detail.get("researcher"))
    findings = [row for row in researcher.get("findings") or detail.get("findings") or [] if isinstance(row, Mapping)]
    projected = [_finding_projection(row) for row in findings]
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in projected:
        groups.setdefault(row["category"], []).append(row)
    identity = _mapping(detail.get("identity"))
    groups["Overall scan result"] = [{
        "category": "Overall scan result",
        "severity": _text(identity.get("highest_severity")).casefold() or "informational",
        "title": "Published SigmaScope scan status", "ruleId": "", "findingId": "",
        "explanation": f"Security Evidence v2 records scan {_integer(identity.get('scan_id') or identity.get('scanId')) or '—'} as {_text(identity.get('scan_status') or identity.get('status')) or 'unknown'}.",
        "whyTriggered": "",
        "evidence": {"scanId": _integer(identity.get("scan_id") or identity.get("scanId")), "scannedAtUtc": _iso(identity.get("scanned_at_utc") or identity.get("scannedAtUtc")), "highestSeverity": _text(identity.get("highest_severity")) or "none"},
        "origin": "published-evidence", "confidence": None, "provenance": {},
    }]

    def structured(title: str, records: Any, *, note: str = "") -> None:
        rows = records if isinstance(records, list) else []
        groups.setdefault(title, [])
        for raw in rows[:80]:
            if not isinstance(raw, Mapping):
                continue
            groups[title].append({
                "category": title,
                "severity": _text(raw.get("severity")).casefold() or "informational",
                "title": _text(raw.get("title") or raw.get("name") or raw.get("id") or raw.get("url") or raw.get("host") or title.rstrip("s")),
                "ruleId": _text(raw.get("ruleId") or raw.get("rule_id")),
                "findingId": _text(raw.get("findingId") or raw.get("finding_id")),
                "explanation": _text(raw.get("description") or raw.get("purpose") or raw.get("summary") or note),
                "whyTriggered": _text(raw.get("reason") or raw.get("classification") or raw.get("match")),
                "evidence": _bounded(raw),
                "origin": _text(raw.get("origin") or raw.get("scope") or "published-evidence"),
                "confidence": raw.get("confidence"),
                "provenance": _bounded(raw.get("provenance") or {}),
            })

    structured("External endpoints", detail.get("networkEndpoints"), note="Endpoint retained in published network evidence.")
    structured("Dependencies", detail.get("dependencies"), note="Dependency retained in published package evidence.")
    structured("Advisories", detail.get("advisories"), note="Frozen advisory relationship retained with this scan.")
    structured("IPC", detail.get("ipc"), note="IPC endpoint retained in published Evidence.")
    structured("Automation capabilities", researcher.get("automationCapabilities"), note="Automation capability retained in published Evidence.")
    secondary = _mapping(detail.get("secondarySecurity"))
    structured("Secondary engines", secondary.get("engines"), note="Secondary engine result retained alongside SigmaScope evidence.")

    source = _mapping(detail.get("sourceCoverage"))
    attribution = _mapping(detail.get("sourceAttribution"))
    if source or attribution:
        groups.setdefault("Source attribution", []).append({
            "category": "Source attribution", "severity": "informational", "title": "Attributed source coverage",
            "ruleId": "", "findingId": "",
            "explanation": "Attributed source is retained as a separate evidence stream from the installable artifact." if source.get("sourceCodeAvailable") else "No attributable source code is recorded for this current scan.",
            "whyTriggered": "", "evidence": _bounded({"coverage": source, "attribution": attribution}), "origin": "published-evidence", "confidence": attribution.get("confidence", source.get("attributionConfidence")), "provenance": {},
        })
    provenance = _mapping(detail.get("sourceProvenance"))
    if provenance:
        groups.setdefault("Source provenance", []).append({
            "category": "Source provenance", "severity": "informational", "title": "Source provenance",
            "ruleId": "", "findingId": "", "explanation": "Published source provenance records where the attributed source snapshot came from and which ref/commit was retained.",
            "whyTriggered": "", "evidence": _bounded(provenance), "origin": "published-evidence", "confidence": provenance.get("confidence"), "provenance": _bounded(provenance),
        })
    projection_state = projection_state if isinstance(projection_state, Mapping) else {}
    deep_request = _mapping(projection_state.get("analysisRequest"))
    reanalysis_request = _mapping(projection_state.get("reanalysisRequest"))
    if deep_request or reanalysis_request:
        request = deep_request or reanalysis_request
        groups.setdefault("Deep / targeted analysis", []).append({
            "category": "Deep / targeted analysis", "severity": "informational",
            "title": "Deep analysis requested" if deep_request else "Targeted reanalysis requested",
            "ruleId": _text(request.get("ruleId")), "findingId": "",
            "explanation": _text(request.get("reason")) or "A deterministic rule/projection requested additional bounded evidence.",
            "whyTriggered": _text(request.get("reason")), "evidence": _bounded(request),
            "origin": "published-rule-projection", "confidence": None, "provenance": {},
        })

    divergence = _mapping(detail.get("sourceArtifactComparison"))
    if divergence:
        groups.setdefault("Source / artifact divergence", []).append({
            "category": "Source / artifact divergence", "severity": _text(divergence.get("severity")).casefold() or "informational",
            "title": "Source ↔ artifact comparison", "ruleId": "", "findingId": "",
            "explanation": "Published comparison data describes the relationship between attributed source and the shipped artifact; it is not itself a malware verdict.",
            "whyTriggered": "", "evidence": _bounded(divergence), "origin": "published-evidence", "confidence": divergence.get("confidence"), "provenance": {},
        })

    catalog = [row for row in detail.get("datasetCatalog") or [] if isinstance(row, Mapping)]
    lazy_counts = {str(row.get("name")): _integer(row.get("records")) for row in catalog}
    preferred_order = [
        "Overall scan result", "Network capabilities", "External endpoints", "Filesystem access",
        "Process / shell execution", "PowerShell", "Registry access", "Native loading",
        "P/Invoke / native APIs", "Memory / process manipulation", "Hooks / listeners",
        "Clipboard / credential APIs", "Dependencies", "Advisories", "IPC", "Source attribution",
        "Source / artifact divergence", "Secondary engines", "Automation capabilities",
        "Deep / targeted analysis", "Source provenance", "Other static findings",
    ]
    result: list[dict[str, Any]] = []
    for title in preferred_order:
        rows = groups.get(title, [])
        if rows:
            result.append({"category": title, "count": len(rows), "records": rows})
    for title in sorted(set(groups) - set(preferred_order)):
        rows = groups[title]
        if rows:
            result.append({"category": title, "count": len(rows), "records": rows})
    # Show immutable large-dataset availability without pretending those rows were loaded.
    for name, label in (("dependencies", "Dependencies"), ("ipc", "IPC")):
        count = lazy_counts.get(name, 0)
        if count and not any(row["category"] == label for row in result):
            result.append({"category": label, "count": count, "records": [], "lazy": True, "note": f"{count} immutable {name} record(s) are available in Evidence; use the expert dataset drill-down to inspect them."})
    return result


def _executive_summary(detail: Mapping[str, Any], sections: list[dict[str, Any]]) -> str:
    identity = _mapping(detail.get("identity"))
    researcher = _mapping(detail.get("researcher"))
    name = _text(identity.get("canonical_name") or identity.get("name") or identity.get("internal_name")) or "This plugin"
    version = _text(identity.get("assembly_version"))
    status = _text(identity.get("scan_status") or identity.get("status")).casefold() or "unknown"
    counts = _mapping(researcher.get("findingCounts"))
    total = sum(_integer(counts.get(key)) for key in ("critical", "high", "caution", "informational"))
    parts = [f"SigmaScope {('completed' if status == 'complete' else 'recorded')} static analysis of {name}{f' version {version}' if version else ''}."]
    if total:
        severity_parts = [f"{_integer(counts.get(key))} {key}" for key in ("critical", "high", "caution", "informational") if _integer(counts.get(key))]
        parts.append(f"The current published Evidence contains {total} static finding(s): {', '.join(severity_parts)}.")
    else:
        parts.append("No static finding is present in the compact current Evidence summary; this is not a safety guarantee.")
    endpoints = len(_list(detail.get("networkEndpoints")))
    if endpoints:
        parts.append(f"{endpoints} external/network endpoint observation(s) are retained.")
    categories = {row.get("category") for row in sections}
    if "Process / shell execution" in categories:
        parts.append("Process or shell execution capability evidence is present and should be reviewed in context.")
    else:
        parts.append("No process/shell finding is present in the compact current Evidence view.")
    source = _mapping(detail.get("sourceCoverage"))
    if source.get("sourceCodeAvailable"):
        verified = "verified" if source.get("sourceToBinaryVerified") else "not cryptographically verified"
        parts.append(f"Source attribution is available; source-to-artifact correspondence is {verified}.")
    else:
        parts.append("No attributable source code is recorded, so the current report is artifact-led.")
    advisory_count = len(_list(detail.get("advisories")))
    if advisory_count:
        parts.append(f"{advisory_count} frozen dependency advisory relationship(s) are retained.")
    return " ".join(parts)


def _identity_projection(detail: Mapping[str, Any]) -> dict[str, Any]:
    identity = _mapping(detail.get("identity"))
    catalog = _mapping(detail.get("catalogContext"))
    artifact = _mapping(detail.get("artifactIdentity"))
    return {
        "name": _text(identity.get("canonical_name") or identity.get("name") or identity.get("internal_name")),
        "internalName": _text(identity.get("internal_name") or identity.get("internalName")),
        "pluginId": _integer(identity.get("plugin_id") or identity.get("pluginId") or catalog.get("pluginId")),
        "variantId": _integer(identity.get("variant_id") or identity.get("variantId")),
        "version": _text(identity.get("assembly_version") or identity.get("version")),
        "dalamudApiLevel": _integer(identity.get("dalamud_api_level") or identity.get("dalamudApiLevel")),
        "artifactSha256": _text(identity.get("artifact_sha256") or artifact.get("sha256") or artifact.get("artifactSha256")),
        "artifactChannel": _text(identity.get("artifact_channel") or artifact.get("channel")),
        "sourceName": _text(identity.get("source_name")),
        "sourceUrl": _text(identity.get("source_url")),
        "repository": _text(_mapping(detail.get("sourceCoverage")).get("repository")),
    }


def _last_published(detail: Mapping[str, Any], summary: Mapping[str, Any]) -> dict[str, Any]:
    identity = _mapping(detail.get("identity"))
    provenance = _mapping(detail.get("scanProvenance"))
    analysis = _mapping(detail.get("analysis"))
    revisions = _mapping(summary.get("revisions") or summary.get("meta"))
    return {
        "authority": "Security Evidence v2",
        "status": _text(identity.get("scan_status") or identity.get("status")) or "unscanned",
        "scanId": _integer(identity.get("scan_id") or identity.get("scanId")),
        "scannedAtUtc": _iso(identity.get("scanned_at_utc") or identity.get("scannedAtUtc")),
        "evidenceRevision": _text(revisions.get("evidenceRevision") or revisions.get("securityEvidenceRevision")),
        "evidenceReference": _text(detail.get("variantPath") or analysis.get("path")),
        "packageSha256": _text(identity.get("artifact_sha256")),
        "scannerVersion": _text(identity.get("scanner_version") or provenance.get("scannerVersion")),
        "scannerRevision": _text(identity.get("scanner_revision") or provenance.get("scannerRevision")),
        "artifactAnalysisRevision": _text(identity.get("artifact_analysis_revision") or provenance.get("artifactAnalysisRevision") or revisions.get("artifactAnalysisRevision")),
        "sourceAnalysisRevision": _text(identity.get("source_analysis_revision") or provenance.get("sourceAnalysisRevision") or revisions.get("sourceAnalysisRevision")),
        "definitionsRevision": _text(identity.get("definitions_revision") or provenance.get("definitionsRevision") or revisions.get("definitionsRevision")),
        "ruleSetRevision": _text(provenance.get("ruleSetRevision") or revisions.get("ruleSetRevision")),
    }


def _comparison_key(row: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    return next((_text(row.get(key)) for key in keys if _text(row.get(key))), "")


def _comparison(inspector: Any, detail: Mapping[str, Any], variant_id: int) -> dict[str, Any]:
    snapshots = inspector.variant_snapshots(variant_id) if hasattr(inspector, "variant_snapshots") else []
    previous = next((row for row in snapshots if isinstance(row, Mapping) and _text(row.get("snapshotKind")) != "current" and _text(row.get("variantPath"))), None)
    if not previous:
        return {"available": False, "explanation": "Previous comparable Evidence unavailable.", "changes": [], "limits": []}
    try:
        before = inspector.snapshot_detail(_text(previous.get("variantPath")))
        projected = deltascope_workbench.project_version_compare(before, detail)
        changes = [dict(row) for row in projected.get("changes") or [] if isinstance(row, Mapping)]
        seen = {(row.get("kind"), row.get("label"), row.get("detail")) for row in changes}
        def add(kind: str, direction: str, label: str, detail_text: str = "") -> None:
            key = (kind, label, detail_text)
            if key not in seen:
                seen.add(key); changes.append({"kind": kind, "direction": direction, "label": label, "detail": detail_text})
        bi, ai = _mapping(before.get("identity")), _mapping(detail.get("identity"))
        bv, av = _text(bi.get("assembly_version")), _text(ai.get("assembly_version"))
        if bv and av and bv != av:
            add("version", "changed", f"Plugin version changed · {bv} → {av}")

        # Individual finding severity changes are meaningful even when the global maximum stays fixed.
        bf = {_comparison_key(row, ("findingId", "finding_id", "ruleId", "rule_id", "title")): row for row in _list(_mapping(before.get("researcher")).get("findings")) if isinstance(row, Mapping)}
        af = {_comparison_key(row, ("findingId", "finding_id", "ruleId", "rule_id", "title")): row for row in _list(_mapping(detail.get("researcher")).get("findings")) if isinstance(row, Mapping)}
        for key in sorted(set(bf) & set(af)):
            old_sev, new_sev = _text(bf[key].get("severity")).casefold(), _text(af[key].get("severity")).casefold()
            if old_sev and new_sev and old_sev != new_sev:
                add("finding-severity", "changed", f"Finding severity changed · {key}", f"{old_sev} → {new_sev}")

        def list_delta(field: str, keys: tuple[str, ...], kind: str, noun: str) -> bool:
            before_rows, after_rows = before.get(field), detail.get(field)
            if not isinstance(before_rows, list) or not isinstance(after_rows, list):
                return False
            old = {_comparison_key(row, keys) for row in before_rows if isinstance(row, Mapping)} - {""}
            new = {_comparison_key(row, keys) for row in after_rows if isinstance(row, Mapping)} - {""}
            for value in sorted(new - old): add(kind, "added", f"New {noun} · {value}")
            for value in sorted(old - new): add(kind, "removed", f"{noun.title()} removed · {value}")
            return True

        compared_dependencies = list_delta("dependencies", ("purl", "id", "name", "package", "assembly"), "dependency", "dependency")
        compared_calls = list_delta("calls", ("call", "member", "method", "signature", "name"), "managed-native-call", "managed/native call")
        before_auto = _mapping(before.get("researcher")).get("automationCapabilities")
        after_auto = _mapping(detail.get("researcher")).get("automationCapabilities")
        compared_automation = isinstance(before_auto, list) and isinstance(after_auto, list)
        if compared_automation:
            old = {_comparison_key(row, ("id", "capabilityId", "capability_id", "name", "capability")) for row in before_auto if isinstance(row, Mapping)} - {""}
            new = {_comparison_key(row, ("id", "capabilityId", "capability_id", "name", "capability")) for row in after_auto if isinstance(row, Mapping)} - {""}
            for value in sorted(new-old): add("automation-capability", "added", f"New automation capability · {value}")
            for value in sorted(old-new): add("automation-capability", "removed", f"Automation capability removed · {value}")
        before_div, after_div = _mapping(before.get("sourceArtifactComparison")), _mapping(detail.get("sourceArtifactComparison"))
        if before_div and after_div and json.dumps(_bounded(before_div), sort_keys=True) != json.dumps(_bounded(after_div), sort_keys=True):
            add("source-divergence", "changed", "Source / artifact comparison changed")
        limits = []
        if not compared_dependencies: limits.append("Dependency-by-dependency history is unavailable in the comparable compact snapshots.")
        if not compared_calls: limits.append("Managed/native call history is unavailable in the comparable compact snapshots.")
        if not compared_automation: limits.append("Automation-capability history is unavailable in the comparable compact snapshots.")
        result = dict(projected)
        result["changes"] = changes
        result["changeCount"] = len(changes)
        result["limits"] = limits
        return {"available": True, **result}
    except Exception as exc:
        return {"available": False, "explanation": f"Previous comparable Evidence unavailable: {exc}", "changes": [], "limits": []}


def _journey(inspector: Any, detail: Mapping[str, Any], variant_id: int, *, projection_state: Mapping[str, Any] | None = None) -> dict[str, Any]:
    observations = inspector.workbench_observation_rows(variant_id, per_collection_limit=40) if hasattr(inspector, "workbench_observation_rows") else {}
    projection = dict(projection_state) if isinstance(projection_state, Mapping) else (inspector.srl_projection_state(variant_id) if hasattr(inspector, "srl_projection_state") else {})
    journey = deltascope_workbench.project_asset_journey(detail, observations, projection)
    section_map = {
        "catalog-discovery": "identity", "artifact-acquisition": "published", "package-inspection": "findings",
        "source-attribution": "findings", "sigmascope-static": "findings", "secondary-engines": "findings",
        "evidence-normalization": "findings", "stigma-rules": "findings", "deep-analysis": "findings",
        "evidence-publication": "published", "deltascope-view": "summary",
    }
    stages = []
    for raw in journey.get("stages") or []:
        if isinstance(raw, Mapping):
            row = dict(raw)
            row["scanReportSection"] = section_map.get(_text(row.get("stageId")), "summary")
            stages.append(row)
    return {**journey, "stages": stages, "integration": "existing-asset-journey", "competingPipeline": False}


def _system_health(queue: Mapping[str, Any], operation: Mapping[str, Any], last: Mapping[str, Any], summary: Mapping[str, Any]) -> dict[str, Any]:
    counts = _mapping(queue.get("counts"))
    plan = _mapping(operation.get("plan"))
    before = _mapping(plan.get("queueSummaryBefore"))
    op_available = bool(operation.get("available"))
    plan_available = bool(operation.get("planAvailable")) and bool(plan)
    jobs = [row for row in operation.get("jobs") or [] if isinstance(row, Mapping)]
    worker_jobs = [row for row in jobs if _worker_slot(_text(row.get("name"))) is not None]
    def known_count(mapping: Mapping[str, Any], key: str) -> int | None:
        return _integer(mapping.get(key)) if key in mapping else None
    return {
        "publishedQueuedCount": _integer(counts.get("pending")),
        "immediatelyEligibleCount": known_count(before, "eligibleNow") if plan_available else None,
        "archiveDeferredCount": (known_count(before, "archiveDeferred") if "archiveDeferred" in before else known_count(before, "archiveDeferredCount")) if plan_available else None,
        "retryDeferredCount": known_count(before, "retryDeferred") if plan_available else None,
        "activeProductionDrain": (bool(_mapping(operation.get("run")).get("runId") and _text(_mapping(operation.get("run")).get("status")).casefold() in _RUNNING) if op_available else None),
        "activeWorkerCount": (sum(_text(row.get("status")).casefold() in _RUNNING for row in worker_jobs) if op_available else None),
        "assignmentsInCurrentWave": (_integer(plan.get("assignmentCount")) if plan_available else None),
        "lastEvidencePublicationTime": _iso(summary.get("generatedAtUtc") or summary.get("generated_at_utc") or last.get("scannedAtUtc")),
        "successfulExactItemsMostRecentWave": None,
        "successfulExactItemsExplanation": "Per-key success is not inferred from Actions duration or worker assignment position. It is shown only after authoritative Evidence advances or an explicit bounded result summary becomes available.",
        "failedWorkerCount": (sum(_text(row.get("conclusion")).casefold() in _FAILURE for row in worker_jobs) if op_available else None),
        "timedOutWorkerCount": (sum(_text(row.get("conclusion")).casefold() == "timed_out" for row in worker_jobs) if op_available else None),
    }


def _worker_summary(operation: Mapping[str, Any], selected_job_id: int = 0) -> dict[str, Any]:
    rows = [row for row in operation.get("jobs") or [] if isinstance(row, Mapping) and _worker_slot(_text(row.get("name"))) is not None]
    others = [row for row in rows if _integer(row.get("jobId")) != selected_job_id]
    return {
        "total": len(rows),
        "active": sum(_text(row.get("status")).casefold() in _RUNNING for row in rows),
        "completed": sum(_text(row.get("status")).casefold() == "completed" for row in rows),
        "otherActive": sum(_text(row.get("status")).casefold() in _RUNNING for row in others),
        "failed": sum(_text(row.get("conclusion")).casefold() in _FAILURE for row in rows),
        "timedOut": sum(_text(row.get("conclusion")).casefold() == "timed_out" for row in rows),
    }


def project_scan_queue_operation(queue_projection: Mapping[str, Any], operation: Mapping[str, Any]) -> dict[str, Any]:
    """Overlay one bounded live drain snapshot onto the published queue projection.

    The published queue fields are preserved verbatim.  GitHub Actions state is exposed
    only as ``live*`` metadata and exact assignment correlation still requires the
    persistent queue key plus variant identity.
    """
    projected = dict(queue_projection)
    plan = _mapping(operation.get("plan"))
    plan_available = bool(operation.get("planAvailable")) and bool(plan)
    run = _mapping(operation.get("run"))
    rows: list[dict[str, Any]] = []
    live_counts: dict[str, int] = {}

    for raw in queue_projection.get("queueItems") or []:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        queue_key = _text(row.get("queueKey"))
        variant_id = _integer(row.get("variantId"))
        correlation = correlate_plan(plan, queue_key, variant_id) if plan_available else None
        run_id = _integer(run.get("runId"))
        if not bool(operation.get("available")):
            live_state = "Unknown"
            live_explanation = _redact_secret(operation.get("error") or operation.get("notice") or "Live SigmaScope state has not been acquired.")
            worker = {}
        elif run_id and not plan_available:
            live_state = "Unknown"
            live_explanation = "A production drain run is visible, but its exact planning artifact is not available yet, so DeltaScope will not guess assignment state."
            worker = {}
        else:
            live_state, live_explanation, worker = _current_status({}, [row], operation, correlation)
        if live_state not in STATUS_VALUES:
            live_state = "Unknown"
            live_explanation = "Available operational metadata does not support a recognized queue state."
        live_counts[live_state] = live_counts.get(live_state, 0) + 1
        worker_summary = _worker_summary(operation, _integer(worker.get("jobId"))) if worker else _worker_summary(operation)
        row["publishedQueueState"] = _text(row.get("state")).casefold() or "pending"
        row["liveState"] = live_state
        row["liveExplanation"] = live_explanation
        row["liveOperation"] = {
            "correlated": bool(correlation),
            "runId": _integer(run.get("runId")),
            "runNumber": _integer(run.get("runNumber")),
            "runStatus": _text(run.get("status")).casefold(),
            "runConclusion": _text(run.get("conclusion")).casefold(),
            "runUrl": _safe_github_url(run.get("url")),
            "wave": (_integer(plan.get("wave")) if plan_available else None),
            "slot": (correlation.get("slot") if correlation else None),
            "lane": (_text(correlation.get("lane")) if correlation else ""),
            "workerAssignmentPosition": (_integer(correlation.get("workerAssignmentPosition")) if correlation else None),
            "workerAssignmentCount": (_integer(correlation.get("workerAssignmentCount")) if correlation else None),
            "completionSemantics": (_text(correlation.get("completionSemantics")) if correlation else ""),
            "worker": {
                "jobId": _integer(worker.get("jobId")),
                "name": _text(worker.get("name")),
                "status": _text(worker.get("status")).casefold(),
                "conclusion": _text(worker.get("conclusion")).casefold(),
                "startedAtUtc": _iso(worker.get("startedAtUtc")),
                "completedAtUtc": _iso(worker.get("completedAtUtc")),
                "elapsedSeconds": worker.get("elapsedSeconds"),
                "url": _safe_github_url(worker.get("url")),
            } if worker else {},
            "workerSummary": worker_summary,
        }
        rows.append(row)

    projected["queueItems"] = rows
    projected["operationalOverlay"] = {
        "schema": OPERATION_SCHEMA,
        "authenticated": bool(operation.get("authenticated")),
        "available": bool(operation.get("available")),
        "refreshRequired": bool(operation.get("refreshRequired")),
        "state": _text(operation.get("state")),
        "fetchedAtUtc": _iso(operation.get("fetchedAtUtc")),
        "error": _redact_secret(operation.get("error")),
        "notice": _text(operation.get("notice")),
        "run": {
            "runId": _integer(run.get("runId")),
            "runNumber": _integer(run.get("runNumber")),
            "status": _text(run.get("status")).casefold(),
            "conclusion": _text(run.get("conclusion")).casefold(),
            "url": _safe_github_url(run.get("url")),
        },
        "planAvailable": plan_available,
        "planRevision": _text(plan.get("planRevision")),
        "wave": (_integer(plan.get("wave")) if plan_available else None),
        "assignmentCount": (_integer(plan.get("assignmentCount")) if plan_available else None),
        "counts": {state: live_counts[state] for state in STATUS_VALUES if live_counts.get(state)},
        "readOnly": True,
        "mutationAuthority": "none",
        "securityAuthority": False,
    }
    return projected


def _raw_queue_context(queue_state: Mapping[str, Any], queue_key: str) -> dict[str, Any]:
    items = queue_state.get("items") if isinstance(queue_state.get("items"), Mapping) else {}
    raw = items.get(queue_key) if queue_key and isinstance(items.get(queue_key), Mapping) else {}
    allowed = (
        "targetFingerprint", "enqueuedAtUtc", "eligibleAtUtc", "firstEligibleAtUtc",
        "nextEligibleAtUtc", "previousScanId", "previousScannedAtUtc", "currentApiLevel",
        "dalamudApiLevel", "archiveDeferred", "archiveDeferredReason", "archiveContext",
    )
    return {key: _bounded(raw.get(key)) for key in allowed if key in raw}


def project_scan_report(inspector: Any, client: Any, variant_id: int, *, operational: Mapping[str, Any] | None = None) -> dict[str, Any]:
    variant_id = int(variant_id)
    if variant_id <= 0:
        raise ValueError("variant_id is required")
    detail = inspector.plugin_detail(variant_id)
    summary = inspector.summary()
    queue_state = inspector.scan_queue_state() if hasattr(inspector, "scan_queue_state") else {}
    queue = deltascope_scan_queue.project_scan_queue(queue_state, current_variants=_integer(_mapping(summary.get("counts")).get("variants")))
    queue_items = _queue_for_variant(queue, variant_id)
    operation = dict(operational) if isinstance(operational, Mapping) else acquire_sigmascope_operation(client, refresh=False)

    correlation: dict[str, Any] | None = None
    plan = _mapping(operation.get("plan"))
    if operation.get("planAvailable") and plan:
        for item in queue_items:
            correlation = correlate_plan(plan, _text(item.get("queueKey")), variant_id)
            if correlation:
                break
    status, status_explanation, worker = _current_status(detail, queue_items, operation, correlation)
    if status not in STATUS_VALUES:
        status, status_explanation = "Unknown", "Available evidence does not support a recognized operational state."

    identity = _identity_projection(detail)
    last = _last_published(detail, summary)
    rule_projection = inspector.srl_projection_state(variant_id) if hasattr(inspector, "srl_projection_state") else {}
    sections = _structured_sections(detail, rule_projection)
    comparison = _comparison(inspector, detail, variant_id)
    journey = _journey(inspector, detail, variant_id, projection_state=rule_projection)
    selected_queue = next((row for row in queue_items if correlation and _text(row.get("queueKey")) == _text(correlation.get("queueKey"))), queue_items[0] if queue_items else {})
    run = _mapping(operation.get("run"))
    merge = _named_job(operation, ("merge",)) or {}
    publish = _publication_job(operation) or {}
    op_signals = [dict(row) for row in operation.get("signals") or [] if isinstance(row, Mapping)]
    queue_seed_revision = _text(queue.get("queueSeedRevision"))
    evidence_revision = _text(_mapping(summary.get("revisions") or summary.get("meta")).get("evidenceRevision"))
    operation_projection = {
        "authenticated": bool(operation.get("authenticated")),
        "available": bool(operation.get("available")),
        "refreshRequired": bool(operation.get("refreshRequired")),
        "fetchedAtUtc": _iso(operation.get("fetchedAtUtc")),
        "error": _redact_secret(operation.get("error")),
        "run": dict(run),
        "plan": {
            "available": bool(operation.get("planAvailable")),
            "schema": _text(plan.get("schema")), "planRevision": _text(plan.get("planRevision")),
            "wave": _integer(plan.get("wave")), "assignmentCount": _integer(plan.get("assignmentCount")),
            "activeWorkerCount": _integer(plan.get("activeWorkerCount")),
            "workerAllocationPolicy": _text(plan.get("workerAllocationPolicy")),
        },
        "assignment": dict(correlation or {}),
        "worker": dict(worker),
        "workerSummary": _worker_summary(operation, _integer(worker.get("jobId")) if worker else 0),
        "mergeJob": dict(merge),
        "publishJob": dict(publish),
        "signals": op_signals,
        "revisionContext": {
            "plannedQueueSeedRevision": _text(plan.get("queueSeedRevision")),
            "publishedQueueSeedRevision": queue_seed_revision,
            "queueSeedMatches": (None if not plan.get("queueSeedRevision") or not queue_seed_revision else _text(plan.get("queueSeedRevision")) == queue_seed_revision),
            "plannedEvidenceRevision": _text(plan.get("evidenceRevision")),
            "publishedEvidenceRevision": evidence_revision,
            "evidenceParentMatches": (None if not plan.get("evidenceRevision") or not evidence_revision else _text(plan.get("evidenceRevision")) == evidence_revision),
        },
        "securityAuthority": False,
    }
    publication = {
        "workerCompleted": bool(worker and _text(worker.get("status")).casefold() == "completed" and _text(worker.get("conclusion")).casefold() == "success"),
        "merge": dict(merge), "publication": dict(publish),
        "authoritativeEvidenceAdvanced": status == "Published" and bool(correlation),
        "explanation": status_explanation,
        "stages": ["Worker finished", "Result bundle available", "All required wave results available", "Merge / validation", "One-writer publication", "Security Evidence v2 advanced"],
    }
    result = {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "queueMutationAuthority": False,
        "scanExecutionAuthority": False,
        "publicationAuthority": False,
        "securityAuthority": "published-security-evidence-v2",
        "operationalMetadataAuthority": False,
        "runtimeAI": False,
        "generatedBy": "deterministic-structured-evidence-projection",
        "currentStatus": {"state": status, "explanation": status_explanation, "boundedStates": list(STATUS_VALUES)},
        "identity": identity,
        "queue": {
            "present": bool(queue_items), "selected": dict(selected_queue), "items": queue_items,
            "count": len(queue_items), "selectionPolicy": _text(queue.get("selectionPolicy")),
            "selectionOrderExact": bool(queue.get("selectionOrderExact")),
            "publishedContext": _raw_queue_context(queue_state, _text(selected_queue.get("queueKey"))),
        },
        "operation": operation_projection,
        "mergePublication": publication,
        "lastPublishedEvidence": last,
        "executiveSummary": _executive_summary(detail, sections),
        "findingReport": {
            "sections": sections,
            "findingCounts": dict(_mapping(_mapping(detail.get("researcher")).get("findingCounts"))),
            "highestSeverity": _text(_mapping(detail.get("identity")).get("highest_severity")) or "none",
            "deterministic": True,
            "malwareVerdictInferred": False,
        },
        "changesSincePrevious": comparison,
        "journey": journey,
        "raw": {
            "evidenceReference": _text(detail.get("variantPath")),
            "analysis": _bounded(detail.get("analysis") or {}),
            "queueRecord": dict(selected_queue),
            "planningAssignment": dict(correlation or {}),
            "githubRunUrl": _safe_github_url(run.get("url")),
            "workerJobUrl": _safe_github_url(worker.get("url")) if worker else "",
        },
    }
    result["systemHealth"] = _system_health(queue, operation, last, summary)
    return result


_SCAN_REPORT_CSS = r'''
.scan-report-shell{display:grid;gap:12px}.scan-report-hero{border:1px solid #c6c6c6;border-left:6px solid #0f62fe;background:#fff;padding:16px}.scan-report-hero h3{margin:2px 0 7px}.scan-report-state{display:inline-block;margin-bottom:6px;font-weight:700;letter-spacing:.03em}.scan-report-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.scan-report-section{border:1px solid #d9dde2;background:#fff;padding:14px;scroll-margin-top:58px}.scan-report-section h3{margin:0 0 8px}.scan-report-kv{display:grid;grid-template-columns:150px minmax(0,1fr);gap:6px 10px}.scan-report-kv code,.scan-report-row code{overflow-wrap:anywhere}.scan-report-operation{border-left:4px solid #0f62fe}.scan-report-authority{border-left:4px solid #24a148}.scan-report-warning{border-left:4px solid #f1c21b}.scan-report-findings{display:grid;gap:8px}.scan-report-category{border-top:1px solid #e0e0e0;padding-top:9px}.scan-report-finding{margin:6px 0;padding:9px;background:#f4f4f4;border-left:3px solid #8d8d8d}.scan-report-finding.high,.scan-report-finding.critical{border-left-color:#da1e28}.scan-report-finding.caution,.scan-report-finding.medium{border-left-color:#f1c21b}.scan-report-finding .meta{font-size:10px;color:#525252}.scan-report-journey{display:flex;flex-wrap:wrap;gap:6px}.scan-report-journey button{text-align:left;min-width:190px;flex:1 1 190px;padding:9px}.scan-report-journey button b{display:block}.scan-report-raw-actions{display:flex;gap:7px;flex-wrap:wrap}.scan-report-position{padding:8px;background:#edf5ff}.scan-report-position b{display:block}.scan-report-muted{color:#525252;font-size:11px}.scan-report-system{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.scan-report-metric{border:1px solid #e0e0e0;padding:9px}.scan-report-metric b{display:block;font-size:18px;font-weight:400}@media(max-width:900px){.scan-report-grid{grid-template-columns:1fr}.scan-report-system{grid-template-columns:repeat(2,1fr)}}
'''

_SCAN_REPORT_JS = r'''
setTimeout(function(){
 if(window.__deltascopeScanReportInstalled)return;window.__deltascopeScanReportInstalled=true;
 var style=document.createElement('style');style.textContent=__SCAN_REPORT_CSS__;document.head.appendChild(style);
 var baseResearchCaseHtml=window.researchCaseHtml,baseWireResearchTabs=window.wireResearchTabs;
 if(typeof baseResearchCaseHtml!=='function'||typeof baseWireResearchTabs!=='function')return;
 function fmtElapsed(seconds){if(seconds==null)return'—';var s=Number(seconds||0),m=Math.floor(s/60),h=Math.floor(m/60);return h?`${h}h ${m%60}m`:`${m}m`}
 function kvRows(rows){return '<div class=scan-report-kv>'+rows.map(function(row){return '<b>'+esc(row[0])+'</b><span>'+row[1]+'</span>'}).join('')+'</div>'}
 function textv(v){return esc(v==null||v===''?'—':String(v))}
 function stateClass(state){return state==='Failed'||state==='Timed out'?'fail':state==='Published'?'pass':state==='Scanning'?'info':state==='Unknown'?'muted':'warn'}
 function findingHtml(row){var evidenceHtml=row.evidence&&Object.keys(row.evidence||{}).length?'<details><summary>Evidence</summary>'+evidence(row.evidence)+'</details>':'';return `<div class="scan-report-finding ${esc(row.severity||'informational')}"><b>${esc(row.title||'Observation')}</b><div class=meta>${esc((row.severity||'informational').toUpperCase())}${row.ruleId?' · '+esc(row.ruleId):''}${row.origin?' · '+esc(row.origin):''}</div><div>${esc(row.explanation||'')}</div>${row.whyTriggered?`<div class="scan-report-muted"><b>Why:</b> ${esc(row.whyTriggered)}</div>`:''}${evidenceHtml}</div>`}
 function renderScanReport(r,id){var state=r.currentStatus||{},q=r.queue||{},op=r.operation||{},run=op.run||{},plan=op.plan||{},a=op.assignment||{},worker=op.worker||{},last=r.lastPublishedEvidence||{},ident=r.identity||{},health=r.systemHealth||{},changes=r.changesSincePrevious||{},journey=r.journey||{},sections=r.findingReport?.sections||[];var position=a.queueKey?`<div class=scan-report-position><b>Exact queue assignment</b><code>${esc(a.queueKey)}</code><div>Wave ${fmt(plan.wave||0)} · ${esc(a.lane||'lane unknown')} slot ${fmt(a.slot||0)} · assignment ${fmt(a.workerAssignmentPosition||0)} of ${fmt(a.workerAssignmentCount||0)} in this worker</div><div class=scan-report-muted>Assignment position only — not “processed” progress.</div></div>`:'';var opBody=!op.authenticated?'<div class=scan-report-warning><b>Published Evidence remains available.</b><div>Sign in to add live GitHub operational correlation for this plugin.</div></div>':!op.available?`<div class=scan-report-warning><b>Operational snapshot unavailable.</b><div>${esc(op.error||'Use Refresh operation to explicitly acquire the current drain snapshot.')}</div></div>`:kvRows([['Production drain',run.runNumber?`#${fmt(run.runNumber)} · ${textv(run.status)}`:'not present'],['Run ID',textv(run.runId)],['Wave',textv(plan.wave)],['Worker slot',a.queueKey?textv(a.slot):'not assigned'],['Lane',a.queueKey?textv(a.lane):'—'],['Worker state',worker.jobId?`${textv(worker.status)}${worker.conclusion?' / '+textv(worker.conclusion):''}`:'not available'],['Started',textv(worker.startedAtUtc)],['Elapsed',textv(fmtElapsed(worker.elapsedSeconds))],['Other workers active',textv(op.workerSummary?.otherActive)]])+position;var findingSections=sections.map(function(group){var rows=group.records||[];return `<div class=scan-report-category><h4>${esc(group.category)} <span class="muted">${fmt(group.count||0)}</span></h4>${group.note?`<div class=scan-report-muted>${esc(group.note)}</div>`:''}${rows.map(findingHtml).join('')}</div>`}).join('')||'<div class=workspace-empty>No structured finding rows are present in the compact current Evidence view.</div>';var changeHtml=changes.available?(((changes.changes||[]).map(function(c){return `<div class=scan-report-row><b>${esc(c.label||c.kind||'Change')}</b>${c.detail?`<div class=scan-report-muted>${esc(c.detail)}</div>`:''}</div>`}).join('')||'<div class=pass>No security-semantic difference was projected between the comparable snapshots.</div>')+(changes.limits||[]).map(function(x){return `<div class=scan-report-muted>${esc(x)}</div>`}).join('')):`<div class=scan-report-muted>${esc(changes.explanation||'Previous comparable Evidence unavailable.')}</div>`;var journeyHtml=(journey.stages||[]).map(function(s){return `<button data-scan-focus="${esc(s.scanReportSection||'summary')}"><b>${esc(s.title||s.stageId||'Stage')}</b><span class="muted small">${esc(s.status||'unknown')} · ${esc(s.summary||'')}</span></button>`}).join('');var runLink=run.url?`<a href="${esc(run.url)}" target=_blank rel="noopener noreferrer">Open GitHub run</a>`:'';var workerLink=worker.url?`<a href="${esc(worker.url)}" target=_blank rel="noopener noreferrer">View worker/job</a>`:'';return `<div class=scan-report-shell><section class=scan-report-hero data-scan-section=summary><div class="scan-report-state ${stateClass(state.state)}">${esc(state.state||'Unknown')}</div><h3>${esc(ident.name||ident.internalName||'Plugin scan report')}</h3><p>${esc(r.executiveSummary||'')}</p><div class=scan-report-muted>${esc(state.explanation||'')}</div></section><div class=scan-report-grid><section class=scan-report-section data-scan-section=identity><h3>Plugin / variant identity</h3>${kvRows([['InternalName',textv(ident.internalName)],['Plugin / variant',`${textv(ident.pluginId)} / ${textv(ident.variantId)}`],['Version',textv(ident.version)],['Dalamud API',textv(ident.dalamudApiLevel)],['Artifact SHA-256',`<code>${textv(ident.artifactSha256)}</code>`],['Channel',textv(ident.artifactChannel)],['Source',textv(ident.sourceName)],['Repository',textv(ident.repository||ident.sourceUrl)]])}</section><section class="scan-report-section scan-report-operation" data-scan-section=operation><div class=panelhead style="padding:0 0 8px"><div><h3>Current operation</h3><div class="muted small">GitHub Actions metadata is operational context only.</div></div><button data-scan-refresh>Refresh operation</button></div>${opBody}</section><section class="scan-report-section scan-report-authority" data-scan-section=published><h3>Last published Evidence</h3>${kvRows([['Status',textv(last.status)],['Scan',textv(last.scanId)],['Completed',textv(last.scannedAtUtc)],['Evidence revision',`<code>${textv(last.evidenceRevision)}</code>`],['Package SHA-256',`<code>${textv(last.packageSha256)}</code>`],['Scanner',textv(last.scannerVersion||last.scannerRevision)],['Artifact analysis',textv(last.artifactAnalysisRevision)],['Source analysis',textv(last.sourceAnalysisRevision)],['Definitions',textv(last.definitionsRevision)],['Rule set',textv(last.ruleSetRevision)]])}<div class="scan-report-muted">This section is authoritative published Security Evidence v2. In-flight Actions data never replaces it.</div></section><section class=scan-report-section data-scan-section=queue><h3>Queue state</h3>${q.present?kvRows([['Queue key',`<code>${textv(q.selected?.queueKey)}</code>`],['Work type',textv(q.selected?.workType)],['State',textv(q.selected?.state)],['Reason',textv(q.selected?.reasonDetails?.[0]?.label||q.selected?.primaryReason)],['Explanation',textv(q.selected?.reasonDetails?.[0]?.explanation||q.selected?.operationalExplanation)],['Attempt',textv(q.selected?.attemptCount)],['Next eligible',textv(q.selected?.nextEligibleAtUtc)],['Previous scan',textv(q.selected?.currentScanId)] ]):'<div class=scan-report-muted>Not present in the currently published queue.</div>'}${q.publishedContext&&Object.keys(q.publishedContext).length?`<details><summary>Published queue context</summary>${evidence(q.publishedContext)}</details>`:''}</section><section class=scan-report-section data-scan-section=publication><h3>Merge / publication state</h3><div class=scan-report-muted>Worker finished ↓ result bundle available ↓ all required wave results available ↓ merge / validation ↓ one-writer publication ↓ Security Evidence v2 advanced.</div><p>${esc(r.mergePublication?.explanation||'')}</p>${(op.signals||[]).map(function(s){return `<div class=research-error><b>${esc(s.label||s.code)}</b><div>${esc(s.explanation||'')}</div></div>`}).join('')}${r.mergePublication?.workerCompleted?'<span class="pill pass">WORKER COMPLETED</span>':''}<span class="pill">Evidence authority: published only</span></section></div><section class=scan-report-section data-scan-section=findings><h3>Human-readable findings</h3><div class=scan-report-findings>${findingSections}</div></section><section class=scan-report-section data-scan-section=changes><h3>What changed since previous scan</h3>${changeHtml}</section><section class=scan-report-section data-scan-section=journey><h3>Asset Journey</h3><div class="muted small">The existing evidence-backed Asset Journey is reused here; these are report deep-links, not a second pipeline model.</div><div class=scan-report-journey>${journeyHtml}</div></section><section class=scan-report-section data-scan-section=health><h3>SigmaScope progress / system health</h3><div class=scan-report-system>${[['Published queued',health.publishedQueuedCount],['Eligible now',health.immediatelyEligibleCount],['Archive deferred',health.archiveDeferredCount],['Active workers',health.activeWorkerCount],['Wave assignments',health.assignmentsInCurrentWave],['Failed workers',health.failedWorkerCount],['Timed out',health.timedOutWorkerCount],['Last Evidence',health.lastEvidencePublicationTime||'—']].map(function(x){return `<div class=scan-report-metric><b>${textv(x[1])}</b><span class=muted>${esc(x[0])}</span></div>`}).join('')}</div><div class=scan-report-muted>${esc(health.successfulExactItemsExplanation||'')}</div></section><section class=scan-report-section data-scan-section=raw><h3>Raw / expert view</h3><div class=scan-report-raw-actions><button data-open-report-tab=evidence>View raw Evidence</button><button data-open-report-tab=findings>View exact observations</button><button data-open-report-tab=journey>Asset Journey</button>${runLink}${workerLink}</div><details><summary>Queue record</summary>${evidence(r.raw?.queueRecord||{})}</details><details><summary>SigmaScope planning assignment</summary>${evidence(r.raw?.planningAssignment||{})}</details></section></div>`}
 async function loadScanReport(id,refresh){var pane=document.querySelector('#pluginDetail [data-research-pane="scan-report"]');if(!pane)return;pane.innerHTML='<div class=workspace-empty>Loading human-readable published Evidence report…</div>';try{var r=await api('/api/plugin-scan-report?variant_id='+encodeURIComponent(id)+(refresh?'&refresh=1':''));pane.innerHTML=renderScanReport(r,id);pane.querySelector('[data-scan-refresh]')?.addEventListener('click',()=>loadScanReport(id,true));pane.querySelectorAll('[data-scan-focus]').forEach(function(b){b.addEventListener('click',function(){var target=pane.querySelector('[data-scan-section="'+b.dataset.scanFocus+'"]');target?.scrollIntoView({behavior:'smooth',block:'start'})})});pane.querySelectorAll('[data-open-report-tab]').forEach(function(b){b.addEventListener('click',()=>activateResearchTab(b.dataset.openReportTab))})}catch(e){pane.innerHTML=`<div class=research-error><b>Could not build scan report</b><div>${esc(e.message)}</div></div>`}}
 window.researchCaseHtml=function(d,id){var html=baseResearchCaseHtml(d,id);if(d?.catalogOnly)return html;html=html.replace('data-research-tab=overview>Overview</button>','data-research-tab=overview>Overview</button><button class=research-tab data-research-tab=scan-report>Scan report</button>');html=html.replace('<section class=research-pane data-research-pane=journey>','<section class=research-pane data-research-pane=scan-report><div class=workspace-empty>Open Scan report to build the human-readable Evidence view.</div></section><section class=research-pane data-research-pane=journey>');return html};
 window.wireResearchTabs=function(id){baseWireResearchTabs(id);var detail=document.getElementById('pluginDetail');detail?.querySelector('[data-research-tab="scan-report"]')?.addEventListener('click',function(){var pane=detail.querySelector('[data-research-pane="scan-report"]');if(pane&&!pane.dataset.scanLoaded){pane.dataset.scanLoaded='1';loadScanReport(id,false)}})};
},0);
'''

_SCAN_QUEUE_LIVE_JS = r'''
setTimeout(function(){
 if(window.__deltascopeQueueLiveInstalled)return;window.__deltascopeQueueLiveInstalled=true;
 var style=document.createElement('style');style.textContent=`
 .queue-live-badge{display:inline-block;padding:3px 7px;border:1px solid #8d8d8d;background:#f4f4f4;font-size:10px;font-weight:700;letter-spacing:.03em;white-space:nowrap}
 .queue-live-badge.scanning{border-color:#0f62fe;background:#edf5ff}.queue-live-badge.assigned{border-color:#8a3ffc;background:#f6f2ff}.queue-live-badge.waiting-for-other-workers,.queue-live-badge.waiting-for-merge,.queue-live-badge.waiting-for-publication,.queue-live-badge.worker-completed{border-color:#b28600;background:#fff8e1}.queue-live-badge.failed,.queue-live-badge.timed-out,.queue-live-badge.stale-superseded{border-color:#da1e28;background:#fff1f1}.queue-live-badge.retry-pending{border-color:#ff832b;background:#fff2e8}.queue-live-badge.queued{border-color:#8d8d8d;background:#f4f4f4}
 .queue-row.queue-live-scanning td:first-child{box-shadow:inset 3px 0 #0f62fe}.queue-row.queue-live-failed td:first-child,.queue-row.queue-live-timed-out td:first-child{box-shadow:inset 3px 0 #da1e28}
 .queue-live-card{margin:10px 0;padding:11px;border:1px solid #c6c6c6;border-left:4px solid #0f62fe;background:#f8fbff}.queue-live-card.failed,.queue-live-card.timed-out{border-left-color:#da1e28;background:#fff1f1}.queue-live-card .queue-live-facts{display:grid;grid-template-columns:120px minmax(0,1fr);gap:4px 9px;margin-top:8px}.queue-live-card .queue-live-links{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}.queue-live-card code{overflow-wrap:anywhere}
 #queueLiveFilter{min-width:150px}#queueLiveRefresh{white-space:nowrap}.queue-live-summary-note{font-size:10px;color:#525252;align-self:center}
 `;document.head.appendChild(style);
 function liveClass(value){return String(value||'unknown').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||'unknown'}
 function liveRow(key){var rows=Array.isArray(currentScanQueue?.queueItems)?currentScanQueue.queueItems:[];return rows.find(function(x){return String(x.queueKey||'')===String(key||'')})||null}
 function fmtElapsed(seconds){if(seconds==null||seconds==='')return'—';var s=Number(seconds||0),m=Math.floor(s/60),h=Math.floor(m/60);return h?`${h}h ${m%60}m`:`${m}m`}
 function isWaiting(state){return String(state||'').startsWith('Waiting ')}
 var baseFiltered=window.queueFilteredItems;
 if(typeof baseFiltered==='function'){
  window.queueFilteredItems=function(){var rows=baseFiltered(),filter=document.getElementById('queueLiveFilter')?.value||'';if(!filter)return rows;return rows.filter(function(x){var state=String(x.liveState||'Queued');if(filter==='waiting')return isWaiting(state);if(filter==='problem')return ['Failed','Timed out','Stale / superseded'].includes(state);return state===filter})};
  queueFilteredItems=window.queueFilteredItems;
 }
 var baseRows=window.renderQueueRows;
 if(typeof baseRows==='function'){
  window.renderQueueRows=function(){baseRows();document.querySelectorAll('#queueNextRows [data-queue-key]').forEach(function(tr){var x=liveRow(tr.dataset.queueKey);if(!x)return;var state=String(x.liveState||'Queued'),published=String(x.publishedQueueState||x.state||'pending').toUpperCase(),op=x.liveOperation||{},worker=op.worker||{},cell=tr.lastElementChild;if(!cell)return;tr.classList.add('queue-live-'+liveClass(state));var assignment=op.correlated?`<div class="muted tiny">wave ${fmt(op.wave??'—')} · slot ${fmt(op.slot??'—')}${op.lane?' · '+esc(op.lane):''}</div>`:'';var workerState=worker.jobId?`<div class="muted tiny">worker ${esc(worker.status||'unknown')}${worker.conclusion?' / '+esc(worker.conclusion):''}</div>`:'';cell.innerHTML=`<span class="queue-live-badge ${liveClass(state)}">${esc(state.toUpperCase())}</span><div class="muted tiny">published queue: ${esc(published)}</div>${assignment}${workerState}`})};
  renderQueueRows=window.renderQueueRows;
 }
 var baseSelected=window.renderQueueSelected;
 if(typeof baseSelected==='function'){
  window.renderQueueSelected=function(key){baseSelected(key);var x=liveRow(key)||liveRow(selectedQueueKey);if(!x)return;var detail=document.getElementById('queueSelectedDetail');if(!detail)return;detail.querySelectorAll('.queue-detail-kv b').forEach(function(label){if(label.textContent==='State')label.textContent='Published queue state'});var state=String(x.liveState||'Unknown'),op=x.liveOperation||{},worker=op.worker||{},overlay=currentScanQueue?.operationalOverlay||{},facts='';if(!overlay.available){facts=`<div class="muted small" style="margin-top:7px">${esc(overlay.error||overlay.notice||'Live SigmaScope state has not been acquired yet.')}</div>`}else if(op.correlated){facts=`<div class=queue-live-facts><b>Run</b><span>${op.runNumber?'#'+fmt(op.runNumber):'—'}${op.runStatus?' · '+esc(op.runStatus):''}</span><b>Wave / slot</b><span>${fmt(op.wave??'—')} / ${fmt(op.slot??'—')} ${op.lane?'· '+esc(op.lane):''}</span><b>Assignment</b><span>${fmt(op.workerAssignmentPosition??'—')} of ${fmt(op.workerAssignmentCount??'—')} in this worker</span><b>Worker</b><span>${worker.jobId?esc(worker.status||'unknown')+(worker.conclusion?' / '+esc(worker.conclusion):''):'state unavailable'}</span><b>Started</b><span>${esc(worker.startedAtUtc||'—')}</span><b>Elapsed</b><span>${esc(fmtElapsed(worker.elapsedSeconds))}</span></div><div class="muted tiny" style="margin-top:6px">Assignment position is placement in the worker batch, not per-item completion progress.</div>`}else{facts='<div class="muted small" style="margin-top:7px">This exact queue key is not assigned to the currently acquired bounded drain wave.</div>'}var links=[];if(op.runUrl)links.push(`<a href="${esc(op.runUrl)}" target=_blank rel="noopener noreferrer">Open GitHub run</a>`);if(worker.url)links.push(`<a href="${esc(worker.url)}" target=_blank rel="noopener noreferrer">Open worker job</a>`);var card=document.createElement('div');card.className='queue-live-card '+liveClass(state);card.innerHTML=`<div><span class="queue-live-badge ${liveClass(state)}">${esc(state.toUpperCase())}</span></div><div class="small" style="margin-top:6px">${esc(x.liveExplanation||'No bounded live explanation is available.')}</div>${facts}${links.length?'<div class=queue-live-links>'+links.join('')+'</div>':''}`;var title=detail.querySelector('.queue-selection-title');if(title)title.insertAdjacentElement('afterend',card);else detail.prepend(card)};
  renderQueueSelected=window.renderQueueSelected;
 }
 function ensureControls(){var toolbar=document.querySelector('#queueSearch')?.closest('.queue-toolbar');if(!toolbar)return;if(!document.getElementById('queueLiveFilter')){var select=document.createElement('select');select.id='queueLiveFilter';select.innerHTML='<option value="">All live states</option><option value="Scanning">Scanning</option><option value="Assigned">Assigned</option><option value="waiting">Waiting for merge/publication</option><option value="Worker completed">Worker completed</option><option value="Retry pending">Retry pending</option><option value="problem">Failed / timed out / stale</option><option value="Queued">Queued / not assigned</option><option value="Unknown">Unknown / live not acquired</option>';select.addEventListener('change',renderQueueRows);toolbar.appendChild(select)}if(!document.getElementById('queueLiveRefresh')){var button=document.createElement('button');button.id='queueLiveRefresh';button.textContent='Refresh live state';button.addEventListener('click',async function(){button.disabled=true;var old=button.textContent;button.textContent='Refreshing…';try{var payload=await api('/api/workbench/scan-queue?refresh=1');renderScanQueue(payload)}catch(e){if(typeof toniSay==='function')toniSay('Live queue refresh failed: '+e.message);button.textContent='Refresh failed';setTimeout(function(){button.textContent=old},1800)}finally{button.disabled=false}});toolbar.appendChild(button)}}
 function renderSummary(){var host=document.getElementById('queueCompactStats'),op=currentScanQueue?.operationalOverlay||{};if(!host)return;host.querySelectorAll('[data-queue-live-stat]').forEach(function(x){x.remove()});var refresh=document.getElementById('queueLiveRefresh');if(refresh){refresh.disabled=!op.authenticated;refresh.title=op.authenticated?'Acquire the current bounded SigmaScope drain snapshot':'Sign in to acquire live SigmaScope state'}if(!op.authenticated){host.insertAdjacentHTML('beforeend','<span data-queue-live-stat class=queue-live-summary-note>Sign in for live worker state</span>');return}if(!op.available){host.insertAdjacentHTML('beforeend',`<span data-queue-live-stat class=queue-live-summary-note>${esc(op.error||op.notice||'Live state not acquired yet')}</span>`);return}var c=op.counts||{},waiting=Object.entries(c).filter(function(x){return isWaiting(x[0])}).reduce(function(n,x){return n+Number(x[1]||0)},0),problem=Number(c.Failed||0)+Number(c['Timed out']||0)+Number(c['Stale / superseded']||0),chips=[['Scanning',c.Scanning],['Assigned',c.Assigned],['Waiting',waiting],['Worker done',c['Worker completed']],['Retry',c['Retry pending']],['Problem',problem],['Queued',c.Queued]].filter(function(x){return Number(x[1]||0)>0});chips.forEach(function(x){host.insertAdjacentHTML('beforeend',`<span data-queue-live-stat class=queue-stat><b>${fmt(x[1])}</b> ${esc(x[0].toLowerCase())}</span>`)});var suffix=op.run?.runNumber?`run #${fmt(op.run.runNumber)}${op.wave!=null?' · wave '+fmt(op.wave):''}`:'live snapshot';if(op.fetchedAtUtc)suffix+=' · '+esc(op.fetchedAtUtc);host.insertAdjacentHTML('beforeend',`<span data-queue-live-stat class=queue-live-summary-note>${suffix}</span>`)}
 var baseScan=window.renderScanQueue;
 if(typeof baseScan==='function'){
  window.renderScanQueue=function(q){baseScan(q);ensureControls();var th=document.querySelector('#queueNextRows')?.closest('table')?.querySelector('thead th:last-child');if(th)th.textContent='Live state';renderSummary()};
  renderScanQueue=window.renderScanQueue;
 }
 ensureControls();if(currentScanQueue)renderScanQueue(currentScanQueue);
},0);
'''


def _patch_html(html: str) -> str:
    text = str(html)
    if "__deltascopeScanReportInstalled" in text:
        return text
    script = _SCAN_REPORT_JS.replace("__SCAN_REPORT_CSS__", json.dumps(_SCAN_REPORT_CSS)) + "\n" + _SCAN_QUEUE_LIVE_JS
    marker = "</script>"
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError("DeltaScope HTML script boundary was not found")
    return text[:index] + "\n" + script + "\n" + text[index:]


def install() -> None:
    import developer_view

    if getattr(developer_view, "_deltascope_scan_report_installed", False):
        return
    developer_view.HTML = _patch_html(developer_view.HTML)
    original_get = developer_view.AppHandler.do_GET

    def patched_get(self: Any) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in {"/api/plugin-scan-report", "/api/workbench/scan-queue"}:
            return original_get(self)
        try:
            query = urllib.parse.parse_qs(parsed.query)
            client = getattr(self, "operations_client", None)
            if client is None:
                class _NoOperations:
                    def access_status(self) -> dict[str, Any]:
                        return {"tokenConfigured": False, "statusMode": "disabled"}
                client = _NoOperations()
                operational = {
                    "schema": OPERATION_SCHEMA, "available": False, "authenticated": False,
                    "readOnly": True, "mutationAuthority": "none", "securityAuthority": False,
                    "refreshRequired": False, "state": "disabled", "notice": "GitHub operational correlation is disabled.",
                }
            else:
                operational = acquire_sigmascope_operation(client, refresh=(query.get("refresh") or ["0"])[0] == "1")

            if parsed.path == "/api/workbench/scan-queue":
                summary = self.inspector.summary()
                queue_state = self.inspector.scan_queue_state() if hasattr(self.inspector, "scan_queue_state") else {}
                counts = summary.get("counts") if isinstance(summary.get("counts"), dict) else {}
                queue = deltascope_scan_queue.project_scan_queue(
                    queue_state, current_variants=int(counts.get("variants") or 0),
                )
                return self.json_response(project_scan_queue_operation(queue, operational))

            variant_id = int((query.get("variant_id") or ["0"])[0])
            if variant_id <= 0:
                return self.json_response({"error": "variant_id is required"}, 400)
            return self.json_response(project_scan_report(self.inspector, client, variant_id, operational=operational))
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get

    # Reuse DeltaScope's one explicit GitHub acquisition action. Navigation remains
    # snapshot-only; a user-triggered source refresh also acquires the bounded drain plan.
    try:
        import deltascope_operations
        cls = deltascope_operations.GitHubOperationsClient
        if not getattr(cls, "_deltascope_scan_report_refresh_wrapped", False):
            original_refresh = cls.refresh_snapshot
            def refresh_with_scan_report(self: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
                payload = dict(original_refresh(self, *args, **kwargs))
                payload["sigmascopeDrain"] = acquire_sigmascope_operation(self, refresh=True)
                return payload
            cls.refresh_snapshot = refresh_with_scan_report
            cls._deltascope_scan_report_refresh_wrapped = True
    except Exception:
        pass
    developer_view._deltascope_scan_report_installed = True
