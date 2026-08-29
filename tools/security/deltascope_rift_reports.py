"""Read-only Rift runtime-report projections and local DeltaScope intake snapshots."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable, Mapping


RIFT_RUNTIME_SCHEMA = "rift.runtime-observation.v2"
RIFT_COLLECTOR_SCHEMA = "omega.collector.rift.runtime.v1"
RIFT_REVIEW_SCHEMA = "omega.deltascope.rift-runtime-review.v1"
MAX_RIFT_REPORT_BYTES = 1536 * 1024
MAX_GITHUB_URL_CHARS = 4096


def _stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def _integer(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _text(value: Any) -> str:
    return str(value or "").strip()


def _json_paths(paths: Iterable[Path]) -> list[Path]:
    found: dict[Path, None] = {}
    for raw_path in paths:
        path = raw_path.expanduser()
        if path.is_dir():
            for candidate in sorted(path.rglob("*.json")):
                found[candidate.resolve()] = None
        elif path.is_file():
            found[path.resolve()] = None
    return sorted(found)


def _runtime_payload(document: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    if document.get("schema_version") == RIFT_RUNTIME_SCHEMA:
        return document, list(document.get("observations") or []), "rift runtime report"
    if document.get("schema_version") == RIFT_COLLECTOR_SCHEMA and document.get("collector") == "omega.collector.rift.runtime":
        subject = document.get("subject") if isinstance(document.get("subject"), dict) else {}
        plugin = subject.get("plugin") if isinstance(subject.get("plugin"), dict) else {}
        runtime = {
            "plugin": plugin,
            "execution": document.get("execution") if isinstance(document.get("execution"), dict) else {},
            "exercise": document.get("exercise") if isinstance(document.get("exercise"), dict) else {},
            "summary": {"total_observations": len(document.get("runtime_observations") or [])},
            "ran_at": "",
        }
        return runtime, list(document.get("runtime_observations") or []), "Omega collector projection"
    raise ValueError("expected Rift runtime observation v2 or Omega Rift runtime collector v1")


def _observation_label(observation: dict[str, Any]) -> str:
    kind = _text(observation.get("kind")) or "runtime observation"
    subject = _text(observation.get("component")) or _text(observation.get("target")) or _text(observation.get("message"))
    operation = _text(observation.get("operation"))
    if subject and operation:
        return f"{kind}: {subject} · {operation}"
    return f"{kind}: {subject}" if subject else kind


def _decode_document(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_RIFT_REPORT_BYTES:
        raise ValueError(f"Rift report exceeds the {MAX_RIFT_REPORT_BYTES // 1024} KiB local intake limit")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Rift report is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("top-level JSON must be an object")
    return document


def _project_document(document: dict[str, Any], *, source: str, source_key: str, acquired_from: str) -> dict[str, Any]:
    runtime, observations, source_kind = _runtime_payload(document)
    plugin = runtime.get("plugin") if isinstance(runtime.get("plugin"), dict) else {}
    execution = runtime.get("execution") if isinstance(runtime.get("execution"), dict) else {}
    timeline = []
    for index, raw_observation in enumerate(observations):
        if not isinstance(raw_observation, dict):
            continue
        offset = _integer(raw_observation.get("ts_offset_ms"))
        timeline.append({
            "eventId": _stable_id("rift-event", {"report": source_key, "index": index, "observation": raw_observation}),
            "offsetMs": offset, "kind": _text(raw_observation.get("kind")) or "runtime observation",
            "phase": _text(raw_observation.get("phase")) or "unattributed", "label": _observation_label(raw_observation),
            "component": _text(raw_observation.get("component")), "operation": _text(raw_observation.get("operation")),
            "target": _text(raw_observation.get("target")), "registrationId": _text(raw_observation.get("registration_id")),
            "invocation": raw_observation.get("invocation"),
        })
    timeline.sort(key=lambda item: (item["offsetMs"], item["eventId"]))
    exercise = runtime.get("exercise") if isinstance(runtime.get("exercise"), dict) else {}
    reported_count = _integer((runtime.get("summary") or {}).get("total_observations")) if isinstance(runtime.get("summary"), dict) else len(timeline)
    return {
        "reportId": _stable_id("rift-report", {"source": source_key, "schema": document.get("schema_version"), "ranAt": runtime.get("ran_at")}),
        "source": source, "sourceKind": source_kind, "acquiredFrom": acquired_from,
        "status": "reviewable", "readOnly": True,
        "schemaVersion": _text(document.get("schema_version")), "ranAt": _text(runtime.get("ran_at")),
        "plugin": {"name": _text(plugin.get("internal_name")) or _text(plugin.get("assembly_name")) or Path(source).stem,
                   "assemblyName": _text(plugin.get("assembly_name")), "loadOutcome": _text(plugin.get("load_outcome")) or _text(execution.get("outcome"))},
        "execution": {"network": _text(execution.get("network")), "profile": _text(execution.get("exercise_profile")) or _text(exercise.get("profile")),
                      "status": _text(exercise.get("status"))},
        "observationCount": len(timeline), "reportedObservationCount": reported_count,
        "durationMs": max((item["offsetMs"] for item in timeline), default=0), "timeline": timeline,
        "exercise": {"discovered": _integer(exercise.get("registrations_discovered")), "exercised": _integer(exercise.get("registrations_exercised")),
                     "unexercised": _integer(exercise.get("registrations_unexercised")), "byKind": exercise.get("by_kind") if isinstance(exercise.get("by_kind"), dict) else {}},
    }


def _unreadable(source: str, source_key: str, reason: str, acquired_from: str) -> dict[str, Any]:
    return {
        "reportId": _stable_id("rift-report", {"source": source_key}), "source": source,
        "sourceKind": "unreadable", "acquiredFrom": acquired_from,
        "status": "unreadable", "reason": reason, "timeline": [], "observationCount": 0, "readOnly": True,
    }


def _project_report(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        document = _decode_document(raw)
        return _project_document(document, source=path.name, source_key=str(path), acquired_from="configured-local-file")
    except (OSError, ValueError) as exc:
        return _unreadable(path.name, str(path), str(exc), "configured-local-file")


def _github_json_request(url: str, *, token: str = "") -> urllib.request.Request:
    text = str(url or "").strip()
    if not text or len(text) > MAX_GITHUB_URL_CHARS:
        raise ValueError("GitHub report URL is required and must be bounded")
    parsed = urllib.parse.urlparse(text)
    host = parsed.hostname.casefold() if parsed.hostname else ""
    if parsed.scheme != "https" or host not in {"github.com", "raw.githubusercontent.com"}:
        raise ValueError("Rift report links must use https://github.com or https://raw.githubusercontent.com")
    headers = {"User-Agent": "Omega-DeltaScope/Rift-Intake", "Accept": "application/vnd.github.raw+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if host == "raw.githubusercontent.com":
        return urllib.request.Request(text, headers=headers)
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[2] not in {"blob", "raw"}:
        raise ValueError("GitHub Rift report link must point to a file, for example /owner/repo/blob/ref/report.json")
    owner, repo, _, ref = parts[:4]
    path = "/".join(parts[4:])
    if not path.casefold().endswith(".json"):
        raise ValueError("GitHub Rift report link must point to a JSON file")
    api = (
        f"https://api.github.com/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"
        f"/contents/{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(ref, safe='')}"
    )
    return urllib.request.Request(api, headers=headers)


def _read_github_json(url: str, *, token: str = "", opener: Any = None) -> bytes:
    request = _github_json_request(url, token=token)
    open_url = opener or urllib.request.urlopen
    with open_url(request, timeout=8) as response:
        raw = response.read(MAX_RIFT_REPORT_BYTES + 1)
        content_type = str(getattr(response, "headers", {}).get("Content-Type", ""))
    if len(raw) > MAX_RIFT_REPORT_BYTES:
        raise ValueError(f"Rift report exceeds the {MAX_RIFT_REPORT_BYTES // 1024} KiB local intake limit")
    # The GitHub contents API normally returns JSON metadata even with the raw Accept header
    # in some test/proxy environments. Decode that bounded representation when encountered.
    if request.full_url.startswith("https://api.github.com/") and ("json" in content_type.casefold() or raw.lstrip().startswith(b"{")):
        try:
            payload = json.loads(raw.decode("utf-8"))
            if isinstance(payload, Mapping) and str(payload.get("encoding") or "").casefold() == "base64":
                return base64.b64decode("".join(str(payload.get("content") or "").split()), validate=True)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            pass
    return raw


class RiftReportStore:
    """Process-local report snapshot. Navigation reads memory; acquisition is explicit."""

    def __init__(self, configured_paths: Iterable[Path] = ()) -> None:
        self.configured_paths = tuple(configured_paths)
        self._lock = threading.RLock()
        self._configured: list[dict[str, Any]] = []
        self._imports: dict[str, dict[str, Any]] = {}
        self.reload_configured()

    def reload_configured(self) -> dict[str, Any]:
        reports = [_project_report(path) for path in _json_paths(self.configured_paths)]
        with self._lock:
            self._configured = reports
        return {"refreshed": True, "configuredReportCount": len(reports), "navigationRefresh": False}

    def import_text(self, name: str, text: str) -> dict[str, Any]:
        label = Path(str(name or "uploaded-rift-report.json")).name[:255] or "uploaded-rift-report.json"
        raw = str(text or "").encode("utf-8")
        document = _decode_document(raw)
        source_key = f"upload:{label}:{hashlib.sha256(raw).hexdigest()}"
        report = _project_document(document, source=label, source_key=source_key, acquired_from="local-upload")
        with self._lock:
            self._imports[report["reportId"]] = report
        return report

    def import_github(self, url: str, *, token: str = "", opener: Any = None) -> dict[str, Any]:
        raw = _read_github_json(url, token=token, opener=opener)
        document = _decode_document(raw)
        parsed = urllib.parse.urlparse(str(url).strip())
        label = Path(parsed.path).name or "github-rift-report.json"
        source_key = f"github:{str(url).strip()}:{hashlib.sha256(raw).hexdigest()}"
        report = _project_document(document, source=label, source_key=source_key, acquired_from="github-link")
        report["sourceUrl"] = str(url).strip()
        with self._lock:
            self._imports[report["reportId"]] = report
        return report

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            reports = [dict(report) for report in self._configured] + [dict(report) for report in self._imports.values()]
        reports.sort(key=lambda report: (report.get("ranAt") or "", report.get("source") or ""), reverse=True)
        reviewable = [report for report in reports if report.get("status") == "reviewable"]
        return {
            "schema": RIFT_REVIEW_SCHEMA, "readOnly": True, "mutationAuthority": "none",
            "reports": reports, "reportCount": len(reports), "reviewableCount": len(reviewable),
            "observationCount": sum(_integer(report.get("observationCount")) for report in reviewable),
            "configuredReportCount": len(self._configured), "sessionImportCount": len(self._imports),
            "navigationRefresh": False, "refreshPolicy": "explicit-intake-or-data-source-refresh",
            "notice": "Rift observations are neutral runtime evidence. Imported reports are held in this local DeltaScope session; navigation never refetches them.",
        }

    def acquisition_status(self) -> dict[str, Any]:
        snap = self.snapshot()
        return {
            "sourceId": "rift-runtime", "label": "Rift runtime reports", "loaded": bool(snap["reportCount"]),
            "cachePolicy": "explicit-refresh", "navigationRefresh": False,
            "configuredReportCount": snap["configuredReportCount"], "sessionImportCount": snap["sessionImportCount"],
            "reportCount": snap["reportCount"],
        }


def project_review(paths: Iterable[Path]) -> dict[str, Any]:
    """Backwards-compatible one-shot projection used by callers/tests outside the server."""
    return RiftReportStore(paths).snapshot()
