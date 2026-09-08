#!/usr/bin/env python3
"""Bounded retained operational telemetry history for DeltaScope.

Only sanitized ``omega.actions.telemetry.v1`` events and the minimal GitHub run/job
identity needed to deduplicate them are persisted. Raw job logs, credentials, request
headers and Security Evidence never enter this store.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

import deltascope_live_operations as live
import deltascope_operations
import omega_actions_telemetry

JOURNAL_SCHEMA = "omega.deltascope.operations-history.v1"
DEFAULT_HISTORY_ROOT = Path(".omega") / "deltascope" / "operations" / "v1"
MAX_ENTRIES = 2048
MAX_SCANNED_RUNS = 256
MAX_VIEW_EVENTS = 256
MAX_AGE_DAYS = 14
BACKFILL_SECONDS = 120
MAX_BACKFILL_RUNS = 1
MAX_BACKFILL_JOBS = 4
MIN_BACKFILL_RATE_REMAINING = 1200


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_history_root() -> Path:
    override = os.environ.get("OMEGA_DELTASCOPE_OPERATIONS_HISTORY_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / DEFAULT_HISTORY_ROOT).resolve()


def _journal_name(repository: str) -> str:
    digest = hashlib.sha256(repository.encode("utf-8")).hexdigest()[:16]
    return f"telemetry-{digest}.json"


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _event_time(value: Any) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _identity(row: Mapping[str, Any], event: Mapping[str, Any]) -> str:
    subject = event.get("subject") if isinstance(event.get("subject"), Mapping) else {}
    parts = (
        str(_int(row.get("runId"))),
        str(_int(row.get("jobId"))),
        str(event.get("event") or ""),
        str(event.get("emittedAtUtc") or ""),
        str(event.get("component") or ""),
        str(event.get("stage") or ""),
        str(_int(subject.get("pluginId"))),
        str(_int(subject.get("variantId"))),
    )
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


class OperationsHistoryStore:
    """Atomic local journal for sanitized operational telemetry."""

    def __init__(self, repository: str, root: Path | None = None) -> None:
        self.repository = str(repository or "").strip()
        if not self.repository:
            raise ValueError("operations history repository is required")
        self.root = (root or default_history_root()).expanduser().resolve()
        self.path = self.root / _journal_name(self.repository)

    def _empty(self) -> dict[str, Any]:
        return {
            "schema": JOURNAL_SCHEMA,
            "repository": self.repository,
            "updatedAtUtc": "",
            "entries": [],
            "scannedCompletedRunIds": [],
        }

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("DeltaScope operations history root may not be a symlink")
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("DeltaScope operations history must be a regular file")
        document = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(document, Mapping) or document.get("schema") != JOURNAL_SCHEMA:
            raise ValueError("DeltaScope operations history has an invalid schema")
        if str(document.get("repository") or "") != self.repository:
            raise ValueError("DeltaScope operations history belongs to another repository")
        entries = document.get("entries")
        scanned = document.get("scannedCompletedRunIds")
        if not isinstance(entries, list) or not isinstance(scanned, list):
            raise ValueError("DeltaScope operations history has invalid collections")
        return dict(document)

    def _normalize_entry(self, row: Mapping[str, Any]) -> dict[str, Any] | None:
        raw_event = row.get("event") if isinstance(row.get("event"), Mapping) else row
        try:
            event = omega_actions_telemetry.sanitize_event(raw_event)
        except (TypeError, ValueError):
            return None
        emitted = _event_time(event.get("emittedAtUtc"))
        if emitted is None:
            return None
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=MAX_AGE_DAYS)
        if emitted < cutoff:
            return None
        identity = str(row.get("identity") or "") if isinstance(row.get("event"), Mapping) else ""
        entry = {
            "identity": identity or _identity(row, event),
            "runId": _int(row.get("runId")),
            "runNumber": _int(row.get("runNumber")),
            "jobId": _int(row.get("jobId")),
            "event": event,
        }
        return entry

    def _prune(self, document: dict[str, Any]) -> dict[str, Any]:
        by_identity: dict[str, dict[str, Any]] = {}
        for raw in document.get("entries") or []:
            if not isinstance(raw, Mapping):
                continue
            entry = self._normalize_entry(raw)
            if entry is not None:
                by_identity[entry["identity"]] = entry
        entries = list(by_identity.values())
        entries.sort(
            key=lambda row: (
                str((row.get("event") or {}).get("emittedAtUtc") or ""),
                _int(row.get("runId")),
                _int(row.get("jobId")),
            ),
            reverse=True,
        )
        scanned = []
        seen_runs: set[int] = set()
        for value in document.get("scannedCompletedRunIds") or []:
            run_id = _int(value)
            if run_id and run_id not in seen_runs:
                seen_runs.add(run_id)
                scanned.append(run_id)
            if len(scanned) >= MAX_SCANNED_RUNS:
                break
        return {
            "schema": JOURNAL_SCHEMA,
            "repository": self.repository,
            "updatedAtUtc": str(document.get("updatedAtUtc") or ""),
            "entries": entries[:MAX_ENTRIES],
            "scannedCompletedRunIds": scanned,
        }

    def _save(self, document: Mapping[str, Any]) -> None:
        self._ensure_root()
        clean = self._prune(dict(document))
        clean["updatedAtUtc"] = _utc_now()
        data = (json.dumps(clean, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            with tmp.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def append_events(self, rows: list[Mapping[str, Any]]) -> int:
        document = self._load()
        entries = list(document.get("entries") or [])
        before = len(entries)
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            entry = self._normalize_entry(row)
            if entry is not None:
                entries.append(entry)
        document["entries"] = entries
        clean = self._prune(document)
        self._save(clean)
        return max(0, len(clean["entries"]) - min(before, len(clean["entries"])))

    def mark_completed_run_scanned(self, run_id: int) -> None:
        run_id = _int(run_id)
        if not run_id:
            return
        document = self._load()
        scanned = [run_id, *list(document.get("scannedCompletedRunIds") or [])]
        document["scannedCompletedRunIds"] = scanned
        self._save(document)

    def completed_run_scanned(self, run_id: int) -> bool:
        run_id = _int(run_id)
        if not run_id:
            return True
        document = self._prune(self._load())
        if run_id in {_int(value) for value in document.get("scannedCompletedRunIds") or []}:
            return True
        return any(_int(row.get("runId")) == run_id for row in document.get("entries") or [] if isinstance(row, Mapping))

    def events(self, *, limit: int = MAX_VIEW_EVENTS) -> list[dict[str, Any]]:
        document = self._prune(self._load())
        result: list[dict[str, Any]] = []
        for entry in document.get("entries") or []:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("event"), Mapping):
                continue
            result.append({
                **dict(entry["event"]),
                "runId": _int(entry.get("runId")),
                "runNumber": _int(entry.get("runNumber")),
                "jobId": _int(entry.get("jobId")),
            })
            if len(result) >= max(1, min(int(limit or MAX_VIEW_EVENTS), MAX_VIEW_EVENTS)):
                break
        return result

    def descriptor(self) -> dict[str, Any]:
        document = self._prune(self._load())
        return {
            "schema": JOURNAL_SCHEMA,
            "persistedEventCount": len(document.get("entries") or []),
            "scannedCompletedRuns": len(document.get("scannedCompletedRunIds") or []),
            "maxEvents": MAX_ENTRIES,
            "maxAgeDays": MAX_AGE_DAYS,
            "containsRawLogs": False,
            "containsCredentials": False,
            "securityAuthority": False,
        }


def _store(client: Any) -> OperationsHistoryStore:
    with client._lock:
        store = getattr(client, "_operations_history_store", None)
        if store is None:
            store = OperationsHistoryStore(client.repository)
            client._operations_history_store = store
        if not hasattr(client, "_operations_history_backfill_at"):
            client._operations_history_backfill_at = 0.0
        return store


def _rate_allows_backfill(result: Mapping[str, Any]) -> bool:
    rate = result.get("rateLimit") if isinstance(result.get("rateLimit"), Mapping) else {}
    limit = _int(rate.get("limit"))
    remaining = _int(rate.get("remaining"))
    if limit <= 0:
        return True
    return remaining >= MIN_BACKFILL_RATE_REMAINING


def _completed_run_candidates(client: Any, store: OperationsHistoryStore) -> list[dict[str, Any]]:
    repository = urllib.parse.quote(client.repository, safe="/")
    url = f"https://api.github.com/repos/{repository}/actions/runs?per_page={deltascope_operations.MAX_RUNS}"
    payload = live._live_request_json(client, url)
    rows = payload.get("workflow_runs")
    if not isinstance(rows, list):
        raise RuntimeError("GitHub retained-history response has no workflow_runs list")
    candidates: list[dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        run = deltascope_operations.normalize_run(raw)
        run_id = _int(run.get("runId"))
        if not run_id or str(run.get("state") or "") == "running" or store.completed_run_scanned(run_id):
            continue
        candidates.append(run)
        if len(candidates) >= MAX_BACKFILL_RUNS:
            break
    return candidates


def _backfill_completed(client: Any, result: Mapping[str, Any], store: OperationsHistoryStore) -> list[dict[str, Any]]:
    if not _rate_allows_backfill(result):
        return []
    now = time.monotonic()
    with client._lock:
        last = float(getattr(client, "_operations_history_backfill_at", 0.0) or 0.0)
        if now - last < BACKFILL_SECONDS:
            return []
        client._operations_history_backfill_at = now
    added: list[dict[str, Any]] = []
    for run in _completed_run_candidates(client, store):
        run_id = _int(run.get("runId"))
        jobs = live._request_live_jobs(client, run)
        for job in jobs[:MAX_BACKFILL_JOBS]:
            projection = live._job_telemetry(client, job, force=True)
            for event in projection.get("events") or []:
                if not isinstance(event, Mapping):
                    continue
                added.append({
                    **dict(event),
                    "runId": run_id,
                    "runNumber": _int(job.get("runNumber")),
                    "jobId": _int(job.get("jobId")),
                    "jobName": str(job.get("name") or ""),
                    "runnerId": _int(job.get("runnerId")),
                    "runnerName": str(job.get("runnerName") or ""),
                    "workflow": str(job.get("workflow") or ""),
                    "workflowPath": str(job.get("workflowPath") or ""),
                })
        store.mark_completed_run_scanned(run_id)
    return added


def retain_live_status(original: Any, client: Any, *, foreground: bool = True, force: bool = False) -> dict[str, Any]:
    result = original(client, foreground=foreground, force=force)
    if not isinstance(result, Mapping):
        return result
    retained = dict(result)
    if not retained.get("authenticated") or not retained.get("available"):
        return retained
    telemetry = retained.get("telemetry") if isinstance(retained.get("telemetry"), Mapping) else {}
    live_events = [dict(row) for row in telemetry.get("recentEvents") or [] if isinstance(row, Mapping)]
    try:
        store = _store(client)
        if live_events:
            store.append_events(live_events)
        backfilled = _backfill_completed(client, retained, store)
        if backfilled:
            store.append_events(backfilled)
        history = store.events()
        merged = dict(telemetry)
        merged.update({
            "available": bool(history),
            "source": "retained-local-journal",
            "eventCount": len(history),
            "recentEvents": history,
            "retainedHistory": store.descriptor(),
            "backfilledEventCount": len(backfilled),
        })
        retained["telemetry"] = merged
        counts = dict(retained.get("counts") or {})
        counts["telemetryEvents"] = len(history)
        retained["counts"] = counts
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        warnings = [str(value) for value in retained.get("warnings") or []]
        warnings.append(f"retained operations history unavailable: {str(exc)[:256]}")
        retained["warnings"] = warnings[:8]
    return retained


def install() -> None:
    if getattr(deltascope_operations.GitHubOperationsClient, "_deltascope_operations_history_installed", False):
        return
    original = live.live_status

    def retained_live_status(client: Any, *, foreground: bool = True, force: bool = False) -> dict[str, Any]:
        return retain_live_status(original, client, foreground=foreground, force=force)

    live.live_status = retained_live_status
    deltascope_operations.GitHubOperationsClient.live_status = retained_live_status
    deltascope_operations.GitHubOperationsClient._deltascope_operations_history_installed = True
