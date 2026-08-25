"""Local Investigator notebook/case storage for DeltaScope.

Investigator casework is intentionally local user state.  It may reference published
Security Evidence v2, findings, observations and derived DeltaScope pivots, but it is
never itself security evidence and has no production authority.

Default layout::

    ~/.omega/deltascope/investigator/v1/
      case-<opaque-id>.json

Files are generated internally, atomically replaced, bounded, and symlinks are rejected.
No case content is written to Security Evidence, Definitions, scanner queues, GitHub or
other production state.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Mapping
import uuid

STORE_SCHEMA = "omega.deltascope.investigator-case-store.v1"
CASE_SCHEMA = "omega.deltascope.investigator-case.v1"
ITEM_SCHEMA = "omega.deltascope.investigator-case-item.v1"
DEFAULT_RELATIVE_ROOT = Path(".omega") / "deltascope" / "investigator" / "v1"
MAX_CASES = 512
MAX_ITEMS_PER_CASE = 2000
MAX_NOTES_PER_CASE = 1000
MAX_CASE_BYTES = 2 * 1024 * 1024
MAX_TITLE_CHARS = 240
MAX_SUMMARY_CHARS = 4000
MAX_NOTE_CHARS = 32768
MAX_LABELS = 32
MAX_LABEL_CHARS = 80
ALLOWED_STATUS = {"open", "watching", "resolved", "archived"}
ALLOWED_ITEM_KINDS = {"bookmark", "finding", "observation", "pivot", "evidence-snapshot"}
ALLOWED_REFERENCE_KEYS = {
    "variantId", "pluginId", "pluginName", "internalName", "version", "scanId",
    "findingId", "ruleId", "severity", "category", "title", "collection", "rowKey",
    "pivotKind", "pivotKey", "pivotLabel", "relationshipRevision", "snapshotKind",
    "snapshotPath", "snapshotSha256", "evidenceRevision", "definitionsRevision", "ruleSetRevision",
    "projectionRevision", "artifactSha256", "scannedAtUtc", "sourceName", "sourceUrl",
    "dataset", "datasetPath", "datasetSha256", "observationId", "observationLabel",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_case_root() -> Path:
    override = os.environ.get("OMEGA_DELTASCOPE_CASE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / DEFAULT_RELATIVE_ROOT).resolve()


def _bounded_text(value: Any, limit: int, field: str) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if len(text) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    return text


def _case_id(value: Any) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"case-[0-9a-f]{20}", text):
        raise ValueError("invalid investigator case id")
    return text


def _item_id(value: Any) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"item-[0-9a-f]{20}", text):
        raise ValueError("invalid investigator case item id")
    return text


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _clean_labels(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("labels must be a list")
    result: list[str] = []
    seen: set[str] = set()
    for raw in value[: MAX_LABELS + 1]:
        label = _bounded_text(raw, MAX_LABEL_CHARS, "label")
        if not label:
            continue
        key = label.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(label)
    if len(result) > MAX_LABELS:
        raise ValueError(f"labels are limited to {MAX_LABELS}")
    return result


def _clean_reference(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("item reference must be an object")
    out: dict[str, Any] = {}
    for key, raw in value.items():
        key = str(key)
        if key not in ALLOWED_REFERENCE_KEYS:
            continue
        if isinstance(raw, bool):
            out[key] = raw
        elif isinstance(raw, int):
            out[key] = raw
        elif isinstance(raw, str):
            out[key] = _bounded_text(raw, 4096, f"reference.{key}")
        elif isinstance(raw, list):
            vals = []
            for item in raw[:100]:
                if isinstance(item, (str, int, bool)):
                    vals.append(_bounded_text(item, 1024, f"reference.{key}") if isinstance(item, str) else item)
            out[key] = vals
    return out


def _authority() -> dict[str, Any]:
    return {
        "localOnly": True,
        "mutationAuthority": "local-user-files-only",
        "securityAuthority": False,
        "findingAuthority": False,
        "policyInput": False,
        "productionWriteBack": False,
        "evidenceWriteBack": False,
        "definitionsWriteBack": False,
        "queueMutationAuthorized": False,
        "publicationWriteBack": False,
        "repositoryWriteBack": False,
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with tmp.open("wb") as handle:
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


class LocalInvestigatorCaseStore:
    """Bounded local notebook/case store with no security or production authority."""

    def __init__(self, root: Path | None = None):
        self.root = (root or default_case_root()).expanduser().absolute()
        self._lock = threading.RLock()

    def reference(self) -> dict[str, Any]:
        return {
            "schema": STORE_SCHEMA,
            "root": str(self.root),
            "version": 1,
            "maxCases": MAX_CASES,
            "maxItemsPerCase": MAX_ITEMS_PER_CASE,
            **_authority(),
        }

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("DeltaScope investigator case root may not be a symlink")
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _paths(self) -> list[Path]:
        if not self.root.exists():
            return []
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("DeltaScope investigator case root must be a real directory")
        rows: list[Path] = []
        for path in sorted(self.root.glob("case-*.json"), key=lambda p: p.name):
            if path.is_symlink() or not path.is_file():
                continue
            rows.append(path)
            if len(rows) > MAX_CASES:
                raise ValueError(f"investigator case store exceeds {MAX_CASES} cases")
        return rows

    def _path(self, case_id: str) -> Path:
        case_id = _case_id(case_id)
        return self.root / f"{case_id}.json"

    def _read_path(self, path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise ValueError("investigator case path is missing or unsafe")
        if path.stat().st_size > MAX_CASE_BYTES:
            raise ValueError(f"investigator case exceeds {MAX_CASE_BYTES} bytes")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != CASE_SCHEMA:
            raise ValueError(f"invalid investigator case document: {path.name}")
        _case_id(raw.get("caseId"))
        if len(raw.get("items") or []) > MAX_ITEMS_PER_CASE:
            raise ValueError("investigator case has too many pinned items")
        if len(raw.get("notes") or []) > MAX_NOTES_PER_CASE:
            raise ValueError("investigator case has too many notes")
        # Local JSON can be inspected or manually edited, but its content can never grant
        # itself security authority.  Reassert the boundary on every read.
        raw.update(_authority())
        normalized_items: list[dict[str, Any]] = []
        for item in raw.get("items") or []:
            if not isinstance(item, Mapping):
                continue
            normalized = dict(item)
            normalized.update(_authority())
            normalized_items.append(normalized)
        raw["items"] = normalized_items
        return raw

    def _read(self, case_id: str) -> tuple[Path, dict[str, Any]]:
        path = self._path(case_id)
        if not path.exists():
            raise ValueError(f"unknown investigator case {case_id}")
        return path, self._read_path(path)

    def _write(self, path: Path, case: Mapping[str, Any]) -> dict[str, Any]:
        payload = json.dumps(dict(case), indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        if len(payload) > MAX_CASE_BYTES:
            raise ValueError(f"investigator case exceeds {MAX_CASE_BYTES} bytes")
        _atomic_write(path, payload)
        return dict(case)

    def list_cases(self) -> dict[str, Any]:
        with self._lock:
            rows: list[dict[str, Any]] = []
            for path in self._paths():
                try:
                    case = self._read_path(path)
                    rows.append({
                        "caseId": case["caseId"],
                        "title": case.get("title") or "Untitled case",
                        "summary": case.get("summary") or "",
                        "status": case.get("status") or "open",
                        "labels": list(case.get("labels") or []),
                        "createdAtUtc": case.get("createdAtUtc") or "",
                        "updatedAtUtc": case.get("updatedAtUtc") or "",
                        "revision": int(case.get("revision") or 1),
                        "itemCount": len(case.get("items") or []),
                        "noteCount": len(case.get("notes") or []),
                    })
                except Exception as exc:
                    rows.append({
                        "caseId": path.stem,
                        "title": path.stem,
                        "status": "invalid",
                        "updatedAtUtc": "",
                        "itemCount": 0,
                        "noteCount": 0,
                        "error": str(exc),
                    })
            rows.sort(key=lambda row: (str(row.get("status")) != "archived", str(row.get("updatedAtUtc") or "")), reverse=True)
            return {**self.reference(), "available": True, "caseCount": len(rows), "cases": rows}

    def get_case(self, case_id: str) -> dict[str, Any]:
        with self._lock:
            _path, case = self._read(case_id)
            return {**case, "store": self.reference()}

    def create_case(self, title: str, *, summary: str = "", labels: Any = None) -> dict[str, Any]:
        title = _bounded_text(title, MAX_TITLE_CHARS, "title") or "Untitled case"
        summary = _bounded_text(summary, MAX_SUMMARY_CHARS, "summary")
        labels_clean = _clean_labels(labels)
        with self._lock:
            self._ensure_root()
            if len(self._paths()) >= MAX_CASES:
                raise ValueError(f"investigator case store is limited to {MAX_CASES} cases")
            case_id = _new_id("case")
            now = utc_now()
            case = {
                "schema": CASE_SCHEMA,
                "caseId": case_id,
                "title": title,
                "summary": summary,
                "status": "open",
                "labels": labels_clean,
                "createdAtUtc": now,
                "updatedAtUtc": now,
                "revision": 1,
                "notes": [],
                "items": [],
                **_authority(),
            }
            self._write(self._path(case_id), case)
            return {**case, "store": self.reference()}

    def update_case(self, case_id: str, *, title: Any = None, summary: Any = None, status: Any = None, labels: Any = None) -> dict[str, Any]:
        with self._lock:
            path, case = self._read(case_id)
            if title is not None:
                case["title"] = _bounded_text(title, MAX_TITLE_CHARS, "title") or "Untitled case"
            if summary is not None:
                case["summary"] = _bounded_text(summary, MAX_SUMMARY_CHARS, "summary")
            if status is not None:
                normalized = str(status or "").strip().lower()
                if normalized not in ALLOWED_STATUS:
                    raise ValueError(f"status must be one of: {', '.join(sorted(ALLOWED_STATUS))}")
                case["status"] = normalized
            if labels is not None:
                case["labels"] = _clean_labels(labels)
            case["updatedAtUtc"] = utc_now()
            case["revision"] = int(case.get("revision") or 0) + 1
            self._write(path, case)
            return {**case, "store": self.reference()}

    def add_note(self, case_id: str, text: str) -> dict[str, Any]:
        note = _bounded_text(text, MAX_NOTE_CHARS, "note")
        if not note:
            raise ValueError("note is required")
        with self._lock:
            path, case = self._read(case_id)
            notes = list(case.get("notes") or [])
            if len(notes) >= MAX_NOTES_PER_CASE:
                raise ValueError(f"investigator case is limited to {MAX_NOTES_PER_CASE} notes")
            now = utc_now()
            row = {"noteId": _new_id("note"), "text": note, "createdAtUtc": now}
            notes.append(row)
            case["notes"] = notes
            case["updatedAtUtc"] = now
            case["revision"] = int(case.get("revision") or 0) + 1
            self._write(path, case)
            return {"ok": True, "note": row, "case": {**case, "store": self.reference()}}

    def add_item(
        self,
        case_id: str,
        *,
        kind: str,
        label: str,
        reference: Any = None,
        note: str = "",
        pinned: bool = True,
    ) -> dict[str, Any]:
        kind = str(kind or "").strip().lower()
        if kind not in ALLOWED_ITEM_KINDS:
            raise ValueError(f"item kind must be one of: {', '.join(sorted(ALLOWED_ITEM_KINDS))}")
        label = _bounded_text(label, MAX_TITLE_CHARS, "item label") or kind
        note = _bounded_text(note, MAX_SUMMARY_CHARS, "item note")
        ref = _clean_reference(reference)
        with self._lock:
            path, case = self._read(case_id)
            items = list(case.get("items") or [])
            if len(items) >= MAX_ITEMS_PER_CASE:
                raise ValueError(f"investigator case is limited to {MAX_ITEMS_PER_CASE} pinned items")
            # Preserve multiple analyst annotations, but avoid accidental duplicate pins of the
            # exact same structured target when no different note is supplied.
            signature = json.dumps({"kind": kind, "reference": ref}, sort_keys=True, separators=(",", ":"))
            for existing in items:
                existing_signature = json.dumps({"kind": existing.get("kind"), "reference": existing.get("reference") or {}}, sort_keys=True, separators=(",", ":"))
                if signature == existing_signature and not note and not existing.get("note"):
                    return {"ok": True, "saved": False, "duplicate": True, "item": existing, "case": {**case, "store": self.reference()}}
            now = utc_now()
            row = {
                "schema": ITEM_SCHEMA,
                "itemId": _new_id("item"),
                "kind": kind,
                "label": label,
                "note": note,
                "pinned": bool(pinned),
                "reference": ref,
                "createdAtUtc": now,
                **_authority(),
            }
            items.append(row)
            case["items"] = items
            case["updatedAtUtc"] = now
            case["revision"] = int(case.get("revision") or 0) + 1
            self._write(path, case)
            return {"ok": True, "saved": True, "duplicate": False, "item": row, "case": {**case, "store": self.reference()}}

    def remove_item(self, case_id: str, item_id: str) -> dict[str, Any]:
        item_id = _item_id(item_id)
        with self._lock:
            path, case = self._read(case_id)
            before = list(case.get("items") or [])
            after = [row for row in before if str(row.get("itemId") or "") != item_id]
            if len(after) == len(before):
                raise ValueError(f"unknown investigator case item {item_id}")
            case["items"] = after
            case["updatedAtUtc"] = utc_now()
            case["revision"] = int(case.get("revision") or 0) + 1
            self._write(path, case)
            return {"ok": True, "removed": item_id, "case": {**case, "store": self.reference()}}

    def delete_case(self, case_id: str) -> dict[str, Any]:
        with self._lock:
            path, case = self._read(case_id)
            if path.is_symlink():
                raise ValueError("investigator case path is unsafe")
            path.unlink()
            return {"ok": True, "deleted": case.get("caseId"), **_authority()}
