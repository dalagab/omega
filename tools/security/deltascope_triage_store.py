"""Local-only triage state for the DeltaScope Findings inbox.

Triage state is researcher workflow metadata, never security evidence. It may refer to a
current derived incident or one of its findings, but it cannot change SigmaScope findings,
severity, Definitions, queues, SRL/Stigma-1 projection, GitHub, or published Evidence-v2.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import re
import threading
from typing import Any

SCHEMA = "omega.deltascope.findings-triage.v1"
DEFAULT_RELATIVE_ROOT = Path(".omega") / "deltascope" / "triage" / "v1"
STATE_FILENAME = "findings-triage.json"
ALLOWED_STATES = {"new", "triaging", "investigating", "escalated", "resolved", "dismissed"}
TERMINAL_REASON_REQUIRED = {"escalated", "dismissed"}
MAX_CASES = 5000
MAX_FINDINGS = 25000
MAX_BYTES = 8 * 1024 * 1024
MAX_OWNER_CHARS = 160
MAX_REASON_CHARS = 4000


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_root() -> Path:
    override = os.environ.get("OMEGA_DELTASCOPE_TRIAGE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / DEFAULT_RELATIVE_ROOT).resolve()


def _text(value: Any, limit: int, field: str) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if len(text) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    return text


def _state(value: Any) -> str:
    value = str(value or "").strip().casefold()
    if value not in ALLOWED_STATES:
        raise ValueError(f"triage state must be one of {', '.join(sorted(ALLOWED_STATES))}")
    return value


def _incident_id(value: Any) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"incident-[0-9a-f]{20}", text):
        raise ValueError("invalid derived incident id")
    return text


def _positive_int(value: Any, field: str) -> int:
    try:
        number = int(value or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if number <= 0:
        raise ValueError(f"{field} must be positive")
    return number


def _finding_identity(*, incident_id: str, variant_id: int, scan_id: int, finding_id: Any, rule_id: Any) -> str:
    finding = _text(finding_id, 512, "findingId")
    rule = _text(rule_id, 512, "ruleId")
    if not finding and not rule:
        raise ValueError("findingId or ruleId is required")
    return f"{incident_id}|{variant_id}|{scan_id}|{finding}|{rule}"


def _authority() -> dict[str, Any]:
    return {
        "localOnly": True,
        "mutationAuthority": "local-user-files-only",
        "securityAuthority": False,
        "findingAuthority": False,
        "severityAuthority": False,
        "policyInput": False,
        "productionWriteBack": False,
        "evidenceWriteBack": False,
        "definitionsWriteBack": False,
        "queueMutationAuthorized": False,
        "repositoryWriteBack": False,
    }


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise ValueError(f"triage store exceeds {MAX_BYTES} bytes")
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


class LocalFindingsTriageStore:
    """Bounded local triage metadata keyed to derived incident/finding identities."""

    def __init__(self, root: Path | None = None):
        self.root = (root or default_root()).expanduser().absolute()
        self.path = self.root / STATE_FILENAME
        self._lock = threading.RLock()

    def reference(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "root": str(self.root), "version": 1, **_authority()}

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("DeltaScope triage root must be a real directory")
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _empty(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "version": 1, "updatedAtUtc": "", "cases": {}, "findings": {}}

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("DeltaScope triage state path is unsafe")
        if self.path.stat().st_size > MAX_BYTES:
            raise ValueError(f"triage store exceeds {MAX_BYTES} bytes")
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
            raise ValueError("invalid DeltaScope triage state document")
        cases = raw.get("cases") if isinstance(raw.get("cases"), dict) else {}
        findings = raw.get("findings") if isinstance(raw.get("findings"), dict) else {}
        if len(cases) > MAX_CASES or len(findings) > MAX_FINDINGS:
            raise ValueError("DeltaScope triage state exceeds bounded record limits")
        raw["cases"], raw["findings"] = cases, findings
        return raw

    def _write(self, data: dict[str, Any]) -> None:
        self._ensure_root()
        data["updatedAtUtc"] = utc_now()
        _atomic_write(self.path, data)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            data = self._read()
            cases = sorted((dict(row) for row in data["cases"].values() if isinstance(row, dict)), key=lambda r: (str(r.get("updatedAtUtc") or ""), str(r.get("incidentId") or "")), reverse=True)
            findings = sorted((dict(row) for row in data["findings"].values() if isinstance(row, dict)), key=lambda r: (str(r.get("updatedAtUtc") or ""), str(r.get("identity") or "")), reverse=True)
            return {**self.reference(), "updatedAtUtc": str(data.get("updatedAtUtc") or ""), "cases": cases, "findings": findings, "caseCount": len(cases), "findingCount": len(findings)}

    def update_case(self, *, incident_id: Any, variant_id: Any, scan_id: Any, state: Any, owner: Any = "", reason: Any = "") -> dict[str, Any]:
        with self._lock:
            incident = _incident_id(incident_id)
            variant = _positive_int(variant_id, "variantId")
            scan = _positive_int(scan_id, "scanId")
            status = _state(state)
            assigned = _text(owner, MAX_OWNER_CHARS, "owner")
            why = _text(reason, MAX_REASON_CHARS, "reason")
            if status in TERMINAL_REASON_REQUIRED and not why:
                raise ValueError(f"{status} triage state requires a reason")
            data = self._read()
            previous = data["cases"].get(incident) if isinstance(data["cases"].get(incident), dict) else {}
            now = utc_now()
            row = {
                "incidentId": incident, "variantId": variant, "scanId": scan,
                "state": status, "owner": assigned, "reason": why,
                "createdAtUtc": str(previous.get("createdAtUtc") or now), "updatedAtUtc": now,
            }
            data["cases"][incident] = row
            self._write(data)
            return {**self.reference(), "case": row}

    def update_finding(self, *, incident_id: Any, variant_id: Any, scan_id: Any, finding_id: Any, rule_id: Any, state: Any, owner: Any = "", reason: Any = "") -> dict[str, Any]:
        with self._lock:
            incident = _incident_id(incident_id)
            variant = _positive_int(variant_id, "variantId")
            scan = _positive_int(scan_id, "scanId")
            status = _state(state)
            assigned = _text(owner, MAX_OWNER_CHARS, "owner")
            why = _text(reason, MAX_REASON_CHARS, "reason")
            if status in TERMINAL_REASON_REQUIRED and not why:
                raise ValueError(f"{status} triage state requires a reason")
            identity = _finding_identity(incident_id=incident, variant_id=variant, scan_id=scan, finding_id=finding_id, rule_id=rule_id)
            data = self._read()
            previous = data["findings"].get(identity) if isinstance(data["findings"].get(identity), dict) else {}
            now = utc_now()
            row = {
                "identity": identity, "incidentId": incident, "variantId": variant, "scanId": scan,
                "findingId": _text(finding_id, 512, "findingId"), "ruleId": _text(rule_id, 512, "ruleId"),
                "state": status, "owner": assigned, "reason": why,
                "createdAtUtc": str(previous.get("createdAtUtc") or now), "updatedAtUtc": now,
            }
            data["findings"][identity] = row
            self._write(data)
            return {**self.reference(), "finding": row}

    def bulk_update_cases(self, rows: Any, *, state: Any, owner: Any = "", reason: Any = "") -> dict[str, Any]:
        if not isinstance(rows, list) or not rows:
            raise ValueError("cases must be a non-empty list")
        if len(rows) > 500:
            raise ValueError("bulk triage is limited to 500 cases")
        status = _state(state)
        assigned = _text(owner, MAX_OWNER_CHARS, "owner")
        why = _text(reason, MAX_REASON_CHARS, "reason")
        if status in TERMINAL_REASON_REQUIRED and not why:
            raise ValueError(f"{status} triage state requires a reason")
        with self._lock:
            data = self._read()
            now = utc_now()
            updated = []
            for raw in rows:
                if not isinstance(raw, dict):
                    raise ValueError("each bulk case must be an object")
                incident = _incident_id(raw.get("incidentId"))
                variant = _positive_int(raw.get("variantId"), "variantId")
                scan = _positive_int(raw.get("scanId"), "scanId")
                previous = data["cases"].get(incident) if isinstance(data["cases"].get(incident), dict) else {}
                row = {"incidentId": incident, "variantId": variant, "scanId": scan, "state": status, "owner": assigned, "reason": why, "createdAtUtc": str(previous.get("createdAtUtc") or now), "updatedAtUtc": now}
                data["cases"][incident] = row
                updated.append(row)
            self._write(data)
            return {**self.reference(), "updated": len(updated), "cases": updated}
