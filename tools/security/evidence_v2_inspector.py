"""Read-only adapter that exposes local Security Evidence v2 JSON to the developer UI."""
from __future__ import annotations

import gzip
import json
from pathlib import Path, PurePosixPath
from typing import Any


SEVERITY_RANK = {"none": 0, "informational": 1, "low": 1, "caution": 2, "medium": 2, "high": 3, "critical": 4}


class V2SecurityInspector:
    """Serve the existing local developer UI directly from an evidence-v2 tree.

    This deliberately has no SQL console or mutation path. It reads the atomic root
    index and individual records on demand, so an operator can inspect a local,
    un-published snapshot without rebuilding a SQLite database.
    """

    def __init__(self, root: Path):
        self.evidence_path = root.resolve()
        self.marketplace_path: Path | None = None
        self.root = self._read_json("index.json")
        if self.root.get("schema") != "omega.security-evidence.v2" or self.root.get("formatVersion") != 2:
            raise ValueError(f"{self.evidence_path} is not an Omega Security Evidence v2 directory")
        plugins = self._read_json(self._index_path("plugins"))
        self.entries = {int(row["variantId"]): row for row in plugins.get("currentVariants") or []}
        self._payload_cache: dict[int, dict[str, Any]] = {}

    def close(self) -> None:
        self._payload_cache.clear()

    def _path(self, relative: str) -> Path:
        value = PurePosixPath(relative)
        if value.is_absolute() or ".." in value.parts:
            raise ValueError(f"unsafe v2 evidence path: {relative!r}")
        path = self.evidence_path.joinpath(*value.parts).resolve()
        if self.evidence_path not in path.parents and path != self.evidence_path:
            raise ValueError(f"v2 evidence path escaped root: {relative!r}")
        return path

    def _read_json(self, relative: str) -> Any:
        path = self._path(relative)
        if not path.is_file():
            raise FileNotFoundError(path)
        return json.loads(path.read_text(encoding="utf-8"))

    def _index_path(self, name: str) -> str:
        return str(((self.root.get("indexes") or {}).get(name) or {}).get("path") or "")

    def _payload(self, variant_id: int) -> dict[str, Any]:
        if variant_id not in self.entries:
            raise ValueError(f"unknown variant {variant_id}")
        if variant_id not in self._payload_cache:
            payload = self._read_json(str(self.entries[variant_id].get("variantPath") or ""))
            if int(payload.get("variantId") or 0) != variant_id:
                raise ValueError(f"v2 variant identity mismatch for {variant_id}")
            self._payload_cache[variant_id] = payload
        return self._payload_cache[variant_id]

    def _dataset(self, payload: dict[str, Any], name: str) -> list[dict[str, Any]]:
        analysis = payload.get("analysis") or {}
        if not analysis.get("path"):
            return []
        manifest = self._read_json(f"{analysis['path']}/manifest.json")
        dataset = (manifest.get("datasets") or {}).get(name) or {}
        rows: list[dict[str, Any]] = []
        for item in dataset.get("files") or []:
            path = str(item.get("path") or "")
            if str(item.get("encoding") or "") == "json":
                value = self._read_json(path)
                rows.extend(value if isinstance(value, list) else [value])
            elif str(item.get("encoding") or "") == "jsonl+gzip":
                with gzip.open(self._path(path), "rt", encoding="utf-8") as stream:
                    rows.extend(json.loads(line) for line in stream if line.strip())
        return rows

    @staticmethod
    def _risk(current: dict[str, Any]) -> int:
        return min(100, int(current.get("informational_count") or 0) + int(current.get("caution_count") or 0) * 6 + int(current.get("high_count") or 0) * 15 + int(current.get("critical_count") or 0) * 30)

    @staticmethod
    def _identity(payload: dict[str, Any]) -> dict[str, Any]:
        plugin, variant, source, current = (payload.get("plugin") or {}), (payload.get("variant") or {}), (payload.get("source") or {}), (payload.get("current") or {})
        return {
            **plugin, **variant, **current,
            "canonical_name": plugin.get("canonical_name") or variant.get("name") or plugin.get("internal_name") or "",
            "internal_name": plugin.get("internal_name") or "",
            "source_name": source.get("name") or "",
            "source_url": source.get("url") or "",
            "source_provider": source.get("provider") or "",
            "scan_status": current.get("status") or "unscanned",
        }

    def summary(self) -> dict[str, Any]:
        counts = self.root.get("counts") or {}
        payloads = [self._payload(variant_id) for variant_id in self.entries]
        currents = [item.get("current") or {} for item in payloads]
        findings = sum(len(self._dataset(item, "findings")) for item in payloads if (item.get("analysis") or {}).get("path"))
        return {
            "evidencePath": str(self.evidence_path), "marketplacePath": "", "databaseBytes": 0, "meta": self.root.get("revisions") or {},
            "counts": {
                "plugins": len({int((item.get("plugin") or {}).get("plugin_id") or 0) for item in payloads}), "variants": len(self.entries),
                "currentScans": len(currents), "completeScans": sum(str(row.get("status")) == "complete" for row in currents),
                "failedScans": sum(str(row.get("status")) != "complete" for row in currents), "findings": findings,
                "criticalFindings": sum(int(row.get("critical_count") or 0) for row in currents), "highFindings": sum(int(row.get("high_count") or 0) for row in currents),
                "advisories": int(counts.get("advisories") or 0), "ipcProviders": int(counts.get("ipcProviders") or 0), "dependencyIssues": 0,
                "currentAtScanner": len(currents), "legacyCurrent": 0, "observedNugetVersions": int(counts.get("nugetPackageVersionPairs") or 0),
                "osvQueriedPackages": 0, "osvMatchedPackages": 0,
            },
            "scannerVersion": str((self.root.get("source") or {}).get("scannerVersion") or "v2 snapshot"),
            "latestScanUtc": max((str(row.get("scanned_at_utc") or "") for row in currents), default=""),
            "hasMarketplaceComparison": False, "generatedAtUtc": self.root.get("generatedAtUtc") or "", "format": "security-evidence-v2",
        }

    def list_plugins(self, q: str = "", severity: str = "", status: str = "", known_risk: bool = False, limit: int = 300, offset: int = 0) -> list[dict[str, Any]]:
        needle = q.casefold().strip()
        rows: list[dict[str, Any]] = []
        for variant_id in self.entries:
            identity = self._identity(self._payload(variant_id))
            haystack = " ".join(str(identity.get(key) or "") for key in ("internal_name", "canonical_name", "name", "author", "source_name", "source_url")).casefold()
            if needle and needle not in haystack:
                continue
            if severity and str(identity.get("highest_severity") or "none").casefold() != severity.casefold():
                continue
            if status and str(identity.get("scan_status") or "unscanned").casefold() != status.casefold():
                continue
            identity.update({"variant_id": variant_id, "knownAdvisoryCount": 0, "knownAdvisoryHighestSeverity": "none", "riskScore": self._risk(identity)})
            rows.append(identity)
        rows.sort(key=lambda item: (-SEVERITY_RANK.get(str(item.get("highest_severity") or "none").casefold(), 0), str(item.get("canonical_name") or "").casefold()))
        return rows[max(0, offset):max(0, offset) + min(max(1, limit), 1000)]

    def plugin_detail(self, variant_id: int) -> dict[str, Any]:
        payload = self._payload(variant_id)
        derived = payload.get("derived") or {}
        current = payload.get("current") or {}
        return {
            "identity": self._identity(payload), "findings": self._dataset(payload, "findings"), "dependencies": self._dataset(payload, "dependencies"),
            "ipc": self._dataset(payload, "ipc"), "permissions": self._dataset(payload, "permissions"), "automation": self._dataset(payload, "automation"),
            "advisories": [], "advisorySummary": {"count": 0, "highestSeverity": "none", "points": 0}, "riskScore": self._risk(current),
            "audit": [], "sourceScope": ((current.get("report_json") or {}).get("source") or {}).get("scope") or {},
            "sourceArtifactComparison": derived.get("sourceArtifactComparison") or {}, "lineage": derived.get("scanLineage") or {},
            "drift": derived.get("dependencyDrift") or [], "marketplaceSecurity": None,
        }

    def managed_calls(self, variant_id: int, query: str = "", limit: int = 250) -> list[dict[str, Any]]:
        rows = self._dataset(self._payload(variant_id), "calls")
        needle = query.casefold().strip()
        if needle:
            rows = [row for row in rows if needle in json.dumps(row, ensure_ascii=False).casefold()]
        return rows[:min(max(1, limit), 1000)]

    def global_audit(self, max_plugin_issues: int = 500) -> dict[str, Any]:
        items = [{"status": "pass", "code": "v2.root_index", "title": "V2 root index", "detail": "Root index is readable and has the expected schema."}]
        return {"counts": {"fail": 0, "warn": 0, "pass": len(items)}, "items": items, "generatedAtUtc": self.root.get("generatedAtUtc") or ""}

    def table_catalog(self) -> list[dict[str, Any]]:
        return [
            {"name": "plugin_security_current", "label": "Current plugin scans", "category": "Current state", "columnCount": 1},
            {"name": "plugin_security_findings", "label": "Static findings", "category": "Evidence", "columnCount": 1},
            {"name": "plugin_security_dependencies", "label": "Observed dependencies", "category": "Evidence", "columnCount": 1},
            {"name": "plugin_security_permission_candidates", "label": "Permission candidates", "category": "Evidence", "columnCount": 1},
            {"name": "plugin_security_automation_capabilities", "label": "Automation evidence", "category": "Evidence", "columnCount": 1},
            {"name": "plugin_security_ipc_endpoints", "label": "IPC endpoints", "category": "Evidence", "columnCount": 1},
        ]

    def browse_table(self, name: str, filter_column: str = "", filter_value: str = "", limit: int = 100, offset: int = 0) -> dict[str, Any]:
        datasets = {"plugin_security_findings": "findings", "plugin_security_dependencies": "dependencies", "plugin_security_permission_candidates": "permissions", "plugin_security_automation_capabilities": "automation", "plugin_security_ipc_endpoints": "ipc"}
        if name == "plugin_security_current":
            rows = self.list_plugins(limit=1000)
        elif name in datasets:
            rows = [{"variant_id": variant_id, **row} for variant_id in self.entries for row in self._dataset(self._payload(variant_id), datasets[name])]
        else:
            raise ValueError(f"unknown v2 evidence table {name!r}")
        if filter_column:
            rows = [row for row in rows if str(row.get(filter_column) or "") == filter_value]
        columns = sorted({key for row in rows for key in row})
        limit = min(max(1, limit), 1000); offset = max(0, offset); page = rows[offset:offset + limit]
        label = next(item["label"] for item in self.table_catalog() if item["name"] == name)
        return {"name": name, "label": label, "columns": [{"name": key} for key in columns], "rows": page, "foreignKeys": [], "limit": limit, "offset": offset, "hasMore": offset + len(page) < len(rows), "filter": {"column": filter_column, "value": filter_value} if filter_column else None}

    def read_sql(self, query: str) -> dict[str, Any]:
        raise ValueError("SQL is unavailable for Security Evidence v2 JSON. Use the Evidence browser instead.")
