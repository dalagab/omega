"""Read-only adapters for local and online Omega Security Evidence v2 JSON.

The online adapter deliberately follows the published v2 graph lazily: it fetches the
atomic root index, then the lightweight plugin index, and only downloads variant
records/manifests/evidence shards when the operator opens them in Developer View.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import time
from typing import Any, Callable
import urllib.parse
import urllib.request


SEVERITY_RANK = {"none": 0, "informational": 1, "low": 1, "caution": 2, "medium": 2, "high": 3, "critical": 4}
DEFAULT_ONLINE_BASE_URL = "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/"
DEFAULT_MAX_REMOTE_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_REMOTE_CACHE_BYTES = 128 * 1024 * 1024
USER_AGENT = "Omega-Sigmascope-Developer-View/2.0"


def _safe_relative(relative: str) -> str:
    value = PurePosixPath(str(relative or ""))
    if not relative or value.is_absolute() or ".." in value.parts:
        raise ValueError(f"unsafe v2 evidence path: {relative!r}")
    return value.as_posix()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class LocalEvidenceSource:
    mode = "local"

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.display = str(self.root)
        self.revision = ""

    def set_revision(self, revision: str) -> None:
        self.revision = str(revision or "")

    def _path(self, relative: str) -> Path:
        relative = _safe_relative(relative)
        path = self.root.joinpath(*PurePosixPath(relative).parts).resolve()
        if self.root not in path.parents and path != self.root:
            raise ValueError(f"v2 evidence path escaped root: {relative!r}")
        return path

    def read_bytes(self, relative: str, *, expected_sha256: str = "", refresh: bool = False) -> bytes:
        del refresh
        path = self._path(relative)
        if not path.is_file():
            raise FileNotFoundError(path)
        data = path.read_bytes()
        if expected_sha256 and _sha256_bytes(data) != expected_sha256.lower():
            raise ValueError(f"Security Evidence v2 SHA-256 mismatch for {relative}")
        return data

    def read_json(self, relative: str, *, expected_sha256: str = "", refresh: bool = False) -> Any:
        return json.loads(self.read_bytes(relative, expected_sha256=expected_sha256, refresh=refresh).decode("utf-8"))

    def cache_status(self) -> dict[str, Any]:
        return {"cacheDirectory": "", "cacheBytes": 0, "cacheLimitBytes": 0}


class RemoteEvidenceSource:
    """Bounded, revision-scoped HTTP reader for raw GitHub Evidence v2 files."""

    mode = "online"

    def __init__(
        self,
        base_url: str,
        cache_dir: Path,
        *,
        cache_limit_bytes: int = DEFAULT_REMOTE_CACHE_BYTES,
        max_file_bytes: int = DEFAULT_MAX_REMOTE_FILE_BYTES,
        timeout: float = 30.0,
        urlopen: Callable[..., Any] | None = None,
    ):
        base = str(base_url or DEFAULT_ONLINE_BASE_URL).strip()
        parsed = urllib.parse.urlparse(base)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("online Evidence v2 base URL must be HTTPS")
        if not base.endswith("/"):
            base += "/"
        self.base_url = base
        self.display = base
        self.cache_dir = cache_dir.resolve()
        self.cache_limit_bytes = max(8 * 1024 * 1024, int(cache_limit_bytes))
        self.max_file_bytes = max(1024 * 1024, int(max_file_bytes))
        self.timeout = max(1.0, float(timeout))
        self._urlopen = urlopen or urllib.request.urlopen
        self.revision = "bootstrap"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def set_revision(self, revision: str) -> None:
        value = str(revision or "").strip()
        self.revision = value if value else "unversioned"

    def _url(self, relative: str) -> str:
        relative = _safe_relative(relative)
        quoted = "/".join(urllib.parse.quote(part, safe="._-") for part in PurePosixPath(relative).parts)
        return urllib.parse.urljoin(self.base_url, quoted)

    def _cache_path(self, relative: str, *, root: bool = False) -> Path:
        relative = _safe_relative(relative)
        namespace = "_root" if root else self.revision
        return self.cache_dir / namespace / Path(*PurePosixPath(relative).parts)

    def _download(self, relative: str) -> bytes:
        req = urllib.request.Request(
            self._url(relative),
            headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream", "Cache-Control": "no-cache"},
        )
        with self._urlopen(req, timeout=self.timeout) as response:
            length = response.headers.get("Content-Length") if getattr(response, "headers", None) else None
            if length and int(length) > self.max_file_bytes:
                raise ValueError(f"remote Evidence v2 file exceeds {self.max_file_bytes} bytes: {relative}")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_file_bytes:
                    raise ValueError(f"remote Evidence v2 file exceeds {self.max_file_bytes} bytes: {relative}")
                chunks.append(chunk)
        return b"".join(chunks)

    def read_bytes(self, relative: str, *, expected_sha256: str = "", refresh: bool = False) -> bytes:
        relative = _safe_relative(relative)
        is_root = relative == "index.json"
        cache_path = self._cache_path(relative, root=is_root)
        if cache_path.is_file() and not refresh:
            data = cache_path.read_bytes()
            if not expected_sha256 or _sha256_bytes(data) == expected_sha256.lower():
                try:
                    os.utime(cache_path, None)
                except OSError:
                    pass
                return data
            cache_path.unlink(missing_ok=True)

        try:
            data = self._download(relative)
        except Exception:
            # Root checks are allowed to fall back to the last successfully fetched root
            # so a transient GitHub outage does not make an already-open read-only view unusable.
            if is_root and cache_path.is_file():
                return cache_path.read_bytes()
            raise
        if expected_sha256 and _sha256_bytes(data) != expected_sha256.lower():
            raise ValueError(f"remote Security Evidence v2 SHA-256 mismatch for {relative}")
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temp = cache_path.with_suffix(cache_path.suffix + ".tmp")
        temp.write_bytes(data)
        temp.replace(cache_path)
        self._prune_cache(protected=cache_path)
        return data

    def read_json(self, relative: str, *, expected_sha256: str = "", refresh: bool = False) -> Any:
        return json.loads(self.read_bytes(relative, expected_sha256=expected_sha256, refresh=refresh).decode("utf-8"))

    def _prune_cache(self, protected: Path | None = None) -> None:
        files = [path for path in self.cache_dir.rglob("*") if path.is_file()]
        total = sum(path.stat().st_size for path in files)
        if total <= self.cache_limit_bytes:
            return
        for path in sorted(files, key=lambda item: item.stat().st_mtime):
            if protected is not None and path == protected:
                continue
            size = path.stat().st_size
            path.unlink(missing_ok=True)
            total -= size
            if total <= self.cache_limit_bytes:
                break

    def cache_status(self) -> dict[str, Any]:
        files = [path for path in self.cache_dir.rglob("*") if path.is_file()]
        return {
            "cacheDirectory": str(self.cache_dir),
            "cacheBytes": sum(path.stat().st_size for path in files),
            "cacheLimitBytes": self.cache_limit_bytes,
        }


class V2SigmascopeInspector:
    """Serve Developer View from either a local or published online Evidence v2 tree."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        base_url: str = "",
        cache_dir: Path | None = None,
        cache_limit_bytes: int = DEFAULT_REMOTE_CACHE_BYTES,
        urlopen: Callable[..., Any] | None = None,
    ):
        if root is not None and base_url:
            raise ValueError("choose either a local Evidence v2 root or an online base URL")
        if root is not None:
            self.source: LocalEvidenceSource | RemoteEvidenceSource = LocalEvidenceSource(root)
        else:
            if cache_dir is None:
                raise ValueError("cache_dir is required for online Evidence v2 browsing")
            self.source = RemoteEvidenceSource(
                base_url or DEFAULT_ONLINE_BASE_URL,
                cache_dir,
                cache_limit_bytes=cache_limit_bytes,
                urlopen=urlopen,
            )
        self.remote = self.source.mode == "online"
        self.evidence_path = self.source.display
        self.marketplace_path: Path | None = None
        self._payload_cache: dict[int, dict[str, Any]] = {}
        self._manifest_cache: dict[str, dict[str, Any]] = {}
        self._identity_maps: dict[str, dict[int, dict[str, Any]]] | None = None
        self._load_snapshot(refresh_root=self.remote)

    @classmethod
    def online(
        cls,
        *,
        base_url: str = DEFAULT_ONLINE_BASE_URL,
        cache_dir: Path,
        cache_limit_bytes: int = DEFAULT_REMOTE_CACHE_BYTES,
        urlopen: Callable[..., Any] | None = None,
    ) -> "V2SigmascopeInspector":
        return cls(base_url=base_url, cache_dir=cache_dir, cache_limit_bytes=cache_limit_bytes, urlopen=urlopen)

    def close(self) -> None:
        self._payload_cache.clear()
        self._manifest_cache.clear()

    @staticmethod
    def _revision(root: dict[str, Any]) -> str:
        return str(((root.get("revisions") or {}).get("evidenceRevision") or "")).strip()

    @classmethod
    def _snapshot_token(cls, root: dict[str, Any]) -> str:
        plugins_sha = str((((root.get("indexes") or {}).get("plugins") or {}).get("sha256") or "")).strip().lower()
        return f"{cls._revision(root)}:{plugins_sha}"

    def _load_snapshot(self, *, refresh_root: bool = False, root: dict[str, Any] | None = None) -> None:
        root = root or self.source.read_json("index.json", refresh=refresh_root)
        if root.get("schema") != "omega.security-evidence.v2" or root.get("formatVersion") != 2:
            raise ValueError(f"{self.evidence_path} is not an Omega Security Evidence v2 tree")
        self.root = root
        self.source.set_revision(self._revision(root))
        plugins_meta = (root.get("indexes") or {}).get("plugins") or {}
        plugins = self.source.read_json(str(plugins_meta.get("path") or ""), expected_sha256=str(plugins_meta.get("sha256") or ""))
        self.entries = {int(row["variantId"]): row for row in plugins.get("currentVariants") or []}
        self._payload_cache.clear()
        self._manifest_cache.clear()
        self._identity_maps = None
        self._summary_index_available = bool(self.entries) and all(isinstance(row.get("summary"), dict) for row in self.entries.values())

    def _index_path(self, name: str) -> str:
        return str(((self.root.get("indexes") or {}).get(name) or {}).get("path") or "")

    def _load_identity_maps(self) -> dict[str, dict[int, dict[str, Any]]]:
        if self._identity_maps is not None:
            return self._identity_maps
        meta = (self.root.get("indexes") or {}).get("identities") or {}
        if not meta.get("path"):
            self._identity_maps = {"plugins": {}, "variants": {}, "sources": {}}
            return self._identity_maps
        payload = self.source.read_json(str(meta.get("path") or ""), expected_sha256=str(meta.get("sha256") or ""))
        maps: dict[str, dict[int, dict[str, Any]]] = {}
        for name, key in (("plugins", "plugin_id"), ("plugin_variants", "variant_id"), ("sources", "source_id")):
            maps["variants" if name == "plugin_variants" else name] = {
                int(row.get(key) or 0): row for row in payload.get(name) or [] if int(row.get(key) or 0) > 0
            }
        self._identity_maps = maps
        return maps

    def _entry_identity(self, variant_id: int, *, require_current: bool = False) -> dict[str, Any]:
        entry = self.entries[variant_id]
        summary = entry.get("summary") if isinstance(entry.get("summary"), dict) else None
        if summary is not None:
            row = dict(summary)
            row["variant_id"] = variant_id
            row.setdefault("scan_id", int(entry.get("scanId") or 0))
            row.setdefault("artifact_sha256", str(entry.get("artifactSha256") or ""))
            row.setdefault("scan_status", row.get("status") or "unscanned")
            return row
        if require_current or not self.remote:
            return self._identity(self._payload(variant_id))
        maps = self._load_identity_maps()
        variant = maps["variants"].get(variant_id, {})
        plugin = maps["plugins"].get(int(variant.get("plugin_id") or 0), {})
        source = maps["sources"].get(int(variant.get("source_id") or 0), {})
        return {
            **plugin,
            **variant,
            "variant_id": variant_id,
            "scan_id": int(entry.get("scanId") or 0),
            "artifact_sha256": str(entry.get("artifactSha256") or ""),
            "canonical_name": plugin.get("canonical_name") or variant.get("name") or plugin.get("internal_name") or "",
            "internal_name": plugin.get("internal_name") or "",
            "source_name": source.get("name") or "",
            "source_url": source.get("url") or "",
            "source_provider": source.get("provider") or "",
            "scan_status": "published",
            "highest_severity": "unknown",
            "summary_pending": True,
        }

    def _payload(self, variant_id: int) -> dict[str, Any]:
        if variant_id not in self.entries:
            raise ValueError(f"unknown variant {variant_id}")
        if variant_id not in self._payload_cache:
            entry = self.entries[variant_id]
            payload = self.source.read_json(
                str(entry.get("variantPath") or ""), expected_sha256=str(entry.get("variantSha256") or "")
            )
            if int(payload.get("variantId") or 0) != variant_id:
                raise ValueError(f"v2 variant identity mismatch for {variant_id}")
            self._payload_cache[variant_id] = payload
        return self._payload_cache[variant_id]

    def _manifest(self, payload: dict[str, Any]) -> dict[str, Any]:
        analysis = payload.get("analysis") or {}
        path = str(analysis.get("path") or "")
        if not path:
            return {"datasets": {}}
        if path not in self._manifest_cache:
            self._manifest_cache[path] = self.source.read_json(f"{path}/manifest.json")
        return self._manifest_cache[path]

    def _dataset(self, payload: dict[str, Any], name: str) -> list[dict[str, Any]]:
        dataset = (self._manifest(payload).get("datasets") or {}).get(name) or {}
        rows: list[dict[str, Any]] = []
        for item in dataset.get("files") or []:
            path = str(item.get("path") or "")
            expected = str(item.get("sha256") or "")
            encoding = str(item.get("encoding") or "")
            data = self.source.read_bytes(path, expected_sha256=expected)
            if encoding == "json":
                value = json.loads(data.decode("utf-8"))
                rows.extend(value if isinstance(value, list) else [value])
            elif encoding == "jsonl+gzip":
                text = gzip.decompress(data).decode("utf-8")
                rows.extend(json.loads(line) for line in text.splitlines() if line.strip())
        return rows

    def _dataset_counts(self, payload: dict[str, Any]) -> dict[str, int]:
        manifest = self._manifest(payload)
        return {
            name: int(descriptor.get("records") or 0)
            for name, descriptor in (manifest.get("datasets") or {}).items()
            if isinstance(descriptor, dict)
        }

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
        summaries = [self._entry_identity(variant_id) for variant_id in self.entries]
        complete = sum(str(row.get("scan_status") or "") == "complete" for row in summaries)
        failed = sum(str(row.get("scan_status") or "") == "failed" for row in summaries)
        known_summaries = [row for row in summaries if not row.get("summary_pending")]
        findings = sum(
            int(row.get("informational_count") or 0) + int(row.get("caution_count") or 0) +
            int(row.get("high_count") or 0) + int(row.get("critical_count") or 0)
            for row in known_summaries
        )
        plugin_ids = {int(row.get("plugin_id") or 0) for row in summaries if int(row.get("plugin_id") or 0) > 0}
        return {
            "evidencePath": str(self.evidence_path), "marketplacePath": "", "databaseBytes": 0, "meta": self.root.get("revisions") or {},
            "counts": {
                "plugins": len(plugin_ids), "variants": len(self.entries), "currentScans": len(self.entries),
                "completeScans": complete, "failedScans": failed, "findings": findings,
                "criticalFindings": sum(int(row.get("critical_count") or 0) for row in known_summaries),
                "highFindings": sum(int(row.get("high_count") or 0) for row in known_summaries),
                "advisories": int(counts.get("advisories") or 0), "ipcProviders": int(counts.get("ipcProviders") or 0), "dependencyIssues": 0,
                "currentAtSigmascope": len(self.entries), "currentAtScanner": len(self.entries), "legacyCurrent": 0,
                "observedNugetVersions": int(counts.get("nugetPackageVersionPairs") or 0), "osvQueriedPackages": 0, "osvMatchedPackages": 0,
            },
            "sigmascopeVersion": str(((self.root.get("engine") or {}).get("version") or (self.root.get("source") or {}).get("engineVersion") or (self.root.get("source") or {}).get("scannerVersion") or "v2 snapshot")),
            "scannerVersion": str((self.root.get("source") or {}).get("scannerVersion") or "v2 snapshot"),
            "latestScanUtc": max((str(row.get("scanned_at_utc") or "") for row in known_summaries), default=""),
            "hasMarketplaceComparison": False, "generatedAtUtc": self.root.get("generatedAtUtc") or "", "format": "security-evidence-v2",
            "indexSummaryAvailable": self._summary_index_available,
        }

    def source_status(self, *, check_remote: bool = False) -> dict[str, Any]:
        current_revision = self._revision(self.root)
        current_token = self._snapshot_token(self.root)
        remote_revision = current_revision
        remote_token = current_token
        generated = str(self.root.get("generatedAtUtc") or "")
        error = ""
        if self.remote and check_remote:
            try:
                remote_root = self.source.read_json("index.json", refresh=True)
                remote_revision = self._revision(remote_root)
                remote_token = self._snapshot_token(remote_root)
                generated = str(remote_root.get("generatedAtUtc") or generated)
            except Exception as exc:
                error = str(exc)
        return {
            "mode": self.source.mode,
            "baseUrl": self.source.display if self.remote else "",
            "currentRevision": current_revision,
            "remoteRevision": remote_revision,
            "currentSnapshotToken": current_token,
            "remoteSnapshotToken": remote_token,
            "generatedAtUtc": generated,
            "updateAvailable": bool(self.remote and remote_token != current_token),
            "error": error,
            **self.source.cache_status(),
        }

    def refresh_online(self) -> dict[str, Any]:
        if not self.remote:
            return self.source_status()
        remote_root = self.source.read_json("index.json", refresh=True)
        if self._snapshot_token(remote_root) != self._snapshot_token(self.root):
            self._load_snapshot(root=remote_root)
        return self.source_status()

    def list_plugins(self, q: str = "", severity: str = "", status: str = "", known_risk: bool = False, limit: int = 300, offset: int = 0) -> list[dict[str, Any]]:
        needle = q.casefold().strip()
        rows: list[dict[str, Any]] = []
        for variant_id in self.entries:
            identity = self._entry_identity(variant_id, require_current=bool(severity or status or known_risk))
            haystack = " ".join(str(identity.get(key) or "") for key in ("internal_name", "canonical_name", "name", "author", "source_name", "source_url")).casefold()
            if needle and needle not in haystack:
                continue
            if severity and str(identity.get("highest_severity") or "none").casefold() != severity.casefold():
                continue
            if status and str(identity.get("scan_status") or "unscanned").casefold() != status.casefold():
                continue
            identity.update({"variant_id": variant_id, "knownAdvisoryCount": 0, "knownAdvisoryHighestSeverity": "none", "riskScore": self._risk(identity)})
            rows.append(identity)
        rows.sort(key=lambda item: (-SEVERITY_RANK.get(str(item.get("highest_severity") or "none").casefold(), -1), str(item.get("canonical_name") or "").casefold()))
        return rows[max(0, offset):max(0, offset) + min(max(1, limit), 1000)]

    def plugin_detail(self, variant_id: int) -> dict[str, Any]:
        payload = self._payload(variant_id)
        derived = payload.get("derived") or {}
        current = payload.get("current") or {}
        base = {
            "identity": self._identity(payload), "advisories": [], "advisorySummary": {"count": 0, "highestSeverity": "none", "points": 0},
            "riskScore": self._risk(current), "audit": [], "sourceScope": ((current.get("report_json") or {}).get("source") or {}).get("scope") or {},
            "sourceArtifactComparison": derived.get("sourceArtifactComparison") or {}, "lineage": derived.get("scanLineage") or {},
            "drift": derived.get("dependencyDrift") or [], "marketplaceSecurity": None,
        }
        if self.remote:
            return {
                **base, "lazyDatasets": True, "datasetCounts": self._dataset_counts(payload),
                "findings": [], "dependencies": [], "ipc": [], "permissions": [], "automation": [],
            }
        return {
            **base, "lazyDatasets": False,
            "findings": self._dataset(payload, "findings"), "dependencies": self._dataset(payload, "dependencies"),
            "ipc": self._dataset(payload, "ipc"), "permissions": self._dataset(payload, "permissions"), "automation": self._dataset(payload, "automation"),
        }

    def plugin_dataset(self, variant_id: int, name: str) -> list[dict[str, Any]]:
        allowed = {"findings", "dependencies", "ipc", "permissions", "automation", "calls"}
        if name not in allowed:
            raise ValueError(f"unknown Evidence v2 plugin dataset {name!r}")
        return self._dataset(self._payload(variant_id), name)

    def managed_calls(self, variant_id: int, query: str = "", limit: int = 250) -> list[dict[str, Any]]:
        rows = self.plugin_dataset(variant_id, "calls")
        needle = query.casefold().strip()
        if needle:
            rows = [row for row in rows if needle in json.dumps(row, ensure_ascii=False).casefold()]
        return rows[:min(max(1, limit), 1000)]

    def global_audit(self, max_plugin_issues: int = 500) -> dict[str, Any]:
        del max_plugin_issues
        items = [{"status": "pass", "code": "v2.root_index", "title": "V2 root index", "detail": "Root index is readable and has the expected schema."}]
        if self.remote:
            items.append({"status": "pass", "code": "v2.online.read_only", "title": "Online evidence source", "detail": "Published Evidence v2 is being fetched read-only and lazily over HTTPS."})
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
            if self.remote and filter_column != "variant_id":
                rows = []
            elif filter_column == "variant_id":
                variant_id = int(filter_value)
                rows = [{"variant_id": variant_id, **row} for row in self.plugin_dataset(variant_id, datasets[name])]
            else:
                rows = [{"variant_id": variant_id, **row} for variant_id in self.entries for row in self.plugin_dataset(variant_id, datasets[name])]
        else:
            raise ValueError(f"unknown v2 evidence table {name!r}")
        if filter_column and filter_column != "variant_id":
            rows = [row for row in rows if str(row.get(filter_column) or "") == filter_value]
        columns = sorted({key for row in rows for key in row})
        limit = min(max(1, limit), 1000); offset = max(0, offset); page = rows[offset:offset + limit]
        label = next(item["label"] for item in self.table_catalog() if item["name"] == name)
        return {"name": name, "label": label, "columns": [{"name": key} for key in columns], "rows": page, "foreignKeys": [], "limit": limit, "offset": offset, "hasMore": offset + len(page) < len(rows), "filter": {"column": filter_column, "value": filter_value} if filter_column else None, "remoteLazy": bool(self.remote and name in datasets and filter_column != "variant_id")}

    def read_sql(self, query: str) -> dict[str, Any]:
        raise ValueError("SQL is unavailable for Security Evidence v2 JSON. Use the Evidence browser instead.")


# Compatibility alias for operator scripts written before the Sigmascope naming cutover.
V2SecurityInspector = V2SigmascopeInspector
