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
import urllib.error
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
        # Keep the on-disk cache deliberately flat/hashed. Windows Store Python users can
        # have a ~150-character cache prefix before Evidence-v2 paths are appended; mirroring
        # immutable artifact/analysis paths verbatim can exceed Win32 MAX_PATH.
        self.cache_root = self.cache_dir / "h"
        self.cache_limit_bytes = max(8 * 1024 * 1024, int(cache_limit_bytes))
        self.max_file_bytes = max(1024 * 1024, int(max_file_bytes))
        self.timeout = max(1.0, float(timeout))
        self._urlopen = urlopen or urllib.request.urlopen
        self.revision = "bootstrap"
        self.cache_root.mkdir(parents=True, exist_ok=True)

    def set_revision(self, revision: str) -> None:
        value = str(revision or "").strip()
        self.revision = value if value else "unversioned"

    def _url(self, relative: str) -> str:
        relative = _safe_relative(relative)
        quoted = "/".join(urllib.parse.quote(part, safe="._-") for part in PurePosixPath(relative).parts)
        return urllib.parse.urljoin(self.base_url, quoted)

    def _cache_path(self, relative: str, *, root: bool = False) -> Path:
        relative = _safe_relative(relative)
        namespace_source = "root" if root else str(self.revision or "unversioned")
        namespace = hashlib.sha256(namespace_source.encode("utf-8")).hexdigest()[:12]
        path_key = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:48]
        # At most: <configured cache>/h/<12>/<48>.bin. The remote relative path never
        # becomes a local filename, avoiding WinError 206 on deeply nested analyses.
        return self.cache_root / namespace / f"{path_key}.bin"

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
        files = [path for path in self.cache_root.rglob("*") if path.is_file()]
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
        files = [path for path in self.cache_root.rglob("*") if path.is_file()]
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
        self.plugins_index = plugins if isinstance(plugins, dict) else {}
        self.current_entries = {int(row["variantId"]): row for row in self.plugins_index.get("currentVariants") or [] if isinstance(row, dict)}
        self.terminal_entries = [row for row in self.plugins_index.get("terminalVariants") or [] if isinstance(row, dict)]
        self.historical_entries = [row for row in self.plugins_index.get("historicalSnapshots") or [] if isinstance(row, dict)]
        # Compatibility alias retained for callers that treat entries as the active/current set.
        self.entries = self.current_entries
        self._payload_cache.clear()
        self._manifest_cache.clear()
        self._identity_maps = None
        self._index_payload_cache: dict[str, Any] = {}
        self._queue_payload_cache: dict[str, Any] = {}
        self._summary_index_available = bool(self.entries) and all(isinstance(row.get("summary"), dict) for row in self.entries.values())

    def _index_path(self, name: str) -> str:
        return str(((self.root.get("indexes") or {}).get(name) or {}).get("path") or "")

    def _index_payload(self, name: str) -> Any:
        if name in self._index_payload_cache:
            return self._index_payload_cache[name]
        meta = (self.root.get("indexes") or {}).get(name) or {}
        path = str(meta.get("path") or "")
        if not path:
            value: Any = {}
        else:
            value = self.source.read_json(path, expected_sha256=str(meta.get("sha256") or ""))
        self._index_payload_cache[name] = value
        return value

    def _queue_payload(self) -> dict[str, Any]:
        if self._queue_payload_cache:
            return self._queue_payload_cache
        descriptor = self.root.get("scannerQueue") if isinstance(self.root.get("scannerQueue"), dict) else {}
        path = str(descriptor.get("path") or "")
        if not path:
            self._queue_payload_cache = {"schema": "", "items": {}, "recentCompleted": []}
            return self._queue_payload_cache
        value = self.source.read_json(path, expected_sha256=str(descriptor.get("sha256") or ""))
        self._queue_payload_cache = value if isinstance(value, dict) else {"schema": "", "items": {}, "recentCompleted": []}
        return self._queue_payload_cache

    def _payload_for_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        path = str(entry.get("variantPath") or "")
        if not path:
            raise ValueError("snapshot entry has no variantPath")
        expected = str(entry.get("variantSha256") or "")
        payload = self.source.read_json(path, expected_sha256=expected)
        if int(payload.get("variantId") or 0) != int(entry.get("variantId") or 0):
            raise ValueError(f"v2 variant identity mismatch for snapshot {path}")
        return payload

    def _snapshot_entries_for_variant(self, variant_id: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        current = self.current_entries.get(variant_id)
        if current:
            rows.append({"snapshotKind": "current", **current})
        for kind, entries in (("retired", self.terminal_entries), ("superseded", self.historical_entries)):
            for entry in entries:
                if int(entry.get("variantId") or 0) == variant_id:
                    rows.append({"snapshotKind": kind, **entry})
        return rows

    @staticmethod
    def _report(current: dict[str, Any]) -> dict[str, Any]:
        raw = current.get("report_json")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        return raw if isinstance(raw, dict) else {}

    def _dataset_catalog(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        manifest = self._manifest(payload)
        result: list[dict[str, Any]] = []
        labels = {
            "findings": "Static findings", "dependencies": "Dependencies", "permissions": "Permission candidates",
            "automation": "Automation evidence", "ipc": "IPC endpoints", "assemblies": "Managed assemblies",
            "imports": "Managed/native imports", "reachability": "Reachability", "symbols": "Managed symbols",
            "calls": "Managed calls",
        }
        order = {name: idx for idx, name in enumerate(("findings","dependencies","permissions","automation","ipc","assemblies","imports","reachability","symbols","calls"))}
        for name, descriptor in (manifest.get("datasets") or {}).items():
            if not isinstance(descriptor, dict):
                continue
            result.append({
                "name": str(name),
                "label": labels.get(str(name), str(name).replace("_", " ").title()),
                "records": int(descriptor.get("records") or 0),
                "recordDigest": str(descriptor.get("recordDigest") or ""),
                "files": len(descriptor.get("files") or []),
            })
        result.sort(key=lambda item: (order.get(item["name"], 100), item["label"].casefold()))
        return result

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
        review_variants = sum(str(row.get("highest_severity") or "none").casefold() in {"high", "critical"} for row in known_summaries)
        findings = sum(
            int(row.get("informational_count") or 0) + int(row.get("caution_count") or 0) +
            int(row.get("high_count") or 0) + int(row.get("critical_count") or 0)
            for row in known_summaries
        )
        plugin_ids = {int(row.get("plugin_id") or 0) for row in summaries if int(row.get("plugin_id") or 0) > 0}
        queue_descriptor = self.root.get("scannerQueue") if isinstance(self.root.get("scannerQueue"), dict) else {}
        queue_summary = queue_descriptor.get("summary") if isinstance(queue_descriptor.get("summary"), dict) else {}
        queue_states = queue_summary.get("states") if isinstance(queue_summary.get("states"), dict) else {}
        source_scan = ((self.root.get("source") or {}).get("scan") or {}) if isinstance((self.root.get("source") or {}).get("scan"), dict) else {}
        queue_batch = source_scan.get("queueBatch") if isinstance(source_scan.get("queueBatch"), dict) else {}
        return {
            "evidencePath": str(self.evidence_path), "marketplacePath": "", "databaseBytes": 0, "meta": self.root.get("revisions") or {},
            "counts": {
                "plugins": len(plugin_ids), "variants": len(self.entries), "currentScans": len(self.entries),
                "completeScans": complete, "failedScans": failed, "findings": findings,
                "criticalFindings": sum(int(row.get("critical_count") or 0) for row in known_summaries),
                "highFindings": sum(int(row.get("high_count") or 0) for row in known_summaries),
                "advisories": int(counts.get("advisories") or 0), "ipcProviders": int(counts.get("ipcProviders") or 0), "dependencyIssues": 0,
                "currentAtSigmascope": len(self.entries), "currentAtScanner": len(self.entries), "legacyCurrent": 0,
                "observedNugetVersions": int(counts.get("nugetPackageVersionPairs") or 0), "osvQueriedPackages": int((((self.root.get("source") or {}).get("osv") or {}).get("queriedPackageVersionPairs") or 0)), "osvMatchedPackages": int((((self.root.get("source") or {}).get("osv") or {}).get("matchedPackageVersionPairs") or 0)),
                "terminalVariants": int(counts.get("terminalVariants") or len(self.terminal_entries)),
                "historicalSnapshots": int(counts.get("historicalSnapshots") or len(self.historical_entries)),
                "analyses": int(counts.get("analyses") or 0),
                "artifactGroups": int(counts.get("artifactGroups") or 0),
                "dependencyComponents": int(counts.get("dependencyComponents") or 0),
                "queueTotal": int(queue_summary.get("total") or 0),
                "queuePending": int(queue_states.get("pending") or 0),
                "queueRetry": int(queue_states.get("retry") or 0),
                "queueComplete": int(queue_states.get("complete") or 0),
                "unscannedVariantsPending": int(queue_summary.get("unscannedVariantsPending") or (queue_summary.get("pendingByReason") or {}).get("new_variant") or 0),
                "coveredWorkPending": int(queue_summary.get("coveredWorkPending") or 0),
                "reviewVariants": int(review_variants),
            },
            "sigmascopeVersion": str(((self.root.get("engine") or {}).get("version") or (self.root.get("source") or {}).get("engineVersion") or (self.root.get("source") or {}).get("scannerVersion") or "v2 snapshot")),
            "scannerVersion": str((self.root.get("source") or {}).get("scannerVersion") or "v2 snapshot"),
            "latestScanUtc": max((str(row.get("scanned_at_utc") or "") for row in known_summaries), default=""),
            "hasMarketplaceComparison": False, "generatedAtUtc": self.root.get("generatedAtUtc") or "", "format": "security-evidence-v2",
            "indexSummaryAvailable": self._summary_index_available,
            "revisions": dict(self.root.get("revisions") or {}),
            "queueSummary": queue_summary,
            "lastBatch": queue_batch,
            "publication": dict(self.root.get("publication") or {}),
            "osv": dict((self.root.get("source") or {}).get("osv") or {}),
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

    @staticmethod
    def _is_snapshot_race_error(exc: Exception) -> bool:
        """Return true for errors that can be caused by the moving publication branch.

        DeltaScope reads the root/index graph lazily from a branch that is atomically
        replaced every publication. A variant or manifest request can therefore race a
        later branch commit after the browser loaded an older root. Those failures are
        transport-coherency problems, not corrupt evidence, and are safe to retry after
        refreshing the root snapshot.
        """
        if isinstance(exc, urllib.error.HTTPError) and int(getattr(exc, "code", 0) or 0) in {404, 410}:
            return True
        text = str(exc).casefold()
        return any(token in text for token in (
            "sha-256 mismatch",
            "unknown variant",
            "unknown evidence v2 snapshot path",
            "unknown immutable analysis manifest path",
        ))

    def _refresh_after_snapshot_race(self, exc: Exception) -> bool:
        if not self.remote or not self._is_snapshot_race_error(exc):
            return False
        before = self._snapshot_token(self.root)
        remote_root = self.source.read_json("index.json", refresh=True)
        after = self._snapshot_token(remote_root)
        if after != before:
            self._load_snapshot(root=remote_root)
        return True

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
            source_available = bool(int(identity.get("source_available") or 0)) if str(identity.get("source_available") or "").strip() else bool(identity.get("source_repository"))
            identity.update({
                "variant_id": variant_id, "knownAdvisoryCount": 0, "knownAdvisoryHighestSeverity": "none", "riskScore": self._risk(identity),
                "source_code_available": source_available,
                "source_code_status": "source+artifact" if source_available else "artifact-only",
                "source_code_repository": str(identity.get("source_repository") or ""),
                "source_coverage_label": str(identity.get("source_coverage_label") or ""),
            })
            rows.append(identity)
        rows.sort(key=lambda item: (-SEVERITY_RANK.get(str(item.get("highest_severity") or "none").casefold(), -1), str(item.get("canonical_name") or "").casefold()))
        return rows[max(0, offset):max(0, offset) + min(max(1, limit), 1000)]

    def _detail_from_payload(self, payload: dict[str, Any], *, snapshot_kind: str = "current") -> dict[str, Any]:
        derived = payload.get("derived") or {}
        current = payload.get("current") or {}
        report = self._report(current)
        intelligence = report.get("intelligence") if isinstance(report.get("intelligence"), dict) else {}
        secondary = report.get("secondarySecurity") if isinstance(report.get("secondarySecurity"), dict) else {}
        source_report = report.get("source") if isinstance(report.get("source"), dict) else {}
        analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
        lifecycle = payload.get("lifecycle") if isinstance(payload.get("lifecycle"), dict) else {}
        variant_id = int(payload.get("variantId") or current.get("variant_id") or 0)
        identity = self._identity(payload)
        identity.setdefault("variant_id", variant_id)
        finding_rows = current.get("findings_json") if isinstance(current.get("findings_json"), list) else []
        capability_rows = current.get("capabilities_json") if isinstance(current.get("capabilities_json"), list) else []
        automation_rows = current.get("automation_capabilities_json") if isinstance(current.get("automation_capabilities_json"), list) else []
        finding_counts = {
            "critical": int(current.get("critical_count") or 0),
            "high": int(current.get("high_count") or 0),
            "caution": int(current.get("caution_count") or 0),
            "informational": int(current.get("informational_count") or 0),
        }
        secondary_engines = secondary.get("engines") if isinstance(secondary.get("engines"), list) else []
        secondary_match_count = sum(len(row.get("matches") or []) for row in secondary_engines if isinstance(row, dict))
        attribution = source_report.get("attribution") if isinstance(source_report.get("attribution"), dict) else {}
        provenance = source_report.get("provenance") if isinstance(source_report.get("provenance"), dict) else {}
        signals: list[dict[str, Any]] = []
        if str(current.get("status") or "complete").casefold() != "complete":
            signals.append({"kind": "scan-state", "level": "critical", "label": f"Current scan status is {current.get('status') or 'unknown'}"})
        unavailable_engines = [str(row.get("engine") or "secondary engine") for row in secondary_engines if isinstance(row, dict) and (row.get("available") is False or str(row.get("status") or "").casefold() not in {"complete", "ready"})]
        if unavailable_engines:
            signals.append({"kind": "coverage", "level": "caution", "label": "Secondary engine incomplete/unavailable: " + ", ".join(unavailable_engines)})
        if secondary_match_count:
            signals.append({"kind": "malware-engine", "level": "critical", "label": f"{secondary_match_count} ClamAV/YARA match(es) require review"})
        if finding_counts["critical"]:
            signals.append({"kind": "static", "level": "critical", "label": f"{finding_counts['critical']} critical static finding(s)"})
        if finding_counts["high"]:
            signals.append({"kind": "static", "level": "high", "label": f"{finding_counts['high']} high static finding(s)"})
        rule_ids = {str(row.get("ruleId") or row.get("rule_id") or "") for row in finding_rows if isinstance(row, dict)}
        if "compound.network-execute" in rule_ids:
            signals.append({"kind": "compound", "level": "high", "label": "Network + process execution compound capability"})
        raw_confidence = attribution.get("confidence") if attribution.get("confidence") is not None else current.get("source_attribution_confidence")
        try:
            confidence = int(raw_confidence or 0)
        except (TypeError, ValueError):
            confidence = 0
        if confidence and confidence < 70:
            signals.append({"kind": "provenance", "level": "caution", "label": f"Source attribution confidence is {confidence}/100"})
        if provenance and not bool(provenance.get("sourceToBinaryVerified")):
            signals.append({"kind": "provenance", "level": "informational", "label": "Source-to-binary correspondence is not verified"})
        endpoint_summary = intelligence.get("endpointSummary") if isinstance(intelligence.get("endpointSummary"), dict) else {}
        if bool(endpoint_summary.get("destinationsUndetermined")):
            signals.append({"kind": "network", "level": "caution", "label": "Network capability observed but concrete destinations are undetermined"})
        intelligence_limits = intelligence.get("limits") if isinstance(intelligence.get("limits"), dict) else {}
        if bool(intelligence_limits.get("truncated")):
            signals.append({"kind": "coverage", "level": "caution", "label": "Intelligence collection hit a configured truncation limit"})
        source_available = bool(source_report.get("available")) and bool(str(source_report.get("repository") or "").strip())
        source_coverage = {
            "artifactAvailable": bool(str(current.get("artifact_sha256") or "").strip()),
            "sourceCodeAvailable": source_available,
            "mode": "artifact+source" if source_available else "artifact-only",
            "repository": str(source_report.get("repository") or ""),
            "commit": str(source_report.get("commit") or ""),
            "selectedRef": str(provenance.get("selectedRef") or ""),
            "coverageLabel": str(attribution.get("coverageLabel") or current.get("source_coverage_label") or ""),
            "attributionConfidence": confidence,
            "sourceToBinaryVerified": bool(provenance.get("sourceToBinaryVerified")),
            "reproducibleSourceToArtifact": bool(provenance.get("reproducibleSourceToArtifact")),
        }
        priority = "routine"
        if any(row.get("level") == "critical" for row in signals):
            priority = "urgent"
        elif any(row.get("level") == "high" for row in signals):
            priority = "review"
        elif signals:
            priority = "watch"
        dataset_error = ""
        try:
            dataset_catalog = self._dataset_catalog(payload)
            dataset_counts = self._dataset_counts(payload)
        except Exception as exc:
            # The compact scan report is still useful to a researcher even if a large
            # immutable manifest shard is temporarily unavailable. Dataset loading can
            # be retried independently after the online snapshot refreshes.
            dataset_catalog = []
            dataset_counts = {}
            dataset_error = str(exc)
        base = {
            "identity": identity, "advisories": list(derived.get("advisoryMatches") or []),
            "advisorySummary": {"count": len(derived.get("advisoryMatches") or []), "highestSeverity": "none", "points": 0},
            "riskScore": self._risk(current), "audit": [],
            "sourceScope": ((report.get("source") or {}).get("scope") or {}) if isinstance(report.get("source"), dict) else {},
            "sourceArtifactComparison": derived.get("sourceArtifactComparison") or {}, "lineage": derived.get("scanLineage") or {},
            "drift": derived.get("dependencyDrift") or [], "marketplaceSecurity": None,
            "snapshotKind": snapshot_kind, "lifecycle": lifecycle or {"state": "active" if snapshot_kind == "current" else snapshot_kind},
            "analysis": analysis,
            "scanProvenance": report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {},
            "contracts": {
                key: report.get(key) for key in (
                    "artifactIdentityContractVersion", "manifestObservationContractVersion",
                    "sourceAttributionContractVersion", "secondarySecurityContractVersion"
                )
            },
            "artifactIdentity": report.get("artifactIdentity") if isinstance(report.get("artifactIdentity"), dict) else {},
            "manifestObservation": report.get("manifestObservation") if isinstance(report.get("manifestObservation"), dict) else {},
            "sourceAttribution": attribution,
            "sourceProvenance": provenance,
            "sourceCoverage": source_coverage,
            "sourceEvidence": source_report,
            "secondarySecurity": secondary,
            "package": report.get("package") if isinstance(report.get("package"), dict) else {},
            "endpointSummary": intelligence.get("endpointSummary") if isinstance(intelligence.get("endpointSummary"), dict) else {},
            "networkEndpoints": intelligence.get("networkEndpoints") if isinstance(intelligence.get("networkEndpoints"), list) else [],
            "componentSummary": intelligence.get("componentSummary") if isinstance(intelligence.get("componentSummary"), dict) else {},
            "intelligenceCoverage": intelligence.get("coverage") if isinstance(intelligence.get("coverage"), dict) else {},
            "intelligenceLimits": intelligence.get("limits") if isinstance(intelligence.get("limits"), dict) else {},
            "datasetCatalog": dataset_catalog,
            "datasetError": dataset_error,
            "researcher": {
                "priority": priority,
                "signals": signals,
                "findingCounts": finding_counts,
                "findings": finding_rows,
                "capabilities": capability_rows,
                "automationCapabilities": automation_rows,
                "automationLevel": str(current.get("automation_level") or ((report.get("automation") or {}).get("level") if isinstance(report.get("automation"), dict) else "") or "none"),
                "secondaryMatchCount": secondary_match_count,
                "artifactAnalysisReused": bool(report.get("artifactAnalysisReused")),
                "artifactAnalysisRepresentativeScanId": int(report.get("artifactAnalysisRepresentativeScanId") or 0),
                "sourceAnalysisReused": bool(report.get("sourceAnalysisReused")),
            },
            "lifecycleHistory": self._snapshot_entries_for_variant(variant_id) if variant_id else [],
        }
        severities = [str(row.get("severity") or "none") for row in base["advisories"] if isinstance(row, dict)]
        if severities:
            highest = max(severities, key=lambda value: SEVERITY_RANK.get(value.casefold(), 0))
            base["advisorySummary"] = {"count": len(severities), "highestSeverity": highest, "points": 0}
        if self.remote:
            return {
                **base, "lazyDatasets": True, "datasetCounts": dataset_counts,
                "findings": [], "dependencies": [], "ipc": [], "permissions": [], "automation": [],
            }
        return {
            **base, "lazyDatasets": False,
            "findings": self._dataset(payload, "findings"), "dependencies": self._dataset(payload, "dependencies"),
            "ipc": self._dataset(payload, "ipc"), "permissions": self._dataset(payload, "permissions"), "automation": self._dataset(payload, "automation"),
        }

    def plugin_detail(self, variant_id: int) -> dict[str, Any]:
        try:
            return self._detail_from_payload(self._payload(variant_id), snapshot_kind="current")
        except Exception as exc:
            if not self._refresh_after_snapshot_race(exc):
                raise
            if variant_id in self.current_entries:
                return {**self._detail_from_payload(self._payload(variant_id), snapshot_kind="current"), "onlineSnapshotRefreshed": True}
            retained = self._snapshot_entries_for_variant(variant_id)
            if retained:
                entry = retained[0]
                return {**self._detail_from_payload(self._payload_for_entry(entry), snapshot_kind=str(entry.get("snapshotKind") or "snapshot")), "onlineSnapshotRefreshed": True, "variantNoLongerCurrent": True}
            raise ValueError(f"variant {variant_id} is no longer present in the refreshed Evidence v2 snapshot") from exc

    def snapshot_detail(self, variant_path: str) -> dict[str, Any]:
        path = _safe_relative(variant_path)

        def resolve() -> tuple[dict[str, Any], str]:
            for candidate_kind, candidates in (("current", list(self.current_entries.values())), ("retired", self.terminal_entries), ("superseded", self.historical_entries)):
                for candidate in candidates:
                    if str(candidate.get("variantPath") or "") == path:
                        return candidate, candidate_kind
            raise ValueError(f"unknown Evidence v2 snapshot path {variant_path!r}")

        try:
            entry, kind = resolve()
            return self._detail_from_payload(self._payload_for_entry(entry), snapshot_kind=kind)
        except Exception as exc:
            if not self._refresh_after_snapshot_race(exc):
                raise
            entry, kind = resolve()
            return {**self._detail_from_payload(self._payload_for_entry(entry), snapshot_kind=kind), "onlineSnapshotRefreshed": True}

    def variant_snapshots(self, variant_id: int) -> list[dict[str, Any]]:
        return self._snapshot_entries_for_variant(variant_id)

    def plugin_dataset(self, variant_id: int, name: str) -> list[dict[str, Any]]:
        def load() -> list[dict[str, Any]]:
            payload = self._payload(variant_id)
            datasets = self._manifest(payload).get("datasets") or {}
            if name not in datasets:
                raise ValueError(f"unknown Evidence v2 plugin dataset {name!r}")
            return self._dataset(payload, name)
        try:
            return load()
        except Exception as exc:
            if not self._refresh_after_snapshot_race(exc):
                raise
            return load()

    def managed_calls(self, variant_id: int, query: str = "", limit: int = 250) -> list[dict[str, Any]]:
        rows = self.plugin_dataset(variant_id, "calls")
        needle = query.casefold().strip()
        if needle:
            rows = [row for row in rows if needle in json.dumps(row, ensure_ascii=False).casefold()]
        return rows[:min(max(1, limit), 1000)]

    def analysis_manifest(self, path: str) -> dict[str, Any]:
        requested = _safe_relative(path)
        def load() -> dict[str, Any]:
            for row in self._special_table_rows("v2_analyses"):
                if str(row.get("manifestPath") or "") != requested:
                    continue
                payload = self.source.read_json(requested, expected_sha256=str(row.get("manifestSha256") or ""))
                if not isinstance(payload, dict):
                    raise ValueError("immutable analysis manifest is not a JSON object")
                return payload
            raise ValueError("unknown immutable analysis manifest path")
        try:
            return load()
        except Exception as exc:
            if not self._refresh_after_snapshot_race(exc):
                raise
            return load()

    def global_audit(self, max_plugin_issues: int = 500) -> dict[str, Any]:
        del max_plugin_issues
        items = [{"status": "pass", "code": "v2.root_index", "title": "V2 root index", "detail": "Root index is readable and has the expected schema."}]
        if self.remote:
            items.append({"status": "pass", "code": "v2.online.read_only", "title": "Online evidence source", "detail": "Published Evidence v2 is being fetched read-only and lazily over HTTPS."})
        return {"counts": {"fail": 0, "warn": 0, "pass": len(items)}, "items": items, "generatedAtUtc": self.root.get("generatedAtUtc") or ""}

    def table_catalog(self) -> list[dict[str, Any]]:
        tables = [
            {"name": "v2_current_variants", "label": "Current variant summaries", "category": "Lifecycle", "columnCount": 1},
            {"name": "v2_terminal_variants", "label": "Retired variant snapshots", "category": "Lifecycle", "columnCount": 1},
            {"name": "v2_historical_snapshots", "label": "Superseded snapshots", "category": "Lifecycle", "columnCount": 1},
            {"name": "v2_artifacts", "label": "Artifact groups", "category": "Artifact identity", "columnCount": 1},
            {"name": "v2_analyses", "label": "Immutable analyses", "category": "Artifact identity", "columnCount": 1},
            {"name": "v2_finding_breakdown", "label": "Finding totals by current variant", "category": "Current conclusions", "columnCount": 1},
            {"name": "v2_review_variants", "label": "Variants needing review", "category": "Current conclusions", "columnCount": 1},
            {"name": "v2_unscanned_queue", "label": "Never-scanned variants", "category": "Coverage", "columnCount": 1},
            {"name": "v2_queue_items", "label": "SigmaScope queue items", "category": "Queue / revisions", "columnCount": 1},
            {"name": "v2_queue_recent_completed", "label": "Recent queue completions", "category": "Queue / revisions", "columnCount": 1},
            {"name": "v2_dependency_components", "label": "Dependency components", "category": "Global evidence", "columnCount": 1},
            {"name": "v2_advisories", "label": "Known advisory matches", "category": "Global evidence", "columnCount": 1},
            {"name": "v2_nuget_packages", "label": "NuGet package/version pairs", "category": "Global evidence", "columnCount": 1},
            {"name": "v2_ipc_providers", "label": "IPC provider registry", "category": "Global evidence", "columnCount": 1},
            {"name": "v2_plugins", "label": "Plugin identities", "category": "Catalog identity", "columnCount": 1},
            {"name": "v2_plugin_variants", "label": "Variant identities", "category": "Catalog identity", "columnCount": 1},
            {"name": "v2_sources", "label": "Source identities", "category": "Catalog identity", "columnCount": 1},
            {"name": "plugin_security_findings", "label": "Static findings", "category": "Per-variant evidence", "columnCount": 1},
            {"name": "plugin_security_dependencies", "label": "Observed dependencies", "category": "Per-variant evidence", "columnCount": 1},
            {"name": "plugin_security_permission_candidates", "label": "Permission candidates", "category": "Per-variant evidence", "columnCount": 1},
            {"name": "plugin_security_automation_capabilities", "label": "Automation evidence", "category": "Per-variant evidence", "columnCount": 1},
            {"name": "plugin_security_ipc_endpoints", "label": "IPC endpoints", "category": "Per-variant evidence", "columnCount": 1},
            {"name": "plugin_security_managed_assemblies", "label": "Managed assemblies", "category": "Forensics", "columnCount": 1},
            {"name": "plugin_security_managed_imports", "label": "Managed/native imports", "category": "Forensics", "columnCount": 1},
            {"name": "plugin_security_managed_reachability", "label": "Managed reachability", "category": "Forensics", "columnCount": 1},
            {"name": "plugin_security_managed_symbols", "label": "Managed symbols", "category": "Forensics", "columnCount": 1},
            {"name": "plugin_security_managed_calls", "label": "Managed calls", "category": "Forensics", "columnCount": 1},
        ]
        return tables

    def _special_table_rows(self, name: str) -> list[dict[str, Any]]:
        if name == "v2_current_variants":
            return [{"snapshot_kind": "current", **dict(entry.get("summary") or {}), **{k: entry.get(k) for k in ("variantId", "scanId", "artifactSha256", "analysisId", "variantPath")}} for entry in self.current_entries.values()]
        if name == "v2_terminal_variants":
            return [{"snapshot_kind": "retired", **dict(entry.get("summary") or {}), **{k: entry.get(k) for k in ("variantId", "scanId", "artifactSha256", "analysisId", "variantPath")}, "lifecycle": entry.get("lifecycle") or {}} for entry in self.terminal_entries]
        if name == "v2_historical_snapshots":
            return [{"snapshot_kind": "superseded", **dict(entry.get("summary") or {}), **{k: entry.get(k) for k in ("variantId", "scanId", "artifactSha256", "analysisId", "variantPath")}, "lifecycle": entry.get("lifecycle") or {}} for entry in self.historical_entries]
        if name == "v2_artifacts":
            payload = self._index_payload("artifacts")
            return list(payload.get("artifacts") or []) if isinstance(payload, dict) else []
        if name == "v2_analyses":
            payload = self._index_payload("artifacts")
            rows: list[dict[str, Any]] = []
            for artifact in (payload.get("artifacts") or []) if isinstance(payload, dict) else []:
                if not isinstance(artifact, dict):
                    continue
                artifact_sha = str(artifact.get("artifactSha256") or "")
                for analysis in artifact.get("analyses") or []:
                    if not isinstance(analysis, dict):
                        continue
                    manifest = analysis.get("manifest") if isinstance(analysis.get("manifest"), dict) else {}
                    rows.append({
                        "artifactSha256": artifact_sha,
                        "analysisId": str(analysis.get("analysisId") or ""),
                        "analysisPath": str(analysis.get("path") or ""),
                        "manifestPath": str(manifest.get("path") or ""),
                        "manifestSha256": str(manifest.get("sha256") or ""),
                        "manifestBytes": int(manifest.get("bytes") or 0),
                        "variantId": int((artifact.get("currentVariants") or [0])[0]) if (artifact.get("currentVariants") or []) else 0,
                        "currentVariants": list(artifact.get("currentVariants") or []),
                        "variants": list(artifact.get("variants") or []),
                        "historicalSnapshotCount": len(artifact.get("historicalSnapshots") or []),
                        "terminalSnapshotCount": len(artifact.get("terminalSnapshots") or []),
                    })
            return rows
        if name == "v2_finding_breakdown":
            rows = []
            for variant_id, entry in sorted(self.current_entries.items()):
                summary = dict(entry.get("summary") or {})
                informational = int(summary.get("informational_count") or 0)
                caution = int(summary.get("caution_count") or 0)
                high = int(summary.get("high_count") or 0)
                critical = int(summary.get("critical_count") or 0)
                rows.append({
                    "variantId": int(variant_id),
                    "plugin": summary.get("canonical_name") or summary.get("name") or summary.get("internal_name") or "",
                    "source": summary.get("source_name") or summary.get("source_provider") or "",
                    "scanId": entry.get("scanId") or summary.get("scan_id") or 0,
                    "informational_count": informational,
                    "caution_count": caution,
                    "high_count": high,
                    "critical_count": critical,
                    "finding_count": informational + caution + high + critical,
                    "highest_severity": summary.get("highest_severity") or "none",
                    "artifactSha256": entry.get("artifactSha256") or summary.get("artifact_sha256") or "",
                })
            return rows
        if name == "v2_review_variants":
            rows = []
            for variant_id, entry in sorted(self.current_entries.items()):
                summary = dict(entry.get("summary") or {})
                if str(summary.get("highest_severity") or "none").casefold() not in {"high", "critical"}:
                    continue
                rows.append({"variantId": int(variant_id), **summary})
            return rows
        if name == "v2_unscanned_queue":
            payload = self._queue_payload()
            rows = []
            for value in (payload.get("items") or {}).values():
                if not isinstance(value, dict) or str(value.get("state") or "pending") == "complete":
                    continue
                if str(value.get("workType") or "") != "artifact":
                    continue
                if int(value.get("currentScanId") or 0) > 0 or str(value.get("currentScannedAtUtc") or "").strip():
                    continue
                rows.append(dict(value))
            rows.sort(key=lambda row: (int(row.get("attemptCount") or 0) > 0, -int(row.get("priority") or 0), str(row.get("internalName") or "").casefold(), int(row.get("variantId") or 0)))
            return rows
        if name == "v2_dependency_components":
            payload = self._index_payload("dependencyComponents")
            return list(payload.get("records") or []) if isinstance(payload, dict) else []
        if name == "v2_advisories":
            payload = self._index_payload("advisories")
            return list(payload.get("records") or []) if isinstance(payload, dict) else []
        if name == "v2_nuget_packages":
            payload = self._index_payload("nuget")
            return list(payload.get("packages") or []) if isinstance(payload, dict) else []
        if name == "v2_ipc_providers":
            payload = self._index_payload("ipc")
            return list(payload.get("providers") or []) if isinstance(payload, dict) else []
        if name in {"v2_plugins", "v2_plugin_variants", "v2_sources"}:
            payload = self._index_payload("identities")
            key = {"v2_plugins": "plugins", "v2_plugin_variants": "plugin_variants", "v2_sources": "sources"}[name]
            return list(payload.get(key) or []) if isinstance(payload, dict) else []
        if name == "v2_queue_items":
            payload = self._queue_payload()
            return [dict(value) for _key, value in sorted((payload.get("items") or {}).items()) if isinstance(value, dict)]
        if name == "v2_queue_recent_completed":
            return [dict(row) for row in (self._queue_payload().get("recentCompleted") or []) if isinstance(row, dict)]
        raise ValueError(f"unknown v2 evidence table {name!r}")

    def browse_table(self, name: str, filter_column: str = "", filter_value: str = "", limit: int = 100, offset: int = 0) -> dict[str, Any]:
        datasets = {
            "plugin_security_findings": "findings",
            "plugin_security_dependencies": "dependencies",
            "plugin_security_permission_candidates": "permissions",
            "plugin_security_automation_capabilities": "automation",
            "plugin_security_ipc_endpoints": "ipc",
            "plugin_security_managed_assemblies": "assemblies",
            "plugin_security_managed_imports": "imports",
            "plugin_security_managed_reachability": "reachability",
            "plugin_security_managed_symbols": "symbols",
            "plugin_security_managed_calls": "calls",
        }
        if name in datasets:
            if self.remote and filter_column != "variant_id":
                rows: list[dict[str, Any]] = []
            elif filter_column == "variant_id":
                variant_id = int(filter_value)
                rows = [{"variant_id": variant_id, **row} for row in self.plugin_dataset(variant_id, datasets[name])]
            else:
                rows = [{"variant_id": variant_id, **row} for variant_id in self.entries for row in self.plugin_dataset(variant_id, datasets[name])]
        else:
            rows = self._special_table_rows(name)
        if filter_column and not (name in datasets and filter_column == "variant_id"):
            if filter_value == "__positive__":
                rows = [row for row in rows if float(row.get(filter_column) or 0) > 0]
            else:
                rows = [row for row in rows if str(row.get(filter_column) if isinstance(row, dict) else "") == filter_value]
        rows = [row for row in rows if isinstance(row, dict)]
        columns = sorted({key for row in rows for key in row})
        limit = min(max(1, limit), 1000); offset = max(0, offset); page = rows[offset:offset + limit]
        catalog = {item["name"]: item for item in self.table_catalog()}
        label = catalog.get(name, {}).get("label", name)
        category = catalog.get(name, {}).get("category", "Evidence")
        return {
            "name": name, "label": label, "category": category,
            "columns": [{"name": key} for key in columns], "rows": page, "foreignKeys": [],
            "limit": limit, "offset": offset, "hasMore": offset + len(page) < len(rows),
            "filter": {"column": filter_column, "value": filter_value} if filter_column else None,
            "remoteLazy": bool(self.remote and name in datasets and filter_column != "variant_id"),
        }

    def read_sql(self, query: str) -> dict[str, Any]:
        raise ValueError("SQL is unavailable for Security Evidence v2 JSON. Use the Evidence browser instead.")


# Compatibility alias for operator scripts written before the Sigmascope naming cutover.
V2SecurityInspector = V2SigmascopeInspector
