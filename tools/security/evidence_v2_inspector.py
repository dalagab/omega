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
import re
from pathlib import Path, PurePosixPath
import time
import threading
from typing import Any, Callable, Iterable
import urllib.error
import urllib.parse
import urllib.request

from deltascope_sdk import observation_projection
import reputation_intelligence
import deltascope_plugin_inventory
import deltascope_plugin_divergence
import deltascope_developer_guidance


SEVERITY_RANK = {"none": 0, "informational": 1, "low": 1, "caution": 2, "medium": 2, "high": 3, "critical": 4}
DEFAULT_ONLINE_BASE_URL = "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/"
DEFAULT_CATALOG_BASE_URL = "https://raw.githubusercontent.com/dalagab/omega/catalog-data/catalog/"
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


def _record_digest(rows: list[dict[str, Any]]) -> str:
    hashes = sorted(
        _sha256_bytes(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for row in rows
    )
    digest = hashlib.sha256()
    for item in hashes:
        digest.update(item.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


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
        # ``tracking_base_url`` follows the mutable publication branch.  The normal
        # snapshot reader starts there too, but can be pinned to an immutable Git commit
        # when raw.githubusercontent.com briefly serves a mixed branch revision.
        self.tracking_base_url = base
        self.snapshot_base_url = base
        self.snapshot_commit = ""
        self._github_raw_locator = self._parse_github_raw_base(base)
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
        self._cache_lock = threading.RLock()
        self.revision = "bootstrap"
        self.cache_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _parse_github_raw_base(base: str) -> dict[str, str] | None:
        parsed = urllib.parse.urlparse(base)
        if parsed.scheme != "https" or parsed.netloc.casefold() != "raw.githubusercontent.com":
            return None
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 3:
            return None
        owner, repo, ref = parts[:3]
        return {"owner": owner, "repo": repo, "ref": ref, "prefix": "/".join(parts[3:])}

    def set_revision(self, revision: str) -> None:
        value = str(revision or "").strip()
        self.revision = value if value else "unversioned"

    def clear_snapshot_pin(self) -> None:
        self.snapshot_base_url = self.tracking_base_url
        self.snapshot_commit = ""

    def pin_current_github_commit(self) -> str:
        """Pin raw GitHub reads to the current immutable commit for the tracked branch.

        Evidence-v2 is published atomically, but raw.githubusercontent.com edges can briefly
        expose an old shard beside a new root/index.  Resolving the branch once through the
        GitHub API and reading the retry from that commit gives DeltaScope one coherent
        snapshot without weakening any SHA-256 verification.
        """
        locator = self._github_raw_locator
        if not locator:
            return ""
        ref = str(locator["ref"] or "")
        if re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            self.snapshot_commit = ref.lower()
            return self.snapshot_commit
        api_url = (
            "https://api.github.com/repos/"
            + urllib.parse.quote(locator["owner"], safe="") + "/"
            + urllib.parse.quote(locator["repo"], safe="") + "/commits/"
            + urllib.parse.quote(ref, safe="")
        )
        request = urllib.request.Request(
            api_url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json", "Cache-Control": "no-cache"}
        )
        with self._urlopen(request, timeout=self.timeout) as response:
            data = response.read(2 * 1024 * 1024)
        payload = json.loads(data.decode("utf-8"))
        commit = str(payload.get("sha") or "").strip().lower() if isinstance(payload, dict) else ""
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("GitHub did not return a valid commit SHA for the Evidence-v2 branch")
        prefix = str(locator.get("prefix") or "").strip("/")
        suffix = f"/{prefix}/" if prefix else "/"
        self.snapshot_base_url = f"https://raw.githubusercontent.com/{locator['owner']}/{locator['repo']}/{commit}{suffix}"
        self.snapshot_commit = commit
        return commit

    def _url(self, relative: str, *, tracking: bool = False) -> str:
        relative = _safe_relative(relative)
        quoted = "/".join(urllib.parse.quote(part, safe="._-") for part in PurePosixPath(relative).parts)
        return urllib.parse.urljoin(self.tracking_base_url if tracking else self.snapshot_base_url, quoted)

    def _cache_path(self, relative: str, *, root: bool = False) -> Path:
        relative = _safe_relative(relative)
        namespace_source = "root" if root else f"{self.revision or 'unversioned'}:{self.snapshot_commit or 'tracking'}"
        namespace = hashlib.sha256(namespace_source.encode("utf-8")).hexdigest()[:12]
        path_key = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:48]
        # At most: <configured cache>/h/<12>/<48>.bin. The remote relative path never
        # becomes a local filename, avoiding WinError 206 on deeply nested analyses.
        return self.cache_root / namespace / f"{path_key}.bin"

    def _download(self, relative: str, *, tracking: bool = False) -> bytes:
        req = urllib.request.Request(
            self._url(relative, tracking=tracking),
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
        if not refresh:
            with self._cache_lock:
                try:
                    cached = cache_path.read_bytes()
                except OSError:
                    cached = None
                if cached is not None:
                    if not expected_sha256 or _sha256_bytes(cached) == expected_sha256.lower():
                        try:
                            os.utime(cache_path, None)
                        except OSError:
                            pass
                        return cached
                    try:
                        cache_path.unlink(missing_ok=True)
                    except OSError:
                        pass

        try:
            data = self._download(relative)
        except Exception:
            # Root checks are allowed to fall back to the last successfully fetched root
            # so a transient GitHub outage does not make an already-open read-only view unusable.
            if is_root:
                with self._cache_lock:
                    try:
                        return cache_path.read_bytes()
                    except OSError:
                        pass
            raise
        if expected_sha256 and _sha256_bytes(data) != expected_sha256.lower():
            raise ValueError(f"remote Security Evidence v2 SHA-256 mismatch for {relative}")
        with self._cache_lock:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            temp = cache_path.with_name(
                f"{cache_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
            )
            try:
                temp.write_bytes(data)
                temp.replace(cache_path)
            finally:
                try:
                    temp.unlink(missing_ok=True)
                except OSError:
                    pass
            self._prune_cache(protected=cache_path)
        return data

    def read_json(self, relative: str, *, expected_sha256: str = "", refresh: bool = False) -> Any:
        return json.loads(self.read_bytes(relative, expected_sha256=expected_sha256, refresh=refresh).decode("utf-8"))

    def read_tracking_json(self, relative: str) -> Any:
        """Read directly from the mutable tracking branch, bypassing snapshot caches."""
        return json.loads(self._download(relative, tracking=True).decode("utf-8"))

    def _cache_entries(self) -> list[tuple[Path, int, float]]:
        """Return a race-tolerant snapshot of cache files.

        Cache maintenance can overlap concurrent HTTP reads/writes.  On Windows in
        particular, a path returned by ``rglob`` may disappear before ``stat``.
        Missing or temporarily inaccessible cache entries are maintenance noise, not
        Evidence-v2 integrity failures, so skip them and let the next snapshot account
        for the current filesystem state.
        """
        entries: list[tuple[Path, int, float]] = []
        for path in self.cache_root.rglob("*"):
            try:
                if path.name.endswith(".tmp") or not path.is_file():
                    continue
                stat = path.stat()
            except OSError:
                continue
            entries.append((path, int(stat.st_size), float(stat.st_mtime)))
        return entries

    def _prune_cache(self, protected: Path | None = None) -> None:
        with self._cache_lock:
            entries = self._cache_entries()
            total = sum(size for _path, size, _mtime in entries)
            if total <= self.cache_limit_bytes:
                return
            for path, size, _mtime in sorted(entries, key=lambda item: item[2]):
                if protected is not None and path == protected:
                    continue
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    # Another process or Windows file locking may win this race.
                    # Keep the accounted bytes and continue with the next candidate.
                    continue
                total -= size
                if total <= self.cache_limit_bytes:
                    break

    def cache_status(self) -> dict[str, Any]:
        with self._cache_lock:
            entries = self._cache_entries()
            return {
                "cacheDirectory": str(self.cache_dir),
                "cacheBytes": sum(size for _path, size, _mtime in entries),
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
        catalog_base_url: str = "",
        catalog_cache_dir: Path | None = None,
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
        self.catalog_source: RemoteEvidenceSource | None = None
        if self.remote and str(catalog_base_url or "").strip():
            if cache_dir is None:
                raise ValueError("cache_dir is required for online catalog browsing")
            self.catalog_source = RemoteEvidenceSource(
                str(catalog_base_url).strip(),
                (catalog_cache_dir or (cache_dir.parent / "catalog-http")).resolve(),
                cache_limit_bytes=max(8 * 1024 * 1024, min(cache_limit_bytes, 64 * 1024 * 1024)),
                urlopen=urlopen,
            )
        self._catalog_inventory_cache: dict[str, Any] | None = None
        self._catalog_source_index_cache: dict[int, dict[str, Any]] | None = None
        self._catalog_plugin_payload_cache: dict[int, dict[str, Any]] = {}
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
        catalog_base_url: str = "",
        catalog_cache_dir: Path | None = None,
    ) -> "V2SigmascopeInspector":
        return cls(
            base_url=base_url, cache_dir=cache_dir, cache_limit_bytes=cache_limit_bytes, urlopen=urlopen,
            catalog_base_url=catalog_base_url, catalog_cache_dir=catalog_cache_dir,
        )

    def close(self) -> None:
        self._payload_cache.clear()
        self._manifest_cache.clear()
        self._catalog_plugin_payload_cache.clear()
        self._catalog_source_index_cache = None
        self._catalog_inventory_cache = None
        self._workbench_relationship_cache = None
        self._threat_intelligence_cache = None

    @staticmethod
    def _revision(root: dict[str, Any]) -> str:
        return str(((root.get("revisions") or {}).get("evidenceRevision") or "")).strip()

    @classmethod
    def _snapshot_token(cls, root: dict[str, Any]) -> str:
        plugins_sha = str((((root.get("indexes") or {}).get("plugins") or {}).get("sha256") or "")).strip().lower()
        return f"{cls._revision(root)}:{plugins_sha}"

    @staticmethod
    def _definitions_revision(root: dict[str, Any]) -> str:
        revisions = root.get("revisions") if isinstance(root.get("revisions"), dict) else {}
        return str(revisions.get("definitionsRevision") or "").strip()

    @classmethod
    def _publication_token(cls, root: dict[str, Any]) -> str:
        """Track the complete published security view, not only plugin rows.

        Definitions and rule provenance can advance without changing the plugin index.
        DeltaScope must therefore refresh when those published inputs change as well.
        """
        revisions = root.get("revisions") if isinstance(root.get("revisions"), dict) else {}
        provenance = (root.get("indexes") or {}).get("definitionProvenance") or {}
        return "|".join((
            cls._snapshot_token(root),
            cls._definitions_revision(root),
            str(revisions.get("ruleSetRevision") or "").strip(),
            str(provenance.get("sha256") or "").strip().lower(),
        ))

    def _load_snapshot(self, *, refresh_root: bool = False, root: dict[str, Any] | None = None, verify_definitions: bool = False) -> None:
        root = root or self.source.read_json("index.json", refresh=refresh_root)
        if root.get("schema") != "omega.security-evidence.v2" or root.get("formatVersion") != 2:
            raise ValueError(f"{self.evidence_path} is not an Omega Security Evidence v2 tree")
        # Stage the root and its authoritative plugin index before swapping the live
        # inspector state. This keeps the last-known-good snapshot intact when a moving
        # publication branch briefly exposes a mixed root/index pair.
        previous_source_revision = str(getattr(self.source, "revision", "") or "")
        next_revision = self._revision(root)
        self.source.set_revision(next_revision)
        try:
            plugins_meta = (root.get("indexes") or {}).get("plugins") or {}
            plugins = self.source.read_json(str(plugins_meta.get("path") or ""), expected_sha256=str(plugins_meta.get("sha256") or ""))
            plugins_index = plugins if isinstance(plugins, dict) else {}
            current_entries = {int(row["variantId"]): row for row in plugins_index.get("currentVariants") or [] if isinstance(row, dict)}
            terminal_entries = [row for row in plugins_index.get("terminalVariants") or [] if isinstance(row, dict)]
            historical_entries = [row for row in plugins_index.get("historicalSnapshots") or [] if isinstance(row, dict)]
            if verify_definitions:
                definitions_meta = (root.get("indexes") or {}).get("definitionProvenance") or {}
                definitions_path = str(definitions_meta.get("path") or "")
                definitions_sha = str(definitions_meta.get("sha256") or "")
                if definitions_path:
                    # A refresh is not committed until the published Definitions provenance
                    # object also passes its descriptor hash. This makes automatic refresh a
                    # coherent Evidence + Definitions swap rather than a root-only update.
                    self.source.read_json(definitions_path, expected_sha256=definitions_sha)
        except Exception:
            self.source.set_revision(previous_source_revision)
            raise
        self.root = root
        self.plugins_index = plugins_index
        self.current_entries = current_entries
        self.terminal_entries = terminal_entries
        self.historical_entries = historical_entries
        # Compatibility alias retained for callers that treat entries as the active/current set.
        self.entries = self.current_entries
        self._payload_cache.clear()
        self._manifest_cache.clear()
        self._identity_maps = None
        self._index_payload_cache: dict[str, Any] = {}
        self._queue_payload_cache: dict[str, Any] = {}
        self._srl_projection_index_cache: dict[str, Any] | None = None
        self._srl_reanalysis_cache: dict[int, dict[str, Any]] | None = None
        self._srl_analysis_request_cache: dict[int, dict[str, Any]] | None = None
        self._workbench_relationship_cache: dict[str, Any] | None = None
        self._threat_intelligence_cache: dict[str, Any] | None = None
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

    def scan_queue_state(self) -> dict[str, Any]:
        """Return a shallow read-only copy of the verified published queue state.

        DeltaScope projections use this only for explanation. Queue mutation remains
        exclusively owned by the SigmaScope production workflow.
        """
        payload = self._queue_payload()
        return dict(payload) if isinstance(payload, dict) else {"schema": "", "items": {}, "recentCompleted": []}

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
        current_definitions = self._definitions_revision(self.root)
        current_token = self._snapshot_token(self.root)
        current_publication_token = self._publication_token(self.root)
        remote_revision = current_revision
        remote_definitions = current_definitions
        remote_token = current_token
        remote_publication_token = current_publication_token
        generated = str(self.root.get("generatedAtUtc") or "")
        error = ""
        if self.remote and check_remote:
            try:
                remote_root = self.source.read_tracking_json("index.json") if isinstance(self.source, RemoteEvidenceSource) else self.source.read_json("index.json", refresh=True)
                remote_revision = self._revision(remote_root)
                remote_definitions = self._definitions_revision(remote_root)
                remote_token = self._snapshot_token(remote_root)
                remote_publication_token = self._publication_token(remote_root)
                generated = str(remote_root.get("generatedAtUtc") or generated)
            except Exception as exc:
                error = str(exc)
        return {
            "mode": self.source.mode,
            "baseUrl": self.source.display if self.remote else "",
            "currentRevision": current_revision,
            "remoteRevision": remote_revision,
            "currentEvidenceRevision": current_revision,
            "remoteEvidenceRevision": remote_revision,
            "currentDefinitionsRevision": current_definitions,
            "remoteDefinitionsRevision": remote_definitions,
            "currentSnapshotToken": current_token,
            "remoteSnapshotToken": remote_token,
            "currentPublicationToken": current_publication_token,
            "remotePublicationToken": remote_publication_token,
            "generatedAtUtc": generated,
            "definitionsUpdateAvailable": bool(self.remote and remote_definitions != current_definitions),
            "evidenceUpdateAvailable": bool(self.remote and remote_token != current_token),
            "updateAvailable": bool(self.remote and remote_publication_token != current_publication_token),
            "error": error,
            **self.source.cache_status(),
        }

    def refresh_online(self) -> dict[str, Any]:
        if not self.remote:
            return {**self.source_status(), "refreshed": False, "evidenceChanged": False, "definitionsChanged": False}
        before_revision = self._revision(self.root)
        before_definitions = self._definitions_revision(self.root)
        before_snapshot_token = self._snapshot_token(self.root)
        before_publication_token = self._publication_token(self.root)
        previous_snapshot_base = self.source.snapshot_base_url if isinstance(self.source, RemoteEvidenceSource) else ""
        previous_snapshot_commit = self.source.snapshot_commit if isinstance(self.source, RemoteEvidenceSource) else ""
        remote_root = self.source.read_tracking_json("index.json") if isinstance(self.source, RemoteEvidenceSource) else self.source.read_json("index.json", refresh=True)
        changed = self._publication_token(remote_root) != before_publication_token
        if changed:
            try:
                if isinstance(self.source, RemoteEvidenceSource):
                    self.source.clear_snapshot_pin()
                try:
                    self._load_snapshot(root=remote_root, verify_definitions=True)
                except Exception as exc:
                    # Automatic/manual refresh can race the same moving raw-GitHub branch as a
                    # lazy plugin open. Retry the complete root/index graph from one immutable
                    # commit, keeping all SHA-256 checks fail-closed.
                    if not isinstance(self.source, RemoteEvidenceSource) or not self._is_snapshot_race_error(exc):
                        raise
                    self.source.pin_current_github_commit()
                    pinned_root = self.source.read_json("index.json", refresh=True)
                    self._load_snapshot(root=pinned_root, verify_definitions=True)
            except Exception:
                # Keep both the logical root and the transport location on the previous
                # last-known-good snapshot when a refresh candidate cannot be verified.
                if isinstance(self.source, RemoteEvidenceSource):
                    self.source.snapshot_base_url = previous_snapshot_base
                    self.source.snapshot_commit = previous_snapshot_commit
                    self.source.set_revision(before_revision)
                raise
        status = self.source_status()
        status.update({
            "refreshed": changed,
            "previousRevision": before_revision,
            "previousDefinitionsRevision": before_definitions,
            "previousSnapshotToken": before_snapshot_token,
            "evidenceChanged": self._snapshot_token(self.root) != before_snapshot_token,
            "definitionsChanged": self._definitions_revision(self.root) != before_definitions,
        })
        return status

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
        # Prefer an immutable Git commit for the recovery attempt.  This handles the
        # particularly nasty case where the root token itself is unchanged but a GitHub raw
        # edge temporarily serves a shard from the adjacent publication commit.
        if isinstance(self.source, RemoteEvidenceSource):
            try:
                if self.source.pin_current_github_commit():
                    self._load_snapshot(refresh_root=True)
                    return True
            except Exception:
                # Custom/mocked transports and GitHub API outages still get the historical
                # branch-refresh fallback below. SHA verification remains mandatory.
                self.source.clear_snapshot_pin()
        before = self._snapshot_token(self.root)
        remote_root = self.source.read_tracking_json("index.json") if isinstance(self.source, RemoteEvidenceSource) else self.source.read_json("index.json", refresh=True)
        after = self._snapshot_token(remote_root)
        if isinstance(self.source, RemoteEvidenceSource):
            self.source.clear_snapshot_pin()
        # Reload even when the token is unchanged: that refreshes the lightweight index
        # graph and prevents a stale cached index from being reused after a branch race.
        self._load_snapshot(root=remote_root)
        return True

    @staticmethod
    def _catalog_descriptor(root: dict[str, Any], path: str) -> dict[str, Any]:
        for item in root.get("files") or []:
            if isinstance(item, dict) and str(item.get("path") or "") == path:
                return item
        return {}

    def _remote_catalog_inventory(self, *, refresh: bool = False) -> dict[str, Any] | None:
        """Load the current catalog logical-plugin index as a separate read-only context.

        Catalog identity is newer/different state from Security Evidence-v2 and is never
        treated as scan evidence.  A failure here degrades the picker to the Evidence-v2
        identity index instead of making the security workbench unavailable.
        """
        if self.catalog_source is None:
            return None
        if self._catalog_inventory_cache is not None and not refresh:
            return self._catalog_inventory_cache
        try:
            if refresh:
                self.catalog_source.clear_snapshot_pin()
            self.catalog_source.pin_current_github_commit()
            root = self.catalog_source.read_json("index.json", refresh=refresh)
            if str(root.get("schema") or "") != "omega.catalog-json.v1" or int(root.get("formatVersion") or 0) != 1:
                raise ValueError("published catalog JSON root has an unsupported schema")
            revision = str(root.get("catalogRevision") or "")
            self.catalog_source.set_revision(revision or "catalog")
            descriptor = self._catalog_descriptor(root, "plugins/index.json")
            plugins = self.catalog_source.read_json(
                "plugins/index.json", expected_sha256=str(descriptor.get("sha256") or "")
            )
            if str(plugins.get("schema") or "") != "omega.catalog-json.plugins-index.v1":
                raise ValueError("published catalog plugin index has an unsupported schema")
            result = {
                "catalogRevision": revision,
                "catalogBaseRevision": str(root.get("catalogBaseRevision") or ""),
                "identityEpoch": str(root.get("identityEpoch") or ""),
                "generatedAtUtc": str(root.get("generatedAtUtc") or ""),
                "plugins": [dict(row) for row in plugins.get("plugins") or [] if isinstance(row, dict)],
                "records": int(plugins.get("records") or 0),
                "activePlugins": int(plugins.get("activePlugins") or 0),
                "sourceIndexDescriptor": dict(self._catalog_descriptor(root, "sources/index.json")),
                "source": self.catalog_source.display,
                "snapshotCommit": str(self.catalog_source.snapshot_commit or ""),
            }
            self._catalog_inventory_cache = result
            self._catalog_source_index_cache = None
            self._catalog_plugin_payload_cache.clear()
            return result
        except Exception:
            # Catalog context is useful but must never weaken or block verified Evidence-v2.
            return None

    def _evidence_inventory_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for variant_id in self.entries:
            try:
                identity = self._entry_identity(variant_id)
            except Exception:
                continue
            identity = dict(identity)
            identity["variant_id"] = int(variant_id)
            rows.append(identity)
        return rows

    def logical_plugin_inventory(
        self, q: str = "", limit: int = 2000, offset: int = 0, *, refresh: bool = False,
        include_legacy: bool = False, current_api_level: int = deltascope_plugin_inventory.DEFAULT_DALAMUD_API_LEVEL,
    ) -> dict[str, Any]:
        """Return one developer-picker row per logical catalog plugin.

        The default projection is compatibility-focused: logical plugins with at least one
        current stable variant for ``current_api_level`` remain visible, as do API-unknown
        rows so missing metadata cannot silently erase a known plugin.  Old, future,
        testing-only and retired identities remain available with ``include_legacy``.
        """
        current_api_level = min(max(1, int(current_api_level or deltascope_plugin_inventory.DEFAULT_DALAMUD_API_LEVEL)), 100)
        evidence_rows = self._evidence_inventory_rows()
        maps = self._load_identity_maps()
        variant_rows = list((maps.get("variants") or {}).values())
        catalog = self._remote_catalog_inventory(refresh=refresh)
        source = "evidence-identities"
        catalog_revision = str(((self.root.get("revisions") or {}).get("catalogDataRevision") or (self.root.get("revisions") or {}).get("catalogRevision") or ""))
        identity_epoch = str(((self.root.get("revisions") or {}).get("catalogIdentityEpoch") or ""))
        if catalog:
            all_rows = deltascope_plugin_inventory.merge_catalog_plugins(
                catalog.get("plugins") or [], evidence_rows,
                catalog_revision=str(catalog.get("catalogRevision") or ""),
                identity_epoch=str(catalog.get("identityEpoch") or ""),
                variant_rows=variant_rows, current_api_level=current_api_level, include_legacy=True,
            )
            source = "catalog-data"
            catalog_revision = str(catalog.get("catalogRevision") or "")
            identity_epoch = str(catalog.get("identityEpoch") or "")
        elif maps.get("plugins"):
            variants_by_plugin: dict[int, list[int]] = {}
            for variant_id, variant in maps.get("variants", {}).items():
                if int(variant.get("active") or 0) != 1:
                    continue
                plugin_id = int(variant.get("plugin_id") or 0)
                if plugin_id:
                    variants_by_plugin.setdefault(plugin_id, []).append(int(variant_id))
            catalog_like = []
            for plugin_id, plugin in maps.get("plugins", {}).items():
                active_ids = sorted(variants_by_plugin.get(int(plugin_id), []))
                catalog_like.append({
                    "pluginId": int(plugin_id),
                    "internalName": str(plugin.get("internal_name") or ""),
                    "name": str(plugin.get("canonical_name") or plugin.get("internal_name") or ""),
                    "active": int(plugin.get("active") or 0) == 1,
                    "variantCount": sum(1 for row in variant_rows if int(row.get("plugin_id") or 0) == int(plugin_id)),
                    "activeVariantCount": len(active_ids),
                    "activeVariantIds": active_ids,
                })
            all_rows = deltascope_plugin_inventory.merge_catalog_plugins(
                catalog_like, evidence_rows, catalog_revision=catalog_revision, identity_epoch=identity_epoch,
                variant_rows=variant_rows, current_api_level=current_api_level, include_legacy=True,
            )
        else:
            # Legacy Evidence-v2 without identity maps cannot prove API compatibility. Keep
            # those rows visible as unknown rather than guessing unsupported state.
            all_rows = deltascope_plugin_inventory.group_evidence_variants(evidence_rows)
            for row in all_rows:
                row.update({
                    "compatibility_state": "unknown",
                    "compatibility_current_api_level": current_api_level,
                    "compatibility_known": False,
                    "stable_api_levels": [],
                    "testing_api_levels": [],
                    "catalog_active": True,
                })
        counts = deltascope_plugin_inventory.compatibility_counts(all_rows)
        visible_rows = all_rows if include_legacy else [
            row for row in all_rows if str(row.get("compatibility_state") or "unknown") in deltascope_plugin_inventory.CURRENT_VISIBILITY_STATES
        ]
        filtered = deltascope_plugin_inventory.filter_inventory(visible_rows, q=q, limit=limit, offset=offset)
        return {
            "schema": "omega.deltascope.logical-plugin-inventory.v1",
            "readOnly": True,
            "mutationAuthority": "none",
            "policyInput": False,
            "groupingAuthority": "catalog-plugin-id",
            "assemblyNameMergeAuthority": False,
            "source": source,
            "catalogRevision": catalog_revision,
            "catalogIdentityEpoch": identity_epoch,
            "evidenceRevision": self._revision(self.root),
            "compatibilityTargetApiLevel": current_api_level,
            "compatibilityTargetSource": "deltascope-browser-preference",
            "includeOldUnsupported": bool(include_legacy),
            "compatibilityCounts": counts,
            "hiddenOldUnsupported": sum(count for state, count in counts.items() if state not in deltascope_plugin_inventory.CURRENT_VISIBILITY_STATES),
            "plugins": filtered,
            "shown": len(filtered),
            "totalLogicalPlugins": len(visible_rows),
            "totalKnownLogicalPlugins": len(all_rows),
            "withCurrentEvidence": sum(1 for row in visible_rows if int(row.get("evidence_variant_count") or 0) > 0),
            "withoutCurrentEvidence": sum(1 for row in visible_rows if int(row.get("evidence_variant_count") or 0) <= 0),
        }

    def _remote_catalog_sources(self) -> dict[int, dict[str, Any]]:
        """Resolve catalog source IDs lazily for the selected logical-plugin dossier."""
        if self._catalog_source_index_cache is not None:
            return self._catalog_source_index_cache
        if self.catalog_source is None:
            return {}
        try:
            catalog = self._remote_catalog_inventory() or {}
            descriptor = dict(catalog.get("sourceIndexDescriptor") or {})
            payload = self.catalog_source.read_json(
                "sources/index.json", expected_sha256=str(descriptor.get("sha256") or "")
            )
            if str(payload.get("schema") or "") != "omega.catalog-json.sources-index.v1":
                raise ValueError("published catalog source index has an unsupported schema")
            rows = {
                int(row.get("sourceId") or 0): dict(row)
                for row in payload.get("sources") or []
                if isinstance(row, dict) and int(row.get("sourceId") or 0) > 0
            }
            self._catalog_source_index_cache = rows
            return rows
        except Exception:
            # Source labels are convenience context only. Variant identity and Evidence-v2
            # detail remain usable when the catalog source index is temporarily unavailable.
            return {}

    def _catalog_plugin_for_variant(self, variant_id: int) -> tuple[dict[str, Any], dict[str, Any]] | None:
        catalog = self._remote_catalog_inventory()
        if not catalog or self.catalog_source is None:
            return None
        plugin_id_hint = 0
        try:
            plugin_id_hint = int(((self._load_identity_maps().get("variants") or {}).get(int(variant_id), {}) or {}).get("plugin_id") or 0)
        except Exception:
            plugin_id_hint = 0
        for row in catalog.get("plugins") or []:
            active_ids = {int(value or 0) for value in row.get("activeVariantIds") or []}
            plugin_id = int(row.get("pluginId") or 0)
            if int(variant_id) not in active_ids and (plugin_id_hint <= 0 or plugin_id != plugin_id_hint):
                continue
            if plugin_id <= 0:
                return None
            payload = self._catalog_plugin_payload_cache.get(plugin_id)
            if payload is None:
                path = str(row.get("path") or "")
                if not path:
                    return None
                payload = self.catalog_source.read_json(path, expected_sha256=str(row.get("sha256") or ""))
                if int(((payload.get("plugin") or {}).get("plugin_id") or 0)) != plugin_id:
                    raise ValueError(f"catalog plugin identity mismatch for plugin {plugin_id}")
                self._catalog_plugin_payload_cache[plugin_id] = payload
            return dict(row), dict(payload)
        return None

    def _catalog_context_for_variant(self, variant_id: int) -> dict[str, Any] | None:
        """Return lazy logical-plugin/catalog context with current Evidence-v2 coverage overlay.

        The catalog shard is fetched only for the selected plugin.  Sibling security state is
        derived from the compact current Evidence-v2 index; opening one logical plugin must not
        fan out into one evidence payload request per active variant.
        """
        try:
            resolved = self._catalog_plugin_for_variant(variant_id)
            if resolved is None:
                return None
            index_row, payload = resolved
            plugin = dict(payload.get("plugin") or {})
            active_ids = {int(value or 0) for value in index_row.get("activeVariantIds") or [] if int(value or 0) > 0}
            raw_variants = [dict(item.get("variant") or {}) for item in payload.get("variants") or [] if isinstance(item, dict)]
            sources = self._remote_catalog_sources()
            variants: list[dict[str, Any]] = []
            for variant in raw_variants:
                sibling_id = int(variant.get("variant_id") or 0)
                if sibling_id <= 0 or (active_ids and sibling_id not in active_ids):
                    continue
                entry = self.current_entries.get(sibling_id) or {}
                summary = dict(entry.get("summary") or {}) if isinstance(entry, dict) else {}
                has_evidence = sibling_id in self.current_entries
                source = dict(sources.get(int(variant.get("source_id") or 0), {}))
                variants.append({
                    **variant,
                    "source_name": str(source.get("name") or ""),
                    "source_url": str(source.get("url") or ""),
                    "source_provider": str(source.get("provider") or ""),
                    "currentEvidence": has_evidence,
                    "evidenceScanId": int(entry.get("scanId") or summary.get("scan_id") or 0) if has_evidence else 0,
                    "evidenceStatus": str(summary.get("scan_status") or summary.get("status") or ("complete" if has_evidence else "unscanned")),
                    "evidenceHighestSeverity": str(summary.get("highest_severity") or "none").casefold() if has_evidence else "none",
                    "evidenceScannedAtUtc": str(summary.get("scanned_at_utc") or "") if has_evidence else "",
                    "evidenceAssemblyVersion": str(summary.get("assembly_version") or "") if has_evidence else "",
                    "evidenceArtifactSha256": str(entry.get("artifactSha256") or summary.get("artifact_sha256") or "") if has_evidence else "",
                    "evidenceFindingCounts": {
                        "informational": int(summary.get("informational_count") or 0) if has_evidence else 0,
                        "caution": int(summary.get("caution_count") or 0) if has_evidence else 0,
                        "high": int(summary.get("high_count") or 0) if has_evidence else 0,
                        "critical": int(summary.get("critical_count") or 0) if has_evidence else 0,
                    },
                    "selected": sibling_id == int(variant_id),
                })
            catalog = self._remote_catalog_inventory() or {}
            covered = sum(1 for row in variants if row.get("currentEvidence"))
            catalog_active = index_row.get("active") is not False
            active_variant_count = sum(1 for row in variants if int(row.get("active") or 0) == 1 and int(row.get("is_hide") or 0) != 1)
            context = {
                "schema": "omega.deltascope.logical-plugin-context.v1",
                "readOnly": True,
                "mutationAuthority": "none",
                "policyInput": False,
                "groupingAuthority": "catalog-plugin-id",
                "pluginId": int(plugin.get("plugin_id") or index_row.get("pluginId") or 0),
                "catalogRevision": str(catalog.get("catalogRevision") or ""),
                "catalogIdentityEpoch": str(catalog.get("identityEpoch") or ""),
                "catalogActive": bool(catalog_active),
                "variantScope": "active" if catalog_active else "historical",
                "activeVariantIds": sorted(active_ids),
                "activeVariantCount": active_variant_count,
                "shownVariantCount": len(variants),
                "currentEvidenceVariantCount": covered,
                "withoutCurrentEvidenceVariantCount": max(0, len(variants) - covered),
                "variants": variants,
                "presentation": payload.get("presentation") or {},
                "search": payload.get("search") or {},
            }
            context["divergence"] = deltascope_plugin_divergence.project_logical_plugin_divergence(context)
            return context
        except Exception:
            # Catalog context is navigation/explanation only and must never block verified
            # Evidence-v2 detail for the selected variant.
            return None

    def _with_catalog_context(self, detail: dict[str, Any], variant_id: int) -> dict[str, Any]:
        context = self._catalog_context_for_variant(variant_id)
        if context is None:
            detail["developerReviewPlan"] = deltascope_developer_guidance.project_developer_review_plan(detail)
            return detail
        enriched = {**detail, "catalogContext": context, "logicalPluginContext": True}
        enriched["developerReviewPlan"] = deltascope_developer_guidance.project_developer_review_plan(enriched)
        return enriched

    def _catalog_only_detail(self, variant_id: int) -> dict[str, Any] | None:
        resolved = self._catalog_plugin_for_variant(variant_id)
        if resolved is None:
            return None
        index_row, payload = resolved
        plugin = dict(payload.get("plugin") or {})
        variants = [dict(item.get("variant") or {}) for item in payload.get("variants") or [] if isinstance(item, dict)]
        variant = next((row for row in variants if int(row.get("variant_id") or 0) == int(variant_id)), {})
        if not variant:
            return None
        context = self._catalog_context_for_variant(variant_id) or {}
        identity = {
            **plugin, **variant,
            "plugin_id": int(plugin.get("plugin_id") or index_row.get("pluginId") or 0),
            "variant_id": int(variant_id),
            "canonical_name": str(plugin.get("canonical_name") or variant.get("name") or plugin.get("internal_name") or ""),
            "internal_name": str(plugin.get("internal_name") or ""),
            "scan_id": 0, "scan_status": "unscanned", "highest_severity": "none",
            "scanned_at_utc": "", "artifact_sha256": "", "scanner_version": "",
        }
        return {
            "catalogOnly": True,
            "catalogContext": context,
            "identity": identity,
            "advisories": [], "advisorySummary": {"count": 0, "highestSeverity": "none", "points": 0},
            "riskScore": 0, "audit": [], "sourceScope": {}, "sourceArtifactComparison": {}, "lineage": {}, "drift": [],
            "marketplaceSecurity": None, "snapshotKind": "catalog-only", "lifecycle": {"state": "active"},
            "analysis": {}, "observations": {}, "projection": {}, "scanProvenance": {}, "contracts": {},
            "artifactIdentity": {}, "manifestObservation": {}, "sourceAttribution": {}, "sourceProvenance": {},
            "sourceCoverage": {
                "artifactAvailable": False, "sourceCodeAvailable": False, "mode": "catalog-only",
                "repository": str(variant.get("repo_url") or ""), "commit": "", "selectedRef": "",
                "coverageLabel": "Catalog identity is known; no current Evidence-v2 scan is published for this active variant.",
                "attributionConfidence": 0, "sourceToBinaryVerified": False, "reproducibleSourceToArtifact": False,
            },
            "sourceEvidence": {}, "behaviorConsistency": {}, "secondarySecurity": {}, "package": {},
            "endpointSummary": {}, "networkEndpoints": [], "componentSummary": {}, "intelligenceCoverage": {}, "intelligenceLimits": {},
            "datasetCatalog": [], "datasetError": "",
            "researcher": {
                "priority": "routine", "signals": [{
                    "kind": "coverage", "level": "informational",
                    "label": "Plugin is present in the current Omega catalog but this active variant has no current published Evidence-v2 scan."
                }],
                "findingCounts": {"informational": 0, "caution": 0, "high": 0, "critical": 0},
                "findings": [], "capabilities": [], "capabilityIds": [], "capabilityRegistryRevision": "",
                "automationCapabilities": [], "automationLevel": "none", "secondaryMatchCount": 0,
            },
            "findings": [],
            "readOnly": True, "mutationAuthority": "none", "policyInput": False,
        }

    def list_plugins(self, q: str = "", severity: str = "", status: str = "", known_risk: bool = False, limit: int = 300, offset: int = 0) -> list[dict[str, Any]]:
        needle = q.casefold().strip()
        rows: list[dict[str, Any]] = []
        for variant_id in self.entries:
            identity = self._entry_identity(variant_id, require_current=bool(severity or status or known_risk))
            haystack = " ".join(str(identity.get(key) or "") for key in ("internal_name", "canonical_name", "name", "author", "source_name", "source_url", "source_repository")).casefold()
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
        return rows[max(0, offset):max(0, offset) + min(max(1, limit), 2000)]

    def latest_findings(self, limit: int = 20) -> list[dict[str, Any]]:
        """Load a bounded newest-finding preview from current immutable variant descriptors."""
        limit = min(max(1, int(limit or 20)), 100)
        candidates: list[tuple[str, int, dict[str, Any], dict[str, Any]]] = []
        for variant_id, entry in self.current_entries.items():
            summary = dict(entry.get("summary") or {})
            count_keys = ("informational_count", "caution_count", "high_count", "critical_count")
            count = sum(int(summary.get(key) or 0) for key in count_keys)
            # Modern Evidence-v2 indexes carry exact finding counts, allowing us to skip
            # clean variants without fetching descriptors. Older/pre-summary snapshots do
            # not; retain a small bounded fallback candidate set for compatibility.
            has_count_summary = any(key in summary for key in count_keys)
            if has_count_summary and count <= 0:
                continue
            candidates.append((str(summary.get("scanned_at_utc") or ""), int(variant_id), summary, dict(entry)))
        candidates.sort(key=lambda row: (row[0], row[1]), reverse=True)
        rows: list[dict[str, Any]] = []
        # A page opening should not fan out across the whole evidence corpus. Most variants
        # with findings contribute several rows, so this is enough for a useful preview.
        max_variants = min(len(candidates), max(8, min(30, limit * 2)))
        for _scanned, variant_id, summary, entry in candidates[:max_variants]:
            try:
                payload = self._payload(variant_id)
            except Exception:
                continue
            current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
            findings = current.get("findings_json") if isinstance(current.get("findings_json"), list) else []
            identity = self._identity(payload)
            occurred = str(current.get("scanned_at_utc") or summary.get("scanned_at_utc") or "")
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                rows.append({
                    "variantId": variant_id,
                    "scanId": int(current.get("scan_id") or entry.get("scanId") or 0),
                    "plugin": str(identity.get("canonical_name") or identity.get("name") or identity.get("internal_name") or ""),
                    "internalName": str(identity.get("internal_name") or ""),
                    "version": str(identity.get("assembly_version") or ""),
                    "sourceName": str(identity.get("source_name") or ""),
                    "occurredAtUtc": occurred,
                    "findingId": str(finding.get("findingId") or finding.get("finding_id") or ""),
                    "ruleId": str(finding.get("ruleId") or finding.get("rule_id") or ""),
                    "title": str(finding.get("title") or finding.get("findingId") or finding.get("finding_id") or "Security finding"),
                    "category": str(finding.get("category") or ""),
                    "severity": str(finding.get("severity") or "none").casefold(),
                    "readOnly": True,
                })
            if len(rows) >= limit * 2:
                break
        rows.sort(key=lambda row: (str(row.get("occurredAtUtc") or ""), SEVERITY_RANK.get(str(row.get("severity") or "none").casefold(), 0), str(row.get("findingId") or "")), reverse=True)
        return rows[:limit]


    def rule_match_fanout(self, rule_ids: Iterable[str], *, limit: int = 40, max_candidates: int = 80) -> dict[str, Any]:
        """Explicitly acquire a bounded cross-variant view for one finding/rule identity.

        This may load current variant descriptors from the configured Evidence-v2 source and is
        therefore intentionally called only from an explicit investigator action. Merely opening
        finding lineage never invokes it.
        """
        requested = {str(item or "").strip() for item in rule_ids if str(item or "").strip()}
        aliases = set(requested)
        for item in list(requested):
            if item.startswith("primitive."):
                aliases.add(item[len("primitive."):])
            elif item and "." in item:
                aliases.add(f"primitive.{item}")
        limit = min(max(1, int(limit or 40)), 100)
        max_candidates = min(max(limit, int(max_candidates or 80)), 200)
        candidates: list[tuple[str, int, dict[str, Any], dict[str, Any]]] = []
        for variant_id, entry in self.current_entries.items():
            summary = dict(entry.get("summary") or {})
            count_keys = ("informational_count", "caution_count", "high_count", "critical_count")
            has_count_summary = any(key in summary for key in count_keys)
            if has_count_summary and sum(int(summary.get(key) or 0) for key in count_keys) <= 0:
                continue
            candidates.append((str(summary.get("scanned_at_utc") or ""), int(variant_id), summary, dict(entry)))
        candidates.sort(key=lambda row: (row[0], row[1]), reverse=True)

        def flatten(value: Any) -> list[str]:
            values: list[str] = []
            if isinstance(value, dict):
                for key in sorted(value):
                    values.extend(flatten(value.get(key)))
            elif isinstance(value, list):
                for item in value:
                    values.extend(flatten(item))
            elif value is not None:
                text = str(value).strip()
                if text:
                    values.append(text)
            return values

        def pattern_key(text: str) -> str:
            value = str(text or "").strip()
            parts = value.split(":")
            if len(parts) >= 2 and parts[0].casefold() in {"metadata", "il", "source", "artifact"}:
                return ":".join(parts[:2])
            return value[:120]

        rows: list[dict[str, Any]] = []
        pattern_variants: dict[str, set[int]] = {}
        pattern_samples: dict[str, str] = {}
        inspected = 0
        for _scanned, variant_id, summary, entry in candidates[:max_candidates]:
            inspected += 1
            try:
                payload = self._payload(variant_id)
            except Exception:
                continue
            current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
            findings = current.get("findings_json") if isinstance(current.get("findings_json"), list) else []
            matches = [
                item for item in findings if isinstance(item, dict) and (
                    str(item.get("ruleId") or item.get("rule_id") or "") in aliases or
                    str(item.get("findingId") or item.get("finding_id") or "") in aliases
                )
            ]
            if not matches:
                continue
            identity = self._identity(payload)
            evidence_values: list[str] = []
            for match in matches:
                evidence_values.extend(flatten(match.get("evidence") or match.get("evidence_json") or []))
            patterns = sorted({pattern_key(item) for item in evidence_values if pattern_key(item)})[:12]
            for pattern in patterns:
                pattern_variants.setdefault(pattern, set()).add(variant_id)
                pattern_samples.setdefault(pattern, next((item for item in evidence_values if pattern_key(item) == pattern), pattern))
            primary = matches[0]
            rows.append({
                "variantId": variant_id,
                "scanId": int(current.get("scan_id") or entry.get("scanId") or 0),
                "plugin": str(identity.get("canonical_name") or identity.get("name") or identity.get("internal_name") or ""),
                "internalName": str(identity.get("internal_name") or ""),
                "version": str(identity.get("assembly_version") or ""),
                "scannedAtUtc": str(current.get("scanned_at_utc") or summary.get("scanned_at_utc") or ""),
                "severity": str(primary.get("severity") or "none").casefold(),
                "title": str(primary.get("title") or primary.get("findingId") or primary.get("ruleId") or "Security finding"),
                "ruleId": str(primary.get("ruleId") or primary.get("rule_id") or ""),
                "findingId": str(primary.get("findingId") or primary.get("finding_id") or ""),
                "evidencePatterns": patterns,
                "evidencePreview": evidence_values[:6],
                "readOnly": True,
            })
            if len(rows) >= limit:
                break
        patterns = sorted(({
            "pattern": pattern,
            "variants": len(variant_ids),
            "sample": pattern_samples.get(pattern, pattern),
        } for pattern, variant_ids in pattern_variants.items()), key=lambda item: (-int(item["variants"]), str(item["pattern"])))[:20]
        return {
            "schema": "omega.deltascope.rule-fanout.v1",
            "readOnly": True,
            "mutationAuthority": "none",
            "explicitAcquisition": True,
            "ruleIds": sorted(requested),
            "aliases": sorted(aliases),
            "matches": rows,
            "patterns": patterns,
            "searchedVariants": inspected,
            "candidateVariants": len(candidates),
            "bounded": inspected < len(candidates) or len(rows) >= limit,
            "note": "This fan-out is an explicitly acquired bounded view over current Evidence-v2 variants; it is not loaded by page navigation.",
        }

    def evidence_value_fanout(self, value: str, *, rule_ids: Iterable[str] = (), limit: int = 40, max_candidates: int = 80) -> dict[str, Any]:
        """Explicit bounded search for other current variants carrying the same finding evidence value.

        This is intentionally an investigator action because it may acquire current variant descriptors.
        It searches retained finding evidence only; it does not infer equality from similar strings or names.
        """
        needle = str(value or "").strip()
        if not needle:
            raise ValueError("evidence value is required")
        requested_rules = {str(item or "").strip() for item in rule_ids if str(item or "").strip()}
        limit = min(max(1, int(limit or 40)), 100)
        max_candidates = min(max(limit, int(max_candidates or 80)), 200)

        def flatten(item: Any) -> list[str]:
            rows: list[str] = []
            if isinstance(item, dict):
                for key in sorted(item):
                    rows.extend(flatten(item.get(key)))
            elif isinstance(item, list):
                for child in item:
                    rows.extend(flatten(child))
            elif item is not None:
                text = str(item).strip()
                if text:
                    rows.append(text)
            return rows

        candidates: list[tuple[str, int, dict[str, Any], dict[str, Any]]] = []
        for variant_id, entry in self.current_entries.items():
            summary = dict(entry.get("summary") or {})
            candidates.append((str(summary.get("scanned_at_utc") or ""), int(variant_id), summary, dict(entry)))
        candidates.sort(key=lambda row: (row[0], row[1]), reverse=True)
        matches: list[dict[str, Any]] = []
        inspected = 0
        needle_cf = needle.casefold()
        for _scanned, variant_id, summary, entry in candidates[:max_candidates]:
            inspected += 1
            try:
                payload = self._payload(variant_id)
            except Exception:
                continue
            current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
            findings = current.get("findings_json") if isinstance(current.get("findings_json"), list) else []
            hit_rows: list[dict[str, Any]] = []
            hit_values: list[str] = []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                rid = str(finding.get("ruleId") or finding.get("rule_id") or "")
                fid = str(finding.get("findingId") or finding.get("finding_id") or "")
                if requested_rules and rid not in requested_rules and fid not in requested_rules:
                    continue
                values = flatten(finding.get("evidence") or finding.get("evidence_json") or [])
                exact = [item for item in values if item.casefold() == needle_cf]
                contained = [item for item in values if needle_cf in item.casefold() or item.casefold() in needle_cf]
                selected = exact or contained
                if not selected:
                    continue
                hit_rows.append(finding)
                hit_values.extend(selected[:4])
            if not hit_rows:
                continue
            identity = self._identity(payload)
            matches.append({
                "variantId": variant_id,
                "scanId": int(current.get("scan_id") or entry.get("scanId") or 0),
                "plugin": str(identity.get("canonical_name") or identity.get("name") or identity.get("internal_name") or ""),
                "internalName": str(identity.get("internal_name") or ""),
                "version": str(identity.get("assembly_version") or ""),
                "scannedAtUtc": str(current.get("scanned_at_utc") or summary.get("scanned_at_utc") or ""),
                "findingCount": len(hit_rows),
                "ruleIds": sorted({str(row.get("ruleId") or row.get("rule_id") or "") for row in hit_rows if str(row.get("ruleId") or row.get("rule_id") or "")}),
                "evidencePreview": list(dict.fromkeys(hit_values))[:6],
                "matchSemantics": "exact" if any(item.casefold() == needle_cf for item in hit_values) else "contained",
                "readOnly": True,
            })
            if len(matches) >= limit:
                break
        return {
            "schema": "omega.deltascope.evidence-value-fanout.v1",
            "readOnly": True,
            "mutationAuthority": "none",
            "explicitAcquisition": True,
            "value": needle,
            "ruleIds": sorted(requested_rules),
            "matches": matches,
            "searchedVariants": inspected,
            "candidateVariants": len(candidates),
            "bounded": inspected < len(candidates) or len(matches) >= limit,
            "note": "Explicit bounded search over retained current finding evidence. Similar-looking values are not treated as equal evidence.",
        }

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
        behavior_consistency = report.get("behaviorConsistency") if isinstance(report.get("behaviorConsistency"), dict) else {}
        behavior_summary = behavior_consistency.get("summary") if isinstance(behavior_consistency.get("summary"), dict) else {}
        if bool(behavior_consistency.get("profileAvailable")):
            not_expected = int(behavior_summary.get("notExpectedObservedCount") or 0)
            undeclared = int(behavior_summary.get("observedUndeclaredCount") or 0)
            unexplained = int(behavior_summary.get("unexplainedDestinationCount") or 0)
            expected_missing = int(behavior_summary.get("expectedNotObservedCount") or 0)
            if not_expected:
                signals.append({"kind": "behavior-consistency", "level": "caution", "label": f"{not_expected} observed capability declaration(s) are explicitly marked not expected by the developer"})
            if undeclared:
                signals.append({"kind": "behavior-consistency", "level": "informational", "label": f"{undeclared} observed capability declaration(s) have no developer explanation"})
            if unexplained:
                signals.append({"kind": "behavior-consistency", "level": "caution", "label": f"{unexplained} observed network destination(s) are not covered by the developer profile"})
            if expected_missing:
                signals.append({"kind": "behavior-consistency", "level": "informational", "label": f"{expected_missing} declared expected capability(s) were not observed in this static analysis"})
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
            "observations": payload.get("observations") if isinstance(payload.get("observations"), dict) else {},
            "projection": payload.get("projection") if isinstance(payload.get("projection"), dict) else {},
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
            "behaviorConsistency": behavior_consistency,
            "secondarySecurity": secondary,
            "package": report.get("package") if isinstance(report.get("package"), dict) else {},
            "endpointSummary": intelligence.get("endpointSummary") if isinstance(intelligence.get("endpointSummary"), dict) else {},
            "networkEndpoints": reputation_intelligence.enrich_network_endpoints(
                intelligence.get("networkEndpoints") if isinstance(intelligence.get("networkEndpoints"), list) else [],
                self.threat_intelligence(),
            ),
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
                "capabilityIds": list(report.get("capabilityIds") or []) if isinstance(report.get("capabilityIds"), list) else [],
                "capabilityRegistryRevision": str(report.get("capabilityRegistryRevision") or ""),
                "automationCapabilities": automation_rows,
                "automationLevel": str(current.get("automation_level") or ((report.get("automation") or {}).get("level") if isinstance(report.get("automation"), dict) else "") or "none"),
                "secondaryMatchCount": secondary_match_count,
                "artifactAnalysisReused": bool(report.get("artifactAnalysisReused")),
                "artifactAnalysisRepresentativeScanId": int(report.get("artifactAnalysisRepresentativeScanId") or 0),
                "sourceAnalysisReused": bool(report.get("sourceAnalysisReused")),
            },
            "lifecycleHistory": self._snapshot_entries_for_variant(variant_id) if variant_id else [],
            "versionHistory": self.version_history(variant_id) if variant_id else [],
            "currentTotalsOnly": True,
        }
        severities = [str(row.get("severity") or "none") for row in base["advisories"] if isinstance(row, dict)]
        if severities:
            highest = max(severities, key=lambda value: SEVERITY_RANK.get(value.casefold(), 0))
            base["advisorySummary"] = {"count": len(severities), "highestSeverity": highest, "points": 0}
        base["developerReviewPlan"] = deltascope_developer_guidance.project_developer_review_plan(base)
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

    def version_history(self, variant_id: int) -> list[dict[str, Any]]:
        """Return current + retained superseded/retired versions for one catalog variant.

        Archive rows are investigation-only.  Headline security counts elsewhere in
        DeltaScope are deliberately derived from ``currentVariants`` only.
        """
        rows: list[dict[str, Any]] = []
        for entry in self._snapshot_entries_for_variant(variant_id):
            summary = dict(entry.get("summary") or {})
            kind = str(entry.get("snapshotKind") or "snapshot")
            rows.append({
                "snapshotKind": kind,
                "isCurrent": kind == "current",
                "variantId": int(entry.get("variantId") or variant_id),
                "scanId": int(entry.get("scanId") or summary.get("scan_id") or 0),
                "version": str(summary.get("assembly_version") or ""),
                "scannedAtUtc": str(summary.get("scanned_at_utc") or ""),
                "highestSeverity": str(summary.get("highest_severity") or "none").casefold(),
                "findingCount": sum(int(summary.get(key) or 0) for key in ("informational_count", "caution_count", "high_count", "critical_count")),
                "criticalCount": int(summary.get("critical_count") or 0),
                "highCount": int(summary.get("high_count") or 0),
                "artifactSha256": str(entry.get("artifactSha256") or summary.get("artifact_sha256") or ""),
                "variantPath": str(entry.get("variantPath") or ""),
                "lifecycle": dict(entry.get("lifecycle") or {}),
                "includedInCurrentTotals": kind == "current",
            })
        rows.sort(key=lambda row: (not bool(row["isCurrent"]), -int(row.get("scanId") or 0)))
        return rows

    def plugin_detail(self, variant_id: int) -> dict[str, Any]:
        def with_snapshot_identity(detail: dict[str, Any], entry: dict[str, Any] | None) -> dict[str, Any]:
            if not entry:
                return detail
            return {
                **detail,
                "variantPath": str(entry.get("variantPath") or ""),
                "snapshotSha256": str(entry.get("variantSha256") or ""),
            }

        try:
            return self._with_catalog_context(with_snapshot_identity(
                self._detail_from_payload(self._payload(variant_id), snapshot_kind="current"),
                self.current_entries.get(variant_id),
            ), variant_id)
        except Exception as exc:
            catalog_only = self._catalog_only_detail(variant_id) if variant_id not in self.current_entries else None
            if catalog_only is not None:
                return catalog_only
            if not self._refresh_after_snapshot_race(exc):
                raise
            if variant_id in self.current_entries:
                return {
                    **self._with_catalog_context(with_snapshot_identity(
                        self._detail_from_payload(self._payload(variant_id), snapshot_kind="current"),
                        self.current_entries.get(variant_id),
                    ), variant_id),
                    "onlineSnapshotRefreshed": True,
                }
            retained = self._snapshot_entries_for_variant(variant_id)
            if retained:
                entry = retained[0]
                return {
                    **with_snapshot_identity(
                        self._detail_from_payload(self._payload_for_entry(entry), snapshot_kind=str(entry.get("snapshotKind") or "snapshot")),
                        entry,
                    ),
                    "onlineSnapshotRefreshed": True,
                    "variantNoLongerCurrent": True,
                }
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
            return {
                **self._detail_from_payload(self._payload_for_entry(entry), snapshot_kind=kind),
                "variantPath": path,
                "snapshotSha256": str(entry.get("variantSha256") or ""),
            }
        except Exception as exc:
            if not self._refresh_after_snapshot_race(exc):
                raise
            entry, kind = resolve()
            return {
                **self._detail_from_payload(self._payload_for_entry(entry), snapshot_kind=kind),
                "variantPath": path,
                "snapshotSha256": str(entry.get("variantSha256") or ""),
                "onlineSnapshotRefreshed": True,
            }

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

    def _dataset_limited(self, payload: dict[str, Any], name: str, limit: int) -> list[dict[str, Any]]:
        """Read at most ``limit`` immutable dataset rows for selected-case investigation."""
        dataset = (self._manifest(payload).get("datasets") or {}).get(name) or {}
        rows: list[dict[str, Any]] = []
        remaining = max(0, int(limit))
        if remaining <= 0:
            return rows
        for item in dataset.get("files") or []:
            if remaining <= 0:
                break
            path = str(item.get("path") or "")
            expected = str(item.get("sha256") or "")
            encoding = str(item.get("encoding") or "")
            data = self.source.read_bytes(path, expected_sha256=expected)
            if encoding == "json":
                value = json.loads(data.decode("utf-8"))
                values = value if isinstance(value, list) else [value]
            elif encoding == "jsonl+gzip":
                text = gzip.decompress(data).decode("utf-8")
                values = [json.loads(line) for line in text.splitlines() if line.strip()]
            else:
                values = []
            for value in values:
                if isinstance(value, dict):
                    rows.append(value)
                    remaining -= 1
                    if remaining <= 0:
                        break
        return rows

    def definition_provenance(self) -> dict[str, Any]:
        """Return the optional exact frozen Definitions/rule provenance sidecar."""
        value = self._index_payload("definitionProvenance")
        if not value:
            return {
                "schema": "omega.security-evidence.definition-provenance.v1",
                "available": False, "readOnly": True, "mutationAuthority": "none", "policyInput": False,
                "provenanceRevision": "", "definitions": {},
                "srl": {"packCount": 0, "activeRuleCount": 0, "productionRuleEvaluationEnabled": False},
                "packs": [], "activeRules": [],
            }
        if not isinstance(value, dict) or str(value.get("schema") or "") != "omega.security-evidence.definition-provenance.v1":
            raise ValueError("unsupported DeltaScope Definition provenance index")
        if value.get("readOnly") is not True or str(value.get("mutationAuthority") or "") != "none" or bool(value.get("policyInput")):
            raise ValueError("DeltaScope Definition provenance violates the read-only boundary")
        return {"available": True, **value}

    def workbench_system_context(self) -> dict[str, Any]:
        """Return bounded published pipeline/revision state for read-only System/Reports views."""
        projections = self._srl_projection_index()
        relationship = (self.root.get("indexes") or {}).get("workbenchRelationships") or {}
        provenance = (self.root.get("indexes") or {}).get("definitionProvenance") or {}
        queue = self.root.get("scannerQueue") if isinstance(self.root.get("scannerQueue"), dict) else {}
        source = self.root.get("source") if isinstance(self.root.get("source"), dict) else {}
        return {
            "schema": "omega.deltascope.system-context.v1",
            "readOnly": True, "mutationAuthority": "none",
            "generatedAtUtc": str(self.root.get("generatedAtUtc") or ""),
            "evidence": {
                "schema": str(self.root.get("schema") or ""),
                "formatVersion": int(self.root.get("formatVersion") or 0),
                "revisions": dict(self.root.get("revisions") or {}),
                "counts": dict(self.root.get("counts") or {}),
                "publication": dict(self.root.get("publication") or {}),
            },
            "engine": dict(self.root.get("engine") or {}),
            "source": {
                **{
                    key: source.get(key) for key in (
                        "engineName", "engineVersion", "scannerVersion", "catalogDataRevision",
                        "catalogIdentityEpoch", "definitionsRevision", "artifactAnalysisRevision",
                        "sourceAnalysisRevision", "advisoryRevision",
                    ) if source.get(key) is not None
                },
                **({"osv": dict(source.get("osv") or {})} if isinstance(source.get("osv"), dict) else {}),
            },
            "queue": {
                "available": bool(queue),
                "schema": str(queue.get("schema") or ""),
                "summary": dict(queue.get("summary") or {}) if isinstance(queue.get("summary"), dict) else {},
            },
            "ruleProjections": {
                "available": bool(projections),
                "schema": str(projections.get("schema") or ""),
                "projectionSetRevision": str(projections.get("projectionSetRevision") or ""),
                "ruleSetRevision": str(projections.get("ruleSetRevision") or ""),
                "counts": dict(projections.get("counts") or {}) if isinstance(projections.get("counts"), dict) else {},
                "productionRuleEvaluationEnabled": bool(projections.get("productionRuleEvaluationEnabled")),
                "productionWriteBack": bool(projections.get("productionWriteBack")),
                "queueMutationAuthorized": bool(projections.get("queueMutationAuthorized")),
            },
            "relationshipIndex": {
                "available": bool(relationship),
                "relationshipRevision": str(relationship.get("relationshipRevision") or ""),
                "path": str(relationship.get("path") or ""),
            },
            "definitionProvenance": {
                "available": bool(provenance),
                "provenanceRevision": str(provenance.get("provenanceRevision") or ""),
                "definitionsRevision": str(provenance.get("definitionsRevision") or ""),
                "ruleSetRevision": str(provenance.get("ruleSetRevision") or ""),
                "activeRuleCount": int(provenance.get("activeRuleCount") or 0),
                "packCount": int(provenance.get("packCount") or 0),
            },
        }

    def _read_record_descriptor(self, descriptor: dict[str, Any], *, label: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for file_info in descriptor.get("files") or []:
            if not isinstance(file_info, dict):
                raise ValueError(f"{label} contains a malformed shard descriptor")
            path = str(file_info.get("path") or "")
            data = self.source.read_bytes(path, expected_sha256=str(file_info.get("sha256") or ""))
            encoding = str(file_info.get("encoding") or "")
            if encoding == "json":
                value = json.loads(data.decode("utf-8"))
                values = value if isinstance(value, list) else [value]
                rows.extend(dict(item) for item in values if isinstance(item, dict))
            elif encoding == "jsonl+gzip":
                text = gzip.decompress(data).decode("utf-8")
                for line in text.splitlines():
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(dict(value))
            else:
                raise ValueError(f"{label} has unsupported encoding {encoding!r}")
        if len(rows) != int(descriptor.get("records") or 0):
            raise ValueError(f"{label} record count mismatch")
        if str(descriptor.get("recordDigest") or "") != _record_digest(rows):
            raise ValueError(f"{label} semantic record digest mismatch")
        return rows

    def threat_intelligence(self) -> dict[str, Any]:
        """Return the verified frozen URL/domain/IP threat-intelligence snapshot published with Evidence v2."""
        if self._threat_intelligence_cache is not None:
            return self._threat_intelligence_cache
        value = self._index_payload("threatIntelligence")
        if not value:
            self._threat_intelligence_cache = {
                "schema": "omega.reputation-definitions.v2", "reputationRevision": "",
                "feeds": [], "indicators": [], "observedEndpointResolutions": [], "observedEndpointMatches": [],
                "indexes": {"byIp": {}, "byHost": {}, "byUrl": {}}, "counts": {},
            }
            return self._threat_intelligence_cache
        if not isinstance(value, dict) or str(value.get("schema") or "") != "omega.reputation-definitions.v2":
            raise ValueError("unsupported frozen threat-intelligence payload")
        descriptor = (self.root.get("indexes") or {}).get("threatIntelligence") or {}
        revision = str(value.get("reputationRevision") or "")
        if revision != str(descriptor.get("reputationRevision") or ""):
            raise ValueError("threat-intelligence reputation revision mismatch")
        self._threat_intelligence_cache = value
        return value

    def workbench_relationship_index(self) -> dict[str, Any]:
        """Return the optional read-only ecosystem relationship index used by DeltaScope.

        V2 keeps only a small manifest in the root graph and fetches the bounded
        compressed relationship shards on first use. Older monolithic V1 snapshots
        remain readable during rollout.
        """
        if self._workbench_relationship_cache is not None:
            return self._workbench_relationship_cache
        value = self._index_payload("workbenchRelationships")
        if not value:
            result = {
                "schema": "omega.security-evidence.workbench-relationships.v2",
                "relationshipRevision": "", "readOnly": True, "mutationAuthority": "none", "policyInput": False,
                "counts": {"endpoints": 0, "components": 0, "advisories": 0},
                "endpoints": [], "components": [], "advisories": [],
            }
            self._workbench_relationship_cache = result
            return result
        if not isinstance(value, dict):
            raise ValueError("unsupported DeltaScope workbench relationship index")
        schema = str(value.get("schema") or "")
        if schema not in {
            "omega.security-evidence.workbench-relationships.v1",
            "omega.security-evidence.workbench-relationships.v2",
        }:
            raise ValueError("unsupported DeltaScope workbench relationship index")
        if value.get("readOnly") is not True or str(value.get("mutationAuthority") or "") != "none" or bool(value.get("policyInput")):
            raise ValueError("DeltaScope workbench relationship index violates the read-only boundary")
        if schema == "omega.security-evidence.workbench-relationships.v1":
            self._workbench_relationship_cache = value
            return value
        if str(value.get("storage") or "") != "sharded-jsonl-gzip":
            raise ValueError("unsupported DeltaScope workbench relationship storage")
        datasets = value.get("datasets") if isinstance(value.get("datasets"), dict) else {}
        rows = {
            name: self._read_record_descriptor(
                datasets.get(name) if isinstance(datasets.get(name), dict) else {},
                label=f"workbenchRelationships {name}",
            )
            for name in ("endpoints", "components", "advisories")
        }
        counts = value.get("counts") if isinstance(value.get("counts"), dict) else {}
        for name, records in rows.items():
            if int(counts.get(name) or 0) != len(records):
                raise ValueError(f"workbenchRelationships {name} count mismatch")
        edge_counts = {
            "endpointVariantEdges": sum(len(item.get("variantIds") or []) for item in rows["endpoints"]),
            "componentVariantEdges": sum(len(item.get("usage") or []) for item in rows["components"]),
            "advisoryVariantEdges": sum(len(item.get("affectedAssets") or []) for item in rows["advisories"]),
        }
        for name, actual in edge_counts.items():
            if int(counts.get(name) or 0) != actual:
                raise ValueError(f"workbenchRelationships {name} count mismatch")
        semantic_core = {name: rows[name] for name in ("endpoints", "components", "advisories")}
        expected_revision = "workbench-rel-v2-" + _sha256_bytes(
            json.dumps(semantic_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )[:20]
        if str(value.get("relationshipRevision") or "") != expected_revision:
            raise ValueError("workbenchRelationships semantic revision mismatch")
        root_meta = (self.root.get("indexes") or {}).get("workbenchRelationships") or {}
        if str(root_meta.get("relationshipRevision") or "") != expected_revision:
            raise ValueError("workbenchRelationships root relationshipRevision mismatch")
        result = {**value, **rows}
        self._workbench_relationship_cache = result
        return result

    def workbench_assets_for_variants(self, variant_ids: Iterable[int]) -> list[dict[str, Any]]:
        """Resolve current variant IDs to the lightweight plugin-index summaries without deep evidence fetches."""
        rows: list[dict[str, Any]] = []
        for variant_id in sorted({int(item) for item in variant_ids if int(item) > 0}):
            if variant_id not in self.entries:
                continue
            identity = self._entry_identity(variant_id, require_current=False)
            identity["variant_id"] = variant_id
            rows.append(identity)
        return rows

    def _collector_result_rows(self, descriptor: dict[str, Any], collection: str, limit: int) -> list[dict[str, Any]]:
        """Load one retained external collector collection after checking its declared identity."""
        result_path = str(descriptor.get("resultPath") or "")
        if not result_path:
            return []
        result = self.source.read_json(_safe_relative(result_path))
        if not isinstance(result, dict) or str(result.get("schema") or "") != "omega.collector-result.v1":
            raise ValueError("collector result has an unsupported schema")
        if str(result.get("resultRevision") or "") != str(descriptor.get("resultRevision") or ""):
            raise ValueError("collector result revision does not match the observation contract")
        result_collections = result.get("collections") if isinstance(result.get("collections"), dict) else {}
        payload = result_collections.get(collection) if isinstance(result_collections.get(collection), dict) else {}
        rows = [dict(row) for row in (payload.get("rows") or []) if isinstance(row, dict)]
        if int(payload.get("records") or 0) != int(descriptor.get("records") or 0):
            raise ValueError("collector result record count does not match the observation contract")
        expected_digest = str(descriptor.get("recordDigest") or "")
        if expected_digest and _record_digest(rows) != expected_digest:
            raise ValueError("collector result record digest does not match the observation contract")
        return rows[:max(0, int(limit))]

    def workbench_observation_rows(self, variant_id: int, *, per_collection_limit: int = 40) -> dict[str, list[dict[str, Any]]]:
        """Load bounded retained observations lazily for one DeltaScope investigation case."""
        payload = self._payload(variant_id)
        manifest = self._manifest(payload)
        report = self._report(payload.get("current") if isinstance(payload.get("current"), dict) else {})
        compact = observation_projection.report_observation_rows(report)
        contract = payload.get("observations") if isinstance(payload.get("observations"), dict) else {}
        collections = contract.get("collections") if isinstance(contract.get("collections"), dict) else {}
        result: dict[str, list[dict[str, Any]]] = {}
        known_collections = list(observation_projection.COLLECTIONS)
        declared_collections = known_collections + sorted(name for name in collections if name not in observation_projection.COLLECTIONS)
        for collection in declared_collections:
            descriptor = collections.get(collection) if isinstance(collections.get(collection), dict) else {}
            backing = str(descriptor.get("backingDataset") or "")
            if backing == "collector-result":
                try:
                    result[collection] = self._collector_result_rows(descriptor, collection, per_collection_limit)
                    continue
                except (KeyError, ValueError, FileNotFoundError):
                    # External collector results are context-only. A malformed or unavailable
                    # result must not become an implied negative observation.
                    result[collection] = []
                    continue
            if backing and backing not in {"compact-report"}:
                try:
                    result[collection] = self._dataset_limited(payload, backing, per_collection_limit)
                    continue
                except (KeyError, ValueError, FileNotFoundError):
                    # A compact compatibility row may still exist; do not turn a workbench
                    # preview failure into evidence mutation or a fabricated observation.
                    pass
            rows = compact.get(collection) or []
            result[collection] = [dict(item) for item in rows[:max(0, int(per_collection_limit))] if isinstance(item, dict)]
        if "networkEndpoints" in result:
            result["networkEndpoints"] = reputation_intelligence.enrich_network_endpoints(
                result["networkEndpoints"], self.threat_intelligence()
            )
        return result

    def _srl_projection_index(self) -> dict[str, Any]:
        if self._srl_projection_index_cache is not None:
            return self._srl_projection_index_cache
        descriptor = self.root.get("srlRuleProjections") if isinstance(self.root.get("srlRuleProjections"), dict) else {}
        path = str(descriptor.get("path") or "")
        if not path:
            self._srl_projection_index_cache = {}
            return self._srl_projection_index_cache
        value = self.source.read_json(path, expected_sha256=str(descriptor.get("sha256") or ""))
        self._srl_projection_index_cache = value if isinstance(value, dict) else {}
        return self._srl_projection_index_cache

    def srl_projection_state(self, variant_id: int) -> dict[str, Any]:
        """Return the non-authoritative Phase-10 projection/reanalysis relationship for a variant."""
        index = self._srl_projection_index()
        if not index:
            return {"available": False, "productionWriteBack": False, "queueMutationAuthorized": False}
        root_path = PurePosixPath(str((self.root.get("srlRuleProjections") or {}).get("path") or "rule-projections/index.json")).parent
        result: dict[str, Any] = {
            "available": True,
            "projectionSetRevision": str(index.get("projectionSetRevision") or ""),
            "ruleSetRevision": str(index.get("ruleSetRevision") or ""),
            "productionRuleEvaluationEnabled": bool(index.get("productionRuleEvaluationEnabled")),
            "productionWriteBack": bool(index.get("productionWriteBack")),
            "queueMutationAuthorized": bool(index.get("queueMutationAuthorized")),
        }
        for entry in index.get("variants") or []:
            if not isinstance(entry, dict) or int(entry.get("variantId") or 0) != int(variant_id):
                continue
            rel = (root_path / _safe_relative(str(entry.get("path") or ""))).as_posix()
            result["projection"] = self.source.read_json(rel, expected_sha256=str(entry.get("sha256") or ""))
            break
        if self._srl_reanalysis_cache is None:
            request = index.get("reanalysisRequests") if isinstance(index.get("reanalysisRequests"), dict) else {}
            path = str(request.get("path") or "")
            requests: dict[int, dict[str, Any]] = {}
            if path:
                rel = (root_path / _safe_relative(path)).as_posix()
                payload = self.source.read_json(rel, expected_sha256=str(request.get("sha256") or ""))
                for item in payload.get("requests") or [] if isinstance(payload, dict) else []:
                    if isinstance(item, dict) and int(item.get("variantId") or 0) > 0:
                        requests[int(item["variantId"])] = dict(item)
            self._srl_reanalysis_cache = requests
        if int(variant_id) in self._srl_reanalysis_cache:
            result["reanalysisRequest"] = dict(self._srl_reanalysis_cache[int(variant_id)])
        if self._srl_analysis_request_cache is None:
            request = index.get("analysisRequests") if isinstance(index.get("analysisRequests"), dict) else {}
            path = str(request.get("path") or "")
            requests: dict[int, dict[str, Any]] = {}
            if path:
                rel = (root_path / _safe_relative(path)).as_posix()
                payload = self.source.read_json(rel, expected_sha256=str(request.get("sha256") or ""))
                for item in payload.get("requests") or [] if isinstance(payload, dict) else []:
                    if isinstance(item, dict) and int(item.get("variantId") or 0) > 0:
                        requests[int(item["variantId"])] = dict(item)
            self._srl_analysis_request_cache = requests
        if int(variant_id) in self._srl_analysis_request_cache:
            result["analysisRequest"] = dict(self._srl_analysis_request_cache[int(variant_id)])
        return result

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
