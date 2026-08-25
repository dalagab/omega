#!/usr/bin/env python3
"""Verified, read-only published resource cache for DeltaScope.

DeltaScope is intentionally a consumer of Omega's published security contracts.  This
module downloads only the small data/contracts needed by the workbench (Definitions index,
SRL Definition Packs, compiled SRL ruleset, and platform registries).  It never downloads or
executes the frozen SigmaScope worker bundle.

The remote ``definitions/index.json`` is the HTTPS trust anchor.  Every child payload is
verified against the SHA-256 pinned by that index (and, for SRL pack files, by the pinned SRL
index).  Successfully materialized revisions are immutable cache snapshots.  If the network
is unavailable, DeltaScope can reuse the last verified snapshot without silently accepting
unverified new bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

RESOURCE_SCHEMA = "omega.deltascope.published-resources.v1"
STATE_SCHEMA = "omega.deltascope.published-resources-state.v1"
DEFAULT_DEFINITIONS_BASE_URL = "https://raw.githubusercontent.com/dalagab/omega/catalog-data/definitions"
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_RESOURCE_BYTES = 16 * 1024 * 1024
MAX_RESOURCE_FILES = 512
USER_AGENT = "Omega-DeltaScope/PublishedResources"
FALLBACK_EXECUTION_TOPOLOGY = Path(__file__).resolve().parents[2] / "deltascope" / "execution-topology-fallback.json"


class ResourceError(RuntimeError):
    pass


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_rel(value: object) -> str:
    text = str(value or "").replace("\\", "/").strip()
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or ".." in pure.parts:
        raise ResourceError(f"unsafe published resource path: {text!r}")
    return pure.as_posix()


def _headers() -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
    token = os.environ.get("OMEGA_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _read_url(url: str, *, maximum: int) -> bytes:
    request = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ResourceError(f"published resource exceeded {maximum:,} bytes: {url}")
    return data


def _json_bytes(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ResourceError(f"{label} is not valid UTF-8 JSON: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise ResourceError(f"{label} must contain a JSON object")
    return value


def _join_url(base_url: str, relative: str) -> str:
    base = str(base_url or "").rstrip("/") + "/"
    return urllib.parse.urljoin(base, "/".join(urllib.parse.quote(part) for part in _safe_rel(relative).split("/")))


def _write_verified(root: Path, relative: str, data: bytes, expected_sha256: str) -> dict[str, Any]:
    relative = _safe_rel(relative)
    expected = str(expected_sha256 or "").lower()
    actual = _sha256_bytes(data)
    if len(expected) != 64 or actual != expected:
        raise ResourceError(f"SHA-256 verification failed for {relative}: expected {expected or '<missing>'}, got {actual}")
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return {"path": relative, "sha256": actual, "bytes": len(data)}


def _descriptor(index: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = index.get(key)
    if not isinstance(value, Mapping):
        raise ResourceError(f"published Definitions index has no {key} descriptor")
    path = _safe_rel(value.get("path"))
    sha256 = str(value.get("sha256") or "").lower()
    if len(sha256) != 64:
        raise ResourceError(f"published Definitions {key} descriptor has no valid SHA-256")
    return {**dict(value), "path": path, "sha256": sha256}

def _optional_descriptor(index: Mapping[str, Any], key: str) -> dict[str, Any] | None:
    value = index.get(key)
    if value is None:
        return None
    return _descriptor(index, key)


def _fallback_execution_topology() -> dict[str, Any]:
    try:
        payload = _json_bytes(FALLBACK_EXECUTION_TOPOLOGY.read_bytes(), label="bundled execution topology")
    except OSError as exc:
        raise ResourceError(f"bundled execution topology is unavailable: {exc}") from exc
    if str(payload.get("schema") or "") != "omega.execution-topology.v1":
        raise ResourceError("bundled execution topology uses an unsupported schema")
    return payload


def _state_path(cache_root: Path) -> Path:
    return cache_root / "current.json"


def _snapshot_root(cache_root: Path, revision: str) -> Path:
    return cache_root / "snapshots" / revision


def _write_state(cache_root: Path, revision: str) -> None:
    state = {
        "schema": STATE_SCHEMA,
        "definitionsRevision": revision,
        "updatedAtUtc": _utc_now(),
    }
    state_temp = _state_path(cache_root).with_suffix(".json.part")
    state_temp.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    state_temp.replace(_state_path(cache_root))


def _load_manifest(root: Path) -> dict[str, Any]:
    path = root / "deltascope-resource-manifest.json"
    if not path.is_file():
        raise ResourceError(f"DeltaScope resource snapshot has no manifest: {root}")
    payload = _json_bytes(path.read_bytes(), label="DeltaScope resource manifest")
    if payload.get("schema") != RESOURCE_SCHEMA:
        raise ResourceError(f"unsupported DeltaScope resource manifest schema: {payload.get('schema')!r}")
    files = payload.get("files")
    if not isinstance(files, list) or len(files) > MAX_RESOURCE_FILES:
        raise ResourceError("DeltaScope resource manifest has an invalid file list")
    for item in files:
        if not isinstance(item, Mapping):
            raise ResourceError("DeltaScope resource manifest contains a malformed file descriptor")
        rel = _safe_rel(item.get("path"))
        path = root / rel
        expected = str(item.get("sha256") or "").lower()
        if not path.is_file() or path.stat().st_size != int(item.get("bytes") or -1) or _sha256_file(path) != expected:
            raise ResourceError(f"cached DeltaScope resource failed verification: {rel}")
    return payload


@dataclass(frozen=True)
class PublishedResources:
    root: Path
    manifest: dict[str, Any]
    stale: bool = False
    warning: str = ""

    @property
    def definitions_index(self) -> dict[str, Any]:
        return _json_bytes((self.root / "index.json").read_bytes(), label="cached Definitions index")

    @property
    def srl_index(self) -> dict[str, Any]:
        rel = str(self.manifest.get("srlIndexPath") or "srl/index.json")
        return _json_bytes((self.root / _safe_rel(rel)).read_bytes(), label="cached SRL index")

    @property
    def packs_root(self) -> Path:
        return self.root / "srl" / "packs"

    def _registry(self, key: str) -> dict[str, Any]:
        rel = str((self.manifest.get("registries") or {}).get(key) or "")
        return _json_bytes((self.root / _safe_rel(rel)).read_bytes(), label=f"cached {key} registry") if rel else {}

    @property
    def component_registry(self) -> dict[str, Any]:
        return self._registry("components")

    @property
    def collector_registry(self) -> dict[str, Any]:
        return self._registry("collectors")

    @property
    def capability_registry(self) -> dict[str, Any]:
        return self._registry("capabilities")

    @property
    def execution_topology(self) -> dict[str, Any]:
        rel = str(self.manifest.get("executionTopologyPath") or "")
        if rel:
            path = self.root / _safe_rel(rel)
            if path.is_file():
                return _json_bytes(path.read_bytes(), label="cached execution topology")
        return _fallback_execution_topology()

    def public_status(self) -> dict[str, Any]:
        return {
            "schema": RESOURCE_SCHEMA,
            "available": True,
            "readOnly": True,
            "mutationAuthority": "none",
            "policyInput": False,
            "sourceAuthority": "published-frozen-definitions",
            "definitionsRevision": str(self.manifest.get("definitionsRevision") or ""),
            "definitionPackRevision": str(self.manifest.get("definitionPackRevision") or ""),
            "ruleSetRevision": str(self.manifest.get("ruleSetRevision") or ""),
            "componentRegistryRevision": str(self.manifest.get("componentRegistryRevision") or ""),
            "collectorRegistryRevision": str(self.manifest.get("collectorRegistryRevision") or ""),
            "capabilityRegistryRevision": str(self.manifest.get("capabilityRegistryRevision") or ""),
            "executionTopologyRevision": str(self.manifest.get("executionTopologyRevision") or self.execution_topology.get("revision") or ""),
            "executionTopologyAuthority": "published-frozen-definitions" if self.manifest.get("executionTopologyPath") else "bundled-rollout-fallback",
            "baseUrl": str(self.manifest.get("baseUrl") or ""),
            "cachedAtUtc": str(self.manifest.get("cachedAtUtc") or ""),
            "stale": bool(self.stale),
            "warning": str(self.warning or ""),
            "downloadedWorkerCode": False,
        }


def load_cached(cache_root: Path) -> PublishedResources:
    cache_root = cache_root.resolve()
    state_file = _state_path(cache_root)
    if not state_file.is_file():
        raise ResourceError("no previously verified DeltaScope platform-resource snapshot is cached")
    state = _json_bytes(state_file.read_bytes(), label="DeltaScope resource state")
    if state.get("schema") != STATE_SCHEMA:
        raise ResourceError("unsupported DeltaScope resource state schema")
    revision = str(state.get("definitionsRevision") or "")
    root = _snapshot_root(cache_root, revision)
    manifest = _load_manifest(root)
    if str(manifest.get("definitionsRevision") or "") != revision:
        raise ResourceError("cached DeltaScope resource state revision mismatch")
    return PublishedResources(root=root, manifest=manifest)


def _fetch_child(base_url: str, root: Path, relative: str, expected_sha256: str, files: list[dict[str, Any]]) -> bytes:
    if len(files) >= MAX_RESOURCE_FILES:
        raise ResourceError("published DeltaScope resource bundle exceeded the file-count bound")
    data = _read_url(_join_url(base_url, relative), maximum=MAX_RESOURCE_BYTES)
    files.append(_write_verified(root, relative, data, expected_sha256))
    return data


def sync_published_resources(
    cache_root: Path,
    *,
    base_url: str = DEFAULT_DEFINITIONS_BASE_URL,
    offline: bool = False,
    allow_stale: bool = True,
) -> PublishedResources:
    """Synchronize the small published contract bundle and return a verified snapshot.

    ``offline=True`` never performs network I/O.  When online synchronization fails and
    ``allow_stale`` is true, the last fully verified snapshot is returned with ``stale=True``.
    """
    cache_root = cache_root.resolve()
    cache_root.mkdir(parents=True, exist_ok=True)
    if offline:
        cached = load_cached(cache_root)
        return PublishedResources(cached.root, cached.manifest, stale=True, warning="offline mode: using last verified published resources")

    try:
        index_bytes = _read_url(_join_url(base_url, "index.json"), maximum=MAX_INDEX_BYTES)
        index = _json_bytes(index_bytes, label="published Definitions index")
        if str(index.get("schema") or "") != "omega.definitions.v1":
            raise ResourceError(f"unsupported published Definitions schema: {index.get('schema')!r}")
        revision = str(index.get("definitionsRevision") or "")
        if not revision.startswith("defs-v1-"):
            raise ResourceError("published Definitions index has no valid revision")
        existing = _snapshot_root(cache_root, revision)
        if existing.is_dir():
            manifest = _load_manifest(existing)
            _write_state(cache_root, revision)
            return PublishedResources(existing, manifest)

        snapshots = cache_root / "snapshots"
        snapshots.mkdir(parents=True, exist_ok=True)
        temp_root = Path(tempfile.mkdtemp(prefix=f".{revision}-", dir=snapshots))
        files: list[dict[str, Any]] = []
        try:
            # The root index is the HTTPS trust anchor for all child descriptors.
            (temp_root / "index.json").write_bytes(index_bytes)
            files.append({"path": "index.json", "sha256": _sha256_bytes(index_bytes), "bytes": len(index_bytes), "trustAnchor": True})

            capability = _descriptor(index, "capabilityRegistry")
            component = _descriptor(index, "componentRegistry")
            collector = _descriptor(index, "collectorRegistry")
            execution = _optional_descriptor(index, "executionTopology")
            srl = _descriptor(index, "srlDefinitionPacks")
            for descriptor in (capability, component, collector):
                _fetch_child(base_url, temp_root, descriptor["path"], descriptor["sha256"], files)
            if execution is not None:
                _fetch_child(base_url, temp_root, execution["path"], execution["sha256"], files)

            srl_bytes = _fetch_child(base_url, temp_root, srl["path"], srl["sha256"], files)
            srl_index = _json_bytes(srl_bytes, label="published SRL Definition Pack index")
            if str(srl_index.get("schema") or "") != str(srl.get("schema") or "omega.sigmascope.definition-packs.v1"):
                raise ResourceError("published SRL Definition Pack index schema mismatch")
            if str(srl_index.get("definitionPackRevision") or "") != str(srl.get("definitionPackRevision") or ""):
                raise ResourceError("published SRL Definition Pack revision mismatch")
            if str(srl_index.get("ruleSetRevision") or "") != str(srl.get("ruleSetRevision") or ""):
                raise ResourceError("published SRL rule-set revision mismatch")

            ruleset = srl_index.get("compiledRuleSet") if isinstance(srl_index.get("compiledRuleSet"), Mapping) else {}
            _fetch_child(base_url, temp_root, _safe_rel(ruleset.get("path")), str(ruleset.get("sha256") or ""), files)

            for pack in srl_index.get("packs") or []:
                if not isinstance(pack, Mapping):
                    raise ResourceError("published SRL pack entry is malformed")
                pack_id = str(pack.get("id") or "")
                if not pack_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for ch in pack_id):
                    raise ResourceError(f"unsafe published SRL pack id: {pack_id!r}")
                base = f"srl/packs/{pack_id}"
                manifest = pack.get("manifest") if isinstance(pack.get("manifest"), Mapping) else {}
                manifest_rel = _safe_rel(manifest.get("path") or "pack.yaml")
                _fetch_child(base_url, temp_root, f"{base}/{manifest_rel}", str(manifest.get("sha256") or ""), files)
                for item in [*(pack.get("rules") or []), *(pack.get("fixtures") or [])]:
                    if not isinstance(item, Mapping):
                        raise ResourceError(f"published SRL pack {pack_id} has a malformed file descriptor")
                    rel = _safe_rel(item.get("path"))
                    _fetch_child(base_url, temp_root, f"{base}/{rel}", str(item.get("sha256") or ""), files)

            parity = srl.get("migrationParity") if isinstance(srl.get("migrationParity"), Mapping) else {}
            if parity.get("path") and parity.get("sha256"):
                _fetch_child(base_url, temp_root, _safe_rel(parity.get("path")), str(parity.get("sha256") or ""), files)

            manifest = {
                "schema": RESOURCE_SCHEMA,
                "readOnly": True,
                "mutationAuthority": "none",
                "policyInput": False,
                "sourceAuthority": "published-frozen-definitions",
                "baseUrl": str(base_url).rstrip("/"),
                "cachedAtUtc": _utc_now(),
                "definitionsRevision": revision,
                "definitionPackRevision": str(srl.get("definitionPackRevision") or ""),
                "ruleSetRevision": str(srl.get("ruleSetRevision") or ""),
                "componentRegistryRevision": str(component.get("revision") or ""),
                "collectorRegistryRevision": str(collector.get("revision") or ""),
                "capabilityRegistryRevision": str(capability.get("revision") or ""),
                "executionTopologyRevision": str((execution or {}).get("revision") or ""),
                "executionTopologyPath": str((execution or {}).get("path") or ""),
                "srlIndexPath": str(srl["path"]),
                "registries": {
                    "components": str(component["path"]),
                    "collectors": str(collector["path"]),
                    "capabilities": str(capability["path"]),
                },
                "files": files,
                "fileCount": len(files),
                "downloadedWorkerCode": False,
            }
            (temp_root / "deltascope-resource-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            _load_manifest(temp_root)
            temp_root.replace(existing)
        except Exception:
            shutil.rmtree(temp_root, ignore_errors=True)
            raise

        _write_state(cache_root, revision)
        return PublishedResources(existing, _load_manifest(existing))
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ResourceError, ValueError, json.JSONDecodeError) as exc:
        if not allow_stale:
            raise ResourceError(str(exc)) from exc
        try:
            cached = load_cached(cache_root)
        except Exception:
            raise ResourceError(f"could not synchronize published DeltaScope resources and no verified cache is available: {exc}") from exc
        return PublishedResources(cached.root, cached.manifest, stale=True, warning=f"published resource refresh failed; using last verified snapshot: {exc}")
