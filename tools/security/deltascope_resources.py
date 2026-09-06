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
RESOURCE_BUNDLE_VERSION = 2
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


def project_security_telemetry(index: Mapping[str, Any]) -> dict[str, Any]:
    """Project the verified Definitions trust anchor into operator-facing telemetry."""
    def value(key: str) -> Mapping[str, Any]:
        candidate = index.get(key)
        return candidate if isinstance(candidate, Mapping) else {}

    source_counts = value("sourceObservations").get("counts")
    source_counts = source_counts if isinstance(source_counts, Mapping) else {}
    secondary_engines = value("secondarySecurity").get("engines")
    secondary_engines = secondary_engines if isinstance(secondary_engines, list) else []
    contracts = [
        {"id": "srl", "label": "SRL rules", "revision": str(value("srlDefinitionPacks").get("ruleSetRevision") or ""), "primaryCount": int(value("srlDefinitionPacks").get("totalRuleCount") or 0), "detail": f"{int(value('srlDefinitionPacks').get('packCount') or 0)} packs / {int(value('srlDefinitionPacks').get('activeRuleCount') or 0)} active / production {'enabled' if value('srlDefinitionPacks').get('productionRuleEvaluationEnabled') else 'gated'}"},
        {"id": "capabilities", "label": "Capabilities", "revision": str(value("capabilityRegistry").get("revision") or ""), "primaryCount": int(value("capabilityRegistry").get("capabilityCount") or 0), "detail": f"{int(value('capabilityRegistry').get('categoryCount') or 0)} categories"},
        {"id": "semantic-apis", "label": "Semantic APIs", "revision": str(value("semanticApiRegistry").get("revision") or ""), "primaryCount": int(value("semanticApiRegistry").get("sourceMatcherCount") or 0) + int(value("semanticApiRegistry").get("compiledMatcherCount") or 0), "detail": f"{int(value('semanticApiRegistry').get('sourceMatcherCount') or 0)} source / {int(value('semanticApiRegistry').get('compiledMatcherCount') or 0)} compiled matchers"},
        {"id": "semantic-flow", "label": "Semantic flow", "revision": str(value("semanticFlowRegistry").get("revision") or ""), "primaryCount": int(value("semanticFlowRegistry").get("sourceCount") or 0) + int(value("semanticFlowRegistry").get("sinkCount") or 0), "detail": f"{int(value('semanticFlowRegistry').get('sourceCount') or 0)} sources / {int(value('semanticFlowRegistry').get('sinkCount') or 0)} sinks / {int(value('semanticFlowRegistry').get('sanitizerCount') or 0)} sanitizers"},
        {"id": "services", "label": "Services", "revision": str(value("serviceRegistry").get("revision") or ""), "primaryCount": int(value("serviceRegistry").get("serviceCount") or 0), "detail": "verified service identities"},
        {"id": "reputation", "label": "Threat reputation", "revision": str(value("reputation").get("reputationRevision") or ""), "primaryCount": int(value("reputation").get("indicators") or 0), "detail": f"{int(value('reputation').get('activeFeeds') or 0)} active feeds / {int(value('reputation').get('matchedEndpointHosts') or 0)} matched hosts"},
        {"id": "osv", "label": "OSV advisories", "revision": str(index.get("advisoryRevision") or ""), "primaryCount": int(value("osv").get("matchedPackages") or 0), "detail": f"{int(value('osv').get('queriedPackages') or 0)} packages queried"},
        {"id": "source-observations", "label": "Source observations", "revision": str(value("sourceObservations").get("revision") or ""), "primaryCount": int(source_counts.get("observed") or 0), "detail": f"{int(source_counts.get('repositories') or 0)} repositories / {int(source_counts.get('failed') or 0)} failed"},
        {"id": "secondary-security", "label": "Secondary engines", "revision": str(value("secondarySecurity").get("revision") or ""), "primaryCount": len(secondary_engines), "detail": " / ".join(str(engine.get("engine") or "") for engine in secondary_engines if isinstance(engine, Mapping))},
        {"id": "components", "label": "Components", "revision": str(value("componentRegistry").get("revision") or ""), "primaryCount": int(value("componentRegistry").get("componentCount") or 0), "detail": f"{int(value('componentRegistry').get('launchableCount') or 0)} launchable"},
        {"id": "collectors", "label": "Collectors", "revision": str(value("collectorRegistry").get("revision") or ""), "primaryCount": int(value("collectorRegistry").get("collectorCount") or 0), "detail": f"{int(value('collectorRegistry').get('observationTypeCount') or 0)} observation types"},
    ]
    return {
        "schema": "omega.deltascope.security-telemetry.v1",
        "generatedAtUtc": str(index.get("generatedAtUtc") or ""),
        "scanner": {
            "version": str(index.get("scannerVersion") or ""),
            "revision": str(index.get("scannerRevision") or ""),
            "artifactAnalysisRevision": str(index.get("artifactAnalysisRevision") or ""),
            "sourceAnalysisRevision": str(index.get("sourceAnalysisRevision") or ""),
            "sourceObservationRevision": str(index.get("sourceObservationRevision") or ""),
        },
        "contracts": contracts,
        "secondaryEngines": [dict(engine) for engine in secondary_engines if isinstance(engine, Mapping)],
        "sourceObservationCounts": dict(source_counts),
    }

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
    return cache_root / "snapshots" / f"{revision}-bundle-v{RESOURCE_BUNDLE_VERSION}"


def _write_state(cache_root: Path, revision: str, snapshot_name: str = "") -> None:
    state = {
        "schema": STATE_SCHEMA,
        "definitionsRevision": revision,
        "snapshotName": snapshot_name or _snapshot_root(cache_root, revision).name,
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

    def available_snapshots(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        snapshots = self.root.parent
        if snapshots.is_dir():
            for candidate in snapshots.iterdir():
                if not candidate.is_dir() or candidate.name.startswith("."):
                    continue
                try:
                    manifest = _load_manifest(candidate)
                except ResourceError:
                    continue
                rows.append({
                    "definitionsRevision": str(manifest.get("definitionsRevision") or ""),
                    "definitionPackRevision": str(manifest.get("definitionPackRevision") or ""),
                    "ruleSetRevision": str(manifest.get("ruleSetRevision") or ""),
                    "cachedAtUtc": str(manifest.get("cachedAtUtc") or ""),
                    "snapshotName": candidate.name,
                    "current": candidate == self.root,
                    "fileCount": int(manifest.get("fileCount") or 0),
                    "consumerBundleVersion": int(manifest.get("consumerBundleVersion") or 1),
                })
        return sorted(rows, key=lambda row: (str(row["cachedAtUtc"]), str(row["snapshotName"])), reverse=True)

    def select_snapshot(self, revision: str = "") -> "PublishedResources":
        requested = str(revision or "").strip()
        if not requested or requested == str(self.manifest.get("definitionsRevision") or ""):
            return self
        matches = [
            row for row in self.available_snapshots()
            if row["definitionsRevision"] == requested or row["snapshotName"] == requested
        ]
        if not matches:
            raise ResourceError(f"verified Definitions snapshot is not cached: {requested}")
        root = self.root.parent / _safe_rel(matches[0]["snapshotName"])
        return PublishedResources(root, _load_manifest(root), stale=root != self.root)

    def _file_descriptor(self, relative: str) -> dict[str, Any]:
        relative = _safe_rel(relative)
        for item in self.manifest.get("files") or []:
            if isinstance(item, Mapping) and str(item.get("path") or "") == relative:
                return dict(item)
        raise ResourceError(f"resource is not allowlisted by the verified snapshot manifest: {relative}")

    def read_contract_resource(self, relative: str) -> dict[str, Any]:
        descriptor = self._file_descriptor(relative)
        path = self.root / _safe_rel(relative)
        data = path.read_bytes()
        expected = str(descriptor.get("sha256") or "").lower()
        if len(data) != int(descriptor.get("bytes") or -1) or _sha256_bytes(data) != expected:
            raise ResourceError(f"cached DeltaScope resource failed verification: {relative}")
        if len(data) > MAX_RESOURCE_BYTES:
            raise ResourceError(f"cached DeltaScope resource exceeded {MAX_RESOURCE_BYTES:,} bytes")
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ResourceError(f"cached DeltaScope resource is not UTF-8 text: {relative}") from exc
        parsed: Any = None
        if relative.casefold().endswith(".json"):
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = None
        return {
            "schema": "omega.deltascope.contract-resource.v1",
            "definitionsRevision": str(self.manifest.get("definitionsRevision") or ""),
            "path": relative, "sha256": expected, "bytes": len(data),
            "content": content, "parsed": parsed, "verified": True, "readOnly": True,
        }

    def contract_inventory(self) -> dict[str, Any]:
        descriptors = {
            str(item.get("path") or ""): dict(item)
            for item in self.manifest.get("files") or [] if isinstance(item, Mapping)
        }

        def resource(path: object, label: str, kind: str, metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
            relative = _safe_rel(path)
            pinned = descriptors.get(relative, {})
            return {
                "label": label, "kind": kind, "path": relative,
                "sha256": str(pinned.get("sha256") or ""), "bytes": int(pinned.get("bytes") or 0),
                "metadata": dict(metadata or {}),
            }

        groups: list[dict[str, Any]] = [{
            "id": "definitions", "label": "Definitions trust anchor", "kind": "trust-anchor",
            "resources": [resource("index.json", "Definitions index", "trust-anchor")],
        }]
        srl = self.srl_index
        srl_resources = [resource(self.manifest.get("srlIndexPath") or "srl/index.json", "Definition pack index", "index")]
        compiled = srl.get("compiledRuleSet") if isinstance(srl.get("compiledRuleSet"), Mapping) else {}
        if compiled.get("path"):
            srl_resources.append(resource(compiled["path"], "Compiled SRL ruleset", "ruleset", compiled))
        packs: list[dict[str, Any]] = []
        for pack in srl.get("packs") or []:
            if not isinstance(pack, Mapping):
                continue
            pack_id = str(pack.get("id") or "")
            base = f"srl/packs/{pack_id}"
            manifest = pack.get("manifest") if isinstance(pack.get("manifest"), Mapping) else {}
            pack_resources = [resource(f"{base}/{_safe_rel(manifest.get('path') or 'pack.yaml')}", "Pack manifest", "pack-manifest", manifest)]
            for item in pack.get("rules") or []:
                if isinstance(item, Mapping):
                    ids = item.get("ruleIds") if isinstance(item.get("ruleIds"), list) else []
                    label = ", ".join(str(value) for value in ids) or str(item.get("path") or "Rule")
                    pack_resources.append(resource(f"{base}/{_safe_rel(item.get('path'))}", label, "rule", item))
            for item in pack.get("fixtures") or []:
                if isinstance(item, Mapping):
                    pack_resources.append(resource(f"{base}/{_safe_rel(item.get('path'))}", str(item.get("name") or item.get("path") or "Fixture"), "fixture", item))
            packs.append({
                "id": pack_id, "label": str(pack.get("title") or pack_id), "kind": "definition-pack",
                "metadata": {key: pack.get(key) for key in ("trustTier", "productionEligible", "packRevision", "compiledRuleSetRevision") if key in pack},
                "resources": pack_resources,
            })
        groups.append({"id": "srl", "label": "SRL definitions and rulesets", "kind": "rules", "resources": srl_resources, "children": packs})

        index = self.definitions_index
        contract_specs = [
            ("capabilities", "Capabilities", "capabilityRegistry"), ("components", "Components", "componentRegistry"),
            ("collectors", "Collectors", "collectorRegistry"), ("execution-topology", "Execution topology", "executionTopology"),
            ("semantic-apis", "Semantic APIs", "semanticApiRegistry"), ("semantic-flow", "Semantic flow", "semanticFlowRegistry"),
            ("services", "Services", "serviceRegistry"), ("reputation", "Threat reputation", "reputation"),
            ("osv", "OSV advisories", "osv"), ("source-observations", "Source observations", "sourceObservations"),
            ("secondary-security", "Secondary engines", "secondarySecurity"),
        ]
        for group_id, label, key in contract_specs:
            descriptor = index.get(key)
            if isinstance(descriptor, Mapping) and descriptor.get("path") and str(descriptor.get("path")) in descriptors:
                groups.append({"id": group_id, "label": label, "kind": "contract", "resources": [resource(descriptor["path"], label, key, descriptor)]})
        return {
            "schema": "omega.deltascope.contract-inventory.v1", "readOnly": True, "verified": True,
            "mutationAuthority": "none", "definitionsRevision": str(self.manifest.get("definitionsRevision") or ""),
            "snapshots": self.available_snapshots(), "groups": groups,
        }

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
            "securityTelemetry": project_security_telemetry(self.definitions_index),
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
    snapshot_name = str(state.get("snapshotName") or "")
    root = cache_root / "snapshots" / _safe_rel(snapshot_name) if snapshot_name else _snapshot_root(cache_root, revision)
    if not root.is_dir():
        candidates = []
        snapshots = cache_root / "snapshots"
        for candidate in snapshots.iterdir() if snapshots.is_dir() else []:
            if not candidate.is_dir():
                continue
            try:
                candidate_manifest = _load_manifest(candidate)
            except ResourceError:
                continue
            if str(candidate_manifest.get("definitionsRevision") or "") == revision:
                candidates.append((int(candidate_manifest.get("consumerBundleVersion") or 1), candidate))
        if candidates:
            root = sorted(candidates, key=lambda item: item[0], reverse=True)[0][1]
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
            _write_state(cache_root, revision, existing.name)
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
            inspectable = {
                key: descriptor for key in (
                    "semanticApiRegistry", "semanticFlowRegistry", "serviceRegistry", "reputation",
                    "osv", "sourceObservations", "secondarySecurity",
                ) if (descriptor := _optional_descriptor(index, key)) is not None
            }
            srl = _descriptor(index, "srlDefinitionPacks")
            for descriptor in (capability, component, collector):
                _fetch_child(base_url, temp_root, descriptor["path"], descriptor["sha256"], files)
            if execution is not None:
                _fetch_child(base_url, temp_root, execution["path"], execution["sha256"], files)
            for descriptor in inspectable.values():
                _fetch_child(base_url, temp_root, descriptor["path"], descriptor["sha256"], files)

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
                "consumerBundleVersion": RESOURCE_BUNDLE_VERSION,
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
                "inspectableContracts": {key: str(value["path"]) for key, value in inspectable.items()},
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

        _write_state(cache_root, revision, existing.name)
        return PublishedResources(existing, _load_manifest(existing))
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ResourceError, ValueError, json.JSONDecodeError) as exc:
        if not allow_stale:
            raise ResourceError(str(exc)) from exc
        try:
            cached = load_cached(cache_root)
        except Exception:
            raise ResourceError(f"could not synchronize published DeltaScope resources and no verified cache is available: {exc}") from exc
        return PublishedResources(cached.root, cached.manifest, stale=True, warning=f"published resource refresh failed; using last verified snapshot: {exc}")
