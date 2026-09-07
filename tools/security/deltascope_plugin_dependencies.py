"""DeltaScope consumer for the published Omega plugin dependency graph.

This module deliberately does not infer package requirements from IPC, assembly
references, NuGet/component observations, or source code. The only package-level
Requires / Required-by relationships come from the published
``omega.plugin-dependency-graph.v1`` projection.

The graph is catalog/package-resolution context, not Security Evidence authority and not
an installation control plane. DeltaScope remains read-only.
"""
from __future__ import annotations

import json
from typing import Any, Mapping
import urllib.parse

GRAPH_SCHEMA = "omega.plugin-dependency-graph.v1"
GRAPH_AUTHORITY = "catalog-package-resolution-projection"
CONTEXT_SCHEMA = "omega.deltascope.plugin-dependency-context.v1"
PROVIDER_IDENTITY = "stable-plugin-id"
CONSUMER_IDENTITY = "catalog-variant"
RECOVERY_SCHEMA = "omega.sigmascope-evidence-recovery.v1"
DELTASCOPE_VERSION = "4.21.15"
PACKAGE_RELATIONSHIPS = ("required", "recommended", "optional")
ALL_RELATIONSHIPS = frozenset((*PACKAGE_RELATIONSHIPS, "observed"))
MAX_INTEGRATIONS = 100
MAX_COMPONENTS = 200


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _root_descriptor(inspector: Any) -> dict[str, Any]:
    root = inspector.root if isinstance(getattr(inspector, "root", None), Mapping) else {}
    indexes = root.get("indexes") if isinstance(root.get("indexes"), Mapping) else {}
    value = indexes.get("pluginDependencies")
    return dict(value) if isinstance(value, Mapping) else {}


def _cache_key(inspector: Any, descriptor: Mapping[str, Any]) -> tuple[str, str, str]:
    root = inspector.root if isinstance(getattr(inspector, "root", None), Mapping) else {}
    revisions = root.get("revisions") if isinstance(root.get("revisions"), Mapping) else {}
    return (
        str(revisions.get("evidenceRevision") or ""),
        str(revisions.get("dependencyGraphRevision") or ""),
        str(descriptor.get("sha256") or ""),
    )


def _validate_edge(row: Mapping[str, Any]) -> dict[str, Any]:
    edge = dict(row)
    consumer_variant = _int(edge.get("consumerVariantId"))
    consumer_plugin = _int(edge.get("consumerPluginId"))
    provider_plugin = _int(edge.get("providerPluginId"))
    provider_name = str(edge.get("providerInternalName") or "").strip()
    relationship = str(edge.get("relationship") or "").strip().casefold()
    if consumer_variant <= 0:
        raise ValueError("plugin dependency edge has invalid consumerVariantId")
    if consumer_plugin < 0 or provider_plugin < 0:
        raise ValueError("plugin dependency edge has invalid stable plugin identity")
    if not provider_name:
        raise ValueError("plugin dependency edge has no providerInternalName")
    if relationship not in ALL_RELATIONSHIPS:
        raise ValueError(f"plugin dependency edge has unsupported relationship {relationship!r}")
    if bool(edge.get("installEligible")) and (
        provider_plugin <= 0 or relationship not in PACKAGE_RELATIONSHIPS
    ):
        raise ValueError("plugin dependency edge has impossible installEligible state")
    origins = edge.get("origins")
    if origins is not None and not isinstance(origins, list):
        raise ValueError("plugin dependency edge origins must be a list")
    edge["consumerVariantId"] = consumer_variant
    edge["consumerPluginId"] = consumer_plugin
    edge["providerPluginId"] = provider_plugin
    edge["providerInternalName"] = provider_name
    edge["relationship"] = relationship
    edge["installEligible"] = bool(edge.get("installEligible"))
    return edge


def _validate_provider(row: Mapping[str, Any]) -> dict[str, Any]:
    provider = dict(row)
    plugin_id = _int(provider.get("providerPluginId"))
    internal = str(provider.get("providerInternalName") or "").strip()
    if plugin_id <= 0 or not internal:
        raise ValueError("plugin dependency provider has invalid stable identity")
    for key in (
        "requiredByCount", "recommendedByCount", "optionalByCount", "totalDependentPlugins"
    ):
        if _int(provider.get(key)) < 0:
            raise ValueError(f"plugin dependency provider has invalid {key}")
        provider[key] = _int(provider.get(key))
    provider["providerPluginId"] = plugin_id
    provider["providerInternalName"] = internal
    if provider.get("requiredBy") is not None and not isinstance(provider.get("requiredBy"), list):
        raise ValueError("plugin dependency provider requiredBy must be a list")
    return provider


def load_plugin_dependency_graph(inspector: Any) -> dict[str, Any]:
    """Load and fail-closed validate the optional published plugin dependency index."""
    descriptor = _root_descriptor(inspector)
    root = inspector.root if isinstance(getattr(inspector, "root", None), Mapping) else {}
    root_counts = root.get("counts") if isinstance(root.get("counts"), Mapping) else {}
    root_revisions = root.get("revisions") if isinstance(root.get("revisions"), Mapping) else {}

    if not str(descriptor.get("path") or ""):
        if _int(root_counts.get("pluginDependencyEdges")) or _int(root_counts.get("pluginDependencyProviders")):
            raise ValueError("Evidence root publishes plugin dependency counts without indexes.pluginDependencies")
        return {
            "available": False,
            "schema": GRAPH_SCHEMA,
            "authority": GRAPH_AUTHORITY,
            "dependencyGraphRevision": str(root_revisions.get("dependencyGraphRevision") or ""),
            "semantics": {"ipcIsPackageDependency": False},
            "counts": {"edges": 0, "providers": 0},
            "edges": [],
            "providers": [],
        }

    key = _cache_key(inspector, descriptor)
    cached = getattr(inspector, "_deltascope_plugin_dependency_graph_cache", None)
    if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == key:
        return cached[1]

    if not hasattr(inspector, "_index_payload"):
        raise ValueError("DeltaScope inspector cannot load indexes.pluginDependencies")
    payload = inspector._index_payload("pluginDependencies")
    if not isinstance(payload, Mapping):
        raise ValueError("plugin dependency graph is not a JSON object")
    if str(payload.get("schema") or "") != GRAPH_SCHEMA:
        raise ValueError("unsupported plugin dependency graph schema")
    if str(payload.get("authority") or "") != GRAPH_AUTHORITY:
        raise ValueError("plugin dependency graph has unexpected authority")

    revision = str(payload.get("dependencyGraphRevision") or "").strip()
    root_revision = str(root_revisions.get("dependencyGraphRevision") or "").strip()
    if not revision or not root_revision or revision != root_revision:
        raise ValueError("plugin dependency graph revision does not match Evidence root")
    descriptor_revision = str(descriptor.get("dependencyGraphRevision") or "").strip()
    if descriptor_revision and descriptor_revision != revision:
        raise ValueError("plugin dependency graph descriptor revision mismatch")

    semantics = payload.get("semantics") if isinstance(payload.get("semantics"), Mapping) else {}
    if semantics.get("ipcIsPackageDependency") is not False:
        raise ValueError("plugin dependency graph must declare ipcIsPackageDependency=false")
    if str(semantics.get("providerIdentity") or "") != PROVIDER_IDENTITY:
        raise ValueError("plugin dependency graph provider identity is not stable-plugin-id")
    if str(semantics.get("consumerIdentity") or "") != CONSUMER_IDENTITY:
        raise ValueError("plugin dependency graph consumer identity is not catalog-variant")
    if semantics.get("securityEvidenceIsObservationOnly") is not True:
        raise ValueError("plugin dependency graph must keep Security Evidence observation-only")

    raw_edges = payload.get("edges") if isinstance(payload.get("edges"), list) else None
    raw_providers = payload.get("providers") if isinstance(payload.get("providers"), list) else None
    if raw_edges is None or raw_providers is None:
        raise ValueError("plugin dependency graph edges/providers must be arrays")
    edges = [_validate_edge(row) for row in raw_edges if isinstance(row, Mapping)]
    providers = [_validate_provider(row) for row in raw_providers if isinstance(row, Mapping)]
    if len(edges) != len(raw_edges) or len(providers) != len(raw_providers):
        raise ValueError("plugin dependency graph contains non-object rows")

    edge_keys: set[tuple[Any, ...]] = set()
    for edge in edges:
        edge_key = (
            edge["consumerVariantId"],
            edge["providerInternalName"].casefold(),
            edge["relationship"],
            str(edge.get("versionConstraint") or ""),
        )
        if edge_key in edge_keys:
            raise ValueError("plugin dependency graph contains duplicate normalized edges")
        edge_keys.add(edge_key)
    provider_keys: set[str] = set()
    for provider in providers:
        provider_key = provider["providerInternalName"].casefold()
        if provider_key in provider_keys:
            raise ValueError("plugin dependency graph contains duplicate providers")
        provider_keys.add(provider_key)

    counts = payload.get("counts") if isinstance(payload.get("counts"), Mapping) else {}
    if _int(counts.get("edges")) != len(edges) or _int(counts.get("providers")) != len(providers):
        raise ValueError("plugin dependency graph payload count mismatch")
    if "records" in descriptor and _int(descriptor.get("records")) != len(edges):
        raise ValueError("plugin dependency graph descriptor record count mismatch")
    if "pluginDependencyEdges" in root_counts and _int(root_counts.get("pluginDependencyEdges")) != len(edges):
        raise ValueError("Evidence root pluginDependencyEdges count mismatch")
    if "pluginDependencyProviders" in root_counts and _int(root_counts.get("pluginDependencyProviders")) != len(providers):
        raise ValueError("Evidence root pluginDependencyProviders count mismatch")

    graph = {
        "available": True,
        "schema": GRAPH_SCHEMA,
        "authority": GRAPH_AUTHORITY,
        "dependencyGraphRevision": revision,
        "semantics": dict(semantics),
        "counts": dict(counts),
        "edges": edges,
        "providers": providers,
    }
    inspector._deltascope_plugin_dependency_graph_cache = (key, graph)
    return graph


def _current_variant_targets(inspector: Any, plugin_id: int) -> list[dict[str, Any]]:
    if plugin_id <= 0:
        return []
    targets: list[dict[str, Any]] = []
    entries = getattr(inspector, "entries", {})
    if not isinstance(entries, Mapping):
        return []
    for raw_variant_id in sorted(entries):
        variant_id = _int(raw_variant_id)
        if variant_id <= 0:
            continue
        try:
            identity = inspector._entry_identity(variant_id, require_current=False)
        except Exception:
            continue
        if _int(identity.get("plugin_id") or identity.get("pluginId")) != plugin_id:
            continue
        targets.append({
            "variantId": variant_id,
            "pluginId": plugin_id,
            "internalName": str(identity.get("internal_name") or identity.get("internalName") or ""),
            "name": str(identity.get("canonical_name") or identity.get("name") or ""),
            "version": str(identity.get("assembly_version") or identity.get("version") or ""),
            "sourceName": str(identity.get("source_name") or identity.get("sourceName") or ""),
        })
    return targets


def _edge_view(inspector: Any, edge: Mapping[str, Any], *, reverse: bool = False) -> dict[str, Any]:
    row = dict(edge)
    if reverse:
        target_variant_ids = [_int(edge.get("consumerVariantId"))]
        preferred = target_variant_ids[0] if target_variant_ids[0] > 0 else 0
    else:
        targets = _current_variant_targets(inspector, _int(edge.get("providerPluginId")))
        target_variant_ids = [item["variantId"] for item in targets]
        preferred = target_variant_ids[0] if target_variant_ids else 0
        row["providerVariants"] = targets
    row["targetVariantIds"] = target_variant_ids
    row["preferredVariantId"] = preferred
    return row


def _component_rows(inspector: Any, variant_id: int) -> tuple[bool, list[dict[str, Any]], str]:
    if not hasattr(inspector, "workbench_relationship_index"):
        return False, [], "Published component relationship index is unavailable."
    try:
        relationships = inspector.workbench_relationship_index()
    except Exception as exc:
        return False, [], str(exc)
    rows: list[dict[str, Any]] = []
    for raw in relationships.get("components") or [] if isinstance(relationships, Mapping) else []:
        if not isinstance(raw, Mapping):
            continue
        usage = [
            dict(item) for item in raw.get("usage") or []
            if isinstance(item, Mapping) and _int(item.get("variantId")) == variant_id
        ]
        if not usage:
            continue
        row = {key: value for key, value in raw.items() if key != "usage"}
        row["usage"] = usage
        rows.append(row)
        if len(rows) >= MAX_COMPONENTS:
            break
    return True, rows, ""


def _ipc_rows(inspector: Any, variant_id: int) -> tuple[bool, list[dict[str, Any]], str]:
    if not hasattr(inspector, "plugin_dataset"):
        return False, [], "Immutable IPC dataset is unavailable."
    try:
        rows = inspector.plugin_dataset(variant_id, "ipc")
    except ValueError as exc:
        if "unknown Evidence v2 plugin dataset" in str(exc):
            return True, [], ""
        return False, [], str(exc)
    except Exception as exc:
        return False, [], str(exc)
    return True, [dict(row) for row in rows[:MAX_INTEGRATIONS] if isinstance(row, Mapping)], ""


def project_plugin_dependency_context(inspector: Any, variant_id: int) -> dict[str, Any]:
    """Project package dependencies, reverse consumers, IPC, and components without conflating them."""
    variant_id = _int(variant_id)
    if variant_id <= 0:
        raise ValueError("variant_id is required")
    graph = load_plugin_dependency_graph(inspector)

    identity: dict[str, Any] = {}
    if hasattr(inspector, "_entry_identity"):
        try:
            identity = dict(inspector._entry_identity(variant_id, require_current=False))
        except Exception:
            identity = {}
    plugin_id = _int(identity.get("plugin_id") or identity.get("pluginId"))

    grouped_requires = {name: [] for name in PACKAGE_RELATIONSHIPS}
    observed: list[dict[str, Any]] = []
    grouped_reverse = {name: [] for name in PACKAGE_RELATIONSHIPS}
    if graph["available"]:
        for edge in graph["edges"]:
            if _int(edge.get("consumerVariantId")) == variant_id:
                relationship = str(edge.get("relationship") or "")
                if relationship in grouped_requires:
                    grouped_requires[relationship].append(_edge_view(inspector, edge))
                else:
                    observed.append(_edge_view(inspector, edge))
            if plugin_id > 0 and _int(edge.get("providerPluginId")) == plugin_id:
                relationship = str(edge.get("relationship") or "")
                if relationship in grouped_reverse:
                    grouped_reverse[relationship].append(_edge_view(inspector, edge, reverse=True))

    sort_key = lambda row: (
        str(row.get("providerInternalName") or row.get("consumerInternalName") or "").casefold(),
        _int(row.get("consumerVariantId")),
        str(row.get("versionConstraint") or ""),
    )
    for rows in (*grouped_requires.values(), *grouped_reverse.values()):
        rows.sort(key=sort_key)
    observed.sort(key=sort_key)

    ipc_available, integrations, ipc_error = _ipc_rows(inspector, variant_id)
    components_available, components, component_error = _component_rows(inspector, variant_id)
    global_empty = bool(graph["available"] and _int(graph["counts"].get("edges")) == 0)
    selected_empty = not any(grouped_requires.values()) and not any(grouped_reverse.values()) and not observed

    if not graph["available"]:
        message = "Normalized plugin dependency graph is not published in this Evidence snapshot."
    elif global_empty:
        message = "No normalized plugin dependency relationships are currently published."
    elif selected_empty:
        message = "No normalized plugin dependency relationships are currently published for this plugin."
    else:
        message = "Normalized package relationships are published separately from IPC integrations and component observations."

    provider_record = next(
        (
            dict(row) for row in graph["providers"]
            if plugin_id > 0 and _int(row.get("providerPluginId")) == plugin_id
        ),
        {},
    )

    return {
        "schema": CONTEXT_SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "installAuthority": False,
        "packageManagementAuthority": False,
        "variantId": variant_id,
        "pluginId": plugin_id,
        "identity": identity,
        "graph": {
            "available": bool(graph["available"]),
            "schema": graph["schema"],
            "authority": graph["authority"],
            "dependencyGraphRevision": graph["dependencyGraphRevision"],
            "counts": dict(graph["counts"]),
            "semantics": dict(graph["semantics"]),
            "globallyEmpty": global_empty,
        },
        "requires": {
            "required": grouped_requires["required"],
            "recommended": grouped_requires["recommended"],
            "optional": grouped_requires["optional"],
            "observedPackageRelationships": observed,
        },
        "requiredBy": {
            "required": grouped_reverse["required"],
            "recommended": grouped_reverse["recommended"],
            "optional": grouped_reverse["optional"],
            "providerRecord": provider_record,
        },
        "integrations": {
            "kind": "ipc",
            "available": ipc_available,
            "ipcIsPackageDependency": False,
            "rows": integrations,
            "error": ipc_error,
            "truncated": len(integrations) >= MAX_INTEGRATIONS,
        },
        "components": {
            "available": components_available,
            "rows": components,
            "error": component_error,
            "truncated": len(components) >= MAX_COMPONENTS,
        },
        "message": message,
        "semanticBoundary": {
            "requiresAuthority": GRAPH_AUTHORITY,
            "providerIdentity": PROVIDER_IDENTITY,
            "consumerIdentity": CONSUMER_IDENTITY,
            "ipcIsPackageDependency": False,
            "ipcMayAppearOnlyAsIntegrationWithoutDependencyEdge": True,
            "componentObservationIsNotPluginRequirement": True,
            "omegaOwnsPackageManagement": True,
            "deltaScopeOwnsInvestigationOnly": True,
        },
    }


def _install_inspector_extensions(cls: Any) -> None:
    if getattr(cls, "_deltascope_plugin_dependencies_installed", False):
        return
    original_catalog = cls.table_catalog
    original_special = cls._special_table_rows
    original_summary = getattr(cls, "summary", None)
    original_system_context = getattr(cls, "workbench_system_context", None)

    def table_catalog(self: Any) -> list[dict[str, Any]]:
        rows = list(original_catalog(self))
        names = {str(row.get("name") or "") for row in rows}
        additions = [
            {
                "name": "v2_plugin_dependencies",
                "label": "Plugin dependency edges",
                "category": "Global evidence",
                "columnCount": 1,
            },
            {
                "name": "v2_plugin_dependency_providers",
                "label": "Plugin dependency providers",
                "category": "Global evidence",
                "columnCount": 1,
            },
        ]
        rows.extend(row for row in additions if row["name"] not in names)
        return rows

    def special_rows(self: Any, name: str) -> list[dict[str, Any]]:
        if name in {"v2_plugin_dependencies", "v2_plugin_dependency_providers"}:
            graph = load_plugin_dependency_graph(self)
            if not graph["available"]:
                return []
            key = "edges" if name == "v2_plugin_dependencies" else "providers"
            return [dict(row) for row in graph[key]]
        return original_special(self, name)

    cls.plugin_dependency_graph = load_plugin_dependency_graph
    cls.plugin_dependency_context = project_plugin_dependency_context
    cls.table_catalog = table_catalog
    cls._special_table_rows = special_rows

    if callable(original_summary):
        def summary(self: Any) -> dict[str, Any]:
            result = dict(original_summary(self))
            counts = dict(result.get("counts") or {}) if isinstance(result.get("counts"), Mapping) else {}
            root = self.root if isinstance(getattr(self, "root", None), Mapping) else {}
            root_counts = root.get("counts") if isinstance(root.get("counts"), Mapping) else {}
            revisions = root.get("revisions") if isinstance(root.get("revisions"), Mapping) else {}
            descriptor = _root_descriptor(self)
            counts["pluginDependencyEdges"] = _int(root_counts.get("pluginDependencyEdges"))
            counts["pluginDependencyProviders"] = _int(root_counts.get("pluginDependencyProviders"))
            result["counts"] = counts
            result["pluginDependencyGraph"] = {
                "available": bool(descriptor.get("path")),
                "dependencyGraphRevision": str(revisions.get("dependencyGraphRevision") or ""),
                "edges": counts["pluginDependencyEdges"],
                "providers": counts["pluginDependencyProviders"],
            }
            return result
        cls.summary = summary

    if callable(original_system_context):
        def workbench_system_context(self: Any) -> dict[str, Any]:
            result = dict(original_system_context(self))
            root = self.root if isinstance(getattr(self, "root", None), Mapping) else {}
            revisions = root.get("revisions") if isinstance(root.get("revisions"), Mapping) else {}
            source = root.get("source") if isinstance(root.get("source"), Mapping) else {}
            scan = source.get("scan") if isinstance(source.get("scan"), Mapping) else {}
            recovery = scan.get("recovery") if isinstance(scan.get("recovery"), Mapping) else {}
            descriptor = _root_descriptor(self)
            result["pluginDependencyGraph"] = {
                "available": bool(descriptor.get("path")),
                "dependencyGraphRevision": str(revisions.get("dependencyGraphRevision") or ""),
                "path": str(descriptor.get("path") or ""),
                "records": _int(descriptor.get("records")),
            }
            result["evidenceRecovery"] = dict(recovery)
            return result
        cls.workbench_system_context = workbench_system_context

    cls._deltascope_plugin_dependencies_installed = True


def project_evidence_recovery(system_context: Mapping[str, Any] | None) -> dict[str, Any]:
    """Turn published recovery provenance into an informational System/Operations notice."""
    context = system_context if isinstance(system_context, Mapping) else {}
    raw = context.get("evidenceRecovery") if isinstance(context.get("evidenceRecovery"), Mapping) else {}
    if not raw:
        return {
            "available": False,
            "securityEvent": False,
            "authorityRepair": False,
        }
    schema = str(raw.get("schema") or "")
    mode = str(raw.get("mode") or "")
    new_scans = _int(raw.get("newScans"))
    if mode == "forward-retained-current-wins":
        headline = "Evidence authority repaired from retained full-tree history"
        if new_scans == 0:
            detail = "Current data won where newer. 0 new scans were performed during recovery."
        else:
            detail = f"Current data won where newer. {new_scans} new scan(s) were performed during recovery."
    else:
        headline = "Evidence recovery publication is active"
        detail = f"Published recovery mode: {mode or 'unspecified'}."
    return {
        "available": True,
        "schema": schema,
        "recognizedSchema": schema == RECOVERY_SCHEMA,
        "mode": mode,
        "newScans": new_scans,
        "retainedEvidenceRevision": str(raw.get("retainedEvidenceRevision") or ""),
        "retainedIndexSha256": str(raw.get("retainedIndexSha256") or ""),
        "headline": headline,
        "detail": detail,
        "securityEvent": False,
        "authorityRepair": mode == "forward-retained-current-wins",
        "readOnly": True,
        "mutationAuthority": "none",
    }


def _install_workbench_extensions(module: Any) -> None:
    if getattr(module, "_deltascope_42115_plugin_dependency_system_installed", False):
        return
    original = module.project_system_status

    def project_system_status(
        system_context: Mapping[str, Any] | None,
        provenance: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        result = dict(original(system_context, provenance))
        context = system_context if isinstance(system_context, Mapping) else {}
        evidence = context.get("evidence") if isinstance(context.get("evidence"), Mapping) else {}
        revisions = evidence.get("revisions") if isinstance(evidence.get("revisions"), Mapping) else {}
        projected_revisions = dict(result.get("revisions") or {}) if isinstance(result.get("revisions"), Mapping) else {}
        projected_revisions["dependencyGraphRevision"] = str(revisions.get("dependencyGraphRevision") or "")
        result["revisions"] = projected_revisions
        graph = context.get("pluginDependencyGraph") if isinstance(context.get("pluginDependencyGraph"), Mapping) else {}
        result["pluginDependencyGraph"] = dict(graph)
        recovery = project_evidence_recovery(context)
        result["evidenceRecovery"] = recovery
        result["compatibilityVersion"] = DELTASCOPE_VERSION

        checks = [dict(row) for row in result.get("checks") or [] if isinstance(row, Mapping)]
        checks.append({
            "code": "dependency.graph",
            "label": "Plugin dependency graph",
            "status": "pass" if graph.get("available") else "warn",
            "detail": str(
                projected_revisions.get("dependencyGraphRevision")
                or "not published in this Evidence snapshot"
            ),
        })
        result["checks"] = checks

        # The original System projection revision predates this compatibility contract.
        # Recompute it over the augmented deterministic payload so graph/recovery changes
        # cannot leave the System projection ID unchanged.
        stable_core = {
            key: value for key, value in result.items()
            if key not in {
                "schema", "projectionRevision", "readOnly", "mutationAuthority",
                "authoritativeChangeBoundary",
            }
        }
        if hasattr(module, "_stable_id"):
            result["projectionRevision"] = module._stable_id("system", stable_core)
        return result

    module.project_system_status = project_system_status
    module._deltascope_42115_plugin_dependency_system_installed = True


_DEPENDENCY_CSS = r"""
.plugin-dependency-shell{margin-top:14px;border-top:1px solid #d9dde2;padding-top:14px}.plugin-dependency-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.plugin-dependency-head h4{margin:0 0 5px}.plugin-dependency-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:10px}.plugin-dependency-box{border:1px solid #d9dde2;background:#fff;padding:12px}.plugin-dependency-box h5{margin:0 0 8px;font-size:13px}.plugin-dependency-group{margin-top:9px}.plugin-dependency-group:first-child{margin-top:0}.plugin-dependency-group-title{font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#525252;margin-bottom:5px}.plugin-dependency-row{padding:7px 0;border-top:1px solid #e8e8e8}.plugin-dependency-row:first-child{border-top:0}.plugin-dependency-row b{display:block}.plugin-dependency-meta{font-size:10px;color:#525252}.plugin-dependency-boundary{margin-top:10px;border-left:4px solid #0f62fe;background:#edf5ff;padding:10px}.plugin-dependency-empty{padding:10px;background:#f4f4f4;color:#525252}.plugin-dependency-raw{margin-top:10px}.evidence-recovery-banner{margin:10px 0;padding:11px 12px;border-left:4px solid #24a148;background:#defbe6}.evidence-recovery-banner b{display:block;margin-bottom:4px}.evidence-recovery-banner code{overflow-wrap:anywhere}@media(max-width:900px){.plugin-dependency-grid{grid-template-columns:1fr}}
"""

_DEPENDENCY_JS = r"""
setTimeout(function(){
 if(window.__deltascopePluginDependenciesInstalled)return;window.__deltascopePluginDependenciesInstalled=true;
 var style=document.createElement('style');style.textContent=__DEPENDENCY_CSS__;document.head.appendChild(style);
 var baseLoad=window.loadAssetRelationships,baseRelationshipCatalog=window.renderRelationshipCatalog,baseSystemStatus=window.renderSystemStatus,baseOperationalSystem=window.renderOperationalSystemPages;
 if(typeof baseLoad!=='function')return;
 function openDependencyVariant(id){id=Number(id||0);if(!id)return;if(typeof clearPivotContext==='function')clearPivotContext();if(typeof setWorkbenchView==='function')setWorkbenchView('assets');if(typeof loadDetail==='function')loadDetail(id,'relationships')}
 function relationRows(rows,direction){if(!Array.isArray(rows)||!rows.length)return'<div class="muted small">none</div>';return rows.map(function(x){var name=direction==='reverse'?(x.consumerInternalName||`plugin ${x.consumerPluginId||'?'}`):(x.providerInternalName||`plugin ${x.providerPluginId||'?'}`),constraint=x.versionConstraint?` · ${esc(x.versionConstraint)}`:'',status=[x.resolutionStatus,x.versionStatus].filter(Boolean).join(' / '),target=x.preferredVariantId?` · current Evidence variant ${fmt(x.preferredVariantId)}`:'',label=x.preferredVariantId?`<button class=linkbutton data-dependency-variant="${Number(x.preferredVariantId)}">${esc(name)}</button>`:`<b>${esc(name)}</b>`;return `<div class=plugin-dependency-row>${label}<div class=plugin-dependency-meta>${esc(x.relationship||'observed')}${constraint}${target}</div>${status?`<div class=plugin-dependency-meta>${esc(status)}</div>`:''}</div>`}).join('')}
 function groups(obj,direction){return [['Required',obj?.required||[]],['Recommended',obj?.recommended||[]],['Optional',obj?.optional||[]]].map(function(pair){return `<div class=plugin-dependency-group><div class=plugin-dependency-group-title>${pair[0]}</div>${relationRows(pair[1],direction)}</div>`}).join('')}
 function integrationHtml(i){if(!i?.available)return `<div class=research-error>${esc(i?.error||'IPC evidence unavailable.')}</div>`;if(!(i.rows||[]).length)return'<div class="muted small">No IPC integration relationships are retained for this variant.</div>';return evidence(i.rows||[])}
 function componentHtml(c){if(!c?.available)return `<div class=research-error>${esc(c?.error||'Component relationship evidence unavailable.')}</div>`;if(!(c.rows||[]).length)return'<div class="muted small">No dependency components are retained for this variant.</div>';return evidence(c.rows||[])}
 function dependencyHtml(r){var g=r.graph||{},req=r.requires||{},rev=r.requiredBy||{},empty=g.globallyEmpty?`<div class=plugin-dependency-empty>${esc(r.message||'No normalized plugin dependency relationships are currently published.')}</div>`:'',observed=(req.observedPackageRelationships||[]).length?`<details><summary>Observed package relationships that are not Required / Recommended / Optional</summary>${evidence(req.observedPackageRelationships)}</details>`:'';return `<section class=plugin-dependency-shell><div class=plugin-dependency-head><div><h4>Plugin dependency graph</h4><div class="muted small">${esc(r.message||'')}</div></div><span class=pill>${g.available?`${fmt(g.counts?.edges||0)} edges · ${fmt(g.counts?.providers||0)} providers`:'GRAPH UNAVAILABLE'}</span></div>${empty}<div class=plugin-dependency-grid><div class=plugin-dependency-box><h5>Requires</h5><div class="muted small">Only normalized plugin-dependency edges can appear here. Click a resolved plugin to investigate it.</div>${groups(req,'forward')}${observed}</div><div class=plugin-dependency-box><h5>Required by</h5><div class="muted small">Consumers resolved against this plugin's stable plugin identity. Click a consumer to investigate it.</div>${groups(rev,'reverse')}</div><div class=plugin-dependency-box><h5>Integrations</h5><div class="muted small">IPC relationships. Integration evidence is not a package requirement.</div>${integrationHtml(r.integrations||{})}</div><div class=plugin-dependency-box><h5>Components</h5><div class="muted small">NuGet/native/framework/assembly observations. Components are not plugin package requirements.</div>${componentHtml(r.components||{})}</div></div><div class=plugin-dependency-boundary><b>Relationship authority boundary</b><div class="small">IPC is explicitly <code>ipcIsPackageDependency=false</code>. DeltaScope will never display “A requires B” from IPC alone. Package requirements come only from <code>indexes.pluginDependencies</code>. Omega owns package management; DeltaScope is investigation/navigation only.</div></div><details class="plugin-dependency-raw technical-detail"><summary>Raw plugin dependency context</summary>${evidence(r)}</details></section>`}
 function wireDependencyLinks(host){host?.querySelectorAll?.('[data-dependency-variant]').forEach(function(x){x.addEventListener('click',()=>openDependencyVariant(x.dataset.dependencyVariant))})}
 async function appendPluginDependencies(id,pane){var target=pane?.querySelector?.('[data-asset-relationships]');if(!target||target.querySelector('.plugin-dependency-shell'))return;var host=document.createElement('div');host.innerHTML='<div class=workspace-empty>Loading normalized plugin dependency relationships…</div>';target.appendChild(host);try{var r=await api('/api/plugin-dependencies?variant_id='+encodeURIComponent(id));host.innerHTML=dependencyHtml(r);wireDependencyLinks(host)}catch(e){host.innerHTML=`<div class=research-error><b>Plugin dependency graph unavailable</b><div>${esc(e.message)}</div></div>`}}
 window.loadAssetRelationships=async function(id,pane){await baseLoad(id,pane);await appendPluginDependencies(id,pane)};
 loadAssetRelationships=window.loadAssetRelationships;
 function markedCard(label,value,action={},hint=''){return card(label,value,action,hint).replace('<div class="card','<div data-delta-plugin-dependency-metric class="card')}
 function refreshDependencyAllMetrics(){var host=document.getElementById('allMetricCards'),c=window.currentSummary?.counts||currentSummary?.counts||{};if(!host)return;host.querySelectorAll('[data-delta-plugin-dependency-metric]').forEach(x=>x.remove());host.insertAdjacentHTML('beforeend',markedCard('Plugin dependency edges',c.pluginDependencyEdges||0,{table:'v2_plugin_dependencies'},'normalized plugin package relationships')+markedCard('Dependency providers',c.pluginDependencyProviders||0,{table:'v2_plugin_dependency_providers'},'stable provider plugin identities'));if(typeof wireMetricCards==='function')wireMetricCards(host)}
 function renderExplicitIntelligenceCards(c){var host=document.getElementById('intelligenceCards'),counts=c?.counts||{},caps=c?.capabilityCoverage||{},s=window.currentSummary?.counts||currentSummary?.counts||{};if(!host||typeof card!=='function')return;host.innerHTML=card('Observed endpoints',counts.endpoints||0)+card('Behavior pivots',caps.exactCompactCapabilityCount||caps.boundedBehaviorSignalCount||0)+card('Source families',counts.families||0)+card('Authors',counts.authors||0)+card('Plugin dependency edges',s.pluginDependencyEdges||0,{table:'v2_plugin_dependencies'},'normalized package relationships')+card('Dependency providers',s.pluginDependencyProviders||0,{table:'v2_plugin_dependency_providers'},'stable provider identities')+card('Dependency components',s.dependencyComponents||0,{table:'v2_dependency_components'},'NuGet/native/framework/assembly observations')+card('IPC providers',s.ipcProviders||0,{table:'v2_ipc_providers'},'integration providers; not package requirements')+card('Known advisories',s.advisories||0,{table:'v2_advisories'},'frozen advisory matches');if(typeof wireMetricCards==='function')wireMetricCards(host);refreshDependencyAllMetrics()}
 if(typeof baseRelationshipCatalog==='function'){window.renderRelationshipCatalog=function(c){baseRelationshipCatalog(c);renderExplicitIntelligenceCards(c)};renderRelationshipCatalog=window.renderRelationshipCatalog}
 function recoveryBanner(s){var r=s?.evidenceRecovery||{};if(!r.available)return'';var rev=r.retainedEvidenceRevision?`<div class="muted tiny">retained Evidence ${esc(r.retainedEvidenceRevision)}</div>`:'';return `<div class=evidence-recovery-banner data-evidence-recovery-banner><span class=pill>AUTHORITY REPAIR · NOT A SECURITY EVENT</span><b>${esc(r.headline||'Evidence recovery publication')}</b><div class=small>${esc(r.detail||'')}</div>${rev}</div>`}
 function decorateOperationalSystem(s){var host=document.getElementById('opsEvidenceChecks');if(host){host.querySelectorAll('[data-evidence-recovery-banner]').forEach(x=>x.remove());var html=recoveryBanner(s);if(html)host.insertAdjacentHTML('afterbegin',html)}var revisions=document.getElementById('opsEvidenceRevision');if(revisions){revisions.querySelectorAll('[data-dependency-graph-revision]').forEach(x=>x.remove());var rev=s?.revisions?.dependencyGraphRevision;if(rev)revisions.insertAdjacentHTML('beforeend',`<div data-dependency-graph-revision class="muted small" style="margin-top:10px"><b>Dependency graph</b> <code>${esc(rev)}</code></div>`)}}
 function decorateSystem(s){var host=document.getElementById('systemChecks');if(host){host.querySelectorAll('[data-evidence-recovery-banner]').forEach(x=>x.remove());var html=recoveryBanner(s);if(html)host.insertAdjacentHTML('afterbegin',html)}}
 if(typeof baseOperationalSystem==='function'){window.renderOperationalSystemPages=function(s){baseOperationalSystem(s);decorateOperationalSystem(s)};renderOperationalSystemPages=window.renderOperationalSystemPages}
 if(typeof baseSystemStatus==='function'){window.renderSystemStatus=function(s){baseSystemStatus(s);decorateSystem(s)};renderSystemStatus=window.renderSystemStatus}
 refreshDependencyAllMetrics();
},0);
"""


def _patch_html(html: str) -> str:
    text = str(html)
    if "__deltascopePluginDependenciesInstalled" in text:
        return text
    script = _DEPENDENCY_JS.replace("__DEPENDENCY_CSS__", json.dumps(_DEPENDENCY_CSS))
    marker = "</script>"
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError("DeltaScope HTML script boundary was not found")
    return text[:index] + "\n" + script + "\n" + text[index:]


def install() -> None:
    """Install the graph consumer into the existing read-only DeltaScope process."""
    import developer_view
    import evidence_v2_inspector
    import deltascope_workbench

    if getattr(developer_view, "_deltascope_plugin_dependencies_installed", False):
        return

    _install_inspector_extensions(evidence_v2_inspector.V2SigmascopeInspector)
    _install_workbench_extensions(deltascope_workbench)
    developer_view.HTML = _patch_html(developer_view.HTML)
    developer_view.AppHandler.server_version = f"OmegaDeltaScope/{DELTASCOPE_VERSION}"
    original_get = developer_view.AppHandler.do_GET

    def patched_get(self: Any) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/plugin-dependencies":
            return original_get(self)
        try:
            query = urllib.parse.parse_qs(parsed.query)
            variant_id = _int((query.get("variant_id") or ["0"])[0])
            if variant_id <= 0:
                return self.json_response({"error": "variant_id is required"}, 400)
            return self.json_response(project_plugin_dependency_context(self.inspector, variant_id))
        except ValueError as exc:
            return self.json_response({"error": str(exc)}, 400)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get
    developer_view._deltascope_plugin_dependencies_installed = True
