"""Runtime binding of the bundled DeltaScope SDK to verified published data contracts."""
from __future__ import annotations

from typing import Any, Mapping

from . import capability_registry, collector_contracts, component_registry, rule_author_reference, srl

SDK_SCHEMA = "omega.deltascope.consumer-sdk.v1"
SDK_VERSION = "1.0.0"
_BOUND: dict[str, str] = {}


def configure_published_contracts(
    *,
    components: Mapping[str, Any] | None = None,
    collectors: Mapping[str, Any] | None = None,
    capabilities: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind verified published registry *data* to the local deterministic SDK.

    No code is loaded from the network. The caller is responsible for supplying payloads
    that already passed DeltaScope resource-cache SHA verification.
    """
    component_document = dict(components) if isinstance(components, Mapping) else None
    collector_document = dict(collectors) if isinstance(collectors, Mapping) else None
    capability_document = dict(capabilities) if isinstance(capabilities, Mapping) else None
    if component_document is not None:
        component_registry.configure_registry(component_document)
    if collector_document is not None:
        collector_contracts.configure_registry(collector_document)
    if capability_document is not None:
        capability_registry.configure_registry(capability_document)
    rule_author_reference.refresh_collections()
    srl.refresh_contracts(
        component_registry_document=component_document,
        collector_registry_document=collector_document,
        capability_registry_document=capability_document,
    )
    _BOUND.clear()
    if component_document:
        _BOUND["componentRegistryRevision"] = str(component_document.get("revision") or "")
    if collector_document:
        _BOUND["collectorRegistryRevision"] = str(collector_document.get("revision") or "")
    if capability_document:
        _BOUND["capabilityRegistryRevision"] = str(capability_document.get("revision") or "")
    return sdk_status()


def sdk_status() -> dict[str, Any]:
    return {
        "schema": SDK_SCHEMA,
        "version": SDK_VERSION,
        "bundledCode": True,
        "remoteCodeExecution": False,
        "productionAuthority": False,
        "repositoryWriteBack": False,
        "evidenceWriteBack": False,
        "queueWriteBack": False,
        "publishedContractBinding": dict(_BOUND),
        "typedCollectionCount": len(srl.FIELD_REGISTRY),
        "componentRegistryRevision": component_registry.component_revision(),
        "collectorRegistryRevision": collector_contracts.registry_revision(),
    }
