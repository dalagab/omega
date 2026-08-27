"""Extract, classify and summarize static endpoint literals without network requests.

Endpoint evidence deliberately distinguishes *network capability* from *destination
literals*. A URL string proves only that the literal exists in the inspected material.
Origin and confidence are retained so source/config literals are not presented with the
same weight as incidental strings embedded in compiled binaries.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import urllib.parse
from typing import Iterable

from semantic_registry import service_for_host

SCHEMA = "omega.sigmascope.endpoint-evidence.v2"
SUMMARY_SCHEMA = "omega.sigmascope.endpoint-summary.v1"
URL_PATTERN = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
COLLECTION_HOSTS = {
    "webhook.site": "temporary webhook collector",
    "requestbin.com": "temporary request collector",
    "pipedream.net": "workflow/webhook collector",
}
CERTIFICATE_INFRASTRUCTURE_SUFFIXES = (
    ".digicert.com", ".sectigo.com", ".comodoca.com", ".globalsign.com",
)
CERTIFICATE_INFRASTRUCTURE_HOSTS = {
    "crl.microsoft.com", "www.microsoft.com", "timestamp.digicert.com", "ocsp.digicert.com",
}
TELEMETRY_SUFFIXES = (".sentry.io", ".ingest.sentry.io")
DOCUMENTATION_HOSTS = {"aka.ms", "learn.microsoft.com", "docs.microsoft.com"}
SOURCE_REFERENCE_PATH_MARKERS = ("/-/tree/", "/-/raw/", "/src/branch/", "/src/commit/", "/blob/", "/raw/", "/tree/", "/archive/")
EXAMPLE_HOSTS = {"example.com", "example.net", "example.org", "server.example.com"}
CONFIDENCE_RANK = {"Low": 1, "Medium": 2, "High": 3, "VeryHigh": 4}


def _safe_path(path: str) -> str:
    """Retain useful endpoint intent without exposing path-embedded secrets."""
    parts = [part for part in path.split("/") if part]
    if any(part.casefold() == "webhooks" for part in parts):
        return "/api/webhooks/<redacted>"
    if any(re.fullmatch(r"[A-Za-z0-9_-]{24,}", part) for part in parts):
        return "/" + "/".join("<redacted>" if re.fullmatch(r"[A-Za-z0-9_-]{24,}", part) else part for part in parts)
    return path or "/"


def _valid_hostname(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    if host not in {"localhost", "localhost.localdomain"} and "." not in host:
        return False
    return bool(host and len(host) <= 253 and all(HOST_LABEL_PATTERN.fullmatch(label) for label in host.split(".")))


def _is_source_reference_path(path: str) -> bool:
    normalized = path.casefold()
    return any(marker in normalized for marker in SOURCE_REFERENCE_PATH_MARKERS) or normalized.endswith((".cs", ".csproj", ".sln", ".props", ".targets"))


def _redacted_url(value: str) -> tuple[str, str, str, str] | None:
    candidate = value.rstrip(".,;:!?)]}")
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.casefold()
    if not _valid_hostname(host) or host in EXAMPLE_HOSTS:
        return None
    # Never persist credentials/userinfo/query/fragment. IPv6 authorities need brackets.
    authority_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    authority = authority_host if parsed.port is None else f"{authority_host}:{parsed.port}"
    path = _safe_path(parsed.path)
    return urllib.parse.urlunsplit((parsed.scheme.lower(), authority, path, "", "")), host, parsed.scheme.lower(), path


def _is_certificate_infrastructure(host: str, path: str) -> bool:
    if host in CERTIFICATE_INFRASTRUCTURE_HOSTS or any(host.endswith(suffix) for suffix in CERTIFICATE_INFRASTRUCTURE_SUFFIXES):
        lower_path = path.casefold()
        return any(marker in lower_path for marker in ("/crl", "/ocsp", "/timestamp", "/pki", ".crl", ".crt", ".cer")) or host.startswith(("ocsp.", "crl.", "timestamp."))
    return False


def _host_classification(host: str, scheme: str, path: str) -> tuple[str, str, str, str]:
    if host in {"localhost", "localhost.localdomain"}:
        return "private-or-loopback", "high", "local machine", "Literal private or loopback endpoint"
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        if address.is_private or address.is_loopback or address.is_link_local:
            return "private-or-loopback", "high", "local/private network", "Literal private, loopback, or link-local IP endpoint"
        if address.is_unspecified or address.is_multicast or address.is_reserved:
            return "special-use-ip", "high", "special-use network", "Literal unspecified, multicast, or reserved IP endpoint"
        return "public-ip-literal", "caution", "direct public IP", "Literal public IP endpoint; no host purpose or reputation can be inferred from a static scan"
    except ValueError:
        pass
    if _is_certificate_infrastructure(host, path):
        return "certificate-infrastructure", "informational", "certificate/revocation infrastructure", "Literal appears to reference certificate, revocation, or timestamp infrastructure"
    if host == "discord.gg" or (host in {"discord.com", "discordapp.com"} and path.startswith("/invite/")):
        return "community-invite", "informational", "community invite", "Literal Discord community invite; this is not evidence of a network data transfer"
    if host.startswith("forums."):
        return "community-forum", "informational", "community forum", "Literal community forum link; this is not evidence of a network data transfer"
    if host.endswith(".finalfantasyxiv.com") and "/lodestone/" in path.casefold():
        return "ffxiv-lodestone-link", "informational", "official FFXIV Lodestone page", "Literal link to an official FFXIV Lodestone page. It does not prove the plugin reads profile or account data"
    if _is_source_reference_path(path):
        return "source-reference", "informational", "source-code reference", "Literal source-code or repository reference; this is not a plugin network destination"
    if host in DOCUMENTATION_HOSTS:
        return "documentation-reference", "informational", "documentation/reference link", "Literal documentation/reference link; this is not treated as a plugin network destination"
    if host in {"discord.com", "discordapp.com"} and path.startswith("/api/webhooks/"):
        return "webhook-endpoint", "caution", "Discord webhook", "Literal Discord webhook endpoint; static analysis cannot determine what data would be sent"
    if any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in TELEMETRY_SUFFIXES):
        return "telemetry-endpoint", "informational", "error/telemetry service", "Literal endpoint belongs to a known error/telemetry service; static analysis cannot determine payload contents"
    if scheme == "http":
        return "insecure-http", "caution", "unencrypted web traffic", "Literal endpoint uses unencrypted HTTP"
    service = service_for_host(host)
    if service.get("serviceRecognition") != "unknown":
        name = str(service.get("serviceName") or service.get("serviceId") or host)
        purpose = str(service.get("servicePurpose") or "registered public service")
        return "recognised-platform", "informational", purpose, f"Recognised public service: {name} ({purpose})"
    if host in COLLECTION_HOSTS:
        purpose = COLLECTION_HOSTS[host]
        return "collection-endpoint", "caution", purpose, f"Literal endpoint uses a {purpose}"
    return "unrecognised-host", "caution", "unrecognised public host", "Literal public endpoint is not in Omega's recognised platform list"


def _origin_metadata(evidence_label: str, origin_type: str | None, confidence: str | None) -> tuple[str, str]:
    if origin_type:
        chosen = origin_type
    elif evidence_label.startswith("source:"):
        chosen = "source-code"
    elif evidence_label.startswith("artifact:"):
        path = evidence_label.split(":", 1)[1].casefold()
        chosen = "artifact-config" if path.endswith((".json", ".xml", ".config", ".yml", ".yaml")) else "artifact-text"
    else:
        chosen = "artifact-text"
    defaults = {
        "artifact-config": "VeryHigh",
        "source-code": "High",
        "artifact-text": "Medium",
        "managed-metadata-string": "Medium",
        "artifact-binary-string": "Low",
    }
    resolved_confidence = confidence or defaults.get(chosen, "Low")
    if resolved_confidence not in CONFIDENCE_RANK:
        resolved_confidence = "Low"
    return chosen, resolved_confidence


def _is_declared_source_reference(endpoint: dict, source_repositories: list[str]) -> bool:
    try:
        endpoint_url = urllib.parse.urlsplit(str(endpoint.get("url") or ""))
    except ValueError:
        return False
    endpoint_host = (endpoint_url.hostname or "").casefold()
    endpoint_path = endpoint_url.path.rstrip("/").casefold()
    for repository in source_repositories:
        try:
            parsed = urllib.parse.urlsplit(str(repository or ""))
        except ValueError:
            continue
        base_path = parsed.path.rstrip("/").casefold()
        if endpoint_host == (parsed.hostname or "").casefold() and base_path and (endpoint_path == base_path or endpoint_path.startswith(base_path + "/")):
            return True
    return False


def endpoint_candidates(text: str, evidence_label: str, *, origin_type: str | None = None, confidence: str | None = None) -> list[dict]:
    candidates: list[dict] = []
    seen: set[str] = set()
    resolved_origin, resolved_confidence = _origin_metadata(evidence_label, origin_type, confidence)
    for match in URL_PATTERN.finditer(text):
        parsed = _redacted_url(match.group(0))
        if parsed is None:
            continue
        url, host, scheme, path = parsed
        if url in seen:
            continue
        seen.add(url)
        classification, severity, purpose, reason = _host_classification(host, scheme, path)
        service = service_for_host(host)
        concrete = classification not in {"source-reference", "documentation-reference", "community-invite", "community-forum", "ffxiv-lodestone-link", "certificate-infrastructure"}
        candidates.append({
            "schema": SCHEMA,
            "url": url,
            "host": host,
            "scheme": scheme,
            "classification": classification,
            "severity": severity,
            "purpose": purpose,
            "reason": reason,
            "serviceId": str(service.get("serviceId") or ""),
            "serviceName": str(service.get("serviceName") or ""),
            "serviceRecognition": str(service.get("serviceRecognition") or "unknown"),
            "serviceCategories": list(service.get("serviceCategories") or [])[:32],
            "serviceCapabilities": list(service.get("serviceCapabilities") or [])[:64],
            "serviceRegistryRevision": str(service.get("serviceRegistryRevision") or ""),
            "originType": resolved_origin,
            "confidence": resolved_confidence,
            # Direction is relative to the plugin. A concrete URL literal is a destination and
            # therefore describes an outbound role if used; informational/reference literals
            # are not treated as traffic and remain unknown. Replies do not turn an outbound
            # client request into a bidirectional role.
            "trafficDirection": "outbound" if concrete else "unknown",
            "concreteDestinationEvidence": concrete,
            "evidence": [f"{evidence_label}: {url}"],
        })
    return candidates


def endpoint_summary(endpoints: Iterable[dict], has_network_capability: bool) -> dict:
    records = [item for item in endpoints if isinstance(item, dict)]
    concrete = [item for item in records if bool(item.get("concreteDestinationEvidence"))]
    hosts: dict[str, dict] = {}
    classifications: dict[str, int] = {}
    origins: dict[str, int] = {}
    directions: dict[str, int] = {}
    for item in records:
        classification = str(item.get("classification") or "unrecognised-host")
        origin = str(item.get("originType") or "unknown")
        classifications[classification] = classifications.get(classification, 0) + 1
        origins[origin] = origins.get(origin, 0) + 1
        direction = str(item.get("trafficDirection") or "unknown")
        directions[direction] = directions.get(direction, 0) + 1
        host = str(item.get("host") or "")
        if not host:
            continue
        current = hosts.setdefault(host, {"host": host, "literalCount": 0, "concreteCount": 0, "classifications": set(), "originTypes": set(), "trafficDirections": set(), "confidence": "Low"})
        current["literalCount"] += 1
        if bool(item.get("concreteDestinationEvidence")):
            current["concreteCount"] += 1
        current["classifications"].add(classification)
        current["originTypes"].add(origin)
        current["trafficDirections"].add(direction)
        confidence = str(item.get("confidence") or "Low")
        if CONFIDENCE_RANK.get(confidence, 0) > CONFIDENCE_RANK.get(str(current["confidence"]), 0):
            current["confidence"] = confidence
    compact_hosts = []
    for host in sorted(hosts, key=str.casefold)[:32]:
        item = hosts[host]
        compact_hosts.append({
            "host": item["host"], "literalCount": item["literalCount"], "concreteCount": item["concreteCount"],
            "classifications": sorted(item["classifications"], key=str.casefold),
            "originTypes": sorted(item["originTypes"], key=str.casefold),
            "trafficDirections": sorted(item["trafficDirections"], key=str.casefold),
            "confidence": item["confidence"],
        })
    return {
        "schema": SUMMARY_SCHEMA,
        "networkCapabilityObserved": bool(has_network_capability),
        "literalCount": len(records),
        "concreteDestinationCount": len(concrete),
        "hostCount": len(hosts),
        "hosts": compact_hosts,
        "classifications": {key: classifications[key] for key in sorted(classifications)},
        "originTypes": {key: origins[key] for key in sorted(origins)},
        "trafficDirectionCounts": {key: directions[key] for key in sorted(directions)},
        "destinationsUndetermined": bool(has_network_capability and not concrete),
    }


def endpoint_findings(endpoints: list[dict], has_network_capability: bool, source_repositories: list[str] | None = None) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    capabilities: list[str] = []
    if not has_network_capability:
        return findings, capabilities
    concrete_count = 0
    for endpoint in endpoints[:64]:
        url = str(endpoint.get("url") or "")
        host = str(endpoint.get("host") or "")
        classification = str(endpoint.get("classification") or "unrecognised-host")
        severity = str(endpoint.get("severity") or "caution")
        confidence = str(endpoint.get("confidence") or "Low")
        origin_type = str(endpoint.get("originType") or "unknown")
        if classification in {"source-reference", "certificate-infrastructure"} or _is_declared_source_reference(endpoint, source_repositories or []):
            continue
        is_concrete = bool(endpoint.get("concreteDestinationEvidence"))
        if not is_concrete and classification not in {"community-invite", "community-forum", "ffxiv-lodestone-link"}:
            continue
        if is_concrete:
            concrete_count += 1
        digest = hashlib.sha256((url + "|" + origin_type).encode("utf-8")).hexdigest()[:12]
        title = f"Endpoint: {host}"
        if classification == "webhook-endpoint":
            title = "Endpoint: Discord webhook"
        elif classification == "community-invite":
            title = "Community invite: Discord"
        elif classification == "community-forum":
            title = f"Community forum: {host}"
        elif classification == "ffxiv-lodestone-link":
            title = "Official FFXIV Lodestone page link"
        findings.append({
            "ruleId": f"network.endpoint.{classification}.{digest}",
            "severity": severity,
            "category": "network-endpoint",
            "title": title,
            "description": f"{endpoint.get('reason')}. Origin: {origin_type}; evidence confidence: {confidence}. This is a static literal, not proof of a runtime connection or payload.",
            "confidence": confidence,
            "endpointOrigin": origin_type,
            "evidence": list(endpoint.get("evidence") or [])[:4],
        })
        capabilities.append(f"Endpoint: {host}")
    if has_network_capability and concrete_count == 0 and not findings:
        findings.append({
            "ruleId": "network.endpoint.dynamic-or-undetermined",
            "severity": "informational",
            "category": "network-endpoint",
            "title": "Network destination undetermined",
            "description": "The artifact references network APIs, but no concrete static HTTP endpoint could be attributed. Destinations may be dynamically constructed, use non-HTTP protocols, or only incidental URL strings were present.",
            "confidence": "High",
            "endpointOrigin": "derived-capability-gap",
            "evidence": [],
        })
        capabilities.append("Network destination undetermined")
    return findings, capabilities
