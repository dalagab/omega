"""Extract and classify static URL literals without making network requests."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import urllib.parse


URL_PATTERN = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
RECOGNISED_PLATFORM_HOSTS = {
    "api.github.com": ("GitHub API", "source hosting"),
    "github.com": ("GitHub", "source hosting"),
    "raw.githubusercontent.com": ("GitHub raw content", "source hosting"),
    "discord.com": ("Discord", "community messaging"),
    "discordapp.com": ("Discord", "community messaging"),
    "cdn.discordapp.com": ("Discord CDN", "community media"),
    "xivlauncher.net": ("XIVLauncher", "FFXIV launcher infrastructure"),
    "dalamud.dev": ("Dalamud", "FFXIV plugin infrastructure"),
    "goatcorp.github.io": ("Goatcorp", "FFXIV plugin infrastructure"),
    "kamori.goats.dev": ("Kamori", "FFXIV plugin distribution"),
    "universalis.app": ("Universalis", "FFXIV market data"),
    "xivapi.com": ("XIVAPI", "FFXIV game data"),
    "nuget.org": ("NuGet", "package registry"),
    "api.nuget.org": ("NuGet", "package registry"),
}

COLLECTION_HOSTS = {
    "webhook.site": "temporary webhook collector",
    "requestbin.com": "temporary request collector",
    "pipedream.net": "workflow/webhook collector",
}

SOURCE_REFERENCE_PATH_MARKERS = ("/-/tree/", "/-/raw/", "/src/branch/", "/src/commit/", "/blob/", "/raw/", "/tree/", "/archive/")
EXAMPLE_HOSTS = {"example.com", "example.net", "example.org", "server.example.com"}


def _safe_path(path: str) -> str:
    """Retain useful endpoint intent without exposing path-embedded secrets."""
    parts = [part for part in path.split("/") if part]
    if any(part.casefold() == "webhooks" for part in parts):
        return "/api/webhooks/<redacted>"
    if any(re.fullmatch(r"[A-Za-z0-9_-]{24,}", part) for part in parts):
        return "/" + "/".join("<redacted>" if re.fullmatch(r"[A-Za-z0-9_-]{24,}", part) else part for part in parts)
    return path or "/"


def _valid_hostname(host: str) -> bool:
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
    authority = host if parsed.port is None else f"{host}:{parsed.port}"
    path = _safe_path(parsed.path)
    return urllib.parse.urlunsplit((parsed.scheme.lower(), authority, path, "", "")), host, parsed.scheme.lower(), path


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
    if host == "discord.gg" or (host in {"discord.com", "discordapp.com"} and path.startswith("/invite/")):
        return "community-invite", "informational", "community invite", "Literal Discord community invite; this is not evidence of a network data transfer"
    if host.startswith("forums."):
        return "community-forum", "informational", "community forum", "Literal community forum link; this is not evidence of a network data transfer"
    if host.endswith(".finalfantasyxiv.com") and "/lodestone/" in path.casefold():
        return "ffxiv-lodestone-link", "informational", "official FFXIV Lodestone page", "Literal link to an official FFXIV Lodestone page. It does not prove the plugin reads profile or account data"
    if _is_source_reference_path(path):
        return "source-reference", "informational", "source-code reference", "Literal source-code or repository reference; this is not a plugin network destination"
    if host in {"discord.com", "discordapp.com"} and path.startswith("/api/webhooks/"):
        return "webhook-endpoint", "caution", "Discord webhook", "Literal Discord webhook endpoint; static analysis cannot determine what data would be sent"
    if scheme == "http":
        return "insecure-http", "caution", "unencrypted web traffic", "Literal endpoint uses unencrypted HTTP"
    if host in RECOGNISED_PLATFORM_HOSTS:
        name, purpose = RECOGNISED_PLATFORM_HOSTS[host]
        return "recognised-platform", "informational", purpose, f"Recognised public platform: {name} ({purpose})"
    if host in COLLECTION_HOSTS:
        purpose = COLLECTION_HOSTS[host]
        return "collection-endpoint", "caution", purpose, f"Literal endpoint uses a {purpose}"
    return "unrecognised-host", "caution", "unrecognised public host", "Literal public endpoint is not in Omega's recognised platform list"


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


def endpoint_candidates(text: str, evidence_label: str) -> list[dict]:
    candidates: list[dict] = []
    seen: set[str] = set()
    for match in URL_PATTERN.finditer(text):
        parsed = _redacted_url(match.group(0))
        if parsed is None:
            continue
        url, host, scheme, path = parsed
        if url in seen:
            continue
        seen.add(url)
        classification, severity, purpose, reason = _host_classification(host, scheme, path)
        candidates.append({
            "url": url,
            "host": host,
            "scheme": scheme,
            "classification": classification,
            "severity": severity,
            "purpose": purpose,
            "reason": reason,
            "evidence": [f"{evidence_label}: {url}"],
        })
    return candidates


def endpoint_findings(endpoints: list[dict], has_network_capability: bool, source_repositories: list[str] | None = None) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    capabilities: list[str] = []
    if not has_network_capability:
        return findings, capabilities
    for endpoint in endpoints[:20]:
        url = str(endpoint.get("url") or "")
        host = str(endpoint.get("host") or "")
        classification = str(endpoint.get("classification") or "unrecognised-host")
        severity = str(endpoint.get("severity") or "caution")
        if classification == "source-reference" or _is_declared_source_reference(endpoint, source_repositories or []):
            continue
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
        title = f"Endpoint: {host}"
        if classification == "community-invite":
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
            "description": f"{endpoint.get('reason')}. This is a static URL literal, not proof of a runtime connection.",
            "evidence": list(endpoint.get("evidence") or [])[:4],
        })
        capabilities.append(f"Endpoint: {host}")
    if has_network_capability and not endpoints:
        findings.append({
            "ruleId": "network.endpoint.dynamic-or-undetermined",
            "severity": "informational",
            "category": "network-endpoint",
            "title": "Network destination undetermined",
            "description": "The artifact references network APIs, but no literal HTTP endpoint was found. Destinations may be dynamically constructed or use non-HTTP protocols.",
            "evidence": [],
        })
        capabilities.append("Network destination undetermined")
    return findings, capabilities
