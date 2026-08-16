"""Extract and classify static URL literals without making network requests."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import urllib.parse


URL_PATTERN = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
RECOGNISED_PLATFORM_HOSTS = {
    "api.github.com": "GitHub API",
    "github.com": "GitHub",
    "raw.githubusercontent.com": "GitHub raw content",
    "discord.com": "Discord",
    "discordapp.com": "Discord",
    "xivlauncher.net": "XIVLauncher",
    "dalamud.dev": "Dalamud",
}


def _redacted_url(value: str) -> tuple[str, str, str] | None:
    candidate = value.rstrip(".,;:!?)]}")
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.casefold()
    authority = host if parsed.port is None else f"{host}:{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", "", "")), host, parsed.scheme.lower()


def _host_classification(host: str, scheme: str) -> tuple[str, str, str]:
    if host in {"localhost", "localhost.localdomain"}:
        return "private-or-loopback", "high", "Literal private or loopback endpoint"
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            return "private-or-loopback", "high", "Literal private, loopback, link-local, or reserved endpoint"
        return "public-ip-literal", "caution", "Literal public IP endpoint"
    except ValueError:
        pass
    if scheme == "http":
        return "insecure-http", "caution", "Literal endpoint uses unencrypted HTTP"
    if host in RECOGNISED_PLATFORM_HOSTS:
        return "recognised-platform", "informational", f"Recognised public platform: {RECOGNISED_PLATFORM_HOSTS[host]}"
    return "unrecognised-host", "caution", "Literal public endpoint is not in Omega's recognised platform list"


def endpoint_candidates(text: str, evidence_label: str) -> list[dict]:
    candidates: list[dict] = []
    seen: set[str] = set()
    for match in URL_PATTERN.finditer(text):
        parsed = _redacted_url(match.group(0))
        if parsed is None:
            continue
        url, host, scheme = parsed
        if url in seen:
            continue
        seen.add(url)
        classification, severity, reason = _host_classification(host, scheme)
        candidates.append({
            "url": url,
            "host": host,
            "scheme": scheme,
            "classification": classification,
            "severity": severity,
            "reason": reason,
            "evidence": [f"{evidence_label}: {url}"],
        })
    return candidates


def endpoint_findings(endpoints: list[dict], has_network_capability: bool) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    capabilities: list[str] = []
    if not has_network_capability:
        return findings, capabilities
    for endpoint in endpoints[:20]:
        url = str(endpoint.get("url") or "")
        host = str(endpoint.get("host") or "")
        classification = str(endpoint.get("classification") or "unrecognised-host")
        severity = str(endpoint.get("severity") or "caution")
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
        findings.append({
            "ruleId": f"network.endpoint.{classification}.{digest}",
            "severity": severity,
            "category": "network-endpoint",
            "title": f"Endpoint: {host}",
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
