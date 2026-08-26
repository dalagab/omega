"""Frozen threat-intelligence helpers shared by SigmaScope reprojection and DeltaScope.

This module performs no network I/O.  It consumes only the already-frozen daily
``reputation.json`` payload and enriches retained endpoint observations deterministically.
"""
from __future__ import annotations

import ipaddress
import urllib.parse
from typing import Any, Iterable, Mapping, Sequence

RISK_RANK = {"none": 0, "informational": 1, "caution": 2, "high": 3, "critical": 4}


def _normalize_ip(value: Any) -> str:
    text = str(value or "").strip().strip("[]")
    if not text:
        return ""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return ""
    return address.compressed if address.is_global else ""


def _normalize_host(value: Any) -> str:
    text = str(value or "").strip().rstrip(".").casefold()
    if not text:
        return ""
    try:
        return text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""


def _normalize_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return ""
    host = _normalize_host(parsed.hostname)
    if not host:
        return ""
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    return urllib.parse.urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/", parsed.query, ""))


def _max_risk(values: Iterable[str]) -> str:
    best = "none"
    for raw in values:
        value = str(raw or "none").casefold()
        if RISK_RANK.get(value, 0) > RISK_RANK.get(best, 0):
            best = value
    return best


def reputation_revision(document: Mapping[str, Any] | None) -> str:
    return str((document or {}).get("reputationRevision") or "")


def _indicator_map(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("indicatorId") or ""): dict(row)
        for row in document.get("indicators") or []
        if isinstance(row, Mapping) and str(row.get("indicatorId") or "")
    }


def _resolution_map(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in document.get("observedEndpointResolutions") or []:
        if not isinstance(row, Mapping):
            continue
        host = _normalize_host(row.get("host"))
        if host:
            result[host] = dict(row)
    return result


def _endpoint_match_map(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in document.get("observedEndpointMatches") or []:
        if not isinstance(row, Mapping):
            continue
        host = _normalize_host(row.get("host"))
        if host:
            result[host] = dict(row)
    return result


def match_endpoint(row: Mapping[str, Any], document: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return deterministic frozen-intelligence context for one retained endpoint row."""
    doc = document if isinstance(document, Mapping) else {}
    indexes = doc.get("indexes") if isinstance(doc.get("indexes"), Mapping) else {}
    by_ip = indexes.get("byIp") if isinstance(indexes.get("byIp"), Mapping) else {}
    by_host = indexes.get("byHost") if isinstance(indexes.get("byHost"), Mapping) else {}
    by_url = indexes.get("byUrl") if isinstance(indexes.get("byUrl"), Mapping) else {}
    indicators = _indicator_map(doc)
    resolutions = _resolution_map(doc)
    host_matches = _endpoint_match_map(doc)

    host = _normalize_host(row.get("host"))
    clean_url = _normalize_url(row.get("url"))
    ids: set[str] = set()
    resolved_ips: set[str] = set()
    if host:
        ids.update(str(item) for item in by_host.get(host) or [] if str(item))
        prior = resolutions.get(host) or {}
        resolved_ips.update(_normalize_ip(ip) for ip in prior.get("resolvedIps") or [] if _normalize_ip(ip))
        prior_match = host_matches.get(host) or {}
        ids.update(str(item) for item in prior_match.get("indicatorIds") or [] if str(item))
    direct_ip = _normalize_ip(host)
    if direct_ip:
        resolved_ips.add(direct_ip)
    for ip in sorted(resolved_ips):
        ids.update(str(item) for item in by_ip.get(ip) or [] if str(item))
    if clean_url:
        ids.update(str(item) for item in by_url.get(clean_url) or [] if str(item))

    matched = [indicators[iid] for iid in sorted(ids) if iid in indicators and bool(indicators[iid].get("active", True))]
    return {
        "matched": bool(matched),
        "active": bool(matched),
        "risk": _max_risk(str(item.get("risk") or "none") for item in matched),
        "categories": sorted({str(item.get("category") or "") for item in matched if item.get("category")}),
        "sources": sorted({str(item.get("source") or "") for item in matched if item.get("source")}),
        "indicatorIds": [str(item.get("indicatorId") or "") for item in matched],
        "resolvedIps": sorted(resolved_ips),
        "reputationRevision": reputation_revision(doc),
    }


def enrich_network_endpoints(rows: Sequence[Mapping[str, Any]], document: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        match = match_endpoint(row, document)
        row.update({
            "resolvedIps": list(match["resolvedIps"]),
            "threatIntelMatched": bool(match["matched"]),
            "threatIntelActive": bool(match["active"]),
            "threatIntelRisk": str(match["risk"]),
            "threatIntelCategories": list(match["categories"]),
            "threatIntelSources": list(match["sources"]),
            "threatIntelIndicatorIds": list(match["indicatorIds"]),
            "threatIntelRevision": str(match["reputationRevision"]),
        })
        result.append(row)
    return result
