"""Read-only DeltaScope projection of frozen URL/domain/IP threat intelligence.

The projection deliberately separates an exact IOC identity hit from a hostname that merely
resolved to an IOC IP.  The latter is shared-infrastructure context (CDNs and hosting
providers make this common), not proof that the hostname itself is a malicious indicator.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import datetime as dt
import ipaddress
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

SCHEMA = "omega.deltascope.threat-intelligence.v2"
RISK_RANK = {"none": 0, "informational": 1, "caution": 2, "high": 3, "critical": 4}


def _safe_ints(values: Any) -> list[int]:
    result: set[int] = set()
    for value in values or []:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        if parsed > 0:
            result.add(parsed)
    return sorted(result)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _normalise_host(value: Any) -> str:
    text = _text(value).rstrip(".").casefold()
    if not text:
        return ""
    try:
        return text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return text


def _normalise_ip(value: Any) -> str:
    text = _text(value).strip("[]")
    if not text:
        return ""
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return ""


def _normalise_url(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return ""
    host = _normalise_host(parsed.hostname)
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/", parsed.query, ""))


def _max_risk(values: Any) -> str:
    best = "none"
    for value in values or []:
        risk = _text(value).casefold() or "none"
        if RISK_RANK.get(risk, 0) > RISK_RANK.get(best, 0):
            best = risk
    return best


def _parse_utc(value: Any) -> dt.datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _first_time(row: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = _text(row.get(name))
        if value:
            return value
    return ""


def _feed_projection(row: Mapping[str, Any], *, snapshot_generated_at: str) -> dict[str, Any]:
    projected = dict(row)
    feed_time = _first_time(row, "updatedAtUtc", "generatedAtUtc", "collectedAtUtc", "fetchedAtUtc", "asOfUtc", "lastUpdatedUtc")
    timestamp_scope = "feed" if feed_time else ("snapshot" if snapshot_generated_at else "unknown")
    effective = feed_time or snapshot_generated_at
    state = "unknown"
    age_hours: int | None = None
    parsed = _parse_utc(effective)
    if str(row.get("status") or "").casefold() not in {"complete", "not-configured"}:
        state = "degraded"
    elif parsed is not None:
        age_hours = max(0, int((dt.datetime.now(dt.timezone.utc) - parsed).total_seconds() // 3600))
        state = "current" if age_hours <= 48 else "attention" if age_hours <= 168 else "stale"
    projected.update({
        "freshnessTimestampUtc": effective,
        "freshnessTimestampScope": timestamp_scope,
        "freshnessState": state,
        "freshnessAgeHours": age_hours,
    })
    return projected


def _well_known_context(host: str) -> dict[str, Any]:
    h = _normalise_host(host)
    if not h:
        return {"kind": "unknown", "label": "No host identity", "risk": "none", "recognised": False, "hideByDefault": False}
    if h in {"localhost", "localhost.localdomain"}:
        return {"kind": "loopback", "label": "Loopback / local process only", "risk": "informational", "recognised": True, "hideByDefault": True}
    if h in {"github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com"} or h.endswith(".githubusercontent.com"):
        return {"kind": "known-platform", "label": "GitHub source / artifact hosting", "risk": "informational", "recognised": True, "hideByDefault": False}
    if h == "cdn.jsdelivr.net" or h.endswith(".jsdelivr.net"):
        return {"kind": "shared-cdn", "label": "jsDelivr public CDN · shared infrastructure", "risk": "informational", "recognised": True, "hideByDefault": False}
    ip_text = _normalise_ip(h)
    if not ip_text:
        return {"kind": "public-host", "label": "Public hostname", "risk": "none", "recognised": False, "hideByDefault": False}
    address = ipaddress.ip_address(ip_text)
    if ip_text == "169.254.169.254":
        return {"kind": "cloud-metadata", "label": "Cloud instance metadata service · SSRF-sensitive target", "risk": "caution", "recognised": True, "hideByDefault": False}
    if address.is_loopback:
        return {"kind": "loopback", "label": "Loopback / local process only", "risk": "informational", "recognised": True, "hideByDefault": True}
    if address.is_unspecified:
        return {"kind": "unspecified", "label": "Unspecified / any-address endpoint", "risk": "caution", "recognised": True, "hideByDefault": True}
    if address.is_private:
        return {"kind": "private", "label": "Private network address", "risk": "informational", "recognised": True, "hideByDefault": True}
    if address.is_link_local:
        return {"kind": "link-local", "label": "Link-local address", "risk": "caution", "recognised": True, "hideByDefault": True}
    if address.is_multicast:
        return {"kind": "multicast", "label": "Multicast address", "risk": "informational", "recognised": True, "hideByDefault": True}
    if address.is_reserved:
        return {"kind": "reserved", "label": "Reserved/special-use address", "risk": "informational", "recognised": True, "hideByDefault": True}
    return {"kind": "public-ip", "label": "Public IP address", "risk": "none", "recognised": False, "hideByDefault": False}


def _indicator_match_kind(*, host: str, url_samples: list[str], resolved_ips: list[str], indicator: Mapping[str, Any]) -> str:
    indicator_type = _text(indicator.get("indicatorType") or indicator.get("type")).casefold()
    value = _text(indicator.get("value"))
    host_norm = _normalise_host(host)
    endpoint_ip = _normalise_ip(host_norm)
    indicator_ip = _normalise_ip(value)
    if indicator_ip:
        if endpoint_ip and endpoint_ip == indicator_ip:
            return "exact-ip"
        if indicator_ip in {_normalise_ip(item) for item in resolved_ips if _normalise_ip(item)}:
            return "resolved-ip-adjacency"
    indicator_host = _normalise_host(value)
    if indicator_type in {"domain", "host", "hostname"} and indicator_host and indicator_host == host_norm:
        return "exact-host"
    if indicator_type in {"url", "uri"}:
        indicator_url = _normalise_url(value)
        if indicator_url and indicator_url in {_normalise_url(item) for item in url_samples if _normalise_url(item)}:
            return "exact-url"
    # Some frozen feed formats omit indicatorType but still carry a host-like value.
    if not indicator_ip and "." in indicator_host and indicator_host == host_norm:
        return "exact-host"
    return "linked-unspecified"


def _asset_label(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "variantId": int(row.get("variant_id") or row.get("variantId") or 0),
        "pluginId": int(row.get("plugin_id") or row.get("pluginId") or 0),
        "name": _text(row.get("canonical_name") or row.get("name") or row.get("internal_name") or row.get("internalName")),
        "internalName": _text(row.get("internal_name") or row.get("internalName")),
        "version": _text(row.get("assembly_version") or row.get("version")),
        "sourceName": _text(row.get("source_name") or row.get("sourceName")),
    }


def _relationship_endpoint_map(inspector: Any) -> dict[str, dict[str, Any]]:
    if not hasattr(inspector, "workbench_relationship_index"):
        return {}
    try:
        payload = inspector.workbench_relationship_index()
    except Exception:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for raw in payload.get("endpoints") or []:
        if not isinstance(raw, Mapping):
            continue
        host = _normalise_host(raw.get("host"))
        if host:
            result[host] = dict(raw)
    return result


def project_threat_intelligence(inspector: Any, *, limit: int = 500) -> dict[str, Any]:
    """Project the frozen reputation snapshot as a researcher-priority intelligence brief.

    This is a view only.  Existing frozen threatIntelMatched fields and SRL policy semantics
    are not rewritten by DeltaScope.  The UI-level ``exactMatched`` distinction exists so a
    researcher can tell an exact IOC identity from shared DNS/CDN infrastructure adjacency.
    """
    doc = inspector.threat_intelligence() if hasattr(inspector, "threat_intelligence") else {}
    if not isinstance(doc, Mapping):
        doc = {}
    indicators = [dict(row) for row in doc.get("indicators") or [] if isinstance(row, Mapping)]
    matches = [dict(row) for row in doc.get("observedEndpointMatches") or [] if isinstance(row, Mapping)]
    resolutions = [dict(row) for row in doc.get("observedEndpointResolutions") or [] if isinstance(row, Mapping)]
    resolution_by_host = {_normalise_host(row.get("host")): row for row in resolutions if _normalise_host(row.get("host"))}
    match_by_host = {_normalise_host(row.get("host")): row for row in matches if _normalise_host(row.get("host"))}
    by_id = {_text(row.get("indicatorId")): row for row in indicators if _text(row.get("indicatorId"))}
    relationship_by_host = _relationship_endpoint_map(inspector)

    endpoint_inventory: list[dict[str, Any]] = []
    all_hosts = sorted(set(resolution_by_host) | set(match_by_host) | set(relationship_by_host))
    all_variant_ids: set[int] = set()
    indicator_to_endpoints: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for key in all_hosts:
        resolution = resolution_by_host.get(key, {})
        match = match_by_host.get(key, {})
        relationship = relationship_by_host.get(key, {})
        host = _text(resolution.get("host") or match.get("host") or relationship.get("host") or key)
        ids = [_text(v) for v in match.get("indicatorIds") or [] if _text(v)]
        linked = [by_id[i] for i in ids if i in by_id]
        url_samples = list(match.get("urlSamples") or resolution.get("urlSamples") or relationship.get("urlSamples") or [])[:16]
        resolved_ips = list(match.get("resolvedIps") or resolution.get("resolvedIps") or [])
        linked_rows: list[dict[str, Any]] = []
        for row in linked:
            kind = _indicator_match_kind(host=host, url_samples=url_samples, resolved_ips=resolved_ips, indicator=row)
            projected = {
                "indicatorId": _text(row.get("indicatorId")), "value": _text(row.get("value")),
                "indicatorType": _text(row.get("indicatorType") or row.get("type")), "risk": _text(row.get("risk") or "none").casefold(),
                "category": _text(row.get("category")), "source": _text(row.get("source")), "active": bool(row.get("active", True)),
                "matchKind": kind, "exact": kind.startswith("exact-"), "sharedInfrastructure": kind == "resolved-ip-adjacency",
            }
            linked_rows.append(projected)
            indicator_to_endpoints[projected["indicatorId"]].append({"host": host, "matchKind": kind})
        exact_rows = [row for row in linked_rows if row["exact"] and row["active"]]
        adjacency_rows = [row for row in linked_rows if row["sharedInfrastructure"] and row["active"]]
        unspecified_rows = [row for row in linked_rows if row["matchKind"] == "linked-unspecified" and row["active"]]
        frozen_matched = bool(ids or match)
        exact_matched = bool(exact_rows or unspecified_rows)
        shared_infrastructure = bool(adjacency_rows) and not exact_matched
        resolution_status = _text(resolution.get("resolutionStatus") or ("resolved" if resolved_ips else "unknown"))
        if exact_matched:
            state = "exact-match"
        elif shared_infrastructure:
            state = "shared-infrastructure"
        elif frozen_matched:
            state = "feed-context"
        elif resolution_status in {"resolution-failed", "no-public-address"}:
            state = resolution_status
        elif resolution_status == "retained-previous":
            state = "unlisted-retained-dns"
        else:
            state = "unlisted"
        variant_ids = _safe_ints(match.get("variantIds") or resolution.get("variantIds") or relationship.get("variantIds"))
        all_variant_ids.update(variant_ids)
        classifications = sorted({_text(x) for x in relationship.get("classifications") or [] if _text(x)})
        purposes = sorted({_text(x) for x in relationship.get("purposes") or [] if _text(x)})
        context = _well_known_context(host)
        recognised = bool(classifications or purposes or context.get("recognised"))
        endpoint_inventory.append({
            "host": host, "urlSamples": url_samples, "resolvedIps": resolved_ips, "resolutionStatus": resolution_status,
            "reputationState": state, "matched": frozen_matched, "exactMatched": exact_matched,
            "sharedInfrastructure": shared_infrastructure, "risk": _max_risk([row["risk"] for row in linked_rows]),
            "exactRisk": _max_risk([row["risk"] for row in exact_rows + unspecified_rows]),
            "adjacencyRisk": _max_risk([row["risk"] for row in adjacency_rows]),
            "categories": sorted({_text(row.get("category")) for row in linked_rows if _text(row.get("category"))}),
            "sources": sorted({_text(row.get("source")) for row in linked_rows if _text(row.get("source"))}),
            "indicatorIds": ids, "matchedIndicators": linked_rows,
            "variantIds": variant_ids, "pluginIds": _safe_ints(match.get("pluginIds") or resolution.get("pluginIds") or relationship.get("pluginIds")),
            "classifications": classifications, "purposes": purposes, "wellKnown": context, "recognised": recognised,
            "firstObservedUtc": _text(relationship.get("firstSeenUtc") or relationship.get("firstObservedAtUtc")),
            "lastObservedUtc": _text(relationship.get("lastSeenUtc") or relationship.get("lastObservedAtUtc")),
            "timeScope": "published-corpus" if relationship.get("firstSeenUtc") or relationship.get("firstObservedAtUtc") else "unavailable",
            "hideByDefault": bool(context.get("hideByDefault")),
            "active": any(bool(row.get("active", True)) for row in linked) if linked else False,
        })

    assets_by_variant: dict[int, dict[str, Any]] = {}
    if all_variant_ids and hasattr(inspector, "workbench_assets_for_variants"):
        try:
            for raw in inspector.workbench_assets_for_variants(all_variant_ids):
                if isinstance(raw, Mapping):
                    asset = _asset_label(raw)
                    if asset["variantId"]:
                        assets_by_variant[asset["variantId"]] = asset
        except Exception:
            assets_by_variant = {}
    for row in endpoint_inventory:
        row["assets"] = [assets_by_variant[v] for v in row["variantIds"] if v in assets_by_variant][:24]
        row["assetCount"] = len(row["variantIds"])

    endpoint_inventory.sort(key=lambda row: (
        0 if row["exactMatched"] else 1 if row["sharedInfrastructure"] else 2 if row["reputationState"].startswith("unlisted") and not row["recognised"] else 3,
        -RISK_RANK.get(row["exactRisk"] or row["risk"], 0), row["host"].casefold(),
    ))
    exact_matches = [row for row in endpoint_inventory if row["exactMatched"]]
    adjacency_matches = [row for row in endpoint_inventory if row["sharedInfrastructure"]]
    unlisted = [row for row in endpoint_inventory if str(row["reputationState"]).startswith("unlisted")]
    unlisted_recognised = [row for row in unlisted if row["recognised"]]
    unlisted_unrecognised = [row for row in unlisted if not row["recognised"]]
    special_use = [row for row in endpoint_inventory if row["hideByDefault"]]

    corpus_indicators: list[dict[str, Any]] = []
    observed_indicator_ids = {iid for row in endpoint_inventory for iid in row["indicatorIds"]}
    for indicator in indicators:
        iid = _text(indicator.get("indicatorId"))
        linked_endpoints = indicator_to_endpoints.get(iid, [])
        if not linked_endpoints:
            continue
        exact_hosts = sorted({row["host"] for row in linked_endpoints if str(row["matchKind"]).startswith("exact-") or row["matchKind"] == "linked-unspecified"})
        adjacency_hosts = sorted({row["host"] for row in linked_endpoints if row["matchKind"] == "resolved-ip-adjacency"})
        variant_ids = sorted({v for endpoint in endpoint_inventory if iid in endpoint["indicatorIds"] for v in endpoint["variantIds"]})
        corpus_indicators.append({
            **dict(indicator), "exactHosts": exact_hosts, "adjacencyHosts": adjacency_hosts,
            "corpusHosts": sorted(set(exact_hosts) | set(adjacency_hosts)), "variantIds": variant_ids,
            "assets": [assets_by_variant[v] for v in variant_ids if v in assets_by_variant][:24],
            "exact": bool(exact_hosts), "sharedInfrastructureOnly": bool(adjacency_hosts) and not exact_hosts,
        })
    corpus_indicators.sort(key=lambda row: (
        0 if row.get("exact") else 1, -RISK_RANK.get(_text(row.get("risk")).casefold(), 0), _text(row.get("value")).casefold()
    ))

    indicator_rows = sorted(
        indicators,
        key=lambda row: (-RISK_RANK.get(_text(row.get("risk")).casefold(), 0), _text(row.get("source")).casefold(), _text(row.get("value"))),
    )[:max(1, min(int(limit), 5000))]
    inactive = [dict(row) for row in indicators if not bool(row.get("active", True))]
    inactive.sort(key=lambda row: (_text(row.get("retractedAtUtc") or row.get("retiredAtUtc") or row.get("lastSeen")), _text(row.get("value"))), reverse=True)
    feed_rows = [_feed_projection(row, snapshot_generated_at=_text(doc.get("generatedAtUtc"))) for row in doc.get("feeds") or [] if isinstance(row, Mapping)]
    degraded_feeds = [row for row in feed_rows if _text(row.get("freshnessState")) in {"degraded", "attention", "stale"}]
    exact_risks = Counter(_text(row.get("exactRisk") or "none") for row in exact_matches)
    state_counts = Counter(_text(row.get("reputationState")) for row in endpoint_inventory)
    strict_high = sum(RISK_RANK.get(_text(row.get("exactRisk")), 0) >= RISK_RANK["high"] for row in exact_matches)
    adjacency_high = sum(RISK_RANK.get(_text(row.get("adjacencyRisk")), 0) >= RISK_RANK["high"] for row in adjacency_matches)

    return {
        "schema": SCHEMA, "readOnly": True, "mutationAuthority": "none", "policyInput": False, "currentVersionOnly": True,
        "reputationRevision": _text(doc.get("reputationRevision")), "generatedAtUtc": _text(doc.get("generatedAtUtc")),
        "policy": _text(doc.get("policy")), "counts": dict(doc.get("counts") or {}),
        "summary": {
            "observedHosts": len(endpoint_inventory), "frozenMatchedHosts": sum(bool(row["matched"]) for row in endpoint_inventory),
            "exactMatchedHosts": len(exact_matches), "sharedInfrastructureHosts": len(adjacency_matches),
            "strictHighRiskHosts": strict_high, "adjacencyHighRiskHosts": adjacency_high,
            "criticalExactHosts": int(exact_risks.get("critical", 0)), "highExactHosts": int(exact_risks.get("high", 0)),
            "unlistedHosts": len(unlisted), "unlistedRecognisedHosts": len(unlisted_recognised), "unlistedUnrecognisedHosts": len(unlisted_unrecognised),
            "specialUseHosts": len(special_use),
            "unresolvedHosts": int(state_counts.get("resolution-failed", 0) + state_counts.get("no-public-address", 0)),
            "retainedDnsHosts": sum(_text(row.get("resolutionStatus")) == "retained-previous" for row in endpoint_inventory),
            "matchedCurrentVariants": len({v for row in exact_matches for v in row["variantIds"]}),
            "activeFeeds": sum(_text(row.get("status")) == "complete" for row in feed_rows), "degradedFeeds": len(degraded_feeds),
            "feeds": len(feed_rows), "indicators": len(indicators), "activeIndicators": sum(bool(row.get("active", True)) for row in indicators),
            "inactiveIndicators": len(inactive), "corpusIndicators": len(corpus_indicators),
            "unobservedIndicators": max(0, len(indicators) - len(observed_indicator_ids)),
        },
        "brief": {
            "headline": f"{strict_high} exact high/critical feed intersection(s)" if strict_high else "No exact high/critical IOC identity hits in the current corpus",
            "exactHighRiskHosts": strict_high, "sharedInfrastructureHighRiskHosts": adjacency_high,
            "unrecognisedUnlistedHosts": len(unlisted_unrecognised),
            "message": "Resolved-IP overlap on a hostname is shared-infrastructure context, not an endpoint identity hit. Unlisted means only no match in the bounded active feeds.",
        },
        "feeds": feed_rows, "endpointInventory": endpoint_inventory, "endpointMatches": exact_matches,
        "sharedInfrastructureMatches": adjacency_matches, "corpusIndicators": corpus_indicators,
        "inactiveIndicators": inactive[:100], "indicators": indicator_rows,
        "indicatorRowsTruncated": len(indicators) > len(indicator_rows),
        "note": "DeltaScope separates exact IOC identity hits from DNS/shared-infrastructure adjacency. This changes presentation only: the immutable frozen reputation snapshot and SRL policy inputs remain untouched. UNLISTED is not a safe/clean verdict. The configured feeds are threat feeds, not an allow-list, so DeltaScope does not invent a 'listed clean' category.",
    }
