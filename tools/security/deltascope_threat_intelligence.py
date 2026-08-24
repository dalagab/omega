"""Read-only DeltaScope projection of frozen URL/domain/IP threat intelligence."""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

SCHEMA = "omega.deltascope.threat-intelligence.v1"
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


def project_threat_intelligence(inspector: Any, *, limit: int = 500) -> dict[str, Any]:
    """Project the frozen reputation snapshot into a corpus endpoint inventory.

    ``endpointInventory`` contains every currently observed host in the frozen DNS
    resolution table.  A row with no matching IOC is deliberately labelled
    ``unlisted`` rather than safe/clean: absence from a bounded feed is not a
    reputation verdict.  ``endpointMatches`` remains as a compatibility subset for
    callers that only need active feed matches.
    """
    doc = inspector.threat_intelligence() if hasattr(inspector, "threat_intelligence") else {}
    if not isinstance(doc, Mapping):
        doc = {}
    indicators = [dict(row) for row in doc.get("indicators") or [] if isinstance(row, Mapping)]
    matches = [dict(row) for row in doc.get("observedEndpointMatches") or [] if isinstance(row, Mapping)]
    resolutions = [dict(row) for row in doc.get("observedEndpointResolutions") or [] if isinstance(row, Mapping)]
    resolution_by_host = {
        str(row.get("host") or "").casefold(): row
        for row in resolutions if row.get("host")
    }
    match_by_host = {
        str(row.get("host") or "").casefold(): row
        for row in matches if row.get("host")
    }
    by_id = {str(row.get("indicatorId") or ""): row for row in indicators if row.get("indicatorId")}

    endpoint_inventory: list[dict[str, Any]] = []
    all_hosts = sorted(set(resolution_by_host) | set(match_by_host))
    for key in all_hosts:
        resolution = resolution_by_host.get(key, {})
        match = match_by_host.get(key, {})
        host = str(resolution.get("host") or match.get("host") or "")
        ids = [str(v) for v in match.get("indicatorIds") or [] if str(v)]
        linked = [by_id[i] for i in ids if i in by_id]
        matched = bool(ids or match)
        resolution_status = str(resolution.get("resolutionStatus") or ("resolved" if match.get("resolvedIps") else "unknown"))
        if matched:
            state = "matched"
        elif resolution_status in {"resolution-failed", "no-public-address"}:
            state = resolution_status
        elif resolution_status == "retained-previous":
            state = "unlisted-retained-dns"
        else:
            state = "unlisted"
        endpoint_inventory.append({
            "host": host,
            "urlSamples": list(match.get("urlSamples") or resolution.get("urlSamples") or [])[:16],
            "resolvedIps": list(match.get("resolvedIps") or resolution.get("resolvedIps") or []),
            "resolutionStatus": resolution_status,
            "reputationState": state,
            "matched": matched,
            "risk": str(match.get("risk") or "none").casefold(),
            "categories": list(match.get("categories") or []),
            "sources": list(match.get("sources") or []),
            "indicatorIds": ids,
            "variantIds": _safe_ints(match.get("variantIds") or resolution.get("variantIds")),
            "pluginIds": _safe_ints(match.get("pluginIds") or resolution.get("pluginIds")),
            "lastSeen": max((str(row.get("lastSeen") or "") for row in linked), default=""),
            "active": any(bool(row.get("active", True)) for row in linked) if linked else False,
        })
    endpoint_inventory.sort(key=lambda row: (-RISK_RANK.get(row["risk"], 0), not row["matched"], row["host"].casefold()))
    endpoint_matches = [row for row in endpoint_inventory if row["matched"]]

    indicator_rows = sorted(
        indicators,
        key=lambda row: (-RISK_RANK.get(str(row.get("risk") or "none").casefold(), 0), str(row.get("source") or "").casefold(), str(row.get("value") or "")),
    )[:max(1, min(int(limit), 5000))]
    risk_counts = Counter(str(row.get("risk") or "none").casefold() for row in endpoint_matches)
    state_counts = Counter(str(row.get("reputationState") or "") for row in endpoint_inventory)
    feed_rows = [dict(row) for row in doc.get("feeds") or [] if isinstance(row, Mapping)]
    degraded_feeds = [row for row in feed_rows if str(row.get("status") or "") not in {"complete", "not-configured"}]
    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "currentVersionOnly": True,
        "reputationRevision": str(doc.get("reputationRevision") or ""),
        "generatedAtUtc": str(doc.get("generatedAtUtc") or ""),
        "policy": str(doc.get("policy") or ""),
        "counts": dict(doc.get("counts") or {}),
        "summary": {
            "observedHosts": len(endpoint_inventory),
            "matchedHosts": len(endpoint_matches),
            "unlistedHosts": int(state_counts.get("unlisted", 0) + state_counts.get("unlisted-retained-dns", 0)),
            "unresolvedHosts": int(state_counts.get("resolution-failed", 0) + state_counts.get("no-public-address", 0)),
            "retainedDnsHosts": sum(str(row.get("resolutionStatus") or "") == "retained-previous" for row in endpoint_inventory),
            "matchedCurrentVariants": len({v for row in endpoint_matches for v in row["variantIds"]}),
            "criticalHosts": int(risk_counts.get("critical", 0)),
            "highHosts": int(risk_counts.get("high", 0)),
            "activeFeeds": sum(str(row.get("status") or "") == "complete" for row in feed_rows),
            "degradedFeeds": len(degraded_feeds),
            "feeds": len(feed_rows),
            "indicators": len(indicators),
            "activeIndicators": sum(bool(row.get("active", True)) for row in indicators),
        },
        "feeds": feed_rows,
        "endpointInventory": endpoint_inventory,
        "endpointMatches": endpoint_matches,
        "indicators": indicator_rows,
        "indicatorRowsTruncated": len(indicators) > len(indicator_rows),
        "note": "UNLISTED means no active match in the bounded frozen feeds; it is not a safe/clean verdict. Feed-backed matches are static context, not proof of runtime contact. Potential exfiltration requires an SRL correlation with sensitive-data capability evidence.",
    }
