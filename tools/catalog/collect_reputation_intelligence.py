#!/usr/bin/env python3
"""Collect frozen URL/domain/IP threat intelligence for Omega Definitions.

The collector is deliberately separate from SigmaScope artifact analysis.  It fetches
bounded public threat-intelligence feeds, resolves hostnames already observed in current
Security Evidence v2, and freezes the resulting indicator/match table.  SRL consumes the
frozen result during rule-only reprojection; scanner workers never perform live reputation
queries while evaluating a plugin.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
SECURITY_DIR = REPO_ROOT / "tools" / "security"
import sys
if str(SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_DIR))
from evidence_v2_inspector import V2SigmascopeInspector  # noqa: E402

SCHEMA = "omega.reputation-definitions.v2"
REVISION_PREFIX = "reputation-v2"
USER_AGENT = "Dalagab-Omega-Reputation-Collector/1.0 (+https://github.com/dalagab/omega)"
FEODO_RECOMMENDED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
HTTP_ATTEMPTS = 3
MAX_ENDPOINT_HOSTS = 5000
MAX_INDICATORS = 100_000
MAX_DNS_IPS = 16
RISK_RANK = {"none": 0, "informational": 1, "caution": 2, "high": 3, "critical": 4}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _request(request: urllib.request.Request, timeout: float) -> bytes:
    last: Exception | None = None
    for attempt in range(HTTP_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (OSError, urllib.error.URLError) as exc:
            last = exc
            if attempt + 1 < HTTP_ATTEMPTS:
                time.sleep(1.5 * (2 ** attempt))
    assert last is not None
    raise last


def get_json(url: str, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    return json.loads(_request(req, timeout).decode("utf-8"))


def post_json(url: str, payload: dict[str, Any], timeout: float, headers: dict[str, str] | None = None) -> Any:
    all_headers = {"Accept": "application/json", "Content-Type": "application/json", "User-Agent": USER_AGENT}
    all_headers.update(headers or {})
    req = urllib.request.Request(url, data=canonical(payload), headers=all_headers, method="POST")
    return json.loads(_request(req, timeout).decode("utf-8"))


def _normalize_ip(value: Any) -> str:
    text = str(value or "").strip().strip("[]")
    if not text:
        return ""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if not address.is_global:
        return ""
    return address.compressed


def _normalize_host(value: Any) -> str:
    text = str(value or "").strip().rstrip(".").casefold()
    if not text or len(text) > 253:
        return ""
    if _normalize_ip(text):
        return text
    try:
        ascii_host = text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""
    if not ascii_host or any(not part or len(part) > 63 for part in ascii_host.split(".")):
        return ""
    return ascii_host


def _normalize_url(value: Any) -> tuple[str, str]:
    text = str(value or "").strip()
    if not text:
        return "", ""
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return "", ""
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return "", ""
    host = _normalize_host(parsed.hostname)
    if not host:
        return "", ""
    # Keep the exact path/query because an IOC may be URL-specific, but never retain
    # credentials/fragments from the feed transport.
    netloc = host
    if parsed.port:
        netloc += f":{parsed.port}"
    clean = urllib.parse.urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/", parsed.query, ""))
    return clean, host


def _indicator_id(source: str, indicator_type: str, value: str) -> str:
    return "ioc-" + digest({"source": source, "type": indicator_type, "value": value})[:24]


def _risk_max(values: Iterable[str]) -> str:
    best = "none"
    for value in values:
        normalized = str(value or "none").casefold()
        if RISK_RANK.get(normalized, 0) > RISK_RANK.get(best, 0):
            best = normalized
    return best


def _indicator(*, source: str, indicator_type: str, value: str, risk: str, category: str,
               active: bool = True, first_seen: str = "", last_seen: str = "", malware: str = "",
               host: str = "", resolved_ips: Iterable[str] = (), source_url: str = "",
               source_record_id: str = "", confidence: str = "high", port: int = 0) -> dict[str, Any]:
    ips = sorted({_normalize_ip(ip) for ip in resolved_ips if _normalize_ip(ip)})
    return {
        "indicatorId": _indicator_id(source, indicator_type, value),
        "indicatorType": indicator_type,
        "value": value,
        "host": _normalize_host(host),
        "resolvedIps": ips,
        "risk": risk,
        "category": category,
        "active": bool(active),
        "confidence": confidence,
        "firstSeen": first_seen,
        "lastSeen": last_seen,
        "malware": malware,
        "port": max(0, int(port or 0)),
        "source": source,
        "sourceUrl": source_url,
        "sourceRecordId": source_record_id,
    }


def collect_feodo(timeout: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payload = get_json(FEODO_RECOMMENDED_URL, timeout)
    if not isinstance(payload, list):
        raise ValueError("Feodo recommended blocklist is not a JSON array")
    indicators: list[dict[str, Any]] = []
    for row in payload:
        if not isinstance(row, dict):
            continue
        ip = _normalize_ip(row.get("ip_address"))
        if not ip:
            continue
        status = str(row.get("status") or "").casefold()
        indicators.append(_indicator(
            source="Feodo Tracker",
            indicator_type="ip",
            value=ip,
            risk="critical",
            category="botnet-c2",
            active=status == "online" or not status,
            first_seen=str(row.get("first_seen") or ""),
            last_seen=str(row.get("last_online") or ""),
            malware=str(row.get("malware") or ""),
            host=str(row.get("hostname") or ""),
            source_url=FEODO_RECOMMENDED_URL,
            source_record_id=f"{ip}:{int(row.get('port') or 0)}",
            confidence="high",
            port=int(row.get("port") or 0),
        ))
    feed = {
        "id": "feodo-recommended",
        "name": "Feodo Tracker recommended active botnet C2 IP blocklist",
        "source": "abuse.ch / Feodo Tracker",
        "url": FEODO_RECOMMENDED_URL,
        "license": "CC0",
        "required": True,
        "status": "complete",
        "records": len(indicators),
        "categories": ["botnet-c2"],
    }
    return feed, indicators


def _threatfox_risk(threat_type: str) -> str:
    value = threat_type.casefold()
    if value in {"botnet_cc", "c2"}:
        return "critical"
    if value in {"payload_delivery", "malware_download"}:
        return "high"
    return "high"


def collect_threatfox(auth_key: str, timeout: float, days: int = 7) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    response = post_json(
        THREATFOX_URL,
        {"query": "get_iocs", "days": max(1, min(int(days), 7))},
        timeout,
        headers={"Auth-Key": auth_key},
    )
    if not isinstance(response, dict) or str(response.get("query_status") or "") != "ok":
        raise ValueError(f"ThreatFox API returned {response.get('query_status') if isinstance(response, dict) else type(response).__name__}")
    rows = response.get("data") if isinstance(response.get("data"), list) else []
    indicators: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ioc = str(row.get("ioc") or "").strip()
        ioc_type = str(row.get("ioc_type") or "").casefold()
        threat_type = str(row.get("threat_type") or "unknown").casefold()
        value = ""
        host = ""
        resolved: list[str] = []
        indicator_type = ioc_type
        port = 0
        if ioc_type in {"ip:port", "ip_port"}:
            raw_ip, _, raw_port = ioc.rpartition(":")
            value = _normalize_ip(raw_ip)
            indicator_type = "ip"
            try:
                port = int(raw_port)
            except ValueError:
                port = 0
        elif ioc_type == "ip":
            value = _normalize_ip(ioc)
        elif ioc_type == "domain":
            value = _normalize_host(ioc)
            host = value
        elif ioc_type == "url":
            value, host = _normalize_url(ioc)
        else:
            continue
        if not value:
            continue
        indicators.append(_indicator(
            source="ThreatFox",
            indicator_type=indicator_type,
            value=value,
            risk=_threatfox_risk(threat_type),
            category=threat_type.replace("_", "-"),
            active=True,
            first_seen=str(row.get("first_seen") or ""),
            last_seen=str(row.get("last_seen") or ""),
            malware=str(row.get("malware_printable") or row.get("malware") or ""),
            host=host,
            resolved_ips=resolved,
            source_url="https://threatfox.abuse.ch/",
            source_record_id=str(row.get("id") or ""),
            confidence="high",
            port=port,
        ))
    feed = {
        "id": "threatfox-recent",
        "name": "ThreatFox recent confirmed IOC feed",
        "source": "abuse.ch / ThreatFox",
        "url": "https://threatfox.abuse.ch/",
        "license": "abuse.ch community API / fair use",
        "required": False,
        "status": "complete",
        "records": len(indicators),
        "categories": sorted({str(item.get("category") or "") for item in indicators if item.get("category")}),
    }
    return feed, indicators


def _current_endpoint_rows(evidence_root: Path | None) -> list[dict[str, Any]]:
    if evidence_root is None or not (evidence_root / "index.json").is_file():
        return []
    inspector = V2SigmascopeInspector(root=evidence_root)
    try:
        relationships = inspector.workbench_relationship_index()
        return [dict(row) for row in relationships.get("endpoints") or [] if isinstance(row, dict)]
    finally:
        inspector.close()


def _previous_resolution_map(previous: dict[str, Any] | None) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for row in (previous or {}).get("observedEndpointResolutions") or []:
        if not isinstance(row, dict):
            continue
        host = _normalize_host(row.get("host"))
        if host:
            result[host] = sorted({_normalize_ip(ip) for ip in row.get("resolvedIps") or [] if _normalize_ip(ip)})
    return result


def resolve_host(host: str) -> list[str]:
    if _normalize_ip(host):
        return [_normalize_ip(host)]
    rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    ips: set[str] = set()
    for row in rows:
        sockaddr = row[4]
        if not sockaddr:
            continue
        ip = _normalize_ip(sockaddr[0])
        if ip:
            ips.add(ip)
        if len(ips) >= MAX_DNS_IPS:
            break
    return sorted(ips)


def resolve_observed_endpoints(rows: list[dict[str, Any]], previous: dict[str, Any] | None) -> list[dict[str, Any]]:
    previous_map = _previous_resolution_map(previous)
    hosts: dict[str, dict[str, Any]] = {}
    for row in rows:
        host = _normalize_host(row.get("host"))
        if not host:
            continue
        item = hosts.setdefault(host, {"host": host, "urlSamples": set(), "variantIds": set(), "pluginIds": set()})
        item["urlSamples"].update(str(v) for v in row.get("urlSamples") or [] if str(v))
        item["variantIds"].update(int(v) for v in row.get("variantIds") or [] if int(v) > 0)
        item["pluginIds"].update(int(v) for v in row.get("pluginIds") or [] if int(v) > 0)
    result: list[dict[str, Any]] = []
    for host in sorted(hosts, key=str.casefold)[:MAX_ENDPOINT_HOSTS]:
        source = hosts[host]
        status = "resolved"
        try:
            ips = resolve_host(host)
            if not ips:
                status = "no-public-address"
        except OSError:
            ips = previous_map.get(host, [])
            status = "retained-previous" if ips else "resolution-failed"
        result.append({
            "host": host,
            "resolvedIps": ips,
            "resolutionStatus": status,
            "urlSamples": sorted(source["urlSamples"], key=str.casefold)[:16],
            "variantIds": sorted(source["variantIds"]),
            "pluginIds": sorted(source["pluginIds"]),
        })
    return result


def _indicator_indexes(indicators: list[dict[str, Any]]) -> dict[str, dict[str, list[str]]]:
    by_ip: dict[str, set[str]] = {}
    by_host: dict[str, set[str]] = {}
    by_url: dict[str, set[str]] = {}
    for row in indicators:
        if not bool(row.get("active", True)):
            continue
        iid = str(row.get("indicatorId") or "")
        typ = str(row.get("indicatorType") or "")
        value = str(row.get("value") or "")
        if typ == "ip" and value:
            by_ip.setdefault(value, set()).add(iid)
        if typ == "domain" and value:
            by_host.setdefault(value.casefold(), set()).add(iid)
        if typ == "url" and value:
            by_url.setdefault(value, set()).add(iid)
            host = _normalize_host(row.get("host"))
            if host:
                by_host.setdefault(host, set()).add(iid)
        for ip in row.get("resolvedIps") or []:
            normalized = _normalize_ip(ip)
            if normalized:
                by_ip.setdefault(normalized, set()).add(iid)
    return {
        "byIp": {k: sorted(v) for k, v in sorted(by_ip.items())},
        "byHost": {k: sorted(v) for k, v in sorted(by_host.items())},
        "byUrl": {k: sorted(v) for k, v in sorted(by_url.items())},
    }


def _endpoint_matches(resolutions: list[dict[str, Any]], indicators: list[dict[str, Any]], indexes: dict[str, Any]) -> list[dict[str, Any]]:
    by_id = {str(row.get("indicatorId") or ""): row for row in indicators}
    by_ip = indexes.get("byIp") if isinstance(indexes.get("byIp"), dict) else {}
    by_host = indexes.get("byHost") if isinstance(indexes.get("byHost"), dict) else {}
    by_url = indexes.get("byUrl") if isinstance(indexes.get("byUrl"), dict) else {}
    matches: list[dict[str, Any]] = []
    for row in resolutions:
        ids: set[str] = set()
        host = _normalize_host(row.get("host"))
        if host:
            ids.update(by_host.get(host) or [])
        for ip in row.get("resolvedIps") or []:
            ids.update(by_ip.get(str(ip)) or [])
        for url in row.get("urlSamples") or []:
            clean, _ = _normalize_url(url)
            if clean:
                ids.update(by_url.get(clean) or [])
        matched = [by_id[iid] for iid in sorted(ids) if iid in by_id]
        if not matched:
            continue
        matches.append({
            "host": host,
            "urlSamples": list(row.get("urlSamples") or []),
            "resolvedIps": list(row.get("resolvedIps") or []),
            "risk": _risk_max(str(item.get("risk") or "none") for item in matched),
            "categories": sorted({str(item.get("category") or "") for item in matched if item.get("category")}),
            "sources": sorted({str(item.get("source") or "") for item in matched if item.get("source")}),
            "indicatorIds": [str(item.get("indicatorId") or "") for item in matched],
            "variantIds": list(row.get("variantIds") or []),
            "pluginIds": list(row.get("pluginIds") or []),
        })
    return matches


def _semantic(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": document.get("schema"),
        "feeds": [
            {key: feed.get(key) for key in ("id", "name", "source", "license", "status", "records", "categories")}
            for feed in document.get("feeds") or [] if isinstance(feed, dict)
        ],
        "indicators": document.get("indicators") or [],
        "observedEndpointResolutions": [
            {key: row.get(key) for key in ("host", "resolvedIps", "urlSamples", "variantIds", "pluginIds")}
            for row in document.get("observedEndpointResolutions") or [] if isinstance(row, dict)
        ],
        "observedEndpointMatches": document.get("observedEndpointMatches") or [],
    }


def build_document(*, evidence_root: Path | None, previous: dict[str, Any] | None, timeout: float,
                   abusech_auth_key: str = "", include_threatfox: bool = True) -> dict[str, Any]:
    feeds: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    feed, rows = collect_feodo(timeout)
    feeds.append(feed)
    indicators.extend(rows)
    if include_threatfox and abusech_auth_key:
        try:
            feed, rows = collect_threatfox(abusech_auth_key, timeout)
        except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
            # ThreatFox is supplemental. A failure must not discard a fresh required
            # Feodo snapshot. Preserve prior ThreatFox rows for research visibility,
            # but mark them inactive so SRL cannot treat stale optional-feed data as
            # a currently active IOC match.
            previous_rows = [
                dict(row) for row in (previous or {}).get("indicators") or []
                if isinstance(row, dict) and str(row.get("source") or "") == "ThreatFox"
            ]
            for row in previous_rows:
                row["active"] = False
                row["confidence"] = "retained-previous"
            feeds.append({
                "id": "threatfox-recent", "name": "ThreatFox recent confirmed IOC feed",
                "source": "abuse.ch / ThreatFox", "url": "https://threatfox.abuse.ch/",
                "license": "abuse.ch community API / fair use", "required": False,
                "status": "retained-previous" if previous_rows else "failed",
                "records": len(previous_rows),
                "categories": sorted({str(item.get("category") or "") for item in previous_rows if item.get("category")}),
                "reason": f"{type(exc).__name__}: {exc}",
            })
            indicators.extend(previous_rows)
        else:
            feeds.append(feed)
            indicators.extend(rows)
    elif include_threatfox:
        feeds.append({
            "id": "threatfox-recent", "name": "ThreatFox recent confirmed IOC feed",
            "source": "abuse.ch / ThreatFox", "url": "https://threatfox.abuse.ch/",
            "license": "abuse.ch community API / fair use", "required": False,
            "status": "not-configured", "records": 0, "categories": [],
            "reason": "ABUSECH_AUTH_KEY is not configured; Feodo remains active.",
        })
    if len(indicators) > MAX_INDICATORS:
        raise ValueError(f"reputation indicator count exceeds hard limit {MAX_INDICATORS}")
    # Sort before indexing so IDs and serialized output are stable.
    indicators.sort(key=lambda row: (str(row.get("source") or "").casefold(), str(row.get("indicatorType") or ""), str(row.get("value") or "")))
    endpoint_rows = _current_endpoint_rows(evidence_root)
    resolutions = resolve_observed_endpoints(endpoint_rows, previous)
    indexes = _indicator_indexes(indicators)
    matches = _endpoint_matches(resolutions, indicators, indexes)
    document = {
        "schema": SCHEMA,
        "generatedAtUtc": utc_now(),
        "policy": "Frozen daily threat intelligence. No live URL/IP reputation query occurs while SigmaScope evaluates a plugin.",
        "feeds": feeds,
        "indicators": indicators,
        "observedEndpointResolutions": resolutions,
        "observedEndpointMatches": matches,
        "indexes": indexes,
        "counts": {
            "feeds": len(feeds),
            "activeFeeds": sum(1 for feed in feeds if str(feed.get("status") or "") == "complete"),
            "indicators": len(indicators),
            "activeIndicators": sum(1 for row in indicators if bool(row.get("active", True))),
            "ips": sum(1 for row in indicators if row.get("indicatorType") == "ip"),
            "domains": sum(1 for row in indicators if row.get("indicatorType") == "domain"),
            "urls": sum(1 for row in indicators if row.get("indicatorType") == "url"),
            "observedEndpointHosts": len(resolutions),
            "matchedEndpointHosts": len(matches),
            "matchedCurrentVariants": len({int(v) for row in matches for v in row.get("variantIds") or [] if int(v) > 0}),
        },
    }
    document["reputationRevision"] = f"{REVISION_PREFIX}-{digest(_semantic(document))[:20]}"
    return document


def load_previous(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) and str(value.get("schema") or "").startswith("omega.reputation-definitions.") else None


def collect(*, evidence_root: Path | None, output: Path, previous_path: Path | None = None,
            timeout: float = 20.0, abusech_auth_key: str = "", include_threatfox: bool = True) -> dict[str, Any]:
    previous = load_previous(previous_path)
    retained_previous = False
    try:
        document = build_document(
            evidence_root=evidence_root,
            previous=previous,
            timeout=timeout,
            abusech_auth_key=abusech_auth_key,
            include_threatfox=include_threatfox,
        )
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        if previous is None:
            raise
        document = previous
        retained_previous = True
        reason = f"{type(exc).__name__}: {exc}"
    else:
        reason = ""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {
        "schema": "omega.reputation-collector-result.v1",
        "output": str(output),
        "reputationRevision": str(document.get("reputationRevision") or ""),
        "counts": dict(document.get("counts") or {}),
        "retainedPrevious": retained_previous,
        "reason": reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--without-threatfox", action="store_true")
    parser.add_argument("--abusech-auth-key", default=os.environ.get("ABUSECH_AUTH_KEY", ""))
    args = parser.parse_args()
    try:
        result = collect(
            evidence_root=args.evidence_root.resolve() if args.evidence_root else None,
            output=args.output,
            previous_path=args.previous,
            timeout=args.timeout,
            abusech_auth_key=str(args.abusech_auth_key or ""),
            include_threatfox=not args.without_threatfox,
        )
    except Exception as exc:
        raise SystemExit(f"Reputation collection failed: {type(exc).__name__}: {exc}") from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
