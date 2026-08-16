#!/usr/bin/env python3
"""Validate issue-provided PluginMaster URLs and source-repository overrides."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import enrich_metadata
from source_resolution import source_candidates


MARKER = "omega-source-submission"
FOLLOWUP_RE = re.compile(r"omega-source-followup:([A-Za-z0-9_-]+)")
INTERNAL_RE = re.compile(r"omega-source-internal:([^\s<>]+)")
URL_RE = re.compile(r"https://[^\s<>()\[\]{}]+", re.IGNORECASE)
OVERRIDES_SCHEMA = "omega.source-overrides.v1"
MAX_SUBMITTED_PLUGINS = 5_000


def public_https_url(url: str) -> bool:
    """Accept only HTTPS names that currently resolve entirely to global IPs."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port or 443
    except ValueError:
        return False
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return False
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return False
    try:
        addresses = {item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except (socket.gaierror, OSError):
        return False
    if not addresses:
        return False
    try:
        return all(ipaddress.ip_address(address).is_global for address in addresses)
    except ValueError:
        return False


def github_repository_is_public(url: str, timeout: float = 10.0) -> bool:
    candidates = source_candidates(url)
    if not candidates:
        return False
    parsed = urlparse(candidates[0])
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        return False
    api_url = f"https://api.github.com/repos/{parts[0]}/{parts[1]}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Dalagab-Omega-Source-Submission/1"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(api_url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            document = json.load(response)
        return isinstance(document, dict) and not bool(document.get("private"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return False


def submitted_urls(text: str) -> list[str]:
    urls: list[str] = []
    for raw in URL_RE.findall(str(text or "")):
        url = raw.rstrip(".,;:!?)]}")
        if public_https_url(url) and url not in urls:
            urls.append(url)
    return urls


def eligible(payload: dict) -> bool:
    issue = payload.get("issue") if isinstance(payload.get("issue"), dict) else {}
    body = str(issue.get("body") or "")
    title = str(issue.get("title") or "")
    return MARKER in body or title.lower().startswith("source submission:")


def source_record(url: str) -> dict:
    host = urlparse(url).netloc.lower()
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    return {
        "id": f"community-{digest}",
        "name": f"Community source ({host})",
        "url": url,
        "description": "Community-submitted Dalamud PluginMaster source; automatically validated before collection.",
        "isOfficial": False,
        "enabledByDefault": False,
        "integrateWithDalamudByDefault": False,
    }


def load_sources(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def load_overrides(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    raw = data.get("overrides") if isinstance(data, dict) and data.get("schema") == OVERRIDES_SCHEMA else data
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in raw.items():
        candidates = source_candidates(str(value or ""))
        if candidates:
            out[str(key)] = candidates[0]
    return out


def save_overrides(path: Path, overrides: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"schema": OVERRIDES_SCHEMA, "overrides": dict(sorted(overrides.items()))}
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def process_followup(issue_body: str, comment_body: str, overrides_path: Path) -> dict:
    match = FOLLOWUP_RE.search(issue_body)
    if not match:
        return {}
    candidates = source_candidates(*submitted_urls(comment_body))
    candidates = [candidate for candidate in candidates if github_repository_is_public(candidate)]
    if not candidates:
        return {"status": "needs-url", "message": "Reply with a public, readable GitHub repository URL for this plugin's source"}
    overrides = load_overrides(overrides_path)
    key, url = match.group(1), candidates[0]
    internal_match = INTERNAL_RE.search(issue_body)
    internal_name = internal_match.group(1) if internal_match else ""
    if overrides.get(key) == url:
        return {"status": "already-added", "url": url, "overrideKey": key, "internalName": internal_name, "message": "This source override is already queued"}
    overrides[key] = url
    save_overrides(overrides_path, overrides)
    return {
        "status": "accepted-override",
        "url": url,
        "overrideKey": key,
        "internalName": internal_name,
        "message": "Queued as the public source repository for this plugin/source pair",
    }


def process(payload: dict, path: Path, overrides_path: Path) -> dict:
    if not eligible(payload):
        return {"status": "ignored", "message": "Issue is not an Omega source submission"}
    issue = payload.get("issue") if isinstance(payload.get("issue"), dict) else {}
    issue_body = str(issue.get("body") or "")
    comment_body = str((payload.get("comment") or {}).get("body") or "")
    followup = process_followup(issue_body, comment_body, overrides_path)
    if followup:
        return followup

    text = "\n".join((issue_body, comment_body))
    urls = submitted_urls(text)
    if not urls:
        return {"status": "needs-url", "message": "No public HTTPS source URL was provided"}
    existing = load_sources(path)
    existing_urls = {str(item.get("url") or "") for item in existing if isinstance(item, dict)}
    for url in urls:
        if url in existing_urls:
            return {"status": "already-added", "url": url, "message": "This source is already collected"}
        # The normal PluginMaster parser is reused so submitted feeds must pass the
        # same JSON/root/identity rules as production catalog ingestion.
        result = enrich_metadata.fetch_source(
            {"url": url, "provider": "community", "kind": "submitted"},
            timeout=15.0,
            max_bytes=16 * 1024 * 1024,
            url_validator=public_https_url,
        )
        plugin_count = int(result.get("pluginCount") or 0)
        if result.get("ok") and 0 < plugin_count <= MAX_SUBMITTED_PLUGINS:
            existing.append(source_record(url))
            existing.sort(key=lambda item: str(item.get("url") or "").lower())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
            return {"status": "accepted", "url": url, "pluginCount": plugin_count, "message": "Validated as a Dalamud PluginMaster source"}
        if result.get("ok") and plugin_count > MAX_SUBMITTED_PLUGINS:
            return {"status": "rejected", "message": f"Source contains {plugin_count} plugins, above the automatic submission limit of {MAX_SUBMITTED_PLUGINS}"}
    return {"status": "rejected", "message": "No supplied URL was a readable Dalamud PluginMaster source"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Process an Omega source-submission issue event")
    parser.add_argument("--event", required=True)
    parser.add_argument("--sources", default="sources/community-sources.json")
    parser.add_argument("--overrides", default="sources/source-overrides.json")
    parser.add_argument("--result", required=True)
    parser.add_argument("--url", default="", help="Manual workflow-dispatch source URL")
    args = parser.parse_args()
    payload = json.loads(Path(args.event).read_text(encoding="utf-8"))
    if args.url:
        payload = {"issue": {"title": "Source submission: manual", "body": args.url}}
    outcome = process(payload, Path(args.sources), Path(args.overrides))
    Path(args.result).write_text(json.dumps(outcome, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outcome))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
