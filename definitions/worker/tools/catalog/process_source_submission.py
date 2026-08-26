#!/usr/bin/env python3
"""Validate issue-provided PluginMaster URLs and source-repository overrides."""
from __future__ import annotations

import argparse
from collections import defaultdict
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
import sigmascope
from source_resolution import source_candidates


MARKER = "omega-source-submission"
FOLLOWUP_RE = re.compile(r"omega-source-followup:([A-Za-z0-9_-]+)")
OVERRIDE_RE = re.compile(r"omega-source-override:([A-Za-z0-9_-]+)")
INTERNAL_RE = re.compile(r"omega-source-internal:([^\s<>]+)")
VERSION_RE = re.compile(r"omega-source-version:([^\s<>]*)")
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


def issue_has_label(issue: dict, name: str) -> bool:
    wanted = str(name or "").casefold()
    for item in issue.get("labels") or []:
        label = str(item.get("name") or "") if isinstance(item, dict) else str(item or "")
        if label.casefold() == wanted:
            return True
    return False


def validate_source_repository_identity(url: str, internal_name: str, assembly_version: str = "") -> dict:
    """Use Sigmascope's bounded source reader to validate a submitted source mapping.

    Community replies may only persist a security source override when the public
    repository actually contains a Dalamud manifest matching the managed follow-up's
    InternalName. Version matches raise provenance confidence but are not required:
    historical tags are often absent even in the correct original repository.
    """
    candidate_hits: dict[str, list[str]] = defaultdict(list)
    result = sigmascope._fetch_source_candidate(
        url,
        os.environ.get("GITHUB_TOKEN", ""),
        candidate_hits,
        internal_name,
        internal_name,
        assembly_version,
        (),
    )
    provenance = result.get("provenance") if isinstance(result.get("provenance"), dict) else {}
    return {
        "ok": bool(result.get("available")) and bool(provenance.get("identityMatched")),
        "repository": str(result.get("repository") or url),
        "commit": str(result.get("commit") or ""),
        "identityMatched": bool(provenance.get("identityMatched")),
        "versionMatched": bool(provenance.get("versionMatched")),
        "selectedRef": str(provenance.get("selectedRef") or ""),
        "error": str(result.get("error") or "")[:500],
    }


def process_followup(issue: dict, comment_body: str, overrides_path: Path) -> dict:
    issue_body = str(issue.get("body") or "")
    match = FOLLOWUP_RE.search(issue_body)
    if not match:
        return {}
    if not issue_has_label(issue, "omega-source-followup"):
        return {
            "status": "rejected",
            "kind": "override",
            "message": "Source override markers are accepted only on Omega-managed source-followup issues",
        }
    candidates = source_candidates(*submitted_urls(comment_body))
    candidates = [candidate for candidate in candidates if github_repository_is_public(candidate)]
    if not candidates:
        return {"status": "needs-url", "kind": "override", "message": "Reply with a public, readable GitHub repository URL for this plugin's source"}
    internal_match = INTERNAL_RE.search(issue_body)
    internal_name = internal_match.group(1) if internal_match else ""
    version_match = VERSION_RE.search(issue_body)
    assembly_version = version_match.group(1) if version_match else ""
    if not internal_name:
        return {"status": "rejected", "kind": "override", "message": "Managed source follow-up is missing its plugin identity marker"}

    validation = validate_source_repository_identity(candidates[0], internal_name, assembly_version)
    if not validation["ok"]:
        return {
            "status": "rejected",
            "kind": "override",
            "url": candidates[0],
            "internalName": internal_name,
            "message": "The repository is public but Sigmascope could not confirm a matching Dalamud plugin identity in its source tree",
            "validation": validation,
        }

    overrides = load_overrides(overrides_path)
    keys = [match.group(1)]
    for override_match in OVERRIDE_RE.finditer(issue_body):
        key = override_match.group(1)
        if key not in keys:
            keys.append(key)
    url = str(validation.get("repository") or candidates[0])
    changed = [key for key in keys if overrides.get(key) != url]
    if not changed:
        return {
            "status": "already-added", "kind": "override", "url": url, "overrideKey": keys[0], "overrideKeys": keys,
            "internalName": internal_name, "message": "This validated source override is already queued for all affected catalog mirrors", "validation": validation,
        }
    for key in keys:
        overrides[key] = url
    save_overrides(overrides_path, overrides)
    return {
        "status": "accepted-override",
        "kind": "override",
        "url": url,
        "overrideKey": keys[0],
        "overrideKeys": keys,
        "internalName": internal_name,
        "assemblyVersion": assembly_version,
        "validation": validation,
        "message": f"Validated and queued as the public source repository for {len(keys)} affected catalog mirror mapping(s)",
    }


def process(payload: dict, path: Path, overrides_path: Path) -> dict:
    if not eligible(payload):
        return {"status": "ignored", "message": "Issue is not an Omega source submission"}
    issue = payload.get("issue") if isinstance(payload.get("issue"), dict) else {}
    issue_body = str(issue.get("body") or "")
    comment_body = str((payload.get("comment") or {}).get("body") or "")
    followup = process_followup(issue, comment_body, overrides_path)
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
            return {"status": "already-added", "kind": "feed", "url": url, "message": "This source is already collected"}
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
            return {"status": "accepted", "kind": "feed", "url": url, "pluginCount": plugin_count, "message": "Validated and scraped as a Dalamud PluginMaster source"}
        if result.get("ok") and plugin_count > MAX_SUBMITTED_PLUGINS:
            return {"status": "rejected", "kind": "feed", "message": f"Source contains {plugin_count} plugins, above the automatic submission limit of {MAX_SUBMITTED_PLUGINS}"}
    return {"status": "rejected", "kind": "feed", "message": "No supplied URL was a readable Dalamud PluginMaster source"}


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
