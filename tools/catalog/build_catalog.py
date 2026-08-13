#!/usr/bin/env python3
"""Validate Omega repository candidates and build a directly-importable catalog bundle.

The builder is intentionally deterministic about *bad content*:
- successfully fetched bytes are SHA-256 hashed;
- a hash already in catalog/known-bad-hashes.json is skipped immediately;
- deterministically invalid repository JSON adds its content hash to the bad-hash file;
- HTTP/DNS/timeouts are transient and never poison the denylist.

If a previously bad URL changes on GitHub, its content hash changes and it is evaluated again.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import io
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_REPOSITORY_ENTRIES = 10_000
DEFAULT_MAX_BYTES = 16 * 1024 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_url(value: str) -> str:
    return value.strip().rstrip("/")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return default


def remove_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = min(len(text), i + 2)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def remove_trailing_commas(text: str) -> str:
    chars = list(text)
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < len(chars) and chars[j].isspace():
                j += 1
            if j < len(chars) and chars[j] in "]}":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def tolerant_loads(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(remove_trailing_commas(remove_comments(text)))


def extract_plugin_array(root: Any) -> list[dict]:
    values: Any
    if isinstance(root, list):
        values = root
    elif isinstance(root, dict):
        values = None
        for key, value in root.items():
            if key.lower() in {"plugins", "pluginmaster"} and isinstance(value, list):
                values = value
                break
        if values is None:
            raise ValueError("root is not a plugin array or supported wrapper")
    else:
        raise ValueError("root is not a plugin array or supported wrapper")

    if len(values) > MAX_REPOSITORY_ENTRIES:
        raise ValueError(f"repository exceeds {MAX_REPOSITORY_ENTRIES} entries")

    plugins = [
        x for x in values
        if isinstance(x, dict)
        and str(x.get("Name", "")).strip()
        and str(x.get("InternalName", "")).strip()
    ]
    if not plugins:
        raise ValueError("repository contains no entries with Name + InternalName")
    return plugins


@dataclass(frozen=True)
class SourceCandidate:
    id: str
    name: str
    url: str
    description: str
    is_official: bool = False
    integrate_with_dalamud: bool = False
    origin: str = "curated"
    repository: str = ""
    path: str = ""
    git_blob_sha: str = ""
    git_blob_fresh: bool = False

    def as_definition(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "description": self.description,
            "isOfficial": self.is_official,
            "enabledByDefault": True,
            "integrateWithDalamudByDefault": self.integrate_with_dalamud,
        }


def slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value[:80] or "repository"


def load_curated(path: Path) -> list[SourceCandidate]:
    doc = read_json(path, [])
    result: list[SourceCandidate] = []
    for item in doc if isinstance(doc, list) else []:
        url = normalize_url(str(item.get("url", "")))
        if not url.startswith("https://"):
            continue
        result.append(SourceCandidate(
            id=str(item.get("id", "")).strip() or f"curated-{sha256_text(url)[:12]}",
            name=str(item.get("name", "")).strip() or url,
            url=url,
            description=str(item.get("description", "")).strip(),
            is_official=bool(item.get("isOfficial", False)),
            integrate_with_dalamud=bool(item.get("integrateWithDalamudByDefault", False)),
            origin="curated",
        ))
    return result


def load_discovered(path: Path) -> list[SourceCandidate]:
    doc = read_json(path, {})
    result: list[SourceCandidate] = []
    generated_at = str(doc.get("generatedAtUtc", "")) if isinstance(doc, dict) else ""
    for item in doc.get("items", []) if isinstance(doc, dict) else []:
        repo = str(item.get("repository", "")).strip()
        file_path = str(item.get("path", "")).strip()
        url = normalize_url(str(item.get("rawUrl", "")))
        if not repo or not file_path or not url.startswith("https://"):
            continue
        identity = f"{repo}/{file_path}"
        git_blob_sha = str(item.get("gitBlobSha", ""))
        last_seen = str(item.get("lastSeenUtc", ""))
        git_blob_fresh = bool(git_blob_sha and generated_at and last_seen == generated_at)
        result.append(SourceCandidate(
            id=f"github-{slug(repo)}-{sha256_text(file_path)[:10]}",
            name=f"{repo} — {Path(file_path).name}",
            url=url,
            description="Discovered by the Omega GitHub catalog builder and validated as a Dalamud repository index.",
            origin="github-discovery",
            repository=repo,
            path=file_path,
            git_blob_sha=git_blob_sha,
            git_blob_fresh=git_blob_fresh,
        ))
    return result


def load_known_bad(path: Path) -> tuple[dict, dict[str, dict]]:
    doc = read_json(path, {"schemaVersion": 1, "items": []})
    if not isinstance(doc, dict):
        doc = {"schemaVersion": 1, "items": []}
    items = doc.get("items", []) if isinstance(doc.get("items", []), list) else []
    return doc, {str(x.get("sha256", "")).lower(): x for x in items if str(x.get("sha256", "")).strip()}


def fetch(
    url: str,
    timeout: float,
    max_bytes: int,
    etag: str = "",
    last_modified: str = "",
) -> dict:
    headers = {
        "Accept": "application/json, text/plain;q=0.9, */*;q=0.1",
        "User-Agent": "Dalagab-Omega-Catalog-Builder/1",
    }
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    req = urllib.request.Request(url, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as ex:
        if ex.code == 304:
            return {
                "status": "not-modified",
                "etag": ex.headers.get("ETag", etag),
                "lastModified": ex.headers.get("Last-Modified", last_modified),
            }
        raise

    with response:
        length = response.headers.get("Content-Length")
        if length and int(length) > max_bytes:
            raise ValueError(f"response exceeds {max_bytes} bytes")
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"response exceeds {max_bytes} bytes")
        response_etag = response.headers.get("ETag", "")
        response_last_modified = response.headers.get("Last-Modified", "")

    return {
        "status": "fetched",
        "manifest": raw.decode("utf-8-sig"),
        "sha256": sha256_bytes(raw),
        "etag": response_etag,
        "lastModified": response_last_modified,
    }


def summarize_manifest(manifest: str) -> tuple[int, int]:
    root = tolerant_loads(manifest)
    plugins = extract_plugin_array(root)
    api_values: list[int] = []
    for plugin in plugins:
        try:
            value = int(str(plugin.get("DalamudApiLevel", "0")).strip())
            if value > 0:
                api_values.append(value)
        except ValueError:
            pass
    return len(plugins), max(api_values, default=0)


def load_seed_bundle(path: Path | None) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}

    records: dict[str, dict] = {}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if not name.startswith("catalog-db/") or not name.endswith(".json"):
                    continue
                try:
                    record = json.loads(zf.read(name).decode("utf-8-sig"))
                    if int(record.get("SchemaVersion", 0)) != 1:
                        continue
                    url = normalize_url(str(record.get("Url", "")))
                    manifest = str(record.get("ManifestJson", ""))
                    expected = str(record.get("ContentSha256", "")).lower()
                    if not url.startswith("https://") or not manifest or sha256_text(manifest) != expected:
                        continue
                    summarize_manifest(manifest)
                    records[url.lower()] = record
                except Exception:
                    continue
    except (OSError, zipfile.BadZipFile):
        return {}
    return records


def write_existing_record(out_dir: Path, record: dict) -> Path:
    normalized = normalize_url(str(record.get("Url", "")))
    filename = f"{sha256_text(normalized)}.json"
    path = out_dir / filename
    path.write_text(json.dumps(record, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return path


def write_record(out_dir: Path, source: SourceCandidate, manifest: str, etag: str, last_modified: str, now: str) -> Path:
    normalized = normalize_url(source.url)
    record = {
        "SchemaVersion": 1,
        "Url": normalized,
        "ETag": etag,
        "LastModified": last_modified,
        "ContentSha256": sha256_text(manifest),
        "FetchedAtUtc": now,
        "CheckedAtUtc": now,
        "ManifestJson": manifest,
    }
    filename = f"{sha256_text(normalized)}.json"
    path = out_dir / filename
    path.write_text(json.dumps(record, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return path


def merge_bad_entry(known: dict[str, dict], sha: str, source: SourceCandidate, reason: str, now: str) -> bool:
    sha = sha.lower()
    existing = known.get(sha)
    if existing:
        existing["lastSeenUtc"] = now
        existing["lastUrl"] = source.url
        if source.git_blob_sha and source.git_blob_fresh:
            existing["gitBlobSha"] = source.git_blob_sha
        return False
    known[sha] = {
        "sha256": sha,
        "reason": reason,
        "firstSeenUtc": now,
        "lastSeenUtc": now,
        "lastUrl": source.url,
        "repository": source.repository,
        "path": source.path,
        "gitBlobSha": source.git_blob_sha if source.git_blob_fresh else "",
    }
    return True



def evaluate_source(
    source: SourceCandidate,
    timeout: float,
    max_bytes: int,
    known_bad: dict[str, dict],
    known_bad_git_blobs: set[str],
    previous_record: dict | None = None,
    now: str = "",
) -> dict:
    if source.git_blob_fresh and source.git_blob_sha and source.git_blob_sha.lower() in known_bad_git_blobs:
        return {
            "status": "known-bad-git-blob",
            "gitBlobSha": source.git_blob_sha,
            "reason": "GitHub blob hash is already known to contain a non-repository JSON document",
            "previousRecord": previous_record,
        }

    previous_etag = str(previous_record.get("ETag", "")) if previous_record else ""
    previous_last_modified = str(previous_record.get("LastModified", "")) if previous_record else ""

    try:
        fetched = fetch(source.url, timeout, max_bytes, previous_etag, previous_last_modified)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as ex:
        return {"status": "transient-error", "error": str(ex), "previousRecord": previous_record}
    except Exception as ex:
        return {"status": "fetch-rejected", "error": str(ex), "previousRecord": previous_record}

    if fetched["status"] == "not-modified":
        if previous_record is None:
            return {"status": "transient-error", "error": "received 304 without a seed record"}
        record = dict(previous_record)
        record["CheckedAtUtc"] = now or utc_now()
        if fetched.get("etag"):
            record["ETag"] = fetched["etag"]
        if fetched.get("lastModified"):
            record["LastModified"] = fetched["lastModified"]
        plugins, highest_api = summarize_manifest(str(record["ManifestJson"]))
        return {
            "status": "not-modified",
            "record": record,
            "plugins": plugins,
            "highestApi": highest_api,
        }

    manifest = fetched["manifest"]
    raw_hash = fetched["sha256"]
    etag = fetched.get("etag", "")
    last_modified = fetched.get("lastModified", "")

    known = known_bad.get(raw_hash.lower())
    if known is not None:
        return {
            "status": "known-bad-hash",
            "sha256": raw_hash,
            "reason": known.get("reason", "known bad content"),
            "previousRecord": previous_record,
        }

    try:
        plugins, highest_api = summarize_manifest(manifest)
    except Exception as ex:
        return {
            "status": "new-bad-hash",
            "sha256": raw_hash,
            "reason": f"invalid Dalamud repository index: {ex}",
            "previousRecord": previous_record,
        }

    return {
        "status": "valid",
        "sha256": raw_hash,
        "manifest": manifest,
        "etag": etag,
        "lastModified": last_modified,
        "plugins": plugins,
        "highestApi": highest_api,
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--curated", required=True, type=Path)
    parser.add_argument("--candidates", required=True, type=Path)
    parser.add_argument("--known-bad", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--generated-sources-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--update-known-bad", action="store_true")
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--workers", type=int, default=12,
                        help="Parallel repository fetch/validation workers. Runtime Omega itself remains sequential.")
    parser.add_argument("--seed-bundle", type=Path,
                        help="Optional previous omega-catalog-db.zip used for conditional requests and last-known-good fallback.")
    parser.add_argument("--download-url", default="",
                        help="Public HTTPS URL for omega-catalog-db.zip, embedded in catalog.json.")
    parser.add_argument("--descriptor-url", default="",
                        help="Public HTTPS URL for catalog.json, written to catalog-endpoint.json for client packaging.")
    args = parser.parse_args()

    now = utc_now()
    args.out.mkdir(parents=True, exist_ok=True)
    db_dir = args.out / "catalog-db"
    db_dir.mkdir(parents=True, exist_ok=True)

    known_doc, known_bad = load_known_bad(args.known_bad)
    curated = load_curated(args.curated)
    discovered = load_discovered(args.candidates)
    seed_records = load_seed_bundle(args.seed_bundle)

    ordered: list[SourceCandidate] = []
    seen_urls: set[str] = set()
    for source in curated + discovered:
        normalized = normalize_url(source.url).lower()
        if normalized in seen_urls:
            continue
        seen_urls.add(normalized)
        ordered.append(source)

    statuses: list[dict] = []
    valid_sources: list[SourceCandidate] = []
    new_bad_count = 0

    worker_count = max(1, min(32, args.workers))
    known_snapshot = dict(known_bad)
    known_bad_git_blobs = {
        str(item.get("gitBlobSha", "")).lower()
        for item in known_snapshot.values()
        if str(item.get("gitBlobSha", "")).strip()
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        evaluations = executor.map(
            lambda source: evaluate_source(
                source,
                args.timeout,
                args.max_bytes,
                known_snapshot,
                known_bad_git_blobs,
                seed_records.get(normalize_url(source.url).lower()),
                now,
            ),
            ordered,
        )

        for index, (source, evaluation) in enumerate(zip(ordered, evaluations), 1):
            print(f"[{index}/{len(ordered)}] {source.name}: {source.url} -> {evaluation['status']}")
            status = evaluation["status"]

            if status in {"transient-error", "fetch-rejected"}:
                previous = evaluation.get("previousRecord")
                retained = previous is not None
                if retained:
                    write_existing_record(db_dir, previous)
                    valid_sources.append(source)
                statuses.append({
                    "url": source.url,
                    "name": source.name,
                    "origin": source.origin,
                    "status": status,
                    "error": evaluation.get("error", ""),
                    "retainedLastKnownGood": retained,
                })
                continue

            if status == "not-modified":
                write_existing_record(db_dir, evaluation["record"])
                valid_sources.append(source)
                statuses.append({
                    "url": source.url,
                    "name": source.name,
                    "origin": source.origin,
                    "status": status,
                    "plugins": evaluation["plugins"],
                    "highestApi": evaluation["highestApi"],
                })
                continue

            if status == "known-bad-git-blob":
                previous = evaluation.get("previousRecord")
                retained = previous is not None
                if retained:
                    write_existing_record(db_dir, previous)
                    valid_sources.append(source)
                statuses.append({
                    "url": source.url,
                    "name": source.name,
                    "origin": source.origin,
                    "status": status,
                    "gitBlobSha": evaluation.get("gitBlobSha", ""),
                    "reason": evaluation.get("reason", "known bad GitHub blob"),
                    "retainedLastKnownGood": retained,
                })
                continue

            if status == "known-bad-hash":
                raw_hash = evaluation["sha256"]
                reason = evaluation.get("reason", "known bad content")
                merge_bad_entry(known_bad, raw_hash, source, reason, now)
                previous = evaluation.get("previousRecord")
                retained = previous is not None
                if retained:
                    write_existing_record(db_dir, previous)
                    valid_sources.append(source)
                statuses.append({
                    "url": source.url,
                    "name": source.name,
                    "origin": source.origin,
                    "status": status,
                    "sha256": raw_hash,
                    "reason": reason,
                    "retainedLastKnownGood": retained,
                })
                continue

            if status == "new-bad-hash":
                raw_hash = evaluation["sha256"]
                reason = evaluation["reason"]
                if merge_bad_entry(known_bad, raw_hash, source, reason, now):
                    new_bad_count += 1
                previous = evaluation.get("previousRecord")
                retained = previous is not None
                if retained:
                    write_existing_record(db_dir, previous)
                    valid_sources.append(source)
                statuses.append({
                    "url": source.url,
                    "name": source.name,
                    "origin": source.origin,
                    "status": status,
                    "sha256": raw_hash,
                    "reason": reason,
                    "retainedLastKnownGood": retained,
                })
                continue

            manifest = evaluation["manifest"]
            write_record(
                db_dir,
                source,
                manifest,
                evaluation.get("etag", ""),
                evaluation.get("lastModified", ""),
                now,
            )
            valid_sources.append(source)
            statuses.append({
                "url": source.url,
                "name": source.name,
                "origin": source.origin,
                "status": "valid",
                "sha256": evaluation["sha256"],
                "plugins": evaluation["plugins"],
                "highestApi": evaluation["highestApi"],
            })

    curated_urls = {normalize_url(x.url).lower() for x in curated}
    generated = [x.as_definition() for x in valid_sources if normalize_url(x.url).lower() not in curated_urls]
    all_definitions = [x.as_definition() for x in curated]
    all_definition_urls = {normalize_url(x["url"]).lower() for x in all_definitions}
    for definition in generated:
        if normalize_url(definition["url"]).lower() not in all_definition_urls:
            all_definition_urls.add(normalize_url(definition["url"]).lower())
            all_definitions.append(definition)

    report = {
        "schemaVersion": 1,
        "generatedAtUtc": now,
        "candidateCount": len(ordered),
        "validRepositoryCount": len(valid_sources),
        "generatedRepositoryCount": len(generated),
        "newBadHashCount": new_bad_count,
        "knownBadHashCount": len(known_bad),
        "seedRecordCount": len(seed_records),
        "retainedLastKnownGoodCount": sum(1 for x in statuses if x.get("retainedLastKnownGood")),
        "statusCounts": {},
        "sources": statuses,
    }
    for status in statuses:
        key = status["status"]
        report["statusCounts"][key] = report["statusCounts"].get(key, 0) + 1

    sources_path = args.out / "sources.json"
    report_path = args.out / "catalog-report.json"
    manifest_path = args.out / "bundle-manifest.json"
    sources_path.write_text(json.dumps(all_definitions, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest_path.write_text(json.dumps({
        "schemaVersion": 1,
        "generatedAtUtc": now,
        "recordCount": len(valid_sources),
        "sourceCount": len(all_definitions),
        "databaseFormat": "Omega CatalogDatabase schema 1",
    }, indent=2) + "\n", encoding="utf-8")

    if args.generated_sources_output:
        args.generated_sources_output.parent.mkdir(parents=True, exist_ok=True)
        args.generated_sources_output.write_text(json.dumps(generated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.update_known_bad:
        items = sorted(known_bad.values(), key=lambda x: (x.get("sha256", ""), x.get("lastUrl", "")))
        known_doc = {"schemaVersion": 1, "items": items}
        args.known_bad.parent.mkdir(parents=True, exist_ok=True)
        args.known_bad.write_text(json.dumps(known_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    bundle_path = args.out / "omega-catalog-db.zip"
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(sources_path, "sources.json")
        zf.write(report_path, "catalog-report.json")
        zf.write(manifest_path, "bundle-manifest.json")
        for record in sorted(db_dir.glob("*.json")):
            zf.write(record, f"catalog-db/{record.name}")

    bundle_sha256 = sha256_bytes(bundle_path.read_bytes())
    checksum_path = args.out / "omega-catalog-db.zip.sha256"
    checksum_path.write_text(f"{bundle_sha256}  omega-catalog-db.zip\n", encoding="utf-8")

    # The bundle contains operational timestamps/reporting, so its byte hash may change even when
    # the marketplace data did not. Build a separate semantic fingerprint from source identities
    # and manifest content hashes. Runtime Omega compares this catalog hash first and only downloads
    # the ZIP when marketplace data actually changed; bundleSha256 still authenticates exact bytes.
    fingerprint_records = []
    for record_path in sorted(db_dir.glob("*.json")):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        fingerprint_records.append({
            "url": normalize_url(str(record.get("Url", ""))),
            "contentSha256": str(record.get("ContentSha256", "")).lower(),
        })
    fingerprint_payload = json.dumps({
        "schemaVersion": 1,
        "records": fingerprint_records,
        "sources": all_definitions,
    }, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    catalog_sha256 = sha256_bytes(fingerprint_payload)

    download_url = args.download_url.strip() or "omega-catalog-db.zip"
    descriptor = {
        "schema": "omega.catalog.v1",
        "schemaVersion": 1,
        "generatedAtUtc": now,
        "catalogSha256": catalog_sha256,
        "bundleSha256": bundle_sha256,
        "sha256": bundle_sha256,
        "size": bundle_path.stat().st_size,
        "downloadUrl": download_url,
        "recordCount": len(valid_sources),
        "sourceCount": len(all_definitions),
    }
    descriptor_path = args.out / "catalog.json"
    descriptor_path.write_text(json.dumps(descriptor, indent=2) + "\n", encoding="utf-8")

    endpoint_path = args.out / "catalog-endpoint.json"
    endpoint_path.write_text(json.dumps({
        "schemaVersion": 1,
        "descriptorUrl": args.descriptor_url.strip(),
    }, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({
        "bundle": str(bundle_path),
        "catalogSha256": catalog_sha256,
        "bundleSha256": bundle_sha256,
        "valid": len(valid_sources),
        "generated": len(generated),
        "newBad": new_bad_count,
        "knownBad": len(known_bad),
        "seedRecords": len(seed_records),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
