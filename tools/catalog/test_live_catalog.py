#!/usr/bin/env python3
"""Smoke-test Omega's published catalog descriptor and downloadable database bundle.

This intentionally tests the same public release URLs that Omega clients use.  It is
run after publishing catalog-latest so a successful catalog-builder job proves that
GitHub's release download path, descriptor hashes, and bundle structure are usable.
It can also run against local descriptor/bundle files for development validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

MAX_DESCRIPTOR_BYTES = 256 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
USER_AGENT = "Dalagab-Omega-Catalog-Smoke/1.0"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_bytes(url: str, max_bytes: int, attempts: int = 6) -> bytes:
    if not url.lower().startswith("https://"):
        raise ValueError(f"HTTPS required: {url}")
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError(f"download exceeds {max_bytes} bytes: {url}")
            return data
        except Exception as exc:  # release assets can be briefly eventually consistent after --clobber
            last = exc
            if attempt < attempts:
                time.sleep(min(2 * attempt, 10))
    raise RuntimeError(f"unable to download {url}: {last}")


def remove_comments(text: str) -> str:
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
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
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
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
            while j < len(text) and text[j].isspace():
                j += 1
            if j < len(text) and text[j] in "]}":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def tolerant_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(remove_trailing_commas(remove_comments(text)))


def load_descriptor(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    if args.descriptor_file:
        data = args.descriptor_file.read_bytes()
        source = args.descriptor_file.as_uri()
    else:
        data = fetch_bytes(args.descriptor_url, MAX_DESCRIPTOR_BYTES)
        source = args.descriptor_url
    if len(data) > MAX_DESCRIPTOR_BYTES:
        raise ValueError("descriptor exceeds maximum size")
    descriptor = json.loads(data.decode("utf-8-sig"))
    if descriptor.get("schema") != "omega.catalog.v1" or descriptor.get("schemaVersion") != 1:
        raise ValueError("unsupported catalog descriptor schema")
    return descriptor, source


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--descriptor-url")
    source.add_argument("--descriptor-file", type=Path)
    parser.add_argument("--bundle-file", type=Path,
                        help="Read bundle locally instead of downloading descriptor downloadUrl")
    parser.add_argument("--expected-bundle", type=Path,
                        help="Require downloaded bundle SHA to match this just-built local bundle")
    args = parser.parse_args()

    descriptor, descriptor_source = load_descriptor(args)
    catalog_sha = descriptor.get("catalogSha256") or descriptor.get("sha256") or ""
    bundle_sha = descriptor.get("bundleSha256") or descriptor.get("sha256") or ""
    if not SHA256_RE.fullmatch(catalog_sha):
        raise ValueError("descriptor catalogSha256 is invalid")
    if not SHA256_RE.fullmatch(bundle_sha):
        raise ValueError("descriptor bundleSha256 is invalid")

    if args.bundle_file:
        bundle = args.bundle_file.read_bytes()
        bundle_source = str(args.bundle_file)
    else:
        download_url = descriptor.get("downloadUrl") or ""
        if not isinstance(download_url, str) or not download_url.lower().startswith("https://"):
            raise ValueError("descriptor downloadUrl must be HTTPS")
        bundle = fetch_bytes(download_url, MAX_BUNDLE_BYTES)
        bundle_source = download_url

    if len(bundle) > MAX_BUNDLE_BYTES:
        raise ValueError("catalog database exceeds maximum size")
    if descriptor.get("size") not in (None, len(bundle)):
        raise ValueError(f"bundle size mismatch: descriptor={descriptor.get('size')} actual={len(bundle)}")
    actual_sha = sha256_bytes(bundle)
    if actual_sha.lower() != bundle_sha.lower():
        raise ValueError(f"bundle SHA mismatch: descriptor={bundle_sha} actual={actual_sha}")

    if args.expected_bundle:
        expected_sha = sha256_bytes(args.expected_bundle.read_bytes())
        if actual_sha != expected_sha:
            raise ValueError(f"published bundle differs from just-built bundle: {actual_sha} != {expected_sha}")

    # Work from memory so the exact downloaded bytes are what get inspected.
    import io
    record_count = 0
    with zipfile.ZipFile(io.BytesIO(bundle), "r") as archive:
        bad_member = archive.testzip()
        if bad_member is not None:
            raise ValueError(f"catalog ZIP CRC failure: {bad_member}")
        required = {"bundle-manifest.json", "sources.json"}
        if not required.issubset(set(archive.namelist())):
            raise ValueError("catalog bundle is missing manifest or sources.json")
        bundle_manifest = json.loads(archive.read("bundle-manifest.json").decode("utf-8-sig"))
        sources = json.loads(archive.read("sources.json").decode("utf-8-sig"))
        record_names = [
            name for name in archive.namelist()
            if name.startswith("catalog-db/") and name.endswith(".json")
        ]
        for name in record_names:
            record = json.loads(archive.read(name).decode("utf-8-sig"))
            if record.get("SchemaVersion") != 1:
                raise ValueError(f"invalid record schema: {name}")
            manifest_json = record.get("ManifestJson")
            if not isinstance(manifest_json, str) or not manifest_json.strip():
                raise ValueError(f"record has no ManifestJson: {name}")
            parsed = tolerant_json(manifest_json)
            if not isinstance(parsed, (list, dict)):
                raise ValueError(f"manifest root is invalid: {name}")
            record_count += 1

    expected_records = descriptor.get("recordCount")
    if expected_records is not None and int(expected_records) != record_count:
        raise ValueError(f"record count mismatch: descriptor={expected_records} actual={record_count}")
    if int(bundle_manifest.get("recordCount", -1)) != record_count:
        raise ValueError("bundle manifest recordCount mismatch")
    expected_sources = descriptor.get("sourceCount")
    if expected_sources is not None and int(expected_sources) != len(sources):
        raise ValueError(f"source count mismatch: descriptor={expected_sources} actual={len(sources)}")
    if int(bundle_manifest.get("sourceCount", -1)) != len(sources):
        raise ValueError("bundle manifest sourceCount mismatch")

    print("Omega live catalog smoke test passed")
    print(f"descriptor: {descriptor_source}")
    print(f"bundle: {bundle_source}")
    print(f"catalogSha256: {catalog_sha}")
    print(f"bundleSha256: {actual_sha}")
    print(f"bytes: {len(bundle)}")
    print(f"records: {record_count}")
    print(f"sources: {len(sources)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Omega live catalog smoke test FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
