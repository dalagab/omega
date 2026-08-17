#!/usr/bin/env python3
"""Download and verify Omega's currently published v1 security evidence database.

This helper is intentionally usable by local/operator tooling. It resolves the
``security-evidence-latest`` GitHub release, verifies the published SHA-256 sidecar,
resumes interrupted downloads when possible, invalidates stale cached assets, and
safely extracts exactly one SQLite database.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from typing import Any

REPOSITORY = "dalagab/omega"
EVIDENCE_TAG = "security-evidence-latest"
EVIDENCE_ASSET = "omega-security-evidence.sqlite.zip"
GITHUB_API = "https://api.github.com"
USER_AGENT = "Omega-Security-Evidence-Migration/1.0"


@dataclass(frozen=True)
class DownloadedEvidence:
    database: Path
    archive: Path
    release_tag: str
    asset_name: str
    asset_bytes: int
    asset_sha256: str

    def state_context(self) -> dict[str, Any]:
        return {
            "mode": "download-current",
            "releaseTag": self.release_tag,
            "assetName": self.asset_name,
            "assetBytes": self.asset_bytes,
            "assetSha256": self.asset_sha256,
            "archivePath": str(self.archive.resolve()),
            "databasePath": str(self.database.resolve()),
        }


def default_cache_dir() -> Path:
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Omega" / "SecurityEvidenceMigration"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "omega-security-evidence-migration"
    return Path.home() / ".cache" / "omega-security-evidence-migration"


def github_headers() -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def http_json(url: str) -> Any:
    req = urllib.request.Request(url, headers=github_headers())
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def release_asset(tag: str, asset_name: str) -> dict[str, Any]:
    release = http_json(f"{GITHUB_API}/repos/{REPOSITORY}/releases/tags/{urllib.parse.quote(tag)}")
    for asset in release.get("assets") or []:
        if str(asset.get("name") or "") == asset_name:
            return asset
    raise RuntimeError(f"Release {tag!r} does not contain {asset_name!r}")


def download_text(url: str) -> str:
    req = urllib.request.Request(url, headers=github_headers())
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read(1024 * 1024).decode("utf-8", "replace")


def parse_sidecar(text: str) -> str:
    match = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    if not match:
        raise RuntimeError("SHA-256 sidecar does not contain a 64-character digest")
    return match.group(1).lower()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _progress(done: int, total: int, label: str, started: float) -> None:
    if total > 0:
        pct = min(100.0, done * 100.0 / total)
        width = 24
        filled = int(width * pct / 100.0)
        bar = "#" * filled + "-" * (width - filled)
        rate = done / max(0.1, time.monotonic() - started)
        print(
            f"\r{label}: [{bar}] {pct:5.1f}%  {done/1024/1024:,.1f}/{total/1024/1024:,.1f} MiB  "
            f"{rate/1024/1024:,.1f} MiB/s",
            end="",
            file=sys.stderr,
            flush=True,
        )
    else:
        print(f"\r{label}: {done/1024/1024:,.1f} MiB", end="", file=sys.stderr, flush=True)


def download_file(url: str, destination: Path, expected_size: int = 0, label: str = "download") -> Path:
    """Download a large release asset with resumable ``.part`` support."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_suffix(destination.suffix + ".part")
    resume_at = part.stat().st_size if part.exists() else 0
    if expected_size and resume_at > expected_size:
        part.unlink(missing_ok=True)
        resume_at = 0
    headers = {**github_headers(), "Accept": "application/octet-stream"}
    if resume_at > 0:
        headers["Range"] = f"bytes={resume_at}-"
    req = urllib.request.Request(url, headers=headers)
    started = time.monotonic()
    with urllib.request.urlopen(req, timeout=60) as response:
        status_value = getattr(response, "status", None)
        status = int(status_value if status_value is not None else response.getcode() or 200)
        append = resume_at > 0 and status == 206
        if append:
            content_range = str(response.headers.get("Content-Range") or "")
            match = re.match(r"bytes\s+(\d+)-\d+/(\d+|\*)", content_range, re.I)
            if not match or int(match.group(1)) != resume_at:
                raise RuntimeError(f"Server returned an invalid resume range for {label}: {content_range or 'missing Content-Range'}")
            total = expected_size or (int(match.group(2)) if match.group(2).isdigit() else 0)
            mode = "ab"
            done = resume_at
            print(f"Resuming {label} at {resume_at/1024/1024:,.1f} MiB", file=sys.stderr)
        else:
            # Some release/CDN endpoints ignore Range. Restart safely instead of appending.
            mode = "wb"
            done = 0
            total = expected_size or int(response.headers.get("Content-Length") or 0)
        with part.open(mode) as out:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                done += len(chunk)
                if done == len(chunk) or done % (8 * 1024 * 1024) < len(chunk):
                    _progress(done, total, label, started)
    print(file=sys.stderr)
    actual_size = part.stat().st_size
    if expected_size and actual_size != expected_size:
        if actual_size > expected_size:
            part.unlink(missing_ok=True)
        raise RuntimeError(f"Incomplete download for {label}: expected {expected_size} bytes, got {actual_size}")
    part.replace(destination)
    return destination


def safe_extract_sqlite(bundle: Path, destination_dir: Path) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle) as archive:
        candidates = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            pure = PurePosixPath(info.filename)
            if pure.is_absolute() or ".." in pure.parts:
                raise RuntimeError(f"Unsafe ZIP member {info.filename!r}")
            if pure.suffix.lower() in {".sqlite", ".db"}:
                candidates.append(info)
        if len(candidates) != 1:
            raise RuntimeError(f"Expected exactly one SQLite database in {bundle.name}; found {len(candidates)}")
        info = candidates[0]
        output = destination_dir / Path(info.filename).name
        temp = output.with_suffix(output.suffix + ".part")
        with archive.open(info) as source, temp.open("wb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        temp.replace(output)
    with output.open("rb") as stream:
        if stream.read(16) != b"SQLite format 3\x00":
            output.unlink(missing_ok=True)
            raise RuntimeError(f"Extracted file {output.name} is not a SQLite 3 database")
    return output


def download_current_database(cache: Path | None = None) -> DownloadedEvidence:
    """Return a verified/extracted copy of the currently published v1 evidence DB."""
    cache = (cache or default_cache_dir()).resolve()
    asset = release_asset(EVIDENCE_TAG, EVIDENCE_ASSET)
    url = str(asset.get("browser_download_url") or "")
    if not url:
        raise RuntimeError(f"Release asset {EVIDENCE_ASSET!r} has no download URL")
    size = int(asset.get("size") or 0)
    api_digest_text = str(asset.get("digest") or "")
    api_digest = api_digest_text.split(":", 1)[1].lower() if api_digest_text.startswith("sha256:") else ""
    sidecar = release_asset(EVIDENCE_TAG, EVIDENCE_ASSET + ".sha256")
    sidecar_url = str(sidecar.get("browser_download_url") or "")
    sidecar_digest = parse_sidecar(download_text(sidecar_url))
    expected = api_digest or sidecar_digest
    if api_digest and api_digest != sidecar_digest:
        raise RuntimeError(f"GitHub asset digest and {EVIDENCE_ASSET}.sha256 disagree")

    release_dir = cache / EVIDENCE_TAG
    archive = release_dir / EVIDENCE_ASSET
    state_path = release_dir / (EVIDENCE_ASSET + ".state.json")
    release_dir.mkdir(parents=True, exist_ok=True)

    if archive.exists():
        size_matches = not size or archive.stat().st_size == size
        if not size_matches:
            print(
                f"Discarding stale cached {archive.name}: published size changed from "
                f"{archive.stat().st_size:,} to {size:,} bytes",
                file=sys.stderr,
            )
            archive.unlink(missing_ok=True)
            state_path.unlink(missing_ok=True)
        elif sha256_file(archive) != expected:
            print(f"Discarding stale cached {archive.name}: SHA-256 changed", file=sys.stderr)
            archive.unlink(missing_ok=True)
            state_path.unlink(missing_ok=True)
        else:
            print(f"Using cached {archive} ({archive.stat().st_size/1024/1024:,.1f} MiB)", file=sys.stderr)

    if not archive.exists():
        print(f"Downloading current Omega security evidence ({size/1024/1024:,.1f} MiB)...", file=sys.stderr)
        download_file(url, archive, size, EVIDENCE_ASSET)
        actual = sha256_file(archive)
        if actual != expected:
            archive.unlink(missing_ok=True)
            raise RuntimeError(f"SHA-256 verification failed for {EVIDENCE_ASSET}: expected {expected}, got {actual}")

    extracted_dir = release_dir / "extracted"
    extracted: Path | None = None
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            candidate = extracted_dir / Path(str(state.get("extractedFile") or "")).name
            if state.get("archiveSha256") == expected and candidate.is_file():
                with candidate.open("rb") as stream:
                    if stream.read(16) == b"SQLite format 3\x00":
                        extracted = candidate
        except Exception:
            extracted = None
    if extracted is None:
        extracted = safe_extract_sqlite(archive, extracted_dir)
        state_path.write_text(
            json.dumps({"archiveSha256": expected, "asset": EVIDENCE_ASSET, "extractedFile": extracted.name}, indent=2) + "\n",
            encoding="utf-8",
        )

    return DownloadedEvidence(
        database=extracted,
        archive=archive,
        release_tag=EVIDENCE_TAG,
        asset_name=EVIDENCE_ASSET,
        asset_bytes=size,
        asset_sha256=expected,
    )
