#!/usr/bin/env python3
"""Safely stage a downloaded Rift request artifact and resolve one plugin entry DLL."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.parse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = ROOT / "tools/extract-rift-artifact.py"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _manifest_candidates(root: Path) -> list[Path]:
    found: list[Path] = []
    for manifest in sorted(root.rglob("*.json")):
        try:
            value = json.loads(manifest.read_text(encoding="utf-8-sig"))
        except Exception:
            continue
        if not isinstance(value, dict) or not str(value.get("InternalName") or "").strip():
            continue
        stems = [manifest.stem, str(value.get("InternalName") or "").strip()]
        for stem in stems:
            candidate = manifest.parent / f"{stem}.dll"
            if candidate.is_file() and candidate not in found:
                found.append(candidate)
    return found


def resolve_plugin(root: Path, explicit: str) -> Path:
    if explicit:
        rel = Path(explicit)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError("plugin_entry must be a safe relative path inside the artifact")
        candidate = root / rel
        if not candidate.is_file() or candidate.suffix.lower() != ".dll" or not _inside(root, candidate):
            raise ValueError(f"plugin_entry does not resolve to a DLL inside the artifact: {explicit}")
        return candidate

    manifests = _manifest_candidates(root)
    if len(manifests) == 1:
        return manifests[0]
    if len(manifests) > 1:
        names = ", ".join(str(p.relative_to(root)) for p in manifests[:12])
        raise ValueError(f"multiple Dalamud manifest DLL candidates found; set plugin_entry explicitly: {names}")

    root_dlls = sorted(path for path in root.glob("*.dll") if path.is_file())
    if len(root_dlls) == 1:
        return root_dlls[0]
    all_dlls = sorted(path for path in root.rglob("*.dll") if path.is_file())
    if len(all_dlls) == 1:
        return all_dlls[0]
    names = ", ".join(str(p.relative_to(root)) for p in all_dlls[:12])
    raise ValueError(f"could not unambiguously resolve plugin entry DLL; set plugin_entry explicitly (candidates: {names or 'none'})")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--request", required=True, type=Path)
    p.add_argument("--download", required=True, type=Path)
    p.add_argument("--artifact-dir", required=True, type=Path)
    p.add_argument("--plugin-entry", default="")
    p.add_argument("--output", required=True, type=Path, help="write staging metadata JSON")
    args = p.parse_args()

    request = json.loads(args.request.read_text(encoding="utf-8"))
    expected = str(request.get("artifactSha256") or "").strip().lower()
    actual = sha256_file(args.download)
    if actual != expected:
        raise SystemExit(f"download SHA-256 mismatch: expected {expected}, got {actual}")

    artifact = args.artifact_dir
    if artifact.exists():
        shutil.rmtree(artifact)
    artifact.mkdir(parents=True)

    if zipfile.is_zipfile(args.download):
        subprocess.run([
            sys.executable, str(EXTRACTOR), str(args.download), str(artifact),
            "--max-total", str(256 * 1024 * 1024), "--max-files", "4096",
        ], check=True)
        artifact_kind = "zip"
    else:
        if args.plugin_entry:
            name = Path(args.plugin_entry).name
        else:
            url_name = Path(urllib.parse.urlparse(str(request.get("artifactUrl") or "")).path).name
            name = url_name or args.download.name
        if not name.lower().endswith(".dll"):
            raise SystemExit("non-ZIP artifact must have a .dll URL path or explicit plugin_entry ending in .dll")
        shutil.copy2(args.download, artifact / name)
        artifact_kind = "dll"

    try:
        plugin = resolve_plugin(artifact, args.plugin_entry)
    except ValueError as exc:
        raise SystemExit(str(exc))

    payload = {
        "schema": "omega.rift.staged-artifact.v1",
        "requestId": str(request.get("requestId") or ""),
        "variantId": int(request.get("variantId") or 0),
        "artifactSha256": actual,
        "artifactKind": artifact_kind,
        "artifactDir": str(artifact.resolve()),
        "pluginEntry": str(plugin.resolve()),
        "pluginEntryRelative": str(plugin.resolve().relative_to(artifact.resolve())),
        "pluginEntrySha256": sha256_file(plugin),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
