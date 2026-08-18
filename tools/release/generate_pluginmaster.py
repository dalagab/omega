#!/usr/bin/env python3
"""Generate Omega's public PluginMaster from the built Dalamud package.

The release package is authoritative for the distributed AssemblyVersion.  Development
`main` is intentionally not authoritative for public release metadata because work builds
may move ahead before a GitHub release is published.
"""
from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path, PurePosixPath

TAG_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+)$")
DEFAULT_REPOSITORY = "dalagab/omega"
DEFAULT_PACKAGE_ASSET = "Omega.zip"
MANIFEST_NAME = "DalagabOmega.json"


def _read_packaged_manifest(package: Path) -> dict:
    with zipfile.ZipFile(package) as archive:
        candidates = [
            name for name in archive.namelist()
            if not name.endswith("/") and PurePosixPath(name).name.casefold() == MANIFEST_NAME.casefold()
        ]
        if len(candidates) != 1:
            raise ValueError(f"{package} must contain exactly one {MANIFEST_NAME}; found {len(candidates)}")
        with archive.open(candidates[0]) as stream:
            value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"packaged {MANIFEST_NAME} must be a JSON object")
    return value


def _read_template(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError("PluginMaster template must contain exactly one JSON object")
    return dict(value[0])


def _release_summary(path: Path, limit: int = 1800) -> str:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("<sub>") or line.startswith("#"):
            continue
        line = re.sub(r"^[-*+]\s+", "", line)
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)
    result = " ".join(lines).strip()
    if len(result) > limit:
        result = result[: limit - 1].rstrip() + "…"
    return result


def generate(template: dict, packaged: dict, tag: str, notes: str, repository: str = DEFAULT_REPOSITORY) -> dict:
    match = TAG_RE.fullmatch(tag.strip())
    if match is None:
        raise ValueError(f"release tag {tag!r} must look like v0.9.10")
    version = match.group("version")
    expected_assembly = f"{version}.0"
    assembly = str(packaged.get("AssemblyVersion") or "").strip()
    if assembly != expected_assembly:
        raise ValueError(f"distributed AssemblyVersion {assembly or '<missing>'} does not match release tag {tag} ({expected_assembly})")

    for field in ("Name", "Author"):
        packaged_value = str(packaged.get(field) or "").strip()
        template_value = str(template.get(field) or "").strip()
        if packaged_value and template_value and packaged_value != template_value:
            raise ValueError(f"packaged {field} {packaged_value!r} does not match PluginMaster template {template_value!r}")

    internal = str(packaged.get("InternalName") or template.get("InternalName") or "").strip()
    if internal != "DalagabOmega":
        raise ValueError(f"unexpected Omega internal name: {internal!r}")

    result = dict(template)
    result["AssemblyVersion"] = assembly
    if packaged.get("DalamudApiLevel") is not None:
        result["DalamudApiLevel"] = int(packaged["DalamudApiLevel"])
    result["DownloadLinkInstall"] = f"https://github.com/{repository}/releases/download/{tag}/{DEFAULT_PACKAGE_ASSET}"
    result["DownloadLinkUpdate"] = result["DownloadLinkInstall"]
    result["Changelog"] = notes.strip()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, default=Path("repository/pluginmaster.template.json"))
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--release-notes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    args = parser.parse_args()

    template = _read_template(args.template)
    packaged = _read_packaged_manifest(args.package)
    notes = _release_summary(args.release_notes)
    generated = generate(template, packaged, args.tag, notes, args.repository)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps([generated], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "assemblyVersion": generated["AssemblyVersion"],
        "downloadUrl": generated["DownloadLinkInstall"],
        "output": str(args.output),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
