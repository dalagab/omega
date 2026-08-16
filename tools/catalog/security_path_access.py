"""Detect static evidence of hard-coded filesystem access outside FFXIV locations."""
from __future__ import annotations

import re


FILESYSTEM_API_MARKERS = (
    "file.open", "file.readall", "file.writeall", "file.delete", "file.move", "file.copy",
    "file.exists", "directory.get", "directory.enumerate", "directory.create", "directory.delete",
    "filestream", "streamreader", "streamwriter",
)
FFXIV_PATH_MARKERS = ("xivlauncher", "dalamud", "final fantasy xiv", "ffxiv")
HARD_CODED_PATH = re.compile(
    r"(?:[a-z]:[\\/][^\r\n\"']{1,260}|\\\\[^\\/\r\n]+[\\/][^\r\n\"']{1,260}|/(?:home|users|etc|var|tmp)/[^\s\"']{1,260})",
    re.IGNORECASE,
)


def external_hard_coded_paths(text: str) -> list[str]:
    lowered = text.casefold()
    if not any(marker in lowered for marker in FILESYSTEM_API_MARKERS):
        return []
    found: list[str] = []
    for match in HARD_CODED_PATH.finditer(text):
        path = match.group(0).rstrip(" \t,);]").strip()
        if not path or any(marker in path.casefold() for marker in FFXIV_PATH_MARKERS):
            continue
        if path not in found:
            found.append(path)
        if len(found) >= 8:
            break
    return found
