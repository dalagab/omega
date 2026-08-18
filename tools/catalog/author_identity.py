"""Normalize Dalamud manifest author strings into individual author identities."""
from __future__ import annotations

import re
from typing import Any

_GENERIC = {
    "contributors",
    "various contributors",
    "and contributors",
    "team",
    "community",
    "unknown",
    "unknown author",
}


def split_authors(value: Any) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    text = re.sub(r"\s+and\s+", ",", text, flags=re.I)
    parts = re.split(r"[,;&]", text)
    out: list[str] = []
    seen: set[str] = set()
    for part in parts:
        author = part.strip().strip(".•-–— ").strip()
        key = author.casefold()
        if not author or key in _GENERIC or key in seen:
            continue
        seen.add(key)
        out.append(author)
    return out
