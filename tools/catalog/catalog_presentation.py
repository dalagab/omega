"""Classify public project presentation content without making trust decisions."""
from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable


DECLARED_ADULT_TAGS = {
    "nsfw", "adult", "18+", "18plus", "explicit", "sexual", "sexual-content", "mature",
}
ADULT_TEXT_MARKER = re.compile(
    r"(?:\bnsfw\b|\b18\s*\+|\badults?[-\s]+only\b|\bexplicit[-\s]+sexual\b|\bhentai\b|\bpornographic\b|\berotic\b)",
    re.IGNORECASE,
)


def is_discord_join_image(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold()
    path = parsed.path.casefold()
    return host in {"discord.com", "www.discord.com", "discordapp.com", "www.discordapp.com"} and "/api/guilds/" in path and "/widget" in path


def split_project_image_urls(urls: Iterable[object]) -> tuple[list[str], list[str]]:
    display: list[str] = []
    discord_join: list[str] = []
    for value in urls:
        url = str(value or "").strip()
        if not url:
            continue
        target = discord_join if is_discord_join_image(url) else display
        if url not in target:
            target.append(url)
    return display, discord_join


def is_adult_content(tags: Iterable[object], texts: Iterable[object]) -> bool:
    normalized_tags = {str(tag or "").strip().casefold() for tag in tags}
    if normalized_tags & DECLARED_ADULT_TAGS:
        return True
    return any(ADULT_TEXT_MARKER.search(str(text or "")) is not None for text in texts)
