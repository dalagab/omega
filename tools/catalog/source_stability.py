"""Shared stable-source baseline rules for Omega catalog/security processing.

These provider tiers are not a safety verdict. They define which long-lived repository
publishers may establish the canonical package/metadata/security baseline when the same
plugin is mirrored elsewhere.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StableSource:
    key: str
    label: str
    priority: int


DALAMUD = StableSource("dalamud", "Dalamud", 0)
PUNI_SH = StableSource("puni-sh", "Puni.sh", 1)
NIGHTMARE_XIV = StableSource("nightmarexiv", "NightmareXIV", 2)
COMBAT_REBORN = StableSource("combat-reborn", "Combat Reborn", 3)


def classify_stable_source(source_name: str | None, source_url: str | None, is_official: bool = False) -> StableSource | None:
    name = (source_name or "").strip()
    url = (source_url or "").strip()
    identity = f"{name}\n{url}".casefold()

    if is_official or "dalamud official" in identity or "goatcorp/dalamudplugins" in identity:
        return DALAMUD
    if "puni.sh" in identity or "puni-sh" in identity or "punish" in identity:
        return PUNI_SH
    if "nightmarexiv" in identity:
        return NIGHTMARE_XIV
    if "ffxiv-combatreborn" in identity or "combatrebornrepo" in identity or "combat reborn" in identity:
        return COMBAT_REBORN
    return None


def stable_source_priority(source_name: str | None, source_url: str | None, is_official: bool = False) -> int | None:
    provider = classify_stable_source(source_name, source_url, is_official)
    return provider.priority if provider is not None else None


def is_stable_source(source_name: str | None, source_url: str | None, is_official: bool = False) -> bool:
    return classify_stable_source(source_name, source_url, is_official) is not None
