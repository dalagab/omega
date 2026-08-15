#!/usr/bin/env python3
"""Build the static Omega GitHub Pages tree from the checked-in site source."""
from __future__ import annotations
import shutil
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "site"
OUTPUT = ROOT / "_site"
BRAND_OUTPUT = OUTPUT / "assets" / "brand"

def main() -> int:
    if not SOURCE.is_dir():
        raise SystemExit("site/ source directory is missing")
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    shutil.copytree(SOURCE, OUTPUT)
    BRAND_OUTPUT.mkdir(parents=True, exist_ok=True)
    for filename in ("icon.png", "title-icon.png"):
        preferred = ROOT / "images" / filename
        fallback = SOURCE / "assets" / "fallback-brand" / filename
        source = preferred if preferred.is_file() else fallback
        if not source.is_file():
            raise SystemExit(f"missing brand asset: {filename}")
        shutil.copy2(source, BRAND_OUTPUT / filename)
    (OUTPUT / ".nojekyll").touch()
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
