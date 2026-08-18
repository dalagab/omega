#!/usr/bin/env python3
"""Validate the generated Omega public site before GitHub Pages publication."""
from __future__ import annotations
import re
from pathlib import Path
from urllib.parse import urlsplit
ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "_site"
HTML_FILES = ("index.html", "features.html", "install.html", "security.html", "faq.html", "about.html", "404.html")
ATTR_RE = re.compile(r'''(?:href|src)=["']([^"']+)["']''', re.I)

def local_target(page: Path, value: str) -> Path | None:
    if not value or value.startswith(("#", "mailto:", "tel:", "data:")):
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return None
    if not parsed.path:
        return None
    return SITE / parsed.path.lstrip("/") if parsed.path.startswith("/") else page.parent / parsed.path

def main() -> int:
    if not SITE.is_dir():
        raise SystemExit("_site/ has not been built")
    required = [*[SITE / name for name in HTML_FILES], SITE / ".nojekyll", SITE / "assets" / "site.css", SITE / "assets" / "site.js", SITE / "assets" / "brand" / "icon.png", SITE / "assets" / "brand" / "title-icon.png"]
    missing = [path.relative_to(SITE).as_posix() for path in required if not path.exists()]
    if missing:
        raise SystemExit("missing generated site files: " + ", ".join(missing))
    broken, forbidden = [], []
    for name in HTML_FILES:
        page = SITE / name
        text = page.read_text(encoding="utf-8")
        lower = text.lower()
        for token in ("omega-marketplace.sqlite", "omega-catalog.sqlite", "catalog-latest/"):
            if token in lower:
                forbidden.append(f"{name}: {token}")
        for ref in ATTR_RE.findall(text):
            target = local_target(page, ref)
            if target is not None and not target.exists():
                broken.append(f"{name}: {ref}")
    if broken:
        raise SystemExit("broken local site references: " + "; ".join(broken))
    if forbidden:
        raise SystemExit("public marketplace boundary violation: " + "; ".join(forbidden))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
