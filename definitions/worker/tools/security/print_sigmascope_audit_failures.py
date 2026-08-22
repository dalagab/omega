#!/usr/bin/env python3
"""Print a bounded human-readable failure summary from a Sigmascope developer audit JSON."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence


def summarize(path: Path, limit: int = 20) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    counts = payload.get("counts") if isinstance(payload, dict) else {}
    items = payload.get("items") if isinstance(payload, dict) else []
    fail_count = int((counts or {}).get("fail") or 0) if isinstance(counts, dict) else 0
    lines = [f"Sigmascope independent audit failed: {fail_count} failing check(s)."]
    shown = 0
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or item.get("status") != "fail":
            continue
        plugin = str(item.get("plugin") or "").strip()
        variant = item.get("variant_id")
        scope = ""
        if plugin:
            scope = f" [{plugin}{f' variant {variant}' if variant is not None else ''}]"
        code = str(item.get("code") or "audit.failure")
        title = str(item.get("title") or "Audit failure")
        detail = str(item.get("detail") or "")
        if len(detail) > 500:
            detail = detail[:500] + "…"
        lines.append(f"- {code}{scope}: {title}" + (f" — {detail}" if detail else ""))
        shown += 1
        if shown >= max(1, limit):
            break
    if fail_count > shown:
        lines.append(f"... {fail_count - shown} additional failing check(s) are in {path}.")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", type=Path)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        for line in summarize(args.audit, args.limit):
            print(line, file=sys.stderr)
    except Exception as exc:
        print(f"Could not summarize Sigmascope audit {args.audit}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
