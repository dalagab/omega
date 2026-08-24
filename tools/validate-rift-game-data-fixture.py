#!/usr/bin/env python3
"""Validate Rift's opt-in synthetic game-data fixture pack before mounting it."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path


MAX_FILES = 128
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_dir", type=Path)
    args = parser.parse_args()

    root = args.fixture_dir.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise SystemExit("fixture root must be a real directory")

    files = 0
    total_bytes = 0
    for current, directories, names in os.walk(root, followlinks=False):
        directory = Path(current)
        for name in directories + names:
            path = directory / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise SystemExit(f"fixture pack may not contain symlinks: {path.relative_to(root)}")

        for name in names:
            path = directory / name
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise SystemExit(f"fixture pack may contain regular files only: {path.relative_to(root)}")
            if metadata.st_size > MAX_FILE_BYTES:
                raise SystemExit(f"fixture file exceeds {MAX_FILE_BYTES} bytes: {path.relative_to(root)}")
            files += 1
            total_bytes += metadata.st_size
            if files > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise SystemExit("fixture pack exceeds bounded file or byte limits")

    print(f"Rift game-data fixture pack: PASS ({files} files, {total_bytes} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
