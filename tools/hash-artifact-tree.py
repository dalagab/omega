#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

ALGORITHM = "sha256(path-nul-file-sha-lf-v1)"

def hash_tree(root: Path) -> str:
    root = root.resolve()
    if not root.is_dir():
        raise SystemExit(f"artifact tree not found: {root}")

    aggregate = hashlib.sha256()
    files = sorted(
        (p for p in root.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(root).as_posix(),
    )

    for path in files:
        rel = path.relative_to(root).as_posix()
        file_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        aggregate.update(rel.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(file_sha.encode("ascii"))
        aggregate.update(b"\n")

    return aggregate.hexdigest()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: hash-artifact-tree.py <artifact-directory>")
    print(hash_tree(Path(sys.argv[1])))
