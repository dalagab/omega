#!/usr/bin/env python3
"""Atomically publish a validated catalog-state JSON tree to a bounded snapshot branch.

Like Security Evidence v2, publication replaces the branch with one orphan snapshot commit
using force-with-lease. Semantic revision IDs provide provenance while Git history stays bounded.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import catalog_state  # noqa: E402


def run(cmd: list[str], *, cwd: Path, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=capture, check=True)


def publish(source: Path, repo: Path, branch: str, remote: str, push: bool) -> dict:
    source = source.resolve()
    validation = catalog_state.validate(source)
    if not validation.get("ok"):
        raise RuntimeError("catalog-state validation failed: " + "; ".join(validation.get("errors") or []))
    repo = Path(run(["git", "rev-parse", "--show-toplevel"], cwd=repo.resolve(), capture=True).stdout.strip()).resolve()
    url = run(["git", "remote", "get-url", remote], cwd=repo, capture=True).stdout.strip()
    old = run(["git", "ls-remote", "--heads", remote, f"refs/heads/{branch}"], cwd=repo, capture=True).stdout.strip()
    old_sha = old.split()[0] if old else ""
    result = {**validation, "branch": branch, "previousHead": old_sha, "pushed": False}
    if not push:
        return result
    index = json.loads((source / "index.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="omega-catalog-state-publish-") as td:
        work = Path(td)
        run(["git", "init", "-q"], cwd=work)
        run(["git", "checkout", "--orphan", branch], cwd=work)
        run(["git", "config", "user.name", "Omega Catalog Publisher"], cwd=work)
        run(["git", "config", "user.email", "omega-catalog@users.noreply.github.com"], cwd=work)
        run(["git", "config", "core.autocrlf", "false"], cwd=work)
        run(["git", "remote", "add", remote, url], cwd=work)
        for item in source.iterdir():
            target = work / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)
        run(["git", "add", "--all"], cwd=work)
        run(["git", "commit", "-q", "-m", f"Catalog state {index.get('stateRevision','snapshot')}"], cwd=work)
        new_sha = run(["git", "rev-parse", "HEAD"], cwd=work, capture=True).stdout.strip()
        refspec = f"HEAD:refs/heads/{branch}"
        if old_sha:
            run(["git", "push", f"--force-with-lease=refs/heads/{branch}:{old_sha}", remote, refspec], cwd=work)
        else:
            run(["git", "push", remote, refspec], cwd=work)
        result.update({"pushed": True, "newHead": new_sha})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--branch", default="catalog-data")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    print(json.dumps(publish(args.input, args.repo, args.branch, args.remote, args.push), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
