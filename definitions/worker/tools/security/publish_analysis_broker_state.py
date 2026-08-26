#!/usr/bin/env python3
"""Atomically publish the bounded Analysis Broker state to a dedicated branch."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import analysis_broker

MAX_STATE_BYTES = 16 * 1024 * 1024


def run(cmd: list[str], *, cwd: Path | None = None, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=capture, check=True)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--branch", default="analysis-broker-state")
    p.add_argument("--remote", default="origin")
    p.add_argument("--push", action="store_true")
    a = p.parse_args()
    src = a.input.resolve()
    index_path = src / "index.json"
    if not index_path.is_file() or index_path.stat().st_size > MAX_STATE_BYTES:
        raise RuntimeError("analysis broker index is missing or oversized")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if str(index.get("schema") or "") != analysis_broker.STATE_SCHEMA:
        raise RuntimeError("invalid analysis broker state schema")
    status = analysis_broker.summary(index)
    root = Path(run(["git", "rev-parse", "--show-toplevel"], cwd=a.repo, capture=True).stdout.strip())
    url = run(["git", "remote", "get-url", a.remote], cwd=root, capture=True).stdout.strip()
    old = run(["git", "ls-remote", "--heads", a.remote, f"refs/heads/{a.branch}"], cwd=root, capture=True).stdout.strip()
    old_sha = old.split()[0] if old else ""
    info = {
        "schema": "omega.analysis-broker-publication.v1",
        "branch": a.branch,
        "previousHead": old_sha,
        "stateRevision": status["stateRevision"],
        "items": status["items"],
        "states": status["states"],
        "pushed": False,
    }
    if not a.push:
        print(json.dumps(info, indent=2))
        return 0
    with tempfile.TemporaryDirectory(prefix="omega-analysis-broker-publish-") as td:
        work = Path(td)
        run(["git", "init", "-q"], cwd=work)
        run(["git", "checkout", "--orphan", a.branch], cwd=work)
        run(["git", "config", "user.name", "Omega Analysis Broker"], cwd=work)
        run(["git", "config", "user.email", "omega-analysis-broker@users.noreply.github.com"], cwd=work)
        run(["git", "remote", "add", a.remote, url], cwd=work)
        for path in src.rglob("*"):
            if path.is_file():
                dest = work / path.relative_to(src)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
        run(["git", "add", "--all"], cwd=work)
        run(["git", "commit", "-q", "-m", f"Analysis broker state {index.get('updatedAtUtc','') or 'update'}"], cwd=work)
        new_sha = run(["git", "rev-parse", "HEAD"], cwd=work, capture=True).stdout.strip()
        ref = f"HEAD:refs/heads/{a.branch}"
        if old_sha:
            run(["git", "push", f"--force-with-lease=refs/heads/{a.branch}:{old_sha}", a.remote, ref], cwd=work)
        else:
            run(["git", "push", a.remote, ref], cwd=work)
        info.update({"pushed": True, "newHead": new_sha})
    print(json.dumps(info, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
