#!/usr/bin/env python3
"""Atomically publish orchestration-only work state to a dedicated branch."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

EXPECTED_SCHEMA = "omega.work-state.v1"


def run(cmd: list[str], cwd: Path | None = None, capture: bool = False):
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=capture, check=True)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--branch", default="security-work-state")
    p.add_argument("--remote", default="origin")
    p.add_argument("--push", action="store_true")
    args = p.parse_args()
    source = args.input.resolve()
    index = json.loads((source / "index.json").read_text(encoding="utf-8"))
    if index.get("schema") != EXPECTED_SCHEMA or index.get("securityAuthority") is not False or index.get("clientDatabaseBuildRequested") is not False:
        raise RuntimeError("invalid or authoritative work-state index")
    root = Path(run(["git", "rev-parse", "--show-toplevel"], cwd=args.repo, capture=True).stdout.strip())
    url = run(["git", "remote", "get-url", args.remote], cwd=root, capture=True).stdout.strip()
    old = run(["git", "ls-remote", "--heads", args.remote, f"refs/heads/{args.branch}"], cwd=root, capture=True).stdout.strip()
    oldsha = old.split()[0] if old else ""
    info = {"branch": args.branch, "workStateRevision": index.get("workStateRevision", ""), "previousHead": oldsha, "pushed": False}
    if not args.push:
        print(json.dumps(info, indent=2)); return 0
    with tempfile.TemporaryDirectory(prefix="omega-work-state-") as td:
        work = Path(td)
        run(["git", "init", "-q"], cwd=work)
        run(["git", "checkout", "--orphan", args.branch], cwd=work)
        run(["git", "config", "user.name", "Omega Work-State Publisher"], cwd=work)
        run(["git", "config", "user.email", "omega-work-state@users.noreply.github.com"], cwd=work)
        run(["git", "remote", "add", args.remote, url], cwd=work)
        for path in source.rglob("*"):
            if path.is_file():
                target = work / path.relative_to(source); target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, target)
        run(["git", "add", "--all"], cwd=work)
        run(["git", "commit", "-q", "-m", f"Work state {index.get('workStateRevision') or 'update'}"], cwd=work)
        newsha = run(["git", "rev-parse", "HEAD"], cwd=work, capture=True).stdout.strip()
        ref = f"HEAD:refs/heads/{args.branch}"
        if oldsha:
            run(["git", "push", f"--force-with-lease=refs/heads/{args.branch}:{oldsha}", args.remote, ref], cwd=work)
        else:
            run(["git", "push", args.remote, ref], cwd=work)
        info.update({"pushed": True, "newHead": newsha})
    print(json.dumps(info, indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
