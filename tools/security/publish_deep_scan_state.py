#!/usr/bin/env python3
"""Atomically publish the small Deep Scan queue/results tree to a dedicated branch."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        text=True,
        capture_output=capture,
        check=True,
    )


def _repo_git(repo: Path, *args: str) -> list[str]:
    """Trust only the exact mounted checkout used for publication."""
    return ["git", "-c", f"safe.directory={repo.resolve()}", *args]


def git_root(path: Path) -> Path:
    requested = path.resolve()
    result = run(
        _repo_git(requested, "rev-parse", "--show-toplevel"),
        cwd=requested,
        capture=True,
    )
    root = Path(result.stdout.strip()).resolve()
    if root != requested:
        raise RuntimeError(
            "Deep Scan publication repo must be its exact Git root: "
            f"requested={requested}, root={root}"
        )
    return root


def remote_url(repo: Path, remote: str) -> str:
    repo = repo.resolve()
    result = run(
        _repo_git(repo, "remote", "get-url", remote),
        cwd=repo,
        capture=True,
    )
    url = result.stdout.strip()
    if not url:
        raise RuntimeError(f"Git remote {remote!r} has no URL")
    return url


def remote_branch_sha(repo: Path, url: str, branch: str) -> str:
    repo = repo.resolve()
    result = run(
        _repo_git(repo, "ls-remote", "--heads", url, f"refs/heads/{branch}"),
        cwd=repo,
        capture=True,
    )
    line = result.stdout.strip()
    return line.split()[0] if line else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--branch", default="deep-scan-state")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()

    source = args.input.resolve()
    index = json.loads((source / "index.json").read_text(encoding="utf-8"))
    if index.get("schema") != "omega.sigmascope.deep-scan-queue.v1":
        raise RuntimeError("invalid deep-scan queue schema")

    root = git_root(args.repo)
    url = remote_url(root, args.remote)
    old_sha = remote_branch_sha(root, url, args.branch)

    info = {
        "queueRevision": index.get("queueRevision", ""),
        "items": len(index.get("items") or []),
        "branch": args.branch,
        "previousHead": old_sha,
        "pushed": False,
    }
    if not args.push:
        print(json.dumps(info, indent=2))
        return 0

    with tempfile.TemporaryDirectory(prefix="omega-deep-scan-publish-") as td:
        work = Path(td)
        run(["git", "init", "-q"], cwd=work)
        run(["git", "checkout", "--orphan", args.branch], cwd=work)
        run(["git", "config", "user.name", "Omega Deep Scan Publisher"], cwd=work)
        run(["git", "config", "user.email", "omega-deepscan@users.noreply.github.com"], cwd=work)
        run(["git", "remote", "add", args.remote, url], cwd=work)

        for path in source.rglob("*"):
            if not path.is_file():
                continue
            destination = work / path.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)

        run(["git", "add", "--all"], cwd=work)
        run(
            ["git", "commit", "-q", "-m", f"Deep scan state {index.get('queueRevision', '') or 'update'}"],
            cwd=work,
        )
        new_sha = run(["git", "rev-parse", "HEAD"], cwd=work, capture=True).stdout.strip()
        refspec = f"HEAD:refs/heads/{args.branch}"
        if old_sha:
            run(
                ["git", "push", f"--force-with-lease=refs/heads/{args.branch}:{old_sha}", args.remote, refspec],
                cwd=work,
            )
        else:
            run(["git", "push", args.remote, refspec], cwd=work)
        info.update({"pushed": True, "newHead": new_sha})

    print(json.dumps(info, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
