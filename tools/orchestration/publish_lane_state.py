\
#!/usr/bin/env python3
"""Publish one validated orchestration worker result to its dedicated state branch.

The worker checkout is mounted into the digest-pinned container by GitHub Actions.
That checkout is owned by the host runner, so modern Git correctly treats it as a
"dubious ownership" repository from inside the container unless that exact path is
explicitly trusted.  Do not use a global safe.directory='*' escape hatch: trust only
the repository path supplied to this publisher.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import work_result


def run(cmd: list[str], cwd: Path | None = None, capture: bool = False):
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=capture,
        check=True,
    )


def _repository_root(repo: Path) -> Path:
    """Resolve a GitHub Actions checkout without weakening Git ownership checks globally."""
    candidate = repo.resolve()
    completed = run(
        ["git", "-c", f"safe.directory={candidate}", "rev-parse", "--show-toplevel"],
        cwd=candidate,
        capture=True,
    )
    text = completed.stdout.strip()
    if not text:
        raise RuntimeError(f"unable to resolve repository root from {candidate}")
    root = Path(text).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(
            f"resolved repository root {root} does not contain requested repo path {candidate}"
        ) from exc
    return root


def _remote_url(root: Path, remote: str) -> str:
    """Read a remote from the exact trusted checkout."""
    completed = run(
        ["git", "-c", f"safe.directory={root}", "remote", "get-url", remote],
        cwd=root,
        capture=True,
    )
    url = completed.stdout.strip()
    if not url:
        raise RuntimeError(f"git remote {remote!r} has no URL")
    return url


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--branch", required=True)
    p.add_argument("--remote", default="origin")
    p.add_argument("--push", action="store_true")
    args = p.parse_args()

    source = args.input.resolve()
    result = work_result.validate_result(source)

    # The exact checkout path is trusted only for the commands that inspect it.
    # Subsequent publication happens from a fresh temporary repository owned by
    # the container user and therefore needs no safe-directory exception.
    root = _repository_root(args.repo)
    url = _remote_url(root, args.remote)

    old = run(
        ["git", "ls-remote", "--heads", url, f"refs/heads/{args.branch}"],
        capture=True,
    ).stdout.strip()
    oldsha = old.split()[0] if old else ""

    info = {
        "branch": args.branch,
        "resultRevision": result["resultRevision"],
        "previousHead": oldsha,
        "pushed": False,
    }
    if not args.push:
        print(json.dumps(info, indent=2))
        return 0

    with tempfile.TemporaryDirectory(prefix="omega-lane-state-") as td:
        work = Path(td)
        run(["git", "init", "-q"], cwd=work)
        run(["git", "checkout", "--orphan", args.branch], cwd=work)
        run(["git", "config", "user.name", "Omega Lane-State Publisher"], cwd=work)
        run(
            ["git", "config", "user.email", "omega-lane-state@users.noreply.github.com"],
            cwd=work,
        )
        run(["git", "remote", "add", args.remote, url], cwd=work)

        for path in source.rglob("*"):
            if path.is_file():
                target = work / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)

        run(["git", "add", "--all"], cwd=work)
        run(
            ["git", "commit", "-q", "-m", f"{result['queueId']} {result['resultRevision']}"],
            cwd=work,
        )
        newsha = run(["git", "rev-parse", "HEAD"], cwd=work, capture=True).stdout.strip()
        ref = f"HEAD:refs/heads/{args.branch}"

        if oldsha:
            run(
                [
                    "git",
                    "push",
                    f"--force-with-lease=refs/heads/{args.branch}:{oldsha}",
                    args.remote,
                    ref,
                ],
                cwd=work,
            )
        else:
            run(["git", "push", args.remote, ref], cwd=work)

        info.update({"pushed": True, "newHead": newsha})

    print(json.dumps(info, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
