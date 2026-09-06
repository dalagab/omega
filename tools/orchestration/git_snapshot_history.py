#!/usr/bin/env python3
"""Shared Git publication helper for authoritative snapshot branches.

Authoritative catalog/Evidence snapshots are content-addressed application state, but Git
can additionally provide a trustworthy transport history: each accepted snapshot becomes
a normal child of the exact remote head observed at publication time.  A normal push then
fails closed if the branch advanced concurrently.

Operational/replaceable state branches intentionally do not use this helper; their bounded
snapshot semantics remain separate from forensic publication history.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Iterable


HISTORY_FAST_FORWARD = "fast-forward"
HISTORY_LEGACY_ORPHAN = "legacy-orphan"
HISTORY_MODES = (HISTORY_FAST_FORWARD, HISTORY_LEGACY_ORPHAN)


def run(
    cmd: list[str],
    *,
    cwd: Path,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=capture, check=check)


def _repo_git(repo: Path, *args: str) -> list[str]:
    """Build a Git command that trusts only the exact mounted checkout.

    GitHub Actions job containers execute against a host-owned workspace mount.  Checkout's
    temporary HOME makes that workspace safe only for the checkout action itself, so later
    container steps must opt into the exact repository path again.  Never use
    ``safe.directory=*`` here: authoritative publication should not broaden Git trust.
    """
    return ["git", "-c", "core.longpaths=true", "-c", f"safe.directory={repo.resolve()}", *args]


def platform_path(path: Path) -> Path:
    if os.name != "nt":
        return path
    resolved = str(path.resolve())
    if resolved.startswith("\\\\?\\"):
        return Path(resolved)
    return Path("\\\\?\\" + resolved)


def publication_temp_parent(source: Path) -> Path | None:
    if os.name != "nt":
        return None
    override = os.environ.get("OMEGA_GIT_SNAPSHOT_TEMP")
    if override:
        parent = Path(override)
    else:
        parent = Path(source.anchor or "C:/") / "osg"
    platform_path(parent).mkdir(parents=True, exist_ok=True)
    return parent


def git_root(path: Path) -> Path:
    requested = path.resolve()
    result = run(_repo_git(requested, "rev-parse", "--show-toplevel"), cwd=requested, capture=True)
    root = Path(result.stdout.strip()).resolve()
    if root != requested:
        raise RuntimeError(f"authoritative publication repo must be its exact Git root: requested={requested}, root={root}")
    return root


def remote_url(repo: Path, remote: str) -> str:
    repo = repo.resolve()
    result = run(_repo_git(repo, "remote", "get-url", remote), cwd=repo, capture=True)
    url = result.stdout.strip()
    if not url:
        raise RuntimeError(f"Git remote {remote!r} has no URL")
    return url


def remote_branch_sha(repo: Path, url: str, branch: str) -> str:
    repo = repo.resolve()
    # Use the already-resolved URL instead of asking Git to resolve a remote name from the
    # mounted checkout a second time.  Keep the exact-path trust option nevertheless so this
    # call is safe even if Git consults repository configuration in a future version.
    result = run(
        _repo_git(repo, "ls-remote", "--heads", url, f"refs/heads/{branch}"),
        cwd=repo,
        capture=True,
    )
    line = result.stdout.strip()
    return line.split()[0] if line else ""


def _copy_tree(
    source: Path,
    target: Path,
    *,
    excluded_names: frozenset[str],
    excluded_prefixes: tuple[str, ...],
) -> None:
    source = source.resolve()
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.name in excluded_names:
            continue
        rel = path.relative_to(source).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        if any(rel == prefix or rel.startswith(prefix.rstrip("/") + "/") for prefix in excluded_prefixes):
            continue
        destination = target / rel
        platform_path(destination.parent).mkdir(parents=True, exist_ok=True)
        shutil.copy2(platform_path(path), platform_path(destination))


@dataclass(frozen=True)
class PublicationResult:
    previous_head: str
    new_head: str
    tree_sha: str
    pushed: bool
    no_op: bool
    history_mode: str
    parent_head: str

    def as_dict(self) -> dict[str, object]:
        return {
            "previousHead": self.previous_head,
            "newHead": self.new_head,
            "treeSha": self.tree_sha,
            "pushed": self.pushed,
            "noOp": self.no_op,
            "historyMode": self.history_mode,
            "parentHead": self.parent_head,
        }


def publish_snapshot_tree(
    source: Path,
    *,
    repo: Path,
    remote: str,
    branch: str,
    push: bool,
    author_name: str,
    author_email: str,
    commit_message: str,
    history_mode: str = HISTORY_FAST_FORWARD,
    excluded_names: Iterable[str] = (),
    excluded_prefixes: Iterable[str] = (),
    expected_previous_head: str | None = None,
) -> PublicationResult:
    """Publish *source* as one exact branch snapshot.

    ``fast-forward`` is the normal authoritative mode.  The exact remote head is fetched,
    checked out, replaced by ``source`` and used as the new commit's parent.  A normal Git
    push provides an additional concurrency guard: if the branch advances after the fetch,
    publication is rejected rather than rewriting history.

    ``legacy-orphan`` preserves the pre-migration force-with-lease behavior as an explicit
    emergency fallback.  It is never selected implicitly.
    """
    if history_mode not in HISTORY_MODES:
        raise ValueError(f"unsupported history mode {history_mode!r}; expected one of {HISTORY_MODES!r}")
    source = source.resolve()
    if not source.is_dir():
        raise RuntimeError(f"snapshot source is not a directory: {source}")

    repo = git_root(repo.resolve())
    url = remote_url(repo, remote)
    old_sha = remote_branch_sha(repo, url, branch)
    if expected_previous_head is not None and old_sha != expected_previous_head:
        raise RuntimeError(
            f"remote {branch!r} head mismatch: expected {expected_previous_head or '<missing>'}, observed {old_sha or '<missing>'}"
        )

    if not push:
        return PublicationResult(
            previous_head=old_sha,
            new_head="",
            tree_sha="",
            pushed=False,
            no_op=False,
            history_mode=history_mode,
            parent_head=old_sha if history_mode == HISTORY_FAST_FORWARD else "",
        )

    with tempfile.TemporaryDirectory(prefix="pub-", dir=publication_temp_parent(source)) as td:
        work = Path(td)
        run(["git", "init", "-q"], cwd=work)
        run(["git", "config", "user.name", author_name], cwd=work)
        run(["git", "config", "user.email", author_email], cwd=work)
        run(["git", "config", "core.longpaths", "true"], cwd=work)
        run(["git", "config", "core.autocrlf", "false"], cwd=work)
        run(["git", "remote", "add", remote, url], cwd=work)

        parent_head = ""
        if history_mode == HISTORY_FAST_FORWARD and old_sha:
            run(
                ["git", "fetch", "--no-tags", "--depth=1", remote, f"refs/heads/{branch}:refs/remotes/{remote}/{branch}"],
                cwd=work,
            )
            fetched = run(["git", "rev-parse", f"refs/remotes/{remote}/{branch}"], cwd=work, capture=True).stdout.strip()
            if fetched != old_sha:
                raise RuntimeError(f"remote {branch!r} changed while preparing publication: expected {old_sha}, fetched {fetched}")
            run(["git", "checkout", "-q", "-B", branch, fetched], cwd=work)
            parent_head = fetched
            run(["git", "rm", "-r", "-q", "--ignore-unmatch", "."], cwd=work)
        else:
            run(["git", "checkout", "-q", "--orphan", branch], cwd=work)

        _copy_tree(
            source,
            work,
            excluded_names=frozenset(excluded_names),
            excluded_prefixes=tuple(excluded_prefixes),
        )
        run(["git", "add", "--all"], cwd=work)

        if history_mode == HISTORY_FAST_FORWARD and old_sha:
            diff = run(["git", "diff", "--cached", "--quiet"], cwd=work, check=False)
            if diff.returncode == 0:
                tree_sha = run(["git", "rev-parse", f"{old_sha}^{{tree}}"], cwd=work, capture=True).stdout.strip()
                return PublicationResult(
                    previous_head=old_sha,
                    new_head=old_sha,
                    tree_sha=tree_sha,
                    pushed=False,
                    no_op=True,
                    history_mode=history_mode,
                    parent_head=old_sha,
                )
            if diff.returncode != 1:
                raise RuntimeError(f"git diff --cached failed with exit code {diff.returncode}")

        run(["git", "commit", "-q", "-m", commit_message], cwd=work)
        new_sha = run(["git", "rev-parse", "HEAD"], cwd=work, capture=True).stdout.strip()
        tree_sha = run(["git", "rev-parse", "HEAD^{tree}"], cwd=work, capture=True).stdout.strip()
        refspec = f"HEAD:refs/heads/{branch}"

        if history_mode == HISTORY_FAST_FORWARD:
            # Normal push only: a concurrent remote advance must fail instead of being rewritten.
            run(["git", "push", remote, refspec], cwd=work)
        elif old_sha:
            run(["git", "push", f"--force-with-lease=refs/heads/{branch}:{old_sha}", remote, refspec], cwd=work)
        else:
            run(["git", "push", remote, refspec], cwd=work)

        return PublicationResult(
            previous_head=old_sha,
            new_head=new_sha,
            tree_sha=tree_sha,
            pushed=True,
            no_op=False,
            history_mode=history_mode,
            parent_head=parent_head,
        )
