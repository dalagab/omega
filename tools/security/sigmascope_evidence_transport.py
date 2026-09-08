#!/usr/bin/env python3
"""Create and rehydrate parent-bound incremental Git transport for SigmaScope Evidence.

The transport is deliberately non-authoritative. It carries an already validated
candidate tree between the merger and the one-writer publisher while excluding Git
objects that are already reachable from the exact published Evidence parent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from typing import Any

SCHEMA = "omega.sigmascope.evidence-transport.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BUNDLE_REF = "refs/sigmascope/transport/candidate"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_git(repo: Path, *args: str, env: dict[str, str] | None = None, input_text: str | None = None) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        encoding="utf-8",
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    return completed.stdout.strip()


def _plumbing_git(repo: Path, work_tree: Path, index_file: Path, *args: str, input_text: str | None = None) -> str:
    env = os.environ.copy()
    env.update({
        "GIT_INDEX_FILE": str(index_file),
        "GIT_AUTHOR_NAME": "SigmaScope transport",
        "GIT_AUTHOR_EMAIL": "sigmascope@omega.invalid",
        "GIT_COMMITTER_NAME": "SigmaScope transport",
        "GIT_COMMITTER_EMAIL": "sigmascope@omega.invalid",
        # The transport commit is ephemeral. Fixed timestamps make identical
        # parent/tree pairs deterministic and keep the carrier free of clock noise.
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    })
    completed = subprocess.run(
        [
            "git",
            f"--git-dir={repo / '.git'}",
            f"--work-tree={work_tree}",
            *args,
        ],
        cwd=work_tree,
        check=True,
        text=True,
        encoding="utf-8",
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    return completed.stdout.strip()


def _require_sha(value: str, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not SHA_RE.fullmatch(normalized):
        raise ValueError(f"{label} must be an exact 40-character Git SHA")
    return normalized


def _read_metadata(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("unsupported SigmaScope Evidence transport metadata")
    return value


def create_transport(
    repository: Path,
    candidate: Path,
    bundle: Path,
    metadata_path: Path,
    *,
    expected_parent_sha: str,
    expected_index_sha: str = "",
) -> dict[str, Any]:
    repository = repository.resolve()
    candidate = candidate.resolve()
    bundle = bundle.resolve()
    metadata_path = metadata_path.resolve()
    parent = _require_sha(expected_parent_sha, "expected parent")
    actual_head = _require_sha(_run_git(repository, "rev-parse", "HEAD"), "repository HEAD")
    if actual_head != parent:
        raise RuntimeError(f"Evidence transport parent mismatch: expected={parent} current={actual_head}")
    index_path = candidate / "index.json"
    if not index_path.is_file():
        raise FileNotFoundError(index_path)
    candidate_index_sha = sha256_file(index_path)
    if expected_index_sha and candidate_index_sha != str(expected_index_sha).strip().lower():
        raise RuntimeError("candidate index SHA differs from serialized merge authorization")

    bundle.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    if bundle.exists():
        bundle.unlink()

    with tempfile.TemporaryDirectory(prefix="sigmascope-transport-index-") as td:
        index_file = Path(td) / "candidate.index"
        _plumbing_git(repository, candidate, index_file, "read-tree", "--empty")
        _plumbing_git(repository, candidate, index_file, "add", "--all", "--", ".")
        tree_sha = _require_sha(_plumbing_git(repository, candidate, index_file, "write-tree"), "candidate tree")
        commit_sha = _require_sha(
            _plumbing_git(
                repository,
                candidate,
                index_file,
                "commit-tree",
                tree_sha,
                "-p",
                parent,
                input_text=f"SigmaScope candidate transport {candidate_index_sha[:16]}\n",
            ),
            "candidate transport commit",
        )

    _run_git(repository, "update-ref", BUNDLE_REF, commit_sha)
    try:
        _run_git(repository, "bundle", "create", str(bundle), BUNDLE_REF, f"^{parent}")
        _run_git(repository, "bundle", "verify", str(bundle))
        changed_raw = _run_git(repository, "diff-tree", "--no-commit-id", "--name-only", "-r", parent, commit_sha)
    finally:
        subprocess.run(
            ["git", "-C", str(repository), "update-ref", "-d", BUNDLE_REF],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    changed_paths = [line for line in changed_raw.splitlines() if line.strip()]
    result = {
        "schema": SCHEMA,
        "authority": "transport-only-no-evidence-publication",
        "parentSha": parent,
        "candidateCommitSha": commit_sha,
        "candidateTreeSha": tree_sha,
        "candidateIndexSha256": candidate_index_sha,
        "bundleRef": BUNDLE_REF,
        "bundleSha256": sha256_file(bundle),
        "bundleBytes": bundle.stat().st_size,
        "changedPathCount": len(changed_paths),
    }
    metadata_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return result


def _safe_extract_git_archive(repository: Path, commit_sha: str, output: Path) -> None:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    with subprocess.Popen(
        ["git", "-C", str(repository), "archive", "--format=tar", commit_sha],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        assert process.stdout is not None
        try:
            with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                for member in archive:
                    rel = PurePosixPath(member.name)
                    if rel.is_absolute() or ".." in rel.parts:
                        raise RuntimeError(f"unsafe path in Git transport archive: {member.name}")
                    if member.issym() or member.islnk() or member.isdev():
                        raise RuntimeError(f"unsupported link/device in Git transport archive: {member.name}")
                    target = output.joinpath(*rel.parts)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    if not member.isfile():
                        raise RuntimeError(f"unsupported entry in Git transport archive: {member.name}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise RuntimeError(f"Git transport archive entry cannot be read: {member.name}")
                    with source, target.open("wb") as destination:
                        shutil.copyfileobj(source, destination, length=1024 * 1024)
                    os.chmod(target, member.mode & 0o777)
            stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr is not None else ""
            status = process.wait()
            if status != 0:
                raise RuntimeError(f"git archive failed with status {status}: {stderr[:500]}")
        except Exception:
            process.kill()
            process.wait()
            raise


def rehydrate_transport(
    repository: Path,
    bundle: Path,
    metadata_path: Path,
    output: Path,
    *,
    expected_parent_sha: str,
    expected_index_sha: str = "",
) -> dict[str, Any]:
    repository = repository.resolve()
    bundle = bundle.resolve()
    metadata_path = metadata_path.resolve()
    output = output.resolve()
    parent = _require_sha(expected_parent_sha, "expected parent")
    metadata = _read_metadata(metadata_path)
    metadata_parent = _require_sha(str(metadata.get("parentSha") or ""), "transport parent")
    if metadata_parent != parent:
        raise RuntimeError("transport metadata parent differs from planned Evidence parent")
    actual_head = _require_sha(_run_git(repository, "rev-parse", "HEAD"), "repository HEAD")
    if actual_head != parent:
        raise RuntimeError(f"Evidence moved before transport rehydration: expected={parent} current={actual_head}")
    if int(metadata.get("bundleBytes") or -1) != bundle.stat().st_size:
        raise RuntimeError("Evidence transport bundle size mismatch")
    if str(metadata.get("bundleSha256") or "").lower() != sha256_file(bundle):
        raise RuntimeError("Evidence transport bundle SHA-256 mismatch")

    _run_git(repository, "bundle", "verify", str(bundle))
    bundle_ref = str(metadata.get("bundleRef") or "")
    if bundle_ref != BUNDLE_REF:
        raise RuntimeError("unexpected Evidence transport bundle ref")
    listed = _run_git(repository, "bundle", "list-heads", str(bundle), bundle_ref).splitlines()
    if len(listed) != 1:
        raise RuntimeError("Evidence transport bundle does not expose exactly one candidate ref")
    listed_sha, listed_ref = listed[0].split(maxsplit=1)
    commit_sha = _require_sha(str(metadata.get("candidateCommitSha") or ""), "transport candidate commit")
    if listed_ref.strip() != bundle_ref or listed_sha.lower() != commit_sha:
        raise RuntimeError("Evidence transport bundle head differs from metadata")

    _run_git(repository, "fetch", "--no-tags", str(bundle), bundle_ref)
    fetched = _require_sha(_run_git(repository, "rev-parse", "FETCH_HEAD"), "fetched candidate")
    if fetched != commit_sha:
        raise RuntimeError("Evidence transport fetched candidate differs from metadata")
    parents = _run_git(repository, "show", "-s", "--format=%P", commit_sha).split()
    if parents != [parent]:
        raise RuntimeError("Evidence transport candidate is not an exact child of the planned parent")
    tree_sha = _require_sha(_run_git(repository, "show", "-s", "--format=%T", commit_sha), "fetched candidate tree")
    if tree_sha != _require_sha(str(metadata.get("candidateTreeSha") or ""), "transport candidate tree"):
        raise RuntimeError("Evidence transport candidate tree differs from metadata")

    _safe_extract_git_archive(repository, commit_sha, output)
    index_path = output / "index.json"
    if not index_path.is_file():
        raise RuntimeError("rehydrated Evidence candidate lacks index.json")
    actual_index_sha = sha256_file(index_path)
    metadata_index_sha = str(metadata.get("candidateIndexSha256") or "").lower()
    if actual_index_sha != metadata_index_sha:
        raise RuntimeError("rehydrated candidate index differs from transport metadata")
    if expected_index_sha and actual_index_sha != str(expected_index_sha).strip().lower():
        raise RuntimeError("rehydrated candidate index differs from serialized merge authorization")

    return {
        "schema": SCHEMA,
        "authority": "rehydrated-transport-only-no-evidence-publication",
        "parentSha": parent,
        "candidateCommitSha": commit_sha,
        "candidateTreeSha": tree_sha,
        "candidateIndexSha256": actual_index_sha,
        "bundleBytes": bundle.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    package = sub.add_parser("package")
    package.add_argument("--repository", type=Path, required=True)
    package.add_argument("--candidate", type=Path, required=True)
    package.add_argument("--bundle", type=Path, required=True)
    package.add_argument("--metadata", type=Path, required=True)
    package.add_argument("--expected-parent-sha", required=True)
    package.add_argument("--expected-index-sha", default="")

    rehydrate = sub.add_parser("rehydrate")
    rehydrate.add_argument("--repository", type=Path, required=True)
    rehydrate.add_argument("--bundle", type=Path, required=True)
    rehydrate.add_argument("--metadata", type=Path, required=True)
    rehydrate.add_argument("--output", type=Path, required=True)
    rehydrate.add_argument("--report", type=Path)
    rehydrate.add_argument("--expected-parent-sha", required=True)
    rehydrate.add_argument("--expected-index-sha", default="")

    args = parser.parse_args()
    if args.command == "package":
        result = create_transport(
            args.repository,
            args.candidate,
            args.bundle,
            args.metadata,
            expected_parent_sha=args.expected_parent_sha,
            expected_index_sha=args.expected_index_sha,
        )
    else:
        result = rehydrate_transport(
            args.repository,
            args.bundle,
            args.metadata,
            args.output,
            expected_parent_sha=args.expected_parent_sha,
            expected_index_sha=args.expected_index_sha,
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
