#!/usr/bin/env python3
"""Fast authoritative publication of an already validated SigmaScope Git transport.

The merge stage has already constructed and validated the complete Evidence candidate.
This module verifies the parent-bound Git bundle and a raw changed-object manifest, then
publishes the validated tree without materializing or hashing the complete Evidence tree.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

TRANSPORT_SCHEMA = "omega.sigmascope.evidence-transport.v1"
MARKER_SCHEMA = "omega.sigmascope.transport-publication-marker.v1"
TRANSPORT_ONLY_MARKER = ".sigmascope-transport-only.json"
BUNDLE_REF = "refs/sigmascope/transport/candidate"
CHANGE_MANIFEST = "candidate-changed-objects.txt"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha(value: str, label: str) -> str:
    value = str(value or "").strip().lower()
    if not SHA_RE.fullmatch(value):
        raise RuntimeError(f"{label} must be an exact 40-character Git SHA")
    return value


def _git(
    repository: Path,
    *args: str,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        text=True,
        encoding="utf-8",
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    return completed.stdout.strip()


def _git_bytes(repository: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


def changed_object_manifest_bytes(repository: Path, parent: str, candidate: str) -> bytes:
    """Return deterministic changed/deleted paths with old/new Git object hashes."""
    return _git_bytes(
        repository,
        "diff-tree",
        "--no-commit-id",
        "--raw",
        "--no-abbrev",
        "--no-renames",
        "-r",
        parent,
        candidate,
    )


def _read_metadata(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != TRANSPORT_SCHEMA:
        raise RuntimeError("unsupported SigmaScope Evidence transport metadata")
    return value


def _verify_change_manifest(
    repository: Path,
    parent: str,
    candidate: str,
    metadata: dict[str, Any],
    metadata_path: Path,
) -> dict[str, Any]:
    descriptor = metadata.get("changedObjectManifest")
    if not isinstance(descriptor, dict):
        raise RuntimeError("Evidence transport lacks changed-object manifest metadata")
    if str(descriptor.get("path") or "") != CHANGE_MANIFEST:
        raise RuntimeError("unexpected Evidence changed-object manifest path")
    manifest_path = metadata_path.parent / CHANGE_MANIFEST
    if not manifest_path.is_file():
        raise RuntimeError("Evidence changed-object manifest is missing")
    payload = manifest_path.read_bytes()
    if int(descriptor.get("bytes") or -1) != len(payload):
        raise RuntimeError("Evidence changed-object manifest size mismatch")
    if str(descriptor.get("sha256") or "").lower() != _sha256_bytes(payload):
        raise RuntimeError("Evidence changed-object manifest SHA-256 mismatch")
    actual = changed_object_manifest_bytes(repository, parent, candidate)
    if actual != payload:
        raise RuntimeError("Evidence changed-object manifest differs from candidate Git objects")
    records = len([line for line in payload.splitlines() if line.strip()])
    if records != int(descriptor.get("records") or -1):
        raise RuntimeError("Evidence changed-object manifest record count mismatch")
    if records != int(metadata.get("changedPathCount") or -1):
        raise RuntimeError("Evidence changed-path count differs from changed-object manifest")
    return {"records": records, "bytes": len(payload), "sha256": _sha256_bytes(payload)}


def verify_transport_for_publication(
    repository: Path,
    bundle: Path,
    metadata_path: Path,
    output: Path,
    *,
    expected_parent_sha: str,
    expected_index_sha: str = "",
) -> dict[str, Any]:
    """Verify transport authority and materialize only publisher control files.

    No candidate archive is extracted. The bundle's candidate commit/tree remains in the
    existing Evidence repository, while only index.json and validation-report.json are
    copied out for the existing publication gates.
    """
    repository = repository.resolve()
    bundle = bundle.resolve()
    metadata_path = metadata_path.resolve()
    output = output.resolve()
    parent = _require_sha(expected_parent_sha, "expected parent")
    metadata = _read_metadata(metadata_path)

    if _require_sha(str(metadata.get("parentSha") or ""), "transport parent") != parent:
        raise RuntimeError("transport metadata parent differs from planned Evidence parent")
    current = _require_sha(_git(repository, "rev-parse", "HEAD"), "repository HEAD")
    if current != parent:
        raise RuntimeError(f"Evidence moved before transport verification: expected={parent} current={current}")
    if int(metadata.get("bundleBytes") or -1) != bundle.stat().st_size:
        raise RuntimeError("Evidence transport bundle size mismatch")
    if str(metadata.get("bundleSha256") or "").lower() != _sha256_file(bundle):
        raise RuntimeError("Evidence transport bundle SHA-256 mismatch")

    _git(repository, "bundle", "verify", str(bundle))
    if str(metadata.get("bundleRef") or "") != BUNDLE_REF:
        raise RuntimeError("unexpected Evidence transport bundle ref")
    listed = _git(repository, "bundle", "list-heads", str(bundle), BUNDLE_REF).splitlines()
    if len(listed) != 1:
        raise RuntimeError("Evidence transport bundle does not expose exactly one candidate ref")
    listed_sha, listed_ref = listed[0].split(maxsplit=1)
    candidate = _require_sha(str(metadata.get("candidateCommitSha") or ""), "transport candidate commit")
    if listed_ref.strip() != BUNDLE_REF or listed_sha.lower() != candidate:
        raise RuntimeError("Evidence transport bundle head differs from metadata")

    _git(repository, "fetch", "--no-tags", str(bundle), BUNDLE_REF)
    if _require_sha(_git(repository, "rev-parse", "FETCH_HEAD"), "fetched candidate") != candidate:
        raise RuntimeError("Evidence transport fetched candidate differs from metadata")
    if _git(repository, "show", "-s", "--format=%P", candidate).split() != [parent]:
        raise RuntimeError("Evidence transport candidate is not an exact child of the planned parent")
    tree = _require_sha(_git(repository, "show", "-s", "--format=%T", candidate), "candidate tree")
    if tree != _require_sha(str(metadata.get("candidateTreeSha") or ""), "transport candidate tree"):
        raise RuntimeError("Evidence transport candidate tree differs from metadata")

    manifest = _verify_change_manifest(repository, parent, candidate, metadata, metadata_path)
    index_bytes = _git_bytes(repository, "show", f"{candidate}:index.json")
    index_sha = _sha256_bytes(index_bytes)
    if index_sha != str(metadata.get("candidateIndexSha256") or "").lower():
        raise RuntimeError("Evidence candidate index differs from transport metadata")
    if expected_index_sha and index_sha != str(expected_index_sha).strip().lower():
        raise RuntimeError("Evidence candidate index differs from serialized merge authorization")
    validation_bytes = _git_bytes(repository, "show", f"{candidate}:validation-report.json")

    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "index.json").write_bytes(index_bytes)
    (output / "validation-report.json").write_bytes(validation_bytes)
    marker = {
        "schema": MARKER_SCHEMA,
        "parentSha": parent,
        "candidateCommitSha": candidate,
        "candidateTreeSha": tree,
        "candidateIndexSha256": index_sha,
        "bundleSha256": str(metadata.get("bundleSha256") or ""),
        "changedObjectManifest": manifest,
    }
    (output / TRANSPORT_ONLY_MARKER).write_text(
        json.dumps(marker, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return {
        **marker,
        "schema": TRANSPORT_SCHEMA,
        "markerSchema": MARKER_SCHEMA,
        "authority": "verified-transport-only-no-evidence-publication",
        "bundleBytes": bundle.stat().st_size,
    }


def publish_verified_transport_tree(
    repository: Path,
    metadata_path: Path,
    *,
    remote: str,
    branch: str,
    expected_parent_sha: str,
    commit_message: str,
    push: bool,
) -> dict[str, Any]:
    """Create a normal child commit from the verified candidate tree and push it."""
    repository = repository.resolve()
    metadata = _read_metadata(metadata_path.resolve())
    parent = _require_sha(expected_parent_sha, "expected parent")
    if _require_sha(str(metadata.get("parentSha") or ""), "transport parent") != parent:
        raise RuntimeError("transport metadata parent differs from publication parent")
    candidate = _require_sha(str(metadata.get("candidateCommitSha") or ""), "transport candidate commit")
    tree = _require_sha(str(metadata.get("candidateTreeSha") or ""), "transport candidate tree")
    if _git(repository, "show", "-s", "--format=%P", candidate).split() != [parent]:
        raise RuntimeError("candidate parent changed before publication")
    if _require_sha(_git(repository, "show", "-s", "--format=%T", candidate), "candidate tree") != tree:
        raise RuntimeError("candidate tree changed before publication")

    remote_head_line = _git(repository, "ls-remote", "--heads", remote, f"refs/heads/{branch}")
    remote_head = remote_head_line.split()[0] if remote_head_line else ""
    if remote_head != parent:
        raise RuntimeError(
            f"remote {branch!r} head mismatch: expected {parent or '<missing>'}, observed {remote_head or '<missing>'}"
        )
    parent_tree = _require_sha(_git(repository, "show", "-s", "--format=%T", parent), "parent tree")
    if tree == parent_tree:
        return {
            "previousHead": parent,
            "newHead": parent,
            "treeSha": tree,
            "pushed": False,
            "noOp": True,
            "historyMode": "fast-forward",
            "parentHead": parent,
            "publicationMode": "validated-git-transport",
        }
    if not push:
        return {
            "previousHead": parent,
            "newHead": "",
            "treeSha": tree,
            "pushed": False,
            "noOp": False,
            "historyMode": "fast-forward",
            "parentHead": parent,
            "publicationMode": "validated-git-transport",
        }

    env = os.environ.copy()
    env.update({
        "GIT_AUTHOR_NAME": "Omega Evidence Publisher",
        "GIT_AUTHOR_EMAIL": "omega-evidence@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "Omega Evidence Publisher",
        "GIT_COMMITTER_EMAIL": "omega-evidence@users.noreply.github.com",
    })
    commit = _require_sha(
        _git(repository, "commit-tree", tree, "-p", parent, input_text=commit_message + "\n", env=env),
        "publication commit",
    )
    _git(repository, "push", remote, f"{commit}:refs/heads/{branch}")
    published_line = _git(repository, "ls-remote", "--heads", remote, f"refs/heads/{branch}")
    published = published_line.split()[0] if published_line else ""
    if published != commit:
        raise RuntimeError("published Evidence head does not equal the direct Git-object commit")
    return {
        "previousHead": parent,
        "newHead": commit,
        "treeSha": tree,
        "pushed": True,
        "noOp": False,
        "historyMode": "fast-forward",
        "parentHead": parent,
        "publicationMode": "validated-git-transport",
    }
