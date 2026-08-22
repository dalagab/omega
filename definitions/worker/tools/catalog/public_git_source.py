"""Bounded, read-only access to public HTTPS Git repositories.

The fallback path deliberately uses a strict partial fetch with ``blob:none``.  It
fetches refs/commit/tree metadata first, never checks out source, and asks Git for
individual blob objects only when the caller selects a file for inspection.  If a
server does not support object filtering Omega refuses the source rather than
silently downloading the whole repository.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import PurePosixPath
import socket
import subprocess
import tempfile
import urllib.parse


MAX_GIT_TREE_ENTRIES = 16_384
MAX_GIT_COMMAND_SECONDS = 75


def _public_https_remote(url: str) -> str:
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("source repository must be a public HTTPS URL without credentials")
    host = parsed.hostname.casefold()
    if host in {"localhost", "localhost.localdomain"}:
        raise ValueError("source repository host must be publicly routable")
    try:
        direct = ipaddress.ip_address(host.strip("[]"))
        if not direct.is_global:
            raise ValueError("source repository host must be publicly routable")
    except ValueError as exc:
        if "publicly routable" in str(exc):
            raise
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise ValueError("source repository host must resolve only to public addresses")
    path = parsed.path.rstrip("/")
    if not path:
        raise ValueError("source repository URL has no repository path")
    authority = host if parsed.port in {None, 443} else f"{host}:{parsed.port}"
    return urllib.parse.urlunsplit(("https", authority, path, "", ""))


def _safe_git_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value and not path.is_absolute() and ".." not in path.parts and "\\" not in value)


def _git_environment() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        # Disable hooks and external helpers from repository-controlled configuration.
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": os.devnull,
        "GIT_CONFIG_KEY_1": "credential.helper",
        "GIT_CONFIG_VALUE_1": "",
    }


def observe_remote_head(repository: str, *, timeout: float = 12.0) -> dict[str, str]:
    """Resolve a public repository HEAD ref/commit without fetching repository data."""
    remote = _public_https_remote(repository)
    result = subprocess.run(
        ["git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
         "ls-remote", "--symref", "--", remote, "HEAD"],
        env=_git_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=max(1.0, float(timeout)), check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().replace("\n", " ")
        raise RuntimeError(f"git ref observation failed: {detail[:400] or result.returncode}")
    default_ref = ""
    commit_sha = ""
    for raw_line in result.stdout.decode("utf-8", "replace").splitlines():
        line = raw_line.strip()
        if line.startswith("ref:") and "\tHEAD" in line:
            default_ref = line.split("\t", 1)[0][4:].strip()
        elif line.endswith("\tHEAD"):
            candidate = line.split("\t", 1)[0].strip().lower()
            if len(candidate) == 40 and all(ch in "0123456789abcdef" for ch in candidate):
                commit_sha = candidate
    if not commit_sha:
        raise RuntimeError("git ref observation returned no immutable HEAD commit")
    return {"repository": remote, "defaultRef": default_ref, "commitSha": commit_sha}


class PublicGitSource:
    """Read selected blobs from a public HTTPS Git remote without a checkout."""

    def __init__(self, repository: str):
        self.repository = _public_https_remote(repository)
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._directory = ""
        self.commit = ""
        self.branch = ""
        self.tree_sha = ""
        # path -> immutable blob object id. No blob sizes are requested while walking
        # the tree because doing so can cause a partial clone to hydrate every blob.
        self.files: dict[str, str] = {}
        self.blobs_read = 0
        self.blob_bytes = 0

    def _run(self, *args: str, binary: bool = False, reject_filter_fallback: bool = False) -> bytes:
        result = subprocess.run(
            ["git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", *args],
            cwd=self._directory or None,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=MAX_GIT_COMMAND_SECONDS,
            check=False,
        )
        stderr = result.stderr.decode("utf-8", "replace")
        if reject_filter_fallback and any(marker in stderr.casefold() for marker in (
            "filtering not recognized by server",
            "does not support filter",
            "filter-spec",  # servers that reject the filter request outright
        )):
            raise RuntimeError("public Git server does not support safe blobless retrieval")
        if result.returncode != 0:
            detail = stderr.strip().replace("\n", " ")
            raise RuntimeError(f"git source retrieval failed: {detail[:400] or result.returncode}")
        return result.stdout

    def __enter__(self) -> "PublicGitSource":
        observation = observe_remote_head(self.repository)
        self.branch = str(observation.get("defaultRef") or "HEAD")
        observed_commit = str(observation.get("commitSha") or "").lower()

        self._temporary = tempfile.TemporaryDirectory(prefix="omega-public-git-")
        self._directory = os.path.join(self._temporary.name, "repository")
        os.makedirs(self._directory, exist_ok=True)
        self._run("-C", self._directory, "init", "--quiet")
        self._run("-C", self._directory, "remote", "add", "origin", self.repository)
        fetch_ref = self.branch if self.branch and self.branch != "HEAD" else "HEAD"
        self._run(
            "-C", self._directory,
            "fetch", "--quiet", "--depth=1", "--no-tags", "--filter=blob:none",
            "origin", fetch_ref,
            reject_filter_fallback=True,
        )
        self.commit = self._run("-C", self._directory, "rev-parse", "FETCH_HEAD").decode("ascii", "replace").strip().lower()
        if observed_commit and self.commit != observed_commit:
            raise RuntimeError("public Git HEAD changed during source retrieval; retry on the next source event")
        self.tree_sha = self._run("-C", self._directory, "rev-parse", "FETCH_HEAD^{tree}").decode("ascii", "replace").strip().lower()
        tree = self._run("-C", self._directory, "ls-tree", "-r", "-z", "FETCH_HEAD")
        records = tree.split(b"\0")
        if len(records) > MAX_GIT_TREE_ENTRIES + 1:
            raise RuntimeError(f"public Git tree exceeds hard limit {MAX_GIT_TREE_ENTRIES}")
        for record in records:
            if b"\t" not in record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            fields = metadata.split()
            if len(fields) != 3 or fields[1] != b"blob":
                continue
            try:
                object_id = fields[2].decode("ascii", "strict").lower()
                path = raw_path.decode("utf-8", "strict")
            except UnicodeDecodeError:
                continue
            if len(object_id) == 40 and _safe_git_path(path):
                self.files[path] = object_id
        return self

    def read_file(self, path: str, maximum_bytes: int) -> bytes:
        object_id = self.files.get(path, "")
        if not object_id or maximum_bytes <= 0:
            return b""
        # cat-file hydrates this one promised blob when the remote supports partial
        # clone. The size check happens before returning the blob to the scanner.
        size_raw = self._run("-C", self._directory, "cat-file", "-s", object_id)
        try:
            size = int(size_raw.decode("ascii", "replace").strip())
        except ValueError as exc:
            raise RuntimeError(f"git source blob size is invalid: {path}") from exc
        if size <= 0 or size > maximum_bytes:
            return b""
        data = self._run("-C", self._directory, "cat-file", "blob", object_id, binary=True)
        if len(data) != size or len(data) > maximum_bytes:
            raise RuntimeError(f"git source blob exceeds limit or changed unexpectedly: {path}")
        self.blobs_read += 1
        self.blob_bytes += len(data)
        return data

    def __exit__(self, *_args: object) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
