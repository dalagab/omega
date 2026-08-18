"""Bounded, read-only access to public HTTPS Git repositories.

This is the fallback for public source hosts that do not expose GitHub's API. It
never checks out source code or runs repository hooks; it uses a shallow partial
clone only to enumerate tracked files and reads selected text blobs with
``git show``.
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


class PublicGitSource:
    """Read bounded source blobs from a public HTTPS Git remote."""

    def __init__(self, repository: str):
        self.repository = _public_https_remote(repository)
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._directory = ""
        self.commit = ""
        self.branch = ""
        self.tree_sha = ""
        self.files: dict[str, int] = {}

    def _run(self, *args: str, binary: bool = False) -> bytes:
        environment = {
            **os.environ,
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        result = subprocess.run(
            ["git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", *args],
            cwd=self._directory or None,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=MAX_GIT_COMMAND_SECONDS,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip().replace("\n", " ")
            raise RuntimeError(f"git source retrieval failed: {detail[:400] or result.returncode}")
        return result.stdout

    def __enter__(self) -> "PublicGitSource":
        self._temporary = tempfile.TemporaryDirectory(prefix="omega-public-git-")
        directory = os.path.join(self._temporary.name, "repository")
        self._run("clone", "--no-checkout", "--depth", "1", "--no-tags", "--single-branch", "--filter=blob:limit=1048576", "--", self.repository, directory)
        self._directory = directory
        self.commit = self._run("-C", self._directory, "rev-parse", "HEAD").decode("ascii", "replace").strip()
        self.tree_sha = self._run("-C", self._directory, "rev-parse", "HEAD^{tree}").decode("ascii", "replace").strip()
        self.branch = self._run("-C", self._directory, "symbolic-ref", "--quiet", "--short", "HEAD").decode("utf-8", "replace").strip() or "HEAD"
        tree = self._run("-C", self._directory, "ls-tree", "-r", "-l", "-z", "HEAD")
        for record in tree.split(b"\0")[:MAX_GIT_TREE_ENTRIES]:
            if b"\t" not in record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            fields = metadata.split()
            if len(fields) != 4 or fields[1] != b"blob":
                continue
            try:
                size = int(fields[3])
                path = raw_path.decode("utf-8", "strict")
            except (UnicodeDecodeError, ValueError):
                continue
            if _safe_git_path(path):
                self.files[path] = size
        return self

    def read_file(self, path: str, maximum_bytes: int) -> bytes:
        if path not in self.files or self.files[path] <= 0 or self.files[path] > maximum_bytes:
            return b""
        data = self._run("-C", self._directory, "show", f"HEAD:{path}")
        if len(data) > maximum_bytes:
            raise RuntimeError(f"git source blob exceeds limit: {path}")
        return data

    def __exit__(self, *_args: object) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
