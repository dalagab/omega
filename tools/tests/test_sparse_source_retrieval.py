from __future__ import annotations

import base64
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import common

CATALOG = common.ROOT / "tools" / "catalog"
if str(CATALOG) not in sys.path:
    sys.path.insert(0, str(CATALOG))

import public_git_source
import sigmascope


class SparseSourceRetrievalTests(unittest.TestCase):
    def test_github_tree_fetches_only_selected_blob_objects(self) -> None:
        files = {
            "Plugin/Plugin.csproj": b'<Project Sdk="Dalamud.NET.Sdk/15.0.0" />',
            "Plugin/Plugin.json": b'{"InternalName":"Plugin","AssemblyVersion":"1.0.0"}',
            "Plugin/Code.cs": b"class Code {}",
        }
        ids = {path: (hex(index + 1)[2:] * 40)[:40] for index, path in enumerate(files)}
        tree = {
            "truncated": False,
            "tree": [
                {"path": path, "type": "blob", "sha": ids[path], "size": len(raw)}
                for path, raw in files.items()
            ] + [{"path": "assets/big.bin", "type": "blob", "sha": "f" * 40, "size": 500_000}],
        }
        calls: list[str] = []

        def fake_json(url: str, _headers: dict[str, str], timeout: float = 20.0):
            calls.append(url)
            if "/git/trees/" in url:
                return tree
            for path, object_id in ids.items():
                if url.endswith("/git/blobs/" + object_id):
                    return {"encoding": "base64", "content": base64.b64encode(files[path]).decode("ascii")}
            raise AssertionError(url)

        with mock.patch.object(sigmascope, "_github_json", side_effect=fake_json):
            entries, blob_ids, read_file, stats = sigmascope._github_source_tree(
                "https://api.github.com/repos/example/plugin", "a" * 40, {"User-Agent": "test"}
            )
            self.assertEqual(set(files), set(entries))
            self.assertEqual(ids["Plugin/Plugin.csproj"], blob_ids["Plugin/Plugin.csproj"])
            self.assertEqual(files["Plugin/Plugin.csproj"], read_file("Plugin/Plugin.csproj"))
            self.assertEqual(1, stats["blobsRead"])
            self.assertEqual(2, len(calls), "tree metadata + exactly one selected blob should be fetched")
            self.assertTrue(all("zipball" not in call for call in calls))

    def test_public_git_uses_blob_none_fetch_without_checkout_or_clone(self) -> None:
        observed = "a" * 40
        tree_sha = "b" * 40
        blob_sha = "c" * 40
        commands: list[tuple[str, ...]] = []

        def fake_run(_self, *args: str, **_kwargs):
            commands.append(tuple(args))
            if args[-2:] == ("rev-parse", "FETCH_HEAD"):
                return (observed + "\n").encode()
            if args[-2:] == ("rev-parse", "FETCH_HEAD^{tree}"):
                return (tree_sha + "\n").encode()
            if "ls-tree" in args:
                return f"100644 blob {blob_sha}\tPlugin/Code.cs\0".encode()
            return b""

        source = public_git_source.PublicGitSource("https://8.8.8.8/example/repo")
        with mock.patch.object(public_git_source, "observe_remote_head", return_value={
            "repository": source.repository, "defaultRef": "refs/heads/main", "commitSha": observed,
        }), mock.patch.object(public_git_source.PublicGitSource, "_run", autospec=True, side_effect=fake_run):
            with source as opened:
                self.assertEqual(observed, opened.commit)
                self.assertIn("Plugin/Code.cs", opened.files)

        flattened = [item for command in commands for item in command]
        self.assertNotIn("clone", flattened)
        self.assertNotIn("checkout", flattened)
        fetch = next(command for command in commands if "fetch" in command)
        self.assertIn("--filter=blob:none", fetch)
        ls_tree = next(command for command in commands if "ls-tree" in command)
        self.assertNotIn("-l", ls_tree, "tree enumeration must not hydrate blobs merely to obtain sizes")

    def test_public_git_rejects_server_filter_fallback(self) -> None:
        source = public_git_source.PublicGitSource("https://8.8.8.8/example/repo")
        source._directory = tempfile.mkdtemp(prefix="omega-filter-test-")
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout=b"", stderr=b"warning: filtering not recognized by server, ignoring\n"
        )
        with mock.patch("public_git_source.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "does not support safe blobless retrieval"):
                source._run("fetch", "--filter=blob:none", reject_filter_fallback=True)

    def test_production_source_has_no_github_zipball_or_git_clone_fallback(self) -> None:
        scanner = (CATALOG / "sigmascope.py").read_text(encoding="utf-8")
        git_source = (CATALOG / "public_git_source.py").read_text(encoding="utf-8")
        self.assertNotIn("/zipball/", scanner)
        self.assertNotIn('"clone"', git_source)
        self.assertIn('"--filter=blob:none"', git_source)
        self.assertIn("/git/trees/", scanner)
        self.assertIn("/git/blobs/", scanner)


if __name__ == "__main__":
    unittest.main()
