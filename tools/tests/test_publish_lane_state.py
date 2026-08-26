\
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


MODULE = Path(__file__).parents[1] / "orchestration" / "publish_lane_state.py"
spec = importlib.util.spec_from_file_location("publish_lane_state", MODULE)
publish_lane_state = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(publish_lane_state)


class PublishLaneStateSafeDirectoryTests(unittest.TestCase):
    def test_repository_root_trusts_only_requested_checkout(self):
        repo = Path("/__w/omega/omega")
        response = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="/__w/omega/omega\n", stderr=""
        )
        with mock.patch.object(publish_lane_state, "run", return_value=response) as run:
            root = publish_lane_state._repository_root(repo)

        self.assertEqual(Path("/__w/omega/omega"), root)
        command = run.call_args.args[0]
        self.assertEqual(
            [
                "git",
                "-c",
                "safe.directory=/__w/omega/omega",
                "rev-parse",
                "--show-toplevel",
            ],
            command,
        )
        self.assertNotIn("safe.directory=*", command)

    def test_remote_url_uses_exact_root_safe_directory(self):
        root = Path("/__w/omega/omega")
        response = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="https://github.com/dalagab/omega\n",
            stderr="",
        )
        with mock.patch.object(publish_lane_state, "run", return_value=response) as run:
            url = publish_lane_state._remote_url(root, "origin")

        self.assertEqual("https://github.com/dalagab/omega", url)
        self.assertEqual(
            [
                "git",
                "-c",
                "safe.directory=/__w/omega/omega",
                "remote",
                "get-url",
                "origin",
            ],
            run.call_args.args[0],
        )

    def test_repository_root_rejects_unrelated_result(self):
        repo = Path("/__w/omega/omega")
        response = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="/tmp/unrelated\n", stderr=""
        )
        with mock.patch.object(publish_lane_state, "run", return_value=response):
            with self.assertRaises(RuntimeError):
                publish_lane_state._repository_root(repo)


if __name__ == "__main__":
    unittest.main()
