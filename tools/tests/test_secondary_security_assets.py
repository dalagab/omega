from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import common  # noqa: F401
import definitions_snapshot
import secondary_security_assets as assets


class SecondarySecurityAssetTests(unittest.TestCase):
    @staticmethod
    def _fake_clamscan(root: Path) -> Path:
        bindir = root / "bin"
        bindir.mkdir(exist_ok=True)
        exe = bindir / "clamscan"
        exe.write_text("#!/bin/sh\necho 'ClamAV test/999/Fri Jan 1 00:00:00 2026'\n", encoding="utf-8")
        exe.chmod(0o755)
        return bindir

    def test_clamav_asset_is_content_addressed_and_materializes_verified_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-clamav-asset-") as td:
            root = Path(td)
            database = root / "database"
            database.mkdir()
            (database / "main.cvd").write_bytes(b"main-db-fixture")
            (database / "daily.cld").write_bytes(b"daily-db-fixture")
            bindir = self._fake_clamscan(root)
            manifest_path = root / "asset-manifest.json"
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                manifest = assets.build_clamav_asset(
                    database_dir=database,
                    output_dir=root / "assets",
                    asset_base_url="https://github.com/dalagab/omega/releases/download/catalog-latest",
                    manifest_output=manifest_path,
                )
                evidence = root / "evidence"
                evidence.mkdir()
                definitions = root / "definitions"
                definitions_snapshot.build_snapshot(
                    repo_root=common.ROOT,
                    evidence_root=evidence,
                    output=definitions,
                    secondary_security_asset_manifest=manifest_path,
                )
                frozen = json.loads((definitions / "secondary-security" / "index.json").read_text(encoding="utf-8"))
                clamav = next(item for item in frozen["engines"] if item["engine"] == "clamav")
                self.assertEqual("configured", clamav["status"])
                self.assertEqual(manifest["revision"], clamav["transport"]["revision"])
                runtime = assets.materialize_clamav_asset(
                    definitions_root=definitions,
                    output=root / "runtime",
                    asset_file=root / "assets" / manifest["asset"]["name"],
                )
            self.assertEqual("ready", runtime["status"])
            self.assertEqual(b"main-db-fixture", (root / "runtime" / "clamav" / "main.cvd").read_bytes())
            self.assertTrue(runtime["executableIdentity"]["verified"])

    def test_tampered_asset_is_rejected_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-clamav-tamper-") as td:
            root = Path(td)
            database = root / "database"
            database.mkdir()
            (database / "main.cvd").write_bytes(b"main-db-fixture")
            bindir = self._fake_clamscan(root)
            manifest_path = root / "asset-manifest.json"
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                manifest = assets.build_clamav_asset(
                    database_dir=database,
                    output_dir=root / "assets",
                    asset_base_url="https://github.com/dalagab/omega/releases/download/catalog-latest",
                    manifest_output=manifest_path,
                )
                evidence = root / "evidence"
                evidence.mkdir()
                definitions = root / "definitions"
                definitions_snapshot.build_snapshot(
                    repo_root=common.ROOT,
                    evidence_root=evidence,
                    output=definitions,
                    secondary_security_asset_manifest=manifest_path,
                )
                asset_path = root / "assets" / manifest["asset"]["name"]
                asset_path.write_bytes(asset_path.read_bytes() + b"tamper")
                with self.assertRaisesRegex(RuntimeError, "byte count|SHA-256"):
                    assets.materialize_clamav_asset(
                        definitions_root=definitions, output=root / "runtime", asset_file=asset_path,
                    )

    def test_executable_identity_mismatch_disables_engine_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-clamav-exe-") as td:
            root = Path(td)
            bindir = self._fake_clamscan(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir)}):
                identity = assets.executable_identity("clamscan")
                (bindir / "clamscan").write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
                (bindir / "clamscan").chmod(0o755)
                result = assets.verify_executable_identity(identity)
            self.assertFalse(result["verified"])
            self.assertIn("mismatch", result["error"].lower())


    def test_previous_frozen_clamav_transport_can_be_retained(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-clamav-retain-") as td:
            root = Path(td)
            database = root / "database"
            database.mkdir()
            (database / "main.cvd").write_bytes(b"previous-main-db")
            bindir = self._fake_clamscan(root)
            source_manifest = root / "source-manifest.json"
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                original = assets.build_clamav_asset(
                    database_dir=database,
                    output_dir=root / "assets",
                    asset_base_url="https://github.com/dalagab/omega/releases/download/sigmascope-definitions",
                    manifest_output=source_manifest,
                )
            previous = root / "previous-definitions"
            secondary = previous / "secondary-security"
            secondary.mkdir(parents=True)
            (secondary / "index.json").write_text(json.dumps({
                "engines": [{"engine": "clamav", "status": "configured", "transport": original}],
            }), encoding="utf-8")
            retained_path = root / "retained.json"
            retained = assets.retain_previous_clamav_transport(
                definitions_root=previous, manifest_output=retained_path,
            )
            self.assertEqual(original["revision"], retained["revision"])
            self.assertEqual(original, json.loads(retained_path.read_text(encoding="utf-8")))

    def test_missing_previous_clamav_transport_is_a_clean_optional_miss(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-clamav-retain-missing-") as td:
            root = Path(td)
            output = root / "retained.json"
            retained = assets.retain_previous_clamav_transport(
                definitions_root=root / "missing-definitions", manifest_output=output,
            )
            self.assertIsNone(retained)
            self.assertFalse(output.exists())

    def test_invalid_previous_clamav_transport_is_never_republished(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-clamav-retain-invalid-") as td:
            root = Path(td)
            secondary = root / "definitions" / "secondary-security"
            secondary.mkdir(parents=True)
            (secondary / "index.json").write_text(json.dumps({
                "engines": [{"engine": "clamav", "transport": {"schema": assets.ASSET_MANIFEST_SCHEMA}}],
            }), encoding="utf-8")
            output = root / "retained.json"
            with self.assertRaisesRegex(RuntimeError, "previous frozen ClamAV transport is invalid"):
                assets.retain_previous_clamav_transport(
                    definitions_root=root / "definitions", manifest_output=output,
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
