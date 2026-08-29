from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
CATALOG = ROOT / "tools" / "catalog"
for path in (SECURITY, CATALOG):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import evidence_v2_inspector


class EvidenceCacheRaceTests(unittest.TestCase):
    def test_cache_enumeration_tolerates_file_disappearing_before_stat(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = evidence_v2_inspector.RemoteEvidenceSource(
                "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/",
                Path(temp_dir),
            )
            victim = source.cache_root / "race" / "victim.bin"
            survivor = source.cache_root / "race" / "survivor.bin"
            victim.parent.mkdir(parents=True, exist_ok=True)
            victim.write_bytes(b"gone")
            survivor.write_bytes(b"present")

            original_is_file = Path.is_file
            original_stat = Path.stat

            def fake_is_file(path: Path) -> bool:
                if path == victim:
                    return True
                return original_is_file(path)

            def fake_stat(path: Path, *args, **kwargs):
                if path == victim:
                    raise FileNotFoundError(path)
                return original_stat(path, *args, **kwargs)

            with mock.patch.object(Path, "is_file", fake_is_file), mock.patch.object(Path, "stat", fake_stat):
                entries = source._cache_entries()
                status = source.cache_status()
                source._prune_cache()

            self.assertEqual([survivor], [row[0] for row in entries])
            self.assertEqual(len(b"present"), status["cacheBytes"])

    def test_cache_snapshot_ignores_in_progress_temp_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = evidence_v2_inspector.RemoteEvidenceSource(
                "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/",
                Path(temp_dir),
            )
            final = source.cache_root / "race" / "final.bin"
            temporary = source.cache_root / "race" / "final.bin.1.2.tmp"
            final.parent.mkdir(parents=True, exist_ok=True)
            final.write_bytes(b"final")
            temporary.write_bytes(b"partial")

            status = source.cache_status()

            self.assertEqual(len(b"final"), status["cacheBytes"])


if __name__ == "__main__":
    unittest.main()
