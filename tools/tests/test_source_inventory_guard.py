from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import source_inventory_guard


class SourceInventoryGuardTests(unittest.TestCase):
    def _write(self, path: Path, value) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_unreachable_sources_remain_valid_catalog_members(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-inventory-") as td:
            root = Path(td)
            raw = self._write(root / "raw.json", {"sources": [
                {"url": "https://example.invalid/one.json", "discoveredBy": "curated-sources.json"},
                {"url": "https://example.invalid/two.json", "discoveredBy": "github-code-search"},
            ]})
            enriched = self._write(root / "enriched.json", {"sources": [
                {"url": "https://example.invalid/one.json", "ok": True},
                {"url": "https://example.invalid/two.json", "ok": False, "error": "timeout"},
            ]})
            curated = self._write(root / "curated.json", [{"url": "https://example.invalid/one.json"}])
            community = self._write(root / "community.json", [])
            catalog = root / "catalog"
            self._write(catalog / "sources" / "index.json", {"sources": [
                {"url": "https://example.invalid/one.json"},
                {"url": "https://example.invalid/two.json"},
            ]})
            report = source_inventory_guard.validate(
                raw=raw, enriched=enriched, curated=curated, community=community, catalog_root=catalog
            )
            self.assertTrue(report["ok"], report)
            self.assertEqual(2, report["counts"]["canonical"])
            self.assertEqual(1, report["counts"]["reachable"])
            self.assertEqual(1, report["counts"]["unreachable"])

    def test_missing_discovered_or_previously_known_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-loss-") as td:
            root = Path(td)
            raw = self._write(root / "raw.json", {"sources": [
                {"url": "https://example.invalid/one.json", "discoveredBy": "curated-sources.json"},
                {"url": "https://example.invalid/two.json", "discoveredBy": "github-code-search"},
            ]})
            curated = self._write(root / "curated.json", [{"url": "https://example.invalid/one.json"}])
            current = root / "current"
            previous = root / "previous"
            self._write(current / "sources" / "index.json", {"sources": [
                {"url": "https://example.invalid/one.json"},
            ]})
            self._write(previous / "sources" / "index.json", {"sources": [
                {"url": "https://example.invalid/one.json"},
                {"url": "https://example.invalid/legacy.json"},
            ]})
            report = source_inventory_guard.validate(
                raw=raw, catalog_root=current, curated=curated, previous_catalog_root=previous
            )
            self.assertFalse(report["ok"])
            self.assertTrue(any("emitted by discovery" in error for error in report["errors"]), report)
            self.assertTrue(any("previously known" in error for error in report["errors"]), report)

            overridden = source_inventory_guard.validate(
                raw=raw, catalog_root=current, curated=curated, previous_catalog_root=previous,
                allow_source_removal=True,
            )
            self.assertFalse(overridden["ok"], "override can permit intentional prior removal but must not hide a currently discovered omission")


if __name__ == "__main__":
    unittest.main()
