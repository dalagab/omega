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

    def _aliases(self, root: Path, groups: list[dict]) -> Path:
        return self._write(root / "aliases.json", {
            "schema": source_inventory_guard.ALIAS_SCHEMA,
            "groups": groups,
        })

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

    def test_explicit_feed_migration_retains_previous_source_without_weakening_guard(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-alias-") as td:
            root = Path(td)
            old = "https://raw.githubusercontent.com/example/repo/main/pluginmaster.json"
            new = "https://example.invalid/releases/latest/pluginmaster.json"
            raw = self._write(root / "raw.json", {"sources": [{"url": new, "discoveredBy": "curated-sources.json"}]})
            curated = self._write(root / "curated.json", [{"url": new}])
            current = root / "current"
            previous = root / "previous"
            self._write(current / "sources" / "index.json", {"sources": [{"url": new}]})
            self._write(previous / "sources" / "index.json", {"sources": [{"url": old}]})
            aliases = self._aliases(root, [{"canonical": new, "aliases": [old], "reason": "feed migration"}])

            report = source_inventory_guard.validate(
                raw=raw, catalog_root=current, curated=curated, previous_catalog_root=previous, aliases=aliases
            )
            self.assertTrue(report["ok"], report)
            self.assertEqual([], report["missing"]["previousFromCanonical"])
            self.assertEqual(1, report["coverage"]["equivalentPreviousRetained"])
            self.assertEqual(old.casefold(), report["equivalence"]["previousMigrations"][0]["required"])
            self.assertEqual(new.casefold(), report["equivalence"]["previousMigrations"][0]["satisfiedBy"])
            self.assertIn("configured_alias", report["equivalence"]["previousMigrations"][0]["basis"])

    def test_successfully_observed_redirect_is_bounded_equivalence_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-redirect-") as td:
            root = Path(td)
            old = "https://example.invalid/old.json"
            new = "https://cdn.example.invalid/new.json"
            raw = self._write(root / "raw.json", {"sources": [{"url": new, "discoveredBy": "github-code-search"}]})
            enriched = self._write(root / "enriched.json", {"sources": [
                {"url": old, "resolvedUrl": new, "ok": True},
            ]})
            current = root / "current"
            previous = root / "previous"
            self._write(current / "sources" / "index.json", {"sources": [{"url": new}]})
            self._write(previous / "sources" / "index.json", {"sources": [{"url": old}]})
            report = source_inventory_guard.validate(
                raw=raw, enriched=enriched, catalog_root=current, previous_catalog_root=previous
            )
            self.assertTrue(report["ok"], report)
            self.assertEqual(1, report["counts"]["observedRedirects"])
            self.assertIn("observed_redirect", report["equivalence"]["previousMigrations"][0]["basis"])

    def test_same_repository_different_feed_path_is_not_implicitly_equivalent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-path-loss-") as td:
            root = Path(td)
            old = "https://raw.githubusercontent.com/example/repo/main/pluginmaster.json"
            new = "https://raw.githubusercontent.com/example/repo/main/testing.json"
            raw = self._write(root / "raw.json", {"sources": [{"url": new, "discoveredBy": "github-code-search"}]})
            current = root / "current"
            previous = root / "previous"
            self._write(current / "sources" / "index.json", {"sources": [{"url": new}]})
            self._write(previous / "sources" / "index.json", {"sources": [{"url": old}]})
            report = source_inventory_guard.validate(raw=raw, catalog_root=current, previous_catalog_root=previous)
            self.assertFalse(report["ok"], report)
            self.assertEqual([old.casefold()], report["missing"]["previousFromCanonical"])
            self.assertTrue(any("previously known" in error for error in report["errors"]), report)

    def test_ambiguous_alias_registry_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-alias-collision-") as td:
            root = Path(td)
            shared = "https://legacy.example.invalid/feed.json"
            first = "https://one.example.invalid/feed.json"
            second = "https://two.example.invalid/feed.json"
            raw = self._write(root / "raw.json", {"sources": [{"url": first, "discoveredBy": "curated-sources.json"}]})
            current = root / "current"
            self._write(current / "sources" / "index.json", {"sources": [{"url": first}]})
            aliases = self._aliases(root, [
                {"canonical": first, "aliases": [shared]},
                {"canonical": second, "aliases": [shared]},
            ])
            report = source_inventory_guard.validate(raw=raw, catalog_root=current, aliases=aliases)
            self.assertFalse(report["ok"], report)
            self.assertTrue(any("ambiguous" in error for error in report["errors"]), report)

    def test_source_removal_override_still_does_not_hide_current_discovery_loss_with_aliases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-override-alias-") as td:
            root = Path(td)
            old = "https://old.example.invalid/feed.json"
            new = "https://new.example.invalid/feed.json"
            omitted = "https://missing.example.invalid/feed.json"
            raw = self._write(root / "raw.json", {"sources": [
                {"url": new, "discoveredBy": "curated-sources.json"},
                {"url": omitted, "discoveredBy": "github-code-search"},
            ]})
            current = root / "current"
            previous = root / "previous"
            self._write(current / "sources" / "index.json", {"sources": [{"url": new}]})
            self._write(previous / "sources" / "index.json", {"sources": [{"url": old}]})
            aliases = self._aliases(root, [{"canonical": new, "aliases": [old]}])
            report = source_inventory_guard.validate(
                raw=raw, catalog_root=current, previous_catalog_root=previous, aliases=aliases,
                allow_source_removal=True,
            )
            self.assertFalse(report["ok"], report)
            self.assertEqual([], report["missing"]["previousFromCanonical"])
            self.assertEqual([omitted.casefold()], report["missing"]["discoveredFromCanonical"])


if __name__ == "__main__":
    unittest.main()
