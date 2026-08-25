from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

import common  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_plugin_inventory as inventory
from evidence_v2_inspector import V2SigmascopeInspector


class DeltaScopeLogicalPluginInventoryTests(unittest.TestCase):
    def test_catalog_plugin_id_collapses_versions_without_overmerging_other_plugin_ids(self) -> None:
        catalog = [
            {"pluginId": 326, "internalName": "AbsoluteRoleplay", "name": "Absolute Roleplay", "active": True,
             "activeVariantCount": 2, "activeVariantIds": [326, 401], "variantCount": 3, "path": "plugins/0000/326.json"},
            {"pluginId": 999, "internalName": "DifferentPlugin", "name": "Different Plugin", "active": True,
             "activeVariantCount": 1, "activeVariantIds": [999], "variantCount": 1, "path": "plugins/0000/999.json"},
        ]
        evidence = [
            {"plugin_id": 326, "variant_id": 326, "internal_name": "AbsoluteRoleplay", "canonical_name": "Absolute Roleplay",
             "assembly_version": "2.0.0", "assembly_name": "AbsoluteRoleplay", "scan_status": "complete", "highest_severity": "none"},
            {"plugin_id": 326, "variant_id": 401, "internal_name": "AbsoluteRoleplay", "canonical_name": "Absolute Roleplay",
             "assembly_version": "1.9.0", "assembly_name": "AbsoluteRoleplay", "scan_status": "complete", "highest_severity": "caution"},
            # Same assembly text must not cross the catalog plugin identity boundary.
            {"plugin_id": 999, "variant_id": 999, "internal_name": "DifferentPlugin", "canonical_name": "Different Plugin",
             "assembly_version": "2.0.0", "assembly_name": "AbsoluteRoleplay", "scan_status": "complete", "highest_severity": "high"},
        ]
        rows = inventory.merge_catalog_plugins(catalog, evidence, catalog_revision="cat-1", identity_epoch="epoch-1")
        self.assertEqual(2, len(rows))
        absolute = next(row for row in rows if row["plugin_id"] == 326)
        self.assertEqual([326, 401], absolute["active_variant_ids"])
        self.assertEqual(2, absolute["evidence_variant_count"])
        self.assertEqual(2, absolute["version_count"])
        self.assertEqual("catalog-plugin-id", absolute["grouping_basis"])
        self.assertFalse(absolute["catalog_only"])
        different = next(row for row in rows if row["plugin_id"] == 999)
        self.assertEqual([999], different["active_variant_ids"])
        self.assertEqual("high", different["highest_severity"])

    def test_default_inventory_hides_known_old_unsupported_but_keeps_api_unknown(self) -> None:
        catalog = [
            {"pluginId": 1, "internalName": "Current", "name": "Current", "active": True, "activeVariantIds": [11], "activeVariantCount": 1},
            {"pluginId": 2, "internalName": "Old", "name": "Old", "active": True, "activeVariantIds": [22], "activeVariantCount": 1},
            {"pluginId": 3, "internalName": "Unknown", "name": "Unknown", "active": True, "activeVariantIds": [33], "activeVariantCount": 1},
            {"pluginId": 4, "internalName": "Retired", "name": "Retired", "active": False, "activeVariantIds": [], "activeVariantCount": 0},
        ]
        variants = [
            {"plugin_id": 1, "variant_id": 11, "active": 1, "is_hide": 0, "dalamud_api_level": 15},
            {"plugin_id": 2, "variant_id": 22, "active": 1, "is_hide": 0, "dalamud_api_level": 14},
            {"plugin_id": 3, "variant_id": 33, "active": 1, "is_hide": 0, "dalamud_api_level": 0},
            {"plugin_id": 4, "variant_id": 44, "active": 0, "is_hide": 0, "dalamud_api_level": 13},
        ]
        current = inventory.merge_catalog_plugins(catalog, [], variant_rows=variants, current_api_level=15)
        self.assertEqual([1, 3], [row["plugin_id"] for row in current])
        self.assertEqual("current", current[0]["compatibility_state"])
        self.assertEqual("unknown", current[1]["compatibility_state"])
        full = inventory.merge_catalog_plugins(catalog, [], variant_rows=variants, current_api_level=15, include_legacy=True)
        states = {row["plugin_id"]: row["compatibility_state"] for row in full}
        self.assertEqual({1: "current", 2: "outdated", 3: "unknown", 4: "retired"}, states)

    def test_current_api_variant_is_preferred_over_older_evidence_sibling(self) -> None:
        catalog = [{"pluginId": 7, "internalName": "Multi", "name": "Multi", "active": True, "activeVariantIds": [70, 71], "activeVariantCount": 2}]
        variants = [
            {"plugin_id": 7, "variant_id": 70, "active": 1, "is_hide": 0, "dalamud_api_level": 14},
            {"plugin_id": 7, "variant_id": 71, "active": 1, "is_hide": 0, "dalamud_api_level": 15},
        ]
        evidence = [{"plugin_id": 7, "variant_id": 70, "scan_status": "complete", "assembly_version": "9.0", "highest_severity": "none"}]
        row = inventory.merge_catalog_plugins(catalog, evidence, variant_rows=variants, current_api_level=15)[0]
        self.assertEqual("current", row["compatibility_state"])
        self.assertEqual(71, row["variant_id"], "developer picker must open the current-compatible sibling")
        self.assertEqual([71], row["current_api_variant_ids"])

    def test_inactive_old_evidence_does_not_make_current_catalog_variant_look_covered(self) -> None:
        catalog = [{
            "pluginId": 326, "internalName": "AbsoluteRoleplay", "name": "Absolute Roleplay", "active": True,
            "activeVariantCount": 1, "activeVariantIds": [326], "variantCount": 2,
        }]
        evidence = [{
            "plugin_id": 326, "variant_id": 777, "internal_name": "AbsoluteRoleplay", "canonical_name": "Absolute Roleplay",
            "assembly_version": "old", "scan_status": "complete", "highest_severity": "none",
        }]
        row = inventory.merge_catalog_plugins(catalog, evidence)[0]
        self.assertEqual(326, row["variant_id"])
        self.assertEqual(0, row["evidence_variant_id"])
        self.assertTrue(row["catalog_only"])
        self.assertEqual("unscanned", row["scan_status"])


    def test_selected_logical_plugin_context_keeps_sibling_variant_coverage_visible(self) -> None:
        inspector = object.__new__(V2SigmascopeInspector)
        inspector.current_entries = {
            401: {
                "scanId": 88,
                "summary": {
                    "variant_id": 401, "plugin_id": 326, "assembly_version": "2.0.0",
                    "scan_status": "complete", "highest_severity": "caution",
                    "scanned_at_utc": "2026-08-24T12:34:56Z",
                },
            }
        }
        index_row = {
            "pluginId": 326, "activeVariantIds": [326, 401], "activeVariantCount": 2,
            "path": "plugins/0000/326.json",
        }
        payload = {
            "schema": "omega.catalog-json.plugin.v1",
            "plugin": {"plugin_id": 326, "internal_name": "AbsoluteRoleplay", "canonical_name": "Absolute Roleplay"},
            "variants": [
                {"variant": {"variant_id": 326, "plugin_id": 326, "source_id": 10, "name": "Absolute Roleplay", "author": "A", "assembly_version": "1.9.0", "repo_url": "https://example.invalid/a", "active": 1}},
                {"variant": {"variant_id": 401, "plugin_id": 326, "source_id": 11, "name": "Absolute Roleplay", "author": "B", "assembly_version": "2.0.0", "repo_url": "https://example.invalid/b", "active": 1}},
            ],
            "presentation": {}, "search": {},
        }
        inspector._catalog_plugin_for_variant = lambda variant_id: (index_row, payload) if variant_id in {326, 401} else None
        inspector._remote_catalog_inventory = lambda: {"catalogRevision": "cat-2", "identityEpoch": "epoch-1"}
        inspector._remote_catalog_sources = lambda: {
            10: {"sourceId": 10, "name": "Repo A", "provider": "custom", "url": "https://repo-a.invalid/pluginmaster.json"},
            11: {"sourceId": 11, "name": "Repo B", "provider": "custom", "url": "https://repo-b.invalid/pluginmaster.json"},
        }

        context = V2SigmascopeInspector._catalog_context_for_variant(inspector, 326)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual("omega.deltascope.logical-plugin-context.v1", context["schema"])
        self.assertEqual(2, context["activeVariantCount"])
        self.assertEqual(1, context["currentEvidenceVariantCount"])
        self.assertEqual(1, context["withoutCurrentEvidenceVariantCount"])
        selected = next(row for row in context["variants"] if row["variant_id"] == 326)
        covered = next(row for row in context["variants"] if row["variant_id"] == 401)
        self.assertTrue(selected["selected"])
        self.assertFalse(selected["currentEvidence"])
        self.assertTrue(covered["currentEvidence"])
        self.assertEqual("Repo B", covered["source_name"])
        self.assertEqual("https://repo-b.invalid/pluginmaster.json", covered["source_url"])
        self.assertEqual(88, covered["evidenceScanId"])
        self.assertEqual("caution", covered["evidenceHighestSeverity"])
        self.assertEqual("omega.deltascope.logical-plugin-divergence.v1", context["divergence"]["schema"])
        self.assertEqual("review", context["divergence"]["state"], "partial sibling coverage should be surfaced")

    def test_online_picker_uses_full_catalog_and_catalog_only_plugin_opens_context_lazily(self) -> None:
        class Response:
            def __init__(self, data: bytes):
                self.data = io.BytesIO(data)
                self.headers = {"Content-Length": str(len(data))}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n: int = -1) -> bytes: return self.data.read(n)

        def packed(value) -> bytes:
            return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")

        evidence_base = "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/"
        commit = "1" * 40
        catalog_base = f"https://raw.githubusercontent.com/dalagab/omega/{commit}/catalog/"
        evidence_plugins = {"schema": "omega.security-evidence.plugins-index.v2", "currentVariants": [{
            "variantId": 1, "scanId": 10, "variantPath": "variants/0000/1.json",
            "summary": {"plugin_id": 1, "variant_id": 1, "internal_name": "Covered", "canonical_name": "Covered",
                        "name": "Covered", "assembly_version": "1.0.0", "scan_status": "complete", "highest_severity": "none"},
        }]}
        evidence_plugins_bytes = packed(evidence_plugins)
        evidence_root = {"schema": "omega.security-evidence.v2", "formatVersion": 2,
                         "revisions": {"evidenceRevision": "ev-1", "catalogDataRevision": "cat-old", "catalogIdentityEpoch": "epoch-1"},
                         "indexes": {"plugins": {"path": "indexes/plugins.json", "sha256": hashlib.sha256(evidence_plugins_bytes).hexdigest()}}}

        catalog_plugins = {"schema": "omega.catalog-json.plugins-index.v1", "records": 2, "activePlugins": 2, "plugins": [
            {"pluginId": 1, "internalName": "Covered", "name": "Covered", "active": True,
             "variantCount": 1, "activeVariantCount": 1, "activeVariantIds": [1], "path": "plugins/0000/1.json", "sha256": ""},
            {"pluginId": 2, "internalName": "CatalogOnly", "name": "Catalog Only", "active": True,
             "variantCount": 1, "activeVariantCount": 1, "activeVariantIds": [2], "path": "plugins/0000/2.json", "sha256": ""},
        ]}
        catalog_plugins_bytes = packed(catalog_plugins)
        catalog_only_shard = {"schema": "omega.catalog-json.plugin.v1",
                              "plugin": {"plugin_id": 2, "internal_name": "CatalogOnly", "canonical_name": "Catalog Only", "active": 1},
                              "variants": [{"variant": {"variant_id": 2, "plugin_id": 2, "source_id": 9, "name": "Catalog Only", "author": "Author", "assembly_version": "3.2.1", "active": 1}}],
                              "presentation": {}, "search": {}}
        catalog_only_bytes = packed(catalog_only_shard)
        catalog_plugins["plugins"][1]["sha256"] = hashlib.sha256(catalog_only_bytes).hexdigest()
        catalog_plugins_bytes = packed(catalog_plugins)
        catalog_sources = {"schema": "omega.catalog-json.sources-index.v1", "records": 1, "sources": [
            {"sourceId": 9, "url": "https://catalog-source.invalid/pluginmaster.json", "name": "Catalog Source", "provider": "custom", "pluginCount": 1, "path": "sources/000009.json", "sha256": ""}
        ]}
        catalog_sources_bytes = packed(catalog_sources)
        catalog_root = {"schema": "omega.catalog-json.v1", "formatVersion": 1, "catalogRevision": "cat-current",
                        "catalogBaseRevision": "base-current", "identityEpoch": "epoch-1", "generatedAtUtc": "2026-08-24T12:00:00Z",
                        "files": [
                            {"path": "plugins/index.json", "sha256": hashlib.sha256(catalog_plugins_bytes).hexdigest()},
                            {"path": "sources/index.json", "sha256": hashlib.sha256(catalog_sources_bytes).hexdigest()},
                        ]}

        files = {
            evidence_base + "index.json": packed(evidence_root),
            evidence_base + "indexes/plugins.json": evidence_plugins_bytes,
            catalog_base + "index.json": packed(catalog_root),
            catalog_base + "plugins/index.json": catalog_plugins_bytes,
            catalog_base + "sources/index.json": catalog_sources_bytes,
            catalog_base + "plugins/0000/2.json": catalog_only_bytes,
        }
        requests: list[str] = []
        def fake_urlopen(request, timeout=0):
            del timeout
            url = request.full_url
            requests.append(url)
            if url not in files:
                raise AssertionError(f"unexpected remote fetch: {url}")
            return Response(files[url])

        with tempfile.TemporaryDirectory() as td:
            inspector = V2SigmascopeInspector.online(
                base_url=evidence_base, cache_dir=Path(td) / "evidence", urlopen=fake_urlopen,
                catalog_base_url=catalog_base, catalog_cache_dir=Path(td) / "catalog",
            )
            try:
                projected = inspector.logical_plugin_inventory()
                self.assertEqual(2, projected["totalLogicalPlugins"])
                self.assertEqual("catalog-data", projected["source"])
                self.assertEqual("cat-current", projected["catalogRevision"])
                self.assertEqual(1, projected["withCurrentEvidence"])
                self.assertEqual(1, projected["withoutCurrentEvidence"])
                catalog_only = next(row for row in projected["plugins"] if row["plugin_id"] == 2)
                self.assertTrue(catalog_only["catalog_only"])
                self.assertEqual(2, catalog_only["variant_id"])
                self.assertNotIn(catalog_base + "plugins/0000/2.json", requests, "picker must not fetch one shard per catalog plugin")

                detail = inspector.plugin_detail(2)
                self.assertTrue(detail["catalogOnly"])
                self.assertEqual("Catalog Only", detail["identity"]["canonical_name"])
                self.assertEqual("3.2.1", detail["identity"]["assembly_version"])
                self.assertEqual("Catalog Source", detail["catalogContext"]["variants"][0]["source_name"])
                self.assertEqual("https://catalog-source.invalid/pluginmaster.json", detail["catalogContext"]["variants"][0]["source_url"])
                self.assertIn(catalog_base + "plugins/0000/2.json", requests)
                self.assertIn(catalog_base + "sources/index.json", requests)
            finally:
                inspector.close()


if __name__ == "__main__":
    unittest.main()
