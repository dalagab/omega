from __future__ import annotations

import copy
import unittest

import common  # noqa: F401
import client_database_audit


class ClientDatabaseAuditGrowthTests(unittest.TestCase):
    def catchup_result(self) -> dict:
        return {
            "projectionMode": "fresh-allowlist-v1",
            "previousProjectionMode": "fresh-allowlist-v1",
            "marketplaceProjectorVersion": "1.9.0",
            "previousMarketplaceProjectorVersion": "1.9.0",
            "catalogRevision": "cat-v2-new",
            "previousCatalogRevision": "cat-v2-old",
            "evidenceRevision": "ev-v2-new",
            "previousEvidenceRevision": "ev-v2-old",
            "growthRatio": 1.4932392393470884,
            "securityCoverage": {
                "marker": "security_scanned_at_utc",
                "coveredVariants": 4700,
            },
            "previousSecurityCoverage": {
                "marker": "security_scanned_at_utc",
                "coveredVariants": 2684,
            },
            "prohibitedTables": [],
            "tableDeltas": [
                {
                    "name": "runtime_plugin_variants",
                    "rows": 6038,
                    "previousRows": 4755,
                    "rowDelta": 1283,
                    "byteDelta": 34467840,
                },
                {
                    "name": "plugin_variants",
                    "rows": 15771,
                    "previousRows": 8131,
                    "rowDelta": 7640,
                    "byteDelta": 2215936,
                },
                {
                    "name": "plugin_search",
                    "rows": 1353,
                    "previousRows": 1169,
                    "rowDelta": 184,
                    "byteDelta": 770048,
                },
                {
                    "name": "sources",
                    "rows": 1257,
                    "previousRows": 1090,
                    "rowDelta": 167,
                    "byteDelta": 20480,
                },
                {
                    "name": "plugin_dependencies",
                    "rows": 5,
                    "previousRows": 0,
                    "rowDelta": 5,
                    "byteDelta": 16384,
                },
                {
                    "name": "plugin_dependency_providers",
                    "rows": 2,
                    "previousRows": 0,
                    "rowDelta": 2,
                    "byteDelta": 8192,
                },
                {
                    "name": "plugins",
                    "rows": 1556,
                    "previousRows": 1375,
                    "rowDelta": 181,
                    "byteDelta": 4096,
                },
                {
                    "name": "catalog_meta",
                    "rows": 37,
                    "previousRows": 36,
                    "rowDelta": 1,
                    "byteDelta": 0,
                },
            ],
        }

    def test_stale_customer_release_can_catch_up_catalog_and_security_together(self) -> None:
        allowed, reasons = client_database_audit.catalog_catchup_growth_allowance(
            self.catchup_result(), 1.20
        )
        self.assertTrue(allowed, reasons)
        self.assertEqual([], reasons)

    def test_catchup_rejects_unknown_table_growth(self) -> None:
        result = self.catchup_result()
        result["tableDeltas"].append(
            {
                "name": "plugin_security_scans",
                "rows": 1,
                "previousRows": 0,
                "rowDelta": 1,
                "byteDelta": 4096,
            }
        )
        allowed, reasons = client_database_audit.catalog_catchup_growth_allowance(
            result, 1.20
        )
        self.assertFalse(allowed)
        self.assertTrue(any("unexpected client tables changed" in item for item in reasons))

    def test_catchup_rejects_density_spike_beyond_runtime_growth(self) -> None:
        result = self.catchup_result()
        result["growthRatio"] = 2.0
        allowed, reasons = client_database_audit.catalog_catchup_growth_allowance(
            result, 1.20
        )
        self.assertFalse(allowed)
        self.assertTrue(any("outpaced bounded catalog catch-up" in item for item in reasons))

    def test_catchup_requires_new_authoritative_catalog_revision(self) -> None:
        result = copy.deepcopy(self.catchup_result())
        result["catalogRevision"] = result["previousCatalogRevision"]
        allowed, reasons = client_database_audit.catalog_catchup_growth_allowance(
            result, 1.20
        )
        self.assertFalse(allowed)
        self.assertIn("authoritative catalog revision did not advance", reasons)


if __name__ == "__main__":
    unittest.main()
