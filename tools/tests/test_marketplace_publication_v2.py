from __future__ import annotations

import unittest

import common  # noqa: F401
import compile_marketplace_snapshot


class MarketplacePublicationV2Tests(unittest.TestCase):
    def test_canonical_revision_maps_to_marketplace_v2(self) -> None:
        self.assertEqual(
            "cat-v2-0123456789abcdef",
            compile_marketplace_snapshot.public_catalog_revision(
                "cat-json-v1-0123456789abcdef"
            ),
        )

    def test_mapping_is_case_normalized_and_fail_closed(self) -> None:
        self.assertEqual(
            "cat-v2-abcdef0123456789",
            compile_marketplace_snapshot.public_catalog_revision(
                "cat-json-v1-ABCDEF0123456789"
            ),
        )
        for value in (
            "",
            "cat-v1-0123456789abcdef",
            "cat-json-v2-0123456789abcdef",
            "cat-json-v1-short",
            "cat-json-v1-0123456789abcdeg",
        ):
            with self.assertRaises(RuntimeError):
                compile_marketplace_snapshot.public_catalog_revision(value)

    def test_public_descriptor_contract_is_v2(self) -> None:
        self.assertEqual(2, compile_marketplace_snapshot.PUBLIC_DESCRIPTOR_VERSION)
        self.assertEqual(
            "omega.catalog.marketplace.v2",
            compile_marketplace_snapshot.PUBLIC_DESCRIPTOR_SCHEMA,
        )


if __name__ == "__main__":
    unittest.main()
