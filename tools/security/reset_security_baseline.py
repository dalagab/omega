#!/usr/bin/env python3
"""Create a fresh Security Evidence v2 baseline without touching catalog/source data.

The input SQLite database MUST be a disposable materialization of catalog-data.  This
tool clears only plugin_security_* rows and security-specific catalog_meta values,
then emits a valid zero-result Security Evidence v2 snapshot plus an empty Deep Scan
queue.  Catalog/plugin/source/site tables are never deleted or rewritten.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
CATALOG_DIR = SCRIPT_DIR.parent / "catalog"
for item in (SCRIPT_DIR, CATALOG_DIR):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import deep_scan_queue  # noqa: E402
import sigmascope  # noqa: E402
from migrate_security_evidence_v2 import migrate  # noqa: E402
from security_evidence_v2 import sha256_file, validate_snapshot  # noqa: E402


RECEIPT_SCHEMA = "omega.security-baseline-reset.v1"
SECURITY_PREFIX = "plugin_security_"
SECURITY_META_KEYS = {
    "security_revision",
    "evidence_revision",
    "security_scanner_version",
    "scanner_version",
    "security_last_scan_utc",
    "security_last_scan_at_utc",
}


def _tables(db: sqlite3.Connection) -> list[str]:
    return [
        str(row[0])
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


def _counts(db: sqlite3.Connection, tables: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for table in tables:
        safe = table.replace('"', '""')
        result[table] = int(db.execute(f'SELECT COUNT(*) FROM "{safe}"').fetchone()[0])
    return result


def reset_security_database(database: Path) -> dict[str, Any]:
    """Clear only derived security rows in a disposable catalog materialization."""
    database = database.resolve()
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        sigmascope.ensure_schema(db)
        db.commit()

        all_tables = _tables(db)
        security_tables = [name for name in all_tables if name.startswith(SECURITY_PREFIX)]
        preserved_tables = [
            name
            for name in all_tables
            if not name.startswith(SECURITY_PREFIX) and name != "catalog_meta"
        ]
        before_preserved = _counts(db, preserved_tables)
        before_security = _counts(db, security_tables)

        db.execute("PRAGMA foreign_keys=OFF")
        for table in security_tables:
            safe = table.replace('"', '""')
            db.execute(f'DELETE FROM "{safe}"')

        if "sqlite_sequence" in {
            str(row[0])
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }:
            for table in security_tables:
                db.execute("DELETE FROM sqlite_sequence WHERE name=?", (table,))

        if "catalog_meta" in all_tables:
            placeholders = ",".join("?" for _ in SECURITY_META_KEYS)
            db.execute(
                f"DELETE FROM catalog_meta WHERE key IN ({placeholders}) OR key LIKE 'security_%'",
                tuple(sorted(SECURITY_META_KEYS)),
            )
        db.commit()
        db.execute("PRAGMA foreign_keys=ON")

        after_preserved = _counts(db, preserved_tables)
        after_security = _counts(db, security_tables)

    if before_preserved != after_preserved:
        changed = sorted(
            key
            for key in set(before_preserved) | set(after_preserved)
            if before_preserved.get(key) != after_preserved.get(key)
        )
        raise RuntimeError(
            "security baseline reset changed non-security table counts: " + ", ".join(changed)
        )
    not_empty = {name: count for name, count in after_security.items() if count}
    if not_empty:
        raise RuntimeError(f"security tables are not empty after reset: {not_empty}")

    return {
        "database": str(database),
        "securityTablesCleared": len(security_tables),
        "securityRowsBefore": sum(before_security.values()),
        "securityRowsAfter": 0,
        "preservedTablesChecked": len(preserved_tables),
        "preservedRows": sum(after_preserved.values()),
        "preservedTableCounts": after_preserved,
    }


def build(
    database: Path,
    evidence_output: Path,
    deep_scan_output: Path,
    receipt_path: Path,
    *,
    previous_evidence_head: str = "",
) -> dict[str, Any]:
    database = database.resolve()
    evidence_output = evidence_output.resolve()
    deep_scan_output = deep_scan_output.resolve()
    receipt_path = receipt_path.resolve()

    reset = reset_security_database(database)
    root = migrate(
        database,
        evidence_output,
        reset=True,
        source_context={
            "mode": "clean-security-baseline-reset",
            "previousEvidenceHead": str(previous_evidence_head or ""),
        },
    )

    if int((root.get("counts") or {}).get("currentVariants") or 0) != 0:
        raise RuntimeError("fresh Security Evidence v2 baseline unexpectedly contains current variants")

    validation = validate_snapshot(evidence_output, require_no_orphans=True)
    validation_path = evidence_output / "validation-report.json"
    validation_path.write_text(
        json.dumps(validation, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    if validation.get("ok") is not True:
        raise RuntimeError(
            "fresh Security Evidence v2 baseline failed intrinsic validation: "
            + "; ".join(validation.get("errors") or [])
        )

    queue = deep_scan_queue.build_queue(evidence_output, [], {})
    deep_scan_queue.write_queue(deep_scan_output / "index.json", queue)
    if queue.get("items"):
        raise RuntimeError("fresh Deep Scan baseline unexpectedly contains requests")

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "scope": "derived-plugin-security-state-only",
        "preserved": [
            "catalog-data/catalog",
            "catalog-data/definitions",
            "plugin-and-variant-identities",
            "sources-and-repositories",
            "scraped-website-and-presentation-data",
            "frozen-source-observations",
            "frozen-advisories",
            "frozen-reputation-and-threat-intelligence",
        ],
        "reset": [
            "Security-Evidence-v2-current-results",
            "SigmaScope-mutable-queue-progress",
            "Deep-Scan-queue-and-results",
        ],
        "previousEvidenceHead": str(previous_evidence_head or ""),
        "database": reset,
        "evidence": {
            "schema": str(root.get("schema") or ""),
            "currentVariants": int((root.get("counts") or {}).get("currentVariants") or 0),
            "indexSha256": sha256_file(evidence_output / "index.json"),
            "validation": validation,
        },
        "deepScan": {
            "schema": str(queue.get("schema") or ""),
            "queueRevision": str(queue.get("queueRevision") or ""),
            "items": len(queue.get("items") or []),
        },
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    parser.add_argument("--deep-scan-output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--previous-evidence-head", default="")
    args = parser.parse_args()
    receipt = build(
        args.database,
        args.evidence_output,
        args.deep_scan_output,
        args.receipt,
        previous_evidence_head=args.previous_evidence_head,
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
