#!/usr/bin/env python3
"""Build small, sanitised Discord notices from Omega publication outputs.

This process deliberately has no webhook credential.  A later, isolated job is
responsible for delivering the JSON it writes.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any


SCHEMA = "omega.discord-notice.v1"
MAX_FIELD_VALUE = 900

VOICE_LINES: dict[str, tuple[str, ...]] = {
    "security": (
        "Really? Another finding wants my attention.",
        "I was hoping for a quiet scan. Apparently not.",
        "Another finding. Fine, I've filed it.",
        "Something new turned up. I have notes.",
    ),
    "catalog": (
        "The vault gets heavier. I approve.",
        "Another deposit cleared. The catalog is richer for it.",
        "The hoard grows. More data, more reach, more power.",
        "Another line in the ledger. Information compounds beautifully.",
    ),
    "definitions": (
        "Fresh definitions! Now that's a worthwhile update.",
        "New definitions landed. Lovely.",
        "Definitions refreshed — excellent. More context is always welcome.",
        "A fresh definitions set! Exactly the sort of update I like.",
    ),
    "evidence": (
        "Reviewed and filed. You're welcome. 😏",
        "Another review complete. I had it handled. 😏",
        "Evidence checked and neatly filed. Naturally. 😏",
        "Done. Nicely, if I do say so myself. 😏",
    ),
}


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected an object in {path}")
    return value


def clean(value: object, limit: int = MAX_FIELD_VALUE) -> str:
    text = " ".join(str(value or "").replace("\x00", " ").split())
    return text.replace("@", "＠").replace("<", "‹")[:limit]


def short(value: object, length: int = 12) -> str:
    return clean(value, length)


def identity_digest(identity: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()


def voice_line(kind: str, identity: dict[str, object]) -> str:
    lines = VOICE_LINES[kind]
    digest = identity_digest(identity)
    return lines[int(digest[:8], 16) % len(lines)]


def notice(
    event: str,
    webhook_key: str,
    payload: dict[str, Any],
    identity: dict[str, object],
    should_notify: bool = True,
) -> dict[str, Any]:
    digest = identity_digest(identity)
    return {
        "schema": SCHEMA,
        "event": event,
        "webhookKey": webhook_key,
        "eventId": digest,
        "shouldNotify": should_notify,
        "payload": {"username": "TONI", "allowed_mentions": {"parse": []}, **payload},
    }


def embed(title: str, description: str, color: int, fields: list[tuple[str, object]]) -> dict[str, Any]:
    return {
        "embeds": [{
            "title": clean(title, 256),
            "description": clean(description, 2048),
            "color": color,
            "fields": [{"name": clean(name, 256), "value": clean(value), "inline": True} for name, value in fields if clean(value)],
        }]
    }


def current_findings(database: Path, variant_id: int) -> tuple[str, list[str]]:
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        current = db.execute(
            "SELECT scan_id,highest_severity FROM plugin_security_current WHERE variant_id=?", (variant_id,)
        ).fetchone()
        if current is None:
            return "", []
        previous = db.execute(
            "SELECT previous_scan_id FROM plugin_security_scan_lineage WHERE current_scan_id=?", (current["scan_id"],)
        ).fetchone()
        rows = db.execute(
            "SELECT rule_id,severity,title FROM plugin_security_findings WHERE scan_id=? AND severity IN ('high','critical') "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, rule_id",
            (current["scan_id"],),
        ).fetchall()
        old_rules: set[tuple[str, str]] = set()
        if previous and previous["previous_scan_id"]:
            old_rows = db.execute(
                "SELECT rule_id,severity FROM plugin_security_findings WHERE scan_id=?", (previous["previous_scan_id"],)
            ).fetchall()
            old_rules = {(str(row["rule_id"]), str(row["severity"])) for row in old_rows}
    introduced = [clean(row["title"] or row["rule_id"], 100) for row in rows if (str(row["rule_id"]), str(row["severity"])) not in old_rules]
    return clean(current["highest_severity"]), introduced[:3]


def build_sigmascope(report_path: Path, database: Path, repository: str, run_url: str) -> dict[str, Any]:
    report = read_json(report_path)
    candidate = report.get("candidate") or {}
    revisions = candidate.get("revisions") or {}
    selected = ((report.get("queue") or {}).get("selected") or {})
    variant_id = int(selected.get("variantId") or 0)
    identity: dict[str, object] = {
        "repository": repository,
        "revisions": revisions,
        "variant": variant_id,
    }

    if not report.get("publicationRequired"):
        return notice("security-evidence", "evidence", {}, identity, False)

    plugin = clean(selected.get("name") or selected.get("internalName") or "Omega plugin")
    work_type = clean(selected.get("workType") or "artifact")
    severity, introduced = current_findings(database, variant_id) if variant_id else ("", [])

    if introduced:
        webhook_key = "security"
        title = f"New security findings for {plugin}"
        description = (
            f"{voice_line('security', identity)} "
            f"SigmaScope recorded new security findings for {plugin}. "
            "Review the findings if you want to know more."
        )
        fields = [
            ("Plugin", plugin),
            ("New findings", ", ".join(introduced)),
            ("Evidence", short(revisions.get("evidenceRevision"))),
            ("Run", run_url),
        ]
        payload = embed(title, description, 15_158_332, fields)
    elif work_type == "advisory":
        webhook_key = "definitions"
        payload = embed(
            "Omega definitions updated",
            (
                f"{voice_line('definitions', identity)} "
                "SigmaScope applied the frozen advisory definitions to the current evidence set."
            ),
            10_181_046,
            [
                ("Advisories", short(revisions.get("advisoryRevision"))),
                ("Evidence", short(revisions.get("evidenceRevision"))),
                ("Run", run_url),
            ],
        )
    else:
        webhook_key = "evidence"
        payload = embed(
            "Omega evidence review complete",
            (
                f"{voice_line('evidence', identity)} "
                f"SigmaScope completed a {work_type} evidence review for {plugin}."
            ),
            5_793_266,
            [
                ("Plugin", plugin),
                ("Highest result", severity or "recorded"),
                ("Evidence", short(revisions.get("evidenceRevision"))),
                ("Run", run_url),
            ],
        )

    return notice("security-evidence", webhook_key, payload, identity)


def plugin_rows(catalog_index: Path) -> dict[str, dict[str, Any]]:
    index_path = catalog_index.parent / "plugins" / "index.json"
    if not index_path.is_file():
        return {}
    rows = read_json(index_path).get("plugins") or []
    return {str(row.get("pluginId")): row for row in rows if isinstance(row, dict) and row.get("pluginId") is not None}


def build_catalog(
    current: Path,
    previous: Path,
    definitions: Path,
    previous_definitions: Path,
    repository: str,
    run_url: str,
) -> dict[str, Any]:
    current_index = read_json(current)
    previous_index = read_json(previous) if previous.is_file() else {}
    current_rows = plugin_rows(current)
    previous_rows = plugin_rows(previous)

    added = [
        row
        for key, row in current_rows.items()
        if key not in previous_rows and row.get("active")
    ]
    changed = [
        row
        for key, row in current_rows.items()
        if key in previous_rows and row.get("sha256") != previous_rows[key].get("sha256")
    ]

    definitions_index = read_json(definitions)
    previous_definitions_index = (
        read_json(previous_definitions) if previous_definitions.is_file() else {}
    )

    catalog_revision = current_index.get("catalogRevision") or ""
    previous_revision = previous_index.get("catalogRevision") or ""
    definitions_revision = definitions_index.get("definitionsRevision") or ""
    previous_definitions_revision = previous_definitions_index.get("definitionsRevision") or ""

    catalog_changed = bool(catalog_revision and catalog_revision != previous_revision)
    definitions_changed = bool(
        definitions_revision and definitions_revision != previous_definitions_revision
    )
    should_notify = catalog_changed or definitions_changed
    webhook_key = "catalog" if catalog_changed else "definitions"
    identity: dict[str, object] = {
        "repository": repository,
        "catalog": catalog_revision,
        "definitions": definitions_revision,
    }

    if not should_notify:
        return notice("catalog", webhook_key, {}, identity, False)

    names = [
        clean(row.get("name") or row.get("internalName"), 70)
        for row in (added + changed)[:5]
    ]

    if catalog_changed:
        title = "Omega catalog updated"
        description = (
            f"{voice_line('catalog', identity)} "
            "The latest catalog snapshot is published and ready for Omega."
        )
    else:
        title = "Omega definitions updated"
        description = (
            f"{voice_line('definitions', identity)} "
            "A new frozen Definitions snapshot is published for SigmaScope."
        )

    payload = embed(
        title,
        description,
        5_793_266 if catalog_changed else 10_181_046,
        [
            ("New plugins", len(added)),
            ("Updated plugins", len(changed)),
            ("Examples", ", ".join(names) or "No plugin records changed"),
            ("Catalog", short(catalog_revision)),
            ("Definitions", short(definitions_revision)),
            ("Run", run_url),
        ],
    )
    return notice("catalog", webhook_key, payload, identity)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    security = subparsers.add_parser("sigmascope")
    security.add_argument("--report", required=True, type=Path)
    security.add_argument("--database", required=True, type=Path)
    catalog = subparsers.add_parser("catalog")
    catalog.add_argument("--catalog-index", required=True, type=Path)
    catalog.add_argument("--previous-catalog-index", required=True, type=Path)
    catalog.add_argument("--definitions-index", required=True, type=Path)
    catalog.add_argument("--previous-definitions-index", required=True, type=Path)
    for command in (security, catalog):
        command.add_argument("--repository", required=True)
        command.add_argument("--run-url", required=True)
        command.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = build_sigmascope(args.report, args.database, args.repository, args.run_url) if args.command == "sigmascope" else build_catalog(args.catalog_index, args.previous_catalog_index, args.definitions_index, args.previous_definitions_index, args.repository, args.run_url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Discord notice: {result['event']} ({'queued' if result['shouldNotify'] else 'no change'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
