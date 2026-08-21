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

VOICE_PARTS: dict[str, dict[str, tuple[str, ...]]] = {
    "security": {
        "lead": (
            "Really? The quiet lasted almost five minutes.",
            "Of course something interesting turned up.",
            "Well, well. The evidence has opinions today.",
            "There it is. I knew the silence was suspicious.",
            "Wonderful. Another reason to open the red ledger.",
            "I was promised routine scans. Apparently that was optimistic.",
        ),
        "middle": (
            "A new security signal made it through review.",
            "Something new surfaced in the current evidence.",
            "The latest comparison has a finding worth looking at.",
            "A fresh finding has joined the case file.",
            "The evidence changed in a way that deserves attention.",
            "A new high-interest result just entered the record.",
        ),
        "tail": (
            "I've marked the page; you can decide how dramatic to be about it.",
            "It's filed, indexed, and waiting for a human with curiosity.",
            "I kept the receipts. Naturally.",
            "Nothing is on fire by definition, but I would still read the notes.",
            "The details are attached; speculation is not.",
            "Consider this the polite version of me tapping the glass.",
        ),
    },
    "catalog": {
        "lead": (
            "The vault gets heavier. I approve.",
            "Another deposit cleared, right on schedule.",
            "The hoard grows. Excellent.",
            "A fresh page just landed in the ledger.",
            "More catalog data arrived. My favorite kind of clutter.",
            "The shelves shifted again; that usually means progress.",
        ),
        "middle": (
            "Omega has a newer map of the plugin ecosystem.",
            "The catalog picked up another useful slice of the ecosystem.",
            "The marketplace snapshot has moved forward.",
            "The plugin ledger has been refreshed with the latest public state.",
            "Another catalog revision is now part of the permanent record.",
            "The ecosystem changed, and Omega bothered to take notes.",
        ),
        "tail": (
            "Information compounds beautifully.",
            "More context, fewer excuses.",
            "I do enjoy an orderly accumulation of facts.",
            "Filed neatly enough that even I can find it later.",
            "The new snapshot is ready whenever Omega asks for it.",
            "No confetti. The revision number will have to do.",
        ),
    },
    "definitions": {
        "lead": (
            "Fresh definitions! Now that's a worthwhile update.",
            "New definitions landed. Lovely.",
            "The rule shelves have been restocked.",
            "A fresh frozen definitions set just arrived.",
            "Good news: the reference material got smarter.",
            "Definitions moved forward. I like useful paperwork.",
        ),
        "middle": (
            "The security service has a newer frozen context set to work from.",
            "The published security vocabulary has advanced.",
            "A new immutable definitions snapshot is now available.",
            "The advisory and rule context has been refreshed.",
            "The next security review gets a newer reference frame.",
            "The definitions ledger now points at a newer frozen state.",
        ),
        "tail": (
            "More context is always welcome.",
            "That should make the next comparison more interesting.",
            "Filed, frozen, and ready to be cited properly.",
            "A small revision number with an unreasonable amount of context behind it.",
            "The important bit is that the snapshot stays reproducible.",
            "I have updated my notes and will pretend I wasn't excited.",
        ),
    },
    "evidence": {
        "lead": (
            "Reviewed and filed. You're welcome. 😏",
            "Another review complete. I had it handled. 😏",
            "Evidence checked and neatly filed. Naturally. 😏",
            "Done. Nicely, if I do say so myself. 😏",
            "Another evidence packet survived my filing system. 😏",
            "The review queue is one item lighter. You're welcome. 😏",
        ),
        "middle": (
            "The current evidence record has been refreshed.",
            "A new evidence revision is now on the books.",
            "The latest review produced a publishable evidence change.",
            "The evidence trail moved forward without changing the rules of the game.",
            "Another plugin review now has a newer retained record.",
            "The current evidence snapshot has caught up with the latest review.",
        ),
        "tail": (
            "Everything useful is attached to the record.",
            "The revision tells the story; I merely improved the filing.",
            "No grand verdict, just better evidence.",
            "Consider the paperwork aggressively complete.",
            "The useful bits are preserved for whoever investigates next.",
            "I left the drama out and kept the provenance.",
        ),
    },
}

# Six interchangeable parts in each of three slots yield 216 deterministic
# voice combinations per notice family (864 across the four current families),
# before event-specific plugin/count/revision text is added.
VOICE_COMBINATIONS_PER_KIND = 216


def voice_variants(kind: str) -> tuple[str, ...]:
    parts = VOICE_PARTS[kind]
    return tuple(
        f"{lead} {middle} {tail}"
        for lead in parts["lead"]
        for middle in parts["middle"]
        for tail in parts["tail"]
    )


# Compatibility/readability surface for tests and anyone previewing TONI's voice.
# The source remains compact: these are generated from phrase banks, not hand-written
# as 864 separate messages.
VOICE_LINES: dict[str, tuple[str, ...]] = {kind: voice_variants(kind) for kind in VOICE_PARTS}


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected an object in {path}")
    return value


def clean(value: object, limit: int = MAX_FIELD_VALUE) -> str:
    text = " ".join(str(value or "").replace("\x00", " ").split())
    return text.replace("@", "＠").replace("<", "‹")[:limit]


def clean_multiline(value: object, limit: int = MAX_FIELD_VALUE) -> str:
    raw = str(value or "").replace("\x00", " ").replace("\r\n", "\n").replace("\r", "\n")
    lines = [" ".join(line.split()) for line in raw.split("\n")]
    text = "\n".join(line for line in lines if line).strip()
    return text.replace("@", "＠").replace("<", "‹")[:limit]


def short(value: object, length: int = 12) -> str:
    return clean(value, length)


def identity_digest(identity: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()


def voice_choice(kind: str, slot: str, identity: dict[str, object]) -> str:
    choices = VOICE_PARTS[kind][slot]
    material = {"identity": identity, "kind": kind, "slot": slot}
    digest = identity_digest(material)
    return choices[int(digest[:8], 16) % len(choices)]


def voice_line(kind: str, identity: dict[str, object]) -> str:
    return " ".join(voice_choice(kind, slot, identity) for slot in ("lead", "middle", "tail"))


def event_choice(kind: str, slot: str, identity: dict[str, object], choices: tuple[str, ...]) -> str:
    material = {"identity": identity, "kind": kind, "slot": slot}
    digest = identity_digest(material)
    return choices[int(digest[:8], 16) % len(choices)]


def deterministic_sample(items: list[Any], identity: dict[str, object], slot: str, count: int = 2) -> list[Any]:
    """Pick stable pseudo-random examples without runtime randomness.

    Discord retries for the same event therefore keep the same examples, while a
    different catalog/evidence identity naturally rotates the representative names.
    """
    ranked: list[tuple[str, Any]] = []
    for item in items:
        try:
            serial = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:
            serial = str(item)
        digest = identity_digest({"identity": identity, "slot": slot, "item": serial})
        ranked.append((digest, item))
    return [item for _, item in sorted(ranked, key=lambda pair: pair[0])[: max(0, count)]]


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


def embed(
    title: str,
    description: str,
    color: int,
    fields: list[tuple[str, object] | tuple[str, object, bool]],
) -> dict[str, Any]:
    rendered: list[dict[str, Any]] = []
    for field in fields:
        name, value = field[0], field[1]
        inline = bool(field[2]) if len(field) > 2 else True
        cleaned = clean_multiline(value)
        if cleaned:
            rendered.append({"name": clean(name, 256), "value": cleaned, "inline": inline})
    return {
        "embeds": [{
            "title": clean(title, 256),
            "description": clean(description, 2048),
            "color": color,
            "fields": rendered,
        }]
    }


def finding_snapshot(database: Path, variant_id: int) -> dict[str, Any]:
    empty = {
        "severity": "", "scanId": 0, "previousScanId": 0,
        "current": [], "introduced": [], "removed": [], "introducedHigh": [], "counts": {},
    }
    if variant_id <= 0 or not database.is_file():
        return empty
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        current = db.execute(
            "SELECT scan_id,highest_severity FROM plugin_security_current WHERE variant_id=?", (variant_id,)
        ).fetchone()
        if current is None:
            return empty
        scan_id = int(current["scan_id"] or 0)
        previous = db.execute(
            "SELECT previous_scan_id FROM plugin_security_scan_lineage WHERE current_scan_id=?", (scan_id,)
        ).fetchone()
        previous_scan_id = int(previous["previous_scan_id"] or 0) if previous and previous["previous_scan_id"] else 0
        rows = db.execute(
            "SELECT rule_id,severity,title FROM plugin_security_findings WHERE scan_id=? "
            "ORDER BY CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'caution' THEN 2 ELSE 3 END, rule_id",
            (scan_id,),
        ).fetchall()
        old_rows = db.execute(
            "SELECT rule_id,severity,title FROM plugin_security_findings WHERE scan_id=?", (previous_scan_id,)
        ).fetchall() if previous_scan_id else []

    def materialize(row: sqlite3.Row) -> dict[str, str]:
        return {
            "ruleId": clean(row["rule_id"], 160),
            "severity": clean(row["severity"], 32).casefold(),
            "title": clean(row["title"] or row["rule_id"], 160),
        }

    current_rows = [materialize(row) for row in rows]
    old = [materialize(row) for row in old_rows]
    old_keys = {(row["ruleId"], row["severity"]) for row in old}
    current_keys = {(row["ruleId"], row["severity"]) for row in current_rows}
    introduced = [row for row in current_rows if (row["ruleId"], row["severity"]) not in old_keys]
    removed = [row for row in old if (row["ruleId"], row["severity"]) not in current_keys]
    counts: dict[str, int] = {}
    for row in current_rows:
        counts[row["severity"]] = counts.get(row["severity"], 0) + 1
    return {
        "severity": clean(current["highest_severity"], 32).casefold(),
        "scanId": scan_id,
        "previousScanId": previous_scan_id,
        "current": current_rows,
        "introduced": introduced,
        "removed": removed,
        "introducedHigh": [row for row in introduced if row["severity"] in {"high", "critical"}],
        "counts": counts,
    }


def current_findings(database: Path, variant_id: int) -> tuple[str, list[str]]:
    """Compatibility helper retained for callers/tests from the first notice pass."""
    snapshot = finding_snapshot(database, variant_id)
    return snapshot["severity"], [row["title"] for row in snapshot["introducedHigh"][:3]]


def finding_count_text(snapshot: dict[str, Any]) -> str:
    current = snapshot.get("current") or []
    counts = snapshot.get("counts") or {}
    if not current:
        return "No current findings"
    ordered = [
        f"{int(counts.get(level) or 0)} {level}"
        for level in ("critical", "high", "caution", "info")
        if int(counts.get(level) or 0)
    ]
    return f"{len(current)} total" + (" • " + " • ".join(ordered) if ordered else "")


def github_rule_sources(definitions_index_path: Path | None, repository: str) -> tuple[str, dict[str, dict[str, object]]]:
    """Map frozen SRL rule IDs back to their exact reviewed source YAML.

    The link is pinned to Definitions' builtFromDevCommit so an old Discord incident
    never silently starts pointing at a newer rule body after the branch moves.
    """
    if not definitions_index_path or not definitions_index_path.is_file():
        return "sigmascope", {}
    index = read_json(definitions_index_path)
    source_ref = clean(index.get("builtFromDevCommit") or "sigmascope", 80)
    descriptor = index.get("srlDefinitionPacks") if isinstance(index.get("srlDefinitionPacks"), dict) else {}
    rel = str(descriptor.get("path") or "srl/index.json")
    srl_index_path = definitions_index_path.parent / rel
    if not srl_index_path.is_file():
        return source_ref, {}
    srl_index = read_json(srl_index_path)
    result: dict[str, dict[str, object]] = {}
    for pack in srl_index.get("packs") or []:
        if not isinstance(pack, dict):
            continue
        pack_id = str(pack.get("id") or "")
        for rule_file in pack.get("rules") or []:
            if not isinstance(rule_file, dict):
                continue
            relative_rule = str(rule_file.get("path") or "")
            source_path = f"security-definitions/packs/{pack_id}/{relative_rule}"
            frozen_path = definitions_index_path.parent / "srl" / "packs" / pack_id / relative_rule
            lines = frozen_path.read_text(encoding="utf-8").splitlines() if frozen_path.is_file() else []
            for rule_id in rule_file.get("ruleIds") or []:
                rule_id = str(rule_id)
                line_number = 0
                needle = f"id: {rule_id}"
                for number, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if stripped == needle or stripped == f"- {needle}":
                        line_number = number
                        break
                url = f"https://github.com/{repository}/blob/{source_ref}/{source_path}"
                if line_number:
                    url += f"#L{line_number}"
                result[rule_id] = {"path": source_path, "url": url, "line": line_number}
    return source_ref, result


def rule_links(
    findings: list[dict[str, str]],
    definitions_index_path: Path | None,
    repository: str,
    identity: dict[str, object],
    count: int = 2,
) -> str:
    _, sources = github_rule_sources(definitions_index_path, repository)
    linked = [row for row in findings if row.get("ruleId") in sources]
    samples = deterministic_sample(linked, identity, "rule-yaml", count)
    return "\n".join(
        f"[{clean(row.get('ruleId'), 100)}]({sources[str(row.get('ruleId'))]['url']})"
        for row in samples
    )


def definitions_metrics(path: Path | None) -> dict[str, Any]:
    if not path or not path.is_file():
        return {}
    index = read_json(path)
    packs = index.get("srlDefinitionPacks") if isinstance(index.get("srlDefinitionPacks"), dict) else {}
    capabilities = index.get("capabilityRegistry") if isinstance(index.get("capabilityRegistry"), dict) else {}
    osv = index.get("osv") if isinstance(index.get("osv"), dict) else {}
    source = index.get("sourceObservations") if isinstance(index.get("sourceObservations"), dict) else {}
    counts = source.get("counts") if isinstance(source.get("counts"), dict) else {}
    secondary = index.get("secondarySecurity") if isinstance(index.get("secondarySecurity"), dict) else {}
    pack_rows: list[dict[str, Any]] = []
    pack_path = path.parent / str(packs.get("path") or "srl/index.json")
    if pack_path.is_file():
        pack_rows = [row for row in (read_json(pack_path).get("packs") or []) if isinstance(row, dict)]
    return {
        "revision": str(index.get("definitionsRevision") or ""),
        "advisoryRevision": str(index.get("advisoryRevision") or ""),
        "packCount": int(packs.get("packCount") or len(pack_rows)),
        "activeRuleCount": int(packs.get("activeRuleCount") or 0),
        "capabilityCount": int(capabilities.get("capabilityCount") or 0),
        "categoryCount": int(capabilities.get("categoryCount") or 0),
        "queriedPackages": int(osv.get("queriedPackages") or 0),
        "matchedPackages": int(osv.get("matchedPackages") or 0),
        "sourceRepositories": int(counts.get("repositories") or 0),
        "sourceObserved": int(counts.get("observed") or 0),
        "sourceFailed": int(counts.get("failed") or 0),
        "secondaryEngineCount": int(secondary.get("engineCount") or len(secondary.get("engines") or [])),
        "packs": pack_rows,
    }


def changed_pack_examples(current: dict[str, Any], previous: dict[str, Any], identity: dict[str, object]) -> str:
    previous_by_id = {str(row.get("id") or ""): row for row in previous.get("packs") or []}
    changed = [
        row for row in current.get("packs") or []
        if str(row.get("id") or "") not in previous_by_id
        or str(row.get("packRevision") or "") != str(previous_by_id[str(row.get("id") or "")].get("packRevision") or "")
    ]
    samples = deterministic_sample(changed, identity, "definition-pack-examples", 2)
    return "\n".join(clean(row.get("title") or row.get("id"), 100) for row in samples)


def evidence_revision_link(repository: str, revision: object) -> str:
    label = short(revision) or "current"
    return f"[{label}](https://github.com/{repository}/tree/security-evidence-v2)"


def build_sigmascope(
    report_path: Path,
    database: Path,
    repository: str,
    run_url: str,
    definitions_index: Path | None = None,
) -> dict[str, Any]:
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
    snapshot = finding_snapshot(database, variant_id)
    severity = str(snapshot.get("severity") or "")
    introduced_high = list(snapshot.get("introducedHigh") or [])
    introduced_all = list(snapshot.get("introduced") or [])
    removed_all = list(snapshot.get("removed") or [])
    sample_high = deterministic_sample(introduced_high, identity, "security-finding-examples", 2)

    if introduced_high:
        webhook_key = "security"
        title_template = event_choice(
            "security", "title", identity, (
                "New security findings for {plugin}",
                "{plugin} picked up new security signals",
                "Fresh security evidence for {plugin}",
                "SigmaScope has new findings for {plugin}",
                "The security record changed for {plugin}",
                "New high-interest evidence: {plugin}",
            ),
        )
        title = title_template.format(plugin=plugin)
        detail_template = event_choice(
            "security", "detail", identity, (
                "SigmaScope recorded {count} new high/critical finding{suffix} for {plugin}.",
                "The latest retained evidence adds {count} new high-interest finding{suffix} for {plugin}.",
                "Compared with the previous scan lineage, {plugin} has {count} newly introduced high/critical finding{suffix}.",
                "The current evidence revision contains {count} high/critical finding{suffix} for {plugin} that were not in its previous scan.",
            ),
        )
        description = (
            f"{voice_line('security', identity)} "
            + detail_template.format(plugin=plugin, count=len(introduced_high), suffix="" if len(introduced_high) == 1 else "s")
            + " Review the findings if you want to know more."
        )
        yaml_links = rule_links(introduced_high, definitions_index, repository, identity)
        example_text = "\n".join(
            f"{row['severity'].upper()} · {row['title']}" for row in sample_high
        )
        fields: list[tuple[str, object] | tuple[str, object, bool]] = [
            ("Plugin", plugin),
            ("Highest result", (severity or "recorded").upper()),
            ("New high / critical", len(introduced_high)),
            ("Finding state", f"{finding_count_text(snapshot)} • +{len(introduced_all)} new • -{len(removed_all)} cleared", False),
            ("Examples", example_text, False),
        ]
        if yaml_links:
            fields.append(("Reviewed rule YAML", yaml_links, False))
        else:
            fields.append(("Rule source", "Legacy scanner finding — no reviewed SRL YAML source is published for this rule yet.", False))
        fields.extend([
            ("Evidence", evidence_revision_link(repository, revisions.get("evidenceRevision"))),
            ("Run", run_url),
        ])
        payload = embed(title, description, 15_158_332, fields)
    elif work_type == "advisory":
        webhook_key = "definitions"
        advisory_title = event_choice(
            "definitions", "advisory-title", identity, (
                "Omega definitions updated",
                "Frozen advisory context refreshed",
                "SigmaScope definitions moved forward",
                "New advisory definitions are in",
                "Security definitions refreshed",
                "A newer Definitions snapshot is active",
            ),
        )
        metrics = definitions_metrics(definitions_index)
        payload = embed(
            advisory_title,
            (
                f"{voice_line('definitions', identity)} "
                "SigmaScope applied the frozen advisory definitions to the current evidence set."
            ),
            10_181_046,
            [
                ("Packages checked", metrics.get("queriedPackages") or "recorded"),
                ("Matched packages", metrics.get("matchedPackages") or 0),
                ("Active SRL rules", metrics.get("activeRuleCount") or "recorded"),
                ("Advisories", short(revisions.get("advisoryRevision") or metrics.get("advisoryRevision"))),
                ("Evidence", evidence_revision_link(repository, revisions.get("evidenceRevision"))),
                ("Run", run_url),
            ],
        )
    else:
        webhook_key = "evidence"
        evidence_title = event_choice(
            "evidence", "title", identity, (
                "Omega evidence review complete",
                "Evidence refreshed for {plugin}",
                "SigmaScope filed a new evidence revision",
                "Review complete: {plugin}",
                "A newer evidence record is published",
                "Evidence ledger updated for {plugin}",
            ),
        ).format(plugin=plugin)
        examples = deterministic_sample(introduced_all or list(snapshot.get("current") or []), identity, "evidence-examples", 2)
        payload = embed(
            evidence_title,
            (
                f"{voice_line('evidence', identity)} "
                f"SigmaScope completed a {work_type} evidence review for {plugin}."
            ),
            5_793_266,
            [
                ("Plugin", plugin),
                ("Review", work_type),
                ("Highest result", severity or "recorded"),
                ("Current findings", finding_count_text(snapshot), False),
                ("Finding delta", f"+{len(introduced_all)} new • -{len(removed_all)} cleared"),
                ("Examples", "\n".join(row["title"] for row in examples), False),
                ("Evidence", evidence_revision_link(repository, revisions.get("evidenceRevision"))),
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


def plugin_name(row: dict[str, Any]) -> str:
    return clean(row.get("name") or row.get("internalName") or "Unnamed plugin", 90)


def catalog_examples(
    added: list[dict[str, Any]],
    changed: list[dict[str, Any]],
    removed: list[dict[str, Any]],
    identity: dict[str, object],
) -> str:
    candidates = [
        {"kind": "added", "icon": "➕", "row": row} for row in added
    ] + [
        {"kind": "updated", "icon": "🔄", "row": row} for row in changed
    ] + [
        {"kind": "removed", "icon": "➖", "row": row} for row in removed
    ]
    samples = deterministic_sample(candidates, identity, "catalog-plugin-examples", 2)
    return "\n".join(f"{item['icon']} {plugin_name(item['row'])} · {item['kind']}" for item in samples)


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

    current_active = {key: row for key, row in current_rows.items() if row.get("active")}
    previous_active = {key: row for key, row in previous_rows.items() if row.get("active")}
    added = [row for key, row in current_active.items() if key not in previous_active]
    changed = [
        row for key, row in current_active.items()
        if key in previous_active and row.get("sha256") != previous_active[key].get("sha256")
    ]
    removed = [row for key, row in previous_active.items() if key not in current_active]

    definitions_index = read_json(definitions)
    previous_definitions_index = read_json(previous_definitions) if previous_definitions.is_file() else {}
    current_definition_metrics = definitions_metrics(definitions)
    previous_definition_metrics = definitions_metrics(previous_definitions)

    catalog_revision = current_index.get("catalogRevision") or ""
    previous_revision = previous_index.get("catalogRevision") or ""
    definitions_revision = definitions_index.get("definitionsRevision") or ""
    previous_definitions_revision = previous_definitions_index.get("definitionsRevision") or ""

    catalog_changed = bool(catalog_revision and catalog_revision != previous_revision)
    definitions_changed = bool(definitions_revision and definitions_revision != previous_definitions_revision)
    should_notify = catalog_changed or definitions_changed
    webhook_key = "catalog" if catalog_changed else "definitions"
    identity: dict[str, object] = {
        "repository": repository,
        "catalog": catalog_revision,
        "definitions": definitions_revision,
    }

    if not should_notify:
        return notice("catalog", webhook_key, {}, identity, False)

    counts = current_index.get("counts") if isinstance(current_index.get("counts"), dict) else {}
    active_plugins = int(counts.get("plugins") or len(current_active))
    active_variants = int(counts.get("variants") or 0)
    source_count = int(counts.get("sources") or 0)

    if catalog_changed:
        title = event_choice(
            "catalog", "title", identity, (
                "Omega catalog updated",
                "A newer Omega catalog is live",
                "Plugin catalog revision published",
                "Omega's plugin ledger moved forward",
                "Fresh catalog state is ready",
                "The Omega catalog just grew",
            ),
        )
        if added or changed or removed:
            change_summary = (
                f"This revision contains {len(added)} added, {len(changed)} updated, "
                f"and {len(removed)} removed plugin record{'s' if (len(added)+len(changed)+len(removed)) != 1 else ''}."
            )
        else:
            change_summary = event_choice(
                "catalog", "revision-summary", identity, (
                    "The catalog revision changed without a plugin shard delta.",
                    "The snapshot moved forward on catalog metadata rather than plugin records.",
                    "This revision is mostly bookkeeping, but reproducible bookkeeping matters.",
                    "The catalog identity advanced even though no plugin record hash changed.",
                ),
            )
        description = (
            f"{voice_line('catalog', identity)} {change_summary} "
            "The latest catalog snapshot is published and ready for Omega."
        )
        examples = catalog_examples(added, changed, removed, identity)
        fields: list[tuple[str, object] | tuple[str, object, bool]] = [
            ("Catalog size", f"{active_plugins} plugins • {active_variants} active variants", False),
            ("Sources", source_count),
            ("Added", len(added)),
            ("Updated", len(changed)),
            ("Removed", len(removed)),
            ("Examples", examples or "Metadata-only catalog change", False),
        ]
        if definitions_changed:
            fields.append(("Definitions", f"also changed · {short(definitions_revision)}"))
        fields.extend([
            ("Catalog", short(catalog_revision)),
            ("Run", run_url),
        ])
    else:
        title = event_choice(
            "definitions", "catalog-title", identity, (
                "Omega definitions updated",
                "New frozen Definitions published",
                "Security context moved forward",
                "Fresh SigmaScope Definitions are live",
                "The Definitions ledger advanced",
                "Omega published newer security definitions",
            ),
        )
        description = (
            f"{voice_line('definitions', identity)} "
            "A new frozen Definitions snapshot is published for SigmaScope."
        )
        changed_packs = changed_pack_examples(current_definition_metrics, previous_definition_metrics, identity)
        fields = [
            ("Rule packs", f"{current_definition_metrics.get('packCount', 0)} packs • {current_definition_metrics.get('activeRuleCount', 0)} active rules", False),
            ("Capabilities", f"{current_definition_metrics.get('capabilityCount', 0)} capabilities • {current_definition_metrics.get('categoryCount', 0)} categories", False),
            ("OSV coverage", f"{current_definition_metrics.get('matchedPackages', 0)} matched • {current_definition_metrics.get('queriedPackages', 0)} package/version pairs checked", False),
            ("Source watch", f"{current_definition_metrics.get('sourceObserved', 0)}/{current_definition_metrics.get('sourceRepositories', 0)} observed • {current_definition_metrics.get('sourceFailed', 0)} failed", False),
            ("Changed packs", changed_packs or "Semantic revision changed; pack counts/names unchanged", False),
            ("Definitions", short(definitions_revision)),
            ("Run", run_url),
        ]

    payload = embed(
        title,
        description,
        5_793_266 if catalog_changed else 10_181_046,
        fields,
    )
    return notice("catalog", webhook_key, payload, identity)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    security = subparsers.add_parser("sigmascope")
    security.add_argument("--report", required=True, type=Path)
    security.add_argument("--database", required=True, type=Path)
    security.add_argument("--definitions-index", type=Path)
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
    result = (
        build_sigmascope(args.report, args.database, args.repository, args.run_url, args.definitions_index)
        if args.command == "sigmascope"
        else build_catalog(
            args.catalog_index, args.previous_catalog_index, args.definitions_index,
            args.previous_definitions_index, args.repository, args.run_url,
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Discord notice: {result['event']} ({'queued' if result['shouldNotify'] else 'no change'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
