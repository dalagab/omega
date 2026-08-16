"""Derive cross-source artifact provenance findings from completed scans.

Omega treats Dalamud, Puni.sh, NightmareXIV and Combat Reborn as stable baseline
publishers for package identity. This is a provenance rule, not a security waiver:
the chosen baseline artifact keeps its normal static-analysis findings.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict

from source_stability import classify_stable_source, stable_source_priority


DERIVED_RULE_ID = "artifact.cross-source-hash-mismatch"


def _severity_counts(findings: list[dict]) -> tuple[dict[str, int], str]:
    ranks = {"none": 0, "informational": 1, "caution": 2, "high": 3, "critical": 4}
    counts = {severity: sum(1 for finding in findings if finding.get("severity") == severity) for severity in ranks if severity != "none"}
    highest = max((str(finding.get("severity") or "none") for finding in findings), key=lambda value: ranks.get(value, 0), default="none")
    return counts, highest


def _baseline_member(members: list[sqlite3.Row]) -> tuple[sqlite3.Row, bool]:
    stable_members = [
        row for row in members
        if stable_source_priority(row["source_name"], row["source_url"], bool(row["is_official"])) is not None
    ]
    if stable_members:
        return min(
            stable_members,
            key=lambda row: (
                stable_source_priority(row["source_name"], row["source_url"], bool(row["is_official"])) or 0,
                str(row["source_name"] or "").casefold(),
                int(row["source_id"]),
            ),
        ), True

    by_hash: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for member in members:
        by_hash[str(member["artifact_sha256"] or "").casefold()].append(member)
    dominant_hash = sorted(
        by_hash,
        key=lambda artifact_hash: (-len({int(row["source_id"]) for row in by_hash[artifact_hash]}), artifact_hash),
    )[0]
    representative = min(
        by_hash[dominant_hash],
        key=lambda row: (str(row["source_name"] or "").casefold(), int(row["source_id"])),
    )
    return representative, False


def canonicalize_current_security_by_artifact(db: sqlite3.Connection) -> dict[str, int]:
    """Canonicalize current user-facing scan summaries for identical package bytes.

    Historical scan/evidence tables remain untouched. The current projection chooses a stable
    provider first, then a deterministic community source, so one artifact SHA-256 has one
    current severity/capability/finding result regardless of which repository mirrors it.
    """
    rows = db.execute("""
        SELECT c.variant_id,c.artifact_sha256,c.assembly_version,p.internal_name,
               s.source_id,s.name AS source_name,s.url AS source_url,s.is_official
          FROM plugin_security_current c
          JOIN plugin_variants v ON v.variant_id=c.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
         WHERE c.status='complete' AND c.artifact_sha256<>'' AND v.active=1 AND p.active=1
         ORDER BY p.internal_name COLLATE NOCASE,c.assembly_version COLLATE NOCASE,c.artifact_sha256,c.variant_id
    """).fetchall()
    groups: dict[tuple[str, str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        groups[(
            str(row["internal_name"] or "").casefold(),
            str(row["assembly_version"] or "").casefold(),
            str(row["artifact_sha256"] or "").casefold(),
        )].append(row)

    fields = (
        "scanner_version", "status", "scanned_at_utc", "highest_severity",
        "informational_count", "caution_count", "high_count", "critical_count",
        "capabilities_json", "automation_level", "automation_capabilities_json",
        "findings_json", "error",
    )
    mirrored_groups = 0
    updated = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        mirrored_groups += 1
        canonical = min(
            members,
            key=lambda row: (
                stable_source_priority(row["source_name"], row["source_url"], bool(row["is_official"]))
                if stable_source_priority(row["source_name"], row["source_url"], bool(row["is_official"])) is not None
                else 1_000,
                str(row["source_name"] or "").casefold(),
                int(row["source_id"]),
            ),
        )
        values = db.execute(
            f"SELECT {','.join(fields)} FROM plugin_security_current WHERE variant_id=?",
            (int(canonical["variant_id"]),),
        ).fetchone()
        if values is None:
            continue
        assignments = ",".join(f"{field}=?" for field in fields)
        for member in members:
            if int(member["variant_id"]) == int(canonical["variant_id"]):
                continue
            db.execute(
                f"UPDATE plugin_security_current SET {assignments} WHERE variant_id=?",
                (*tuple(values), int(member["variant_id"])),
            )
            updated += 1
    return {"mirroredArtifactGroups": mirrored_groups, "canonicalizedVariants": updated}


def refresh_cross_source_hash_findings(db: sqlite3.Connection) -> dict[str, int]:
    rows = db.execute("""
        SELECT c.variant_id,c.scan_id,c.findings_json,c.capabilities_json,c.artifact_sha256,v.assembly_version,p.internal_name,
               s.source_id,s.name AS source_name,s.url AS source_url,s.is_official
          FROM plugin_security_current c
          JOIN plugin_variants v ON v.variant_id=c.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
         WHERE c.status='complete' AND c.artifact_sha256<>'' AND v.active=1 AND p.active=1
    """).fetchall()

    groups: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        groups[(str(row["internal_name"]).casefold(), str(row["assembly_version"] or "").casefold())].append(row)

    derived: dict[int, dict] = {}
    mismatch_groups = 0
    stable_baseline_groups = 0
    for (_internal_name, version), members in groups.items():
        hashes = {str(row["artifact_sha256"] or "").casefold() for row in members if str(row["artifact_sha256"] or "")}
        if len(hashes) < 2:
            continue
        mismatch_groups += 1

        baseline, has_stable_baseline = _baseline_member(members)
        if has_stable_baseline:
            stable_baseline_groups += 1
        baseline_hash = str(baseline["artifact_sha256"] or "").casefold()
        baseline_provider = classify_stable_source(baseline["source_name"], baseline["source_url"], bool(baseline["is_official"]))
        baseline_label = baseline_provider.label if baseline_provider is not None else str(baseline["source_name"] or "source consensus")
        participants = [
            f"{row['source_name']}: {str(row['artifact_sha256'])[:12]}"
            for row in sorted(members, key=lambda item: (str(item["source_name"]).casefold(), int(item["source_id"])))[:8]
        ]

        for member in members:
            artifact_hash = str(member["artifact_sha256"] or "").casefold()
            if artifact_hash == baseline_hash:
                continue
            severity = "high" if has_stable_baseline else "caution"
            title = "Artifact differs from stable package baseline" if has_stable_baseline else "Cross-source artifact hash mismatch"
            description = (
                f"This source publishes different package bytes for the same plugin version than Omega's {baseline_label} baseline. "
                "The source is treated as an artifact deviation and should be reviewed before installation."
                if has_stable_baseline else
                "Sources publish different artifact hashes for the same plugin version and no stable baseline publisher is present. "
                "Omega uses the source consensus as the comparison baseline."
            )
            derived[int(member["variant_id"])] = {
                "ruleId": DERIVED_RULE_ID,
                "severity": severity,
                "category": "provenance",
                "title": title,
                "description": description,
                "evidence": [
                    f"Version: {version or 'unknown'}",
                    f"Baseline: {baseline_label} {baseline_hash[:12]}",
                    *participants,
                ],
            }

    updated = 0
    for row in rows:
        current_findings = json.loads(str(row["findings_json"] or "[]"))
        findings = [item for item in current_findings if isinstance(item, dict) and item.get("ruleId") != DERIVED_RULE_ID]
        dynamic = derived.get(int(row["variant_id"]))
        if dynamic is not None:
            findings.append(dynamic)
        findings.sort(key=lambda item: ({"critical": 4, "high": 3, "caution": 2, "informational": 1}.get(str(item.get("severity") or "none"), 0), str(item.get("ruleId") or "")), reverse=True)
        counts, highest = _severity_counts(findings)
        capabilities = [
            str(value) for value in json.loads(str(row["capabilities_json"] or "[]"))
            if str(value) and str(value) != "Cross-source hash comparison"
        ]
        if dynamic is not None and "Cross-source hash comparison" not in capabilities:
            capabilities.append("Cross-source hash comparison")
        db.execute("""
            UPDATE plugin_security_current
               SET highest_severity=?,informational_count=?,caution_count=?,high_count=?,critical_count=?,
                   capabilities_json=?,findings_json=?
             WHERE variant_id=?
        """, (
            highest, counts["informational"], counts["caution"], counts["high"], counts["critical"],
            json.dumps(sorted(capabilities, key=str.casefold), separators=(",", ":")),
            json.dumps(findings, separators=(",", ":")), int(row["variant_id"]),
        ))
        updated += 1
    return {
        "groupsWithMismatches": mismatch_groups,
        "stableBaselineGroups": stable_baseline_groups,
        "updatedVariants": updated,
    }
