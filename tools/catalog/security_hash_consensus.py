"""Derive current cross-source artifact-hash findings from completed scans."""
from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict


DERIVED_RULE_ID = "artifact.cross-source-hash-mismatch"


def _severity_counts(findings: list[dict]) -> tuple[dict[str, int], str]:
    ranks = {"none": 0, "informational": 1, "caution": 2, "high": 3, "critical": 4}
    counts = {severity: sum(1 for finding in findings if finding.get("severity") == severity) for severity in ranks if severity != "none"}
    highest = max((str(finding.get("severity") or "none") for finding in findings), key=lambda value: ranks.get(value, 0), default="none")
    return counts, highest


def refresh_cross_source_hash_findings(db: sqlite3.Connection) -> dict[str, int]:
    rows = db.execute("""
        SELECT c.variant_id,c.scan_id,c.report_json,c.artifact_sha256,v.assembly_version,p.internal_name,
               s.source_id,s.name AS source_name,s.is_official
          FROM plugin_security_current c
          JOIN plugin_variants v ON v.variant_id=c.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
         WHERE c.status='complete' AND c.artifact_sha256<>'' AND v.active=1 AND p.active=1
    """).fetchall()
    source_counts = Counter({
        int(row["source_id"]): int(row["variant_count"])
        for row in db.execute("""
            SELECT s.source_id,COUNT(*) AS variant_count
              FROM sources s
              JOIN plugin_variants v ON v.source_id=s.source_id
              JOIN plugins p ON p.plugin_id=v.plugin_id
             WHERE v.active=1 AND p.active=1
             GROUP BY s.source_id
        """).fetchall()
    })
    top_sources = {source_id for source_id, _count in source_counts.most_common(4)}
    groups: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        groups[(str(row["internal_name"]).casefold(), str(row["assembly_version"] or "").casefold())].append(row)

    derived: dict[int, dict] = {}
    for (_internal_name, version), members in groups.items():
        by_hash: dict[str, list[sqlite3.Row]] = defaultdict(list)
        for member in members:
            by_hash[str(member["artifact_sha256"]).casefold()].append(member)
        if len(by_hash) < 2:
            continue
        dominant_hash, dominant_members = max(by_hash.items(), key=lambda item: len({row["source_id"] for row in item[1]}))
        dominant_sources = {row["source_id"] for row in dominant_members}
        dominant_is_trusted = any(bool(row["is_official"]) or row["source_id"] in top_sources for row in dominant_members)
        participants = [
            f"{row['source_name']}: {str(row['artifact_sha256'])[:12]}"
            for row in sorted(members, key=lambda item: (str(item["source_name"]).casefold(), item["source_id"]))[:8]
        ]
        for artifact_hash, hash_members in by_hash.items():
            hash_sources = {row["source_id"] for row in hash_members}
            is_unshared_outlier = (
                artifact_hash != dominant_hash and len(hash_sources) == 1 and len(dominant_sources) >= 2 and dominant_is_trusted
            )
            severity = "high" if is_unshared_outlier else "caution"
            title = "Unshared artifact hash beside source consensus" if is_unshared_outlier else "Cross-source artifact hash mismatch"
            description = (
                "This artifact hash appears in one source while a different hash for the same plugin version is shared by multiple official or top-four catalog sources. Review the source and hash before installing."
                if is_unshared_outlier else
                "Sources publish different artifact hashes for the same plugin version. This can be legitimate re-packaging, but the source and hash deserve review."
            )
            for member in hash_members:
                derived[int(member["variant_id"])] = {
                    "ruleId": DERIVED_RULE_ID,
                    "severity": severity,
                    "category": "provenance",
                    "title": title,
                    "description": description,
                    "evidence": [f"Version: {version or 'unknown'}", *participants],
                }

    updated = 0
    for row in rows:
        report = json.loads(str(row["report_json"] or "{}"))
        findings = [item for item in report.get("findings") or [] if isinstance(item, dict) and item.get("ruleId") != DERIVED_RULE_ID]
        dynamic = derived.get(int(row["variant_id"]))
        if dynamic is not None:
            findings.append(dynamic)
        findings.sort(key=lambda item: ({"critical": 4, "high": 3, "caution": 2, "informational": 1}.get(str(item.get("severity") or "none"), 0), str(item.get("ruleId") or "")), reverse=True)
        counts, highest = _severity_counts(findings)
        capabilities = [str(value) for value in report.get("capabilities") or [] if str(value)]
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
    return {"groupsWithMismatches": sum(1 for members in groups.values() if len({str(row['artifact_sha256']).casefold() for row in members}) > 1), "updatedVariants": updated}
