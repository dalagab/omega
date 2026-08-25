#!/usr/bin/env python3
"""Read-only cross-variant explainability for one Omega logical plugin.

The catalog intentionally allows several source/build variants beneath one canonical
``plugin_id``.  DeltaScope's developer picker collapses those variants for navigation,
but the collapse must never hide meaningful differences.  This module compares only
already-published catalog/evidence metadata and returns explanation cues.  It does not
create SigmaScope findings, establish maliciousness, or alter scan/catalog policy.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

SCHEMA = "omega.deltascope.logical-plugin-divergence.v1"
SEVERITY_ORDER = {"none": 0, "informational": 1, "low": 1, "caution": 2, "moderate": 2, "medium": 2, "high": 3, "critical": 4}


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _text(value: Any) -> str:
    return str(value or "").strip()


def _norm(value: Any) -> str:
    return _text(value).casefold()


def _visible_variant(row: Mapping[str, Any], historical: bool) -> bool:
    if historical:
        return True
    return _int(row.get("active")) == 1 and _int(row.get("is_hide") or row.get("isHide")) != 1


def _finding_counts(row: Mapping[str, Any]) -> tuple[int, int, int, int]:
    raw = row.get("evidenceFindingCounts") if isinstance(row.get("evidenceFindingCounts"), Mapping) else {}
    return (
        _int(raw.get("informational") or row.get("evidenceInformationalCount")),
        _int(raw.get("caution") or row.get("evidenceCautionCount")),
        _int(raw.get("high") or row.get("evidenceHighCount")),
        _int(raw.get("critical") or row.get("evidenceCriticalCount")),
    )


def _security_signature(row: Mapping[str, Any]) -> tuple[Any, ...]:
    severity = _norm(row.get("evidenceHighestSeverity") or "none") or "none"
    return (severity, *_finding_counts(row))


def _cohort_key(row: Mapping[str, Any]) -> tuple[str, int]:
    return (_norm(row.get("assembly_version") or row.get("evidenceAssemblyVersion")), _int(row.get("dalamud_api_level")))


def _signal(kind: str, level: str, label: str, detail: str, variant_ids: Iterable[int] = ()) -> dict[str, Any]:
    return {
        "kind": kind,
        "level": level,
        "label": label,
        "detail": detail,
        "variantIds": sorted({_int(value) for value in variant_ids if _int(value) > 0}),
    }


def project_logical_plugin_divergence(context: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compare sibling catalog variants without creating security authority.

    Stronger warnings are intentionally limited to *same version + same API* cohorts.
    Different artifacts across different versions are normal version skew, not proof of a
    suspicious build.  Similarly, differing security summaries are review cues only.
    """
    context = context if isinstance(context, Mapping) else {}
    rows = [dict(row) for row in context.get("variants") or [] if isinstance(row, Mapping)]
    historical = str(context.get("variantScope") or "active") == "historical" or context.get("catalogActive") is False
    variants = [row for row in rows if _visible_variant(row, historical)]
    variant_ids = [_int(row.get("variant_id") or row.get("variantId")) for row in variants]
    covered = [row for row in variants if bool(row.get("currentEvidence"))]
    uncovered = [row for row in variants if not bool(row.get("currentEvidence"))]

    versions = sorted({_text(row.get("assembly_version") or row.get("evidenceAssemblyVersion")) for row in variants if _text(row.get("assembly_version") or row.get("evidenceAssemblyVersion"))}, key=str.casefold)
    api_levels = sorted({_int(row.get("dalamud_api_level")) for row in variants if _int(row.get("dalamud_api_level")) > 0})
    unknown_api_ids = [_int(row.get("variant_id")) for row in variants if _int(row.get("dalamud_api_level")) <= 0]
    sources = {
        _norm(row.get("source_url") or row.get("source_name") or row.get("source_id"))
        for row in variants
        if _text(row.get("source_url") or row.get("source_name") or row.get("source_id"))
    }

    signals: list[dict[str, Any]] = []
    if len(variants) <= 1:
        signals.append(_signal("single-variant", "ok", "One comparable catalog variant", "There is no sibling source/build to compare for this logical plugin.", variant_ids))
    else:
        if uncovered:
            signals.append(_signal(
                "coverage-gap", "attention", "Not every sibling has current Evidence-v2",
                f"{len(covered)} of {len(variants)} comparable variants have current published evidence. Unscanned siblings are not assumed equivalent to scanned siblings.",
                [_int(row.get("variant_id")) for row in uncovered],
            ))
        else:
            signals.append(_signal("coverage-complete", "ok", "All comparable siblings have current Evidence-v2", f"All {len(variants)} comparable variants can be checked against published security summaries.", variant_ids))

        if len(versions) > 1:
            signals.append(_signal(
                "version-skew", "info", "Current sources publish different plugin versions",
                "The logical plugin is current in more than one source/build, but the assembly versions are not identical: " + ", ".join(versions) + ". This can be normal repository lag or release-channel skew.",
                variant_ids,
            ))
        if len(api_levels) > 1 or unknown_api_ids:
            detail = f"Stable API levels present: {', '.join(str(v) for v in api_levels) or 'none recorded'}."
            if unknown_api_ids:
                detail += f" {len(unknown_api_ids)} sibling(s) have unknown API metadata."
            signals.append(_signal("api-skew", "info", "Sibling API metadata is mixed", detail, variant_ids))

        cohorts: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for row in covered:
            cohorts[_cohort_key(row)].append(row)
        for (version, api_level), cohort in sorted(cohorts.items()):
            if len(cohort) < 2:
                continue
            cohort_ids = [_int(row.get("variant_id")) for row in cohort]
            hashes = {_norm(row.get("evidenceArtifactSha256")) for row in cohort if _text(row.get("evidenceArtifactSha256"))}
            if len(hashes) > 1:
                signals.append(_signal(
                    "same-version-artifact-difference", "attention", "Same-version siblings have different artifact hashes",
                    f"At version {version or 'unknown'} / API {api_level or 'unknown'}, published artifact SHA-256 values differ across sources. Different packaging can be legitimate; inspect the exact variants before drawing a security conclusion.",
                    cohort_ids,
                ))
            signatures = {_security_signature(row) for row in cohort}
            if len(signatures) > 1:
                signals.append(_signal(
                    "same-version-security-difference", "attention", "Same-version siblings have different security summaries",
                    f"At version {version or 'unknown'} / API {api_level or 'unknown'}, current Evidence-v2 severity/finding counts are not identical across sibling variants. This is a review cue, not a finding about either source.",
                    cohort_ids,
                ))

        if len(sources) > 1 and not any(item["kind"].startswith("same-version-") for item in signals):
            signals.append(_signal(
                "multiple-sources", "ok", "Multiple sources remain independently attributable",
                f"{len(sources)} source identities are represented. No same-version artifact/security mismatch is visible in the compact published comparison.",
                variant_ids,
            ))

    attention = [row for row in signals if row.get("level") == "attention"]
    info = [row for row in signals if row.get("level") == "info"]
    if attention:
        state = "review"
        headline = "Sibling variants need comparison"
        explanation = "DeltaScope found differences or coverage gaps that should be inspected at exact variant level before treating the logical plugin as uniform."
    elif len(variants) <= 1:
        state = "single"
        headline = "One comparable variant"
        explanation = "There is no current sibling source/build to compare for this logical plugin."
    elif info:
        state = "mixed"
        headline = "Sibling metadata differs, but no same-version security mismatch is proven"
        explanation = "The current catalog variants are not identical in version/API metadata. DeltaScope keeps those differences visible without turning normal source/release skew into a security finding."
    else:
        state = "aligned"
        headline = "Sibling variants align on the compact comparable state"
        explanation = "No material difference is visible in the published compact metadata that DeltaScope can compare without loading every sibling's detailed evidence."

    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "findingAuthority": False,
        "scanEligibilityAuthority": False,
        "pluginId": _int(context.get("pluginId")),
        "variantScope": "historical" if historical else "active",
        "state": state,
        "headline": headline,
        "explanation": explanation,
        "comparableVariantCount": len(variants),
        "coveredVariantCount": len(covered),
        "uncoveredVariantCount": len(uncovered),
        "sourceCount": len(sources),
        "versionCount": len(versions),
        "versions": versions,
        "apiLevels": api_levels,
        "signals": signals,
        "limits": [
            "This projection compares catalog metadata and compact current Evidence-v2 summaries only.",
            "Different hashes across different versions are normal version skew and are not labeled as suspicious.",
            "A difference is a navigation/review cue, never a SigmaScope finding or source trust verdict.",
        ],
    }
