"""Deterministic read-only developer review guidance for DeltaScope.

The projection turns already-loaded dossier state into a prioritized navigation plan.
It does not create findings, change scan eligibility, enqueue work, or write production state.
"""
from __future__ import annotations

from typing import Any, Mapping

SCHEMA = "omega.deltascope.developer-review-plan.v1"
SEVERITY = {"none": 0, "informational": 1, "low": 1, "caution": 2, "moderate": 2, "medium": 2, "high": 3, "critical": 4}
PRIORITY = {"urgent": 0, "review": 1, "follow-up": 2, "context": 3}


def _int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _text(v: Any) -> str:
    return str(v or "").strip()


def _action(action_id: str, priority: str, title: str, reason: str, tab: str, *, variant_ids=(), category="review") -> dict[str, Any]:
    return {
        "actionId": action_id,
        "priority": priority,
        "category": category,
        "title": title,
        "reason": reason,
        "targetTab": tab,
        "variantIds": sorted({_int(v) for v in variant_ids if _int(v) > 0}),
        "readOnly": True,
        "mutationRequired": False,
    }


def project_developer_review_plan(detail: Mapping[str, Any] | None) -> dict[str, Any]:
    d = detail if isinstance(detail, Mapping) else {}
    identity = d.get("identity") if isinstance(d.get("identity"), Mapping) else {}
    researcher = d.get("researcher") if isinstance(d.get("researcher"), Mapping) else {}
    context = d.get("catalogContext") if isinstance(d.get("catalogContext"), Mapping) else {}
    divergence = context.get("divergence") if isinstance(context.get("divergence"), Mapping) else {}
    coverage = d.get("sourceCoverage") if isinstance(d.get("sourceCoverage"), Mapping) else {}
    secondary = d.get("secondarySecurity") if isinstance(d.get("secondarySecurity"), Mapping) else {}
    findings = researcher.get("findings") if isinstance(researcher.get("findings"), list) else d.get("findings") if isinstance(d.get("findings"), list) else []
    advisories = d.get("advisories") if isinstance(d.get("advisories"), list) else []
    variant_id = _int(identity.get("variant_id") or identity.get("variantId"))
    actions: list[dict[str, Any]] = []

    highest = _text(identity.get("highest_severity") or identity.get("highestSeverity") or "none").casefold()
    if SEVERITY.get(highest, 0) >= SEVERITY["high"]:
        actions.append(_action("elevated-findings", "urgent" if highest == "critical" else "review", "Review elevated security findings", f"The selected variant's highest deterministic finding severity is {highest}.", "findings", variant_ids=[variant_id], category="security"))
    elif findings:
        actions.append(_action("review-findings", "follow-up", "Review the retained findings", f"{len(findings)} current finding(s) are available for exact evidence inspection.", "findings", variant_ids=[variant_id], category="security"))

    signals = divergence.get("signals") if isinstance(divergence.get("signals"), list) else []
    attention = [s for s in signals if isinstance(s, Mapping) and _text(s.get("level")) == "attention"]
    if attention:
        ids = [v for s in attention for v in (s.get("variantIds") or [])]
        labels = "; ".join(_text(s.get("label")) for s in attention[:3] if _text(s.get("label")))
        actions.append(_action("compare-siblings", "review", "Compare sibling source/build variants", labels or "The logical plugin has sibling coverage or same-version differences that merit exact-variant review.", "overview", variant_ids=ids, category="provenance"))

    missing = _int(context.get("withoutCurrentEvidenceVariantCount"))
    shown = _int(context.get("shownVariantCount") or context.get("activeVariantCount"))
    if missing > 0 and not any(a["actionId"] == "compare-siblings" for a in actions):
        ids = [_int(v.get("variant_id") or v.get("variantId")) for v in context.get("variants") or [] if isinstance(v, Mapping) and not bool(v.get("currentEvidence"))]
        actions.append(_action("unscanned-siblings", "review", "Inspect unscanned sibling variants", f"{missing} of {shown or missing} shown sibling variant(s) have no current Evidence-v2. A scanned sibling is not evidence for an unscanned one.", "overview", variant_ids=ids, category="coverage"))

    if coverage:
        if not bool(coverage.get("sourceCodeAvailable")):
            actions.append(_action("source-attribution", "follow-up", "Review source attribution coverage", "The current dossier is artifact-only; attributable source code is not available in the retained evidence.", "supply", variant_ids=[variant_id], category="provenance"))
        elif not bool(coverage.get("sourceToBinaryVerified")):
            actions.append(_action("source-binary", "follow-up", "Review source-to-artifact correspondence", "Source is attributed, but reproducible source-to-artifact equivalence is not verified.", "supply", variant_ids=[variant_id], category="provenance"))

    engines = secondary.get("engines") if isinstance(secondary.get("engines"), list) else []
    incomplete = [e for e in engines if isinstance(e, Mapping) and _text(e.get("status")).casefold() not in {"complete", "ready"}]
    if incomplete:
        names = ", ".join(_text(e.get("engine") or e.get("name") or "secondary engine") for e in incomplete[:4])
        actions.append(_action("secondary-coverage", "follow-up", "Check secondary security coverage", f"Incomplete or unavailable secondary analysis: {names}.", "malware", variant_ids=[variant_id], category="coverage"))

    if advisories:
        actions.append(_action("advisories", "review", "Review dependency advisories", f"{len(advisories)} frozen advisory match(es) are attached to this variant.", "supply", variant_ids=[variant_id], category="supply-chain"))

    history = d.get("versionHistory") if isinstance(d.get("versionHistory"), list) else []
    if len(history) > 1:
        actions.append(_action("version-history", "context", "Compare with retained previous versions", f"{len(history)} retained version/scan entries are available for security-semantic comparison.", "compare", variant_ids=[variant_id], category="history"))

    if _text(d.get("datasetError")):
        actions.append(_action("dataset-transport", "context", "Retry immutable dataset inspection", "The compact dossier is valid, but one immutable dataset manifest was temporarily unavailable.", "evidence", variant_ids=[variant_id], category="evidence"))

    # Stable order and bounded UI contract.
    actions.sort(key=lambda a: (PRIORITY.get(a["priority"], 99), a["actionId"]))
    actions = actions[:8]
    urgent = sum(1 for a in actions if a["priority"] in {"urgent", "review"})
    if urgent:
        state, headline = "review", f"{urgent} review item{'s' if urgent != 1 else ''} should be checked"
    elif actions:
        state, headline = "follow-up", "No urgent review cue; useful follow-ups remain"
    else:
        state, headline = "clear", "No immediate follow-up from the compact current dossier"

    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "findingAuthority": False,
        "queueMutationAuthority": False,
        "pluginId": _int(identity.get("plugin_id") or identity.get("pluginId") or context.get("pluginId")),
        "variantId": variant_id,
        "state": state,
        "headline": headline,
        "actionCount": len(actions),
        "reviewCount": urgent,
        "actions": actions,
        "limits": [
            "Actions are deterministic navigation guidance over already-loaded published/local evidence.",
            "This projection cannot create findings, change severity, enqueue scans, edit Definitions, or publish evidence.",
            "An absent action is not a safety verdict; exact evidence remains authoritative.",
        ],
    }
