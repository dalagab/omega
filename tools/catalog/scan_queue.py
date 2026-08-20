#!/usr/bin/env python3
"""Deterministic Sigmascope queue seed and mutable worker-state helpers.

The daily catalog/Definitions boundary publishes an immutable queue *seed* derived
from that day's canonical catalog plus the last-known-good Security Evidence v2
snapshot. Continuous workers never rewrite that seed. Their bounded operational
progress (attempts, retries and completion state) lives with Security Evidence v2.

Queue semantics are event-driven and typed. Artifact work, source work and frozen
advisory projection are independent. Elapsed time never creates work. A scanner/rule
change can invalidate artifact analysis; source attribution/revision changes can
invalidate source analysis; an OSV advisory revision change creates one global advisory
projection item instead of re-scanning plugin code. The production workflow has one
Sigmascope concurrency lock, so distributed lease machinery is intentionally absent.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
SECURITY_DIR = SCRIPT_DIR.parent / "security"
for item in (SCRIPT_DIR, SECURITY_DIR):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from security_evidence_v2 import iter_variant_entries  # noqa: E402
from artifact_source_model import BASIS_DEFAULT_BRANCH  # noqa: E402
from source_resolution import public_repository_url, source_candidate_records  # noqa: E402

SEED_SCHEMA = "omega.sigmascope.queue-seed.v2"
STATE_SCHEMA = "omega.sigmascope.queue-state.v2"
ATTEMPT_SCHEMA = "omega.sigmascope.queue-attempt.v2"
MAX_RECENT_ATTEMPTS = 16

REASON_PRIORITIES = {
    "manual": 1000,
    "baseline_scan": 950,
    "source_followup": 925,
    "new_variant": 900,
    "artifact_url_changed": 875,
    "artifact_version_changed": 870,
    "artifact_analysis_changed": 850,
    "advisory_changed": 800,
    "source_candidates_changed": 725,
    "source_candidate_observed": 710,
    "source_observation_changed": 700,
    "source_analysis_changed": 675,
    "source_unresolved": 650,
    "failed_retry": 600,
}

REASON_CONTRACTS = {
    "manual": {"workType": "artifact", "invalidates": ["artifact", "source-followup"], "event": "developer_recheck"},
    "baseline_scan": {"workType": "artifact", "invalidates": ["artifact", "source-followup"], "event": "catalog_identity_epoch_changed"},
    "new_variant": {"workType": "artifact", "invalidates": ["artifact", "source-followup"], "event": "new_active_variant"},
    "artifact_url_changed": {"workType": "artifact", "invalidates": ["artifact", "source-followup"], "event": "selected_artifact_url_changed"},
    "artifact_version_changed": {"workType": "artifact", "invalidates": ["artifact", "source-followup"], "event": "selected_artifact_version_changed"},
    "artifact_analysis_changed": {"workType": "artifact", "invalidates": ["artifact", "source-followup"], "event": "artifact_analysis_revision_changed"},
    "failed_retry": {"workType": "artifact", "invalidates": ["failed-work"], "event": "previous_artifact_attempt_incomplete"},
    "source_followup": {"workType": "source", "invalidates": ["source-attribution", "source-analysis"], "event": "artifact_analysis_completed"},
    "source_candidates_changed": {"workType": "source", "invalidates": ["source-attribution", "source-analysis"], "event": "catalog_source_candidates_changed"},
    "source_candidate_observed": {"workType": "source", "invalidates": ["source-attribution", "source-analysis"], "event": "previously_unresolved_source_now_observed"},
    "source_observation_changed": {"workType": "source", "invalidates": ["source-attribution", "source-analysis"], "event": "observed_default_branch_commit_changed"},
    "source_analysis_changed": {"workType": "source", "invalidates": ["source-analysis"], "event": "source_analysis_revision_changed"},
    "source_unresolved": {"workType": "source", "invalidates": ["source-attribution"], "event": "source_attribution_unresolved"},
    "advisory_changed": {"workType": "advisory", "invalidates": ["advisory-projection"], "event": "frozen_advisory_revision_changed"},
}


RETRY_DELAYS_MINUTES = (60, 240, 720, 1440, 2880, 5760)


def utc_now(now: dt.datetime | None = None) -> str:
    value = now or dt.datetime.now(dt.timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except ValueError:
        return None


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def _report_provenance(current: dict[str, Any]) -> dict[str, Any]:
    raw = current.get("report_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    report = raw if isinstance(raw, dict) else {}
    provenance = report.get("scanProvenance")
    return provenance if isinstance(provenance, dict) else {}


def _artifact_from_variant(variant: dict[str, Any]) -> tuple[str, str, str]:
    stable = str(variant.get("download_link_install") or "").strip()
    testing = str(variant.get("download_link_testing") or "").strip()
    if stable:
        return "stable", str(variant.get("assembly_version") or ""), stable
    if testing:
        return "testing", str(variant.get("testing_assembly_version") or variant.get("assembly_version") or ""), testing
    return "", "", ""


def _source_records(catalog_root: Path) -> dict[int, dict[str, Any]]:
    index = read_json(catalog_root / "sources" / "index.json", {}) or {}
    result: dict[int, dict[str, Any]] = {}
    for entry in index.get("sources") or []:
        if not isinstance(entry, dict):
            continue
        source_id = int(entry.get("sourceId") or 0)
        path = str(entry.get("path") or "")
        payload = read_json(catalog_root / path, {}) if path else {}
        source = payload.get("source") if isinstance(payload, dict) and isinstance(payload.get("source"), dict) else {}
        if source_id > 0:
            result[source_id] = source
    return result


def catalog_variants(catalog_root: Path) -> list[dict[str, Any]]:
    plugin_index = read_json(catalog_root / "plugins" / "index.json", {}) or {}
    sources = _source_records(catalog_root)
    result: list[dict[str, Any]] = []
    for entry in plugin_index.get("plugins") or []:
        if not isinstance(entry, dict) or not entry.get("active"):
            continue
        path = str(entry.get("path") or "")
        payload = read_json(catalog_root / path, {}) if path else {}
        plugin = payload.get("plugin") if isinstance(payload, dict) and isinstance(payload.get("plugin"), dict) else {}
        for grouped in payload.get("variants") or []:
            if not isinstance(grouped, dict):
                continue
            variant = grouped.get("variant") if isinstance(grouped.get("variant"), dict) else {}
            if int(variant.get("active") or 0) != 1:
                continue
            source_id = int(variant.get("source_id") or 0)
            source = sources.get(source_id, {})
            channel, version, artifact_url = _artifact_from_variant(variant)
            if not artifact_url:
                continue
            result.append({
                "variantId": int(variant.get("variant_id") or 0),
                "pluginId": int(variant.get("plugin_id") or plugin.get("plugin_id") or 0),
                "sourceId": source_id,
                "internalName": str(plugin.get("internal_name") or ""),
                "name": str(variant.get("name") or plugin.get("canonical_name") or plugin.get("internal_name") or ""),
                "sourceName": str(source.get("name") or ""),
                "assemblyVersion": version,
                "artifactChannel": channel,
                "artifactUrl": artifact_url,
                "repositoryUrl": str(variant.get("repo_url") or ""),
                "sourceRepositoryUrl": str(source.get("source_repo_url") or ""),
            })
    return sorted(result, key=lambda row: (str(row["internalName"]).casefold(), str(row["sourceName"]).casefold(), int(row["variantId"])))




def evidence_identity_epoch(evidence_root: Path) -> str:
    index = read_json(evidence_root / "index.json", {}) or {}
    revisions = index.get("revisions") if isinstance(index.get("revisions"), dict) else {}
    return str((revisions or {}).get("catalogIdentityEpoch") or index.get("catalogIdentityEpoch") or "")

def evidence_advisory_revision(evidence_root: Path) -> str:
    index = read_json(evidence_root / "index.json", {}) or {}
    revisions = index.get("revisions") if isinstance(index.get("revisions"), dict) else {}
    return str((revisions or {}).get("advisoryRevision") or "")


def source_observations(definitions_root: Path) -> dict[str, dict[str, Any]]:
    index = read_json(definitions_root / "index.json", {}) or {}
    descriptor = index.get("sourceObservations") if isinstance(index.get("sourceObservations"), dict) else {}
    path = definitions_root / str(descriptor.get("path") or "source-revisions.json")
    document = read_json(path, {}) or {}
    result: dict[str, dict[str, Any]] = {}
    for item in document.get("repositories") or []:
        if not isinstance(item, dict) or str(item.get("status") or "") != "observed":
            continue
        repository = public_repository_url(str(item.get("repository") or ""))
        commit = str(item.get("commitSha") or "").strip().lower()
        if repository and commit:
            result[repository.casefold()] = {
                "repository": repository,
                "commitSha": commit,
                "defaultRef": str(item.get("defaultRef") or ""),
            }
    return result


def _observed_source_for_variant(variant: dict[str, Any], observations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    records = source_candidate_records((
        ("repo-url", str(variant.get("repositoryUrl") or "")),
        ("catalog-source", str(variant.get("sourceRepositoryUrl") or "")),
        ("artifact", str(variant.get("artifactUrl") or "")),
    ))
    for record in records:
        repository = public_repository_url(str(record.get("repository") or ""))
        observed = observations.get(repository.casefold()) if repository else None
        if isinstance(observed, dict):
            return observed
    return {}


def evidence_current(evidence_root: Path) -> dict[int, dict[str, Any]]:
    if not (evidence_root / "index.json").is_file():
        return {}
    result: dict[int, dict[str, Any]] = {}
    for _entry, payload in iter_variant_entries(evidence_root):
        if not isinstance(payload, dict):
            continue
        variant_id = int(payload.get("variantId") or 0)
        current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
        if variant_id > 0:
            result[variant_id] = current
    return result


def _current_report(current: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(current, dict):
        return {}
    raw = current.get("report_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    return raw if isinstance(raw, dict) else {}


def _has_source_candidate(variant: dict[str, Any]) -> bool:
    return any(str(variant.get(key) or "").strip() for key in ("repositoryUrl", "sourceRepositoryUrl", "artifactUrl"))


def _source_candidate_repositories(variant: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for record in source_candidate_records((
        ("repo-url", str(variant.get("repositoryUrl") or "")),
        ("catalog-source", str(variant.get("sourceRepositoryUrl") or "")),
        ("artifact", str(variant.get("artifactUrl") or "")),
    )):
        repository = public_repository_url(str(record.get("repository") or ""))
        if repository and repository.casefold() not in {item.casefold() for item in result}:
            result.append(repository)
    return result


def source_due_reasons(
    variant: dict[str, Any],
    current: dict[str, Any] | None,
    *,
    source_analysis_revision: str,
    observations: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    if not current or str(current.get("status") or "") != "complete":
        return []
    if not str(current.get("artifact_sha256") or "").strip():
        return []
    if not _has_source_candidate(variant):
        return []
    report = _current_report(current)
    source = report.get("source") if isinstance(report.get("source"), dict) else {}
    attribution = source.get("attribution") if isinstance(source.get("attribution"), dict) else {}
    confidence = int(attribution.get("confidence") or 0)
    basis = {str(item or "").strip() for item in attribution.get("basis") or []}
    reasons: list[str] = []

    candidate_repositories = _source_candidate_repositories(variant)
    previous_candidates = [
        public_repository_url(str(item or ""))
        for item in (source.get("candidates") or [])
        if public_repository_url(str(item or ""))
    ]
    if previous_candidates and {item.casefold() for item in previous_candidates} != {item.casefold() for item in candidate_repositories}:
        reasons.append("source_candidates_changed")

    observed = _observed_source_for_variant(variant, observations or {})
    if confidence <= 0 or not bool(source.get("available")):
        if observed:
            reasons.append("source_candidate_observed")
        reasons.append("source_unresolved")

    if str(report.get("workType") or "") == "source":
        previous_analysis_revision = str(report.get("sourceAnalysisRevision") or "")
        if source_analysis_revision and previous_analysis_revision != source_analysis_revision:
            reasons.append("source_analysis_changed")
        # Only confidence-40/default-branch attribution tracks mutable HEAD. Version-
        # correlated/tag/pinned evidence remains tied to its immutable revision.
        if confidence == 40 and BASIS_DEFAULT_BRANCH in basis:
            current_repository = public_repository_url(str(source.get("repository") or ""))
            current_commit = str(source.get("commit") or "").strip().lower()
            observed_repository = public_repository_url(str(observed.get("repository") or ""))
            observed_commit = str(observed.get("commitSha") or "").strip().lower()
            if (
                current_repository and observed_repository
                and current_repository.casefold() == observed_repository.casefold()
                and current_commit and observed_commit and current_commit != observed_commit
            ):
                reasons.append("source_observation_changed")
    return list(dict.fromkeys(reasons))


def due_reasons(
    variant: dict[str, Any],
    current: dict[str, Any] | None,
    *,
    artifact_analysis_revision: str,
    manual: bool = False,
) -> list[str]:
    """Return artifact work reasons driven only by artifact identity/analysis events."""
    reasons: list[str] = []
    if manual:
        reasons.append("manual")
    if not current:
        reasons.append("new_variant")
        return reasons

    status = str(current.get("status") or "")
    if status != "complete":
        reasons.append("failed_retry")
    if str(current.get("artifact_url") or "") != str(variant.get("artifactUrl") or ""):
        reasons.append("artifact_url_changed")
    if str(current.get("assembly_version") or "") != str(variant.get("assemblyVersion") or ""):
        reasons.append("artifact_version_changed")

    report = _current_report(current)
    previous_analysis_revision = str(report.get("artifactAnalysisRevision") or "")
    if artifact_analysis_revision and previous_analysis_revision != artifact_analysis_revision:
        reasons.append("artifact_analysis_changed")

    return list(dict.fromkeys(reasons))


def _target_fingerprint(
    variant: dict[str, Any], current: dict[str, Any] | None, artifact_analysis_revision: str,
) -> str:
    semantic = {
        "workType": "artifact",
        "variantId": int(variant.get("variantId") or 0),
        "assemblyVersion": str(variant.get("assemblyVersion") or ""),
        "artifactUrl": str(variant.get("artifactUrl") or ""),
        "artifactAnalysisRevision": artifact_analysis_revision,
    }
    return f"artifact-target-v2-{digest(semantic)[:20]}"


def _queue_item(
    variant: dict[str, Any],
    current: dict[str, Any] | None,
    reasons: list[str],
    *,
    catalog_revision: str,
    catalog_identity_epoch: str,
    definitions_revision: str,
    scanner_revision: str,
    artifact_analysis_revision: str,
    rule_set_revision: str,
    generated_at: str,
) -> dict[str, Any]:
    ordered = sorted(reasons, key=lambda reason: (-REASON_PRIORITIES.get(reason, 0), reason))
    primary = ordered[0] if ordered else ""
    return {
        "queueKey": f"variant-{int(variant.get('variantId') or 0)}",
        "workType": "artifact",
        "targetFingerprint": _target_fingerprint(variant, current, artifact_analysis_revision),
        "variantId": int(variant.get("variantId") or 0),
        "pluginId": int(variant.get("pluginId") or 0),
        "sourceId": int(variant.get("sourceId") or 0),
        "internalName": str(variant.get("internalName") or ""),
        "name": str(variant.get("name") or ""),
        "sourceName": str(variant.get("sourceName") or ""),
        "assemblyVersion": str(variant.get("assemblyVersion") or ""),
        "artifactChannel": str(variant.get("artifactChannel") or ""),
        "artifactUrl": str(variant.get("artifactUrl") or ""),
        "repositoryUrl": str(variant.get("repositoryUrl") or ""),
        "sourceRepositoryUrl": str(variant.get("sourceRepositoryUrl") or ""),
        "catalogRevision": catalog_revision,
        "catalogIdentityEpoch": catalog_identity_epoch,
        "definitionsRevision": definitions_revision,
        "scannerRevision": scanner_revision,
        "artifactAnalysisRevision": artifact_analysis_revision,
        "ruleSetRevision": rule_set_revision,
        "reasons": ordered,
        "primaryReason": primary,
        "priority": max((REASON_PRIORITIES.get(reason, 0) for reason in ordered), default=0),
        "currentScanId": int((current or {}).get("scan_id") or 0),
        "currentScannedAtUtc": str((current or {}).get("scanned_at_utc") or ""),
        "currentArtifactSha256": str((current or {}).get("artifact_sha256") or "").strip().lower(),
        "enqueuedAtUtc": generated_at,
    }


def _source_target_fingerprint(
    variant: dict[str, Any], current: dict[str, Any] | None, source_analysis_revision: str, observed: dict[str, Any] | None = None,
) -> str:
    semantic = {
        "workType": "source",
        "variantId": int(variant.get("variantId") or 0),
        "artifactSha256": str((current or {}).get("artifact_sha256") or "").strip().lower(),
        "repositoryUrl": str(variant.get("repositoryUrl") or ""),
        "sourceRepositoryUrl": str(variant.get("sourceRepositoryUrl") or ""),
        "sourceAnalysisRevision": source_analysis_revision,
        "observedSourceCommit": str((observed or {}).get("commitSha") or "").lower(),
    }
    return f"source-target-v2-{digest(semantic)[:20]}"


def _source_queue_item(
    variant: dict[str, Any],
    current: dict[str, Any],
    reasons: list[str],
    *,
    catalog_revision: str,
    catalog_identity_epoch: str,
    definitions_revision: str,
    scanner_revision: str,
    source_analysis_revision: str,
    rule_set_revision: str,
    generated_at: str,
    observations: dict[str, dict[str, Any]] | None = None,
    priority_override: int = 0,
) -> dict[str, Any]:
    ordered = sorted(reasons, key=lambda reason: (-REASON_PRIORITIES.get(reason, 0), reason))
    primary = ordered[0] if ordered else ""
    priority = max((REASON_PRIORITIES.get(reason, 0) for reason in ordered), default=0)
    if priority_override:
        priority = max(priority, int(priority_override))
    observed = _observed_source_for_variant(variant, observations or {})
    return {
        "queueKey": f"source-variant-{int(variant.get('variantId') or 0)}",
        "workType": "source",
        "targetFingerprint": _source_target_fingerprint(variant, current, source_analysis_revision, observed),
        "variantId": int(variant.get("variantId") or 0),
        "pluginId": int(variant.get("pluginId") or 0),
        "sourceId": int(variant.get("sourceId") or 0),
        "internalName": str(variant.get("internalName") or ""),
        "name": str(variant.get("name") or ""),
        "sourceName": str(variant.get("sourceName") or ""),
        "assemblyVersion": str(variant.get("assemblyVersion") or ""),
        "artifactChannel": str(variant.get("artifactChannel") or ""),
        "artifactUrl": str(variant.get("artifactUrl") or ""),
        "repositoryUrl": str(variant.get("repositoryUrl") or ""),
        "sourceRepositoryUrl": str(variant.get("sourceRepositoryUrl") or ""),
        "catalogRevision": catalog_revision,
        "catalogIdentityEpoch": catalog_identity_epoch,
        "definitionsRevision": definitions_revision,
        "scannerRevision": scanner_revision,
        "sourceAnalysisRevision": source_analysis_revision,
        "ruleSetRevision": rule_set_revision,
        "observedSourceRepository": str(observed.get("repository") or ""),
        "observedSourceCommit": str(observed.get("commitSha") or ""),
        "observedSourceRef": str(observed.get("defaultRef") or ""),
        "reasons": ordered,
        "primaryReason": primary,
        "priority": priority,
        "currentScanId": int((current or {}).get("scan_id") or 0),
        "currentScannedAtUtc": str((current or {}).get("scanned_at_utc") or ""),
        "currentArtifactSha256": str((current or {}).get("artifact_sha256") or "").strip().lower(),
        "enqueuedAtUtc": generated_at,
    }


def _advisory_queue_item(
    *,
    catalog_revision: str,
    catalog_identity_epoch: str,
    definitions_revision: str,
    scanner_revision: str,
    scanner_bundle_sha256: str,
    rule_set_revision: str,
    advisory_revision: str,
    previous_advisory_revision: str,
    generated_at: str,
) -> dict[str, Any]:
    semantic = {
        "workType": "advisory",
        "catalogRevision": catalog_revision,
        "catalogIdentityEpoch": catalog_identity_epoch,
        "advisoryRevision": advisory_revision,
    }
    return {
        "queueKey": "advisory-projection",
        "workType": "advisory",
        "targetFingerprint": f"advisory-target-v1-{digest(semantic)[:20]}",
        "variantId": 0,
        "pluginId": 0,
        "sourceId": 0,
        "internalName": "",
        "name": "Frozen advisory projection",
        "sourceName": "",
        "assemblyVersion": "",
        "artifactChannel": "",
        "artifactUrl": "",
        "repositoryUrl": "",
        "sourceRepositoryUrl": "",
        "catalogRevision": catalog_revision,
        "catalogIdentityEpoch": catalog_identity_epoch,
        "definitionsRevision": definitions_revision,
        "scannerRevision": scanner_revision,
        "scannerBundleSha256": scanner_bundle_sha256,
        "ruleSetRevision": rule_set_revision,
        "advisoryRevision": advisory_revision,
        "previousAdvisoryRevision": previous_advisory_revision,
        "reasons": ["advisory_changed"],
        "primaryReason": "advisory_changed",
        "priority": REASON_PRIORITIES["advisory_changed"],
        "currentScanId": 0,
        "currentScannedAtUtc": "",
        "currentArtifactSha256": "",
        "enqueuedAtUtc": generated_at,
    }


def enqueue_source_followup(
    state: dict[str, Any],
    artifact_item: dict[str, Any] | None,
    current: dict[str, Any] | None,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any] | None:
    if not isinstance(artifact_item, dict) or str(artifact_item.get("workType") or "") != "artifact":
        return None
    if not isinstance(current, dict) or str(current.get("status") or "") != "complete":
        return None
    variant = {
        "variantId": int(artifact_item.get("variantId") or 0),
        "pluginId": int(artifact_item.get("pluginId") or 0),
        "sourceId": int(artifact_item.get("sourceId") or 0),
        "internalName": str(artifact_item.get("internalName") or ""),
        "name": str(artifact_item.get("name") or ""),
        "sourceName": str(artifact_item.get("sourceName") or ""),
        "assemblyVersion": str(artifact_item.get("assemblyVersion") or ""),
        "artifactChannel": str(artifact_item.get("artifactChannel") or ""),
        "artifactUrl": str(artifact_item.get("artifactUrl") or ""),
        "repositoryUrl": str(artifact_item.get("repositoryUrl") or ""),
        "sourceRepositoryUrl": str(artifact_item.get("sourceRepositoryUrl") or ""),
    }
    if not _has_source_candidate(variant):
        return None
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    item = _source_queue_item(
        variant, current, ["source_followup"],
        catalog_revision=str(state.get("catalogRevision") or artifact_item.get("catalogRevision") or ""),
        catalog_identity_epoch=str(state.get("catalogIdentityEpoch") or artifact_item.get("catalogIdentityEpoch") or ""),
        definitions_revision=str(state.get("definitionsRevision") or artifact_item.get("definitionsRevision") or ""),
        scanner_revision=str(state.get("scannerRevision") or artifact_item.get("scannerRevision") or ""),
        source_analysis_revision=str(state.get("sourceAnalysisRevision") or artifact_item.get("sourceAnalysisRevision") or ""),
        rule_set_revision=str(state.get("ruleSetRevision") or artifact_item.get("ruleSetRevision") or ""),
        generated_at=utc_now(now_dt),
        priority_override=int(artifact_item.get("priority") or 0) + 1,
    )
    existing = (state.get("items") or {}).get(item["queueKey"])
    if isinstance(existing, dict) and str(existing.get("targetFingerprint") or "") == item["targetFingerprint"] and str(existing.get("state") or "") != "complete":
        return existing
    item.update({
        "dynamic": True,
        "attemptCount": 0, "recentAttempts": [], "state": "pending", "nextEligibleAtUtc": "",
        "lastAttemptStatus": "", "lastError": "",
    })
    state.setdefault("items", {})[item["queueKey"]] = item
    state["updatedAtUtc"] = utc_now(now_dt)
    return item


def build_seed(
    *,
    catalog_root: Path,
    definitions_root: Path,
    evidence_root: Path,
    output: Path,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    generated = utc_now(now_dt)
    catalog_index = read_json(catalog_root / "index.json", {}) or {}
    definitions_index = read_json(definitions_root / "index.json", {}) or {}
    catalog_revision = str(catalog_index.get("catalogRevision") or "")
    catalog_identity_epoch = str(catalog_index.get("identityEpoch") or "")
    definitions_revision = str(definitions_index.get("definitionsRevision") or "")
    rule_set_revision = str(definitions_index.get("ruleSetRevision") or "")
    scanner_revision = str(definitions_index.get("scannerRevision") or "")
    artifact_analysis_revision = str(definitions_index.get("artifactAnalysisRevision") or "")
    source_analysis_revision = str(definitions_index.get("sourceAnalysisRevision") or "")
    scanner_bundle_sha256 = str((definitions_index.get("scannerBundle") or {}).get("sha256") or "")
    advisory_revision = str(definitions_index.get("advisoryRevision") or "")
    previous_evidence_identity_epoch = evidence_identity_epoch(evidence_root)
    previous_advisory_revision = evidence_advisory_revision(evidence_root)
    observations = source_observations(definitions_root)
    baseline_security_rebuild = bool(catalog_identity_epoch and previous_evidence_identity_epoch != catalog_identity_epoch)
    current = {} if baseline_security_rebuild else evidence_current(evidence_root)
    items: list[dict[str, Any]] = []
    counts = {reason: 0 for reason in REASON_PRIORITIES}
    for variant in catalog_variants(catalog_root):
        current_row = current.get(int(variant["variantId"]))
        reasons = ["baseline_scan"] if baseline_security_rebuild else due_reasons(
            variant,
            current_row,
            artifact_analysis_revision=artifact_analysis_revision,
        )
        if reasons:
            item = _queue_item(
                variant,
                current_row,
                reasons,
                catalog_revision=catalog_revision,
                catalog_identity_epoch=catalog_identity_epoch,
                definitions_revision=definitions_revision,
                scanner_revision=scanner_revision,
                artifact_analysis_revision=artifact_analysis_revision,
                rule_set_revision=rule_set_revision,
                generated_at=generated,
            )
            items.append(item)
            for reason in reasons:
                counts[reason] = counts.get(reason, 0) + 1
        if not baseline_security_rebuild and current_row:
            source_reasons = source_due_reasons(
                variant, current_row, source_analysis_revision=source_analysis_revision, observations=observations,
            )
            if source_reasons:
                source_item = _source_queue_item(
                    variant, current_row, source_reasons,
                    catalog_revision=catalog_revision, catalog_identity_epoch=catalog_identity_epoch,
                    definitions_revision=definitions_revision, scanner_revision=scanner_revision,
                    source_analysis_revision=source_analysis_revision, rule_set_revision=rule_set_revision, generated_at=generated,
                    observations=observations,
                )
                items.append(source_item)
                for reason in source_reasons:
                    counts[reason] = counts.get(reason, 0) + 1
    if (
        not baseline_security_rebuild
        and advisory_revision
        and advisory_revision != previous_advisory_revision
    ):
        items.append(_advisory_queue_item(
            catalog_revision=catalog_revision,
            catalog_identity_epoch=catalog_identity_epoch,
            definitions_revision=definitions_revision,
            scanner_revision=scanner_revision,
            scanner_bundle_sha256=scanner_bundle_sha256,
            rule_set_revision=rule_set_revision,
            advisory_revision=advisory_revision,
            previous_advisory_revision=previous_advisory_revision,
            generated_at=generated,
        ))
        counts["advisory_changed"] = counts.get("advisory_changed", 0) + 1
    items.sort(key=lambda item: (-int(item["priority"]), str(item["currentScannedAtUtc"]), str(item["internalName"]).casefold(), str(item["sourceName"]).casefold(), int(item["variantId"]), str(item.get("workType") or "")))
    semantic = {
        "schema": SEED_SCHEMA,
        "catalogRevision": catalog_revision,
        "catalogIdentityEpoch": catalog_identity_epoch,
        "definitionsRevision": definitions_revision,
        "scannerRevision": scanner_revision,
        "scannerBundleSha256": scanner_bundle_sha256,
        "ruleSetRevision": rule_set_revision,
        "advisoryRevision": advisory_revision,
        "baselineSecurityRebuild": baseline_security_rebuild,
        "reasonContracts": REASON_CONTRACTS,
        "items": [
            {
                key: item[key]
                for key in ("queueKey", "workType", "targetFingerprint", "variantId", "assemblyVersion", "artifactUrl", "artifactAnalysisRevision", "sourceAnalysisRevision", "ruleSetRevision", "observedSourceCommit", "reasons", "priority")
                if key in item
            }
            for item in items
        ],
    }
    seed = {
        "schema": SEED_SCHEMA,
        "queueSeedRevision": f"queue-seed-v2-{digest(semantic)[:16]}",
        "generatedAtUtc": generated,
        "catalogRevision": catalog_revision,
        "catalogIdentityEpoch": catalog_identity_epoch,
        "definitionsRevision": definitions_revision,
        "scannerRevision": scanner_revision,
        "scannerBundleSha256": scanner_bundle_sha256,
        "artifactAnalysisRevision": artifact_analysis_revision,
        "sourceAnalysisRevision": source_analysis_revision,
        "sourceObservationRevision": str(definitions_index.get("sourceObservationRevision") or ""),
        "baselineSecurityRebuild": baseline_security_rebuild,
        "previousEvidenceIdentityEpoch": previous_evidence_identity_epoch,
        "ruleSetRevision": rule_set_revision,
        "advisoryRevision": advisory_revision,
        "previousAdvisoryRevision": previous_advisory_revision,
        "reasonContracts": REASON_CONTRACTS,
        "counts": {**counts, "queued": len(items)},
        "items": items,
    }
    write_json(output, seed)
    return seed


def load_state(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"schema": STATE_SCHEMA, "items": {}, "recentCompleted": []}
    doc = read_json(path, {}) or {}
    if doc.get("schema") != STATE_SCHEMA or not isinstance(doc.get("items"), dict):
        return {"schema": STATE_SCHEMA, "items": {}, "recentCompleted": []}
    return doc


def _retry_at(now: dt.datetime, attempt_count: int) -> str:
    index = min(max(0, attempt_count - 1), len(RETRY_DELAYS_MINUTES) - 1)
    return utc_now(now + dt.timedelta(minutes=RETRY_DELAYS_MINUTES[index]))


def sync_state(seed: dict[str, Any], previous: dict[str, Any] | None, *, now: dt.datetime | None = None) -> dict[str, Any]:
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    previous = previous if isinstance(previous, dict) else {}
    previous_items = previous.get("items") if isinstance(previous.get("items"), dict) else {}
    items: dict[str, Any] = {}
    for seeded in seed.get("items") or []:
        if not isinstance(seeded, dict):
            continue
        key = str(seeded.get("queueKey") or "")
        if not key:
            continue
        old = previous_items.get(key) if isinstance(previous_items.get(key), dict) else {}
        same_target = str(old.get("targetFingerprint") or "") == str(seeded.get("targetFingerprint") or "")
        state = {
            **seeded,
            "state": "pending",
            "attemptCount": int(old.get("attemptCount") or 0) if same_target else 0,
            "nextEligibleAtUtc": str(old.get("nextEligibleAtUtc") or "") if same_target else "",
            "lastAttemptStatus": str(old.get("lastAttemptStatus") or "") if same_target else "",
            "lastError": str(old.get("lastError") or "")[:4096] if same_target else "",
            "recentAttempts": list(old.get("recentAttempts") or [])[-MAX_RECENT_ATTEMPTS:] if same_target else [],
        }
        if same_target and str(old.get("state") or "") == "complete":
            state["state"] = "complete"
        elif same_target and state["nextEligibleAtUtc"]:
            next_at = parse_utc(state["nextEligibleAtUtc"])
            if next_at is not None and now_dt < next_at:
                state["state"] = "retry"
        items[key] = state
    same_seed = str(previous.get("queueSeedRevision") or "") == str(seed.get("queueSeedRevision") or "")
    if same_seed:
        for key, old in previous_items.items():
            if key in items or not isinstance(old, dict) or not bool(old.get("dynamic")):
                continue
            if str(old.get("catalogRevision") or "") != str(seed.get("catalogRevision") or ""):
                continue
            if str(old.get("definitionsRevision") or "") != str(seed.get("definitionsRevision") or ""):
                continue
            items[str(key)] = dict(old)
    return {
        "schema": STATE_SCHEMA,
        "queueSeedRevision": str(seed.get("queueSeedRevision") or ""),
        "catalogRevision": str(seed.get("catalogRevision") or ""),
        "catalogIdentityEpoch": str(seed.get("catalogIdentityEpoch") or ""),
        "baselineSecurityRebuild": bool(seed.get("baselineSecurityRebuild")),
        "definitionsRevision": str(seed.get("definitionsRevision") or ""),
        "scannerRevision": str(seed.get("scannerRevision") or ""),
        "scannerBundleSha256": str(seed.get("scannerBundleSha256") or ""),
        "artifactAnalysisRevision": str(seed.get("artifactAnalysisRevision") or ""),
        "sourceAnalysisRevision": str(seed.get("sourceAnalysisRevision") or ""),
        "sourceObservationRevision": str(seed.get("sourceObservationRevision") or ""),
        "ruleSetRevision": str(seed.get("ruleSetRevision") or ""),
        "advisoryRevision": str(seed.get("advisoryRevision") or ""),
        "reasonContracts": dict(seed.get("reasonContracts") or REASON_CONTRACTS),
        "updatedAtUtc": str(previous.get("updatedAtUtc") or "") if same_seed else utc_now(now_dt),
        "items": items,
        "recentCompleted": list(previous.get("recentCompleted") or [])[-64:],
    }


def add_manual_items_from_database(
    state: dict[str, Any],
    db: sqlite3.Connection,
    internal_names: Iterable[str],
    *,
    now: dt.datetime | None = None,
) -> None:
    names = {str(name or "").strip().casefold() for name in internal_names if str(name or "").strip()}
    if not names:
        return
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    columns = {str(row[1]).casefold() for row in db.execute("PRAGMA table_info(plugin_variants)")}
    update_projection = "v.download_link_update" if "download_link_update" in columns else "'' AS download_link_update"
    rows = db.execute(f"""
        SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.assembly_version,v.testing_assembly_version,
               v.download_link_install,{update_projection},v.download_link_testing,v.repo_url,
               s.name AS source_name,s.source_repo_url,sc.*
          FROM plugin_variants v
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
          LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
         WHERE v.active=1 AND p.active=1
         ORDER BY p.internal_name COLLATE NOCASE,s.name COLLATE NOCASE,v.variant_id
    """).fetchall()
    for row in rows:
        if str(row["internal_name"] or "").casefold() not in names:
            continue
        stable = str(row["download_link_install"] or "").strip()
        testing = str(row["download_link_testing"] or "").strip()
        if not stable and not testing:
            continue
        variant = {
            "variantId": int(row["variant_id"]),
            "pluginId": int(row["plugin_id"]),
            "sourceId": int(row["source_id"]),
            "internalName": str(row["internal_name"] or ""),
            "name": str(row["name"] or ""),
            "sourceName": str(row["source_name"] or ""),
            "assemblyVersion": str(row["assembly_version"] or "") if stable else str(row["testing_assembly_version"] or row["assembly_version"] or ""),
            "artifactChannel": "stable" if stable else "testing",
            "artifactUrl": stable or testing,
            "repositoryUrl": str(row["repo_url"] or ""),
            "sourceRepositoryUrl": str(row["source_repo_url"] or ""),
        }
        current = dict(row) if row["scan_id"] is not None else None
        reasons = due_reasons(
            variant,
            current,
            artifact_analysis_revision=str(state.get("artifactAnalysisRevision") or ""),
            manual=True,
        )
        item = _queue_item(
            variant,
            current,
            reasons,
            catalog_revision=str(state.get("catalogRevision") or ""),
            catalog_identity_epoch=str(state.get("catalogIdentityEpoch") or ""),
            definitions_revision=str(state.get("definitionsRevision") or ""),
            scanner_revision=str(state.get("scannerRevision") or ""),
            artifact_analysis_revision=str(state.get("artifactAnalysisRevision") or ""),
            rule_set_revision=str(state.get("ruleSetRevision") or ""),
            generated_at=utc_now(now_dt),
        )
        old = (state.get("items") or {}).get(item["queueKey"])
        if isinstance(old, dict) and str(old.get("targetFingerprint") or "") == item["targetFingerprint"]:
            item["attemptCount"] = int(old.get("attemptCount") or 0)
            item["recentAttempts"] = list(old.get("recentAttempts") or [])[-MAX_RECENT_ATTEMPTS:]
        else:
            item["attemptCount"] = 0
            item["recentAttempts"] = []
        item["state"] = "pending"
        item["nextEligibleAtUtc"] = ""
        item["lastAttemptStatus"] = ""
        item["lastError"] = ""
        state.setdefault("items", {})[item["queueKey"]] = item


def select_next(state: dict[str, Any], *, now: dt.datetime | None = None) -> dict[str, Any] | None:
    """Select one eligible item under the single Sigmascope workflow lock.

    There is deliberately no lease/expiry state. If a runner dies before publication,
    its mutation is never committed to Security Evidence v2 and the next worker simply
    selects the same previously-published item again.
    """
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    eligible: list[dict[str, Any]] = []
    for item in (state.get("items") or {}).values():
        if not isinstance(item, dict) or str(item.get("state") or "") == "complete":
            continue
        next_at = parse_utc(str(item.get("nextEligibleAtUtc") or ""))
        if next_at is not None and now_dt < next_at:
            item["state"] = "retry"
            continue
        if str(item.get("state") or "") == "attempted":
            # An attempted state should not normally survive atomic publication, but
            # treating it as eligible is the safest recovery behavior.
            item["state"] = "pending"
        eligible.append(item)
    if not eligible:
        return None

    eligible.sort(key=lambda item: (
        -int(item.get("priority") or 0),
        str(item.get("currentScannedAtUtc") or ""),
        str(item.get("internalName") or "").casefold(),
        str(item.get("sourceName") or "").casefold(),
        int(item.get("variantId") or 0),
        str(item.get("workType") or ""),
    ))
    item = eligible[0]
    attempt_count = int(item.get("attemptCount") or 0) + 1
    attempt_id = f"attempt-v2-{digest([item.get('targetFingerprint'), attempt_count, utc_now(now_dt)])[:16]}"
    attempt = {
        "schema": ATTEMPT_SCHEMA,
        "attemptId": attempt_id,
        "attemptNumber": attempt_count,
        "selectedAtUtc": utc_now(now_dt),
        "status": "attempted",
    }
    attempts = list(item.get("recentAttempts") or [])
    attempts.append(attempt)
    item["recentAttempts"] = attempts[-MAX_RECENT_ATTEMPTS:]
    item["attemptCount"] = attempt_count
    item["state"] = "attempted"
    item["nextEligibleAtUtc"] = ""
    state["updatedAtUtc"] = utc_now(now_dt)
    return dict(item)


def finish_attempt(
    state: dict[str, Any],
    selected: dict[str, Any] | None,
    *,
    status: str,
    error: str = "",
    artifact_sha256: str = "",
    scan_id: int = 0,
    now: dt.datetime | None = None,
) -> None:
    if not selected:
        return
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    key = str(selected.get("queueKey") or "")
    item = (state.get("items") or {}).get(key)
    if not isinstance(item, dict):
        return

    attempts = list(item.get("recentAttempts") or [])
    attempt_id = ""
    if attempts and isinstance(attempts[-1], dict):
        attempt_id = str(attempts[-1].get("attemptId") or "")
    for attempt in reversed(attempts):
        if isinstance(attempt, dict) and str(attempt.get("attemptId") or "") == attempt_id:
            attempt["status"] = status
            attempt["completedAtUtc"] = utc_now(now_dt)
            attempt["error"] = str(error or "")[:4096]
            attempt["artifactSha256"] = str(artifact_sha256 or "").strip().lower()
            attempt["scanId"] = int(scan_id or 0)
            break

    item["recentAttempts"] = attempts[-MAX_RECENT_ATTEMPTS:]
    item["lastAttemptStatus"] = status
    item["lastError"] = str(error or "")[:4096]
    if status == "complete":
        item["state"] = "complete"
        item["completedAtUtc"] = utc_now(now_dt)
        item["nextEligibleAtUtc"] = ""
        completed = list(state.get("recentCompleted") or [])
        completed.append({
            "variantId": int(item.get("variantId") or 0),
            "workType": str(item.get("workType") or "artifact"),
            "internalName": str(item.get("internalName") or ""),
            "targetFingerprint": str(item.get("targetFingerprint") or ""),
            "primaryReason": str(item.get("primaryReason") or ""),
            "completedAtUtc": utc_now(now_dt),
            "attemptCount": int(item.get("attemptCount") or 0),
        })
        state["recentCompleted"] = completed[-64:]
    else:
        item["state"] = "retry"
        item["nextEligibleAtUtc"] = _retry_at(now_dt, int(item.get("attemptCount") or 1))
    state["updatedAtUtc"] = utc_now(now_dt)


def state_summary(state: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    due_by_reason: dict[str, int] = {}
    for item in (state.get("items") or {}).values():
        if not isinstance(item, dict):
            continue
        status = str(item.get("state") or "pending")
        counts[status] = counts.get(status, 0) + 1
        if status != "complete":
            reason = str(item.get("primaryReason") or "")
            due_by_reason[reason] = due_by_reason.get(reason, 0) + 1
    return {
        "schema": "omega.sigmascope.queue-summary.v1",
        "queueSeedRevision": str(state.get("queueSeedRevision") or ""),
        "catalogRevision": str(state.get("catalogRevision") or ""),
        "catalogIdentityEpoch": str(state.get("catalogIdentityEpoch") or ""),
        "baselineSecurityRebuild": bool(state.get("baselineSecurityRebuild")),
        "definitionsRevision": str(state.get("definitionsRevision") or ""),
        "scannerRevision": str(state.get("scannerRevision") or ""),
        "scannerBundleSha256": str(state.get("scannerBundleSha256") or ""),
        "artifactAnalysisRevision": str(state.get("artifactAnalysisRevision") or ""),
        "sourceAnalysisRevision": str(state.get("sourceAnalysisRevision") or ""),
        "sourceObservationRevision": str(state.get("sourceObservationRevision") or ""),
        "ruleSetRevision": str(state.get("ruleSetRevision") or ""),
        "advisoryRevision": str(state.get("advisoryRevision") or ""),
        "states": counts,
        "pendingByReason": due_by_reason,
        "reasonContracts": dict(state.get("reasonContracts") or REASON_CONTRACTS),
        "total": sum(counts.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-seed")
    build.add_argument("--catalog-root", required=True, type=Path)
    build.add_argument("--definitions-root", required=True, type=Path)
    build.add_argument("--evidence-root", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "build-seed":
        result = build_seed(
            catalog_root=args.catalog_root,
            definitions_root=args.definitions_root,
            evidence_root=args.evidence_root,
            output=args.output,
        )
        print(json.dumps({"queueSeedRevision": result["queueSeedRevision"], "queued": result["counts"]["queued"]}, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
