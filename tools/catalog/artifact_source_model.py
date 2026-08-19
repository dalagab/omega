"""Shared artifact/source identity and attribution contracts for Omega.

This module deliberately contains no network or scanner behavior.  It defines the
stable machine-facing vocabulary used by the catalog, Sigmascope and later Deltascope
work so distributed artifacts remain ground truth while source code is represented as
separate, confidence-bearing evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

ATTRIBUTION_SCHEMA = "omega.artifact-source-attribution.v1"
IDENTITY_ALIAS_SCHEMA = "omega.plugin-identity-alias.v1"

CONFIDENCE_NONE = 0
CONFIDENCE_CURRENT_SOURCE = 40
CONFIDENCE_VERSION_CORRELATED = 70
CONFIDENCE_PINNED_COMMIT = 95
CONFIDENCE_REPRODUCIBLE = 100  # Reserved until source-to-artifact reproduction exists.
ALLOWED_CONFIDENCE = {0, 40, 70, 95, 100}

BASIS_DEFAULT_BRANCH = "default_branch"
BASIS_REPOSITORY_METADATA = "repository_metadata"
BASIS_ARTIFACT_ORIGIN = "artifact_origin"
BASIS_MANIFEST_REPOSITORY = "manifest_repository"
BASIS_IDENTITY_MATCH = "identity_match"
BASIS_VERSION_MATCH = "version_match"
BASIS_RELEASE_OR_TAG = "release_or_tag"
BASIS_PINNED_COMMIT = "pinned_commit"
BASIS_REPRODUCIBLE_BUILD = "reproducible_build"

COVERAGE_LABELS = {
    0: "Unresolved",
    40: "Current source found",
    70: "Version-correlated source",
    95: "Commit-pinned source",
    100: "Reproducibly verified",
}


def casefold_key(value: Any) -> str:
    return str(value or "").strip().casefold()


def stable_key(prefix: str, *parts: Any, length: int = 24) -> str:
    payload = "\n".join(casefold_key(part) for part in parts)
    return f"{prefix}-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


def repository_key(canonical_url: str) -> str:
    return stable_key("repo", canonical_url)


def source_revision_key(canonical_url: str, commit_sha: str) -> str:
    return stable_key("rev", canonical_url, commit_sha)


def attribution_key(variant_id: int, artifact_sha256: str, source_revision: str, root_path: str) -> str:
    return stable_key("attr", variant_id, artifact_sha256, source_revision, root_path)


def normalize_basis(values: Iterable[Any]) -> list[str]:
    allowed = {
        BASIS_DEFAULT_BRANCH,
        BASIS_REPOSITORY_METADATA,
        BASIS_ARTIFACT_ORIGIN,
        BASIS_MANIFEST_REPOSITORY,
        BASIS_IDENTITY_MATCH,
        BASIS_VERSION_MATCH,
        BASIS_RELEASE_OR_TAG,
        BASIS_PINNED_COMMIT,
        BASIS_REPRODUCIBLE_BUILD,
    }
    result: list[str] = []
    for value in values:
        code = str(value or "").strip().casefold().replace("-", "_")
        if code in allowed and code not in result:
            result.append(code)
    return result


def confidence_label(score: int) -> str:
    return COVERAGE_LABELS.get(int(score), "Unknown")


def _looks_like_commit(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", str(value or "").strip()))


def attribution_from_source_result(source: dict[str, Any]) -> dict[str, Any]:
    """Project existing source-resolution evidence onto the numeric attribution ladder.

    The score is an ordinal policy level, not a probability.  A resolved immutable
    commit alone does not earn 95: that level requires the *input evidence* to pin the
    artifact to that commit.  100 remains reserved for future reproducible proof.
    """
    if not bool(source.get("available")):
        return {
            "schema": ATTRIBUTION_SCHEMA,
            "confidence": CONFIDENCE_NONE,
            "coverageLabel": confidence_label(CONFIDENCE_NONE),
            "basis": [],
        }

    provenance = source.get("provenance") if isinstance(source.get("provenance"), dict) else {}
    basis: list[str] = []
    if bool(provenance.get("identityMatched")):
        basis.append(BASIS_IDENTITY_MATCH)
    if bool(provenance.get("versionMatched")):
        basis.append(BASIS_VERSION_MATCH)
    if bool(provenance.get("manifestRepositoryMatched")) or bool(provenance.get("repoUrlMatched")):
        basis.append(BASIS_MANIFEST_REPOSITORY)
    if bool(provenance.get("artifactOriginMatched")):
        basis.append(BASIS_ARTIFACT_ORIGIN)

    selected_kind = str(provenance.get("selectedRefKind") or "").strip().casefold()
    selected_ref = str(provenance.get("selectedRef") or source.get("branch") or "").strip()
    if selected_kind in {"default-branch", "git-head"}:
        basis.append(BASIS_DEFAULT_BRANCH)
    elif selected_ref:
        basis.append(BASIS_RELEASE_OR_TAG)

    explicitly_pinned = bool(provenance.get("artifactPinnedCommit")) and _looks_like_commit(
        str(provenance.get("artifactPinnedCommit") or "")
    )
    reproducible = bool(provenance.get("reproducibleSourceToArtifact"))

    if reproducible:
        basis.extend((BASIS_PINNED_COMMIT, BASIS_REPRODUCIBLE_BUILD))
        score = CONFIDENCE_REPRODUCIBLE
    elif explicitly_pinned:
        basis.append(BASIS_PINNED_COMMIT)
        score = CONFIDENCE_PINNED_COMMIT
    elif bool(provenance.get("versionMatched")):
        score = CONFIDENCE_VERSION_CORRELATED
    else:
        # Reachable/default-branch source with matched identity is useful evidence and
        # is a normal fallback, not an error/degraded exception.
        score = CONFIDENCE_CURRENT_SOURCE

    basis = normalize_basis(basis)
    return {
        "schema": ATTRIBUTION_SCHEMA,
        "confidence": score,
        "coverageLabel": confidence_label(score),
        "basis": basis,
    }


def basis_json(values: Iterable[Any]) -> str:
    return json.dumps(normalize_basis(values), ensure_ascii=False, separators=(",", ":"))


def resolve_identity_candidates(rows: Iterable[dict[str, Any]], value: Any) -> dict[str, Any]:
    """Resolve a normalized alias without ever guessing through collisions."""
    key = casefold_key(value)
    plugin_ids = sorted({
        int(row.get("plugin_id") or row.get("pluginId") or 0)
        for row in rows
        if casefold_key(row.get("normalized_value") or row.get("normalizedValue") or row.get("alias_value") or row.get("aliasValue")) == key
        and int(row.get("plugin_id") or row.get("pluginId") or 0) > 0
    })
    status = "unresolved" if not plugin_ids else ("resolved" if len(plugin_ids) == 1 else "ambiguous")
    return {"status": status, "pluginIds": plugin_ids, "normalizedValue": key}
