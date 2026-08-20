"""Terminal/superseded Security Evidence v2 variant snapshot helpers.

Current catalog variants remain in ``variants/`` and the plugins index's
``currentVariants`` collection.  Historical state is immutable evidence rather than
queue input:

* ``terminalVariants`` records variants that disappeared or became inactive;
* ``historicalSnapshots`` records a previous current artifact/source projection that
  was superseded by a later successful analysis for the same catalog variant ID.

The scanner queue intentionally consumes only ``currentVariants``.  These snapshots
exist for investigation/comparison and to retain the analyses they reference.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

LIFECYCLE_SCHEMA = "omega.security-evidence.variant-lifecycle.v1"
ACTIVE = "active"
RETIRED = "retired"
SUPERSEDED = "superseded"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def artifact_sha(payload: dict[str, Any]) -> str:
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    return str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()


def scan_id(payload: dict[str, Any]) -> int:
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    return int(current.get("scan_id") or 0)


def analysis_path(payload: dict[str, Any]) -> str:
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
    return str(analysis.get("path") or "")


def identity_fingerprint(payload: dict[str, Any]) -> str:
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    semantic = {
        "variantId": int(payload.get("variantId") or 0),
        "scanId": scan_id(payload),
        "artifactSha256": artifact_sha(payload),
        "artifactUrl": str(current.get("artifact_url") or ""),
        "assemblyVersion": str(current.get("assembly_version") or ""),
        "analysisPath": analysis_path(payload),
    }
    return hashlib.sha256(_canonical(semantic)).hexdigest()


def artifact_identity_fingerprint(payload: dict[str, Any]) -> str:
    """Fingerprint the shipped artifact identity, excluding source-only scan IDs."""
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    semantic = {
        "variantId": int(payload.get("variantId") or 0),
        "artifactSha256": artifact_sha(payload),
        "artifactUrl": str(current.get("artifact_url") or ""),
        "assemblyVersion": str(current.get("assembly_version") or ""),
        "analysisPath": analysis_path(payload),
    }
    return hashlib.sha256(_canonical(semantic)).hexdigest()


def mark_active(payload: dict[str, Any], *, catalog_revision: str = "") -> dict[str, Any]:
    result = copy.deepcopy(payload)
    previous = result.get("lifecycle") if isinstance(result.get("lifecycle"), dict) else {}
    result["lifecycle"] = {
        "schema": LIFECYCLE_SCHEMA,
        "state": ACTIVE,
        "catalogRevision": str(catalog_revision or previous.get("catalogRevision") or ""),
        "identityFingerprint": identity_fingerprint(result),
    }
    return result


def terminal_snapshot(
    payload: dict[str, Any], *, reason: str, catalog_revision: str = "", observed_at_utc: str = "",
) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    # Derived graph/advisory/source-cache datasets are keyed by the *current* variant
    # identity and can be refreshed independently. Terminal snapshots retain the
    # immutable artifact analysis plus bounded current/source comparison, but do not
    # pin mutable derived projection paths that a later reappearance may reuse.
    result.pop("derivedEvidence", None)
    result["lifecycle"] = {
        "schema": LIFECYCLE_SCHEMA,
        "state": RETIRED,
        "reason": str(reason or "catalog_variant_inactive"),
        "catalogRevision": str(catalog_revision or ""),
        "observedAtUtc": str(observed_at_utc or ""),
        "identityFingerprint": identity_fingerprint(result),
        "terminal": True,
        "rescanEligible": False,
    }
    return result


def superseded_snapshot(
    payload: dict[str, Any], *, replacement: dict[str, Any], reason: str = "current_analysis_replaced", observed_at_utc: str = "",
) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    result.pop("derivedEvidence", None)
    result["lifecycle"] = {
        "schema": LIFECYCLE_SCHEMA,
        "state": SUPERSEDED,
        "reason": str(reason or "current_analysis_replaced"),
        "observedAtUtc": str(observed_at_utc or ""),
        "identityFingerprint": identity_fingerprint(result),
        "terminal": True,
        "rescanEligible": False,
        "supersededBy": {
            "scanId": scan_id(replacement),
            "artifactSha256": artifact_sha(replacement),
            "identityFingerprint": identity_fingerprint(replacement),
        },
    }
    return result


def snapshot_name(payload: dict[str, Any]) -> str:
    sha = artifact_sha(payload) or "no-artifact"
    sid = scan_id(payload)
    return f"{sid:012d}-{sha[:20]}-{identity_fingerprint(payload)[:12]}.json"


def terminal_path(root: Path, variant_id: int) -> Path:
    return root / "terminal" / "variants" / f"{variant_id // 1000:04d}" / f"{variant_id}.json"


def history_path(root: Path, variant_id: int, payload: dict[str, Any]) -> Path:
    return root / "history" / "variants" / f"{variant_id // 1000:04d}" / str(variant_id) / snapshot_name(payload)
