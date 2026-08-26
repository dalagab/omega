"""Typed Stigma-1 deep-analysis request contracts.

Rules may request only a named profile, a bounded scan depth, a comparison target and a
human-readable reason. They cannot provide commands, runner settings, network policy,
arbitrary paths, raw timeouts, or executable payload. SigmaScope/Actions own the exact
resource budgets behind each depth.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

REQUEST_SCHEMA = "omega.stigma-1.analysis-request.v1"
QUEUE_SCHEMA = "omega.sigmascope.deep-scan-queue.v1"
QUEUE_ITEM_SCHEMA = "omega.sigmascope.deep-scan-request.v1"
RESULT_SCHEMA = "omega.sigmascope.deep-scan-result.v1"
PROFILE_SET_SCHEMA = "omega.sigmascope.deep-scan-profiles.v1"

DEPTH_ORDER = {"standard": 0, "extended": 1, "exhaustive": 2}
COMPARE_WITH = {"none", "stable-artifact-baseline"}

# Resource budgets are code-owned. SRL chooses only the semantic depth. This means a
# rule can say "look harder" without gaining authority over GitHub runner controls.
PROFILES: dict[str, dict[str, Any]] = {
    "artifact-differential-v1": {
        "available": True,
        "executionMode": "non-executing-static-differential",
        "description": "Compare exact candidate and baseline package contents without executing either plugin.",
        "depths": {
            "standard": {
                "workflowTimeoutMinutes": 20,
                "workerBudgetSeconds": 15 * 60,
                "maxArtifactBytes": 256 * 1024 * 1024,
                "maxArchiveEntries": 2048,
                "maxMemberBytes": 32 * 1024 * 1024,
                "maxUncompressedBytes": 256 * 1024 * 1024,
                "analysisFamilies": ["package-inventory", "sigmascope-static-behavior"],
            },
            "extended": {
                "workflowTimeoutMinutes": 40,
                "workerBudgetSeconds": 35 * 60,
                "maxArtifactBytes": 384 * 1024 * 1024,
                "maxArchiveEntries": 4096,
                "maxMemberBytes": 64 * 1024 * 1024,
                "maxUncompressedBytes": 512 * 1024 * 1024,
                "contentInspectionBytes": 96 * 1024 * 1024,
                "maxExtractedStrings": 4096,
                "analysisFamilies": ["package-inventory", "sigmascope-static-behavior", "member-content-summary"],
            },
            "exhaustive": {
                "workflowTimeoutMinutes": 65,
                "workerBudgetSeconds": 55 * 60,
                "maxArtifactBytes": 512 * 1024 * 1024,
                "maxArchiveEntries": 8192,
                "maxMemberBytes": 128 * 1024 * 1024,
                "maxUncompressedBytes": 1024 * 1024 * 1024,
                "contentInspectionBytes": 256 * 1024 * 1024,
                "maxExtractedStrings": 16384,
                "analysisFamilies": ["package-inventory", "sigmascope-static-behavior", "member-content-summary", "expanded-literal-diff"],
            },
        },
    },
    "sandbox-differential-v1": {
        "available": False,
        "executionMode": "isolated-sandbox-required",
        "description": "Reserved for equal-profile behavioral execution once an isolated plugin sandbox exists.",
        "blockedReason": "no isolated plugin execution sandbox is implemented; never execute untrusted plugins on a normal Actions runner",
        "depths": {
            "standard": {"workflowTimeoutMinutes": 30, "workerBudgetSeconds": 20 * 60, "analysisFamilies": ["sandbox-behavior"]},
            "extended": {"workflowTimeoutMinutes": 50, "workerBudgetSeconds": 40 * 60, "analysisFamilies": ["sandbox-behavior", "extended-observation-window"]},
            "exhaustive": {"workflowTimeoutMinutes": 65, "workerBudgetSeconds": 55 * 60, "analysisFamilies": ["sandbox-behavior", "extended-observation-window", "expanded-behavior-diff"]},
        },
    },
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def profile_set_revision() -> str:
    semantic = {"schema": PROFILE_SET_SCHEMA, "profiles": PROFILES, "depthOrder": DEPTH_ORDER}
    return "deep-profiles-v1-" + hashlib.sha256(canonical(semantic)).hexdigest()[:16]


def normalize_depth(value: Any) -> str:
    depth = str(value or "standard").strip().casefold()
    if depth not in DEPTH_ORDER:
        raise ValueError(f"analysisRequest.depth must be one of {sorted(DEPTH_ORDER)}")
    return depth


def deeper_depth(a: str, b: str) -> str:
    return a if DEPTH_ORDER[normalize_depth(a)] >= DEPTH_ORDER[normalize_depth(b)] else b


def profile_status(profile: str, depth: str = "standard") -> dict[str, Any]:
    name = str(profile)
    spec = dict(PROFILES.get(name, {}))
    selected_depth = normalize_depth(depth)
    depths = spec.pop("depths", {}) if isinstance(spec.get("depths"), Mapping) else {}
    budget = dict(depths.get(selected_depth, {})) if isinstance(depths.get(selected_depth), Mapping) else {}
    return {
        "profile": name,
        "depth": selected_depth,
        "profileSetRevision": profile_set_revision(),
        "supportedDepths": sorted(depths, key=lambda item: DEPTH_ORDER.get(item, 999)),
        **spec,
        **budget,
    }


def compile_analysis_request(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ValueError("analysisRequest must be a mapping")
    allowed = {"profile", "depth", "reason", "compareWith"}
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"analysisRequest contains unsupported fields: {sorted(unknown)}")
    profile = str(raw.get("profile") or "").strip()
    if profile not in PROFILES:
        raise ValueError(f"analysisRequest.profile must be one of {sorted(PROFILES)}")
    depth = normalize_depth(raw.get("depth"))
    reason = str(raw.get("reason") or "").strip()
    if not reason or len(reason) > 512:
        raise ValueError("analysisRequest.reason must be 1..512 characters")
    compare_with = str(raw.get("compareWith") or "none").strip()
    if compare_with not in COMPARE_WITH:
        raise ValueError(f"analysisRequest.compareWith must be one of {sorted(COMPARE_WITH)}")
    if "differential" in profile and compare_with == "none":
        raise ValueError("differential deep-scan profiles require compareWith: stable-artifact-baseline")
    status = profile_status(profile, depth)
    if depth not in status.get("supportedDepths", []):
        raise ValueError(f"analysisRequest.depth {depth!r} is not supported by {profile}")
    return {
        "schema": REQUEST_SCHEMA,
        "profile": profile,
        "depth": depth,
        "profileSetRevision": profile_set_revision(),
        "reason": reason,
        "compareWith": compare_with,
    }
