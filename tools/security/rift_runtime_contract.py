#!/usr/bin/env python3
"""Production boundary contracts for importing Interdimensional Rift runtime evidence.

Rift produces neutral runtime facts.  This module validates identity/provenance and projects
those facts into collector-registry observations.  It never assigns severity or security verdicts.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

import collector_contracts

REQUEST_SCHEMA = "omega.rift.execution-request.v1"
ATTESTATION_SCHEMA_V1 = "rift.supervisor-attestation.v1"
ATTESTATION_SCHEMA_V2 = "rift.supervisor-attestation.v2"
RUNTIME_SCHEMA = "rift.runtime-observation.v2"
COMPONENT_SECURITY_SCHEMA = "omega.rift.component-security.v1"
INGESTION_SCHEMA = "omega.security-evidence.rift-ingestion.v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_RUNTIME_OBSERVATIONS = 25_000
MAX_COMPONENT_RECORDS = 5_000


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(data)


def _text(value: Any, limit: int = 4096) -> str:
    return str(value or "")[:limit]


def _sha(value: Any, label: str, errors: list[str]) -> str:
    text = str(value or "").strip().lower()
    if not HEX64.fullmatch(text):
        errors.append(f"{label} must be a lowercase SHA-256")
    return text


def validate_request(request: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(request.get("schema") or "") != REQUEST_SCHEMA:
        errors.append(f"request schema must be {REQUEST_SCHEMA}")
    request_id = str(request.get("requestId") or "").strip()
    if not request_id or len(request_id) > 160:
        errors.append("requestId must be 1..160 characters")
    try:
        variant_id = int(request.get("variantId") or 0)
    except (TypeError, ValueError):
        variant_id = 0
    if variant_id <= 0:
        errors.append("variantId must be positive")
    _sha(request.get("artifactSha256"), "artifactSha256", errors)
    profile = str(request.get("profile") or "").strip()
    if not profile:
        errors.append("profile is required")
    if str(request.get("authority") or "orchestrator") not in {"orchestrator", "analysis-broker"}:
        errors.append("request authority is unsupported")
    return errors


def validate_runtime_report(report: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(report.get("schema_version") or "") != RUNTIME_SCHEMA:
        errors.append(f"runtime report schema must be {RUNTIME_SCHEMA}")
    if not str(report.get("producer") or ""):
        errors.append("runtime report producer is missing")
    if not str(report.get("producer_version") or ""):
        errors.append("runtime report producer_version is missing")
    if not str(report.get("ran_at") or ""):
        errors.append("runtime report ran_at is missing")
    plugin = report.get("plugin") if isinstance(report.get("plugin"), Mapping) else {}
    if not str(plugin.get("path") or "") or not str(plugin.get("load_outcome") or ""):
        errors.append("runtime report plugin identity/lifecycle fields are missing")
    exercise = report.get("exercise") if isinstance(report.get("exercise"), Mapping) else {}
    if str(exercise.get("schema_version") or "") != "rift.exercise.v1":
        errors.append("runtime exercise schema must be rift.exercise.v1")
    observations = report.get("observations") if isinstance(report.get("observations"), list) else None
    if observations is None:
        errors.append("runtime report observations must be an array")
    elif len(observations) > MAX_RUNTIME_OBSERVATIONS:
        errors.append(f"runtime report exceeds {MAX_RUNTIME_OBSERVATIONS} observations")
    else:
        for index, item in enumerate(observations):
            if not isinstance(item, Mapping):
                errors.append(f"runtime observation {index} is not an object")
                continue
            if not str(item.get("id") or "") or not str(item.get("kind") or "") or not str(item.get("phase") or ""):
                errors.append(f"runtime observation {index} lacks id/kind/phase")
                continue
            try:
                if int(item.get("ts_offset_ms") or 0) < 0:
                    errors.append(f"runtime observation {index} has negative timestamp offset")
            except (TypeError, ValueError):
                errors.append(f"runtime observation {index} has invalid timestamp offset")
    return errors


def validate_attestation(attestation: Mapping[str, Any], report_bytes: bytes, request: Mapping[str, Any], *, production: bool = True) -> list[str]:
    errors: list[str] = []
    schema = str(attestation.get("schema_version") or "")
    if schema not in {ATTESTATION_SCHEMA_V1, ATTESTATION_SCHEMA_V2}:
        errors.append("unsupported Rift supervisor attestation schema")
    if str(attestation.get("producer") or "") != "interdimensional-rift-supervisor":
        errors.append("attestation producer is not the trusted Rift supervisor")
    if str(attestation.get("outcome") or "") != "runtime_report_emitted":
        errors.append("attestation does not represent a successful runtime report")
    declared_report_sha = _sha(attestation.get("runtime_report_sha256"), "runtime_report_sha256", errors)
    actual_report_sha = sha256_bytes(report_bytes)
    if declared_report_sha and declared_report_sha != actual_report_sha:
        errors.append("runtime report SHA-256 does not match supervisor attestation")
    _sha(attestation.get("artifact_tree_sha256"), "artifact_tree_sha256", errors)
    _sha(attestation.get("entry_sha256"), "entry_sha256", errors)
    if str(attestation.get("network") or "") != "isolated":
        errors.append("Rift network boundary was not isolated")
    if str(attestation.get("seccomp") or "") != "enforced":
        errors.append("Rift seccomp boundary was not enforced")
    if not str(attestation.get("boundary_profile") or ""):
        errors.append("Rift boundary profile is missing")
    if not str(attestation.get("contract_mode") or ""):
        errors.append("Rift contract mode is missing")

    binding = attestation.get("omega_request") if isinstance(attestation.get("omega_request"), Mapping) else {}
    expected = {
        "request_id": str(request.get("requestId") or ""),
        "variant_id": int(request.get("variantId") or 0),
        "artifact_sha256": str(request.get("artifactSha256") or "").strip().lower(),
    }
    if production and schema != ATTESTATION_SCHEMA_V2:
        errors.append("production ingestion requires Rift supervisor attestation v2 request binding")
    if production or binding:
        if str(binding.get("request_id") or "") != expected["request_id"]:
            errors.append("Rift attestation request_id does not match broker request")
        try:
            bound_variant = int(binding.get("variant_id") or 0)
        except (TypeError, ValueError):
            bound_variant = 0
        if bound_variant != expected["variant_id"]:
            errors.append("Rift attestation variant_id does not match broker request")
        if str(binding.get("artifact_sha256") or "").strip().lower() != expected["artifact_sha256"]:
            errors.append("Rift attestation artifact_sha256 does not match broker request")
    return errors


def validate_report_attestation_correlation(report: Mapping[str, Any], attestation: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    execution = report.get("execution") if isinstance(report.get("execution"), Mapping) else {}
    pairs = (
        ("artifact_tree_sha256", "artifact_tree_sha256"),
        ("artifact_tree_hash_algorithm", "artifact_tree_hash_algorithm"),
        ("entry_sha256", "entry_sha256"),
        ("network", "network"),
        ("seccomp", "seccomp"),
        ("boundary_profile", "boundary_profile"),
        ("contract_mode", "contract_mode"),
        ("exercise_profile", "exercise_profile"),
        ("framework_ticks", "framework_ticks"),
    )
    for execution_key, attestation_key in pairs:
        a = execution.get(execution_key)
        b = attestation.get(attestation_key)
        if a not in (None, "") and b not in (None, "") and a != b:
            errors.append(f"runtime report {execution_key} does not match supervisor attestation")
    exercise = report.get("exercise") if isinstance(report.get("exercise"), Mapping) else {}
    if exercise:
        if str(exercise.get("profile") or "") and str(attestation.get("exercise_profile") or "") and str(exercise.get("profile")) != str(attestation.get("exercise_profile")):
            errors.append("runtime exercise profile does not match supervisor attestation")
        try:
            requested = int(exercise.get("framework_ticks_requested") or 0)
            attested = int(attestation.get("framework_ticks") or 0)
            if requested != attested:
                errors.append("runtime exercise framework tick count does not match supervisor attestation")
        except (TypeError, ValueError):
            errors.append("runtime exercise framework tick count is invalid")
    return errors


def validate_component_security(report: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(report.get("schema") or "") != COMPONENT_SECURITY_SCHEMA:
        errors.append(f"component security schema must be {COMPONENT_SECURITY_SCHEMA}")
    records = report.get("records") if isinstance(report.get("records"), list) else None
    if records is None:
        errors.append("component security records must be an array")
    elif len(records) > MAX_COMPONENT_RECORDS:
        errors.append(f"component security report exceeds {MAX_COMPONENT_RECORDS} records")
    return errors


def build_observation_bundle(
    request: Mapping[str, Any], report: Mapping[str, Any], attestation: Mapping[str, Any],
    component_security: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    collector_id = "omega.collector.rift.runtime"
    request_id = str(request.get("requestId") or "")
    variant_id = int(request.get("variantId") or 0)
    artifact_sha = str(request.get("artifactSha256") or "").strip().lower()
    observed_at = str(report.get("ran_at") or "")
    provenance = {
        "requestId": request_id,
        "runtimeReportSha256": str(attestation.get("runtime_report_sha256") or ""),
        "artifactTreeSha256": str(attestation.get("artifact_tree_sha256") or ""),
        "entrySha256": str(attestation.get("entry_sha256") or ""),
    }
    event_rows: list[dict[str, Any]] = []
    for item in report.get("observations") or []:
        if not isinstance(item, Mapping):
            continue
        values = {
            "id": _text(item.get("id"), 256),
            "kind": _text(item.get("kind"), 128),
            "phase": _text(item.get("phase"), 128),
            "tsOffsetMs": int(item.get("ts_offset_ms") or 0),
            "component": _text(item.get("component"), 256),
            "operation": _text(item.get("operation"), 256),
            "target": _text(item.get("target"), 1024),
            "outcome": _text(item.get("outcome"), 128),
            "activityId": _text(item.get("activity_id"), 256),
            "parentActivityId": _text(item.get("parent_activity_id"), 256),
            "registrationId": _text(item.get("registration_id"), 256),
            "invocation": int(item.get("invocation") or 0),
            "requestId": request_id, "variantId": variant_id, "artifactSha256": artifact_sha,
        }
        event_rows.append(collector_contracts.make_row("riftRuntimeEvents", collector_id, values, observed_at=observed_at, provenance=provenance))

    exercise = report.get("exercise") if isinstance(report.get("exercise"), Mapping) else {}
    exercise_row = collector_contracts.make_row(
        "riftRuntimeExercise", collector_id,
        {
            "profile": _text(exercise.get("profile"), 128), "status": _text(exercise.get("status"), 128),
            "reason": _text(exercise.get("reason"), 1000),
            "frameworkTicksRequested": int(exercise.get("framework_ticks_requested") or 0),
            "registrationsDiscovered": int(exercise.get("registrations_discovered") or 0),
            "registrationsExercised": int(exercise.get("registrations_exercised") or 0),
            "registrationsUnexercised": int(exercise.get("registrations_unexercised") or 0),
            "requestId": request_id, "variantId": variant_id, "artifactSha256": artifact_sha,
        }, observed_at=observed_at, provenance=provenance,
    )
    boundary_row = collector_contracts.make_row(
        "riftRuntimeBoundary", collector_id,
        {
            "requestId": request_id, "variantId": variant_id, "artifactSha256": artifact_sha,
            "artifactTreeSha256": _text(attestation.get("artifact_tree_sha256"), 128),
            "entrySha256": _text(attestation.get("entry_sha256"), 128),
            "runtimeReportSha256": _text(attestation.get("runtime_report_sha256"), 128),
            "producer": _text(report.get("producer"), 256), "producerVersion": _text(report.get("producer_version"), 128),
            "ranAtUtc": observed_at, "network": _text(attestation.get("network"), 64),
            "seccomp": _text(attestation.get("seccomp"), 64), "boundaryProfile": _text(attestation.get("boundary_profile"), 256),
            "contractMode": _text(attestation.get("contract_mode"), 256),
            "processExitCode": int(attestation.get("process_exit_code") or 0), "attested": True,
        }, observed_at=observed_at, provenance=provenance,
    )
    component_rows: list[dict[str, Any]] = []
    if component_security:
        for item in component_security.get("records") or []:
            if not isinstance(item, Mapping):
                continue
            component_rows.append(collector_contracts.make_row(
                "riftComponentSecurity", collector_id,
                {
                    "component": _text(item.get("component"), 512), "version": _text(item.get("version"), 128),
                    "kind": _text(item.get("kind"), 128), "status": _text(item.get("status"), 128),
                    "advisoryId": _text(item.get("advisoryId"), 256), "advisoryUrl": _text(item.get("advisoryUrl"), 2048),
                    "fixedVersion": _text(item.get("fixedVersion"), 128),
                    "requestId": request_id, "variantId": variant_id, "artifactSha256": artifact_sha,
                }, observed_at=observed_at, provenance=provenance,
            ))
    return collector_contracts.build_bundle(
        {
            "riftRuntimeEvents": event_rows,
            "riftRuntimeExercise": [exercise_row],
            "riftRuntimeBoundary": [boundary_row],
            "riftComponentSecurity": component_rows,
        }, generated_at=observed_at, component_id="omega.rift",
    )
