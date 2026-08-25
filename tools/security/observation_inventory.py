#!/usr/bin/env python3
"""Materialize current reusable observations for the Omega Analysis Broker.

The inventory is a read-only index over already-published component evidence.  It does not
copy evidence and it never creates security conclusions.  The Analysis Broker uses these
records only to answer: "does an observation for this exact logical subject already exist and
is it still fresh enough to reuse?"

Current production sources:
* Security Evidence v2 retained SigmaScope observation contracts;
* retained collector bundles embedded in Evidence v2 (for example runtime/component lanes);
* the latest Omega Discovery collector-observation snapshot when supplied.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

import analysis_broker
import collector_contracts
import collector_results
import security_evidence_v2

SCHEMA = analysis_broker.INVENTORY_SCHEMA
BUILD_SCHEMA = "omega.observation-inventory-build.v1"
MAX_RECORDS = analysis_broker.MAX_INVENTORY_RECORDS


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _parse_utc(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _expiry(observation: str, observed_at: str) -> str:
    policy = collector_contracts.freshness_policy(observation)
    if str(policy.get("model") or "") != "ttl":
        return ""
    observed = _parse_utc(observed_at)
    ttl = int(policy.get("ttlSeconds") or 0)
    if observed is None or ttl <= 0:
        return ""
    return _format_utc(observed + timedelta(seconds=ttl))


def _active_provider(observation: str, *, component_id: str = "") -> str:
    providers: list[str] = []
    cmap = collector_contracts.collector_map()
    for collector_id in collector_contracts.providers_for(observation, include_planned=False):
        collector = cmap.get(collector_id) or {}
        if component_id and str(collector.get("componentId") or "") != component_id:
            continue
        providers.append(collector_id)
    return sorted(providers)[0] if providers else ""


def _subject_aliases(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
    variant_id = int(payload.get("variantId") or current.get("variant_id") or 0)
    plugin_id = int(payload.get("pluginId") or current.get("plugin_id") or 0)
    artifact_sha = str(current.get("artifact_sha256") or "").strip().lower()
    aliases: list[dict[str, Any]] = []
    if variant_id > 0:
        aliases.append({"type": "variant", "variantId": variant_id})
        if artifact_sha:
            aliases.append({"type": "variant", "variantId": variant_id, "artifactSha256": artifact_sha})
    if artifact_sha:
        aliases.append({"type": "artifact", "artifactSha256": artifact_sha})
    # pluginId is useful context in the inventory output, but deliberately not added to
    # subject aliases: callers should choose plugin/variant/artifact semantics explicitly.
    if plugin_id > 0 and not aliases:
        aliases.append({"type": "plugin", "pluginId": plugin_id})
    unique: dict[str, dict[str, Any]] = {}
    for subject in aliases:
        unique[analysis_broker.subject_key(subject)] = subject
    return [unique[key] for key in sorted(unique)]


def _record(*, observation: str, subject: Mapping[str, Any], observed_at: str, collector_id: str,
            component_id: str, reference: str, record_digest: str, expires_at: str = "") -> dict[str, Any]:
    return {
        "observation": observation,
        "subjectKey": analysis_broker.subject_key(subject),
        "observedAtUtc": observed_at,
        "expiresAtUtc": expires_at or _expiry(observation, observed_at),
        "collectorId": collector_id,
        "componentId": component_id,
        "reference": reference[:2048],
        "recordDigest": record_digest[:256],
    }


def _static_evidence_records(evidence_root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        observations = payload.get("observations") if isinstance(payload.get("observations"), Mapping) else {}
        collections = observations.get("collections") if isinstance(observations.get("collections"), Mapping) else {}
        current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
        observed_at = str(current.get("scanned_at_utc") or current.get("scannedAtUtc") or "")
        variant_path = str(entry.get("variantPath") or "")
        aliases = _subject_aliases(payload)
        for observation, descriptor in sorted(collections.items()):
            if not isinstance(descriptor, Mapping):
                continue
            # Generic collector results have their own exact-subject inventory path below.
            # Treating them as core static collections here would incorrectly manufacture
            # variant-only/artifact aliases for observations that are artifact-bound.
            if str(descriptor.get("backingDataset") or "") == "collector-result":
                continue
            if str(descriptor.get("completeness") or "") not in {"retained", "retained-snapshot"}:
                continue
            collector_id = _active_provider(str(observation), component_id="omega.sigmascope")
            if not collector_id:
                continue
            digest = str(descriptor.get("recordDigest") or "") or _sha({
                "collection": observation,
                "records": int(descriptor.get("records") or 0),
                "schema": str(descriptor.get("collectionSchema") or ""),
            })
            for subject in aliases:
                records.append(_record(
                    observation=str(observation), subject=subject, observed_at=observed_at,
                    collector_id=collector_id, component_id="omega.sigmascope",
                    reference=f"{variant_path}#observations/{observation}", record_digest=digest,
                ))
    return records


def _retained_bundle_records(evidence_root: Path) -> list[dict[str, Any]]:
    """Index collector bundles retained under variant-derived evidence without owning them."""
    records: list[dict[str, Any]] = []
    for entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        runtime = payload.get("runtime") if isinstance(payload.get("runtime"), Mapping) else {}
        run_id = str(runtime.get("runId") or "")
        if not run_id:
            continue
        variant_id = int(payload.get("variantId") or 0)
        artifact_sha = str(runtime.get("artifactSha256") or "").strip().lower()
        if variant_id <= 0 or not artifact_sha:
            continue
        bundle_rel = Path("derived") / "variants" / f"{variant_id // 1000:04d}" / str(variant_id) / "rift" / run_id / "collector-observations.json"
        bundle_path = evidence_root / bundle_rel
        if not bundle_path.is_file():
            continue
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            rows = collector_contracts.rows_from_bundle(bundle)
        except Exception:
            # Inventory construction is not allowed to make a valid Evidence-v2 snapshot
            # unusable merely because an optional derived collector lane is malformed.
            continue
        observed_at = str(runtime.get("observedAtUtc") or bundle.get("generatedAtUtc") or "")
        subject = {"type": "variant", "variantId": variant_id, "artifactSha256": artifact_sha}
        for observation, values in sorted(rows.items()):
            descriptor = (bundle.get("collections") or {}).get(observation) if isinstance(bundle.get("collections"), Mapping) else {}
            providers = list((descriptor or {}).get("providers") or []) if isinstance(descriptor, Mapping) else []
            collector_id = str(providers[0] if providers else runtime.get("collectorId") or "")
            component_id = str((collector_contracts.collector_map().get(collector_id) or {}).get("componentId") or "")
            if not collector_id or not component_id:
                continue
            digest = str((descriptor or {}).get("recordDigest") or "") or _sha(values)
            records.append(_record(
                observation=observation, subject=subject, observed_at=observed_at,
                collector_id=collector_id, component_id=component_id,
                reference=bundle_rel.as_posix() + f"#collections/{observation}", record_digest=digest,
            ))
    return records




def _generic_collector_result_records(evidence_root: Path) -> list[dict[str, Any]]:
    """Index latest generic collector results retained in Evidence-v2 variants."""
    records: list[dict[str, Any]] = []
    cmap = collector_contracts.collector_map()
    for entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        latest = payload.get("collectorResults") if isinstance(payload.get("collectorResults"), Mapping) else {}
        if not latest:
            continue
        variant_id = int(payload.get("variantId") or 0)
        current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
        analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
        artifact_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()
        if variant_id <= 0 or len(artifact_sha) != 64:
            continue
        subject = {"type": "variant", "variantId": variant_id, "artifactSha256": artifact_sha}
        for observation, metadata in sorted(latest.items()):
            if not isinstance(metadata, Mapping):
                continue
            result_rel = str(metadata.get("resultPath") or "")
            if not result_rel:
                continue
            try:
                result = collector_results.validate_result(security_evidence_v2.read_json_file(evidence_root, result_rel))
            except Exception:
                continue
            descriptor = (result.get("collections") or {}).get(observation) if isinstance(result.get("collections"), Mapping) else {}
            if not isinstance(descriptor, Mapping):
                continue
            collector_id = str((result.get("collector") or {}).get("id") or "") if isinstance(result.get("collector"), Mapping) else ""
            component_id = str((cmap.get(collector_id) or {}).get("componentId") or "")
            if not collector_id or not component_id:
                continue
            records.append(_record(
                observation=str(observation),
                subject=subject,
                observed_at=str(result.get("generatedAtUtc") or ""),
                collector_id=collector_id,
                component_id=component_id,
                reference=result_rel + f"#collections/{observation}",
                record_digest=str(descriptor.get("recordDigest") or "") or _sha(descriptor.get("rows") or []),
            ))
    return records


def _discovery_records(discovery_root: Path | None) -> list[dict[str, Any]]:
    if discovery_root is None:
        return []
    root = discovery_root.resolve()
    index_path = root / "index.json"
    observations_path = root / "observations.json"
    if not index_path.is_file() or not observations_path.is_file():
        return []
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        bundle = json.loads(observations_path.read_text(encoding="utf-8"))
        rows = collector_contracts.rows_from_bundle(bundle)
    except Exception:
        # Discovery is a replaceable cache. An old/incompatible snapshot must never be
        # trusted for reuse, but it also should not block security queue reconciliation.
        return []
    observed_at = str(bundle.get("generatedAtUtc") or index.get("generatedAtUtc") or "")
    subject = {"type": "catalog"}
    records: list[dict[str, Any]] = []
    descriptors = bundle.get("collections") if isinstance(bundle.get("collections"), Mapping) else {}
    for observation, values in sorted(rows.items()):
        descriptor = descriptors.get(observation) if isinstance(descriptors.get(observation), Mapping) else {}
        providers = sorted(str(item) for item in (descriptor.get("providers") or []) if str(item))
        digest = str(descriptor.get("recordDigest") or "") or _sha(values)
        if not providers:
            providers = [""]
        for collector_id in providers:
            component_id = str((collector_contracts.collector_map().get(collector_id) or {}).get("componentId") or collector_contracts.DISCOVERY_COMPONENT_ID)
            records.append(_record(
                observation=observation, subject=subject, observed_at=observed_at,
                collector_id=collector_id, component_id=component_id,
                reference=f"catalog-discovery/observations.json#collections/{observation}", record_digest=digest,
            ))
    return records


def build_inventory(evidence_root: Path | None, *, discovery_root: Path | None = None, generated_at: str = "") -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    if evidence_root is not None:
        root = evidence_root.resolve()
        records.extend(_static_evidence_records(root))
        records.extend(_retained_bundle_records(root))
        records.extend(_generic_collector_result_records(root))
    records.extend(_discovery_records(discovery_root))
    # Stable dedupe lets multiple aliases/providers coexist while repeated builders remain byte-stable.
    unique: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for row in records:
        key = (
            str(row.get("observation") or ""), str(row.get("subjectKey") or ""),
            str(row.get("collectorId") or ""), str(row.get("componentId") or ""), str(row.get("recordDigest") or ""),
        )
        unique[key] = row
    clean = [unique[key] for key in sorted(unique)]
    if len(clean) > MAX_RECORDS:
        raise ValueError(f"observation inventory exceeds {MAX_RECORDS} records")
    validated = analysis_broker.validate_inventory({"schema": SCHEMA, "records": clean})
    return {
        **validated,
        "generatedAtUtc": generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "recordCount": len(validated["records"]),
        "inventoryRevision": f"observation-inventory-v1-{_sha(validated)[:20]}",
        "sources": {
            "securityEvidenceV2": str(evidence_root or ""),
            "catalogDiscovery": str(discovery_root or ""),
        },
        "authority": "reuse-index-only",
    }


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the current Omega Analysis Broker observation inventory")
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--discovery-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory = build_inventory(args.evidence_root, discovery_root=args.discovery_root)
    _write(args.output, inventory)
    print(json.dumps({"schema": BUILD_SCHEMA, "records": inventory["recordCount"], "revision": inventory["inventoryRevision"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
