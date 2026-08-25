#!/usr/bin/env python3
"""Read-only finding-lineage projection for DeltaScope.

A finding is much easier to review when the workbench can show the chain that led to it:
collector/producer -> retained collection -> selector/evidence -> fact/rule -> finding ->
published Evidence.  This module reconstructs that chain from already retained Evidence-v2
and frozen Definition provenance.  It never opens plugin bytes, performs network reputation
queries, changes findings, or authorizes production write-back.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

from deltascope_sdk import observation_projection, srl

SCHEMA = "omega.deltascope.finding-lineage.v1"
MAX_GRAPH_NODES = 180
MAX_GRAPH_EDGES = 320
MAX_OBSERVATION_NODES_PER_SELECTOR = 8


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical(value)).hexdigest()[:18]}"


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return "…"
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key in sorted(str(k) for k in value.keys())[:20]:
            out[key] = _bounded(value.get(key), depth + 1)
        if len(value) > 20:
            out["_truncatedFields"] = len(value) - 20
        return out
    if isinstance(value, list):
        out = [_bounded(item, depth + 1) for item in value[:12]]
        if len(value) > 12:
            out.append(f"… {len(value)-12} more")
        return out
    if isinstance(value, str):
        return value if len(value) <= 800 else value[:797] + "…"
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:800]


def _identity(detail: Mapping[str, Any]) -> dict[str, Any]:
    raw = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
    return {
        "pluginId": int(raw.get("plugin_id") or raw.get("pluginId") or 0),
        "variantId": int(raw.get("variant_id") or raw.get("variantId") or 0),
        "scanId": int(raw.get("scan_id") or raw.get("scanId") or 0),
        "name": str(raw.get("canonical_name") or raw.get("canonicalName") or raw.get("name") or raw.get("internal_name") or raw.get("internalName") or ""),
        "internalName": str(raw.get("internal_name") or raw.get("internalName") or ""),
        "version": str(raw.get("assembly_version") or raw.get("version") or ""),
        "artifactSha256": str(raw.get("artifact_sha256") or raw.get("artifactSha256") or ""),
        "scannerVersion": str(raw.get("scanner_version") or raw.get("scannerVersion") or ""),
        "definitionsRevision": str(raw.get("definitions_revision") or raw.get("definitionsRevision") or ""),
        "scannedAtUtc": str(raw.get("scanned_at_utc") or raw.get("scannedAtUtc") or ""),
    }


def _finding_rows(detail: Mapping[str, Any]) -> list[dict[str, Any]]:
    researcher = detail.get("researcher") if isinstance(detail.get("researcher"), Mapping) else {}
    source = researcher.get("findings") if isinstance(researcher.get("findings"), list) else detail.get("findings")
    rows: list[dict[str, Any]] = []
    for raw in source or []:
        if not isinstance(raw, Mapping):
            continue
        evidence = raw.get("evidence") if raw.get("evidence") is not None else raw.get("evidence_json")
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = [evidence]
        rows.append({
            "findingRowId": int(raw.get("finding_id") or 0) if str(raw.get("finding_id") or "").isdigit() else 0,
            "findingId": str(raw.get("findingId") or raw.get("ruleId") or raw.get("rule_id") or raw.get("finding_id") or ""),
            "ruleId": str(raw.get("ruleId") or raw.get("rule_id") or ""),
            "title": str(raw.get("title") or raw.get("findingId") or raw.get("finding_id") or raw.get("ruleId") or raw.get("rule_id") or "Security finding"),
            "description": str(raw.get("description") or ""),
            "severity": str(raw.get("severity") or "none").casefold(),
            "category": str(raw.get("category") or ""),
            "evidence": _bounded(evidence or []),
        })
    return rows


def _select_finding(detail: Mapping[str, Any], finding_id: str, rule_id: str) -> dict[str, Any]:
    rows = _finding_rows(detail)
    fid = str(finding_id or "").strip()
    rid = str(rule_id or "").strip()
    for row in rows:
        if fid and fid in {str(row.get("findingId") or ""), str(row.get("findingRowId") or "")}:
            return row
    for row in rows:
        if rid and rid == str(row.get("ruleId") or ""):
            return row
    if len(rows) == 1 and not fid and not rid:
        return rows[0]
    if not rows:
        raise ValueError("selected plugin has no current finding rows")
    raise ValueError("finding was not found in the selected plugin's current evidence")


def _active_rules(provenance: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(item) for item in provenance.get("activeRules") or [] if isinstance(item, Mapping)]


def _target_rule(finding: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any] | None:
    rule_id = str(finding.get("ruleId") or "")
    finding_id = str(finding.get("findingId") or "")
    for rule in _active_rules(provenance):
        emit = rule.get("emit") if isinstance(rule.get("emit"), Mapping) else {}
        if rule_id and str(rule.get("ruleId") or rule.get("id") or "") == rule_id:
            return rule
        if finding_id and str(emit.get("findingId") or "") == finding_id:
            return rule
    return None


def _rule_id(rule: Mapping[str, Any]) -> str:
    return str(rule.get("ruleId") or rule.get("id") or "")


def _emit_fact(rule: Mapping[str, Any]) -> str:
    emit = rule.get("emit") if isinstance(rule.get("emit"), Mapping) else {}
    return str(emit.get("fact") or "")


def _selector_fact_dependencies(rule: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    for selector in rule.get("selectors") or []:
        if isinstance(selector, Mapping) and str(selector.get("type") or "") == "facts":
            result.update(str(item) for item in selector.get("facts") or [] if str(item))
    return result


def _rule_closure(target: Mapping[str, Any], active_rules: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_fact = {_emit_fact(rule): dict(rule) for rule in active_rules if _emit_fact(rule)}
    chosen: dict[str, dict[str, Any]] = {_rule_id(target): dict(target)}
    pending = list(_selector_fact_dependencies(target))
    while pending:
        fact = pending.pop()
        producer = by_fact.get(fact)
        if not producer:
            continue
        rid = _rule_id(producer)
        if rid in chosen:
            continue
        chosen[rid] = producer
        pending.extend(sorted(_selector_fact_dependencies(producer)))
    return sorted(chosen.values(), key=lambda r: (0 if str(r.get("kind") or "") in {"observation", "classification"} else 1, _rule_id(r)))


def _required_collections(rules: Iterable[Mapping[str, Any]]) -> list[str]:
    return sorted({str(name) for rule in rules for name in rule.get("requires") or [] if str(name)})


def _contract(detail: Mapping[str, Any]) -> dict[str, Any]:
    value = detail.get("observations") if isinstance(detail.get("observations"), Mapping) else {}
    return dict(value)


def _loaded_rows_complete(collection: str, observations: Mapping[str, Sequence[Mapping[str, Any]]], contract: Mapping[str, Any]) -> tuple[bool, dict[str, Any]]:
    rows = observations.get(collection) or []
    collections = contract.get("collections") if isinstance(contract.get("collections"), Mapping) else {}
    descriptor = collections.get(collection) if isinstance(collections.get(collection), Mapping) else {}
    if not descriptor:
        return False, {"records": len(rows), "loaded": len(rows), "completeness": "unknown", "reason": "no observation-contract descriptor"}
    expected = int(descriptor.get("records") or 0)
    completeness = str(descriptor.get("completeness") or "unknown")
    exact_semantics = completeness == "retained"
    complete = exact_semantics and len(rows) >= expected
    return complete, {
        "records": expected,
        "loaded": len(rows),
        "completeness": completeness,
        "recordDigest": str(descriptor.get("recordDigest") or ""),
        "backingDataset": str(descriptor.get("backingDataset") or ""),
        "collectionSchema": str(descriptor.get("collectionSchema") or ""),
        "reason": "complete retained collection loaded" if complete else "bounded/missing rows prevent exact selector replay",
    }


def _producer(collection: str) -> dict[str, str]:
    spec = observation_projection.COLLECTIONS.get(collection) or {}
    origin = str(spec.get("origin") or "")
    if collection == "secondarySecurity":
        return {"id": "secondary-security", "label": "YARA / ClamAV secondary engines", "kind": "collector", "origin": origin}
    if collection == "manifestObservation":
        return {"id": "manifest-normalization", "label": "Catalog manifest normalization", "kind": "collector", "origin": origin}
    if collection in {"sourceFiles", "sourceAttribution", "sourceProvenance", "developerProfile"}:
        return {"id": "source-analysis", "label": "Source discovery / SigmaScope source analysis", "kind": "collector", "origin": origin}
    if origin == "artifact+source":
        return {"id": "sigmascope-analysis", "label": "SigmaScope artifact/source analysis", "kind": "collector", "origin": origin}
    return {"id": "sigmascope-artifact", "label": "SigmaScope artifact analysis", "kind": "collector", "origin": origin or "artifact"}


def _infer_static_collections(finding: Mapping[str, Any]) -> list[str]:
    rid = str(finding.get("ruleId") or "").casefold()
    cat = str(finding.get("category") or "").casefold()
    text = " ".join(str(x) for x in finding.get("evidence") or []).casefold()
    result: set[str] = set()
    if rid.startswith("network.endpoint") or "network-endpoint" in cat:
        result.add("networkEndpoints")
    if rid.startswith("native.") or "pinvoke" in rid or "native" in cat:
        result.update({"nativeImports", "binaryClassifications"})
    if rid.startswith("package."):
        result.update({"binaryClassifications", "artifactIdentity"})
    if "dependency" in rid or "advisory" in rid or "dependency" in cat:
        result.add("dependencies")
    if "yara" in rid or "clamav" in rid or "malware" in cat:
        result.add("secondarySecurity")
    if text:
        if "il:" in text:
            result.add("managedCallSites")
        if "metadata:" in text or "source:" in text or "artifact:" in text:
            result.add("staticPatternMatches")
        if "dllimport" in text or "native" in text:
            result.add("nativeImports")
        if "http://" in text or "https://" in text:
            result.add("networkEndpoints")
    if not result and rid:
        # Primitive scanner rules are pattern-driven. staticPatternMatches is the closest
        # retained raw observation family when no more specific structured collection is known.
        result.add("staticPatternMatches")
    return sorted(result)


def _node(nodes: list[dict[str, Any]], seen: set[str], *, node_id: str, kind: str, label: str, stage: str, **extra: Any) -> str:
    if node_id in seen:
        return node_id
    if len(nodes) >= MAX_GRAPH_NODES:
        return node_id
    seen.add(node_id)
    nodes.append({"id": node_id, "kind": kind, "label": label, "stage": stage, **extra})
    return node_id


def _edge(edges: list[dict[str, Any]], *, source: str, target: str, relationship: str, **extra: Any) -> None:
    if len(edges) >= MAX_GRAPH_EDGES:
        return
    item = {"source": source, "target": target, "relationship": relationship, **extra}
    if item not in edges:
        edges.append(item)


def _static_lineage(
    finding: Mapping[str, Any], identity: Mapping[str, Any], observations: Mapping[str, Sequence[Mapping[str, Any]]],
    detail: Mapping[str, Any],
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    collections = _infer_static_collections(finding)
    producer_nodes: dict[str, str] = {}
    for collection in collections:
        producer = _producer(collection)
        producer_id = f"collector:{producer['id']}"
        _node(nodes, seen, node_id=producer_id, kind="collector", label=producer["label"], stage="producer", origin=producer.get("origin", ""))
        producer_nodes[collection] = producer_id
        spec = observation_projection.COLLECTIONS.get(collection) or {}
        collection_id = f"collection:{collection}"
        rows = [dict(item) for item in observations.get(collection) or [] if isinstance(item, Mapping)]
        _node(
            nodes, seen, node_id=collection_id, kind="collection", label=collection, stage="observation",
            collection=collection, schema=str(spec.get("schema") or ""), backingDataset=str(spec.get("backingDataset") or ""),
            rowCount=len(rows), preview=_bounded(rows[:6]),
        )
        _edge(edges, source=producer_id, target=collection_id, relationship="produces")
    rule_id = str(finding.get("ruleId") or finding.get("findingId") or "")
    rule_node = _node(nodes, seen, node_id=f"static-rule:{rule_id or 'finding'}", kind="static-rule", label=rule_id or "SigmaScope static finding logic", stage="evaluation", engine="SigmaScope")
    for collection in collections:
        _edge(edges, source=f"collection:{collection}", target=rule_node, relationship="evaluated-by")
    for index, evidence in enumerate(finding.get("evidence") or []):
        ev_id = _stable_id("evidence", {"finding": finding.get("findingId"), "index": index, "value": evidence})
        _node(nodes, seen, node_id=ev_id, kind="evidence-row", label=str(evidence)[:180] or "finding evidence", stage="observation", evidence=_bounded(evidence))
        _edge(edges, source=ev_id, target=rule_node, relationship="supports")
    finding_node = _node(nodes, seen, node_id=f"finding:{finding.get('findingId') or rule_id}", kind="finding", label=str(finding.get("title") or finding.get("findingId") or "Finding"), stage="finding", severity=str(finding.get("severity") or "none"), category=str(finding.get("category") or ""), finding=dict(finding))
    _edge(edges, source=rule_node, target=finding_node, relationship="emits")
    published_id = _node(nodes, seen, node_id=f"published:{identity.get('variantId')}:{identity.get('scanId')}", kind="published-evidence", label="Published Security Evidence v2 / current scan", stage="publication", variantId=identity.get("variantId"), scanId=identity.get("scanId"), scannedAtUtc=identity.get("scannedAtUtc", ""), scannerVersion=identity.get("scannerVersion", ""), definitionsRevision=identity.get("definitionsRevision", ""))
    _edge(edges, source=finding_node, target=published_id, relationship="published-as-current-evidence")
    return {
        "origin": "sigmascope-static",
        "exactReplay": False,
        "replayReason": "This finding belongs to SigmaScope's current static projection, not an active Stigma-1 rule. DeltaScope links retained supporting collections/evidence without pretending to re-run the legacy projection code.",
        "collections": collections,
        "rules": [],
        "graph": {"nodes": nodes, "edges": edges},
    }


def _stigma_lineage(
    finding: Mapping[str, Any], target: Mapping[str, Any], identity: Mapping[str, Any],
    observations: Mapping[str, Sequence[Mapping[str, Any]]], provenance: Mapping[str, Any], detail: Mapping[str, Any],
    projection_state: Mapping[str, Any],
) -> dict[str, Any]:
    active = _active_rules(provenance)
    closure = _rule_closure(target, active)
    required = _required_collections(closure)
    contract = _contract(detail)
    coverage: dict[str, Any] = {}
    exact = True
    for collection in required:
        complete, descriptor = _loaded_rows_complete(collection, observations, contract)
        coverage[collection] = descriptor
        exact = exact and complete

    evaluation: dict[str, Any] = {}
    if exact:
        evaluator_rules = [{**dict(rule), "id": _rule_id(rule)} for rule in closure]
        compiled = {
            "schema": getattr(srl, "COMPILED_RULESET_SCHEMA", "omega.srl.compiled-ruleset.v1"),
            "engineSchema": getattr(srl, "ENGINE_SCHEMA", ""),
            "rules": evaluator_rules,
            "ruleSetRevision": str((provenance.get("srl") or {}).get("ruleSetRevision") or ""),
        }
        try:
            evaluation = srl.evaluate_ruleset(compiled, observations, observation_contract=contract)
            exact = bool(evaluation.get("evaluated"))
        except Exception as exc:
            exact = False
            evaluation = {"evaluated": False, "error": f"{type(exc).__name__}: {exc}"}

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    for collection in required:
        producer = _producer(collection)
        producer_id = f"collector:{producer['id']}"
        _node(nodes, seen, node_id=producer_id, kind="collector", label=producer["label"], stage="producer", origin=producer.get("origin", ""))
        descriptor = coverage.get(collection) or {}
        collection_id = f"collection:{collection}"
        spec = observation_projection.COLLECTIONS.get(collection) or {}
        _node(
            nodes, seen, node_id=collection_id, kind="collection", label=collection, stage="observation",
            collection=collection, schema=str(spec.get("schema") or ""), backingDataset=str(spec.get("backingDataset") or ""),
            rowCount=int(descriptor.get("records") or len(observations.get(collection) or [])), loadedRows=len(observations.get(collection) or []),
            completeness=str(descriptor.get("completeness") or "unknown"), exact=bool(descriptor.get("reason") == "complete retained collection loaded"),
        )
        _edge(edges, source=producer_id, target=collection_id, relationship="produces")

    evaluation_by_rule = {str(item.get("ruleId") or ""): item for item in evaluation.get("rules") or [] if isinstance(item, Mapping)}
    fact_producers: dict[str, str] = {}
    for rule in closure:
        rid = _rule_id(rule)
        rule_node = _node(nodes, seen, node_id=f"rule:{rid}", kind="stigma-rule", label=rid, stage="evaluation", ruleId=rid, packId=str(rule.get("packId") or ""), ruleRevision=str(rule.get("ruleRevision") or ""), ruleKind=str(rule.get("kind") or ""), status=str(rule.get("status") or ""), isTarget=(rid == _rule_id(target)))
        ev = evaluation_by_rule.get(rid) or {}
        selectors_by_name = {str(item.get("name") or ""): item for item in ev.get("selectors") or [] if isinstance(item, Mapping)}
        for selector in rule.get("selectors") or []:
            if not isinstance(selector, Mapping):
                continue
            name = str(selector.get("name") or "selector")
            selector_id = f"selector:{rid}:{name}"
            selector_eval = selectors_by_name.get(name) or {}
            _node(nodes, seen, node_id=selector_id, kind="selector", label=name, stage="evaluation", selectorType=str(selector.get("type") or ""), collection=str(selector.get("collection") or ""), matched=selector_eval.get("matched"), matchCount=int(selector_eval.get("matchCount") or 0), predicates=_bounded(selector.get("predicates") or []), facts=list(selector.get("facts") or []))
            _edge(edges, source=selector_id, target=rule_node, relationship="feeds-rule")
            collection = str(selector.get("collection") or "")
            if collection:
                _edge(edges, source=f"collection:{collection}", target=selector_id, relationship="selected-from")
                for matched in list(selector_eval.get("evidenceRows") or [])[:MAX_OBSERVATION_NODES_PER_SELECTOR]:
                    if not isinstance(matched, Mapping):
                        continue
                    row = matched.get("row") if isinstance(matched.get("row"), Mapping) else matched
                    obs_id = _stable_id("observation", {"collection": collection, "row": row})
                    _node(nodes, seen, node_id=obs_id, kind="observation-row", label=f"{collection} matched row", stage="observation", collection=collection, index=matched.get("index"), row=_bounded(row))
                    _edge(edges, source=f"collection:{collection}", target=obs_id, relationship="contains")
                    _edge(edges, source=obs_id, target=selector_id, relationship="matches-selector")
            else:
                for fact in selector.get("facts") or []:
                    fact_id = f"fact:{fact}"
                    _node(nodes, seen, node_id=fact_id, kind="fact", label=str(fact), stage="fact", fact=str(fact), matched=(str(fact) in set(selector_eval.get("matchedFacts") or [])))
                    _edge(edges, source=fact_id, target=selector_id, relationship="consumed-by")
        emitted_fact = _emit_fact(rule)
        if emitted_fact:
            fact_id = f"fact:{emitted_fact}"
            _node(nodes, seen, node_id=fact_id, kind="fact", label=emitted_fact, stage="fact", fact=emitted_fact, emitted=bool(ev.get("emittedFact")))
            _edge(edges, source=rule_node, target=fact_id, relationship="emits-fact")
            fact_producers[emitted_fact] = rule_node

    target_rule_id = _rule_id(target)
    finding_node = _node(nodes, seen, node_id=f"finding:{finding.get('findingId') or target_rule_id}", kind="finding", label=str(finding.get("title") or finding.get("findingId") or "Finding"), stage="finding", severity=str(finding.get("severity") or "none"), category=str(finding.get("category") or ""), finding=dict(finding))
    _edge(edges, source=f"rule:{target_rule_id}", target=finding_node, relationship="emits-finding")
    published_id = _node(nodes, seen, node_id=f"published:{identity.get('variantId')}:{identity.get('scanId')}", kind="published-evidence", label="Published Security Evidence v2 / current scan", stage="publication", variantId=identity.get("variantId"), scanId=identity.get("scanId"), scannedAtUtc=identity.get("scannedAtUtc", ""), scannerVersion=identity.get("scannerVersion", ""), definitionsRevision=str((provenance.get("definitions") or {}).get("definitionsRevision") or identity.get("definitionsRevision") or ""), ruleSetRevision=str((provenance.get("srl") or {}).get("ruleSetRevision") or ""))
    _edge(edges, source=finding_node, target=published_id, relationship="published-as-current-evidence")

    # Published projection sidecar is useful provenance even when selector replay is bounded.
    projection = projection_state.get("projection") if isinstance(projection_state.get("projection"), Mapping) else {}
    projection_match = target_rule_id in set(str(item) for item in projection.get("matchedRuleIds") or [])
    return {
        "origin": "stigma-1",
        "exactReplay": exact,
        "replayReason": "Exact selector/fact replay from complete retained observation collections." if exact else "The lineage is structurally exact, but one or more required collections were unavailable/bounded in the workbench preview; selector-match rows are shown only when DeltaScope could replay them safely.",
        "collections": required,
        "collectionCoverage": coverage,
        "rules": [{
            "ruleId": _rule_id(rule), "packId": str(rule.get("packId") or ""), "kind": str(rule.get("kind") or ""),
            "ruleRevision": str(rule.get("ruleRevision") or ""), "requires": list(rule.get("requires") or []),
            "emit": _bounded(rule.get("emit") or {}),
        } for rule in closure],
        "evaluation": _bounded(evaluation),
        "projection": {
            "available": bool(projection),
            "projectionRevision": str(projection.get("projectionRevision") or ""),
            "ruleSetRevision": str(projection.get("ruleSetRevision") or projection_state.get("ruleSetRevision") or ""),
            "targetRuleMatched": projection_match,
            "productionWriteBack": bool(projection.get("productionWriteBack") or projection_state.get("productionWriteBack")),
        },
        "graph": {"nodes": nodes, "edges": edges},
    }


def project_finding_lineage(
    detail: Mapping[str, Any], observations: Mapping[str, Sequence[Mapping[str, Any]]], provenance: Mapping[str, Any],
    projection_state: Mapping[str, Any] | None = None, *, finding_id: str = "", rule_id: str = "",
) -> dict[str, Any]:
    """Project one current finding into a bounded, read-only causal/evidence graph."""
    finding = _select_finding(detail, finding_id, rule_id)
    identity = _identity(detail)
    target = _target_rule(finding, provenance)
    if target:
        body = _stigma_lineage(finding, target, identity, observations, provenance, detail, projection_state or {})
    else:
        body = _static_lineage(finding, identity, observations, detail)
    graph = body.get("graph") if isinstance(body.get("graph"), Mapping) else {}
    semantic = {
        "variantId": identity.get("variantId"), "scanId": identity.get("scanId"),
        "findingId": finding.get("findingId"), "ruleId": finding.get("ruleId"),
        "origin": body.get("origin"), "nodes": graph.get("nodes") or [], "edges": graph.get("edges") or [],
    }
    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "currentVersionOnly": True,
        "lineageProjectionId": _stable_id("finding-lineage", semantic),
        "identity": identity,
        "finding": finding,
        **body,
    }
