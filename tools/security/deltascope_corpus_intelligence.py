"""Local read-only corpus-intelligence pivots for DeltaScope.

This module turns already-acquired Evidence-v2 relationship and compact plugin-index state
into fast researcher pivots.  It never becomes security authority.  Local observation
history only records what this DeltaScope instance has seen; it is not corpus publication
history and must never be presented as authoritative first-seen data.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

SCHEMA = "omega.deltascope.corpus-intelligence.v1"
HISTORY_SCHEMA = "omega.deltascope.corpus-intelligence-history.v1"
PIVOT_SCHEMA = "omega.deltascope.corpus-intelligence-pivot.v1"
DEFAULT_RELATIVE_ROOT = Path(".omega") / "deltascope" / "intelligence" / "v1"
HISTORY_FILENAME = "corpus-history.json"
MAX_HISTORY_SNAPSHOTS = 32
MAX_HISTORY_BYTES = 8 * 1024 * 1024
MAX_ENTITY_TOKENS_PER_VARIANT = 24
MAX_GLOBAL_COOCCURRENCES = 40
MAX_PIVOT_COOCCURRENCES = 20


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical(value)).hexdigest()[:20]}"


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _text(value: Any) -> str:
    return str(value or "").strip()


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else []


def default_root() -> Path:
    override = os.environ.get("OMEGA_DELTASCOPE_INTELLIGENCE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / DEFAULT_RELATIVE_ROOT).resolve()


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if len(data) > MAX_HISTORY_BYTES:
        raise ValueError("DeltaScope corpus-intelligence history exceeds its bounded local size")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with tmp.open("wb") as handle:
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


class LocalCorpusIntelligenceHistory:
    """Bounded local observation history; never authoritative corpus history."""

    def __init__(self, root: Path | None = None):
        self.root = (root or default_root()).expanduser().absolute()
        self.path = self.root / HISTORY_FILENAME
        self._lock = threading.RLock()

    def _empty(self) -> dict[str, Any]:
        return {"schema": HISTORY_SCHEMA, "version": 1, "updatedAtUtc": "", "snapshots": []}

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        if self.path.is_symlink() or not self.path.is_file() or self.path.stat().st_size > MAX_HISTORY_BYTES:
            raise ValueError("DeltaScope corpus-intelligence history path is unsafe")
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != HISTORY_SCHEMA:
            raise ValueError("invalid DeltaScope corpus-intelligence history")
        snapshots = [dict(row) for row in raw.get("snapshots") or [] if isinstance(row, dict)]
        raw["snapshots"] = snapshots[-MAX_HISTORY_SNAPSHOTS:]
        return raw

    def observe(self, *, revision: str, generated_at_utc: str, endpoint_keys: Iterable[str], advisory_keys: Iterable[str]) -> dict[str, Any]:
        revision = _text(revision) or "unknown"
        endpoint_keys = sorted({_text(value) for value in endpoint_keys if _text(value)})
        advisory_keys = sorted({_text(value) for value in advisory_keys if _text(value)})
        with self._lock:
            data = self._read()
            snapshots = data["snapshots"]
            current = next((row for row in reversed(snapshots) if _text(row.get("revision")) == revision), None)
            if current is None:
                current = {
                    "revision": revision,
                    "generatedAtUtc": _text(generated_at_utc),
                    "observedAtUtc": utc_now(),
                    "endpointKeys": endpoint_keys,
                    "advisoryKeys": advisory_keys,
                }
                snapshots.append(current)
                data["snapshots"] = snapshots[-MAX_HISTORY_SNAPSHOTS:]
                data["updatedAtUtc"] = utc_now()
                self.root.mkdir(parents=True, exist_ok=True)
                try:
                    os.chmod(self.root, 0o700)
                except OSError:
                    pass
                _atomic_write(self.path, data)
            prior = None
            for row in reversed(data["snapshots"]):
                if _text(row.get("revision")) != revision:
                    prior = row
                    break
            endpoint_history: dict[str, dict[str, Any]] = {}
            advisory_history: dict[str, dict[str, Any]] = {}
            for snapshot in data["snapshots"]:
                observed = _text(snapshot.get("observedAtUtc"))
                snap_revision = _text(snapshot.get("revision"))
                for key in snapshot.get("endpointKeys") or []:
                    item = endpoint_history.setdefault(str(key), {"firstObservedLocalUtc": observed, "lastObservedLocalUtc": observed, "firstRevision": snap_revision, "lastRevision": snap_revision, "snapshotCount": 0})
                    item["lastObservedLocalUtc"] = observed
                    item["lastRevision"] = snap_revision
                    item["snapshotCount"] += 1
                for key in snapshot.get("advisoryKeys") or []:
                    item = advisory_history.setdefault(str(key), {"firstObservedLocalUtc": observed, "lastObservedLocalUtc": observed, "firstRevision": snap_revision, "lastRevision": snap_revision, "snapshotCount": 0})
                    item["lastObservedLocalUtc"] = observed
                    item["lastRevision"] = snap_revision
                    item["snapshotCount"] += 1
            prior_endpoints = set(prior.get("endpointKeys") or []) if isinstance(prior, dict) else set()
            prior_advisories = set(prior.get("advisoryKeys") or []) if isinstance(prior, dict) else set()
            return {
                "localOnly": True,
                "authoritativeFirstSeen": False,
                "historyScope": "this-deltascope-instance",
                "snapshotCount": len(data["snapshots"]),
                "hasPreviousSnapshot": prior is not None,
                "previousRevision": _text((prior or {}).get("revision")),
                "currentObservedAtUtc": _text(current.get("observedAtUtc")),
                "endpointHistory": endpoint_history,
                "advisoryHistory": advisory_history,
                "newEndpointKeys": sorted(set(endpoint_keys) - prior_endpoints) if prior is not None else [],
                "newAdvisoryKeys": sorted(set(advisory_keys) - prior_advisories) if prior is not None else [],
            }


def _normalise_repository(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    text = re.sub(r"\.git$", "", text.rstrip("/"), flags=re.I)
    try:
        parsed = urlparse(text if "://" in text else f"https://{text}")
    except ValueError:
        return text.casefold()
    host = (parsed.hostname or "").casefold()
    parts = [part for part in parsed.path.split("/") if part]
    if host == "github.com" and len(parts) >= 2:
        return f"github.com/{parts[0].casefold()}/{parts[1].casefold().removesuffix('.git')}"
    if host and parts:
        return f"{host}/{'/'.join(parts).casefold()}"
    return text.casefold()


def _asset(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "variantId": _int(row.get("variant_id") or row.get("variantId")),
        "pluginId": _int(row.get("plugin_id") or row.get("pluginId")),
        "name": _text(row.get("canonical_name") or row.get("name") or row.get("internal_name") or row.get("internalName")),
        "internalName": _text(row.get("internal_name") or row.get("internalName")),
        "version": _text(row.get("assembly_version") or row.get("version")),
        "author": _text(row.get("author")),
        "sourceName": _text(row.get("source_name") or row.get("sourceName")),
        "sourceUrl": _text(row.get("source_url") or row.get("sourceUrl")),
        "sourceRepository": _text(row.get("source_repository") or row.get("source_code_repository") or row.get("repository") or row.get("repo_url")),
        "scannedAtUtc": _text(row.get("scanned_at_utc") or row.get("scannedAtUtc")),
    }


def _capability_values(row: Mapping[str, Any]) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    raw = row.get("capabilityIds") if isinstance(row.get("capabilityIds"), list) else row.get("capability_ids")
    if isinstance(raw, list):
        for item in raw:
            text = _text(item)
            if text:
                values.append((text, text))
    caps = row.get("capabilities")
    if isinstance(caps, list):
        for item in caps:
            if isinstance(item, Mapping):
                key = _text(item.get("capabilityId") or item.get("id") or item.get("key"))
                label = _text(item.get("label") or item.get("title") or key)
            else:
                key = label = _text(item)
            if key:
                values.append((key, label or key))
    return values


def _source_family_rows(asset_rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for raw in asset_rows:
        if not isinstance(raw, Mapping):
            continue
        asset = _asset(raw)
        variant_id, plugin_id = asset["variantId"], asset["pluginId"]
        if variant_id <= 0:
            continue
        repo = _normalise_repository(asset["sourceRepository"] or asset["sourceUrl"])
        if repo:
            key, kind = f"repo:{repo}", "shared-source-repository"
            label = repo
        elif plugin_id > 0:
            key, kind = f"plugin:{plugin_id}", "catalog-plugin"
            label = asset["name"] or asset["internalName"] or f"plugin {plugin_id}"
        else:
            continue
        group = groups.setdefault(key, {"kind": "family", "key": key, "label": label, "familyKind": kind, "variantIds": set(), "pluginIds": set(), "names": set(), "authors": set(), "versions": set(), "repositories": set(), "evidenceTimes": []})
        group["variantIds"].add(variant_id)
        if plugin_id:
            group["pluginIds"].add(plugin_id)
        if asset["name"]:
            group["names"].add(asset["name"])
        if asset["author"]:
            group["authors"].add(asset["author"])
        if asset["version"]:
            group["versions"].add(asset["version"])
        if repo:
            group["repositories"].add(repo)
        if asset["scannedAtUtc"]:
            group["evidenceTimes"].append(asset["scannedAtUtc"])
    rows: list[dict[str, Any]] = []
    for group in groups.values():
        plugin_ids = sorted(group["pluginIds"])
        variant_ids = sorted(group["variantIds"])
        times = sorted(group["evidenceTimes"])
        rows.append({
            "kind": "family", "key": group["key"], "label": group["label"], "familyKind": group["familyKind"],
            "variantIds": variant_ids, "variantCount": len(variant_ids), "pluginIds": plugin_ids, "pluginCount": len(plugin_ids),
            "names": sorted(group["names"]), "authors": sorted(group["authors"]), "versions": sorted(group["versions"]), "repositories": sorted(group["repositories"]),
            "crossPlugin": len(plugin_ids) > 1, "firstEvidenceUtc": times[0] if times else "", "lastEvidenceUtc": times[-1] if times else "",
            "lineageAuthority": "shared-source-repository" if group["familyKind"] == "shared-source-repository" else "catalog-plugin-id",
            "forkInference": False,
        })
    rows.sort(key=lambda row: (-_int(row.get("pluginCount")), -_int(row.get("variantCount")), _text(row.get("label")).casefold()))
    return rows


def _author_rows(asset_rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for raw in asset_rows:
        if not isinstance(raw, Mapping):
            continue
        asset = _asset(raw)
        author = asset["author"]
        if not author or asset["variantId"] <= 0:
            continue
        key = author.casefold()
        group = groups.setdefault(key, {"kind": "author", "key": key, "label": author, "variantIds": set(), "pluginIds": set(), "repositories": set(), "names": set()})
        group["variantIds"].add(asset["variantId"])
        if asset["pluginId"]:
            group["pluginIds"].add(asset["pluginId"])
        repo = _normalise_repository(asset["sourceRepository"] or asset["sourceUrl"])
        if repo:
            group["repositories"].add(repo)
        if asset["name"]:
            group["names"].add(asset["name"])
    rows = [{
        "kind": "author", "key": group["key"], "label": group["label"], "variantIds": sorted(group["variantIds"]),
        "variantCount": len(group["variantIds"]), "pluginIds": sorted(group["pluginIds"]), "pluginCount": len(group["pluginIds"]),
        "repositories": sorted(group["repositories"]), "repositoryCount": len(group["repositories"]), "names": sorted(group["names"]),
    } for group in groups.values()]
    rows.sort(key=lambda row: (-_int(row.get("pluginCount")), -_int(row.get("variantCount")), _text(row.get("label")).casefold()))
    return rows


def _capability_rows(asset_rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for raw in asset_rows:
        if not isinstance(raw, Mapping):
            continue
        variant_id = _int(raw.get("variant_id") or raw.get("variantId"))
        if variant_id <= 0:
            continue
        for key, label in _capability_values(raw):
            norm = key.casefold()
            group = groups.setdefault(norm, {"kind": "capability", "key": key, "label": label, "variantIds": set()})
            group["variantIds"].add(variant_id)
    rows = [{"kind": "capability", "key": row["key"], "label": row["label"], "variantIds": sorted(row["variantIds"]), "variantCount": len(row["variantIds"]), "scope": "compact-current-index", "exact": True} for row in groups.values()]
    rows.sort(key=lambda row: (-_int(row.get("variantCount")), _text(row.get("label")).casefold()))
    return rows


def _behavior_key(row: Mapping[str, Any]) -> tuple[str, str]:
    rule = _text(row.get("ruleId") or row.get("findingId"))
    title = _text(row.get("title"))
    category = _text(row.get("category"))
    key = rule or category or title
    return key, title or rule or category or "Observed behavior"


def _behavior_rows(latest_findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for raw in latest_findings:
        if not isinstance(raw, Mapping):
            continue
        variant_id = _int(raw.get("variantId") or raw.get("variant_id"))
        key, label = _behavior_key(raw)
        if not key or variant_id <= 0:
            continue
        norm = key.casefold()
        group = groups.setdefault(norm, {"kind": "behavior", "key": key, "label": label, "variantIds": set(), "severities": Counter(), "categories": set()})
        group["variantIds"].add(variant_id)
        severity = _text(raw.get("severity") or "none").casefold()
        group["severities"][severity] += 1
        if _text(raw.get("category")):
            group["categories"].add(_text(raw.get("category")))
    rows = []
    for group in groups.values():
        rows.append({
            "kind": "behavior", "key": group["key"], "label": group["label"], "variantIds": sorted(group["variantIds"]), "variantCount": len(group["variantIds"]),
            "scope": "newest-finding-window", "exact": False, "categories": sorted(group["categories"]), "findingCount": sum(group["severities"].values()),
        })
    rows.sort(key=lambda row: (-_int(row.get("variantCount")), -_int(row.get("findingCount")), _text(row.get("label")).casefold()))
    return rows


def _entity_postings(endpoints: Iterable[Mapping[str, Any]], components: Iterable[Mapping[str, Any]], capabilities: Iterable[Mapping[str, Any]]) -> tuple[dict[str, set[int]], dict[str, dict[str, Any]]]:
    postings: dict[str, set[int]] = {}
    meta: dict[str, dict[str, Any]] = {}
    for kind, rows in (("endpoint", endpoints), ("component", components), ("capability", capabilities)):
        for row in rows:
            key = _text(row.get("key"))
            if not key:
                continue
            token = f"{kind}:{key}"
            ids = {_int(value) for value in row.get("variantIds") or [] if _int(value) > 0}
            if not ids:
                continue
            postings[token] = ids
            meta[token] = {"kind": kind, "key": key, "label": _text(row.get("label") or key), "variantCount": len(ids)}
    return postings, meta


def _global_cooccurrences(postings: Mapping[str, set[int]], meta: Mapping[str, Mapping[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    by_variant: dict[int, list[str]] = defaultdict(list)
    for token, ids in postings.items():
        for variant_id in ids:
            by_variant[int(variant_id)].append(token)
    pairs: Counter[tuple[str, str]] = Counter()
    truncated = 0
    for tokens in by_variant.values():
        ordered = sorted(tokens, key=lambda token: (len(postings.get(token, set())), token))
        if len(ordered) > MAX_ENTITY_TOKENS_PER_VARIANT:
            truncated += 1
            ordered = ordered[:MAX_ENTITY_TOKENS_PER_VARIANT]
        for index, left in enumerate(ordered):
            for right in ordered[index + 1:]:
                if left != right:
                    pairs[(left, right)] += 1
    rows: list[dict[str, Any]] = []
    for (left, right), overlap in pairs.items():
        if overlap < 2:
            continue
        lcount, rcount = len(postings[left]), len(postings[right])
        confidence = overlap / max(1, min(lcount, rcount))
        union = lcount + rcount - overlap
        rows.append({
            "pairId": _stable_id("cooccur", [left, right]), "left": dict(meta[left]), "right": dict(meta[right]),
            "overlapVariants": overlap, "confidence": round(confidence, 4), "jaccard": round(overlap / max(1, union), 4),
        })
    rows.sort(key=lambda row: (-float(row["confidence"]), -_int(row["overlapVariants"]), _text(row["left"].get("label")).casefold(), _text(row["right"].get("label")).casefold()))
    return rows[:MAX_GLOBAL_COOCCURRENCES], truncated


def _cooccurrences_for(token: str, postings: Mapping[str, set[int]], meta: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    base = postings.get(token) or set()
    rows = []
    for other, ids in postings.items():
        if other == token:
            continue
        overlap = len(base & ids)
        if overlap <= 0:
            continue
        confidence = overlap / max(1, len(base))
        rows.append({"entity": dict(meta[other]), "overlapVariants": overlap, "selectedVariantCount": len(base), "confidence": round(confidence, 4)})
    rows.sort(key=lambda row: (-float(row["confidence"]), -_int(row["overlapVariants"]), _text(row["entity"].get("label")).casefold()))
    return rows[:MAX_PIVOT_COOCCURRENCES]


def _enrich_endpoints(endpoints: list[dict[str, Any]], history: Mapping[str, Any]) -> list[dict[str, Any]]:
    endpoint_history = history.get("endpointHistory") if isinstance(history.get("endpointHistory"), Mapping) else {}
    new_keys = set(history.get("newEndpointKeys") or [])
    result = []
    for raw in endpoints:
        row = dict(raw)
        key = _text(row.get("key"))
        local = endpoint_history.get(key) if isinstance(endpoint_history.get(key), Mapping) else {}
        published_first = _text(row.get("firstSeenUtc") or row.get("firstObservedAtUtc"))
        published_last = _text(row.get("lastSeenUtc") or row.get("lastObservedAtUtc"))
        row.update({
            "publishedFirstSeenUtc": published_first, "publishedLastSeenUtc": published_last,
            "firstObservedLocalUtc": _text(local.get("firstObservedLocalUtc")), "lastObservedLocalUtc": _text(local.get("lastObservedLocalUtc")),
            "firstSeenScope": "published-corpus" if published_first else "this-deltascope-instance",
            "newSincePreviousLocalSnapshot": key in new_keys,
        })
        result.append(row)
    return result


def _brief(*, history: Mapping[str, Any], families: list[dict[str, Any]], authors: list[dict[str, Any]], behaviors: list[dict[str, Any]], cooccurrences: list[dict[str, Any]], advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    if history.get("hasPreviousSnapshot"):
        count = len(history.get("newEndpointKeys") or [])
        signals.append({"kind": "endpoint-delta", "title": f"{count} endpoint{'s' if count != 1 else ''} new since the previous locally observed Evidence snapshot", "detail": "Local snapshot delta only; this is not authoritative corpus first-seen history.", "count": count})
        advisory_count = len(history.get("newAdvisoryKeys") or [])
        if advisory_count:
            signals.append({"kind": "advisory-delta", "title": f"{advisory_count} advisory relationship{'s' if advisory_count != 1 else ''} new since the previous local snapshot", "detail": "Compare the affected plugin set before treating this as a security regression.", "count": advisory_count})
    else:
        signals.append({"kind": "history-baseline", "title": "Local intelligence baseline established", "detail": "Future acquired Evidence revisions can now show endpoint/advisory novelty relative to this DeltaScope instance."})
    cross = next((row for row in families if row.get("crossPlugin")), families[0] if families else None)
    if cross:
        signals.append({"kind": "family", "title": f"Largest visible source lineage: {cross['label']}", "detail": f"{cross['pluginCount']} logical plugin(s), {cross['variantCount']} variant(s). Shared repository/catalog identity is evidence of source lineage, not proof of a fork.", "pivotKind": "family", "pivotKey": cross["key"]})
    if cooccurrences:
        top = cooccurrences[0]
        signals.append({"kind": "cooccurrence", "title": f"Co-occurrence cluster: {top['left']['label']} + {top['right']['label']}", "detail": f"Observed together in {top['overlapVariants']} current variant(s); {round(float(top['confidence'])*100)}% containment against the smaller posting set."})
    if authors:
        top = authors[0]
        signals.append({"kind": "author", "title": f"Largest author cluster: {top['label']}", "detail": f"{top['pluginCount']} logical plugin(s) across {top['repositoryCount']} source repository signal(s).", "pivotKind": "author", "pivotKey": top["key"]})
    if behaviors:
        top = behaviors[0]
        signals.append({"kind": "behavior", "title": f"Most repeated behavior in the loaded finding window: {top['label']}", "detail": f"Seen in {top['variantCount']} variant(s) within the bounded newest-finding window; not a full-corpus capability count.", "pivotKind": "behavior", "pivotKey": top["key"]})
    return signals[:6]


def project_catalog(base_catalog: Mapping[str, Any], relationship_index: Mapping[str, Any], asset_rows: Iterable[Mapping[str, Any]], latest_findings: Iterable[Mapping[str, Any]], *, history_store: LocalCorpusIntelligenceHistory | None = None, evidence_revision: str = "", generated_at_utc: str = "") -> dict[str, Any]:
    """Extend the existing relationship catalog with fast corpus pivots and local novelty."""
    base = dict(base_catalog)
    endpoints = [dict(row) for row in base.get("endpoints") or [] if isinstance(row, Mapping)]
    components = [dict(row) for row in base.get("components") or [] if isinstance(row, Mapping)]
    advisories = [dict(row) for row in base.get("advisories") or [] if isinstance(row, Mapping)]
    assets = [dict(row) for row in asset_rows if isinstance(row, Mapping)]
    findings = [dict(row) for row in latest_findings if isinstance(row, Mapping)]
    history = history_store.observe(
        revision=evidence_revision or _text(base.get("relationshipRevision")) or "unknown",
        generated_at_utc=generated_at_utc,
        endpoint_keys=[row.get("key") for row in endpoints],
        advisory_keys=[row.get("key") for row in advisories],
    ) if history_store is not None else {"localOnly": True, "authoritativeFirstSeen": False, "historyScope": "this-deltascope-instance", "snapshotCount": 0, "hasPreviousSnapshot": False, "endpointHistory": {}, "advisoryHistory": {}, "newEndpointKeys": [], "newAdvisoryKeys": []}
    endpoints = _enrich_endpoints(endpoints, history)
    families = _source_family_rows(assets)
    authors = _author_rows(assets)
    capabilities = _capability_rows(assets)
    behaviors = _behavior_rows(findings)
    postings, entity_meta = _entity_postings(endpoints, components, capabilities)
    cooccurrences, truncated_variants = _global_cooccurrences(postings, entity_meta)
    brief = _brief(history=history, families=families, authors=authors, behaviors=behaviors, cooccurrences=cooccurrences, advisories=advisories)
    extension_core = {
        "families": families, "authors": authors, "capabilities": capabilities, "behaviors": behaviors,
        "cooccurrences": cooccurrences, "history": {key: history.get(key) for key in ("snapshotCount", "hasPreviousSnapshot", "previousRevision", "newEndpointKeys", "newAdvisoryKeys")},
    }
    counts = dict(base.get("counts") or {})
    counts.update({"families": len(families), "authors": len(authors), "capabilities": len(capabilities), "behaviors": len(behaviors), "cooccurrences": len(cooccurrences)})
    return {
        **base,
        "corpusIntelligenceSchema": SCHEMA,
        "corpusIntelligenceRevision": _stable_id("corpus-intelligence", extension_core),
        "endpoints": endpoints, "families": families, "authors": authors, "capabilities": capabilities, "behaviors": behaviors,
        "cooccurrences": cooccurrences, "brief": brief, "counts": counts, "history": history,
        "cooccurrenceModel": {"algorithm": "variant-posting-pairs", "maxEntityTokensPerVariant": MAX_ENTITY_TOKENS_PER_VARIANT, "truncatedHighCardinalityVariants": truncated_variants, "globalPairLimit": MAX_GLOBAL_COOCCURRENCES},
        "capabilityCoverage": {"exactCompactCapabilityCount": len(capabilities), "boundedBehaviorSignalCount": len(behaviors), "behaviorWindow": len(findings), "fullCorpusCapabilityIndexAvailable": bool(capabilities)},
        "familyModel": {"exact": True, "signals": ["catalog-plugin-id", "shared-source-repository"], "crossRepositoryForkDetection": False, "limitation": "Cross-repository fork/rename inference requires published commit ancestry or code fingerprints."},
        "codeReuse": {"available": False, "reason": "Code-reuse pivots require a published code/string/resource fingerprint index; DeltaScope will not infer code reuse from names alone."},
        "firstSeenModel": {"publishedCorpusTimestampsAvailable": any(row.get("publishedFirstSeenUtc") for row in endpoints), "localObservationFallback": True, "localObservationIsAuthoritativeCorpusHistory": False},
    }


def _catalog_rows(catalog: Mapping[str, Any], kind: str) -> list[dict[str, Any]]:
    source = {"endpoint": "endpoints", "component": "components", "advisory": "advisories", "family": "families", "author": "authors", "capability": "capabilities", "behavior": "behaviors"}.get(kind)
    return [dict(row) for row in catalog.get(source) or [] if isinstance(row, Mapping)] if source else []


def project_pivot(catalog: Mapping[str, Any], kind: str, key: str, asset_rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    kind = _text(kind).casefold()
    key = _text(key)
    rows = _catalog_rows(catalog, kind)
    match = next((row for row in rows if _text(row.get("key")) == key), None)
    if match is None:
        raise ValueError(f"unknown {kind} intelligence key")
    ids = {_int(value) for value in match.get("variantIds") or [] if _int(value) > 0}
    assets = [_asset(row) for row in asset_rows if isinstance(row, Mapping) and _int(row.get("variant_id") or row.get("variantId")) in ids]
    assets.sort(key=lambda row: (_text(row.get("name")).casefold(), _int(row.get("variantId"))))
    postings, meta = _entity_postings(catalog.get("endpoints") or [], catalog.get("components") or [], catalog.get("capabilities") or [])
    cooccurrences = _cooccurrences_for(f"{kind}:{key}", postings, meta) if kind in {"endpoint", "component", "capability"} else []
    return {
        "schema": PIVOT_SCHEMA, "readOnly": True, "mutationAuthority": "none", "policyInput": False,
        "pivotId": _stable_id("corpus-pivot", {"kind": kind, "key": key, "variantIds": sorted(ids)}),
        "relationshipRevision": _text(catalog.get("relationshipRevision")), "corpusIntelligenceRevision": _text(catalog.get("corpusIntelligenceRevision")),
        "relationship": match, "assets": assets, "cooccurrences": cooccurrences,
    }
