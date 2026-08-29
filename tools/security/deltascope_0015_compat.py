"""DeltaScope 0015 compatibility repair.

This module deliberately hooks the small, stable DeltaScope entry point instead of
patching the fast-moving developer-view and Evidence-v2 inspector bodies.  It keeps
Rift intake process-local, resolves GitHub plugin links through existing catalog
identity, and repairs the logical-plugin dossier renderer removed by an earlier UI
refactor.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable, Mapping


RIFT_RUNTIME_SCHEMA = "rift.runtime-observation.v2"
RIFT_COLLECTOR_SCHEMA = "omega.collector.rift.runtime.v1"
RIFT_REVIEW_SCHEMA = "omega.deltascope.rift-runtime-review.v1"
MAX_RIFT_REPORT_BYTES = 1536 * 1024
MAX_GITHUB_URL_CHARS = 4096


def _stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def _integer(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _text(value: Any) -> str:
    return str(value or "").strip()


def _json_paths(paths: Iterable[Path]) -> list[Path]:
    found: dict[Path, None] = {}
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if path.is_dir():
            for candidate in sorted(path.rglob("*.json")):
                found[candidate.resolve()] = None
        elif path.is_file():
            found[path.resolve()] = None
    return sorted(found)


def _runtime_payload(document: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    if document.get("schema_version") == RIFT_RUNTIME_SCHEMA:
        return document, list(document.get("observations") or []), "rift runtime report"
    if document.get("schema_version") == RIFT_COLLECTOR_SCHEMA and document.get("collector") == "omega.collector.rift.runtime":
        subject = document.get("subject") if isinstance(document.get("subject"), dict) else {}
        plugin = subject.get("plugin") if isinstance(subject.get("plugin"), dict) else {}
        runtime = {
            "plugin": plugin,
            "execution": document.get("execution") if isinstance(document.get("execution"), dict) else {},
            "exercise": document.get("exercise") if isinstance(document.get("exercise"), dict) else {},
            "summary": {"total_observations": len(document.get("runtime_observations") or [])},
            "ran_at": "",
        }
        return runtime, list(document.get("runtime_observations") or []), "Omega collector projection"
    raise ValueError("expected Rift runtime observation v2 or Omega Rift runtime collector v1")


def _observation_label(observation: dict[str, Any]) -> str:
    kind = _text(observation.get("kind")) or "runtime observation"
    subject = _text(observation.get("component")) or _text(observation.get("target")) or _text(observation.get("message"))
    operation = _text(observation.get("operation"))
    if subject and operation:
        return f"{kind}: {subject} · {operation}"
    return f"{kind}: {subject}" if subject else kind


def _decode_document(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_RIFT_REPORT_BYTES:
        raise ValueError(f"Rift report exceeds the {MAX_RIFT_REPORT_BYTES // 1024} KiB local intake limit")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Rift report is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("top-level JSON must be an object")
    return document


def _project_document(document: dict[str, Any], *, source: str, source_key: str, acquired_from: str) -> dict[str, Any]:
    runtime, observations, source_kind = _runtime_payload(document)
    plugin = runtime.get("plugin") if isinstance(runtime.get("plugin"), dict) else {}
    execution = runtime.get("execution") if isinstance(runtime.get("execution"), dict) else {}
    timeline: list[dict[str, Any]] = []
    for index, raw_observation in enumerate(observations):
        if not isinstance(raw_observation, dict):
            continue
        offset = _integer(raw_observation.get("ts_offset_ms"))
        timeline.append({
            "eventId": _stable_id("rift-event", {"report": source_key, "index": index, "observation": raw_observation}),
            "offsetMs": offset,
            "kind": _text(raw_observation.get("kind")) or "runtime observation",
            "phase": _text(raw_observation.get("phase")) or "unattributed",
            "label": _observation_label(raw_observation),
            "component": _text(raw_observation.get("component")),
            "operation": _text(raw_observation.get("operation")),
            "target": _text(raw_observation.get("target")),
            "registrationId": _text(raw_observation.get("registration_id")),
            "invocation": raw_observation.get("invocation"),
        })
    timeline.sort(key=lambda item: (item["offsetMs"], item["eventId"]))
    exercise = runtime.get("exercise") if isinstance(runtime.get("exercise"), dict) else {}
    reported_count = (
        _integer((runtime.get("summary") or {}).get("total_observations"))
        if isinstance(runtime.get("summary"), dict) else len(timeline)
    )
    return {
        "reportId": _stable_id("rift-report", {"source": source_key, "schema": document.get("schema_version"), "ranAt": runtime.get("ran_at")}),
        "source": source,
        "sourceKind": source_kind,
        "acquiredFrom": acquired_from,
        "status": "reviewable",
        "readOnly": True,
        "schemaVersion": _text(document.get("schema_version")),
        "ranAt": _text(runtime.get("ran_at")),
        "plugin": {
            "name": _text(plugin.get("internal_name")) or _text(plugin.get("assembly_name")) or Path(source).stem,
            "assemblyName": _text(plugin.get("assembly_name")),
            "loadOutcome": _text(plugin.get("load_outcome")) or _text(execution.get("outcome")),
        },
        "execution": {
            "network": _text(execution.get("network")),
            "profile": _text(execution.get("exercise_profile")) or _text(exercise.get("profile")),
            "status": _text(exercise.get("status")),
        },
        "observationCount": len(timeline),
        "reportedObservationCount": reported_count,
        "durationMs": max((item["offsetMs"] for item in timeline), default=0),
        "timeline": timeline,
        "exercise": {
            "discovered": _integer(exercise.get("registrations_discovered")),
            "exercised": _integer(exercise.get("registrations_exercised")),
            "unexercised": _integer(exercise.get("registrations_unexercised")),
            "byKind": exercise.get("by_kind") if isinstance(exercise.get("by_kind"), dict) else {},
        },
    }


def _unreadable(source: str, source_key: str, reason: str, acquired_from: str) -> dict[str, Any]:
    return {
        "reportId": _stable_id("rift-report", {"source": source_key}),
        "source": source,
        "sourceKind": "unreadable",
        "acquiredFrom": acquired_from,
        "status": "unreadable",
        "reason": reason,
        "timeline": [],
        "observationCount": 0,
        "readOnly": True,
    }


def _project_path(path: Path) -> dict[str, Any]:
    try:
        return _project_document(
            _decode_document(path.read_bytes()),
            source=path.name,
            source_key=str(path),
            acquired_from="configured-local-file",
        )
    except (OSError, ValueError) as exc:
        return _unreadable(path.name, str(path), str(exc), "configured-local-file")


def _github_json_request(url: str, *, token: str = "") -> urllib.request.Request:
    text = str(url or "").strip()
    if not text or len(text) > MAX_GITHUB_URL_CHARS:
        raise ValueError("GitHub report URL is required and must be bounded")
    parsed = urllib.parse.urlparse(text)
    host = parsed.hostname.casefold() if parsed.hostname else ""
    if parsed.scheme != "https" or host not in {"github.com", "raw.githubusercontent.com"}:
        raise ValueError("Rift report links must use https://github.com or https://raw.githubusercontent.com")
    headers = {"User-Agent": "Omega-DeltaScope/Rift-Intake", "Accept": "application/vnd.github.raw+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if host == "raw.githubusercontent.com":
        if not parsed.path.casefold().endswith(".json"):
            raise ValueError("GitHub Rift report link must point to a JSON file")
        return urllib.request.Request(text, headers=headers)
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[2] not in {"blob", "raw"}:
        raise ValueError("GitHub Rift report link must point to a file, for example /owner/repo/blob/main/report.json")
    owner, repo, _, ref = parts[:4]
    path = "/".join(parts[4:])
    if not path.casefold().endswith(".json"):
        raise ValueError("GitHub Rift report link must point to a JSON file")
    api = (
        f"https://api.github.com/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"
        f"/contents/{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(ref, safe='')}"
    )
    return urllib.request.Request(api, headers=headers)


def _read_github_json(url: str, *, token: str = "", opener: Any = None) -> bytes:
    request = _github_json_request(url, token=token)
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=8) as response:
            raw = response.read(MAX_RIFT_REPORT_BYTES + 1)
            headers = getattr(response, "headers", {})
            content_type = str(headers.get("Content-Type", "")) if hasattr(headers, "get") else ""
    except urllib.error.HTTPError as exc:
        raise ValueError(f"GitHub returned HTTP {exc.code} for the Rift report") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"GitHub Rift report acquisition failed: {exc.reason}") from exc
    if len(raw) > MAX_RIFT_REPORT_BYTES:
        raise ValueError(f"Rift report exceeds the {MAX_RIFT_REPORT_BYTES // 1024} KiB local intake limit")
    if request.full_url.startswith("https://api.github.com/") and ("json" in content_type.casefold() or raw.lstrip().startswith(b"{")):
        try:
            payload = json.loads(raw.decode("utf-8"))
            if isinstance(payload, Mapping) and str(payload.get("encoding") or "").casefold() == "base64":
                decoded = base64.b64decode("".join(str(payload.get("content") or "").split()), validate=True)
                if len(decoded) > MAX_RIFT_REPORT_BYTES:
                    raise ValueError(f"Rift report exceeds the {MAX_RIFT_REPORT_BYTES // 1024} KiB local intake limit")
                return decoded
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            pass
    return raw


class RiftReportStore:
    """Process-local report snapshot. Navigation reads memory; acquisition is explicit."""

    def __init__(self, configured_paths: Iterable[Path] = ()) -> None:
        self.configured_paths = tuple(Path(path) for path in configured_paths)
        self._lock = threading.RLock()
        self._configured: list[dict[str, Any]] = []
        self._imports: dict[str, dict[str, Any]] = {}
        self.reload_configured()

    def reload_configured(self) -> dict[str, Any]:
        reports = [_project_path(path) for path in _json_paths(self.configured_paths)]
        with self._lock:
            self._configured = reports
        return {"refreshed": True, "configuredReportCount": len(reports), "navigationRefresh": False}

    def import_text(self, name: str, text: str) -> dict[str, Any]:
        label = Path(str(name or "uploaded-rift-report.json")).name[:255] or "uploaded-rift-report.json"
        raw = str(text or "").encode("utf-8")
        document = _decode_document(raw)
        source_key = f"upload:{label}:{hashlib.sha256(raw).hexdigest()}"
        report = _project_document(document, source=label, source_key=source_key, acquired_from="local-upload")
        with self._lock:
            self._imports[report["reportId"]] = report
        return report

    def import_github(self, url: str, *, token: str = "", opener: Any = None) -> dict[str, Any]:
        raw = _read_github_json(url, token=token, opener=opener)
        document = _decode_document(raw)
        parsed = urllib.parse.urlparse(str(url).strip())
        label = Path(parsed.path).name or "github-rift-report.json"
        source_key = f"github:{str(url).strip()}:{hashlib.sha256(raw).hexdigest()}"
        report = _project_document(document, source=label, source_key=source_key, acquired_from="github-link")
        report["sourceUrl"] = str(url).strip()
        with self._lock:
            self._imports[report["reportId"]] = report
        return report

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            reports = [dict(report) for report in self._configured] + [dict(report) for report in self._imports.values()]
        reports.sort(key=lambda report: (report.get("ranAt") or "", report.get("source") or ""), reverse=True)
        reviewable = [report for report in reports if report.get("status") == "reviewable"]
        return {
            "schema": RIFT_REVIEW_SCHEMA,
            "readOnly": True,
            "mutationAuthority": "none",
            "reports": reports,
            "reportCount": len(reports),
            "reviewableCount": len(reviewable),
            "observationCount": sum(_integer(report.get("observationCount")) for report in reviewable),
            "configuredReportCount": len(self._configured),
            "sessionImportCount": len(self._imports),
            "navigationRefresh": False,
            "refreshPolicy": "explicit-intake-or-rift-only-refresh",
            "notice": (
                "Rift observations are neutral runtime evidence. Imported reports are held in this local DeltaScope "
                "session; changing pages never rereads an uploaded file or refetches GitHub."
            ),
        }

    def acquisition_status(self) -> dict[str, Any]:
        snap = self.snapshot()
        return {
            "sourceId": "rift-runtime",
            "label": "Rift runtime reports",
            "loaded": bool(snap["reportCount"]),
            "cachePolicy": "explicit-refresh",
            "navigationRefresh": False,
            "configuredReportCount": snap["configuredReportCount"],
            "sessionImportCount": snap["sessionImportCount"],
            "reportCount": snap["reportCount"],
        }


def _github_repository_key(value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > MAX_GITHUB_URL_CHARS:
        return ""
    parsed = urllib.parse.urlparse(text if "://" in text else f"https://{text}")
    host = (parsed.hostname or "").casefold()
    if host not in {"github.com", "www.github.com", "raw.githubusercontent.com"}:
        return ""
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return ""
    owner, repo = parts[0].casefold(), parts[1].casefold()
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"{owner}/{repo}" if owner and repo else ""


def _row_repository_candidates(row: Mapping[str, Any]) -> tuple[object, ...]:
    return tuple(row.get(key) for key in (
        "repo_url", "repository", "repository_url", "source_repository", "source_code_repository",
        "source_url", "repoUrl", "sourceRepository",
    ))


def resolve_catalog_plugin_link(inspector: Any, value: object) -> dict[str, Any]:
    """Resolve a GitHub link to catalog InternalName without widening the scanner contract."""
    url = str(value or "").strip()
    key = _github_repository_key(url)
    if not key:
        raise ValueError("plugin link must be a GitHub repository, release, or file URL")
    matches: dict[str, dict[str, Any]] = {}

    try:
        rows = inspector.list_plugins(limit=5000, offset=0)
    except TypeError:
        rows = inspector.list_plugins(limit=5000)
    except Exception:
        rows = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, Mapping):
            continue
        if key not in {_github_repository_key(candidate) for candidate in _row_repository_candidates(row) if candidate}:
            continue
        internal = _text(row.get("internal_name") or row.get("internalName"))
        if not internal:
            continue
        matches[internal.casefold()] = {
            "internalName": internal,
            "plugin": _text(row.get("canonical_name") or row.get("name")) or internal,
            "variantId": _integer(row.get("variant_id") or row.get("variantId")),
            "repository": key,
        }

    # Evidence-v2 keeps exact catalog identity maps locally.  Use them as a read-only
    # fallback rather than changing list/search semantics in the inspector itself.
    if hasattr(inspector, "_load_identity_maps"):
        try:
            maps = inspector._load_identity_maps()
            plugins = maps.get("plugins") or {}
            for variant_id, variant in (maps.get("variants") or {}).items():
                if not isinstance(variant, Mapping):
                    continue
                if key not in {_github_repository_key(candidate) for candidate in _row_repository_candidates(variant) if candidate}:
                    continue
                plugin = plugins.get(_integer(variant.get("plugin_id")), {})
                internal = _text(plugin.get("internal_name") if isinstance(plugin, Mapping) else "")
                if internal:
                    matches[internal.casefold()] = {
                        "internalName": internal,
                        "plugin": _text(plugin.get("canonical_name") if isinstance(plugin, Mapping) else "") or internal,
                        "variantId": _integer(variant_id),
                        "repository": key,
                    }
        except Exception:
            pass

    # Legacy/local SQLite view: query the catalog relation directly when available.
    db = getattr(inspector, "db", None)
    if db is not None:
        try:
            for row in db.execute(
                "SELECT p.internal_name,p.canonical_name,v.variant_id,v.repo_url,s.url AS source_url "
                "FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id "
                "LEFT JOIN sources s ON s.source_id=v.source_id"
            ).fetchall():
                mapping = dict(row) if not isinstance(row, dict) else row
                if key not in {_github_repository_key(candidate) for candidate in _row_repository_candidates(mapping) if candidate}:
                    continue
                internal = _text(mapping.get("internal_name"))
                if internal:
                    matches[internal.casefold()] = {
                        "internalName": internal,
                        "plugin": _text(mapping.get("canonical_name")) or internal,
                        "variantId": _integer(mapping.get("variant_id")),
                        "repository": key,
                    }
        except Exception:
            pass

    resolved = sorted(matches.values(), key=lambda item: (item["internalName"].casefold(), item["variantId"]))
    return {
        "schema": "omega.deltascope.plugin-link-resolution.v1",
        "readOnly": True,
        "mutationAuthority": "none",
        "inputUrl": url,
        "repository": key,
        "matched": bool(resolved),
        "matches": resolved,
        "internalNames": [item["internalName"] for item in resolved],
        "dispatchContract": "internal_names",
        "notice": (
            "Resolved against the loaded Omega catalog. DeltaScope will populate the existing internal_names workflow input; it does not add a scanner-side URL bypass."
            if resolved else
            "No loaded catalog plugin maps to this GitHub repository. DeltaScope will not dispatch an arbitrary URL outside the existing scanner contract."
        ),
    }


_LOGICAL_PLUGIN_JS = r'''
function logicalPluginDivergenceHtml(ctx){const d=ctx?.divergence;if(!d||!Array.isArray(d.signals))return'';const state=String(d.state||'aligned'),cls=state==='review'?'warn':state==='aligned'||state==='single'?'pass':'informational';const signals=d.signals.map(sig=>{const level=String(sig.level||'info'),ids=Array.isArray(sig.variantIds)?sig.variantIds:[],buttons=ids.length?`<div class=logical-divergence-actions>${ids.map(vid=>`<button data-open-logical-variant="${Number(vid)}">Variant ${fmt(vid)}</button>`).join('')}</div>`:'';return `<div class="logical-divergence-signal ${esc(level)}"><b>${esc(sig.label||sig.kind||'Variant difference')}</b><div class="muted small">${esc(sig.detail||'')}</div>${buttons}</div>`}).join('');return `<div class="logical-divergence ${esc(state)}"><div class=logical-divergence-head><div><div class=logical-divergence-kicker>Cross-source comparison · read only</div><h4>${esc(d.headline||'Sibling variant comparison')}</h4><div class="muted small">${esc(d.explanation||'')}</div></div><span class="pill ${cls}">${esc(state.toUpperCase())}</span></div><div class=logical-divergence-summary><span><b>${fmt(d.comparableVariantCount||0)}</b> comparable</span><span><b>${fmt(d.coveredVariantCount||0)}</b> covered</span><span><b>${fmt(d.sourceCount||0)}</b> sources</span><span><b>${fmt(d.versionCount||0)}</b> versions</span></div><div class=logical-divergence-signals>${signals}</div><div class="muted small">Differences are review/navigation cues only. They do not create SigmaScope findings or source trust verdicts.</div></div>`}
function logicalPluginVariantsHtml(d,id){const ctx=d.catalogContext||{},raw=Array.isArray(ctx.variants)?ctx.variants:[];if(!raw.length)return'';const rank={'current':0,'unknown':1,'testing-current':2,'outdated':3,'future':4,'hidden':5,'retired':6},variants=[...raw].sort((a,b)=>{const av=Number(a.variant_id||0),bv=Number(b.variant_id||0),as=av===Number(id),bs=bv===Number(id);if(as!==bs)return as?-1:1;const ar=rank[variantCompatibilityState(a)]??9,br=rank[variantCompatibilityState(b)]??9;if(ar!==br)return ar-br;return String(a.source_name||a.source_provider||a.source_url||'').localeCompare(String(b.source_name||b.source_provider||b.source_url||''))});const covered=Number(ctx.currentEvidenceVariantCount??variants.filter(v=>v.currentEvidence).length),activeTotal=Number(ctx.activeVariantCount||0),shown=Number(ctx.shownVariantCount||variants.length),isHistorical=ctx.variantScope==='historical'||ctx.catalogActive===false,sources=new Set(variants.map(v=>String(v.source_id||v.source_name||v.source_url||'')).filter(Boolean)).size;const rows=variants.map(v=>{const vid=Number(v.variant_id||0),has=!!v.currentEvidence,status=has?String(v.evidenceStatus||'complete').toUpperCase():'NO CURRENT EVIDENCE',severity=has?String(v.evidenceHighestSeverity||'none').toUpperCase():'UNSCANNED',source=v.source_name||v.source_provider||(v.source_id?`Source ${v.source_id}`:'Catalog source'),version=v.assembly_version||v.evidenceAssemblyVersion||'—',api=Number(v.dalamud_api_level||0),repo=v.repo_url||v.source_url||'',selected=vid===Number(id),compat=variantCompatibilityState(v),hash=String(v.evidenceArtifactSha256||'');return `<tr class="${selected?'selected-row':''}"><td><b>${fmt(vid)}</b>${selected?' <span class=pill>selected</span>':''}<div class="muted small">${esc(source)}</div></td><td>${esc(version)}${api?`<div class="muted small">API ${fmt(api)}</div>`:''}<span class="plugin-picker-compat ${esc(compat)}">${esc(variantCompatibilityLabel(v))}</span></td><td>${repo?`<span title="${esc(repo)}">${esc(repo.length>48?repo.slice(0,45)+'…':repo)}</span>`:'—'}</td><td><span class="pill ${has?sev(v.evidenceHighestSeverity):'warn'}">${esc(severity)}</span><div class="muted small">${esc(status)}${v.evidenceScanId?` · scan ${fmt(v.evidenceScanId)}`:''}${hash?` · ${esc(hash.slice(0,10))}…`:''}</div></td><td><button data-open-logical-variant="${vid}" ${selected?'disabled':''}>${selected?'Open':'Inspect variant'}</button></td></tr>`}).join('');const totalLabel=isHistorical?`${shown} retained variant${shown===1?'':'s'}`:`${activeTotal||shown} active variant${(activeTotal||shown)===1?'':'s'}`;return `<div class="research-box logical-plugin-context"><div class=section-heading><div><h4>${isHistorical?'Historical catalog variants':'Current catalog variants'}</h4><div class="muted small">My Plugins shows one logical plugin. Source/build/version variants remain visible here, including their API compatibility and exact Evidence-v2 coverage, so logical grouping never hides materially different repository subjects.</div></div><span class=pill>plugin ${fmt(ctx.pluginId||d.identity?.plugin_id||0)}</span></div>${logicalPluginDivergenceHtml(ctx)}<div class=case-summary><span class=pill><b>${esc(totalLabel)}</b></span><span class=pill><b>${fmt(sources)}</b> source${sources===1?'':'s'}</span><span class="pill ${covered<(activeTotal||shown)?'warn':'pass'}"><b>${fmt(covered)}/${fmt(activeTotal||shown)}</b> current evidence</span><span class=pill>target API ${fmt(myPluginPreferences.apiLevel)}</span></div><table><thead><tr><th>Variant / source</th><th>Version / compatibility</th><th>Repository</th><th>Evidence</th><th></th></tr></thead><tbody>${rows}</tbody></table><div class="muted small" style="margin-top:8px">Identity authority remains catalog <code>plugin_id</code>; API compatibility controls developer-picker visibility only. It never changes security findings, scan eligibility, or Catalog identity.</div></div>`}
'''

_COMPAT_JS = r'''
setTimeout(()=>{
 const css=document.createElement('style');css.textContent='.rift-intake{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:12px;border:1px solid #e0e0e0;background:#fff}.rift-intake-box{display:grid;gap:7px;padding:10px;background:#f4f4f4;border-left:4px solid #0f62fe}.rift-intake-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px}.github-plugin-link-helper{display:grid;gap:7px;padding:10px;border-left:4px solid #0f62fe;background:#edf5ff}.github-plugin-link-helper>div:first-child{display:grid;gap:2px}.github-plugin-link-helper span{font-size:11px;color:#525252}.github-plugin-link-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px}@media(max-width:780px){.rift-intake{grid-template-columns:1fr}.rift-intake-row,.github-plugin-link-row{grid-template-columns:1fr}}';document.head.appendChild(css);
 function installRiftIntake(){const view=$('workbench-rift-reports'),notice=$('riftReviewNotice');if(!view||!notice||$('riftIntakeCompat'))return false;notice.insertAdjacentHTML('afterend',`<section id=riftIntakeCompat class=rift-intake><div class=rift-intake-box><b>Open local Rift report</b><div class="muted small">Import once into this DeltaScope session. Changing pages only reads the local snapshot; it never rereads the file.</div><div class=rift-intake-row><input id=riftFileInputCompat type=file accept=".json,application/json"><button id=riftImportFileCompat disabled>Import file</button></div></div><div class=rift-intake-box><b>Open Rift report from GitHub</b><div class="muted small">Use a GitHub JSON file link. The report is fetched once and retained in this local session.</div><div class=rift-intake-row><input id=riftGithubUrlCompat type=url placeholder="https://github.com/owner/repo/blob/main/runtime-report.json"><button id=riftImportGithubCompat>Import link</button></div></div><div id=riftIntakeStatusCompat class="muted small" style="grid-column:1/-1">Rift intake is independent from normal page navigation and from the other data-source refreshes.</div></section>`);const file=$('riftFileInputCompat'),fileButton=$('riftImportFileCompat'),url=$('riftGithubUrlCompat'),urlButton=$('riftImportGithubCompat'),status=$('riftIntakeStatusCompat');file.addEventListener('change',()=>{fileButton.disabled=!file.files?.length});async function intake(payload){status.textContent='Importing report into the local snapshot…';try{const result=await api('/api/workbench/rift-reports/intake',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});status.textContent=`Imported ${result.report?.source||'Rift report'} · page changes reuse this snapshot.`;await window.deltaScopeRift?.load?.();return true}catch(error){status.textContent=`Import failed: ${error.message}`;return false}}fileButton.addEventListener('click',async()=>{const item=file.files?.[0];if(!item)return;if(item.size>1500*1024){status.textContent='Import failed: report exceeds the 1500 KiB local intake limit.';return}if(await intake({kind:'file',name:item.name,content:await item.text()})){file.value='';fileButton.disabled=true}});urlButton.addEventListener('click',async()=>{const value=url.value.trim();if(!value){status.textContent='Paste a GitHub JSON file link first.';return}if(await intake({kind:'github',url:value}))url.value=''});const refresh=$('riftRefresh');if(refresh){refresh.textContent='Reload configured files';refresh.title='Explicitly reread only the configured Rift report paths';refresh.addEventListener('click',async event=>{event.preventDefault();event.stopImmediatePropagation();refresh.disabled=true;try{await api('/api/acquisition/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:'rift-runtime'})});await window.deltaScopeRift?.load?.();status.textContent='Configured Rift paths reloaded. Session imports were kept.'}catch(error){status.textContent=`Rift refresh failed: ${error.message}`}finally{refresh.disabled=false}},true)}return true}
 let attempts=0;const riftTimer=setInterval(()=>{attempts++;if(installRiftIntake()||attempts>80)clearInterval(riftTimer)},25);
 const renderDataSources0015=renderDataSources;renderDataSources=function(payload){renderDataSources0015(payload);const host=$('dataSourceRows');if(!host||!payload?.rift||host.querySelector('[data-acquisition-source="rift-runtime"]'))return;host.insertAdjacentHTML('beforeend',acquisitionSourceHtml(payload.rift,'rift-runtime'));host.querySelector('[data-acquisition-source="rift-runtime"] [data-refresh-source]')?.addEventListener('click',()=>refreshDataSources('rift-runtime'))};
 function ensurePluginLinkHelper(){const host=$('githubDispatchDeclaredInputs');if(!host)return;const fields=[...host.querySelectorAll('[data-workflow-input]')],names=new Set(fields.map(field=>String(field.dataset.workflowInput||''))),direct=['plugin_url','artifact_url','repository_url','repo_url'].find(name=>names.has(name));if(!names.has('internal_names')&&!direct){host.querySelector('[data-plugin-link-helper-compat]')?.remove();return}if(host.querySelector('[data-plugin-link-helper-compat]'))return;const helper=document.createElement('div');helper.dataset.pluginLinkHelperCompat='1';helper.className='github-plugin-link-helper';helper.innerHTML=`<div><b>Plugin GitHub link</b><span>Resolve a repository/release/file link into the workflow's declared scan input. DeltaScope never invents an undeclared scanner parameter.</span></div><div class=github-plugin-link-row><input type=url data-plugin-scan-link-compat placeholder="https://github.com/owner/plugin"><button type=button data-resolve-plugin-scan-compat>${direct?'Use declared URL input':'Resolve to catalog plugin'}</button></div><div class="muted small" data-plugin-scan-status-compat>${direct?`This workflow declares <code>${esc(direct)}</code>. The link will populate that exact input.`:'For SigmaScope this resolves the loaded catalog repository to the existing <code>internal_names</code> contract.'}</div>`;const head=host.querySelector('.github-form-head');head?.after(helper);const input=helper.querySelector('[data-plugin-scan-link-compat]'),button=helper.querySelector('[data-resolve-plugin-scan-compat]'),message=helper.querySelector('[data-plugin-scan-status-compat]');button.addEventListener('click',async()=>{const value=String(input.value||'').trim();if(!value){message.textContent='Paste a GitHub plugin link first.';return}if(direct){const target=host.querySelector(`[data-workflow-input="${direct}"]`);if(target){target.value=value;target.dispatchEvent(new Event('input',{bubbles:true}));message.innerHTML=`Populated declared <code>${esc(direct)}</code>.`;return}}message.textContent='Resolving against the loaded Omega catalog…';try{const result=await api(`/api/operations/plugin-link?url=${encodeURIComponent(value)}`);if(!result.matched){message.textContent=result.notice||'No catalog plugin matched this repository.';return}const target=host.querySelector('[data-workflow-input="internal_names"]');if(!target){message.textContent='The selected workflow has no compatible declared scan input.';return}target.value=(result.internalNames||[]).join(',');target.dispatchEvent(new Event('input',{bubbles:true}));message.textContent=`Resolved ${(result.internalNames||[]).join(', ')} through the existing internal_names contract.`}catch(error){message.textContent=`Could not resolve plugin link: ${error.message}`}})}
 let workflowAttempts=0;const workflowTimer=setInterval(()=>{workflowAttempts++;const host=$('githubDispatchDeclaredInputs');if(host){ensurePluginLinkHelper();new MutationObserver(()=>ensurePluginLinkHelper()).observe(host,{childList:true,subtree:true})}if(host||workflowAttempts>80)clearInterval(workflowTimer)},25);
},0);
'''


def _patch_html(html: str) -> str:
    text = str(html)
    additions = ""
    if "function logicalPluginVariantsHtml(" not in text:
        additions += _LOGICAL_PLUGIN_JS
    if "data-plugin-link-helper-compat" not in text:
        additions += _COMPAT_JS
    if not additions:
        return text
    marker = "</script>"
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError("DeltaScope HTML script boundary was not found")
    return text[:index] + "\n" + additions + "\n" + text[index:]


def _rift_store(handler: Any) -> RiftReportStore:
    cls = handler.__class__
    store = getattr(cls, "_deltascope_0015_rift_store", None)
    if store is None:
        store = RiftReportStore(getattr(handler, "rift_report_paths", ()))
        setattr(cls, "_deltascope_0015_rift_store", store)
    return store


def _acquisition_payload(handler: Any) -> dict[str, Any]:
    published = handler.inspector.source_status(check_remote=False) if hasattr(handler.inspector, "source_status") else {
        "mode": "sqlite", "currentRevision": "", "currentDefinitionsRevision": "", "generatedAtUtc": ""
    }
    github = handler.operations_client.snapshot_status() if getattr(handler, "operations_client", None) else {
        "schema": "omega.deltascope.github-acquisition-state.v1",
        "sourceId": "github-actions", "label": "GitHub Actions", "loaded": False,
        "cachePolicy": "explicit-refresh", "navigationRefresh": False, "available": False,
        "error": "GitHub status disabled",
    }
    public_git = handler.public_git_monitor.snapshot_status()
    return {
        "schema": "omega.deltascope.data-acquisition.v1",
        "readOnly": True,
        "mutationAuthority": "none",
        "navigationRefresh": False,
        "refreshPolicy": "explicit-only",
        "published": {
            "sourceId": "published-security", "label": "Published security state", "loaded": True,
            "cachePolicy": "explicit-refresh", "navigationRefresh": False,
            "fetchedAtUtc": str(published.get("generatedAtUtc") or ""),
            "currentRevision": str(published.get("currentRevision") or ""),
            "definitionsRevision": str(published.get("currentDefinitionsRevision") or ""),
            "mode": str(published.get("mode") or "local"),
        },
        "github": github,
        "publicGit": public_git,
        "rift": _rift_store(handler).acquisition_status(),
    }


def _read_json_body(handler: Any, *, maximum: int) -> dict[str, Any]:
    declared = max(0, int(handler.headers.get("Content-Length") or 0))
    if declared > maximum:
        raise ValueError("request body exceeds the DeltaScope local API safety bound")
    body = handler.rfile.read(declared) if declared else b"{}"
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"request body is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    return payload


def install() -> None:
    import developer_view

    if getattr(developer_view, "_deltascope_0015_compat_installed", False):
        return
    developer_view.HTML = _patch_html(developer_view.HTML)
    original_get = developer_view.AppHandler.do_GET
    original_post = developer_view.AppHandler.do_POST

    def patched_get(self: Any) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path == "/api/workbench/rift-reports":
                return self.json_response(_rift_store(self).snapshot())
            if parsed.path == "/api/operations/plugin-link":
                return self.json_response(resolve_catalog_plugin_link(self.inspector, (query.get("url") or [""])[0]))
            if parsed.path == "/api/acquisition":
                return self.json_response(_acquisition_payload(self))
        except ValueError as exc:
            return self.json_response({"error": str(exc)}, 400)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)
        return original_get(self)

    def patched_post(self: Any) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path not in {"/api/workbench/rift-reports/intake", "/api/acquisition/refresh"}:
            return original_post(self)
        try:
            declared = max(0, int(self.headers.get("Content-Length") or 0))
            maximum = 4 * 1024 * 1024 if path == "/api/workbench/rift-reports/intake" else 2 * 1024 * 1024
            if declared > maximum:
                raise ValueError("request body exceeds the DeltaScope local API safety bound")
            raw_body = self.rfile.read(declared) if declared else b"{}"
            try:
                payload = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"request body is not valid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            if path == "/api/workbench/rift-reports/intake":
                kind = _text(payload.get("kind")).casefold()
                store = _rift_store(self)
                if kind == "file":
                    report = store.import_text(_text(payload.get("name")) or "rift-report.json", str(payload.get("content") or ""))
                elif kind == "github":
                    token = _text(getattr(getattr(self, "operations_client", None), "token", ""))
                    report = store.import_github(_text(payload.get("url")), token=token)
                else:
                    raise ValueError("Rift intake kind must be file or github")
                return self.json_response({
                    "accepted": True,
                    "report": report,
                    "snapshot": store.snapshot(),
                    "navigationRefresh": False,
                })
            source_id = _text(payload.get("source") or "all").casefold()
            if source_id != "rift-runtime":
                # Hand the exact body back to the original handler so the established
                # published/GitHub/public-Git refresh contracts remain untouched.
                self.rfile = io.BytesIO(raw_body)
                return original_post(self)
            refreshed = _rift_store(self).reload_configured()
            return self.json_response({
                "schema": "omega.deltascope.data-acquisition-refresh.v1",
                "source": source_id,
                "refreshed": {"rift": refreshed},
                "navigationRefresh": False,
                "refreshPolicy": "rift-only-explicit",
            })
        except ValueError as exc:
            return self.json_response({"error": str(exc)}, 400)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get
    developer_view.AppHandler.do_POST = patched_post
    developer_view._deltascope_0015_compat_installed = True
