#!/usr/bin/env python3
"""Bounded GitHub Actions status and explicitly confirmed dispatch support for DeltaScope.

Public status remains the default. Optional authenticated workflow access can be remembered
locally by DeltaScope (Windows uses current-user DPAPI; other platforms use a user-only 0600
credential file) or supplied by the process environment. The token is never returned to the
browser. Starting a workflow is limited to ``workflow_dispatch`` and requires explicit confirmation.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml
from typing import Any, Callable, Iterable, Mapping

SCHEMA = "omega.deltascope.operations.v1"
DEFAULT_REPOSITORY = "dalagab/omega"
DEFAULT_TTL_SECONDS = 60
GITHUB_CREDENTIAL_SCHEMA = "omega.deltascope.github-credential.v1"
DEFAULT_GITHUB_CREDENTIAL_ROOT = Path(".omega") / "deltascope" / "github" / "v1"
MAX_RUNS = 50
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_WORKFLOW_DEFINITION_BYTES = 512 * 1024
MAX_JOB_LOG_BYTES = 2 * 1024 * 1024
MAX_WORKFLOW_HISTORY = 8
CLIENT_RELEASE_TAG = "catalog-latest"
CLIENT_BUILD_ASSET = "database-build.json"
RUNNING_STATES = {"queued", "in_progress", "requested", "waiting", "pending"}
FAIL_CONCLUSIONS = {"failure", "timed_out", "action_required", "startup_failure"}
WARN_CONCLUSIONS = {"cancelled", "neutral", "stale"}
EXPECTED_COMPONENTS: tuple[tuple[str, str], ...] = (
    ("sigmascope", "SigmaScope"),
    ("omega-builds", "Omega builds"),
    ("catalog-definitions", "Catalog / Definitions"),
    ("deltascope", "DeltaScope"),
    ("stigma-1", "Stigma-1"),
    ("deep-scan", "Deep Scan"),
    ("security-regression", "Security regression"),
    ("source-intake", "Source intake"),
)



def default_github_credential_root() -> Path:
    override = os.environ.get("OMEGA_DELTASCOPE_GITHUB_CREDENTIAL_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / DEFAULT_GITHUB_CREDENTIAL_ROOT).resolve()


def _credential_file_name(repository: str) -> str:
    digest = hashlib.sha256(repository.encode("utf-8")).hexdigest()[:16]
    return f"credential-{digest}.json"


def _protect_token(raw: bytes) -> tuple[str, bytes]:
    """Protect a remembered token for the current local user where the OS supports it."""
    if os.name != "nt":
        return "filesystem-mode-0600", raw
    try:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        source = ctypes.create_string_buffer(raw)
        source_blob = DATA_BLOB(len(raw), ctypes.cast(source, ctypes.POINTER(ctypes.c_byte)))
        output_blob = DATA_BLOB()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptProtectData(ctypes.byref(source_blob), "Omega DeltaScope GitHub access", None, None, None, 0, ctypes.byref(output_blob)):
            raise OSError(ctypes.get_last_error(), "CryptProtectData failed")
        try:
            protected = ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)
        return "windows-dpapi-current-user", protected
    except Exception as exc:
        raise RuntimeError(f"Windows could not protect the remembered GitHub credential: {exc}") from exc


def _unprotect_token(protection: str, raw: bytes) -> bytes:
    if protection == "filesystem-mode-0600":
        if os.name == "nt":
            raise ValueError("plaintext filesystem GitHub credentials are not accepted on Windows")
        return raw
    if protection != "windows-dpapi-current-user" or os.name != "nt":
        raise ValueError("remembered GitHub credential uses an unsupported protection mode")
    try:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        source = ctypes.create_string_buffer(raw)
        source_blob = DATA_BLOB(len(raw), ctypes.cast(source, ctypes.POINTER(ctypes.c_byte)))
        output_blob = DATA_BLOB()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptUnprotectData(ctypes.byref(source_blob), None, None, None, None, 0, ctypes.byref(output_blob)):
            raise OSError(ctypes.get_last_error(), "CryptUnprotectData failed")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)
    except Exception as exc:
        raise RuntimeError(f"Windows could not unlock the remembered GitHub credential: {exc}") from exc


class LocalGitHubCredentialStore:
    """Small local credential store used only to remember optional GitHub workflow access."""

    def __init__(self, repository: str, root: Path | None = None) -> None:
        self.repository = repository
        self.root = (root or default_github_credential_root()).expanduser().resolve()
        self.path = self.root / _credential_file_name(repository)

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("DeltaScope GitHub credential root may not be a symlink")
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def load(self) -> str:
        if not self.path.exists():
            return ""
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("DeltaScope GitHub credential file must be a regular file")
        document = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(document, Mapping) or document.get("schema") != GITHUB_CREDENTIAL_SCHEMA:
            raise ValueError("DeltaScope GitHub credential file has an invalid schema")
        if str(document.get("repository") or "") != self.repository:
            raise ValueError("DeltaScope GitHub credential does not belong to this repository")
        protection = str(document.get("protection") or "")
        try:
            protected = base64.b64decode(str(document.get("token") or ""), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("DeltaScope GitHub credential payload is invalid") from exc
        token = _unprotect_token(protection, protected).decode("utf-8")
        if not token or len(token) > 4096 or any(ch.isspace() for ch in token):
            raise ValueError("remembered GitHub token format is invalid")
        return token

    def save(self, token: str) -> None:
        token = str(token or "").strip()
        if not token:
            self.clear()
            return
        self._ensure_root()
        protection, protected = _protect_token(token.encode("utf-8"))
        document = {
            "schema": GITHUB_CREDENTIAL_SCHEMA,
            "repository": self.repository,
            "protection": protection,
            "token": base64.b64encode(protected).decode("ascii"),
        }
        data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            with tmp.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def clear(self) -> None:
        if self.path.is_symlink():
            raise ValueError("DeltaScope GitHub credential file may not be a symlink")
        self.path.unlink(missing_ok=True)

    def descriptor(self) -> dict[str, Any]:
        return {
            "rememberSupported": True,
            "credentialProtection": "windows-dpapi-current-user" if os.name == "nt" else "filesystem-mode-0600",
        }

def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _component(path: str, name: str, branch: str) -> tuple[str, str]:
    key = f"{path} {name}".casefold()
    if "sigmascope.yml" in key or "sigmascope continuous" in key:
        return "sigmascope", "SigmaScope"
    if "catalog-builder.yml" in key or "catalog snapshot" in key:
        return "catalog-definitions", "Catalog / Definitions"
    if "deltascope.yml" in key or "deltascope developer" in key:
        return "deltascope", "DeltaScope"
    if "deep-scan.yml" in key or "deep scan" in key:
        return "deep-scan", "Deep Scan"
    if "regression-tests.yml" in key or "security services regression" in key:
        return "security-regression", "Security regression"
    if "srl-cutover" in key or "rule-candidates" in key or "stigma" in key or " srl " in f" {key} ":
        return "stigma-1", "Stigma-1"
    if "source-submissions" in key or "source submissions" in key:
        return "source-intake", "Source intake"
    if "catalog-compaction" in key:
        return "legacy-compactor", "Legacy compactor"
    # The main branch contains client/build workflows that are intentionally not copied
    # into the security branch. Keep them visible rather than dropping unknown workflows.
    if branch == "main" or "omega" in key:
        return "omega-builds", "Omega builds"
    return "other", name or "Other workflow"


def _state(run: Mapping[str, Any]) -> tuple[str, str]:
    status = str(run.get("status") or "").casefold()
    conclusion = str(run.get("conclusion") or "").casefold()
    if status in RUNNING_STATES:
        return "running", status
    if conclusion in FAIL_CONCLUSIONS:
        return "failed", conclusion
    if conclusion in WARN_CONCLUSIONS:
        return "warning", conclusion
    if conclusion == "success":
        return "healthy", conclusion
    if conclusion in {"skipped"}:
        return "idle", conclusion
    return "unknown", conclusion or status or "unknown"


def normalize_run(run: Mapping[str, Any]) -> dict[str, Any]:
    path = str(run.get("path") or "")
    name = str(run.get("name") or "")
    branch = str(run.get("head_branch") or "")
    component_id, component = _component(path, name, branch)
    state, detail = _state(run)
    display = str(run.get("display_title") or name or "Workflow run")
    raw_url = str(run.get("html_url") or "")
    url = raw_url if raw_url.startswith("https://github.com/") else ""
    return {
        "runId": int(run.get("id") or 0),
        "runNumber": int(run.get("run_number") or 0),
        "attempt": int(run.get("run_attempt") or 1),
        "componentId": component_id,
        "component": component,
        "workflow": name,
        "workflowPath": path,
        "title": display,
        "event": str(run.get("event") or ""),
        "branch": branch,
        "sha": str(run.get("head_sha") or ""),
        "status": str(run.get("status") or ""),
        "conclusion": str(run.get("conclusion") or ""),
        "state": state,
        "stateDetail": detail,
        "createdAtUtc": str(run.get("created_at") or ""),
        "updatedAtUtc": str(run.get("updated_at") or ""),
        "url": url,
        "readOnly": True,
    }


def project_runs(repository: str, runs: list[Mapping[str, Any]], *, fetched_at_utc: str = "", source: str = "github-actions-public-api") -> dict[str, Any]:
    normalized = [normalize_run(run) for run in runs[:MAX_RUNS] if isinstance(run, Mapping)]
    normalized.sort(key=lambda row: (row["createdAtUtc"], row["runId"]), reverse=True)

    latest_by_component: dict[str, dict[str, Any]] = {}
    running_by_component: dict[str, list[dict[str, Any]]] = {}
    for run in normalized:
        component_id = str(run["componentId"])
        latest_by_component.setdefault(component_id, run)
        if run["state"] == "running":
            running_by_component.setdefault(component_id, []).append(run)

    components: list[dict[str, Any]] = []
    expected = dict(EXPECTED_COMPONENTS)
    component_ids = list(expected) + [key for key in latest_by_component if key not in expected]
    for component_id in component_ids:
        latest = latest_by_component.get(component_id)
        running = running_by_component.get(component_id) or []
        effective = running[0] if running else latest
        components.append({
            "componentId": component_id,
            "component": str((effective or {}).get("component") or (latest or {}).get("component") or expected.get(component_id) or component_id),
            "state": "running" if running else str((latest or {}).get("state") or "unknown"),
            "stateDetail": str((effective or {}).get("stateDetail") or ("not observed in recent Actions history" if latest is None else "")),
            "runningCount": len(running),
            "latestRun": latest,
            "activeRun": effective if running else None,
            "observed": latest is not None,
            "readOnly": True,
        })
    order = {"sigmascope": 0, "omega-builds": 1, "catalog-definitions": 2, "deltascope": 3, "stigma-1": 4, "deep-scan": 5, "security-regression": 6, "source-intake": 7, "legacy-compactor": 8, "other": 9}
    components.sort(key=lambda row: (order.get(str(row.get("componentId")), 50), str(row.get("component") or "").casefold()))

    return {
        "schema": SCHEMA,
        "available": True,
        "readOnly": True,
        "mutationAuthority": "none",
        "source": source,
        "repository": repository,
        "fetchedAtUtc": fetched_at_utc or _utc_now(),
        "actionsRunning": sum(1 for run in normalized if run["state"] == "running"),
        "recentFailureCount": sum(1 for run in normalized[:20] if run["state"] == "failed"),
        "components": components,
        "events": normalized,
    }


class GitHubOperationsClient:
    """Fail-soft GitHub Actions acquisition snapshot for the local DeltaScope client.

    Network acquisition is explicit. Once a payload has been acquired it remains the
    process-local snapshot until a caller requests refresh=True (or credentials change).
    Normal page reads therefore never age out into surprise GitHub requests.
    """

    def __init__(
        self,
        repository: str = DEFAULT_REPOSITORY,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        token: str | None = None,
        opener: Callable[..., Any] | None = None,
        credential_store: LocalGitHubCredentialStore | None = None,
    ) -> None:
        repository = str(repository or DEFAULT_REPOSITORY).strip()
        if not repository or repository.count("/") != 1 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for ch in repository.replace("/", "")):
            raise ValueError("GitHub repository must use owner/name syntax")
        self.repository = repository
        self.ttl_seconds = max(10, min(900, int(ttl_seconds or DEFAULT_TTL_SECONDS)))
        self.credential_store = credential_store or LocalGitHubCredentialStore(repository)
        self._credential_error = ""
        environment_token = os.environ.get("OMEGA_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        remembered_token = ""
        if token is None and not environment_token:
            try:
                remembered_token = self.credential_store.load()
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                self._credential_error = str(exc)
        self.token = str(token if token is not None else environment_token or remembered_token).strip()
        self._token_source = (
            "session" if token is not None and self.token
            else "environment" if token is None and environment_token
            else "remembered" if token is None and remembered_token
            else "none"
        )
        self._opener = opener or urllib.request.urlopen
        self._lock = threading.RLock()
        self._cached_at = 0.0
        self._cache: dict[str, Any] | None = None
        self._workflow_cache: dict[tuple[Any, ...], tuple[float, dict[str, Any]]] = {}

    def _headers(self, *, accept: str = "application/vnd.github+json") -> dict[str, str]:
        headers = {
            "User-Agent": "Omega-DeltaScope/Collectors",
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request_json(self, url: str, *, timeout: float = 6.0, maximum: int = MAX_RESPONSE_BYTES, accept: str = "application/vnd.github+json") -> Mapping[str, Any]:
        request = urllib.request.Request(url, headers=self._headers(accept=accept))
        with self._opener(request, timeout=timeout) as response:
            raw = response.read(maximum + 1)
        if len(raw) > maximum:
            raise RuntimeError("GitHub Actions response exceeded the DeltaScope safety bound")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, Mapping):
            raise RuntimeError("GitHub Actions response was not an object")
        return payload

    def client_delivery(self, *, refresh: bool = False) -> dict[str, Any]:
        """Return the authenticated, explicitly acquired client release snapshot."""
        cache_key = ("client-delivery",)
        with self._lock:
            cached = self._workflow_cache.get(cache_key)
            if not refresh and cached:
                return dict(cached[1])
        if not self.token:
            return {
                "schema": "omega.deltascope.client-delivery.v1", "available": False,
                "authenticated": False, "repository": self.repository, "tag": CLIENT_RELEASE_TAG,
                "snapshotLoaded": False, "cachePolicy": "explicit-refresh",
                "error": "Connect authenticated GitHub access to inspect client delivery telemetry",
            }
        repository = urllib.parse.quote(self.repository, safe="/")
        release_url = f"https://api.github.com/repos/{repository}/releases/tags/{CLIENT_RELEASE_TAG}"
        try:
            release = self._request_json(release_url)
            raw_assets = release.get("assets") if isinstance(release.get("assets"), list) else []
            assets = []
            build_asset: Mapping[str, Any] | None = None
            for row in raw_assets:
                if not isinstance(row, Mapping):
                    continue
                name = str(row.get("name") or "")
                assets.append({
                    "name": name, "bytes": int(row.get("size") or 0),
                    "updatedAtUtc": str(row.get("updated_at") or ""),
                    "downloadCount": int(row.get("download_count") or 0),
                    "url": self._safe_github_url(row.get("browser_download_url")),
                })
                if name == CLIENT_BUILD_ASSET:
                    build_asset = row
            if build_asset is None or not str(build_asset.get("url") or "").startswith("https://api.github.com/"):
                raise RuntimeError(f"{CLIENT_BUILD_ASSET} is missing from release {CLIENT_RELEASE_TAG}")
            manifest = self._request_json(
                str(build_asset.get("url")), maximum=MAX_RESPONSE_BYTES,
                accept="application/octet-stream",
            )
            operations = self.status(refresh=False)
            publisher = next((
                dict(row) for row in operations.get("events") or []
                if isinstance(row, Mapping) and str(row.get("workflowPath") or "").replace("\\", "/").endswith("/catalog-client-publish.yml")
            ), None)
            result = {
                "schema": "omega.deltascope.client-delivery.v1", "available": True,
                "authenticated": True, "repository": self.repository, "tag": CLIENT_RELEASE_TAG,
                "release": {
                    "name": str(release.get("name") or CLIENT_RELEASE_TAG),
                    "publishedAtUtc": str(release.get("published_at") or ""),
                    "updatedAtUtc": str(release.get("updated_at") or ""),
                    "url": self._safe_github_url(release.get("html_url")), "assets": assets,
                },
                "manifest": dict(manifest), "publisherRun": publisher,
                "fetchedAtUtc": _utc_now(), "snapshotLoaded": True,
                "cachePolicy": "explicit-refresh", "readOnly": True, "mutationAuthority": "none",
            }
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            result = {
                "schema": "omega.deltascope.client-delivery.v1", "available": False,
                "authenticated": True, "repository": self.repository, "tag": CLIENT_RELEASE_TAG,
                "fetchedAtUtc": _utc_now(), "snapshotLoaded": True,
                "cachePolicy": "explicit-refresh", "error": str(exc),
            }
        with self._lock:
            self._workflow_cache[cache_key] = (time.monotonic(), dict(result))
        return result

    def _request(self, url: str, *, method: str = "GET", body: Mapping[str, Any] | None = None, timeout: float = 10.0) -> tuple[int, Mapping[str, Any]]:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
        headers = self._headers()
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=encoded, headers=headers, method=method)
        with self._opener(request, timeout=timeout) as response:
            status = int(getattr(response, "status", None) or getattr(response, "getcode", lambda: 200)() or 200)
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("GitHub response exceeded the DeltaScope safety bound")
        if not raw:
            return status, {}
        payload = json.loads(raw.decode("utf-8"))
        return status, payload if isinstance(payload, Mapping) else {}

    def configure_token(self, token: object, *, remember: bool = True) -> dict[str, Any]:
        value = str(token or "").strip()
        if value and (len(value) < 20 or len(value) > 4096 or any(ch.isspace() for ch in value)):
            raise ValueError("GitHub token format is invalid")
        if value and remember:
            self.credential_store.save(value)
        elif not value:
            self.credential_store.clear()
        with self._lock:
            self.token = value
            self._token_source = "remembered" if value and remember else "session" if value else "none"
            self._credential_error = ""
            self._cache = None
            self._cached_at = 0.0
            self._workflow_cache.clear()
        return self.access_status()

    def configure_session_token(self, token: object) -> dict[str, Any]:
        """Backward-compatible process-only configuration used by older callers/tests."""
        return self.configure_token(token, remember=False)

    def access_status(self) -> dict[str, Any]:
        persistence = (
            "local-credential" if self._token_source == "remembered"
            else "process-environment" if self._token_source == "environment"
            else "process-memory-only" if self._token_source == "session"
            else "none"
        )
        return {
            "schema": "omega.deltascope.github-access.v1",
            "repository": self.repository,
            "tokenConfigured": bool(self.token),
            "tokenPersistence": persistence,
            "tokenSource": self._token_source,
            "statusMode": "authenticated" if self.token else "public",
            "dispatchAvailable": bool(self.token),
            "dispatchConfirmation": "DISPATCH",
            "credentialError": self._credential_error,
            **self.credential_store.descriptor(),
        }

    def workflows(self, *, refresh: bool = False) -> dict[str, Any]:
        cache_key = ("workflows",)
        now = time.monotonic()
        with self._lock:
            cached = self._workflow_cache.get(cache_key)
            if not refresh:
                if cached:
                    return dict(cached[1])
                return {
                    "schema": "omega.deltascope.github-workflows.v1", "available": False,
                    "repository": self.repository, "workflows": [], "fetchedAtUtc": "",
                    "snapshotLoaded": False, "cachePolicy": "explicit-refresh",
                    "error": "GitHub workflow snapshot has not been acquired yet", **self.access_status(),
                }
        url = f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}/actions/workflows?per_page=100"
        try:
            payload = self._request_json(url)
            rows = payload.get("workflows") if isinstance(payload.get("workflows"), list) else []
            workflows = [{
                "id": int(row.get("id") or 0), "name": str(row.get("name") or "Workflow"),
                "path": str(row.get("path") or ""), "state": str(row.get("state") or "unknown"),
                "url": self._safe_github_url(row.get("html_url")),
            } for row in rows if isinstance(row, Mapping) and int(row.get("id") or 0) > 0]
            result = {"schema": "omega.deltascope.github-workflows.v1", "available": True, "repository": self.repository, "workflows": workflows, "fetchedAtUtc": _utc_now(), **self.access_status()}
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            result = {"schema": "omega.deltascope.github-workflows.v1", "available": False, "repository": self.repository, "workflows": [], "fetchedAtUtc": _utc_now(), "error": str(exc), **self.access_status()}
        with self._lock:
            self._workflow_cache[cache_key] = (now, dict(result))
        return result

    def workflow_dispatch_form(self, workflow_id: object, ref: object, *, refresh: bool = False) -> dict[str, Any]:
        """Project a workflow_dispatch declaration into a bounded client-side form schema."""
        try:
            workflow_number = int(workflow_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("workflow_id must be a GitHub workflow ID") from exc
        if workflow_number <= 0:
            raise ValueError("workflow_id must be positive")
        branch = str(ref or "").strip()
        if not branch or len(branch) > 255 or any(ch in branch for ch in "\r\n"):
            raise ValueError("ref must be a branch or tag name")

        cache_key = ("workflow-form", workflow_number, branch)
        now = time.monotonic()
        with self._lock:
            cached = self._workflow_cache.get(cache_key)
            if not refresh and cached:
                return dict(cached[1])

        workflow_payload = self.workflows(refresh=refresh)
        rows = workflow_payload.get("workflows") if isinstance(workflow_payload.get("workflows"), list) else []
        workflow = next((row for row in rows if isinstance(row, Mapping) and int(row.get("id") or 0) == workflow_number), None)
        if workflow is None:
            raise ValueError("workflow is not present in the current GitHub workflow inventory")
        path = str(workflow.get("path") or "").strip()
        if not path.startswith(".github/workflows/") or not path.casefold().endswith((".yml", ".yaml")):
            raise ValueError("workflow path is outside .github/workflows")

        url = (
            f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}"
            f"/contents/{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(branch, safe='')}"
        )
        try:
            source_payload = self._request_json(url)
            if str(source_payload.get("encoding") or "").casefold() != "base64":
                raise RuntimeError("GitHub workflow source was not returned as base64")
            encoded = "".join(str(source_payload.get("content") or "").split())
            try:
                source = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise RuntimeError("GitHub workflow source was not valid base64") from exc
            if len(source) > MAX_WORKFLOW_DEFINITION_BYTES:
                raise RuntimeError("GitHub workflow definition exceeded the DeltaScope safety bound")
            document = yaml.safe_load(source.decode("utf-8")) or {}
            if not isinstance(document, Mapping):
                raise RuntimeError("GitHub workflow definition was not a YAML object")

            # PyYAML 1.1 resolves the unquoted key `on` to True. Accept both forms
            # without changing the loader globally.
            triggers = document.get("on") if "on" in document else document.get(True)
            dispatch_config: Mapping[str, Any] = {}
            dispatchable = False
            if isinstance(triggers, str):
                dispatchable = triggers == "workflow_dispatch"
            elif isinstance(triggers, list):
                dispatchable = "workflow_dispatch" in [str(item) for item in triggers]
            elif isinstance(triggers, Mapping) and "workflow_dispatch" in triggers:
                dispatchable = True
                candidate = triggers.get("workflow_dispatch")
                dispatch_config = candidate if isinstance(candidate, Mapping) else {}

            raw_inputs = dispatch_config.get("inputs") if isinstance(dispatch_config.get("inputs"), Mapping) else {}
            form_inputs: list[dict[str, Any]] = []
            for name, raw_config in list(raw_inputs.items())[:25]:
                input_name = str(name).strip()
                if not input_name:
                    continue
                config = raw_config if isinstance(raw_config, Mapping) else {}
                input_type = str(config.get("type") or "string").strip().casefold()
                if input_type not in {"boolean", "choice", "environment", "number", "string"}:
                    input_type = "string"
                default = config.get("default")
                options = config.get("options") if isinstance(config.get("options"), list) else []
                form_inputs.append({
                    "name": input_name[:128],
                    "description": str(config.get("description") or "")[:1000],
                    "required": config.get("required") is True or str(config.get("required") or "").casefold() == "true",
                    "type": input_type,
                    "default": "" if default is None else str(default),
                    "options": [str(option)[:4096] for option in options[:100]],
                })
            result = {
                "schema": "omega.deltascope.workflow-dispatch-form.v1",
                "available": True,
                "dispatchable": dispatchable,
                "repository": self.repository,
                "workflowId": workflow_number,
                "workflowName": str(workflow.get("name") or "Workflow"),
                "path": path,
                "ref": branch,
                "inputs": form_inputs if dispatchable else [],
                "readOnly": True,
                "mutationAuthority": "none",
                "fetchedAtUtc": _utc_now(),
            }
        except (OSError, UnicodeDecodeError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, yaml.YAMLError) as exc:
            result = {
                "schema": "omega.deltascope.workflow-dispatch-form.v1",
                "available": False,
                "dispatchable": False,
                "repository": self.repository,
                "workflowId": workflow_number,
                "workflowName": str(workflow.get("name") or "Workflow"),
                "path": path,
                "ref": branch,
                "inputs": [],
                "readOnly": True,
                "mutationAuthority": "none",
                "fetchedAtUtc": _utc_now(),
                "error": str(exc),
            }
        with self._lock:
            self._workflow_cache[cache_key] = (now, dict(result))
        return result

    def dispatch_workflow(self, workflow_id: object, ref: object, inputs: object, confirmation: object) -> dict[str, Any]:
        if str(confirmation or "") != "DISPATCH":
            raise ValueError("type DISPATCH to confirm starting a GitHub workflow")
        if not self.token:
            raise ValueError("connect a GitHub token before starting a workflow")
        try:
            workflow_number = int(workflow_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("workflow_id must be a GitHub workflow ID") from exc
        if workflow_number <= 0:
            raise ValueError("workflow_id must be positive")
        branch = str(ref or "").strip()
        if not branch or len(branch) > 255 or any(ch in branch for ch in "\r\n"):
            raise ValueError("ref must be a branch or tag name")
        raw_inputs = inputs if isinstance(inputs, Mapping) else {}
        if len(raw_inputs) > 25:
            raise ValueError("GitHub workflow dispatch accepts at most 25 inputs")
        safe_inputs: dict[str, str] = {}
        for key, value in raw_inputs.items():
            name = str(key).strip()
            text = str(value)
            if not name or len(name) > 128 or len(text) > 4096:
                raise ValueError("workflow input names and values must be bounded")
            safe_inputs[name] = text
        url = f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}/actions/workflows/{workflow_number}/dispatches"
        status, payload = self._request(url, method="POST", body={"ref": branch, "inputs": safe_inputs})
        with self._lock:
            self._cache = None
            self._workflow_cache.clear()
        return {"schema": "omega.deltascope.workflow-dispatch.v1", "accepted": status in {200, 201, 204}, "status": status, "repository": self.repository, "workflowId": workflow_number, "ref": branch, "runUrl": self._safe_github_url(payload.get("html_url")), "readOnly": False, "mutationAuthority": "github-workflow-dispatch"}

    def _request_runs(self) -> list[Mapping[str, Any]]:
        url = f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}/actions/runs?per_page={MAX_RUNS}"
        payload = self._request_json(url)
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise RuntimeError("GitHub Actions response has no workflow_runs list")
        return [run for run in runs if isinstance(run, Mapping)]

    def _request_workflow_runs(self, workflow_file: str, limit: int) -> list[Mapping[str, Any]]:
        workflow = urllib.parse.quote(str(workflow_file or "").strip(), safe="")
        url = (
            f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}"
            f"/actions/workflows/{workflow}/runs?per_page={max(1, min(limit, MAX_WORKFLOW_HISTORY))}"
        )
        payload = self._request_json(url)
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise RuntimeError("GitHub workflow response has no workflow_runs list")
        return [run for run in runs if isinstance(run, Mapping)]

    def _request_jobs(self, run_id: int) -> list[Mapping[str, Any]]:
        url = (
            f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}"
            f"/actions/runs/{int(run_id)}/jobs?per_page=100"
        )
        payload = self._request_json(url)
        jobs = payload.get("jobs")
        if not isinstance(jobs, list):
            raise RuntimeError("GitHub workflow run has no jobs list")
        return [job for job in jobs if isinstance(job, Mapping)]

    def _request_artifacts(self, run_id: int) -> list[Mapping[str, Any]]:
        url = (
            f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}"
            f"/actions/runs/{int(run_id)}/artifacts?per_page=100"
        )
        payload = self._request_json(url)
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            return []
        return [artifact for artifact in artifacts if isinstance(artifact, Mapping)]

    def _request_job_log(self, job_id: int) -> str:
        url = (
            f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}"
            f"/actions/jobs/{int(job_id)}/logs"
        )
        request = urllib.request.Request(url, headers=self._headers(accept="text/plain"))
        with self._opener(request, timeout=10) as response:
            raw = response.read(MAX_JOB_LOG_BYTES + 1)
        if len(raw) > MAX_JOB_LOG_BYTES:
            return raw[:MAX_JOB_LOG_BYTES].decode("utf-8", "replace") + "\n[DeltaScope: log preview truncated]"
        return raw.decode("utf-8", "replace")

    @staticmethod
    def _safe_github_url(value: object) -> str:
        text = str(value or "")
        return text if text.startswith("https://github.com/") else ""

    def workflow_history(
        self,
        workflow_file: str,
        *,
        limit: int = 5,
        include_logs: bool = True,
        log_job_names: Iterable[str] | None = None,
        log_run_limit: int = 1,
        refresh: bool = False,
    ) -> dict[str, Any]:
        """Return a bounded, read-only recent workflow/job/step history.

        This powers DeltaScope collector review.  It deliberately fetches only a few
        recent runs and bounded job logs, and it is cached so opening the Operations
        workspace does not turn DeltaScope into a GitHub polling agent.
        """
        workflow_file = str(workflow_file or "").strip()
        if not workflow_file or "/" in workflow_file or "\\" in workflow_file or not workflow_file.endswith((".yml", ".yaml")):
            raise ValueError("workflow_file must be a workflow filename")
        limit = max(1, min(int(limit or 5), MAX_WORKFLOW_HISTORY))
        normalized_log_jobs = tuple(sorted({str(name).strip() for name in (log_job_names or []) if str(name).strip()}))
        log_run_limit = max(0, min(int(log_run_limit or 0), limit, 4))
        key = (workflow_file, limit, bool(include_logs), normalized_log_jobs, log_run_limit)
        now = time.monotonic()
        with self._lock:
            cached = self._workflow_cache.get(key)
            if not refresh:
                if cached:
                    return dict(cached[1])
                return {
                    "schema": "omega.deltascope.workflow-history.v1", "available": False,
                    "readOnly": True, "mutationAuthority": "none", "workflowFile": workflow_file,
                    "repository": self.repository, "fetchedAtUtc": "", "runs": [],
                    "snapshotLoaded": False, "cachePolicy": "explicit-refresh",
                    "error": "GitHub runner-history snapshot has not been acquired yet",
                }

        runs_out: list[dict[str, Any]] = []
        try:
            runs = self._request_workflow_runs(workflow_file, limit)
            for run_index, raw_run in enumerate(runs[:limit]):
                run = normalize_run(raw_run)
                try:
                    raw_artifacts = self._request_artifacts(int(run["runId"])) if run_index == 0 else []
                except Exception:
                    raw_artifacts = []
                run["artifacts"] = [{
                    "artifactId": int(artifact.get("id") or 0),
                    "name": str(artifact.get("name") or ""),
                    "bytes": int(artifact.get("size_in_bytes") or 0),
                    "expired": bool(artifact.get("expired", False)),
                    "createdAtUtc": str(artifact.get("created_at") or ""),
                    "updatedAtUtc": str(artifact.get("updated_at") or ""),
                } for artifact in raw_artifacts]
                jobs_out: list[dict[str, Any]] = []
                for raw_job in self._request_jobs(int(run["runId"])):
                    steps = []
                    for raw_step in raw_job.get("steps") or []:
                        if not isinstance(raw_step, Mapping):
                            continue
                        steps.append({
                            "number": int(raw_step.get("number") or 0),
                            "name": str(raw_step.get("name") or ""),
                            "status": str(raw_step.get("status") or ""),
                            "conclusion": str(raw_step.get("conclusion") or ""),
                            "startedAtUtc": str(raw_step.get("started_at") or ""),
                            "completedAtUtc": str(raw_step.get("completed_at") or ""),
                        })
                    job = {
                        "jobId": int(raw_job.get("id") or 0),
                        "name": str(raw_job.get("name") or ""),
                        "status": str(raw_job.get("status") or ""),
                        "conclusion": str(raw_job.get("conclusion") or ""),
                        "startedAtUtc": str(raw_job.get("started_at") or ""),
                        "completedAtUtc": str(raw_job.get("completed_at") or ""),
                        "url": self._safe_github_url(raw_job.get("html_url")),
                        "steps": steps,
                        "logPreview": "",
                    }
                    # Collector trend analysis needs a short history of throughput/result metrics.
                    # Keep it bounded to the newest four workflow runs and only collector-relevant jobs;
                    # older runs still retain job/step outcomes without downloading logs.
                    wants_log = run_index < log_run_limit and include_logs and (not normalized_log_jobs or job["name"] in normalized_log_jobs)
                    if wants_log and job["jobId"]:
                        try:
                            job["logPreview"] = self._request_job_log(job["jobId"])
                        except Exception:
                            job["logPreview"] = ""
                    jobs_out.append(job)
                run["jobs"] = jobs_out
                runs_out.append(run)
            payload = {
                "schema": "omega.deltascope.workflow-history.v1",
                "available": True,
                "readOnly": True,
                "mutationAuthority": "none",
                "repository": self.repository,
                "workflowFile": workflow_file,
                "fetchedAtUtc": _utc_now(),
                "runs": runs_out,
            }
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            payload = {
                "schema": "omega.deltascope.workflow-history.v1",
                "available": False,
                "readOnly": True,
                "mutationAuthority": "none",
                "repository": self.repository,
                "workflowFile": workflow_file,
                "fetchedAtUtc": _utc_now(),
                "runs": [],
                "error": str(exc),
            }
        with self._lock:
            self._workflow_cache[key] = (time.monotonic(), dict(payload))
        return payload

    def status(self, *, refresh: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            if not refresh:
                if self._cache is not None:
                    return dict(self._cache)
                return {
                    "schema": SCHEMA, "available": False, "readOnly": True,
                    "mutationAuthority": "none", "source": "github-actions-public-api",
                    "repository": self.repository, "fetchedAtUtc": "", "actionsRunning": 0,
                    "recentFailureCount": 0, "components": [], "events": [],
                    "snapshotLoaded": False, "cachePolicy": "explicit-refresh",
                    "error": "GitHub Actions snapshot has not been acquired yet",
                }
        try:
            payload = project_runs(self.repository, self._request_runs())
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            payload = {
                "schema": SCHEMA,
                "available": False,
                "readOnly": True,
                "mutationAuthority": "none",
                "source": "github-actions-public-api",
                "repository": self.repository,
                "fetchedAtUtc": _utc_now(),
                "actionsRunning": 0,
                "recentFailureCount": 0,
                "components": [],
                "events": [],
                "error": str(exc),
            }
        with self._lock:
            self._cache = dict(payload)
            self._cached_at = now
        return payload


    def snapshot_status(self) -> dict[str, Any]:
        """Describe the already-acquired GitHub snapshot without performing I/O."""
        with self._lock:
            payload = dict(self._cache or {})
            workflow_keys = list(self._workflow_cache)
        history_count = sum(1 for key in workflow_keys if key and key[0] not in {"workflows", "workflow-form", "client-delivery"})
        form_count = sum(1 for key in workflow_keys if key and key[0] == "workflow-form")
        return {
            "schema": "omega.deltascope.github-acquisition-state.v1",
            "sourceId": "github-actions",
            "label": "GitHub Actions",
            "loaded": bool(payload),
            "fetchedAtUtc": str(payload.get("fetchedAtUtc") or ""),
            "cachePolicy": "explicit-refresh",
            "navigationRefresh": False,
            "workflowHistorySnapshots": history_count,
            "workflowFormSnapshots": form_count,
            **self.access_status(),
        }

    def refresh_snapshot(
        self,
        workflow_contracts: Mapping[str, Iterable[str]] | None = None,
        *,
        history_limit: int = 8,
    ) -> dict[str, Any]:
        """Acquire the operational GitHub snapshot independently from page navigation."""
        # Explicit acquisition replaces the previous derived caches as one user action.
        with self._lock:
            self._cache = None
            self._cached_at = 0.0
            self._workflow_cache.clear()
        operations = self.status(refresh=True)
        workflows = self.workflows(refresh=True)
        client_delivery = self.client_delivery(refresh=True)
        histories: dict[str, dict[str, Any]] = {}
        for workflow_file, job_names in sorted((workflow_contracts or {}).items()):
            names = {str(name).strip() for name in (job_names or []) if str(name).strip()}
            histories[str(workflow_file)] = self.workflow_history(
                str(workflow_file), limit=history_limit, include_logs=True,
                log_job_names=names or None, log_run_limit=4, refresh=True,
            )
        return {
            "schema": "omega.deltascope.github-acquisition-refresh.v1",
            "sourceId": "github-actions",
            "refreshed": True,
            "operations": operations,
            "workflows": workflows,
            "clientDelivery": client_delivery,
            "workflowHistories": histories,
            "snapshot": self.snapshot_status(),
        }


def merge_component_registry(payload: Mapping[str, Any], registry: Mapping[str, Any] | None) -> dict[str, Any]:
    """Overlay the published component registry onto Actions-derived status.

    DeltaScope's dashboard must not require a code change merely because the platform gains a
    component.  The registry is authoritative only for component identity/declared launch
    metadata; Actions remains diagnostic runtime status.  Unknown/unobserved components are
    therefore shown as ``unknown`` rather than inferred healthy/failed.
    """
    result = dict(payload or {})
    if not isinstance(registry, Mapping) or str(registry.get("schema") or "") != "omega.component-registry.v1":
        result["componentRegistryAvailable"] = False
        return result

    events = [dict(row) for row in (result.get("events") or []) if isinstance(row, Mapping)]
    legacy_components = [dict(row) for row in (result.get("components") or []) if isinstance(row, Mapping)]
    registered = [dict(row) for row in (registry.get("components") or []) if isinstance(row, Mapping)]

    def workflow_name(component: Mapping[str, Any]) -> str:
        launch = component.get("launch") if isinstance(component.get("launch"), Mapping) else {}
        path = str(launch.get("workflow") or "").replace("\\", "/")
        return path.rsplit("/", 1)[-1].casefold()

    def matching_event(component: Mapping[str, Any]) -> dict[str, Any] | None:
        wanted = workflow_name(component)
        if not wanted:
            return None
        for event in events:
            raw_path = str(event.get("workflowPath") or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
            workflow = str(event.get("workflow") or "").casefold()
            if raw_path == wanted or workflow == wanted or workflow.endswith(wanted):
                return event
        return None

    rows: list[dict[str, Any]] = []
    claimed_legacy: set[str] = set()
    for component in registered:
        component_id = str(component.get("id") or "")
        name = str(component.get("name") or component_id)
        launch = dict(component.get("launch") or {}) if isinstance(component.get("launch"), Mapping) else {}
        event = matching_event(component)
        state = str((event or {}).get("state") or "unknown")
        detail = str((event or {}).get("stateDetail") or ("not observed in recent Actions history" if event is None else ""))
        # Avoid retaining a duplicate legacy dashboard row when the same workflow/name has now
        # been described by the platform registry.
        for legacy in legacy_components:
            latest = legacy.get("activeRun") or legacy.get("latestRun") or {}
            legacy_workflow = str((latest or {}).get("workflowPath") or (latest or {}).get("workflow") or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
            if workflow_name(component) and legacy_workflow == workflow_name(component):
                claimed_legacy.add(str(legacy.get("componentId") or ""))
            elif str(legacy.get("component") or "").casefold() == name.casefold():
                claimed_legacy.add(str(legacy.get("componentId") or ""))
        rows.append({
            "componentId": component_id,
            "component": name,
            "componentType": str(component.get("type") or ""),
            "componentStatus": str(component.get("status") or ""),
            "executionClass": str(component.get("executionClass") or ""),
            "state": state,
            "stateDetail": detail,
            "runningCount": 1 if state == "running" else 0,
            "latestRun": event,
            "activeRun": event if state == "running" else None,
            "observed": event is not None,
            "launch": launch,
            "readOnly": True,
            "registryDriven": True,
        })

    for legacy in legacy_components:
        legacy_id = str(legacy.get("componentId") or "")
        if legacy_id not in claimed_legacy:
            rows.append({**legacy, "registryDriven": False})

    rows.sort(key=lambda row: (
        0 if row.get("registryDriven") else 1,
        str(row.get("componentStatus") or "active") != "active",
        str(row.get("component") or row.get("componentId") or "").casefold(),
    ))
    result["components"] = rows
    result["componentRegistryAvailable"] = True
    result["componentRegistryRevision"] = str(registry.get("revision") or "")
    result["registeredComponentCount"] = len(registered)
    return result
