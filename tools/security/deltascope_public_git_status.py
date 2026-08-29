"""Token-free public GitHub URL availability checks for DeltaScope Operations."""
from __future__ import annotations

import datetime as dt
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable


SCHEMA = "omega.deltascope.public-git-component-status.v1"
DEFAULT_TTL_SECONDS = 15


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _repository(value: str) -> str:
    value = str(value or "").strip()
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    if value.count("/") != 1 or any(character not in allowed for character in value.replace("/", "")):
        raise ValueError("GitHub repository must use owner/name syntax")
    return value


def component_urls(repository: str) -> list[dict[str, str]]:
    repository = _repository(repository)
    root = f"https://github.com/{repository}"
    return [
        {"componentId": "repository", "component": "Source repository", "url": root, "purpose": "public source and change boundary"},
        {"componentId": "actions", "component": "GitHub Actions", "url": f"{root}/actions", "purpose": "public workflow activity"},
        {"componentId": "releases", "component": "Releases", "url": f"{root}/releases", "purpose": "public release publication"},
        {"componentId": "security", "component": "Security advisories", "url": f"{root}/security", "purpose": "public security disclosure surface"},
        {"componentId": "github-status", "component": "GitHub service status", "url": "https://www.githubstatus.com/", "purpose": "public GitHub service status page"},
    ]


class PublicGitUrlMonitor:
    """Explicitly refreshed public-HTTPS snapshot; navigation never re-probes URLs."""

    def __init__(self, repository: str, *, ttl_seconds: int = DEFAULT_TTL_SECONDS, opener: Callable[..., Any] | None = None) -> None:
        self.repository = _repository(repository)
        self.ttl_seconds = max(5, min(300, int(ttl_seconds or DEFAULT_TTL_SECONDS)))
        self._opener = opener or urllib.request.urlopen
        self._lock = threading.RLock()
        self._cached_at = 0.0
        self._cache: dict[str, Any] | None = None

    def _probe(self, component: dict[str, str]) -> dict[str, Any]:
        started = time.monotonic()
        request = urllib.request.Request(component["url"], method="HEAD", headers={"User-Agent": "Omega-DeltaScope/PublicUrlMonitor"})
        try:
            with self._opener(request, timeout=8.0) as response:
                status = int(getattr(response, "status", None) or getattr(response, "getcode", lambda: 200)() or 200)
            state = "healthy" if 200 <= status < 400 else "failed"
            detail = f"HTTP {status}"
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            state = "failed"
            detail = f"HTTP {status}"
        except (OSError, ValueError) as exc:
            status = 0
            state = "unreachable"
            detail = str(exc) or "network request failed"
        return {
            **component, "state": state, "detail": detail, "httpStatus": status,
            "latencyMs": round((time.monotonic() - started) * 1000), "readOnly": True,
        }

    def status(self, *, refresh: bool = False) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            if not refresh:
                if self._cache is not None:
                    return dict(self._cache)
                return {
                    "schema": SCHEMA, "available": False, "readOnly": True, "mutationAuthority": "none",
                    "source": "public-https-url-probes", "usesGitHubApi": False, "usesCredentials": False,
                    "repository": self.repository, "fetchedAtUtc": "", "cachePolicy": "explicit-refresh",
                    "navigationRefresh": False, "snapshotLoaded": False, "components": [],
                    "error": "Public Git status snapshot has not been acquired yet",
                }
            components = [self._probe(component) for component in component_urls(self.repository)]
            payload = {
                "schema": SCHEMA, "available": True, "readOnly": True, "mutationAuthority": "none",
                "source": "public-https-url-probes", "usesGitHubApi": False, "usesCredentials": False,
                "repository": self.repository, "fetchedAtUtc": _utc_now(), "cachePolicy": "explicit-refresh", "navigationRefresh": False,
                "components": components,
            }
            self._cached_at = now
            self._cache = payload
            return dict(payload)

    def snapshot_status(self) -> dict[str, Any]:
        """Describe the cached public-Git probe result without network access."""
        with self._lock:
            payload = dict(self._cache or {})
        return {
            "schema": "omega.deltascope.public-git-acquisition-state.v1",
            "sourceId": "public-git",
            "label": "Public Git endpoints",
            "loaded": bool(payload),
            "fetchedAtUtc": str(payload.get("fetchedAtUtc") or ""),
            "cachePolicy": "explicit-refresh",
            "navigationRefresh": False,
            "componentCount": len(payload.get("components") or []),
            "usesGitHubApi": False,
            "usesCredentials": False,
        }
