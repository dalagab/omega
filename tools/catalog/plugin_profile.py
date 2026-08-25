#!/usr/bin/env python3
"""Validate bounded developer-provided `.omega/plugin.yaml` metadata.

The profile is untrusted developer-authored context. It can describe a plugin and explain
expected capabilities, services, native components, and IPC use. It cannot declare the
plugin safe, suppress SigmaScope evidence, or claim source/artifact verification.

Parsing is fail-soft for catalog ingestion: callers receive diagnostics and may ignore an
invalid profile without dropping the plugin or its security evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from deltascope_sdk.capability_registry import describe_capability, load_registry, normalize_capability_id

PROFILE_SCHEMA = "omega.plugin-profile.v1"
PROFILE_OBSERVATION_SCHEMA = "omega.plugin-profile-observation.v1"
PROFILE_PATH = ".omega/plugin.yaml"
MAX_PROFILE_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_NODES = 1024
MAX_CAPABILITIES = 64
MAX_SERVICES = 32
MAX_NATIVE_COMPONENTS = 64
MAX_IPC = 64
MAX_TAGS = 32
MAX_CATEGORIES = 16
MAX_MEDIA_SCREENSHOTS = 12
MAX_DESTINATIONS = 32
MAX_DIAGNOSTICS = 32
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$|^\*\.(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+$")
FORBIDDEN_AUTHORITY_KEYS = {
    "safe", "issafe", "risk", "riskscore", "trusted", "trust", "severity", "highestseverity",
    "scannerseverity", "override", "overrides", "suppression", "suppress", "suppressions",
    "allowlist", "whitelist", "yarasafe", "clamavsafe", "sourceverified", "sourceverification",
    "sourcetobinaryverified", "reproducible", "reproduciblesource", "artifactsha", "artifactsha256",
    "reviewcoverage", "reviewcoveragelabel", "attributionconfidence", "scannerverdict", "verdict",
}


class ProfileError(ValueError):
    def __init__(self, code: str, message: str, path: str = ""):
        super().__init__(message)
        self.code = code
        self.path = path


class _UniqueSafeLoaderPlaceholder:
    pass


def _yaml_module():
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise ProfileError("yaml-unavailable", "PyYAML is required to validate .omega/plugin.yaml") from exc
    return yaml


def _load_yaml(raw: bytes) -> Any:
    yaml = _yaml_module()
    if len(raw) > MAX_PROFILE_BYTES:
        raise ProfileError("oversized", f"profile exceeds {MAX_PROFILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig", "strict")
    except UnicodeDecodeError as exc:
        raise ProfileError("encoding", "profile must be UTF-8") from exc

    # Anchors/aliases/tags/merge keys make human review and resource bounds less obvious.
    # Reject them even though SafeLoader would prevent Python object construction.
    try:
        token_count = 0
        for token in yaml.scan(text):
            token_count += 1
            if token_count > 4096:
                raise ProfileError("yaml-complexity", "profile YAML token count exceeds 4096")
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken)):
                raise ProfileError("yaml-feature", "YAML anchors, aliases, and explicit tags are not allowed")
    except ProfileError:
        raise
    except yaml.YAMLError as exc:
        raise ProfileError("yaml-syntax", f"invalid YAML: {exc}") from exc

    class UniqueSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key == "<<":
                raise ProfileError("yaml-feature", "YAML merge keys are not allowed")
            if key in mapping:
                raise ProfileError("duplicate-key", f"duplicate YAML key: {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    try:
        return yaml.load(text, Loader=UniqueSafeLoader)
    except ProfileError:
        raise
    except yaml.YAMLError as exc:
        raise ProfileError("yaml-syntax", f"invalid YAML: {exc}") from exc


def _walk_bounds(value: Any, depth: int = 0) -> int:
    if depth > MAX_DEPTH:
        raise ProfileError("depth", f"profile nesting exceeds {MAX_DEPTH}")
    count = 1
    if isinstance(value, dict):
        if len(value) > 128:
            raise ProfileError("mapping-size", "profile mapping exceeds 128 entries")
        for key, child in value.items():
            if not isinstance(key, str):
                raise ProfileError("key-type", "profile mapping keys must be strings")
            if len(key) > 128:
                raise ProfileError("key-length", "profile mapping key exceeds 128 characters")
            count += _walk_bounds(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 256:
            raise ProfileError("list-size", "profile list exceeds 256 entries")
        for child in value:
            count += _walk_bounds(child, depth + 1)
    elif isinstance(value, str):
        if len(value) > 12_000:
            raise ProfileError("string-length", "profile string exceeds 12000 characters")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ProfileError("scalar-type", f"unsupported profile value type: {type(value).__name__}")
    if count > MAX_NODES:
        raise ProfileError("node-count", f"profile structure exceeds {MAX_NODES} nodes")
    return count


def _authority_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _reject_authority_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = _authority_key(str(key))
            if normalized in FORBIDDEN_AUTHORITY_KEYS:
                raise ProfileError("authority-field", f"developer profiles cannot set scanner authority field {key!r}", f"{path}.{key}")
            _reject_authority_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_authority_fields(child, f"{path}[{index}]")


def _string(value: Any, path: str, *, maximum: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ProfileError("type", f"{path} must be a string", path)
    value = value.strip()
    if required and not value:
        raise ProfileError("required", f"{path} is required", path)
    if len(value) > maximum:
        raise ProfileError("length", f"{path} exceeds {maximum} characters", path)
    return value


def _bool(value: Any, path: str, *, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if not isinstance(value, bool):
        raise ProfileError("type", f"{path} must be true or false", path)
    return value


def _list(value: Any, path: str, *, maximum: int) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ProfileError("type", f"{path} must be a list", path)
    if len(value) > maximum:
        raise ProfileError("length", f"{path} exceeds {maximum} entries", path)
    return value


def _known_fields(raw: dict[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ProfileError("unsupported-field", f"{path} has unsupported field(s): {', '.join(unknown)}", path)


def _https_url(value: Any, path: str, *, required: bool = False) -> str:
    url = _string(value, path, maximum=2048, required=required)
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise ProfileError("url", f"{path} is not a valid URL", path) from exc
    if parsed.scheme.casefold() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ProfileError("url", f"{path} must be an HTTPS URL without embedded credentials", path)
    host = parsed.hostname.strip("[]").casefold()
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local")):
        raise ProfileError("url", f"{path} must use a public hostname", path)
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            raise ProfileError("url", f"{path} cannot use a private/reserved IP literal", path)
    except ValueError:
        pass
    return urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path or "", parsed.query or "", ""))


def _repo_media_ref(value: Any, path: str) -> str:
    text = _string(value, path, maximum=1024)
    if not text:
        return ""
    if text.casefold().startswith("https://"):
        return _https_url(text, path)
    normalized = text.replace("\\", "/").strip("/")
    posix = PurePosixPath(normalized)
    if not normalized or posix.is_absolute() or ".." in posix.parts:
        raise ProfileError("media-path", f"{path} must be a safe repository-relative path or HTTPS URL", path)
    return normalized


def _host(value: Any, path: str) -> str:
    host = _string(value, path, maximum=253, required=True).casefold().rstrip(".")
    if "://" in host or "/" in host:
        raise ProfileError("destination", f"{path} must be a hostname, not a URL", path)
    if not HOST_RE.fullmatch(host):
        raise ProfileError("destination", f"{path} is not a valid hostname pattern", path)
    return host


def _string_list(value: Any, path: str, *, maximum_items: int, maximum_text: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(_list(value, path, maximum=maximum_items)):
        text = _string(item, f"{path}[{index}]", maximum=maximum_text, required=True)
        folded = text.casefold()
        if folded not in seen:
            seen.add(folded)
            result.append(text)
    return result


def _profile_block(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProfileError("type", "profile must be an object", "$.profile")
    _known_fields(raw, {"tagline", "description", "categories", "tags", "homepage", "documentation", "support", "source", "license", "securityPolicy", "vulnerabilityReporting"}, "$.profile")
    result = {
        "tagline": _string(raw.get("tagline"), "$.profile.tagline", maximum=180),
        "description": _string(raw.get("description"), "$.profile.description", maximum=8000),
        "categories": _string_list(raw.get("categories"), "$.profile.categories", maximum_items=MAX_CATEGORIES, maximum_text=64),
        "tags": _string_list(raw.get("tags"), "$.profile.tags", maximum_items=MAX_TAGS, maximum_text=64),
        "homepage": _https_url(raw.get("homepage"), "$.profile.homepage"),
        "documentation": _https_url(raw.get("documentation"), "$.profile.documentation"),
        "support": _https_url(raw.get("support"), "$.profile.support"),
        "source": _https_url(raw.get("source"), "$.profile.source"),
        "license": _string(raw.get("license"), "$.profile.license", maximum=128),
        "securityPolicy": _https_url(raw.get("securityPolicy"), "$.profile.securityPolicy"),
        "vulnerabilityReporting": _https_url(raw.get("vulnerabilityReporting"), "$.profile.vulnerabilityReporting"),
    }
    return {key: value for key, value in result.items() if value not in ("", [], {})}


def _capabilities(raw: Any, registry: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(_list(raw, "$.capabilities", maximum=MAX_CAPABILITIES)):
        path = f"$.capabilities[{index}]"
        if not isinstance(item, dict):
            raise ProfileError("type", f"{path} must be an object", path)
        _known_fields(item, {"id", "expected", "required", "reason", "destinations"}, path)
        declared_id = _string(item.get("id"), f"{path}.id", maximum=128, required=True)
        canonical = normalize_capability_id(declared_id, registry)
        if not canonical:
            raise ProfileError("unknown-capability", f"{path}.id is not in the SigmaScope capability registry: {declared_id}", f"{path}.id")
        if canonical in seen:
            raise ProfileError("duplicate-capability", f"capability {canonical} is declared more than once", path)
        seen.add(canonical)
        description = describe_capability(canonical, registry) or {}
        expected = _bool(item.get("expected"), f"{path}.expected", default=True)
        required = _bool(item.get("required"), f"{path}.required", default=False)
        reason = _string(item.get("reason"), f"{path}.reason", maximum=1200, required=True)
        destinations = [_host(value, f"{path}.destinations[{i}]") for i, value in enumerate(_list(item.get("destinations"), f"{path}.destinations", maximum=MAX_DESTINATIONS))]
        if destinations and not bool((description.get("attributes") or {}).get("destinationAware")):
            raise ProfileError("destination-not-supported", f"capability {canonical} does not accept destinations", f"{path}.destinations")
        result.append({
            "id": canonical,
            "declaredId": declared_id if declared_id != canonical else "",
            "label": str(description.get("label") or canonical),
            "category": str(description.get("category") or ""),
            "expected": expected,
            "required": required,
            "reason": reason,
            "destinations": sorted(set(destinations)),
        })
    return result


def _services(raw: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, item in enumerate(_list(raw, "$.services", maximum=MAX_SERVICES)):
        path = f"$.services[{index}]"
        if not isinstance(item, dict):
            raise ProfileError("type", f"{path} must be an object", path)
        _known_fields(item, {"id", "name", "url", "purpose", "required"}, path)
        service_id = _string(item.get("id"), f"{path}.id", maximum=128, required=True)
        if not ID_RE.fullmatch(service_id):
            raise ProfileError("id", f"{path}.id is invalid", f"{path}.id")
        folded = service_id.casefold()
        if folded in ids:
            raise ProfileError("duplicate-service", f"service {service_id} is declared more than once", path)
        ids.add(folded)
        result.append({
            "id": service_id,
            "name": _string(item.get("name"), f"{path}.name", maximum=160, required=True),
            "url": _https_url(item.get("url"), f"{path}.url", required=True),
            "purpose": _string(item.get("purpose"), f"{path}.purpose", maximum=1200, required=True),
            "required": _bool(item.get("required"), f"{path}.required", default=False),
        })
    return result


def _native_components(raw: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(_list(raw, "$.nativeComponents", maximum=MAX_NATIVE_COMPONENTS)):
        path = f"$.nativeComponents[{index}]"
        if not isinstance(item, dict):
            raise ProfileError("type", f"{path} must be an object", path)
        _known_fields(item, {"name", "purpose", "required"}, path)
        name = _string(item.get("name"), f"{path}.name", maximum=256, required=True)
        folded = name.casefold()
        if folded in seen:
            raise ProfileError("duplicate-native-component", f"native component {name} is declared more than once", path)
        seen.add(folded)
        result.append({
            "name": name,
            "purpose": _string(item.get("purpose"), f"{path}.purpose", maximum=1200, required=True),
            "required": _bool(item.get("required"), f"{path}.required", default=False),
        })
    return result


def _ipc(raw: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, item in enumerate(_list(raw, "$.ipc", maximum=MAX_IPC)):
        path = f"$.ipc[{index}]"
        if not isinstance(item, dict):
            raise ProfileError("type", f"{path} must be an object", path)
        _known_fields(item, {"plugin", "channel", "purpose", "required"}, path)
        plugin = _string(item.get("plugin"), f"{path}.plugin", maximum=256)
        channel = _string(item.get("channel"), f"{path}.channel", maximum=256)
        if not plugin and not channel:
            raise ProfileError("required", f"{path} must provide plugin and/or channel", path)
        result.append({
            "plugin": plugin,
            "channel": channel,
            "purpose": _string(item.get("purpose"), f"{path}.purpose", maximum=1200, required=True),
            "required": _bool(item.get("required"), f"{path}.required", default=False),
        })
    return result


def _media(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProfileError("type", "$.media must be an object", "$.media")
    _known_fields(raw, {"icon", "banner", "screenshots"}, "$.media")
    screenshots = [_repo_media_ref(value, f"$.media.screenshots[{i}]") for i, value in enumerate(_list(raw.get("screenshots"), "$.media.screenshots", maximum=MAX_MEDIA_SCREENSHOTS))]
    result = {
        "icon": _repo_media_ref(raw.get("icon"), "$.media.icon"),
        "banner": _repo_media_ref(raw.get("banner"), "$.media.banner"),
        "screenshots": screenshots,
    }
    return {key: value for key, value in result.items() if value not in ("", [], {})}


def normalize_profile(document: Any, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    registry = registry or load_registry()
    _walk_bounds(document)
    _reject_authority_fields(document)
    if not isinstance(document, dict):
        raise ProfileError("type", "profile document must be an object", "$")
    _known_fields(document, {"schema", "profile", "capabilities", "services", "nativeComponents", "ipc", "media"}, "$")
    if document.get("schema") != PROFILE_SCHEMA:
        raise ProfileError("schema", f"unsupported profile schema: {document.get('schema')!r}", "$.schema")
    normalized = {
        "schema": PROFILE_SCHEMA,
        "profile": _profile_block(document.get("profile")),
        "capabilities": _capabilities(document.get("capabilities"), registry),
        "services": _services(document.get("services")),
        "nativeComponents": _native_components(document.get("nativeComponents")),
        "ipc": _ipc(document.get("ipc")),
        "media": _media(document.get("media")),
        "capabilityRegistryRevision": str(registry.get("revision") or ""),
    }
    return normalized


def validate_profile_bytes(raw: bytes, *, path: str = PROFILE_PATH, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    sha = hashlib.sha256(raw).hexdigest()
    base = {
        "schema": PROFILE_OBSERVATION_SCHEMA,
        "path": path,
        "sha256": sha,
        "bytes": len(raw),
        "status": "invalid",
        "valid": False,
        "profile": {},
        "diagnostics": [],
    }
    try:
        document = _load_yaml(raw)
        profile = normalize_profile(document, registry)
        base.update({"status": "valid", "valid": True, "profile": profile})
    except ProfileError as exc:
        base["diagnostics"] = [{"code": exc.code, "path": exc.path, "message": str(exc)[:1000]}]
    except ValueError as exc:
        base["diagnostics"] = [{"code": "registry", "path": "", "message": str(exc)[:1000]}]
    return base


def profile_candidates(primary_project: str = "") -> list[str]:
    result: list[str] = []
    project = str(primary_project or "").replace("\\", "/").strip("/")
    if project:
        parent = str(PurePosixPath(project).parent)
        if parent == ".":
            parent = ""
        local = f"{parent}/{PROFILE_PATH}".strip("/")
        if local and local not in result:
            result.append(local)
    if PROFILE_PATH not in result:
        result.append(PROFILE_PATH)
    return result


def observe_profile(paths: set[str] | list[str] | dict[str, Any], read_file: Callable[[str], bytes], *, primary_project: str = "", registry: dict[str, Any] | None = None) -> dict[str, Any]:
    available = set(paths.keys() if isinstance(paths, dict) else paths)
    for candidate in profile_candidates(primary_project):
        if candidate not in available:
            continue
        raw = read_file(candidate)
        if not raw:
            return {
                "schema": PROFILE_OBSERVATION_SCHEMA,
                "path": candidate,
                "sha256": "",
                "bytes": 0,
                "status": "invalid",
                "valid": False,
                "profile": {},
                "diagnostics": [{"code": "unreadable", "path": candidate, "message": "profile exists but could not be read within the configured size limit"}],
            }
        return validate_profile_bytes(raw, path=candidate, registry=registry)
    return {
        "schema": PROFILE_OBSERVATION_SCHEMA,
        "path": "",
        "sha256": "",
        "bytes": 0,
        "status": "absent",
        "valid": False,
        "profile": {},
        "diagnostics": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an Omega .omega/plugin.yaml developer profile")
    parser.add_argument("command", nargs="?", choices=["validate", "example"], default="validate")
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "example":
        example = Path(__file__).resolve().parents[2] / "docs" / "plugin-developers" / "examples" / "plugin.yaml"
        print(example.read_text(encoding="utf-8"), end="")
        return 0
    if not args.path:
        parser.error("path is required for validate")
    try:
        raw = args.path.read_bytes()
    except OSError as exc:
        print(f"error: {exc}")
        return 2
    result = validate_profile_bytes(raw, path=args.path.as_posix())
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif result["valid"]:
        profile = result["profile"]
        print(f"Profile OK: {len(profile.get('capabilities') or [])} capabilities, {len(profile.get('services') or [])} services, sha256={result['sha256']}")
    else:
        for diagnostic in result.get("diagnostics") or []:
            print(f"ERROR {diagnostic.get('code')}: {diagnostic.get('path') or args.path}: {diagnostic.get('message')}")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
