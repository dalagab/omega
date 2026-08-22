"""Versioned local SRL rule storage for DeltaScope.

This module is intentionally DeltaScope-only. It stores user-authored inert SRL YAML
under the user's home directory and has no authority to write repository Definitions,
Security Evidence, scanner state, queues, or publication outputs.

The on-disk contract is deliberately simple and recoverable:

    ~/.omega/deltascope/rules/v1/
      <rule-slug>-<id-hash>/
        metadata.json
        current.yaml
        revisions/
          000001-<content-hash>.yaml
          000002-<content-hash>.yaml

Every save is validated by SRL Core first. Revisions are immutable, current.yaml is
atomically replaced, paths are generated internally, and symlinked store entries are
rejected.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Mapping

try:
    from . import srl
except ImportError:  # direct script/import from tools/security
    import srl  # type: ignore

STORE_SCHEMA = "omega.deltascope.local-rule-store.v1"
ENTRY_SCHEMA = "omega.deltascope.local-rule.v1"
DEFAULT_RELATIVE_ROOT = Path(".omega") / "deltascope" / "rules" / "v1"
MAX_LOCAL_RULES = 1024
MAX_REVISIONS_PER_RULE = 4096


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_rule_root() -> Path:
    override = os.environ.get("OMEGA_DELTASCOPE_RULE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / DEFAULT_RELATIVE_ROOT).resolve()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_slug(rule_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", rule_id).strip(".-_") or "rule"
    slug = slug[:72].rstrip(".-_") or "rule"
    suffix = hashlib.sha256(rule_id.encode("utf-8")).hexdigest()[:10]
    return f"{slug}-{suffix}"


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _single_rule(text: str) -> tuple[dict[str, Any], dict[str, Any]]:
    document = srl.parse_yaml_text(text)
    rule = srl.single_rule_document(document)  # shared SRL Core one-rule authoring boundary
    compiled = srl.compile_rule(rule)
    return rule, compiled


class LocalRuleStore:
    """Small versioned local rule repository with a deliberately narrow write surface."""

    def __init__(self, root: Path | None = None):
        self.root = (root or default_rule_root()).expanduser().resolve()
        self._lock = threading.RLock()

    def reference(self) -> dict[str, Any]:
        return {
            "schema": STORE_SCHEMA,
            "root": str(self.root),
            "version": 1,
            "localOnly": True,
            "productionWriteBack": False,
            "repositoryWriteBack": False,
            "evidenceWriteBack": False,
            "revisioned": True,
            "immutableRevisions": True,
        }

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("DeltaScope local rule root may not be a symlink")

    def _entry_dirs(self) -> list[Path]:
        if not self.root.exists():
            return []
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("DeltaScope local rule root must be a real directory")
        result: list[Path] = []
        for child in sorted(self.root.iterdir(), key=lambda p: p.name.casefold()):
            if child.is_symlink():
                continue
            if child.is_dir() and (child / "metadata.json").is_file():
                result.append(child)
                if len(result) > MAX_LOCAL_RULES:
                    raise ValueError(f"local rule store exceeds {MAX_LOCAL_RULES} entries")
        return result

    @staticmethod
    def _read_metadata(entry: Path) -> dict[str, Any]:
        meta_path = entry / "metadata.json"
        if meta_path.is_symlink():
            raise ValueError("local rule metadata may not be a symlink")
        value = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") != ENTRY_SCHEMA:
            raise ValueError(f"invalid local rule metadata in {entry.name}")
        return value

    def _find_entry(self, rule_id: str) -> tuple[Path, dict[str, Any]] | None:
        for entry in self._entry_dirs():
            meta = self._read_metadata(entry)
            if str(meta.get("ruleId") or "") == rule_id:
                return entry, meta
        return None

    def list_rules(self) -> dict[str, Any]:
        with self._lock:
            rows: list[dict[str, Any]] = []
            for entry in self._entry_dirs():
                try:
                    meta = self._read_metadata(entry)
                    current = entry / "current.yaml"
                    if current.is_symlink() or not current.is_file():
                        raise ValueError("current.yaml is missing or unsafe")
                    text = current.read_text(encoding="utf-8")
                    rule, compiled = _single_rule(text)
                    rows.append({
                        "ruleId": str(rule.get("id") or meta.get("ruleId") or ""),
                        "kind": str(rule.get("kind") or ""),
                        "status": str(rule.get("status") or "experimental"),
                        "title": str((rule.get("emit") or {}).get("title") or rule.get("id") or ""),
                        "description": str((rule.get("emit") or {}).get("description") or ""),
                        "revision": int(meta.get("revision") or 0),
                        "revisionId": str(meta.get("revisionId") or ""),
                        "updatedAtUtc": str(meta.get("updatedAtUtc") or ""),
                        "createdAtUtc": str(meta.get("createdAtUtc") or ""),
                        "ruleRevision": str(compiled.get("ruleRevision") or ""),
                        "path": str(current),
                        "editable": True,
                        "local": True,
                    })
                except Exception as exc:
                    rows.append({
                        "ruleId": str(entry.name), "kind": "", "status": "invalid",
                        "title": entry.name, "revision": 0, "updatedAtUtc": "",
                        "editable": False, "local": True, "error": str(exc),
                    })
            rows.sort(key=lambda row: str(row.get("ruleId") or "").casefold())
            return {**self.reference(), "available": True, "ruleCount": len(rows), "rules": rows}

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        rule_id = str(rule_id or "").strip()
        if not rule_id:
            raise ValueError("ruleId is required")
        with self._lock:
            found = self._find_entry(rule_id)
            if not found:
                raise ValueError(f"unknown local rule {rule_id}")
            entry, meta = found
            current = entry / "current.yaml"
            if current.is_symlink() or not current.is_file():
                raise ValueError("local current.yaml is missing or unsafe")
            text = current.read_text(encoding="utf-8")
            rule, compiled = _single_rule(text)
            revisions: list[dict[str, Any]] = []
            revision_root = entry / "revisions"
            if revision_root.exists() and revision_root.is_dir() and not revision_root.is_symlink():
                for item in sorted(revision_root.glob("*.yaml"), reverse=True)[:100]:
                    if item.is_symlink() or not item.is_file():
                        continue
                    match = re.fullmatch(r"(\d{6})-([0-9a-f]{12})\.yaml", item.name)
                    if match:
                        revisions.append({"revision": int(match.group(1)), "contentHash": match.group(2), "file": item.name})
            return {
                "schema": ENTRY_SCHEMA, "local": True, "editable": True,
                "ruleId": rule_id, "yaml": text, "rule": rule, "compiled": compiled,
                "metadata": meta, "revisions": revisions, "store": self.reference(),
            }

    def save_rule(self, text: str, *, expected_rule_id: str = "") -> dict[str, Any]:
        encoded = str(text or "").encode("utf-8")
        if len(encoded) > srl.MAX_DOCUMENT_BYTES:
            raise ValueError(f"local rule exceeds {srl.MAX_DOCUMENT_BYTES} bytes")
        rule, compiled = _single_rule(str(text or ""))
        rule_id = str(rule.get("id") or "")
        if expected_rule_id and expected_rule_id != rule_id:
            raise ValueError("edited rule id differs from the selected local rule; use Fork/New Rule for a new id")
        canonical_yaml = srl.authoring_graph_to_yaml(srl.rule_to_authoring_graph(rule))
        content = canonical_yaml.encode("utf-8")
        content_hash = _hash_bytes(content)
        with self._lock:
            self._ensure_root()
            found = self._find_entry(rule_id)
            now = utc_now()
            if found:
                entry, meta = found
                if entry.is_symlink():
                    raise ValueError("local rule entry may not be a symlink")
                revision = int(meta.get("revision") or 0)
                current = entry / "current.yaml"
                if current.is_file() and not current.is_symlink() and _hash_bytes(current.read_bytes()) == content_hash:
                    return {
                        "schema": ENTRY_SCHEMA, "ok": True, "saved": False, "unchanged": True,
                        "ruleId": rule_id, "revision": revision, "revisionId": str(meta.get("revisionId") or ""),
                        "yaml": canonical_yaml, "compiled": compiled, "store": self.reference(),
                    }
                revision += 1
                created = str(meta.get("createdAtUtc") or now)
            else:
                if len(self._entry_dirs()) >= MAX_LOCAL_RULES:
                    raise ValueError(f"local rule store is limited to {MAX_LOCAL_RULES} rules")
                entry = self.root / _safe_slug(rule_id)
                if entry.exists() and (entry.is_symlink() or not entry.is_dir()):
                    raise ValueError("generated local rule path is unsafe")
                entry.mkdir(parents=True, exist_ok=True)
                revision = 1
                created = now
            if revision > MAX_REVISIONS_PER_RULE:
                raise ValueError(f"local rule {rule_id} exceeds {MAX_REVISIONS_PER_RULE} revisions")
            revision_id = f"r{revision:06d}-{content_hash[:12]}"
            revisions = entry / "revisions"
            revisions.mkdir(parents=True, exist_ok=True)
            if revisions.is_symlink():
                raise ValueError("local rule revisions directory may not be a symlink")
            revision_path = revisions / f"{revision:06d}-{content_hash[:12]}.yaml"
            if revision_path.exists():
                if revision_path.is_symlink() or revision_path.read_bytes() != content:
                    raise ValueError("local revision path collision")
            else:
                _atomic_write(revision_path, content)
            _atomic_write(entry / "current.yaml", content)
            meta = {
                "schema": ENTRY_SCHEMA,
                "ruleId": rule_id,
                "createdAtUtc": created,
                "updatedAtUtc": now,
                "revision": revision,
                "revisionId": revision_id,
                "contentSha256": content_hash,
                "ruleRevision": str(compiled.get("ruleRevision") or ""),
                "localOnly": True,
                "productionWriteBack": False,
            }
            _atomic_write(entry / "metadata.json", json.dumps(meta, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n")
            return {
                "schema": ENTRY_SCHEMA, "ok": True, "saved": True, "unchanged": False,
                "ruleId": rule_id, "revision": revision, "revisionId": revision_id,
                "yaml": canonical_yaml, "compiled": compiled, "metadata": meta,
                "store": self.reference(),
            }

    def fork_rule(self, text: str, *, new_rule_id: str) -> dict[str, Any]:
        document = srl.parse_yaml_text(text)
        rule = srl.single_rule_document(document)
        new_id = str(new_rule_id or "").strip()
        rule["id"] = new_id
        rule["status"] = "experimental"
        yaml_text = srl.authoring_graph_to_yaml(srl.rule_to_authoring_graph(rule))
        return self.save_rule(yaml_text)
