"""Compute narrow semantic revisions for Sigmascope artifact and source analysis.

The frozen worker bundle SHA identifies *all* executable worker bytes.  It is an
execution-integrity identity and therefore changes for queue/publisher/transport edits
that must not force plugin code to be re-analysed.

This module instead fingerprints the transitive top-level Python symbols reachable from
explicit artifact/source analysis roots in ``sigmascope.py`` plus the small helper files
whose semantics those analyses consume.  The resulting revisions are safe queue/cache
identities and remain stable across unrelated scheduler/publication edits.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "omega.sigmascope.analysis-revisions.v1"

ARTIFACT_ROOT_SYMBOLS = (
    "_build_artifact_analysis",
    "_finalize_findings",
    "_load_cached_artifact_analysis",
    "_apply_artifact_analysis",
)
SOURCE_ROOT_SYMBOLS = (
    "scan_source_row",
    "fetch_source",
    "_source_payload",
    "_load_cached_source_analysis",
    "_apply_source_analysis",
    "_source_candidates_for_row",
)

ARTIFACT_SUPPORT_FILES = (
    "tools/catalog/security_endpoint_inventory.py",
    "tools/catalog/security_path_access.py",
    "tools/catalog/security_secondary_engines.py",
    "tools/catalog/secondary_security_assets.py",
    "tools/catalog/security_binary_classifier.py",
    "tools/catalog/security_component_summary.py",
)
SOURCE_SUPPORT_FILES = (
    "tools/catalog/source_resolution.py",
    "tools/catalog/public_git_source.py",
    "tools/catalog/source_stability.py",
    "tools/catalog/artifact_source_model.py",
    "tools/catalog/security_endpoint_inventory.py",
    "tools/catalog/security_path_access.py",
    "tools/catalog/security_component_summary.py",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _top_level_symbols(tree: ast.Module) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = node
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            result[node.target.id] = node
    return result


def symbol_closure(path: Path, roots: Iterable[str]) -> dict[str, str]:
    """Return canonical AST dumps for the transitive top-level symbol closure."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    symbols = _top_level_symbols(tree)
    missing = [name for name in roots if name not in symbols]
    if missing:
        raise RuntimeError(f"analysis revision roots missing from {path.name}: {', '.join(missing)}")
    selected: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        node = symbols.get(name)
        if node is None:
            continue
        selected.add(name)
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in symbols and child.id not in selected:
                pending.append(child.id)
    return {
        name: ast.dump(symbols[name], annotate_fields=True, include_attributes=False)
        for name in sorted(selected)
    }


def _python_semantic_sha(path: Path) -> str:
    """Hash Python semantics rather than formatting/comments for support modules."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    semantic = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return _sha256(semantic.encode("utf-8"))


def _revision(repo_root: Path, *, kind: str, roots: Iterable[str], support_files: Iterable[str]) -> tuple[str, dict[str, Any]]:
    sigmascope_path = repo_root / "tools/catalog/sigmascope.py"
    closure = symbol_closure(sigmascope_path, roots)
    support: dict[str, str] = {}
    for rel in support_files:
        path = repo_root / rel
        if not path.is_file():
            raise RuntimeError(f"analysis support file is missing: {rel}")
        support[rel] = _python_semantic_sha(path)
    semantic = {
        "schema": SCHEMA,
        "kind": kind,
        "sigmascopeSymbols": closure,
        "supportFiles": support,
    }
    prefix = "artifact-analysis-v1" if kind == "artifact" else "source-analysis-v1"
    return f"{prefix}-{_sha256(_canonical(semantic))[:16]}", semantic


def compute(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    artifact_revision, artifact_semantic = _revision(
        repo_root, kind="artifact", roots=ARTIFACT_ROOT_SYMBOLS, support_files=ARTIFACT_SUPPORT_FILES,
    )
    source_revision, source_semantic = _revision(
        repo_root, kind="source", roots=SOURCE_ROOT_SYMBOLS, support_files=SOURCE_SUPPORT_FILES,
    )
    return {
        "schema": SCHEMA,
        "artifactAnalysisRevision": artifact_revision,
        "sourceAnalysisRevision": source_revision,
        "artifact": artifact_semantic,
        "source": source_semantic,
    }
