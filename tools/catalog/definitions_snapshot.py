#!/usr/bin/env python3
"""Build and verify Omega's frozen scanner Definitions snapshot.

Definitions are refreshed at the daily publication boundary. A Sigmascope worker may
run many times during that day, but it must use the same Definitions revision. The
snapshot therefore captures:

* semantic hashes of scanner/rule-bearing source files;
* a self-contained immutable worker bundle with the exact catalog/security Python code;
* a frozen OSV advisory response for the exact NuGet pairs known at refresh time;
* an explicit versioned reputation-feed document (empty until such a feed exists).

The Git branch that launches Actions is development/transport only. Scheduled workers execute
the frozen bundle carried by ``catalog-data`` and never checkout a historical development
commit. A development commit may be recorded as provenance, but it is not executable input.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import collect_public_advisories  # noqa: E402
import sigmascope  # noqa: E402

SCHEMA = "omega.definitions.v1"
FORMAT_VERSION = 1

WORKER_BUNDLE_SCHEMA = "omega.sigmascope.worker-bundle.v1"
WORKER_BUNDLE_PATH = "worker"
WORKER_BUNDLE_DIRS = ("tools/catalog", "tools/security")
WORKER_BUNDLE_EXTRA_FILES = ("sources/source-overrides.json",)

RULE_SET_FILES = (
    # Static artifact/source analysis and the helper modules whose semantics feed
    # directly into findings, source provenance, endpoint/path evidence, and
    # cross-source conclusions. Changes elsewhere in the catalog pipeline do not
    # force expensive artifact rescans.
    "tools/catalog/sigmascope.py",
    "tools/catalog/security_endpoint_inventory.py",
    "tools/catalog/security_path_access.py",
    "tools/catalog/security_hash_consensus.py",
    "tools/catalog/source_resolution.py",
    "tools/catalog/public_git_source.py",
    "tools/catalog/source_stability.py",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def git_commit(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True, capture_output=True, check=True
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def rule_files(repo_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for rel in RULE_SET_FILES:
        path = repo_root / rel
        if not path.is_file():
            raise RuntimeError(f"scanner rule-set file is missing: {rel}")
        result[rel] = sha256_file(path)
    return result


def rule_set_revision(fingerprints: dict[str, str], scanner_version: str | None = None) -> str:
    semantic = {
        "schema": "omega.sigmascope.rule-set.v1",
        "scannerVersion": str(scanner_version or sigmascope.SCANNER_VERSION),
        "files": fingerprints,
    }
    return f"rules-v1-{sha256_bytes(canonical(semantic))[:16]}"


def worker_bundle_files(repo_root: Path) -> list[str]:
    files: set[str] = set()
    for rel_dir in WORKER_BUNDLE_DIRS:
        directory = repo_root / rel_dir
        if not directory.is_dir():
            raise RuntimeError(f"worker bundle directory is missing: {rel_dir}")
        for path in directory.rglob("*.py"):
            if path.is_file() and "__pycache__" not in path.parts:
                files.add(path.relative_to(repo_root).as_posix())
    for rel in WORKER_BUNDLE_EXTRA_FILES:
        if not (repo_root / rel).is_file():
            raise RuntimeError(f"worker bundle file is missing: {rel}")
        files.add(rel)
    return sorted(files)


def build_worker_bundle(repo_root: Path, definitions_root: Path) -> dict[str, Any]:
    bundle_root = definitions_root / WORKER_BUNDLE_PATH
    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for rel in worker_bundle_files(repo_root):
        source = repo_root / rel
        destination = bundle_root / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        size = destination.stat().st_size
        total_bytes += size
        entries.append({"path": rel, "sha256": sha256_file(destination), "bytes": size})
    semantic = {"schema": WORKER_BUNDLE_SCHEMA, "files": entries}
    scanner_revision = f"scanner-v1-{sha256_bytes(canonical(semantic))[:16]}"
    manifest = {
        "schema": WORKER_BUNDLE_SCHEMA,
        "scannerRevision": scanner_revision,
        "fileCount": len(entries),
        "totalBytes": total_bytes,
        "files": entries,
    }
    manifest_path = bundle_root / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {
        "path": WORKER_BUNDLE_PATH,
        "manifestPath": f"{WORKER_BUNDLE_PATH}/manifest.json",
        "sha256": sha256_file(manifest_path),
        "scannerRevision": scanner_revision,
        "fileCount": len(entries),
        "totalBytes": total_bytes,
    }


def verify_worker_bundle(definitions_root: Path, descriptor: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    manifest_rel = str(descriptor.get("manifestPath") or "")
    expected_manifest_sha = str(descriptor.get("sha256") or "")
    manifest_path = definitions_root / manifest_rel
    if not manifest_rel or not manifest_path.is_file():
        return [f"worker bundle manifest missing: {manifest_rel or '<unset>'}"]
    if sha256_file(manifest_path) != expected_manifest_sha:
        errors.append("worker bundle manifest SHA-256 mismatch")
        return errors
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"worker bundle manifest unreadable: {type(exc).__name__}: {exc}"]
    if manifest.get("schema") != WORKER_BUNDLE_SCHEMA:
        errors.append(f"unsupported worker bundle schema: {manifest.get('schema')!r}")
    entries = [item for item in manifest.get("files") or [] if isinstance(item, dict)]
    semantic_entries: list[dict[str, Any]] = []
    total_bytes = 0
    bundle_root = definitions_root / str(descriptor.get("path") or WORKER_BUNDLE_PATH)
    for item in entries:
        rel = str(item.get("path") or "")
        expected = str(item.get("sha256") or "")
        expected_bytes = int(item.get("bytes") or 0)
        path = bundle_root / rel
        if not rel or not path.is_file():
            errors.append(f"worker bundle file missing: {rel or '<unset>'}")
            continue
        actual_bytes = path.stat().st_size
        if actual_bytes != expected_bytes:
            errors.append(f"worker bundle file size mismatch: {rel}")
        if sha256_file(path) != expected:
            errors.append(f"worker bundle file SHA-256 mismatch: {rel}")
        total_bytes += actual_bytes
        semantic_entries.append({"path": rel, "sha256": expected, "bytes": expected_bytes})
    expected_revision = f"scanner-v1-{sha256_bytes(canonical({'schema': WORKER_BUNDLE_SCHEMA, 'files': semantic_entries}))[:16]}"
    manifest_revision = str(manifest.get("scannerRevision") or "")
    descriptor_revision = str(descriptor.get("scannerRevision") or "")
    if expected_revision != manifest_revision or expected_revision != descriptor_revision:
        errors.append("scanner revision does not match frozen worker bundle")
    if len(entries) != int(descriptor.get("fileCount") or 0):
        errors.append("worker bundle file count mismatch")
    if total_bytes != int(descriptor.get("totalBytes") or 0):
        errors.append("worker bundle byte count mismatch")
    return errors


def definitions_revision(
    *, scanner_version: str, scanner_revision: str, scanner_rule_revision: str, fingerprints: dict[str, str],
    osv_document: dict[str, Any], reputation: dict[str, Any],
) -> str:
    semantic = {
        "schema": SCHEMA,
        "formatVersion": FORMAT_VERSION,
        "scannerVersion": scanner_version,
        "scannerRevision": scanner_revision,
        "ruleSetRevision": scanner_rule_revision,
        "ruleFiles": fingerprints,
        "osv": _semantic_osv(osv_document),
        "reputation": reputation,
    }
    return f"defs-v1-{sha256_bytes(canonical(semantic))[:16]}"


def _semantic_osv(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": document.get("schema"),
        "source": document.get("source"),
        "ecosystem": document.get("ecosystem"),
        "queriedPackages": int(document.get("queriedPackages") or 0),
        "matchedPackages": int(document.get("matchedPackages") or 0),
        # The exact frozen query universe is semantic. Two days that happened to query the
        # same number of packages must not share a Definitions revision when the package/version
        # identities differ.
        "queriedPackageVersionPairs": sorted(
            [
                {"name": str(item.get("name") or ""), "version": str(item.get("version") or "")}
                for item in document.get("queriedPackageVersionPairs") or []
                if isinstance(item, dict) and str(item.get("name") or "") and str(item.get("version") or "")
            ],
            key=lambda item: (item["name"].casefold(), item["version"]),
        ),
        "advisories": document.get("advisories") or [],
    }


def build_snapshot(
    *,
    repo_root: Path,
    evidence_root: Path,
    output: Path,
    source_commit: str = "",
    advisories_input: Path | None = None,
    timeout: float = 20.0,
    max_packages: int = 2000,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = evidence_root.resolve()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    built_from_dev_commit = source_commit.strip() or git_commit(repo_root)
    fingerprints = rule_files(repo_root)
    scanner_rule_revision = rule_set_revision(fingerprints)
    worker_bundle = build_worker_bundle(repo_root, output)
    scanner_revision = str(worker_bundle["scannerRevision"])

    evidence_index_path = evidence_root / "index.json"
    evidence_index = json.loads(evidence_index_path.read_text(encoding="utf-8")) if evidence_index_path.is_file() else {}
    evidence_revision = str((evidence_index.get("revisions") or {}).get("evidenceRevision") or "")
    nuget_meta = (evidence_index.get("indexes") or {}).get("nuget") or {}
    nuget_path = evidence_root / str(nuget_meta.get("path") or "indexes/nuget.json")

    osv_path = output / "osv-advisories.json"
    if advisories_input is not None:
        document = json.loads(advisories_input.read_text(encoding="utf-8"))
        osv_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif nuget_path.is_file():
        document = collect_public_advisories.collect_from_nuget_index(
            nuget_path, osv_path, timeout=timeout, max_packages=max_packages
        )
    else:
        document = {
            "schema": "omega.public-advisories.v1",
            "generatedAtUtc": utc_now(),
            "source": "OSV",
            "ecosystem": "NuGet",
            "queriedPackages": 0,
            "matchedPackages": 0,
            "advisories": [],
        }
        osv_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Preserve the exact package/version query set beside the frozen advisory response.
    # New dependencies discovered by workers during the day remain explicitly uncovered
    # until the next Definitions refresh rather than triggering live OSV calls.
    queried_pairs: list[dict[str, str]] = []
    if nuget_path.is_file():
        for name, version in collect_public_advisories.observed_nuget_index(nuget_path, max_packages):
            queried_pairs.append({"name": name, "version": version})
    document["queriedPackageVersionPairs"] = queried_pairs
    osv_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    reputation = {
        "schema": "omega.reputation-definitions.v1",
        "feeds": [],
        "policy": "No third-party URL/IP reputation feed is enabled. Findings remain static and deterministic.",
    }
    reputation_path = output / "reputation.json"
    reputation_path.write_text(json.dumps(reputation, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    revision = definitions_revision(
        scanner_version=sigmascope.SCANNER_VERSION,
        scanner_revision=scanner_revision,
        scanner_rule_revision=scanner_rule_revision,
        fingerprints=fingerprints,
        osv_document=document,
        reputation=reputation,
    )
    index = {
        "schema": SCHEMA,
        "formatVersion": FORMAT_VERSION,
        "definitionsRevision": revision,
        "generatedAtUtc": utc_now(),
        "builtFromDevCommit": built_from_dev_commit,
        "scannerVersion": sigmascope.SCANNER_VERSION,
        "scannerRevision": scanner_revision,
        "scannerBundle": worker_bundle,
        "sourceEvidenceRevision": evidence_revision,
        "ruleSetRevision": scanner_rule_revision,
        "ruleFiles": fingerprints,
        "osv": {
            "path": "osv-advisories.json",
            "sha256": sha256_file(osv_path),
            "queriedPackages": int(document.get("queriedPackages") or 0),
            "matchedPackages": int(document.get("matchedPackages") or 0),
            "semanticSha256": sha256_bytes(canonical(_semantic_osv(document))),
        },
        "reputation": {
            "path": "reputation.json",
            "sha256": sha256_file(reputation_path),
            "feeds": 0,
        },
    }
    (output / "index.json").write_text(json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return index


def verify_snapshot(*, definitions_root: Path, repo_root: Path | None = None) -> dict[str, Any]:
    definitions_root = definitions_root.resolve()
    errors: list[str] = []
    try:
        index = json.loads((definitions_root / "index.json").read_text(encoding="utf-8"))
    except Exception as exc:
        return {"schema": "omega.definitions.validation.v1", "ok": False, "errors": [f"index unreadable: {type(exc).__name__}: {exc}"]}
    if index.get("schema") != SCHEMA:
        errors.append(f"unsupported schema {index.get('schema')!r}")
    worker_bundle = index.get("scannerBundle") if isinstance(index.get("scannerBundle"), dict) else {}
    errors.extend(verify_worker_bundle(definitions_root, worker_bundle))
    bundle_root = definitions_root / str(worker_bundle.get("path") or WORKER_BUNDLE_PATH)
    for rel, expected in sorted((index.get("ruleFiles") or {}).items()):
        path = bundle_root / rel
        if not path.is_file():
            errors.append(f"frozen scanner rule file missing from worker bundle: {rel}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"frozen scanner rule file hash mismatch: {rel}")
    payloads: dict[str, dict[str, Any]] = {}
    for key in ("osv", "reputation"):
        item = index.get(key) or {}
        rel = str(item.get("path") or "")
        path = definitions_root / rel
        if not path.is_file():
            errors.append(f"definitions payload missing: {rel}")
        elif str(item.get("sha256") or "") != sha256_file(path):
            errors.append(f"definitions payload hash mismatch: {rel}")
        else:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                payloads[key] = value if isinstance(value, dict) else {}
            except Exception as exc:
                errors.append(f"definitions payload unreadable: {rel}: {type(exc).__name__}: {exc}")
    scanner_version = str(index.get("scannerVersion") or "")
    fingerprints = {str(k): str(v) for k, v in (index.get("ruleFiles") or {}).items()}
    expected_rule_set = rule_set_revision(fingerprints, scanner_version=scanner_version) if fingerprints else ""
    if expected_rule_set != str(index.get("ruleSetRevision") or ""):
        errors.append("rule-set revision does not match frozen scanner rule files")
    if "osv" in payloads and "reputation" in payloads and expected_rule_set:
        expected_definitions = definitions_revision(
            scanner_version=scanner_version,
            scanner_revision=str(index.get("scannerRevision") or ""),
            scanner_rule_revision=expected_rule_set,
            fingerprints=fingerprints,
            osv_document=payloads["osv"],
            reputation=payloads["reputation"],
        )
        if expected_definitions != str(index.get("definitionsRevision") or ""):
            errors.append("Definitions revision does not match frozen semantic payload")
    return {
        "schema": "omega.definitions.validation.v1",
        "ok": not errors,
        "definitionsRevision": str(index.get("definitionsRevision") or ""),
        "ruleSetRevision": str(index.get("ruleSetRevision") or ""),
        "scannerRevision": str(index.get("scannerRevision") or ""),
        "scannerBundleSha256": str((index.get("scannerBundle") or {}).get("sha256") or ""),
        "builtFromDevCommit": str(index.get("builtFromDevCommit") or ""),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--repo-root", type=Path, default=Path.cwd())
    build.add_argument("--evidence-root", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--built-from-dev-commit", "--source-commit", dest="source_commit", default="", help="Optional development provenance only; never an execution dependency")
    build.add_argument("--advisories-input", type=Path)
    build.add_argument("--timeout", type=float, default=20.0)
    build.add_argument("--max-packages", type=int, default=2000)
    verify = sub.add_parser("verify")
    verify.add_argument("--definitions-root", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        result = build_snapshot(
            repo_root=args.repo_root,
            evidence_root=args.evidence_root,
            output=args.output,
            source_commit=args.source_commit,
            advisories_input=args.advisories_input,
            timeout=args.timeout,
            max_packages=args.max_packages,
        )
    else:
        result = verify_snapshot(definitions_root=args.definitions_root)
        if not result.get("ok"):
            print(json.dumps(result, indent=2))
            return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
