#!/usr/bin/env python3
"""Build and verify Omega's frozen scanner Definitions snapshot.

Definitions are refreshed at the daily publication boundary. A Sigmascope worker may
run many times during that day, but it must use the same Definitions revision. The
snapshot therefore captures:

* semantic hashes of scanner/rule-bearing source files;
* the exact Git commit containing those files;
* a frozen OSV advisory response for the exact NuGet pairs known at refresh time;
* an explicit versioned reputation-feed document (empty until such a feed exists).

The worker can checkout ``sourceCommit`` and verify the file hashes before scanning,
preventing a mid-day main-branch change from silently changing scanner semantics.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
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


def definitions_revision(
    *, scanner_version: str, scanner_rule_revision: str, fingerprints: dict[str, str],
    osv_document: dict[str, Any], reputation: dict[str, Any],
) -> str:
    semantic = {
        "schema": SCHEMA,
        "formatVersion": FORMAT_VERSION,
        "scannerVersion": scanner_version,
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
    source_commit = source_commit.strip() or git_commit(repo_root)
    fingerprints = rule_files(repo_root)
    scanner_rule_revision = rule_set_revision(fingerprints)

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
        "sourceCommit": source_commit,
        "scannerVersion": sigmascope.SCANNER_VERSION,
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


def verify_snapshot(*, repo_root: Path, definitions_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    definitions_root = definitions_root.resolve()
    errors: list[str] = []
    try:
        index = json.loads((definitions_root / "index.json").read_text(encoding="utf-8"))
    except Exception as exc:
        return {"schema": "omega.definitions.validation.v1", "ok": False, "errors": [f"index unreadable: {type(exc).__name__}: {exc}"]}
    if index.get("schema") != SCHEMA:
        errors.append(f"unsupported schema {index.get('schema')!r}")
    for rel, expected in sorted((index.get("ruleFiles") or {}).items()):
        path = repo_root / rel
        if not path.is_file():
            errors.append(f"definition file missing at worker checkout: {rel}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"definition file changed since freeze: {rel}")
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
        "sourceCommit": str(index.get("sourceCommit") or ""),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--repo-root", type=Path, default=Path.cwd())
    build.add_argument("--evidence-root", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--source-commit", default="")
    build.add_argument("--advisories-input", type=Path)
    build.add_argument("--timeout", type=float, default=20.0)
    build.add_argument("--max-packages", type=int, default=2000)
    verify = sub.add_parser("verify")
    verify.add_argument("--repo-root", type=Path, default=Path.cwd())
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
        result = verify_snapshot(repo_root=args.repo_root, definitions_root=args.definitions_root)
        if not result.get("ok"):
            print(json.dumps(result, indent=2))
            return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
