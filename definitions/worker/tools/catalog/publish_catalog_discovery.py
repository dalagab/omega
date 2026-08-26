#!/usr/bin/env python3
"""Atomically publish the non-authoritative catalog discovery snapshot to an orphan branch."""
from __future__ import annotations
import argparse, json, shutil, subprocess, tempfile, sys
from pathlib import Path

SECURITY_DIR = Path(__file__).resolve().parents[1] / "security"
if str(SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_DIR))
import collector_contracts  # noqa: E402
import component_registry  # noqa: E402

SCHEMA = "omega.catalog-discovery.v1"
MAX_FILE_BYTES = 32 * 1024 * 1024


def run(cmd, cwd=None, capture=False):
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=capture, check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--repo", default=Path.cwd(), type=Path)
    ap.add_argument("--branch", default="catalog-discovery")
    ap.add_argument("--remote", default="origin")
    ap.add_argument("--push", action="store_true")
    args = ap.parse_args()
    root = args.input.resolve()
    index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    if index.get("schema") != SCHEMA:
        raise RuntimeError("unsupported catalog discovery snapshot")
    if str(index.get("collectorRegistryRevision") or "") != collector_contracts.registry_revision():
        raise RuntimeError("catalog discovery snapshot collector registry revision is stale or invalid")
    if str(index.get("componentRegistryRevision") or "") != component_registry.component_revision():
        raise RuntimeError("catalog discovery snapshot component registry revision is stale or invalid")
    observations_path = root / str((index.get("files") or {}).get("observations") or "observations.json")
    registry_path = root / str((index.get("files") or {}).get("collectorRegistry") or "collector-registry.json")
    component_registry_path = root / str((index.get("files") or {}).get("componentRegistry") or "component-registry.json")
    observations = json.loads(observations_path.read_text(encoding="utf-8"))
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    components = json.loads(component_registry_path.read_text(encoding="utf-8"))
    if observations.get("schema") != collector_contracts.BUNDLE_SCHEMA:
        raise RuntimeError("catalog discovery observation bundle schema is invalid")
    if registry.get("schema") != collector_contracts.REGISTRY_SCHEMA or registry.get("revision") != collector_contracts.registry_revision():
        raise RuntimeError("catalog discovery collector registry is invalid")
    if components.get("schema") != component_registry.REGISTRY_SCHEMA or components.get("revision") != component_registry.component_revision():
        raise RuntimeError("catalog discovery component registry is invalid")
    collector_contracts.rows_from_bundle(observations)  # validate schema/shape before publication
    files = [p for p in root.rglob("*") if p.is_file()]
    if not files or any(p.stat().st_size > MAX_FILE_BYTES for p in files):
        raise RuntimeError("catalog discovery snapshot is empty or contains an oversized file")
    info = {"schema": SCHEMA, "files": len(files), "bytes": sum(p.stat().st_size for p in files), "branch": args.branch}
    if not args.push:
        print(json.dumps(info, indent=2)); return 0
    repo = Path(run(["git", "rev-parse", "--show-toplevel"], cwd=args.repo, capture=True).stdout.strip())
    remote_url = run(["git", "remote", "get-url", args.remote], cwd=repo, capture=True).stdout.strip()
    old = run(["git", "ls-remote", "--heads", args.remote, f"refs/heads/{args.branch}"], cwd=repo, capture=True).stdout.strip()
    old_sha = old.split()[0] if old else ""
    with tempfile.TemporaryDirectory(prefix="omega-catalog-discovery-publish-") as td:
        work = Path(td)
        run(["git", "init", "-q"], cwd=work)
        run(["git", "checkout", "--orphan", args.branch], cwd=work)
        run(["git", "config", "user.name", "Omega Catalog Discovery"], cwd=work)
        run(["git", "config", "user.email", "omega-discovery@users.noreply.github.com"], cwd=work)
        run(["git", "remote", "add", args.remote, remote_url], cwd=work)
        for path in files:
            dest = work / path.relative_to(root); dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, dest)
        run(["git", "add", "--all"], cwd=work)
        run(["git", "commit", "-q", "-m", f"Catalog discovery snapshot {index.get('generatedAtUtc','')}"] , cwd=work)
        refspec = f"HEAD:refs/heads/{args.branch}"
        if old_sha:
            run(["git", "push", f"--force-with-lease=refs/heads/{args.branch}:{old_sha}", args.remote, refspec], cwd=work)
        else:
            run(["git", "push", args.remote, refspec], cwd=work)
    info["pushed"] = True
    print(json.dumps(info, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
