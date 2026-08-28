#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "omega.alpha.registry.v1"
TEST_SCHEMA = "omega.alpha.test.v1"
ID_RE = re.compile(r"^alpha\.[a-z0-9][a-z0-9._-]+$")
ALLOWED_ENGINES = {"sigmascope", "rift", "srl"}
ALLOWED_MODES = {"static-only", "sandbox-runtime"}
ALLOWED_SAFETY = {"inert-static", "sandbox-local-runtime"}
ALLOWED_STATUS = {"draft", "candidate", "active", "retired"}

def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()

def revision(doc: dict[str, Any]) -> str:
    semantic = {"schema": doc.get("schema"), "branch": doc.get("branch"), "entries": doc.get("entries") or []}
    return "alpha-registry-v1-" + hashlib.sha256(canonical(semantic)).hexdigest()[:20]

def _read_manifest(path: Path, root: Path) -> dict[str, Any]:
    row=json.loads(path.read_text(encoding="utf-8"))
    if row.get("schema") != TEST_SCHEMA: raise ValueError(f"{path}: schema must be {TEST_SCHEMA}")
    project=str(row.get("project") or "")
    if not project or PurePosixPath(project).is_absolute() or ".." in PurePosixPath(project).parts or "/" in project or "\\" in project:
        raise ValueError(f"{path}: project must be a local project filename")
    rel_manifest=path.relative_to(root).as_posix()
    project_path=(path.parent/project)
    if not project_path.is_file(): raise ValueError(f"{path}: project does not exist: {project}")
    out={k:v for k,v in row.items() if k not in {"schema","project"}}
    out["manifestPath"]=rel_manifest
    out["projectPath"]=project_path.relative_to(root).as_posix()
    return out

def discover(root: Path) -> list[dict[str, Any]]:
    rows=[_read_manifest(path,root) for path in sorted((root/"tests").glob("**/alpha.json")) if not ({"bin","obj"}&set(path.relative_to(root).parts))]
    rows.sort(key=lambda x:str(x.get("id") or ""))
    return rows

def generated_document(root: Path) -> dict[str, Any]:
    return {"schema":SCHEMA,"branch":"alpha","description":"Harmless adversarial Alpha scenarios and static fixtures. Runtime Alphas execute only in the dedicated Rift Alpha boundary.","entries":discover(root)}

def validate_document(doc: dict[str, Any], path: Path) -> None:
    errors=[]
    if doc.get("schema") != SCHEMA: errors.append(f"schema must be {SCHEMA}")
    if doc.get("branch") != "alpha": errors.append("branch must be alpha")
    entries=doc.get("entries") if isinstance(doc.get("entries"),list) else []
    if not isinstance(doc.get("entries"),list): errors.append("entries must be an array")
    seen=set(); root=path.resolve().parents[1]
    for i,row in enumerate(entries):
        if not isinstance(row,dict): errors.append(f"entry {i} must be an object"); continue
        test_id=str(row.get("id") or "")
        if not ID_RE.fullmatch(test_id): errors.append(f"entry {i} has invalid id {test_id!r}")
        if test_id in seen: errors.append(f"duplicate id {test_id}")
        seen.add(test_id)
        for key in ("manifestPath","projectPath"):
            rel=PurePosixPath(str(row.get(key) or ""))
            if rel.is_absolute() or ".." in rel.parts or not rel.parts or rel.parts[0] != "tests" or not (root/Path(*rel.parts)).is_file(): errors.append(f"{test_id}: invalid {key}")
        engines=row.get("engines") if isinstance(row.get("engines"),list) else []
        if not engines or any(x not in ALLOWED_ENGINES for x in engines): errors.append(f"{test_id}: invalid engines")
        mode=str(row.get("mode") or ""); safety=str(row.get("safetyClass") or ""); status=str(row.get("status") or "")
        if mode not in ALLOWED_MODES: errors.append(f"{test_id}: invalid mode")
        if safety not in ALLOWED_SAFETY: errors.append(f"{test_id}: invalid safetyClass")
        if status not in ALLOWED_STATUS: errors.append(f"{test_id}: invalid status")
        if mode=="static-only" and safety!="inert-static": errors.append(f"{test_id}: static-only must be inert-static")
        if mode=="sandbox-runtime" and (safety!="sandbox-local-runtime" or "rift" not in engines): errors.append(f"{test_id}: sandbox-runtime must use Rift and sandbox-local-runtime")
        if not isinstance(row.get("expected"),dict): errors.append(f"{test_id}: expected must be an object")
    if errors: raise ValueError("\n".join(errors))

def load(path: Path, require_synced: bool=True) -> dict[str, Any]:
    doc=json.loads(path.read_text(encoding="utf-8")); validate_document(doc,path)
    if require_synced:
        expected=generated_document(path.resolve().parents[1])
        if canonical(doc)!=canonical(expected): raise ValueError("registry is stale; run: python tools/alpha_registry.py build")
    return doc

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--registry",type=Path,default=Path(__file__).resolve().parents[1]/"registry/registry.json")
    sub=p.add_subparsers(dest="cmd",required=True); sub.add_parser("validate"); sub.add_parser("list"); sub.add_parser("build")
    r=sub.add_parser("resolve"); r.add_argument("--id",required=True); r.add_argument("--github-output",type=Path)
    a=p.parse_args(); root=a.registry.resolve().parents[1]
    if a.cmd=="build":
        doc=generated_document(root); validate_document(doc,a.registry); a.registry.parent.mkdir(parents=True,exist_ok=True); a.registry.write_text(json.dumps(doc,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        print(json.dumps({"ok":True,"entries":len(doc["entries"]),"registryRevision":revision(doc),"registry":str(a.registry)},sort_keys=True)); return 0
    doc=load(a.registry); rev=revision(doc)
    if a.cmd=="validate": print(json.dumps({"ok":True,"entries":len(doc["entries"]),"registryRevision":rev},sort_keys=True)); return 0
    if a.cmd=="list": print(json.dumps({"schema":SCHEMA,"registryRevision":rev,"entries":doc["entries"]},indent=2,sort_keys=True)); return 0
    row=next((x for x in doc["entries"] if x.get("id")==a.id),None)
    if row is None: raise SystemExit(f"unknown Alpha test id: {a.id}")
    out={**row,"registryRevision":rev}
    if a.github_output:
        lines={"test_id":row["id"],"manifest_path":row["manifestPath"],"project_path":row["projectPath"],"assembly_name":row["assemblyName"],"entry_assembly":row["entryAssembly"],"mode":row["mode"],"engines":",".join(row["engines"]),"registry_revision":rev}
        with a.github_output.open("a",encoding="utf-8") as f:
            for k,v in lines.items(): f.write(f"{k}={v}\n")
    print(json.dumps(out,indent=2,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
