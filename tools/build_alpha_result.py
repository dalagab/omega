#!/usr/bin/env python3
"""Normalize independent detector output into the non-authoritative ALPHA result lane."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import Any, Mapping
from alpha_registry import load, revision


def find_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list): return [dict(x) for x in payload if isinstance(x, Mapping)]
    if not isinstance(payload, Mapping): return []
    for key in ("findings","securityFindings","rows","items"):
        value=payload.get(key)
        if isinstance(value,list): return [dict(x) for x in value if isinstance(x,Mapping)]
    # A single finding object is accepted if it exposes a detector identity.
    return [dict(payload)] if any(k in payload for k in ("findingId","ruleId","id")) else []

def fid(row: Mapping[str,Any])->str:
    return str(row.get("findingId") or row.get("ruleId") or row.get("id") or "").strip()

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--registry",type=Path,required=True); p.add_argument("--test-id",required=True); p.add_argument("--scanner-findings",type=Path); p.add_argument("--rift-result",type=Path); p.add_argument("--corpus-commit",default=""); p.add_argument("--run-id",default=""); p.add_argument("--output",type=Path,required=True); a=p.parse_args()
    reg=load(a.registry); entry=next((x for x in reg["entries"] if x["id"]==a.test_id),None)
    if entry is None: raise SystemExit(f"unknown Alpha test id: {a.test_id}")
    raw={}; rows=[]
    if a.scanner_findings and a.scanner_findings.is_file():
        raw=json.loads(a.scanner_findings.read_text(encoding="utf-8")); rows=find_rows(raw)
    expected=set(str(x) for x in (entry.get("expected") or {}).get("findingIds") or [])
    normalized=[]; observed=set()
    for row in rows:
        base=fid(row)
        if not base: continue
        observed.add(base)
        copy=dict(row)
        copy["id"]="ALPHA:"+base
        copy["alphaFindingId"]="ALPHA:"+base
        copy["productionFindingId"]=base
        copy["title"]="ALPHA: "+str(row.get("title") or base)
        copy["lane"]="alpha"; copy["syntheticSubject"]=True; copy["expected"]=base in expected
        normalized.append(copy)
    missing=sorted(expected-observed); unexpected=sorted(observed-expected)
    runtime=None
    if a.rift_result and a.rift_result.is_file(): runtime=json.loads(a.rift_result.read_text(encoding="utf-8"))
    status="pass" if not missing else "fail"
    payload={
      "schema":"omega.alpha.scan-result.v1","lane":"alpha","synthetic":True,"authority":"calibration-only",
      "testId":entry["id"],"title":entry["title"],"registryRevision":revision(reg),"corpusCommit":a.corpus_commit,"runId":a.run_id,
      "engines":entry["engines"],"safetyClass":entry["safetyClass"],"findings":normalized,
      "calibration":{"status":status,"expectedFindingIds":sorted(expected),"observedExpectedFindingIds":sorted(expected & observed),"missingFindingIds":missing,"unexpectedFindingIds":unexpected,"missingLabels":["ALPHA:"+x+":MISSING" for x in missing]},
      "runtime":runtime
    }
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8"); print(json.dumps(payload,sort_keys=True)); return 0 if status=="pass" else 3
if __name__=="__main__": raise SystemExit(main())
