#!/usr/bin/env python3
"""Build/update a durable, separate security-alpha-evidence snapshot from Alpha results."""
from __future__ import annotations
import argparse, hashlib, json, shutil
from datetime import datetime, timezone
from pathlib import Path

def now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
def main()->int:
 p=argparse.ArgumentParser(); p.add_argument("--state",type=Path,required=True); p.add_argument("--result",type=Path,required=True); p.add_argument("--run-id",required=True); p.add_argument("--max-runs",type=int,default=200); a=p.parse_args()
 result=json.loads(a.result.read_text(encoding="utf-8"));
 if result.get("schema")!="omega.alpha.scan-result.v1" or result.get("lane")!="alpha" or result.get("authority")!="calibration-only": raise SystemExit("refusing non-Alpha result")
 root=a.state; runs=root/"runs"; runs.mkdir(parents=True,exist_ok=True); target=runs/str(a.run_id); target.mkdir(parents=True,exist_ok=True); shutil.copy2(a.result,target/"result.json")
 dirs=sorted([x for x in runs.iterdir() if x.is_dir()],key=lambda x:x.stat().st_mtime,reverse=True)
 for old in dirs[max(1,a.max_runs):]: shutil.rmtree(old)
 records=[]
 for d in sorted([x for x in runs.iterdir() if x.is_dir()]):
  f=d/"result.json"
  if f.is_file():
   v=json.loads(f.read_text(encoding="utf-8")); records.append({"runId":d.name,"testId":v.get("testId"),"registryRevision":v.get("registryRevision"),"calibrationStatus":(v.get("calibration") or {}).get("status"),"findingCount":len(v.get("findings") or []),"path":f"runs/{d.name}/result.json"})
 digest=hashlib.sha256(json.dumps(records,sort_keys=True,separators=(",",":")).encode()).hexdigest()
 index={"schema":"omega.alpha.evidence-index.v1","lane":"alpha","authority":"calibration-only","generatedAtUtc":now(),"revision":"alpha-evidence-v1-"+digest[:20],"runCount":len(records),"runs":records}
 (root/"index.json").write_text(json.dumps(index,indent=2,sort_keys=True)+"\n",encoding="utf-8"); print(json.dumps(index,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
