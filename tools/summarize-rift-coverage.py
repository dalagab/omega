#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument("report", type=Path)
p.add_argument("--out", type=Path, required=True)
p.add_argument("--subject", default="")
a=p.parse_args()

d=json.loads(a.report.read_text(encoding="utf-8"))
plugin=d.get("plugin") or {}
obs=d.get("observations") or []

def uniq_append(lst, item):
    key=json.dumps(item, sort_keys=True)
    if key not in {json.dumps(x, sort_keys=True) for x in lst}: lst.append(item)

inj=[]; access=[]; gaps=[]; blockers=[]; hooks=[]; signatures=[]; emulation=[]
for o in obs:
    kind=str(o.get("kind") or "").lower()
    item={k:o.get(k) for k in ("component","operation","outcome","message","exception_type","exception_message","exception_detail","context","parameters")}
    if kind=="service_injection": uniq_append(inj,item)
    elif kind=="service_access": uniq_append(access,item)
    elif kind in {"assembly_load","native_library"} and str(o.get("outcome")).lower() not in {"ok","loaded","resolved","success"}:
        uniq_append(gaps, {"type":kind.replace("_","-"), **item})
    elif kind=="hook":
        uniq_append(hooks, item)
        if "synthetic" in str(o.get("outcome") or "").lower() or "inert" in str(o.get("outcome") or "").lower():
            uniq_append(emulation, {"type":"synthetic-hook", **item})
    elif kind=="signature_scan":
        uniq_append(signatures, item)
        if "synthetic" in str(o.get("outcome") or "").lower():
            uniq_append(emulation, {"type":"synthetic-signature", **item})
    elif kind=="exception":
        uniq_append(blockers, {"type":"exception", **item})
    elif kind=="timeout":
        uniq_append(blockers, {"type":"timeout", **item})

load=plugin.get("load_outcome")
if load and load!="ok":
    blockers.insert(0, {"type":"plugin-load","outcome":load,"detail":plugin.get("load_error")})

blob=json.dumps(obs, sort_keys=True).lower()
cats=[]
for needle,cat in (
    ("ipc","plugin-ipc"),("ffxivclientstructs","game-native-structs"),
    ("gamedata","game-data"),("texture","textures"),("framework","framework-events"),
    ("condition","condition-state"),("clientstate","client-state"),
    ("command","command-manager"),("uibuilder","ui-builder"),("window","windowing"),
    ("hook","game-hooks"),("signature","signature-scanning"),("addressresolver","signature-scanning"),
    ("network","network"),
):
    if needle in blob and cat not in cats: cats.append(cat)

payload={
 "schema_version":"rift.coverage-gap.v1",
 "producer":"rift-coverage-gap-summarizer",
 "subject":a.subject or plugin.get("internal_name") or plugin.get("assembly_name"),
 "rift_schema":d.get("schema_version"),
 "plugin":{k:plugin.get(k) for k in ("assembly_name","internal_name","load_outcome","load_error","init_duration_ms","dispose_outcome")},
 "observed_service_injections":inj,
 "observed_service_accesses":access,
 "runtime_gaps":gaps,
 "observed_hook_operations":hooks,
 "observed_signature_operations":signatures,
 "emulation_limits":emulation,
 "blockers":blockers,
 "coverage_categories_touched":cats,
 "interpretation":{
   "startup_ok":load=="ok",
   "full_plugin_functionality_proven":False,
   "note":"Startup exercise is bounded. Missing observations mean not observed, not impossible."
 }
}
a.out.parent.mkdir(parents=True,exist_ok=True)
a.out.write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8")
print(f"Coverage-gap report: startup={load} injections={len(inj)} accesses={len(access)} hooks={len(hooks)} signatures={len(signatures)} emulation={len(emulation)} gaps={len(gaps)} blockers={len(blockers)}")
for b in blockers[:8]:
    print("blocker:", b.get("exception_type") or b.get("outcome") or b.get("type"), b.get("exception_message") or b.get("detail") or "")
