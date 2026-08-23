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
exercise=d.get("exercise") or {}

def uniq_append(lst, item):
    key=json.dumps(item, sort_keys=True)
    if key not in {json.dumps(x, sort_keys=True) for x in lst}: lst.append(item)

inj=[]; access=[]; gaps=[]; blockers=[]; hooks=[]; signatures=[]; native_state=[]; registrations=[]; exercised=[]; emulation=[]
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
    elif kind=="native_game_state":
        uniq_append(native_state, item)
        uniq_append(emulation, {"type":"synthetic-native-game-state", **item})
    elif kind=="registration":
        uniq_append(registrations, item)
    elif kind=="exercise":
        uniq_append(exercised, item)
        if str(o.get("outcome") or "").lower() in {"threw","timeout"}:
            uniq_append(blockers, {"type":"exercise-callback", **item})
    elif kind=="exception":
        uniq_append(blockers, {"type":"exception", **item})
    elif kind=="timeout":
        uniq_append(blockers, {"type":"timeout", **item})

load=plugin.get("load_outcome")
if load and load!="ok":
    blockers.insert(0, {"type":"plugin-load","outcome":load,"detail":plugin.get("load_error")})

# Classify only plugin-behavior-bearing fields. Do not scan the entire report blob:
# exercise/boundary metadata such as network_boundary=isolated must never create a
# false claim that the plugin touched networking.
def behavior_text(o):
    kind=str(o.get("kind") or "").lower()
    if kind in {"boundary"}:
        return ""
    component=str(o.get("component") or "").lower()
    operation=str(o.get("operation") or "").lower()
    params=o.get("parameters") or {}
    registration_kind=str(params.get("registration_kind") or "").lower()
    return " ".join((kind, component, operation, registration_kind))

behavior_blob="\n".join(filter(None, (behavior_text(o) for o in obs)))
cats=[]
for needles,cat in (
    (("ipc",),"plugin-ipc"),
    (("ffxivclientstructs","native_game_state"),"game-native-structs"),
    (("idatamanager","excelsheet","gamedata"),"game-data"),
    (("texture",),"textures"),
    (("framework",),"framework-events"),
    (("condition",),"condition-state"),
    (("clientstate",),"client-state"),
    (("command",),"command-manager"),
    (("uibuilder",),"ui-builder"),
    (("window",),"windowing"),
    (("hook",),"game-hooks"),
    (("signature","addressresolver"),"signature-scanning"),
    (("http","socket","connect","dns","networkstream","webrequest","httpclient"),"network"),
):
    if any(needle in behavior_blob for needle in needles) and cat not in cats:
        cats.append(cat)

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
 "observed_native_game_state_operations":native_state,
 "observed_registrations":registrations,
 "observed_exercise_operations":exercised,
 "exercise":exercise,
 "emulation_limits":emulation,
 "blockers":blockers,
 "coverage_categories_touched":cats,
 "interpretation":{
   "startup_ok":load=="ok",
   "full_plugin_functionality_proven":False,
   "note":"Startup and post-init exercise are bounded. Missing observations mean not observed, not impossible."
 }
}
a.out.parent.mkdir(parents=True,exist_ok=True)
a.out.write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8")
print(f"Coverage-gap report: startup={load} exercise={exercise.get('status')} registrations={len(registrations)} exercised={len(exercised)} injections={len(inj)} accesses={len(access)} hooks={len(hooks)} signatures={len(signatures)} native_state={len(native_state)} emulation={len(emulation)} gaps={len(gaps)} blockers={len(blockers)}")
for b in blockers[:8]:
    print("blocker:", b.get("exception_type") or b.get("outcome") or b.get("type"), b.get("exception_message") or b.get("detail") or "")
