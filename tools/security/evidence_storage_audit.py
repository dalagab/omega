#!/usr/bin/env python3
"""Measure Evidence-v2 storage by responsibility without deleting any evidence."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from collections import defaultdict


def sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()


def area(rel: str) -> str:
    first=rel.split('/',1)[0]
    if first in {'artifacts','variants','history','derived','indexes','rule-projections','terminal'}: return first
    if rel == 'scanner-queue.json': return 'scanner-queue'
    return 'root'


def audit(root: Path) -> dict:
    files=[p for p in root.rglob('*') if p.is_file() and '.git' not in p.parts]
    areas=defaultdict(lambda:{'files':0,'bytes':0})
    hashes=defaultdict(list)
    for p in files:
        rel=p.relative_to(root).as_posix(); size=p.stat().st_size; a=area(rel)
        areas[a]['files']+=1; areas[a]['bytes']+=size
        hashes[sha(p)].append((rel,size))
    duplicate_groups=[]; duplicate_bytes=0
    for digest, members in hashes.items():
        if len(members)<2: continue
        size=members[0][1]; duplicate_bytes += size*(len(members)-1)
        duplicate_groups.append({'sha256':digest,'bytesEach':size,'copies':len(members),'paths':[m[0] for m in members[:12]]})
    duplicate_groups.sort(key=lambda x: -(x['bytesEach']*(x['copies']-1)))
    total=sum(p.stat().st_size for p in files)
    return {
        'schema':'omega.security-evidence.storage-audit.v1','files':len(files),'bytes':total,
        'areas':dict(sorted(areas.items())),'exactDuplicateBytes':duplicate_bytes,
        'largestExactDuplicateGroups':duplicate_groups[:30],
        'historyToCurrentVariantRatio': (areas['history']['bytes']/areas['variants']['bytes']) if areas['variants']['bytes'] else None,
        'note':'Exact duplicate SHA groups are diagnostic only; content-addressed reuse and projected summaries may be intentional.'
    }


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--root',required=True,type=Path); ap.add_argument('--report',type=Path); args=ap.parse_args()
    result=audit(args.root); text=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if args.report: args.report.parent.mkdir(parents=True,exist_ok=True); args.report.write_text(text,encoding='utf-8')
    print(text,end=''); return 0
if __name__=='__main__': raise SystemExit(main())
