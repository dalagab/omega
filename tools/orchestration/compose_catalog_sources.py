#!/usr/bin/env python3
"""Compose a settled discovery result into the raw source inventory without network access."""
from __future__ import annotations
import argparse, json
from datetime import datetime, timezone
from pathlib import Path
import sys

CATALOG = Path(__file__).resolve().parents[1] / 'catalog'
if str(CATALOG) not in sys.path: sys.path.insert(0,str(CATALOG))
import collect_sources


def main():
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);p.add_argument('--discovery-snapshot',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    base=json.loads(a.base.read_text(encoding='utf-8'))
    if not isinstance(base,dict) or not isinstance(base.get('sources'),list): raise SystemExit('base discovery candidates are invalid')
    discovery,_fresh=collect_sources.collect_discovery_snapshot(str(a.discovery_snapshot),max_age_hours=24*365*20)
    sources=[dict(row) for row in base['sources'] if isinstance(row,dict)] + discovery
    unique=[];seen=set()
    for row in sources:
        url=str(row.get('url') or '').strip()
        if not url or url in seen: continue
        seen.add(url); unique.append(row)
    document={
      'metadata':{
        'generatedAt':datetime.now(timezone.utc).isoformat(),
        'networkCollection':False,
        'sourceCounts':{'baseDiscovery':len(base['sources']),'typedNovelDiscovery':len(discovery),'deduplicated':len(unique)}
      },
      'sources':unique,
    }
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(document,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(document['metadata']['sourceCounts'],indent=2));return 0
if __name__=='__main__': raise SystemExit(main())
