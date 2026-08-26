#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,re
from pathlib import Path
DIGEST_RE=re.compile(r'^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$')
def main():
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--image',required=True);a=p.parse_args();d=json.loads(a.manifest.read_text());
 if d.get('schema')!='omega.worker-images.v1': raise SystemExit('unsupported worker image manifest')
 ref=str((d.get('images') or {}).get(a.image) or '')
 if not DIGEST_RE.fullmatch(ref): raise SystemExit(f'invalid/missing digest ref for {a.image}')
 print(ref);return 0
if __name__=='__main__': raise SystemExit(main())
