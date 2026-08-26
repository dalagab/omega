#!/usr/bin/env python3
"""Publish the immutable worker-image digest manifest to a dedicated branch."""
from __future__ import annotations
import argparse, json, shutil, subprocess, tempfile
from pathlib import Path

SCHEMA="omega.worker-images.v1"

def run(cmd, cwd=None, capture=False):
    return subprocess.run(cmd,cwd=str(cwd) if cwd else None,text=True,capture_output=capture,check=True)

def main():
    p=argparse.ArgumentParser(); p.add_argument('--input',type=Path,required=True); p.add_argument('--repo',type=Path,default=Path.cwd()); p.add_argument('--branch',default='security-worker-images'); p.add_argument('--remote',default='origin'); p.add_argument('--push',action='store_true'); a=p.parse_args()
    source=a.input.resolve(); index=json.loads((source/'index.json').read_text())
    if index.get('schema')!=SCHEMA or not str(index.get('workerImagesRevision') or '').startswith('worker-images-v1-'):
        raise RuntimeError('invalid worker image manifest')
    root=Path(run(['git','rev-parse','--show-toplevel'],cwd=a.repo,capture=True).stdout.strip()); url=run(['git','remote','get-url',a.remote],cwd=root,capture=True).stdout.strip(); old=run(['git','ls-remote','--heads',a.remote,f'refs/heads/{a.branch}'],cwd=root,capture=True).stdout.strip(); oldsha=old.split()[0] if old else ''
    info={'branch':a.branch,'workerImagesRevision':index['workerImagesRevision'],'previousHead':oldsha,'pushed':False}
    if not a.push: print(json.dumps(info,indent=2)); return 0
    with tempfile.TemporaryDirectory(prefix='omega-worker-images-') as td:
        w=Path(td); run(['git','init','-q'],cwd=w); run(['git','checkout','--orphan',a.branch],cwd=w); run(['git','config','user.name','Omega Worker Image Publisher'],cwd=w); run(['git','config','user.email','omega-worker-images@users.noreply.github.com'],cwd=w); run(['git','remote','add',a.remote,url],cwd=w)
        for f in source.rglob('*'):
            if f.is_file():
                t=w/f.relative_to(source); t.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(f,t)
        run(['git','add','--all'],cwd=w); run(['git','commit','-q','-m',f"Worker images {index['workerImagesRevision']}"],cwd=w); newsha=run(['git','rev-parse','HEAD'],cwd=w,capture=True).stdout.strip(); ref=f'HEAD:refs/heads/{a.branch}'
        if oldsha: run(['git','push',f'--force-with-lease=refs/heads/{a.branch}:{oldsha}',a.remote,ref],cwd=w)
        else: run(['git','push',a.remote,ref],cwd=w)
        info.update({'pushed':True,'newHead':newsha})
    print(json.dumps(info,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
