#!/usr/bin/env python3
"""Atomically publish the small deep-scan queue/results tree to a dedicated branch."""
from __future__ import annotations
import argparse, json, shutil, subprocess, tempfile
from pathlib import Path


def run(cmd, cwd=None, capture=False):
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=capture, check=True)


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--input',type=Path,required=True);p.add_argument('--repo',type=Path,default=Path.cwd());p.add_argument('--branch',default='deep-scan-state');p.add_argument('--remote',default='origin');p.add_argument('--push',action='store_true')
    a=p.parse_args(); src=a.input.resolve(); index=json.loads((src/'index.json').read_text(encoding='utf-8'))
    if index.get('schema')!='omega.sigmascope.deep-scan-queue.v1': raise RuntimeError('invalid deep-scan queue schema')
    root=Path(run(['git','rev-parse','--show-toplevel'],cwd=a.repo,capture=True).stdout.strip()); url=run(['git','remote','get-url',a.remote],cwd=root,capture=True).stdout.strip(); old=run(['git','ls-remote','--heads',a.remote,f'refs/heads/{a.branch}'],cwd=root,capture=True).stdout.strip(); oldsha=old.split()[0] if old else ''
    info={'queueRevision':index.get('queueRevision',''),'items':len(index.get('items') or []),'branch':a.branch,'previousHead':oldsha,'pushed':False}
    if not a.push: print(json.dumps(info,indent=2)); return 0
    with tempfile.TemporaryDirectory(prefix='omega-deep-scan-publish-') as td:
        work=Path(td);run(['git','init','-q'],cwd=work);run(['git','checkout','--orphan',a.branch],cwd=work);run(['git','config','user.name','Omega Deep Scan Publisher'],cwd=work);run(['git','config','user.email','omega-deepscan@users.noreply.github.com'],cwd=work);run(['git','remote','add',a.remote,url],cwd=work)
        for path in src.rglob('*'):
            if path.is_file(): dest=work/path.relative_to(src);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest)
        run(['git','add','--all'],cwd=work);run(['git','commit','-q','-m',f"Deep scan state {index.get('queueRevision','') or 'update'}"],cwd=work);new=run(['git','rev-parse','HEAD'],cwd=work,capture=True).stdout.strip();ref=f'HEAD:refs/heads/{a.branch}'
        if oldsha: run(['git','push',f'--force-with-lease=refs/heads/{a.branch}:{oldsha}',a.remote,ref],cwd=work)
        else: run(['git','push',a.remote,ref],cwd=work)
        info.update({'pushed':True,'newHead':new})
    print(json.dumps(info,indent=2));return 0
if __name__=='__main__': raise SystemExit(main())
