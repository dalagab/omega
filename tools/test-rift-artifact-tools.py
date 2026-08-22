#!/usr/bin/env python3
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import zipfile

root=Path(__file__).resolve().parents[1]
extractor=root/'tools/extract-rift-artifact.py'
hasher=root/'tools/hash-artifact-tree.py'

with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    archive=td/'windows-paths.zip'
    target=td/'tree'
    with zipfile.ZipFile(archive,'w') as z:
        z.writestr(r'Images\\Icon.png', b'icon')
        z.writestr('Artisan.dll', b'dll')
    subprocess.run([sys.executable,str(extractor),str(archive),str(target)],check=True,capture_output=True,text=True)
    assert (target/'Images'/'Icon.png').read_bytes()==b'icon'
    assert not any('\\' in p.name for p in target.rglob('*'))
    first=subprocess.check_output([sys.executable,str(hasher),str(target)],text=True).strip()
    second=subprocess.check_output([sys.executable,str(hasher),str(target)],text=True).strip()
    assert first==second and len(first)==64

    dup=td/'duplicate.zip'
    with zipfile.ZipFile(dup,'w') as z:
        z.writestr(r'Images\\Icon.png',b'a')
        z.writestr('images/icon.png',b'b')
    r=subprocess.run([sys.executable,str(extractor),str(dup),str(td/'dup-tree')],capture_output=True,text=True)
    assert r.returncode != 0
    assert 'duplicate normalized ZIP path' in (r.stdout+r.stderr)

print('Rift artifact tool self-test: PASS')
