#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zipfile

p=argparse.ArgumentParser(description='Safely extract a plugin ZIP into Rift canonical artifact-tree form.')
p.add_argument('archive', type=Path)
p.add_argument('target', type=Path)
p.add_argument('--max-total', type=int, default=512*1024*1024)
p.add_argument('--max-files', type=int, default=8192)
a=p.parse_args()

archive=a.archive.resolve()
target=a.target.resolve()
target.mkdir(parents=True, exist_ok=True)

seen:set[str]=set()
file_count=0
total=0

def canonical_parts(raw:str) -> tuple[str,...]:
    # Dalamud packages are Windows-authored frequently. ZIP itself uses '/'
    # canonically, but real feeds also contain '\\'. Treat both as separators.
    name=raw.replace('\\','/')
    if '\x00' in name:
        raise SystemExit(f'NUL in ZIP path: {raw!r}')
    pp=PurePosixPath(name)
    if pp.is_absolute():
        raise SystemExit(f'absolute ZIP path: {raw!r}')
    parts=tuple(part for part in pp.parts if part not in ('', '.'))
    if not parts:
        return ()
    if any(part == '..' for part in parts):
        raise SystemExit(f'parent traversal ZIP path: {raw!r}')
    if re.fullmatch(r'[A-Za-z]:', parts[0]):
        raise SystemExit(f'drive-qualified ZIP path: {raw!r}')
    return parts

with zipfile.ZipFile(archive) as zf:
    infos=zf.infolist()
    if len(infos)>a.max_files:
        raise SystemExit(f'too many ZIP entries: {len(infos)} > {a.max_files}')

    planned=[]
    for info in infos:
        parts=canonical_parts(info.filename)
        if not parts:
            continue
        key='/'.join(parts).casefold()
        if key in seen:
            raise SystemExit(f'duplicate normalized ZIP path: {info.filename!r}')
        seen.add(key)

        mode=(info.external_attr>>16)&0xFFFF
        if stat.S_ISLNK(mode):
            raise SystemExit(f'symlink ZIP entry: {info.filename!r}')
        if info.flag_bits & 0x1:
            raise SystemExit(f'encrypted ZIP entry: {info.filename!r}')

        is_dir=info.is_dir() or info.filename.endswith(('/', '\\'))
        if not is_dir:
            file_count += 1
            total += info.file_size
            if file_count>a.max_files:
                raise SystemExit(f'too many files: {file_count} > {a.max_files}')
            if total>a.max_total:
                raise SystemExit(f'ZIP expands beyond staging limit: {total} > {a.max_total}')
        planned.append((info, parts, is_dir))

    for info,parts,is_dir in planned:
        out=target.joinpath(*parts)
        # target contains no attacker-controlled symlinks because symlink ZIP
        # entries are rejected and target begins as an empty staging directory.
        resolved=out.resolve(strict=False)
        try:
            resolved.relative_to(target)
        except ValueError:
            raise SystemExit(f'normalized extraction escaped target: {info.filename!r}')
        if is_dir:
            out.mkdir(parents=True, exist_ok=True)
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists() and out.is_dir():
            raise SystemExit(f'file/directory path collision: {info.filename!r}')
        with zf.open(info, 'r') as src, out.open('wb') as dst:
            shutil.copyfileobj(src, dst, length=1024*1024)

print(f'Rift artifact extraction: PASS files={file_count} bytes={total}')
