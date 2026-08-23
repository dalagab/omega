#!/usr/bin/env python3
"""One-command launcher for DeltaScope from the SigmaScope repository root.

The launcher keeps DeltaScope's Python dependencies in a repository-local virtual
environment.  Users only need a working Python 3 installation; the first launch creates
``.deltascope-venv`` and installs the pinned requirements from
``tools/requirements-security.txt``.  Subsequent launches reuse that environment until
the requirements file changes.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import venv
from typing import List, Optional

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".deltascope-venv"
REQUIREMENTS = ROOT / "tools" / "requirements-security.txt"
ENTRYPOINT = ROOT / "tools" / "security" / "deltascope.py"
MARKER = VENV_DIR / ".omega-requirements.sha256"

DELTA_COMMANDS = {
    "fetch", "serve", "serve-online", "audit", "rule-schema", "observation-schema",
    "capabilities", "definition-packs", "rule-compile", "rule-test", "rule-eval",
    "rule-parity", "rule-replay", "rule-reproject",
}


def _venv_python(venv_dir: Path = VENV_DIR) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _requirements_digest(path: Path = REQUIREMENTS) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _needs_bootstrap(venv_dir: Path = VENV_DIR, requirements: Path = REQUIREMENTS) -> bool:
    python = _venv_python(venv_dir)
    marker = venv_dir / MARKER.name
    if not python.is_file() or not marker.is_file():
        return True
    try:
        return marker.read_text(encoding="utf-8").strip() != _requirements_digest(requirements)
    except OSError:
        return True


def ensure_runtime(venv_dir: Path = VENV_DIR, requirements: Path = REQUIREMENTS) -> Path:
    """Create/update the private DeltaScope runtime and return its Python executable."""
    if not requirements.is_file():
        raise RuntimeError(f"DeltaScope requirements file is missing: {requirements}")
    entrypoint = ROOT / "tools" / "security" / "deltascope.py"
    if not entrypoint.is_file():
        raise RuntimeError(f"DeltaScope entry point is missing: {entrypoint}")

    python = _venv_python(venv_dir)
    if not python.is_file():
        print(f"DeltaScope: creating private Python environment at {venv_dir}", file=sys.stderr)
        venv.EnvBuilder(with_pip=True, clear=False).create(venv_dir)
        python = _venv_python(venv_dir)

    if _needs_bootstrap(venv_dir, requirements):
        print("DeltaScope: installing pinned Python requirements (first run or requirements changed)...", file=sys.stderr)
        subprocess.check_call([
            str(python), "-m", "pip", "install", "--disable-pip-version-check",
            "-r", str(requirements),
        ], cwd=ROOT)
        (venv_dir / MARKER.name).write_text(_requirements_digest(requirements) + "\n", encoding="utf-8")
    return python


def delta_args(argv: List[str]) -> List[str]:
    """Default a root-level launch to the online workbench while preserving full CLI use."""
    if not argv:
        return ["serve-online"]
    if argv[0] in {"-h", "--help"}:
        return argv
    if argv[0].startswith("-"):
        return ["serve-online", *argv]
    return argv


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if sys.version_info < (3, 10):
        print("DeltaScope requires Python 3.10 or newer.", file=sys.stderr)
        return 2
    try:
        python = ensure_runtime()
        command = [str(python), str(ENTRYPOINT), *delta_args(args)]
        return subprocess.call(command, cwd=ROOT)
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"DeltaScope launcher error: {exc}", file=sys.stderr)
        print("A working Python 3.10+ installation with venv/pip support is required.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
