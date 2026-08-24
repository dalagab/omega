#!/usr/bin/env python3
"""Regression checks for Rift's bounded headless ImGui symbol shim."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "tools" / "build-headless-cimgui.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("rift_headless_cimgui", BUILDER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load headless cimgui builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    contract_directory = os.environ.get("RIFT_DALAMUD_CONTRACT_DIR") or os.environ.get("RIFT_HOOKS")
    if not contract_directory:
        print("SKIP: RIFT_DALAMUD_CONTRACT_DIR or RIFT_HOOKS is not set")
        return 0

    binding = Path(contract_directory) / "Dalamud.Bindings.ImGui.dll"
    builder = load_builder()
    symbols = builder.collect_symbols(binding)
    source = builder.build_source(symbols)

    assert len(symbols) >= 1000, f"expected a complete cimgui symbol table, got {len(symbols)}"
    assert "igGetIO" in symbols
    assert "uintptr_t igGetIO(void)" in source
    assert "#include <stdint.h>" in source
    print(f"OK: validated {len(symbols)} frozen cimgui symbols")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
