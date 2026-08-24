#!/usr/bin/env python3
"""Build the bounded native symbol shim used by Rift's headless UI profile."""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path


ASCII_SYMBOL_PATTERN = re.compile(rb"\b(?:ig|Im)[A-Za-z_][A-Za-z0-9_]*\b")
UTF16_SYMBOL_PATTERN = re.compile(rb"(?:(?:i\x00g\x00)|(?:I\x00m\x00))(?:[A-Za-z0-9_]\x00)+")
SPECIAL_SYMBOLS = {
    "igGetIO": "static uintptr_t rift_headless_io[512]; uintptr_t igGetIO(void) { return (uintptr_t)rift_headless_io; }",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding", required=True, type=Path, help="Frozen Dalamud.Bindings.ImGui assembly")
    parser.add_argument("--out", required=True, type=Path, help="Output cimgui.so path")
    parser.add_argument("--cc", default="cc", help="C compiler command")
    return parser.parse_args()


def collect_symbols(binding: Path) -> list[str]:
    data = binding.read_bytes()
    symbols = {match.decode("ascii") for match in ASCII_SYMBOL_PATTERN.findall(data)}
    symbols.update(match[::2].decode("ascii") for match in UTF16_SYMBOL_PATTERN.findall(data))
    symbols = sorted(symbols)
    if "igGetIO" not in symbols or len(symbols) < 1000:
        raise RuntimeError("frozen ImGui binding did not expose the expected cimgui symbol table")
    return symbols


def build_source(symbols: list[str]) -> str:
    exports = [SPECIAL_SYMBOLS.get(symbol, f"uintptr_t {symbol}(void) {{ return 0; }}") for symbol in symbols]
    return "\n".join(
        [
            "#include <stdint.h>",
            *exports,
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    binding = args.binding.resolve()
    output = args.out.resolve()
    if not binding.is_file():
        raise SystemExit(f"frozen ImGui binding was not found: {binding}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rift-headless-cimgui-") as temporary:
        source = Path(temporary) / "headless-cimgui.c"
        source.write_text(build_source(collect_symbols(binding)), encoding="utf-8")
        subprocess.run(
            [args.cc, "-shared", "-fPIC", "-O2", "-Wl,-z,relro,-z,now", "-o", str(output), str(source)],
            check=True,
        )
    output.chmod(0o555)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
