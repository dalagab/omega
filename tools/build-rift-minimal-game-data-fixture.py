#!/usr/bin/env python3
"""Create a tiny synthetic FDT fixture pack for headless plugin qualification."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


def empty_fdt() -> bytes:
    font_table_offset = 32
    kerning_table_offset = 64
    data = bytearray(80)
    data[0:8] = b"fcsv\0\0\0\0"
    struct.pack_into("<ii", data, 8, font_table_offset, kerning_table_offset)
    data[font_table_offset : font_table_offset + 4] = b"fthd"
    struct.pack_into("<ii", data, font_table_offset + 4, 0, 0)
    struct.pack_into("<HHfii", data, font_table_offset + 16, 1, 1, 12.0, 12, 9)
    data[kerning_table_offset : kerning_table_offset + 4] = b"knhd"
    struct.pack_into("<i", data, kerning_table_offset + 4, 0)
    return bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    output = args.out.resolve()
    target = output / "common" / "font" / "axis_12.fdt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(empty_fdt())
    (output / "rift-fixture-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "rift.synthetic-game-data-fixture.v1",
                "profile": "minimal-font-v1",
                "real_game_data": False,
                "files": ["common/font/axis_12.fdt"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Created Rift synthetic game-data fixture pack at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
