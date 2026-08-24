#!/usr/bin/env python3
"""Regression checks for Rift's synthetic game-data fixture pack tools."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "tools" / "build-rift-minimal-game-data-fixture.py"
VALIDATOR = ROOT / "tools" / "validate-rift-game-data-fixture.py"


with tempfile.TemporaryDirectory(prefix="rift-fixture-test-") as temporary:
    fixture_root = Path(temporary) / "fixture"
    subprocess.run([sys.executable, str(BUILDER), "--out", str(fixture_root)], check=True, capture_output=True, text=True)
    result = subprocess.run([sys.executable, str(VALIDATOR), str(fixture_root)], check=True, capture_output=True, text=True)
    assert "PASS" in result.stdout
    assert (fixture_root / "common" / "font" / "axis_12.fdt").read_bytes().startswith(b"fcsv")
    manifest = json.loads((fixture_root / "rift-fixture-manifest.json").read_text(encoding="utf-8"))
    assert manifest["real_game_data"] is False

print("Rift game-data fixture tool self-test: PASS")
