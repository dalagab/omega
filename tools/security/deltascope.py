#!/usr/bin/env python3
"""DeltaScope: developer-only, read-only Omega security evidence and Stigma-1 / SRL Core workbench entry point.

DeltaScope never scans plugins and never publishes catalog, Definitions, or Security
Evidence state. Published/security state is inspected read-only. The Rules workspace may
write only versioned user-authored SRL YAML under the configured local rule home
(default: ~/.omega/deltascope/rules/v1).
"""
from __future__ import annotations

from developer_view import main

if __name__ == "__main__":
    raise SystemExit(main())
