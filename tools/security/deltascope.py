#!/usr/bin/env python3
"""DeltaScope: developer-only, read-only inspection/audit entry point for SigmaScope evidence.

DeltaScope never scans plugins and never publishes catalog or Security Evidence state.
It delegates to the hardened read-only developer view/audit implementation.
"""
from __future__ import annotations

from developer_view import main

if __name__ == "__main__":
    raise SystemExit(main())
