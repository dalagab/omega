#!/usr/bin/env python3
"""Compatibility shim for the renamed production Sigmascope v2 pipeline."""
from production_sigmascope_v2_pipeline import *  # noqa: F401,F403
from production_sigmascope_v2_pipeline import main

if __name__ == "__main__":
    main()
