#!/usr/bin/env python3
"""Compatibility shim for the renamed local Sigmascope v2 test tool."""
from local_sigmascope_v2_test import *  # noqa: F401,F403
from local_sigmascope_v2_test import main

if __name__ == "__main__":
    main()
