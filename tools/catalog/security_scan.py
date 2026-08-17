#!/usr/bin/env python3
"""Compatibility shim for the renamed Omega Sigmascope engine.

New code should import or execute ``sigmascope``.  This module remains so older local
operator commands and persisted automation do not break during the naming transition.
"""
from sigmascope import *  # noqa: F401,F403
from sigmascope import main

if __name__ == "__main__":
    main()
