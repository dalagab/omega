"""Stigma-1 public component facade for the shared SRL Core.

The implementation remains in :mod:`srl` so existing frozen workers and Definition
tooling keep their stable import path. New developer/workbench code may import
``stigma1`` to make the component boundary explicit without creating a second rule
implementation.
"""
from __future__ import annotations

try:
    from .srl import *  # noqa: F401,F403
except ImportError:  # direct script/import from tools/security
    from srl import *  # type: ignore # noqa: F401,F403
