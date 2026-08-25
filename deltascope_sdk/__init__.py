"""Bundled, non-authoritative DeltaScope consumer SDK.

The SDK contains deterministic SRL parsing/evaluation and contract readers needed by the
local workbench. It is deliberately separate from SigmaScope's scanner implementation and
never provides repository, Evidence-v2, queue, or publication authority.
"""
from .runtime import configure_published_contracts, sdk_status

__all__ = ["configure_published_contracts", "sdk_status"]
